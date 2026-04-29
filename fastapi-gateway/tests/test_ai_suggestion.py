from __future__ import annotations

from pathlib import Path
import sys

import httpx
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import main as gateway_main
from app.dependencies.auth import CurrentUser
from app.internal.ai_suggestion_client import _proto_to_response, ai_suggestion_client
from app.routers.ai_suggestion_router import generate_suggestion, get_suggestion
from app.schemas.ai_suggestion_schemas import AISuggestionResponse
from app.schemas.ai_suggestion_schemas import GenerateAISuggestionRequest
from app.services.ai_suggestion import orchestrator
from app.services.ai_suggestion.prompts import next_steps
from app.gen import ai_suggestion_pb2


class _FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def get(self, key: str):
        return self.values.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        self.values[key] = value
        return True


def _make_current_user() -> CurrentUser:
    return CurrentUser(
        user_id="11111111-1111-1111-1111-111111111111",
        azp="platform-web",
        actor_type="web_user",
        roles={"USER"},
        scopes=set(),
        claims={"sub": "11111111-1111-1111-1111-111111111111"},
        project_id="22222222-2222-2222-2222-222222222222",
        api_key_id=None,
    )


def test_next_steps_prepare_context_preserves_user_input() -> None:
    prepared = next_steps.prepare_context(
        {
            "job_id": "job-1",
            "user_input": "Test a target for XSS and SQL injection vulnerabilities",
            "target": {"name": "api.example.com", "type": "domain"},
            "findings": [{"title": "Reflected XSS", "severity": "high"}],
        }
    )

    assert prepared["user_input"] == "Test a target for XSS and SQL injection vulnerabilities"
    assert prepared["target"] == {"name": "api.example.com", "type": "domain"}


def test_proto_to_response_backfills_commands_for_legacy_saved_output() -> None:
    response = ai_suggestion_pb2.SuggestionResponse(
        id="legacy-1",
        job_id="job-legacy",
        mode=ai_suggestion_pb2.SUGGESTION_MODE_NEXT_STEPS,
        provider="groq",
        model="llama-test",
        content="",
        output_json="""
{
  "suggestions": [
    {
      "title": "Validate live web services with httpx",
      "params": {
        "target": "https://norton-u.com",
        "status_code": true,
        "title": true,
        "tech_detect": true
      },
      "tool_id": "httpx",
      "priority": "medium",
      "reasoning": "Validate reachability and fingerprint services.",
      "confidence": 0.83
    }
  ]
}
""".strip(),
    )

    parsed = _proto_to_response(response)

    assert parsed.output == {
        "suggestions": [
            {
                "title": "Validate live web services with httpx",
                "tool_id": "httpx",
                "command": "httpx -u https://norton-u.com -sc -title -td",
                "priority": "medium",
                "reasoning": "Validate reachability and fingerprint services.",
                "confidence": 0.83,
                "params": {
                    "target": "https://norton-u.com",
                    "status_code": True,
                    "title": True,
                    "tech_detect": True,
                },
            }
        ]
    }


@pytest.mark.asyncio
async def test_internal_ai_suggestion_uses_redis_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_redis = _FakeRedis()
    calls = {"count": 0}

    async def fake_call_groq(system_prompt: str, user_prompt: str, model: str, api_key: str):
        calls["count"] += 1
        return orchestrator.ProviderResult(
            provider="groq",
            model=model,
            content="1. close risky ports\n2. patch exposed services",
            input_tokens=12,
            output_tokens=8,
        )

    monkeypatch.setattr(orchestrator, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(orchestrator, "_call_groq", fake_call_groq)
    monkeypatch.setenv("AI_SUGGESTION_GROQ_API_KEY", "groq-test-key")
    monkeypatch.setenv("AI_SUGGESTION_MODEL_NEXT_STEPS", "llama-test")

    transport = httpx.ASGITransport(app=gateway_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "job_id": "job-1",
            "mode": "next_steps",
            "context": {"job_id": "job-1", "severity_counts": {"high": 2}},
        }
        first = await client.post("/internal/ai/suggest", json=payload)
        second = await client.post("/internal/ai/suggest", json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["content"] == ""
    assert first.json()["output"] == {
        "suggestions": [
            {
                "title": "close risky ports",
                "tool_id": "nuclei",
                "command": "nuclei -u TARGET",
                "priority": "medium",
                "reasoning": "Recovered from unstructured AI output.",
                "confidence": 0.3,
                "params": {},
            },
            {
                "title": "patch exposed services",
                "tool_id": "nuclei",
                "command": "nuclei -u TARGET",
                "priority": "medium",
                "reasoning": "Recovered from unstructured AI output.",
                "confidence": 0.3,
                "params": {},
            }
        ]
    }
    assert second.json() == first.json()
    assert calls["count"] == 1


@pytest.mark.asyncio
async def test_internal_ai_suggestion_next_steps_normalizes_structured_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_redis = _FakeRedis()

    async def fake_call_groq(system_prompt: str, user_prompt: str, model: str, api_key: str):
        return orchestrator.ProviderResult(
            provider="groq",
            model=model,
            content="""
{
  "suggestions": [
    {
      "title": "Investigate Apache RCE vulnerability",
      "tool_id": "nuclei",
      "priority": "high",
      "reasoning": "Apache 2.4.49 is vulnerable to CVE-2021-41773",
      "params": { "template": "cves/2021/CVE-2021-41773.yaml" },
      "confidence": 0.88
    }
  ]
}
""".strip(),
            input_tokens=20,
            output_tokens=30,
        )

    monkeypatch.setattr(orchestrator, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(orchestrator, "_call_groq", fake_call_groq)
    monkeypatch.setenv("AI_SUGGESTION_GROQ_API_KEY", "groq-test-key")
    monkeypatch.setenv("AI_SUGGESTION_MODEL_NEXT_STEPS", "llama-test")

    transport = httpx.ASGITransport(app=gateway_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "job_id": "job-2",
            "mode": "next_steps",
            "context": {"job_id": "job-2", "severity_counts": {"high": 1}},
        }
        result = await client.post("/internal/ai/suggest", json=payload)

    assert result.status_code == 200
    data = result.json()
    assert data["content"] == ""
    assert data["output"] == {
        "suggestions": [
            {
                "title": "Investigate Apache RCE vulnerability",
                "tool_id": "nuclei",
                "command": "nuclei -u TARGET -t cves/2021/CVE-2021-41773.yaml",
                "priority": "high",
                "reasoning": "Apache 2.4.49 is vulnerable to CVE-2021-41773",
                "params": {"template": "cves/2021/CVE-2021-41773.yaml"},
                "confidence": 0.88,
            }
        ]
    }


@pytest.mark.asyncio
async def test_internal_ai_suggestion_filters_unknown_tools_and_normalizes_priority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_redis = _FakeRedis()

    async def fake_call_groq(system_prompt: str, user_prompt: str, model: str, api_key: str):
        return orchestrator.ProviderResult(
            provider="groq",
            model=model,
            content="""
{
  "suggestions": [
    {
      "title": "Enumerate subdomains with Amass",
      "tool_id": "amass",
      "priority": "critical",
      "reasoning": "Broaden asset inventory before deeper validation.",
      "params": { "domain": "example.com", "passive": true },
      "confidence": 0.91
    },
    {
      "title": "Run unsupported browser automation",
      "tool_id": "playwright",
      "priority": "high",
      "reasoning": "This tool is not allowed by the contract.",
      "params": { "url": "https://example.com" },
      "confidence": 0.8
    }
  ]
}
""".strip(),
            input_tokens=20,
            output_tokens=30,
        )

    monkeypatch.setattr(orchestrator, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(orchestrator, "_call_groq", fake_call_groq)
    monkeypatch.setenv("AI_SUGGESTION_GROQ_API_KEY", "groq-test-key")
    monkeypatch.setenv("AI_SUGGESTION_MODEL_NEXT_STEPS", "llama-test")

    transport = httpx.ASGITransport(app=gateway_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "job_id": "job-3",
            "mode": "next_steps",
            "context": {"job_id": "job-3", "target": {"name": "example.com"}, "severity_counts": {"high": 1}},
        }
        result = await client.post("/internal/ai/suggest", json=payload)

    assert result.status_code == 200
    data = result.json()
    assert data["output"] == {
        "suggestions": [
            {
                "title": "Enumerate subdomains with Amass",
                "tool_id": "amass",
                "command": "amass enum -passive -d example.com",
                "priority": "medium",
                "reasoning": "Broaden asset inventory before deeper validation.",
                "params": {"domain": "example.com", "passive": True},
                "confidence": 0.91,
            }
        ]
    }


@pytest.mark.asyncio
async def test_internal_mcp_context_bridge_shapes_scan_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AI_SUGGESTION_MCP_SECRET", raising=False)

    transport = httpx.ASGITransport(app=gateway_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "mode": "next_steps",
            "context": {
                "job_id": "job-1",
                "project_id": "project-1",
                "status": "completed",
                "target": {"name": "api.mock.internal", "type": "domain"},
                "severity_counts": {"high": 1, "medium": 1},
                "hosts": ["api.mock.internal"],
                "ports": [22, 443],
                "top_findings": [
                    {
                        "title": "Outdated web service fingerprint detected",
                        "severity": "high",
                        "host": "api.mock.internal",
                        "port": 443,
                        "fingerprint": "api.mock.internal:443:nginx-1.14.0",
                    },
                    {
                        "title": "SSH exposed to the internet",
                        "severity": "medium",
                        "host": "api.mock.internal",
                        "port": 22,
                        "fingerprint": "api.mock.internal:22:ssh-exposed",
                    },
                ],
                "results": [
                    {"tool": "nuclei", "severity": "high"},
                    {"tool": "httpx", "severity": "medium"},
                ],
                "metadata": {"total_findings": 2, "total_results": 2},
            },
        }
        result = await client.post("/internal/ai/mcp/ai-suggestion/context", json=payload)

    assert result.status_code == 200
    data = result.json()
    assert data["resources"] == ["scan_jobs", "targets", "findings", "scan_results"]
    assert "api.mock.internal" in data["summary"]
    assert data["context"]["scan_job"]["job_id"] == "job-1"
    assert "api.mock.internal:22" in data["context"]["exposed_services"]
    assert data["context"]["findings_by_host"]["api.mock.internal"][0]["title"] == "Outdated web service fingerprint detected"
    assert data["context"]["tool_observations"][0]["tool"] == "nuclei"


@pytest.mark.asyncio
async def test_internal_mcp_context_bridge_enforces_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_SUGGESTION_MCP_SECRET", "bridge-secret")

    transport = httpx.ASGITransport(app=gateway_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "mode": "next_steps",
            "context": {"job_id": "job-1"},
        }
        result = await client.post("/internal/ai/mcp/ai-suggestion/context", json=payload)

    assert result.status_code == 401
    assert result.json() == {"detail": "invalid mcp secret"}


@pytest.mark.asyncio
async def test_internal_ai_suggestion_can_enrich_context_with_mcp(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_redis = _FakeRedis()
    captured: dict[str, object] = {}

    async def fake_call_groq(system_prompt: str, user_prompt: str, model: str, api_key: str):
        captured["user_prompt"] = user_prompt
        return orchestrator.ProviderResult(
            provider="groq",
            model=model,
            content='{"suggestions":[]}',
            input_tokens=20,
            output_tokens=11,
        )

    async def fake_mcp_enrich(mode: str, context: dict[str, object]):
        enriched = dict(context)
        enriched["metadata"] = {
            **dict(context.get("metadata") or {}),
            "mcp_summary": "MCP added relationship context",
        }
        enriched["mcp_context"] = {
            "linked_assets": ["api.mock.internal", "admin.mock.internal"],
        }
        return enriched

    monkeypatch.setattr(orchestrator, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(orchestrator, "_call_groq", fake_call_groq)
    monkeypatch.setattr(orchestrator, "enrich_context_with_mcp", fake_mcp_enrich)
    monkeypatch.setenv("AI_SUGGESTION_GROQ_API_KEY", "groq-test-key")
    monkeypatch.setenv("AI_SUGGESTION_MODEL_NEXT_STEPS", "llama-test")

    transport = httpx.ASGITransport(app=gateway_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "job_id": "job-1",
            "mode": "next_steps",
            "context": {"job_id": "job-1", "severity_counts": {"high": 2}},
        }
        result = await client.post("/internal/ai/suggest", json=payload)

    assert result.status_code == 200
    assert "MCP added relationship context" in str(captured["user_prompt"])
    assert "admin.mock.internal" in str(captured["user_prompt"])


@pytest.mark.asyncio
async def test_internal_ai_suggestion_returns_400_for_strict_mcp_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_mcp_enrich(mode: str, context: dict[str, object]):
        raise orchestrator.MCPContextError("MCP context enrichment failed: bridge unavailable")

    monkeypatch.setattr(orchestrator, "enrich_context_with_mcp", fake_mcp_enrich)
    monkeypatch.setenv("AI_SUGGESTION_GROQ_API_KEY", "groq-test-key")
    monkeypatch.setenv("AI_SUGGESTION_MODEL_NEXT_STEPS", "llama-test")

    transport = httpx.ASGITransport(app=gateway_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "job_id": "job-1",
            "mode": "next_steps",
            "context": {"job_id": "job-1", "severity_counts": {"high": 2}},
        }
        result = await client.post("/internal/ai/suggest", json=payload)

    assert result.status_code == 400
    assert result.json() == {
        "detail": "MCP context enrichment failed: bridge unavailable"
    }


@pytest.mark.asyncio
async def test_internal_ai_suggestion_returns_clean_503_on_provider_rate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = httpx.Request(
        "POST",
        "https://api.groq.com/openai/v1/chat/completions",
    )
    response = httpx.Response(429, request=request, headers={"Retry-After": "60"})

    async def fake_call_groq(system_prompt: str, user_prompt: str, model: str, api_key: str):
        raise httpx.HTTPStatusError("rate limited", request=request, response=response)

    monkeypatch.setattr(orchestrator, "_call_groq", fake_call_groq)
    monkeypatch.setenv("AI_SUGGESTION_GROQ_API_KEY", "groq-test-key")
    monkeypatch.setenv("AI_SUGGESTION_MODEL_NEXT_STEPS", "llama-test")

    transport = httpx.ASGITransport(app=gateway_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "job_id": "job-1",
            "mode": "next_steps",
            "context": {"job_id": "job-1", "severity_counts": {"high": 2}},
        }
        result = await client.post("/internal/ai/suggest", json=payload)

    assert result.status_code == 503
    assert result.json() == {
        "detail": "Groq AI provider is temporarily rate limited. Please try again later."
    }
    assert result.headers["Retry-After"] == "60"
    assert "groq-test-key" not in result.text


@pytest.mark.asyncio
async def test_internal_ai_suggestion_includes_provider_400_detail(monkeypatch: pytest.MonkeyPatch) -> None:
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    response = httpx.Response(
        400,
        request=request,
        json={
            "error": {
                "message": "model: llama-disabled is not a valid model",
            },
        },
    )

    async def fake_call_groq(system_prompt: str, user_prompt: str, model: str, api_key: str):
        raise httpx.HTTPStatusError("bad request", request=request, response=response)

    monkeypatch.setattr(orchestrator, "_call_groq", fake_call_groq)
    monkeypatch.setenv("AI_SUGGESTION_GROQ_API_KEY", "groq-test-key")
    monkeypatch.setenv("AI_SUGGESTION_MODEL_NEXT_STEPS", "llama-disabled")

    transport = httpx.ASGITransport(app=gateway_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "job_id": "job-1",
            "mode": "next_steps",
            "context": {"job_id": "job-1", "severity_counts": {"high": 2}},
        }
        result = await client.post("/internal/ai/suggest", json=payload)

    assert result.status_code == 502
    assert result.json() == {
        "detail": "Groq AI provider request failed with status 400: model: llama-disabled is not a valid model"
    }


@pytest.mark.asyncio
async def test_public_generate_route_calls_grpc_client_with_current_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_generate(body, *, user_id: str, api_key_id: str | None = None, api_project_id: str | None = None):
        captured["job_id"] = body.job_id
        captured["mode"] = body.mode
        captured["user_id"] = user_id
        captured["api_key_id"] = api_key_id
        captured["api_project_id"] = api_project_id
        return AISuggestionResponse(
            id="suggestion-1",
            job_id=body.job_id,
            mode=body.mode,
            provider="groq",
            model="llama-test",
            content="",
            output={"suggestions": []},
            input_tokens=10,
            output_tokens=5,
            feedback="",
            is_suggested=True,
            created_at=None,
            updated_at=None,
        )

    monkeypatch.setattr(ai_suggestion_client, "generate_suggestion", fake_generate)

    response = generate_suggestion(
        GenerateAISuggestionRequest(job_id="job-123", mode="next_steps"),
        _make_current_user(),
    )

    assert response.job_id == "job-123"
    assert captured == {
        "job_id": "job-123",
        "mode": "next_steps",
        "user_id": "11111111-1111-1111-1111-111111111111",
        "api_key_id": None,
        "api_project_id": "22222222-2222-2222-2222-222222222222",
    }


def test_public_get_route_calls_grpc_client_with_suggestion_id(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_get(suggestion_id: str, *, user_id: str, api_key_id: str | None = None, api_project_id: str | None = None):
        captured["suggestion_id"] = suggestion_id
        captured["user_id"] = user_id
        captured["api_key_id"] = api_key_id
        captured["api_project_id"] = api_project_id
        return AISuggestionResponse(
            id=suggestion_id,
            job_id="job-123",
            mode="next_steps",
            provider="groq",
            model="llama-test",
            content="",
            output={"suggestions": []},
            input_tokens=10,
            output_tokens=5,
            feedback="",
            is_suggested=True,
            created_at=None,
            updated_at=None,
        )

    monkeypatch.setattr(ai_suggestion_client, "get_suggestion", fake_get)

    response = get_suggestion(
        "suggestion-123",
        _make_current_user(),
    )

    assert response.id == "suggestion-123"
    assert captured == {
        "suggestion_id": "suggestion-123",
        "user_id": "11111111-1111-1111-1111-111111111111",
        "api_key_id": None,
        "api_project_id": "22222222-2222-2222-2222-222222222222",
    }
