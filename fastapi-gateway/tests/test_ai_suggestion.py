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


def _first_suggestion(output: dict) -> dict:
    suggestions = output.get("suggestions") or []
    assert suggestions
    return suggestions[0]


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


def test_next_steps_prepare_context_compacts_large_scan_context() -> None:
    oversized_text = "A" * 600
    prepared = next_steps.prepare_context(
        {
            "job_id": "job-1",
            "user_input": oversized_text,
            "target": {
                "name": "api.example.com",
                "type": "domain",
                "description": oversized_text,
            },
            "metadata": {
                "note": oversized_text,
                "total_findings": 20,
                "total_results": 20,
            },
            "mcp_context": {
                "linked_assets": [f"asset-{index}.example.com" for index in range(20)],
                "summary": oversized_text,
            },
            "findings": [
                {
                    "title": oversized_text,
                    "severity": "high",
                    "host": f"host-{index}.example.com",
                    "port": 443,
                    "fingerprint": oversized_text,
                    "tool_name": "nuclei",
                }
                for index in range(20)
            ],
            "scan_results": [
                {
                    "tool_name": "httpx",
                    "severity": "medium",
                    "parsed_data": {
                        "url": f"https://host-{index}.example.com/path",
                        "headers": {f"header-{n}": oversized_text for n in range(10)},
                        "paths": [f"/endpoint/{n}" for n in range(10)],
                    },
                    "raw_preview": oversized_text,
                }
                for index in range(20)
            ],
        }
    )

    assert len(prepared["user_input"]) <= 200
    assert len(prepared["target"]["description"]) <= 120
    assert len(prepared["findings"]) == 5
    assert len(prepared["scan_results"]) == 5
    assert prepared["metadata"]["prompt_context"] == {
        "total_findings": 20,
        "included_findings": 5,
        "total_results": 20,
        "included_results": 5,
    }
    assert len(prepared["findings"][0]["title"]) <= 120
    assert "raw_preview" not in prepared["scan_results"][0]
    assert prepared["scan_results"][0]["parsed_data"]["headers"]["_truncated_items"] == 6
    assert prepared["scan_results"][0]["parsed_data"]["paths"][-1] == {"_truncated_items": 6}
    assert prepared["mcp_context"]["linked_assets"][-1] == {"_truncated_items": 14}

    prompt = next_steps.user_prompt(prepared)
    assert len(prompt) < 16000


def test_next_steps_prepare_context_derives_evidence_from_scan_state() -> None:
    prepared = next_steps.prepare_context(
        {
            "job_id": "job-2",
            "target": {"name": "example.com", "type": "domain"},
            "findings": [
                {"title": "Admin route exposed", "severity": "high", "host": "app.example.com", "port": 443},
            ],
            "results": [
                {
                    "tool_name": "httpx",
                    "severity": "medium",
                    "parsed_data": {
                        "host": "app.example.com",
                        "scheme": "https",
                        "port": 443,
                        "path": "/admin",
                        "url": "https://app.example.com/admin",
                    },
                },
                {
                    "tool_name": "subfinder",
                    "severity": "info",
                    "parsed_data": {
                        "hosts": ["app.example.com", "api.example.com"],
                    },
                },
            ],
            "mcp_context": {
                "linked_assets": ["app.example.com", "api.example.com"],
                "candidate_paths": ["/admin"],
            },
        }
    )

    evidence = prepared["evidence"]
    assert "example.com" in evidence["candidate_domains"]
    assert "https://app.example.com/admin" in evidence["candidate_urls"]
    assert "/admin" in evidence["candidate_paths"]
    assert "httpx" in evidence["executed_tools"]
    assert "subfinder" in evidence["executed_tools"]
    assert any("Concrete URLs are available" in hint for hint in evidence["workflow_hints"])


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
    suggestion = _first_suggestion(parsed.output)
    assert suggestion["title"] == "Validate live web services with httpx"
    assert suggestion["priority"] == "medium"
    assert suggestion["action"]["tool_id"] == "httpx"
    assert suggestion["action"]["command"] == "httpx -u https://norton-u.com -sc -title -td"
    assert suggestion["action"]["params"] == {
        "target": "https://norton-u.com",
        "status_code": True,
        "title": True,
        "tech_detect": True,
    }
    assert suggestion["score"]["confidence"] == 0.83


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
    suggestions = first.json()["output"]["suggestions"]
    assert len(suggestions) == 2
    assert suggestions[0]["action"]["tool_id"] == "nuclei"
    assert suggestions[0]["action"]["command"] == "nuclei -u TARGET"
    assert suggestions[0]["score"]["confidence"] == 0.3
    assert suggestions[0]["reasoning"] == "Recovered from unstructured AI output."
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
    suggestion = _first_suggestion(data["output"])
    assert suggestion["title"] == "Investigate Apache RCE vulnerability"
    assert suggestion["action"]["tool_id"] == "nuclei"
    assert suggestion["action"]["command"] == "nuclei -u TARGET -t cves/2021/CVE-2021-41773.yaml"
    assert suggestion["action"]["params"] == {"template": "cves/2021/CVE-2021-41773.yaml"}
    assert suggestion["priority"] == "high"
    assert suggestion["score"]["confidence"] == 0.88


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
    suggestion = _first_suggestion(data["output"])
    assert suggestion["title"] == "Enumerate subdomains with Amass"
    assert suggestion["action"]["tool_id"] == "amass"
    assert suggestion["action"]["command"] == "amass enum -passive -d example.com"
    assert suggestion["action"]["params"] == {"domain": "example.com", "passive": True}
    assert suggestion["priority"] == "critical"
    assert suggestion["score"]["confidence"] == 0.91


def test_next_steps_normalize_output_dedupes_overlapping_discovery_and_fills_targets() -> None:
    context = {
        "target": {"name": "rupp.edu.kh", "type": "domain"},
        "results": [
            {
                "tool_name": "subfinder",
                "severity": "info",
                "parsed_data": {
                    "url": "https://portal.rupp.edu.kh",
                    "hosts": ["portal.rupp.edu.kh", "lms.rupp.edu.kh"],
                },
            }
        ],
    }

    normalized = next_steps.normalize_output(
        """
{
  "suggestions": [
    {
      "title": "Validate live portal with httpx",
      "tool_id": "httpx",
      "priority": "high",
      "reasoning": "A concrete web asset is already known and should be verified first.",
      "params": {
        "status_code": true,
        "title": true
      },
      "confidence": 0.9
    },
    {
      "title": "Discover subdomains with subfinder",
      "tool_id": "subfinder",
      "priority": "medium",
      "reasoning": "Continue domain enumeration.",
      "params": {
        "domain": "rupp.edu.kh",
        "output_file": "subdomains.txt"
      },
      "confidence": 0.78
    },
    {
      "title": "Enumerate subdomains with amass",
      "tool_id": "amass",
      "priority": "medium",
      "reasoning": "Cross-check the same domain with another discovery source.",
      "params": {
        "domain": "rupp.edu.kh",
        "output_file": "amass_subdomains.txt"
      },
      "confidence": 0.69
    }
  ]
}
""".strip(),
        context,
    )

    suggestions = normalized["suggestions"]
    assert len(suggestions) == 2
    assert suggestions[0]["action"]["tool_id"] == "httpx"
    assert suggestions[0]["action"]["command"] == "httpx -u https://portal.rupp.edu.kh -sc -title"
    assert suggestions[0]["action"]["params"] == {
        "status_code": True,
        "title": True,
        "url": "https://portal.rupp.edu.kh",
    }
    assert suggestions[1]["action"]["tool_id"] == "amass"
    assert suggestions[1]["action"]["params"] == {
        "domain": "rupp.edu.kh",
        "output": "amass_subdomains.txt",
    }


def test_next_steps_normalize_output_rewrites_invented_files_and_supports_param_aliases() -> None:
    context = {
        "target": {"name": "rupp.edu.kh", "type": "domain"},
        "findings": [
            {"title": "Potential web exposure", "severity": "medium", "host": "www.ruppv2.rupp.edu.kh", "port": 443},
        ],
        "results": [
            {
                "tool_name": "subfinder",
                "severity": "info",
                "parsed_data": {
                    "hosts": ["www.ruppv2.rupp.edu.kh", "sso.rupp.edu.kh"],
                    "url": "https://www.ruppv2.rupp.edu.kh",
                },
            }
        ],
    }

    normalized = next_steps.normalize_output(
        """
{
  "suggestions": [
    {
      "title": "Validate live web assets with httpx",
      "tool_id": "httpx",
      "priority": "medium",
      "reasoning": "Validate identified hosts before deeper testing.",
      "params": {
        "cdn": true,
        "input": "httpx_input.txt",
        "title": true,
        "output": "httpx_output.txt",
        "status_code": true,
        "tech_detect": true
      },
      "confidence": 0.85
    },
    {
      "title": "Probe for potential vulnerabilities with nuclei",
      "tool_id": "nuclei",
      "priority": "medium",
      "reasoning": "Probe the validated web target with targeted templates.",
      "params": {
        "url": "https://www.ruppv2.rupp.edu.kh",
        "workers": 100,
        "templates": "nuclei-templates/http/"
      },
      "confidence": 0.82
    }
  ]
}
""".strip(),
        context,
    )

    suggestions = normalized["suggestions"]
    assert len(suggestions) == 2
    assert suggestions[0]["action"]["tool_id"] == "httpx"
    assert suggestions[0]["action"]["command"] == "httpx -u https://www.ruppv2.rupp.edu.kh -sc -title -td -cdn"
    assert suggestions[0]["action"]["params"] == {
        "cdn_detect": True,
        "status_code": True,
        "tech_detect": True,
        "title": True,
        "url": "https://www.ruppv2.rupp.edu.kh",
    }
    assert suggestions[1]["action"]["tool_id"] == "nuclei"
    assert suggestions[1]["action"]["command"] == "nuclei -u https://www.ruppv2.rupp.edu.kh -t nuclei-templates/http/ -c 100"
    assert suggestions[1]["action"]["params"] == {
        "template": "nuclei-templates/http/",
        "url": "https://www.ruppv2.rupp.edu.kh",
        "workers": 100,
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
                    {
                        "tool": "httpx",
                        "severity": "medium",
                        "parsed_data": {
                            "host": "api.mock.internal",
                            "scheme": "https",
                            "port": 443,
                            "url": "https://api.mock.internal",
                            "path": "/",
                        },
                    },
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
    assert "https://api.mock.internal" in data["context"]["candidate_urls"]
    assert "nuclei" in data["context"]["executed_tools"]
    assert data["context"]["findings_by_host"]["api.mock.internal"][0]["title"] == "Outdated web service fingerprint detected"
    assert data["context"]["tool_observations"][0]["tool"] == "nuclei"
    assert any("Concrete URLs exist" in hint for hint in data["context"]["workflow_hints"])


@pytest.mark.asyncio
async def test_internal_mcp_context_bridge_understands_go_context_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AI_SUGGESTION_MCP_SECRET", raising=False)

    transport = httpx.ASGITransport(app=gateway_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "mode": "next_steps",
            "context": {
                "job_id": "job-go-1",
                "project_id": "project-1",
                "status": "completed",
                "target": {"name": "rupp.edu.kh", "type": "domain"},
                "severity_counts": {"high": 1, "medium": 1},
                "findings": [
                    {
                        "title": "Login host identified",
                        "severity": "high",
                        "host": "sso.rupp.edu.kh",
                        "port": 443,
                        "fingerprint": "nginx",
                    },
                    {
                        "title": "Legacy site exposed",
                        "severity": "medium",
                        "host": "www.ruppv2.rupp.edu.kh",
                        "port": 443,
                        "fingerprint": "apache",
                    },
                ],
                "results": [
                    {
                        "tool_name": "subfinder",
                        "severity": "info",
                        "parsed_data": {
                            "hosts": ["sso.rupp.edu.kh", "www.ruppv2.rupp.edu.kh"],
                            "url": "https://sso.rupp.edu.kh",
                        },
                    }
                ],
                "metadata": {"total_findings": 2, "total_results": 1},
            },
        }
        result = await client.post("/internal/ai/mcp/ai-suggestion/context", json=payload)

    assert result.status_code == 200
    data = result.json()
    assert "sso.rupp.edu.kh" in data["context"]["linked_assets"]
    assert "https://sso.rupp.edu.kh" in data["context"]["candidate_urls"]
    assert "subfinder" in data["context"]["executed_tools"]
    assert data["context"]["findings_by_host"]["sso.rupp.edu.kh"][0]["title"] == "Login host identified"
    assert any("Discovery already ran" in hint for hint in data["context"]["workflow_hints"])


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
