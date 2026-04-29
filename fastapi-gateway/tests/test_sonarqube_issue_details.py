from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
from fastapi import HTTPException

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from app.dependencies.auth import CurrentUser
from app.internal.sonarqube_client import SonarQubeClient
import app.internal.sonarqube_client as sonarqube_client_module
from app.routers import sonarqube as sonarqube_router


def _make_current_user() -> CurrentUser:
    return CurrentUser(
        user_id="user-1",
        azp="nextjs_user",
        actor_type="web_user",
        roles={"USER"},
        scopes=set(),
        claims={"sub": "user-1"},
    )


@pytest.mark.asyncio
async def test_build_issue_details_aggregates_and_caches_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    client = SonarQubeClient("http://sonar.example", "token-1")

    async def _fake_request(*, method: str, path: str, params=None, data=None):
        if path == "/api/issues/search":
            return {
                "issues": [
                    {
                        "key": "AYz123abc",
                        "rule": "python:S1234",
                        "severity": "CRITICAL",
                        "type": "VULNERABILITY",
                        "component": "demo-project:src/app.py",
                        "project": "demo-project",
                        "line": 14,
                        "textRange": {
                            "startLine": 14,
                            "endLine": 15,
                            "startOffset": 2,
                            "endOffset": 18,
                        },
                        "tags": ["security", "owasp-a2"],
                        "comments": [
                            {
                                "key": "comment-1",
                                "login": "alice",
                                "htmlText": "<p>Needs a quick fix.</p>",
                                "createdAt": "2026-04-24T09:00:00+0000",
                            }
                        ],
                    }
                ]
            }
        if path == "/api/rules/show":
            return {
                "rule": {
                    "key": "python:S1234",
                    "name": "Avoid dangerous call",
                    "htmlDesc": "<p>Dangerous call can be exploited.</p>",
                    "debtRemFnType": "LINEAR",
                    "engineId": "eslint",
                    "descriptionSections": [
                        {"key": "root_cause", "content": "<p>Unsanitized input reaches a sink.</p>"},
                    ],
                }
            }
        if path == "/api/sources/show":
            return {
                "sources": [
                    {"line": 14, "code": "dangerous_call(user_input)"},
                    {"line": 15, "code": "return None"},
                ]
            }
        if path == "/api/issues/changelog":
            return {
                "changelog": [
                    {
                        "creationDate": "2026-04-24T10:00:00+0000",
                        "user": "bob",
                        "diffs": [
                            {"key": "status", "oldValue": "OPEN", "newValue": "CONFIRMED"},
                        ],
                    }
                ]
            }
        raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(client, "_request", AsyncMock(side_effect=_fake_request))

    issue = await client.get_issue("AYz123abc")

    assert issue is not None

    details = await client.build_issue_details(issue)
    more_info_only = await client.build_issue_details(issue, tab="moreInfo")

    assert details["whereIsTheIssue"]["componentKey"] == "demo-project:src/app.py"
    assert details["whereIsTheIssue"]["filePath"] == "src/app.py"
    assert details["whereIsTheIssue"]["codeSnippet"] == "dangerous_call(user_input)\nreturn None"
    assert details["whyIsThisAnIssue"]["ruleName"] == "Avoid dangerous call"
    assert details["whyIsThisAnIssue"]["debtRemediationFunction"] == "LINEAR"
    assert details["activity"]["comments"][0]["login"] == "alice"
    assert details["activity"]["changelog"][0]["diffs"][0]["newValue"] == "CONFIRMED"
    assert details["moreInfo"]["externalRuleEngine"] == "eslint"
    assert details["moreInfo"]["documentationUrl"] == (
        "http://sonar.example/coding_rules?open=python:S1234&rule_key=python:S1234"
    )
    assert details["moreInfo"]["descriptionSections"] == [
        {"key": "root_cause", "content": "<p>Unsanitized input reaches a sink.</p>"},
    ]
    assert more_info_only == {"moreInfo": details["moreInfo"]}

    rule_calls = [
        call
        for call in client._request.await_args_list
        if call.kwargs.get("path") == "/api/rules/show"
    ]
    assert len(rule_calls) == 1


@pytest.mark.asyncio
async def test_issue_details_route_returns_404_when_issue_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = SimpleNamespace(
        get_issue=AsyncMock(return_value=None),
        build_issue_details=AsyncMock(),
    )
    monkeypatch.setattr(sonarqube_router, "get_sonarqube_client", lambda: fake_client)

    with pytest.raises(HTTPException) as exc_info:
        await sonarqube_router.get_issue_details(
            issue_key="missing-issue",
            tab=None,
            current_user=_make_current_user(),
        )

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_issue_details_route_returns_403_without_project_access(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = SimpleNamespace(
        get_issue=AsyncMock(
            return_value={
                "key": "AYz123abc",
                "project": "demo-project",
            }
        ),
        build_issue_details=AsyncMock(return_value={}),
    )
    monkeypatch.setattr(sonarqube_router, "get_sonarqube_client", lambda: fake_client)
    monkeypatch.setattr(
        sonarqube_router.user_client,
        "list_sonar_analyses_gateway",
        lambda **kwargs: SimpleNamespace(json_payload='{"analyses": []}'),
    )

    with pytest.raises(HTTPException) as exc_info:
        await sonarqube_router.get_issue_details(
            issue_key="AYz123abc",
            tab=None,
            current_user=_make_current_user(),
        )

    assert exc_info.value.status_code == 403
    fake_client.build_issue_details.assert_not_called()


@pytest.mark.asyncio
async def test_request_maps_invalid_token_to_401(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeResponse:
        status_code = 401

        @staticmethod
        def json() -> dict[str, object]:
            return {"errors": [{"msg": "Unauthorized"}]}

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def request(self, *args, **kwargs):
            return _FakeResponse()

    monkeypatch.setattr(sonarqube_client_module.httpx, "AsyncClient", _FakeAsyncClient)
    client = SonarQubeClient("http://sonar.example", "token-1")

    with pytest.raises(HTTPException) as exc_info:
        await client._request(method="GET", path="/api/issues/search")

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid SonarQube token"


@pytest.mark.asyncio
async def test_request_maps_network_error_to_502(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def request(self, *args, **kwargs):
            raise httpx.ConnectError(
                "boom",
                request=httpx.Request("GET", "http://sonar.example/api/issues/search"),
            )

    monkeypatch.setattr(sonarqube_client_module.httpx, "AsyncClient", _FakeAsyncClient)
    client = SonarQubeClient("http://sonar.example", "token-1")

    with pytest.raises(HTTPException) as exc_info:
        await client._request(method="GET", path="/api/issues/search")

    assert exc_info.value.status_code == 502
    assert exc_info.value.detail == "SonarQube is unreachable"
