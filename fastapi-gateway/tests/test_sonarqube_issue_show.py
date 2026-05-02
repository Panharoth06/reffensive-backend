from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace

from fastapi import HTTPException

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from app.dependencies.auth import CurrentUser
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
async def test_get_issue_show_returns_clean_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sonarqube_router.user_client,
        "get_sonar_issue_detail_gateway",
        lambda **kwargs: SimpleNamespace(
            json_payload=(
                '{"issue":{"key":"AYz123abc","message":"Fix this issue","line":18,'
                '"severity":"MAJOR","status":"OPEN","tags":["security"]},'
                '"rule":{"key":"python:S1234","name":"Rule title",'
                '"htmlDesc":"<p>Rule description</p>"}}'
            )
        ),
    )

    payload = await sonarqube_router.get_issue_show(" AYz123abc ", _make_current_user())

    assert payload == {
        "issue": {
            "key": "AYz123abc",
            "message": "Fix this issue",
            "line": 18,
            "severity": "MAJOR",
            "status": "OPEN",
            "tags": ["security"],
        },
        "rule": {
            "key": "python:S1234",
            "name": "Rule title",
            "htmlDesc": "<p>Rule description</p>",
        },
    }


@pytest.mark.asyncio
async def test_get_issue_show_rejects_blank_issue_key() -> None:
    with pytest.raises(HTTPException) as exc_info:
        await sonarqube_router.get_issue_show(
            "   ",
            _make_current_user(),
        )

    assert exc_info.value.status_code == 400
