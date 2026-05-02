from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
from types import SimpleNamespace
from uuid import NAMESPACE_URL, uuid5

from starlette.requests import Request

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import app.dependencies.auth as auth_module
import main as gateway_main
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.routing import APIRoute
from app.routers.project_router import create_project as create_project_route
from app.routers.project_router import project_client
from app.routers.medium_scan_router import (
    get_medium_job_status as get_medium_job_status_route,
    medium_scan_client,
    submit_medium_scan as submit_medium_scan_route,
)
from app.schemas.medium_scan_schemas import MediumScanJobStatusResponse, MediumScanSubmitRequest, MediumScanSubmitResponse
from app.schemas.project_schemas import CreateProjectRequest, ProjectResponse


def _anon_user_id(fingerprint: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"anon-scan:{fingerprint}"))


def _patch_anon_identity(monkeypatch: pytest.MonkeyPatch, fingerprint: str = "fingerprint-1") -> str:
    anon_user_id = _anon_user_id(fingerprint)
    monkeypatch.setattr(auth_module, "build_anon_fingerprint", lambda request: fingerprint)
    return anon_user_id


def _make_request(path: str, headers: dict[str, str] | None = None) -> Request:
    header_pairs = [
        (key.lower().encode("latin-1"), value.encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "http_version": "1.1",
        "scheme": "http",
        "method": "GET",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": header_pairs,
        "client": ("203.0.113.42", 12345),
        "server": ("testserver", 80),
        "state": {},
    }
    return Request(scope)


def test_get_scan_current_user_falls_back_to_anonymous(monkeypatch: pytest.MonkeyPatch) -> None:
    anon_user_id = _patch_anon_identity(monkeypatch)
    monkeypatch.setattr(
        auth_module.user_client,
        "check_user_exists",
        lambda **kwargs: SimpleNamespace(exists=True, resolved_user_id=anon_user_id),
    )
    request = _make_request("/tools")

    current_user = auth_module.get_scan_current_user(request, credentials=None, x_api_key=None)

    assert current_user.actor_type == "anonymous"
    assert current_user.auth_method == "anonymous"
    assert current_user.user_id == anon_user_id
    assert auth_module.require_scan_permission(current_user) == current_user


def test_get_scan_current_user_rejects_invalid_bearer_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_anon_identity(monkeypatch)
    monkeypatch.setattr(
        auth_module.user_client,
        "check_user_exists",
        lambda **kwargs: SimpleNamespace(exists=True, resolved_user_id="should-not-be-used"),
    )
    request = _make_request("/tools", headers={"Authorization": "Bearer a.b.c"})

    with pytest.raises(auth_module.HTTPException) as exc_info:
        auth_module.get_scan_current_user(
            request,
            credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials="a.b.c"),
            x_api_key=None,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid JWT payload"


def test_require_scan_permission_allows_admin_web_user() -> None:
    current_user = auth_module.CurrentUser(
        user_id="admin-1",
        azp="platform-web",
        actor_type="web_user",
        roles={auth_module.PLATFORM_ROLE_ADMIN},
        scopes=set(),
        claims={"sub": "admin-1"},
    )

    assert auth_module.require_scan_permission(current_user) == current_user


def test_require_scan_permission_rejects_web_user_without_scan_role() -> None:
    current_user = auth_module.CurrentUser(
        user_id="viewer-1",
        azp="platform-web",
        actor_type="web_user",
        roles={"VIEWER"},
        scopes=set(),
        claims={"sub": "viewer-1"},
    )

    with pytest.raises(auth_module.HTTPException) as exc_info:
        auth_module.require_scan_permission(current_user)

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "USER or ADMIN role is required for scan endpoints"


def test_require_project_access_allows_web_user_without_platform_role() -> None:
    current_user = auth_module.CurrentUser(
        user_id="viewer-1",
        azp="platform-web",
        actor_type="web_user",
        roles={"VIEWER"},
        scopes=set(),
        claims={"sub": "viewer-1"},
    )

    assert auth_module.require_project_access(current_user) == current_user


def test_basic_scan_routes_use_scan_identity_without_role_gate() -> None:
    basic_route_paths = {
        "/scans/basic/submit",
        "/scans/basic/jobs/{job_id}",
        "/scans/basic/results",
        "/scans/basic/jobs/{job_id}/findings",
        "/scans/basic/jobs/{job_id}/summary",
    }

    seen_paths: set[str] = set()
    for route in gateway_main.app.routes:
        if not isinstance(route, APIRoute) or route.path not in basic_route_paths:
            continue
        seen_paths.add(route.path)
        dependency_calls = {dep.call for dep in route.dependant.dependencies}
        assert auth_module.get_scan_current_user in dependency_calls
        assert auth_module.require_scan_permission not in dependency_calls

    assert seen_paths == basic_route_paths


def test_medium_scan_routes_use_scan_identity_without_role_gate() -> None:
    medium_route_paths = {
        "/scans/medium/submit",
        "/scans/medium/steps/{step_id}",
        "/scans/medium/jobs/{job_id}",
        "/scans/medium/results",
        "/scans/medium/steps/{step_id}/logs/stream",
    }

    seen_paths: set[str] = set()
    for route in gateway_main.app.routes:
        if not isinstance(route, APIRoute) or route.path not in medium_route_paths:
            continue
        seen_paths.add(route.path)
        dependency_calls = {dep.call for dep in route.dependant.dependencies}
        assert auth_module.get_scan_current_user in dependency_calls
        assert auth_module.require_scan_permission not in dependency_calls

    assert seen_paths == medium_route_paths


@pytest.mark.asyncio
async def test_anon_can_create_project_and_is_auto_provisioned(monkeypatch: pytest.MonkeyPatch) -> None:
    anon_user_id = _patch_anon_identity(monkeypatch)
    check_calls = {"count": 0}
    create_calls: list[dict[str, str]] = []
    captured: dict[str, str] = {}

    def _check_user_exists(**kwargs):
        check_calls["count"] += 1
        if check_calls["count"] == 1:
            return SimpleNamespace(exists=False, resolved_user_id="")
        return SimpleNamespace(exists=True, resolved_user_id=anon_user_id)

    def _create_user(**kwargs):
        create_calls.append(kwargs)
        return None

    def _create_project(body, user_id):
        captured["user_id"] = user_id
        return ProjectResponse(
            project_id="project-1",
            name=body.name,
            description=body.description,
            owner_id=user_id,
            created_at=datetime.now(timezone.utc),
            last_modified=datetime.now(timezone.utc),
        )

    monkeypatch.setattr(auth_module.user_client, "check_user_exists", _check_user_exists)
    monkeypatch.setattr(auth_module.user_client, "create_user", _create_user)
    monkeypatch.setattr(project_client, "create_project", _create_project)

    request = _make_request("/projects")
    current_user = auth_module.get_scan_current_user(request, credentials=None, x_api_key=None)
    project = create_project_route(
        CreateProjectRequest(name="Anon Project", description="temp"),
        current_user=current_user,
    )

    assert project.owner_id == anon_user_id
    assert captured["user_id"] == anon_user_id
    assert len(create_calls) == 1
    assert create_calls[0]["user_id"] == anon_user_id
    assert create_calls[0]["username"].startswith("anon-")
    assert create_calls[0]["email"].endswith("@anonymous.local")


@pytest.mark.asyncio
async def test_anon_can_submit_medium_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    anon_user_id = _patch_anon_identity(monkeypatch)
    captured: dict[str, str | int | None] = {}

    monkeypatch.setattr(
        auth_module.user_client,
        "check_user_exists",
        lambda **kwargs: SimpleNamespace(exists=True, resolved_user_id=anon_user_id),
    )

    def _submit_medium_scan(body, user_id, api_key_id=None, api_project_id=None, quota_remaining=None):
        captured["user_id"] = user_id
        captured["quota_remaining"] = quota_remaining
        return MediumScanSubmitResponse(
            job_id="job-1",
            step_id="step-1",
            status="SCAN_STATUS_QUEUED",
            is_idempotent_replay=False,
            queued_at=datetime.now(timezone.utc),
        )

    monkeypatch.setattr(medium_scan_client, "submit_medium_scan", _submit_medium_scan)

    request = _make_request("/scans/medium/submit")
    request.state.quota_remaining = 2
    current_user = auth_module.get_scan_current_user(request, credentials=None, x_api_key=None)
    response = submit_medium_scan_route(
        request,
        MediumScanSubmitRequest(
            project_id="project-1",
            target_value="scanme.nmap.org",
            tool_name="nmap",
            tool_options={},
        ),
        current_user=current_user,
    )

    assert response.job_id == "job-1"
    assert captured["user_id"] == anon_user_id
    assert captured["quota_remaining"] == 2


@pytest.mark.asyncio
async def test_anon_can_read_medium_job_status_with_same_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    anon_user_id = _patch_anon_identity(monkeypatch)
    captured: dict[str, str | None] = {}

    monkeypatch.setattr(
        auth_module.user_client,
        "check_user_exists",
        lambda **kwargs: SimpleNamespace(exists=True, resolved_user_id=anon_user_id),
    )

    def _get_job_status(job_id, user_id, api_key_id=None, api_project_id=None):
        captured["user_id"] = user_id
        return MediumScanJobStatusResponse(
            job_id=job_id,
            project_id="project-1",
            status="JOB_STATUS_RUNNING",
            total_steps=1,
            completed_steps=0,
            failed_steps=0,
            pending_steps=1,
            total_findings=0,
            created_at=datetime.now(timezone.utc),
            started_at=None,
            finished_at=None,
            steps=[],
        )

    monkeypatch.setattr(medium_scan_client, "get_job_status", _get_job_status)

    request = _make_request("/scans/medium/jobs/job-1")
    current_user = auth_module.get_scan_current_user(request, credentials=None, x_api_key=None)
    response = get_medium_job_status_route("job-1", current_user=current_user)

    assert response.job_id == "job-1"
    assert captured["user_id"] == anon_user_id
