from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import httpx
from fastapi import FastAPI
from fastapi import HTTPException

from app.dependencies.auth import CurrentUser
from app.routers import scanner as scanner_router
from app.schemas.sonarqube_scan_schemas import ProjectScanResponse, ProjectScansResponse


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
async def test_list_current_user_scans_uses_current_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _fake_list_user_scans(*, project_key, page, page_size, user_id, api_key_id, api_project_id):
        captured.update(
            {
                "project_key": project_key,
                "page": page,
                "page_size": page_size,
                "user_id": user_id,
                "api_key_id": api_key_id,
                "api_project_id": api_project_id,
            }
        )
        return ProjectScansResponse(
            scans=[
                ProjectScanResponse(
                    scan_id="scan-1",
                    project_key="proj-1",
                    branch="main",
                    status="PENDING",
                    progress=0,
                    created_at=datetime(2026, 4, 28, tzinfo=UTC),
                )
            ],
            page=page,
            page_size=page_size,
            total=1,
        )

    monkeypatch.setattr(scanner_router.sonarqube_scan_client, "list_user_scans", _fake_list_user_scans)

    response = await scanner_router.list_current_user_scans(
        project_key="proj-1",
        page=2,
        page_size=25,
        current_user=_make_current_user(),
    )

    assert captured == {
        "project_key": "proj-1",
        "page": 2,
        "page_size": 25,
        "user_id": "user-1",
        "api_key_id": None,
        "api_project_id": None,
    }
    assert response.total == 1
    assert response.scans[0].scan_id == "scan-1"


@pytest.mark.asyncio
async def test_list_current_user_scan_ids_returns_lightweight_refs(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_list_user_scans(*, project_key, page, page_size, user_id, api_key_id, api_project_id):
        return ProjectScansResponse(
            scans=[
                ProjectScanResponse(
                    scan_id="scan-2",
                    project_key="proj-b",
                    branch="main",
                    status="SUCCESS",
                    progress=100,
                ),
                ProjectScanResponse(
                    scan_id="scan-3",
                    project_key="proj-a",
                    branch="develop",
                    status="FAILED",
                    progress=100,
                ),
                ProjectScanResponse(
                    scan_id="scan-4",
                    project_key="proj-b",
                    branch="main",
                    status="PENDING",
                    progress=0,
                ),
            ],
            page=page,
            page_size=page_size,
            total=3,
        )

    monkeypatch.setattr(scanner_router.sonarqube_scan_client, "list_user_scans", _fake_list_user_scans)

    response = await scanner_router.list_current_user_scan_ids(
        project_key=None,
        page=1,
        page_size=50,
        current_user=_make_current_user(),
    )

    assert response.total == 3
    assert response.project_keys == ["proj-a", "proj-b"]
    assert [item.model_dump() for item in response.tasks] == [
        {"scan_id": "scan-2", "project_key": "proj-b"},
        {"scan_id": "scan-3", "project_key": "proj-a"},
        {"scan_id": "scan-4", "project_key": "proj-b"},
    ]


@pytest.mark.asyncio
async def test_list_current_user_scans_preserves_http_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_http_exception(**_kwargs):
        raise HTTPException(status_code=400, detail="invalid user_id")

    monkeypatch.setattr(scanner_router.sonarqube_scan_client, "list_user_scans", _raise_http_exception)

    with pytest.raises(HTTPException) as exc_info:
        await scanner_router.list_current_user_scans(
            project_key=None,
            page=1,
            page_size=50,
            current_user=_make_current_user(),
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "invalid user_id"


@pytest.mark.asyncio
async def test_list_current_user_scan_ids_preserves_http_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_http_exception(**_kwargs):
        raise HTTPException(status_code=503, detail="scanner backend unavailable")

    monkeypatch.setattr(scanner_router.sonarqube_scan_client, "list_user_scans", _raise_http_exception)

    with pytest.raises(HTTPException) as exc_info:
        await scanner_router.list_current_user_scan_ids(
            project_key=None,
            page=1,
            page_size=50,
            current_user=_make_current_user(),
        )

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "scanner backend unavailable"


@pytest.mark.asyncio
async def test_scans_me_route_prefers_static_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    app = FastAPI()
    app.include_router(scanner_router.router)
    app.dependency_overrides[scanner_router.require_scan_permission] = _make_current_user

    def _fake_list_user_scans(*, project_key, page, page_size, user_id, api_key_id, api_project_id):
        return ProjectScansResponse(
            scans=[
                ProjectScanResponse(
                    scan_id="scan-5",
                    project_key="proj-static",
                    branch="main",
                    status="SUCCESS",
                    progress=100,
                    created_at=datetime(2026, 5, 4, tzinfo=UTC),
                )
            ],
            page=page,
            page_size=page_size,
            total=1,
        )

    def _fake_get_scan_detail(*_args, **_kwargs):
        raise AssertionError("dynamic scan detail route should not handle /scans/me")

    monkeypatch.setattr(scanner_router.sonarqube_scan_client, "list_user_scans", _fake_list_user_scans)
    monkeypatch.setattr(scanner_router.sonarqube_scan_client, "get_scan_detail", _fake_get_scan_detail)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/v1/scanner/scans/me")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["scans"][0]["scan_id"] == "scan-5"
