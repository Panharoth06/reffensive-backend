from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

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
