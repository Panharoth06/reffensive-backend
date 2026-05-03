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
from app.schemas.sonarqube_scan_schemas import (
    DeleteScanResponse,
    RetryScanResponse,
    ScanDetailResponse,
    StopScanResponse,
)


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
async def test_get_scan_detail_uses_current_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _fake_get_scan_detail(scan_id: str, *, user_id, api_key_id, api_project_id):
        captured.update(
            {
                "scan_id": scan_id,
                "user_id": user_id,
                "api_key_id": api_key_id,
                "api_project_id": api_project_id,
            }
        )
        return ScanDetailResponse(
            scan_id=scan_id,
            project_key="proj-1",
            sonar_project_key="proj-1:scan-1",
            repo_url="https://example.com/repo.git",
            branch="main",
            status="CANCELLED",
            progress=100,
            created_at=datetime(2026, 5, 4, tzinfo=UTC),
        )

    monkeypatch.setattr(scanner_router.sonarqube_scan_client, "get_scan_detail", _fake_get_scan_detail)

    response = await scanner_router.get_scan_detail(
        scan_id="scan-1",
        current_user=_make_current_user(),
    )

    assert captured == {
        "scan_id": "scan-1",
        "user_id": "user-1",
        "api_key_id": None,
        "api_project_id": None,
    }
    assert response.status == "CANCELLED"


@pytest.mark.asyncio
async def test_scan_action_routes_forward_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, tuple[str, str | None, str | None, str]] = {}

    def _fake_stop_scan(scan_id: str, *, user_id, api_key_id, api_project_id):
        captured["stop"] = (scan_id, user_id, api_key_id, api_project_id)
        return StopScanResponse(scan_id=scan_id, status="CANCELLED", message="scan cancelled by user")

    def _fake_retry_scan(scan_id: str, *, user_id, api_key_id, api_project_id):
        captured["retry"] = (scan_id, user_id, api_key_id, api_project_id)
        return RetryScanResponse(
            source_scan_id=scan_id,
            scan_id="scan-2",
            status="PENDING",
            created_at=datetime(2026, 5, 4, tzinfo=UTC),
        )

    def _fake_delete_scan(scan_id: str, *, user_id, api_key_id, api_project_id):
        captured["delete"] = (scan_id, user_id, api_key_id, api_project_id)
        return DeleteScanResponse(scan_id=scan_id, deleted=True)

    monkeypatch.setattr(scanner_router.sonarqube_scan_client, "stop_scan", _fake_stop_scan)
    monkeypatch.setattr(scanner_router.sonarqube_scan_client, "retry_scan", _fake_retry_scan)
    monkeypatch.setattr(scanner_router.sonarqube_scan_client, "delete_scan", _fake_delete_scan)

    current_user = _make_current_user()
    stop_response = await scanner_router.stop_scan(scan_id="scan-1", current_user=current_user)
    retry_response = await scanner_router.retry_scan(scan_id="scan-1", current_user=current_user)
    delete_response = await scanner_router.delete_scan(scan_id="scan-1", current_user=current_user)

    assert stop_response.status == "CANCELLED"
    assert retry_response.scan_id == "scan-2"
    assert delete_response.deleted is True
    assert captured == {
        "stop": ("scan-1", "user-1", None, None),
        "retry": ("scan-1", "user-1", None, None),
        "delete": ("scan-1", "user-1", None, None),
    }
