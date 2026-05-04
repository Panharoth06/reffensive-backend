from __future__ import annotations

import json
from typing import Optional

import grpc
from fastapi import APIRouter, Depends, HTTPException, Query
from sse_starlette.sse import EventSourceResponse

from app.core.config import get_settings
from app.dependencies.auth import CurrentUser, require_scan_permission
from app.internal.grpc.sonarqube_scan_client import sonarqube_scan_client
from app.schemas.sonarqube_scan_schemas import (
    DeleteScanResponse,
    DependencySummaryResponse,
    DependencyListResponse,
    IssueDetailResponse,
    IssueListResponse,
    ScanTaskRefResponse,
    ScanDetailResponse,
    StopScanResponse,
    RetryScanResponse,
    ScanStatusResponse,
    ScanSummaryResponse,
    TriggerScanRequest,
    TriggerScanResponse,
    ProjectScansResponse,
    ScanLogsResponse,
    UserScanTaskRefsResponse,
)
from app.queue.subscriber import ProgressSubscriber
from app.utils.grpc_errors import raise_for_grpc_error

router = APIRouter(prefix="/api/v1/scanner", tags=["Scanner"])


# ============================================================================
# Submission & Status
# ============================================================================


@router.post(
    "/scans",
    response_model=TriggerScanResponse,
    summary="Trigger a new code scan",
)
async def trigger_scan(
    body: TriggerScanRequest,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> TriggerScanResponse:
    """
    Trigger a new code scan on a repository.
    
    The scan is queued asynchronously and processed by the worker.
    Use the returned scan_id to stream progress or fetch results.
    """
    try:
        resp = sonarqube_scan_client.trigger_scan(
            TriggerScanRequest(
                repo_url=body.repo_url,
                branch=body.branch or "main",
                project_key=body.project_key,
            ),
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
        return resp
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to trigger scan") from exc


@router.get(
    "/scans/me",
    response_model=ProjectScansResponse,
    summary="List current user scans",
)
async def list_current_user_scans(
    project_key: Optional[str] = Query(None, description="Optional project key filter"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: CurrentUser = Depends(require_scan_permission),
) -> ProjectScansResponse:
    """Get scans created by the current authenticated user."""
    try:
        return sonarqube_scan_client.list_user_scans(
            project_key=project_key,
            page=page,
            page_size=page_size,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except HTTPException:
        raise
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to list current user scans") from exc


@router.get(
    "/scans/me/ids",
    response_model=UserScanTaskRefsResponse,
    summary="List current user scan IDs",
)
async def list_current_user_scan_ids(
    project_key: Optional[str] = Query(None, description="Optional project key filter"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: CurrentUser = Depends(require_scan_permission),
) -> UserScanTaskRefsResponse:
    """Get lightweight scan references for the current authenticated user."""
    try:
        response = sonarqube_scan_client.list_user_scans(
            project_key=project_key,
            page=page,
            page_size=page_size,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except HTTPException:
        raise
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to list current user scan IDs") from exc

    tasks = [
        ScanTaskRefResponse(scan_id=item.scan_id, project_key=item.project_key)
        for item in response.scans
    ]
    project_keys = sorted({item.project_key for item in tasks if item.project_key})
    return UserScanTaskRefsResponse(
        tasks=tasks,
        project_keys=project_keys,
        page=response.page,
        page_size=response.page_size,
        total=response.total,
    )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get scan detail",
)
async def get_scan_detail(
    scan_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> ScanDetailResponse:
    """Get the full persisted metadata and phase state for a scan."""
    try:
        return sonarqube_scan_client.get_scan_detail(
            scan_id,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to get scan detail") from exc


@router.get(
    "/scans/{scan_id}/status",
    response_model=ScanStatusResponse,
    summary="Get scan status",
)
async def get_scan_status(
    scan_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> ScanStatusResponse:
    """Get the current status and progress of a scan."""
    try:
        return sonarqube_scan_client.get_scan_status(
            scan_id,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to get scan status") from exc


@router.post(
    "/scans/{scan_id}/stop",
    response_model=StopScanResponse,
    summary="Stop a scan",
)
async def stop_scan(
    scan_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> StopScanResponse:
    """Cancel a queued or running scan."""
    try:
        return sonarqube_scan_client.stop_scan(
            scan_id,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to stop scan") from exc


@router.post(
    "/scans/{scan_id}/retry",
    response_model=RetryScanResponse,
    summary="Retry a finished scan",
)
async def retry_scan(
    scan_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> RetryScanResponse:
    """Create a new queued scan using the same repository, branch, and project key."""
    try:
        return sonarqube_scan_client.retry_scan(
            scan_id,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to retry scan") from exc


@router.get(
    "/scans/{scan_id}/stream",
    summary="Stream scan progress (SSE)",
)
async def stream_scan_progress(
    scan_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
):
    """
    Stream real-time progress updates via Server-Sent Events (SSE).
    
    The stream will automatically close when the scan reaches a terminal state
    (SUCCESS, FAILED, or PARTIAL).
    """
    try:
        sonarqube_scan_client.get_scan_status(
            scan_id,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to authorize scan stream") from exc

    settings = get_settings()
    subscriber = ProgressSubscriber(settings.redis_url)

    async def generator():
        try:
            async for event in subscriber.subscribe(scan_id):
                yield {"data": json.dumps(event)}
        finally:
            await subscriber.close()

    return EventSourceResponse(generator())


@router.get(
    "/scans/{scan_id}/logs",
    response_model=ScanLogsResponse,
    summary="Get scan logs",
)
async def get_scan_logs(
    scan_id: str,
    after_sequence_num: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=1000),
    phases: Optional[str] = Query(None, description="Comma-separated phases"),
    current_user: CurrentUser = Depends(require_scan_permission),
) -> ScanLogsResponse:
    try:
        phase_list = [item.strip() for item in (phases or "").split(",") if item.strip()]
        return sonarqube_scan_client.get_scan_logs(
            scan_id=scan_id,
            after_sequence_num=after_sequence_num,
            limit=limit,
            phases=phase_list,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to get scan logs") from exc


@router.get(
    "/scans/{scan_id}/logs/stream",
    summary="Stream scan logs (SSE)",
)
async def stream_scan_logs(
    scan_id: str,
    include_history: bool = Query(True),
    history_limit: int = Query(200, ge=1, le=1000),
    phases: Optional[str] = Query(None, description="Comma-separated phases"),
    current_user: CurrentUser = Depends(require_scan_permission),
):
    phase_list = [item.strip() for item in (phases or "").split(",") if item.strip()]

    def generator():
        try:
            for chunk in sonarqube_scan_client.stream_scan_logs(
                scan_id=scan_id,
                include_history=include_history,
                history_limit=history_limit,
                phases=phase_list,
                user_id=current_user.user_id,
                api_key_id=current_user.api_key_id,
                api_project_id=current_user.project_id,
            ):
                payload = chunk.model_dump(mode="json")
                yield {"data": json.dumps(payload)}
        except grpc.RpcError as exc:
            yield {"event": "error", "data": json.dumps({"detail": exc.details() or "stream failed"})}

    return EventSourceResponse(generator())


# ============================================================================
# Results & Issues
# ============================================================================


@router.get(
    "/scans/{scan_id}/summary",
    response_model=ScanSummaryResponse,
    summary="Get scan summary",
)
async def get_scan_summary(
    scan_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> ScanSummaryResponse:
    """Get the summary of a completed scan (quality gates, metrics, etc.)."""
    try:
        return sonarqube_scan_client.get_scan_summary(
            scan_id,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to get scan summary") from exc


@router.get(
    "/scans/{scan_id}/issues",
    response_model=IssueListResponse,
    summary="List code issues",
)
async def list_issues(
    scan_id: str,
    type_filter: Optional[str] = Query(None, description="Filter by issue type"),
    severity_filter: Optional[str] = Query(None, description="Filter by severity"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: CurrentUser = Depends(require_scan_permission),
) -> IssueListResponse:
    """
    List code issues found in a scan.
    
    Supports filtering by type (BUG, VULNERABILITY, CODE_SMELL, etc.)
    and severity (BLOCKER, CRITICAL, MAJOR, MINOR, INFO).
    """
    try:
        return sonarqube_scan_client.list_issues(
            scan_id=scan_id,
            type_filter=type_filter,
            severity_filter=severity_filter,
            page=page,
            page_size=page_size,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to list issues") from exc


@router.get(
    "/scans/{scan_id}/issues/{issue_key}",
    response_model=IssueDetailResponse,
    summary="Get issue detail",
)
async def get_issue_detail(
    scan_id: str,
    issue_key: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> IssueDetailResponse:
    """Get detailed information about a specific issue, including history and metadata."""
    try:
        return sonarqube_scan_client.get_issue_detail(
            scan_id=scan_id,
            issue_key=issue_key,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to get issue detail") from exc


@router.get(
    "/scans/{scan_id}/files/{file_path}/issues",
    response_model=IssueListResponse,
    summary="Get issues in a file",
)
async def get_file_issues(
    scan_id: str,
    file_path: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> IssueListResponse:
    """Get all issues found in a specific file."""
    try:
        return sonarqube_scan_client.get_file_issues(
            scan_id=scan_id,
            file_path=file_path,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to get file issues") from exc


# ============================================================================
# Dependencies
# ============================================================================


@router.get(
    "/scans/{scan_id}/dependencies",
    response_model=DependencyListResponse,
    summary="List dependencies",
)
async def list_dependencies(
    scan_id: str,
    tool: Optional[str] = Query(None, description="Filter by tool (govulncheck, pip-audit, npm-audit, etc.)"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    languages: list[str] = Query(default=[], description="Filter by languages"),
    outdated_only: bool = Query(False),
    vulnerable_only: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: CurrentUser = Depends(require_scan_permission),
) -> DependencyListResponse:
    """
    List dependency vulnerabilities and outdated packages found in a scan.
    
    Supports filtering by:
    - tool: govulncheck, pip-audit, npm-audit, mvn-dependency-check, etc.
    - severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
    - languages: go, python, node, java, kotlin, php, rust, ruby, dotnet, swift, dart
    - outdated_only: Show only outdated dependencies
    - vulnerable_only: Show only vulnerable dependencies
    """
    try:
        return sonarqube_scan_client.list_dependencies(
            scan_id=scan_id,
            tool=tool,
            severity=severity,
            languages=languages,
            outdated_only=outdated_only,
            vulnerable_only=vulnerable_only,
            page=page,
            page_size=page_size,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to list dependencies") from exc


@router.get(
    "/scans/{scan_id}/dependencies/summary",
    response_model=DependencySummaryResponse,
    summary="Get dependency summary",
)
async def get_dependency_summary(
    scan_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> DependencySummaryResponse:
    """Get a summary of dependency findings (CVEs, outdated packages, licenses)."""
    try:
        return sonarqube_scan_client.get_dependency_summary(
            scan_id,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to get dependency summary") from exc


# ============================================================================
# Project History
# ============================================================================


@router.get(
    "/projects/{project_key}/scans",
    response_model=ProjectScansResponse,
    summary="List project scans",
)
async def list_project_scans(
    project_key: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: CurrentUser = Depends(require_scan_permission),
) -> ProjectScansResponse:
    """Get all scans for a project, with pagination."""
    try:
        return sonarqube_scan_client.list_project_scans(
            project_key=project_key,
            page=page,
            page_size=page_size,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to list project scans") from exc


@router.delete(
    "/scans/{scan_id}",
    response_model=DeleteScanResponse,
    summary="Delete a finished scan",
)
async def delete_scan(
    scan_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> DeleteScanResponse:
    """Delete a finished scan record and its persisted logs."""
    try:
        return sonarqube_scan_client.delete_scan(
            scan_id,
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to delete scan") from exc
