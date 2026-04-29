from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.core.config import get_settings
from app.dependencies.auth import CurrentUser, require_scan_permission, require_user_scan_permission
from app.internal.advanced_scan_client import advanced_scan_client
from app.schemas.advanced_scan_schemas import (
    AdvancedFindingsResponse,
    AdvancedJobStatusResponse,
    AdvancedRawOutputResponse,
    AdvancedResultsResponse,
    AdvancedResultsSummaryResponse,
    AdvancedScanSubmitRequest,
    AdvancedScanSubmitResponse,
    AdvancedStepStatusResponse,
    CancelQueuedJobResponse,
    JobParsedDataResponse,
    JobQueuePositionResponse,
    ParsedDataResponse,
    QueueStatusResponse,
)
from app.utils.scan_helpers import (
    fetch_advanced_findings,
    stream_step_logs_response,
)

router = APIRouter(prefix="/scans/advanced", tags=["Advanced Scans"])


# ============================================================================
# Submission & Job/Step Status
# ============================================================================


@router.post("/submit", response_model=AdvancedScanSubmitResponse, summary="Submit advanced scan")
def submit_advanced_scan(
    request: Request,
    body: AdvancedScanSubmitRequest,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> AdvancedScanSubmitResponse:
    quota_remaining = getattr(request.state, "quota_remaining", None)
    return advanced_scan_client.submit_advanced_scan(
        body,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
        quota_remaining=quota_remaining,
    )


@router.get("/steps/{step_id}", response_model=AdvancedStepStatusResponse, summary="Get advanced step status")
def get_advanced_step_status(
    step_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> AdvancedStepStatusResponse:
    return advanced_scan_client.get_step_status(
        step_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get("/jobs/{job_id}", response_model=AdvancedJobStatusResponse, summary="Get advanced job status")
def get_advanced_job_status(
    job_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> AdvancedJobStatusResponse:
    return advanced_scan_client.get_job_status(
        job_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


# ============================================================================
# Results & Findings
# ============================================================================


@router.get("/results", response_model=AdvancedResultsResponse, summary="Get advanced findings/results")
def get_advanced_results(
    job_id: str | None = None,
    step_id: str | None = None,
    severity: list[str] | None = Query(default=None),
    host_contains: str | None = None,
    port_eq: int | None = None,
    fingerprint_eq: str | None = None,
    created_after: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> AdvancedResultsResponse:
    if not job_id and not step_id:
        raise HTTPException(status_code=400, detail="job_id or step_id is required")
    try:
        return advanced_scan_client.get_results(
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
            job_id=job_id,
            step_id=step_id,
            severity_in=severity,
            host_contains=host_contains,
            port_eq=port_eq,
            fingerprint_eq=fingerprint_eq,
            created_after=created_after,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/jobs/{job_id}/findings", response_model=AdvancedFindingsResponse, summary="Get advanced findings for a job")
def get_advanced_job_findings(
    job_id: str,
    severity: list[str] | None = Query(default=None),
    host_contains: str | None = None,
    port_eq: int | None = None,
    fingerprint_eq: str | None = None,
    created_after: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> AdvancedFindingsResponse:
    try:
        return fetch_advanced_findings(
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
            job_id=job_id,
            severity=severity,
            host_contains=host_contains,
            port_eq=port_eq,
            fingerprint_eq=fingerprint_eq,
            created_after=created_after,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/steps/{step_id}/findings", response_model=AdvancedFindingsResponse, summary="Get advanced findings for a step")
def get_advanced_step_findings(
    step_id: str,
    severity: list[str] | None = Query(default=None),
    host_contains: str | None = None,
    port_eq: int | None = None,
    fingerprint_eq: str | None = None,
    created_after: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> AdvancedFindingsResponse:
    try:
        return fetch_advanced_findings(
            user_id=current_user.user_id,
            api_key_id=current_user.api_key_id,
            api_project_id=current_user.project_id,
            step_id=step_id,
            severity=severity,
            host_contains=host_contains,
            port_eq=port_eq,
            fingerprint_eq=fingerprint_eq,
            created_after=created_after,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ============================================================================
# Summaries & Data Retrieval
# ============================================================================


@router.get("/jobs/{job_id}/summary", response_model=AdvancedResultsSummaryResponse, summary="Get advanced job summary")
def get_advanced_job_summary(
    job_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> AdvancedResultsSummaryResponse:
    return advanced_scan_client.get_job_summary(
        job_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get("/steps/{step_id}/summary", response_model=AdvancedResultsSummaryResponse, summary="Get advanced step summary")
def get_advanced_step_summary(
    step_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> AdvancedResultsSummaryResponse:
    return advanced_scan_client.get_step_summary(
        step_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get("/steps/{step_id}/raw-output", response_model=AdvancedRawOutputResponse, summary="Get advanced step raw output")
def get_advanced_step_raw_output(
    step_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> AdvancedRawOutputResponse:
    return advanced_scan_client.get_step_raw_output(
        step_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get("/steps/{step_id}/parsed-data", response_model=ParsedDataResponse, summary="Get advanced step parsed data for table rendering")
def get_advanced_step_parsed_data(
    step_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> ParsedDataResponse:
    return advanced_scan_client.get_parsed_data(
        step_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get("/jobs/{job_id}/parsed-data", response_model=JobParsedDataResponse, summary="Get parsed data for all steps in a job")
def get_advanced_job_parsed_data(
    job_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> JobParsedDataResponse:
    """Returns structured table data for every completed step in a job,
    ordered by step_order. Steps with no data (pending/failed) are omitted.
    Columns are derived from each tool's output_schema; unknown fields are
    placed in discovered_columns for client-side 'Extra Fields' grouping.
    """
    return advanced_scan_client.get_job_parsed_data(
        job_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


# ============================================================================
# Streaming & Queue Management
# ============================================================================


@router.get("/steps/{step_id}/logs/stream", summary="Stream advanced step logs over SSE")
async def stream_advanced_step_logs(
    step_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> StreamingResponse:
    # Verify ownership before streaming
    advanced_scan_client.get_step_status(
        step_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )
    settings = get_settings()
    channel = f"scan:logs:{step_id}"
    try:
        return stream_step_logs_response(
            channel=channel,
            redis_url=settings.redis_url,
            poll_interval=settings.scan_stream_poll_interval,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"failed to stream logs: {exc}") from exc


@router.get("/queue/status", response_model=QueueStatusResponse, summary="Get scan queue status")
def get_scan_queue_status(
    current_user: CurrentUser = Depends(require_scan_permission),
) -> QueueStatusResponse:
    return advanced_scan_client.get_queue_status(
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get("/queue/jobs/{job_id}/position", response_model=JobQueuePositionResponse, summary="Get job queue position")
def get_job_queue_position(
    job_id: str,
    current_user: CurrentUser = Depends(require_scan_permission),
) -> JobQueuePositionResponse:
    return advanced_scan_client.get_job_queue_position(
        job_id=job_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.post("/queue/jobs/{job_id}/cancel", response_model=CancelQueuedJobResponse, summary="Cancel queued job")
def cancel_queued_job(
    job_id: str,
    current_user: CurrentUser = Depends(require_user_scan_permission),
) -> CancelQueuedJobResponse:
    return advanced_scan_client.cancel_queued_job(
        job_id=job_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )
