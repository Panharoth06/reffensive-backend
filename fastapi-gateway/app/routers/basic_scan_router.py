from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from app.core.config import get_settings
from app.dependencies.auth import CurrentUser, get_scan_current_user
from app.internal.basic_scan_client import basic_scan_client
from app.schemas.basic_scan_schemas import (
    BasicFindingsResponse,
    BasicJobStatusResponse,
    BasicResultsResponse,
    BasicResultsSummaryResponse,
    BasicScanSubmitRequest,
)
from app.utils.scan_helpers import (
    collect_basic_findings,
    stream_basic_submit_response,
    summarize_basic_findings,
)

router = APIRouter(prefix="/scans/basic", tags=["Basic Scans"])


# ============================================================================
# Submission & Streaming
# ============================================================================


@router.post("/submit", summary="Submit basic scan and stream output")
async def submit_basic_scan(
    request: Request,
    body: BasicScanSubmitRequest,
    current_user: CurrentUser = Depends(get_scan_current_user),
) -> StreamingResponse:
    # Basic scan is modeled as one tool execution; step_id stays internal.
    quota_remaining = getattr(request.state, "quota_remaining", None)
    try:
        submit_resp = await asyncio.to_thread(
            basic_scan_client.submit_basic_scan,
            body,
            current_user.user_id,
            current_user.api_key_id,
            current_user.project_id,
            quota_remaining,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    settings = get_settings()
    return stream_basic_submit_response(
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
        job_id=submit_resp.job_id,
        step_id=submit_resp.step_id,
        queued_at=submit_resp.queued_at.isoformat() if submit_resp.queued_at else "",
        redis_url=settings.redis_url,
        poll_interval=settings.scan_stream_poll_interval,
    )


# ============================================================================
# Status & Results
# ============================================================================


@router.get("/jobs/{job_id}", response_model=BasicJobStatusResponse, summary="Get basic job status")
def get_basic_job_status(
    job_id: str,
    current_user: CurrentUser = Depends(get_scan_current_user),
) -> BasicJobStatusResponse:
    return basic_scan_client.get_job_status(
        job_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get("/results", response_model=BasicResultsResponse, summary="Get basic findings/results")
def get_basic_results(
    job_id: str | None = None,
    step_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
    current_user: CurrentUser = Depends(get_scan_current_user),
) -> BasicResultsResponse:
    if not job_id and not step_id:
        raise HTTPException(status_code=400, detail="job_id or step_id is required")
    return basic_scan_client.get_results(
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
        job_id=job_id,
        step_id=step_id,
        limit=limit,
        offset=offset,
    )


# ============================================================================
# Findings & Summary
# ============================================================================


@router.get("/jobs/{job_id}/findings", response_model=BasicFindingsResponse, summary="Get basic findings for a job")
def get_basic_job_findings(
    job_id: str,
    limit: int = 100,
    offset: int = 0,
    current_user: CurrentUser = Depends(get_scan_current_user),
) -> BasicFindingsResponse:
    results = basic_scan_client.get_results(
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
        job_id=job_id,
        limit=limit,
        offset=offset,
    )
    return BasicFindingsResponse(
        scope_id=results.scope_id,
        findings=results.findings,
        total_count=results.total_count,
        limit=results.limit,
        offset=results.offset,
        has_more=results.has_more,
        next_cursor=results.next_cursor,
    )


@router.get("/jobs/{job_id}/summary", response_model=BasicResultsSummaryResponse, summary="Get basic job summary")
def get_basic_job_summary(
    job_id: str,
    current_user: CurrentUser = Depends(get_scan_current_user),
) -> BasicResultsSummaryResponse:
    job = basic_scan_client.get_job_status(
        job_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )
    findings = collect_basic_findings(
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
        job_id=job_id,
    )
    severity_counts, unique_hosts, unique_ports, unique_services, unique_fingerprints = summarize_basic_findings(findings)
    return BasicResultsSummaryResponse(
        scope_id=job_id,
        scope_type="job",
        job_id=job_id,
        status=job.status,
        total_steps=job.total_steps,
        total_findings=len(findings),
        unique_hosts=unique_hosts,
        unique_ports=unique_ports,
        unique_services=unique_services,
        unique_fingerprints=unique_fingerprints,
        severity_counts=severity_counts,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        steps=job.steps,
    )
