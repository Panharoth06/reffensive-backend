from __future__ import annotations

import asyncio
import json
import time
from typing import AsyncIterator

import redis.asyncio as redis_async
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.core.config import get_settings
from app.dependencies.auth import CurrentUser, get_scan_current_user, require_scan_permission
from app.internal.medium_scan_client import medium_scan_client
from app.schemas.medium_scan_schemas import (
    MediumJobParsedDataResponse,
    MediumScanJobStatusResponse,
    MediumParsedDataResponse,
    MediumScanResultsResponse,
    MediumScanStepStatusResponse,
    MediumScanSubmitRequest,
    MediumScanSubmitResponse,
)

router = APIRouter(prefix="/scans/medium", tags=["Medium Scans"])


@router.post("/submit", response_model=MediumScanSubmitResponse, summary="Submit medium scan")
def submit_medium_scan(
    request: Request,
    body: MediumScanSubmitRequest,
    current_user: CurrentUser = Depends(get_scan_current_user),
) -> MediumScanSubmitResponse:
    """Submit a medium scan with admin-allowed options.

    Users can provide options from the tool's scan_config.medium schema.
    The go-server validates these options against the allowed schema,
    applies defaults, and builds CLI flags accordingly.
    """
    return medium_scan_client.submit_medium_scan(
        body,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
        quota_remaining=getattr(request.state, "quota_remaining", None),
    )


@router.get("/steps/{step_id}", response_model=MediumScanStepStatusResponse, summary="Get medium scan step status")
def get_medium_step_status(
    step_id: str,
    current_user: CurrentUser = Depends(get_scan_current_user),
) -> MediumScanStepStatusResponse:
    return medium_scan_client.get_step_status(
        step_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get("/jobs/{job_id}", response_model=MediumScanJobStatusResponse, summary="Get medium scan job status")
def get_medium_job_status(
    job_id: str,
    current_user: CurrentUser = Depends(get_scan_current_user),
) -> MediumScanJobStatusResponse:
    return medium_scan_client.get_job_status(
        job_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get("/results", response_model=MediumScanResultsResponse, summary="Get medium scan results")
def get_medium_results(
    job_id: str | None = None,
    step_id: str | None = None,
    current_user: CurrentUser = Depends(get_scan_current_user),
) -> MediumScanResultsResponse:
    if not job_id and not step_id:
        raise HTTPException(status_code=400, detail="job_id or step_id is required")
    return medium_scan_client.get_results(
        job_id=job_id,
        step_id=step_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get("/steps/{step_id}/parsed-data", response_model=MediumParsedDataResponse, summary="Get medium step parsed data")
def get_medium_step_parsed_data(
    step_id: str,
    current_user: CurrentUser = Depends(get_scan_current_user),
) -> MediumParsedDataResponse:
    return medium_scan_client.get_parsed_data(
        step_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get("/jobs/{job_id}/parsed-data", response_model=MediumJobParsedDataResponse, summary="Get parsed data for all medium job steps")
def get_medium_job_parsed_data(
    job_id: str,
    current_user: CurrentUser = Depends(get_scan_current_user),
) -> MediumJobParsedDataResponse:
    return medium_scan_client.get_job_parsed_data(
        job_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get("/steps/{step_id}/logs/stream", summary="Stream medium scan step logs over SSE")
async def stream_medium_step_logs(
    step_id: str,
    current_user: CurrentUser = Depends(get_scan_current_user),
) -> StreamingResponse:
    # Verify ownership before streaming
    medium_scan_client.get_step_status(
        step_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )
    settings = get_settings()
    channel = f"scan:logs:{step_id}"

    async def event_generator() -> AsyncIterator[str]:
        client = redis_async.from_url(settings.redis_url, decode_responses=True)
        pubsub = client.pubsub()
        try:
            await pubsub.subscribe(channel)
            yield "event: ready\ndata: {\"status\":\"subscribed\"}\n\n"
            last_heartbeat = time.monotonic()
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message.get("type") == "message":
                    payload = message.get("data", "")
                    if not isinstance(payload, str):
                        payload = json.dumps(payload, ensure_ascii=True)
                    yield f"data: {payload}\n\n"

                now = time.monotonic()
                if now - last_heartbeat >= 15:
                    yield "event: heartbeat\ndata: {}\n\n"
                    last_heartbeat = now
                await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error_payload = json.dumps({"error": str(exc)}, ensure_ascii=True)
            yield f"event: stream-error\ndata: {error_payload}\n\n"
        finally:
            try:
                try:
                    await pubsub.unsubscribe(channel)
                except Exception:
                    pass
                try:
                    await pubsub.close()
                except Exception:
                    pass
            finally:
                try:
                    await client.close()
                except Exception:
                    pass

    return StreamingResponse(event_generator(), media_type="text/event-stream")
