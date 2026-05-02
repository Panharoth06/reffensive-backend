from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from typing import Any, AsyncIterator

import redis.asyncio as redis_async
from fastapi.responses import StreamingResponse

from app.internal.advanced_scan_client import advanced_scan_client
from app.internal.basic_scan_client import basic_scan_client
from app.schemas.advanced_scan_schemas import AdvancedFindingsResponse
from app.schemas.basic_scan_schemas import BasicFinding


async def _close_async_resource(resource) -> None:
    if resource is None:
        return
    close_fn = getattr(resource, "aclose", None) or getattr(resource, "close", None)
    if close_fn is None:
        return
    try:
        result = close_fn()
        if asyncio.iscoroutine(result):
            await result
    except Exception:
        # Cleanup failures should not crash request handlers.
        return


def fetch_advanced_findings(
    *,
    user_id: str,
    api_key_id: str | None = None,
    api_project_id: str | None = None,
    job_id: str | None = None,
    step_id: str | None = None,
    severity: list[str] | None = None,
    host_contains: str | None = None,
    port_eq: int | None = None,
    fingerprint_eq: str | None = None,
    created_after: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> AdvancedFindingsResponse:
    return advanced_scan_client.get_findings(
        user_id=user_id,
        api_key_id=api_key_id,
        api_project_id=api_project_id,
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


def collect_basic_findings(
    *,
    user_id: str,
    job_id: str,
    api_key_id: str | None = None,
    api_project_id: str | None = None,
    page_size: int = 500,
) -> list[BasicFinding]:
    findings: list[BasicFinding] = []
    offset = 0
    while True:
        page = basic_scan_client.get_results(
            user_id=user_id,
            api_key_id=api_key_id,
            api_project_id=api_project_id,
            job_id=job_id,
            limit=page_size,
            offset=offset,
        )
        findings.extend(page.findings)
        if not page.has_more or not page.findings:
            return findings
        offset += page.limit or len(page.findings)


def summarize_basic_findings(findings: list[BasicFinding]) -> tuple[dict[str, int], int, int, int, int]:
    severity_counts: dict[str, int] = {}
    hosts: set[str] = set()
    ports: set[int] = set()
    services: set[tuple[str, int]] = set()
    fingerprints: set[str] = set()

    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        host = finding.host.strip().lower()
        if host:
            hosts.add(host)
        if finding.port > 0:
            ports.add(finding.port)
        if host or finding.port > 0:
            services.add((host, finding.port))
        if finding.fingerprint:
            fingerprints.add(finding.fingerprint)

    return severity_counts, len(hosts), len(ports), len(services), len(fingerprints)


def _decode_pubsub_payload(data: Any) -> tuple[str, dict[str, Any] | None]:
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")

    parsed: dict[str, Any] | None = data if isinstance(data, dict) else None
    if isinstance(data, str):
        payload = data
        try:
            candidate = json.loads(data)
        except json.JSONDecodeError:
            candidate = None
        if isinstance(candidate, dict):
            parsed = candidate
    else:
        payload = json.dumps(data)

    return payload, parsed


def _serialize_basic_parsed_data(parsed_data: Any) -> dict[str, Any] | None:
    if parsed_data is None:
        return None
    if hasattr(parsed_data, "model_dump"):
        return parsed_data.model_dump(mode="json")
    if isinstance(parsed_data, dict):
        return parsed_data
    return None


def _parsed_data_signature(parsed_data: Any) -> str | None:
    payload = _serialize_basic_parsed_data(parsed_data)
    if payload is None:
        return None
    return json.dumps(payload, sort_keys=True, ensure_ascii=True)


def _build_basic_result_payload(
    *,
    job_id: str,
    page: Any,
    offset: int,
    parsed_data_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "job_id": job_id,
        "scope_id": page.scope_id,
        "offset": offset,
        "count": len(page.findings),
        "total_count": page.total_count,
        "findings": [item.model_dump(mode="json") for item in page.findings],
    }
    if getattr(page, "raw_output_inline", None):
        payload["raw_output_inline"] = page.raw_output_inline
    if getattr(page, "raw_output_s3_url", None):
        payload["raw_output_s3_url"] = page.raw_output_s3_url
    if parsed_data_payload is not None:
        payload["parsed_data"] = parsed_data_payload
    return payload


def stream_step_logs_response(*, channel: str, redis_url: str, poll_interval: float) -> StreamingResponse:
    async def event_gen() -> AsyncIterator[str]:
        client = None
        pubsub = None
        try:
            client = redis_async.from_url(redis_url, decode_responses=True)
            pubsub = client.pubsub()
            await pubsub.subscribe(channel)
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message is None:
                    payload = json.dumps({"type": "heartbeat", "ts": int(time.time())})
                    yield f"event: ping\ndata: {payload}\n\n"
                    await asyncio.sleep(poll_interval)
                    continue
                payload, _ = _decode_pubsub_payload(message.get("data"))
                yield f"event: log\ndata: {payload}\n\n"
        except Exception as exc:
            payload = json.dumps({"type": "stream_error", "message": str(exc)})
            yield f"event: error\ndata: {payload}\n\n"
        finally:
            if pubsub is not None:
                try:
                    await pubsub.unsubscribe(channel)
                except Exception:
                    pass
            await _close_async_resource(pubsub)
            await _close_async_resource(client)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def stream_basic_submit_response(
    *,
    user_id: str,
    job_id: str,
    step_id: str,
    api_key_id: str | None,
    api_project_id: str | None,
    queued_at: str,
    redis_url: str,
    poll_interval: float,
) -> StreamingResponse:
    terminal_statuses = {
        "JOB_STATUS_COMPLETED",
        "JOB_STATUS_FAILED",
        "JOB_STATUS_CANCELLED",
        "JOB_STATUS_PARTIAL",
    }
    channel = f"scan:logs:{step_id}"

    async def event_gen() -> AsyncIterator[str]:
        client = None
        pubsub = None
        emitted_findings = 0
        observed_total_findings = 0
        page_size = 200
        last_raw_output_inline = None
        last_raw_output_s3_url = None
        last_parsed_data_payload = None
        last_parsed_data_signature = None
        last_step_completion_status = None
        last_result_sync_at = 0.0

        started_payload = {
            "job_id": job_id,
            "status": "JOB_STATUS_PENDING",
            "queued_at": queued_at,
        }
        yield f"event: scan_started\ndata: {json.dumps(started_payload)}\n\n"

        last_status = "JOB_STATUS_PENDING"
        last_reported_total_findings = 0

        async def fetch_job_status():
            return await asyncio.to_thread(
                basic_scan_client.get_job_status,
                job_id,
                user_id,
                api_key_id,
                api_project_id,
            )

        async def stream_pending_results(*, force_final: bool = False) -> AsyncIterator[str]:
            nonlocal emitted_findings
            observed_total_findings
            nonlocal last_raw_output_inline
            nonlocal last_raw_output_s3_url
            nonlocal last_parsed_data_payload
            nonlocal last_parsed_data_signature

            while True:
                page = await asyncio.to_thread(
                    basic_scan_client.get_results,
                    user_id=user_id,
                    api_key_id=api_key_id,
                    api_project_id=api_project_id,
                    job_id=job_id,
                    limit=page_size,
                    offset=emitted_findings,
                )
                parsed_data_payload = _serialize_basic_parsed_data(page.parsed_data)
                parsed_data_signature = _parsed_data_signature(page.parsed_data)
                observed_total_findings = max(observed_total_findings, page.total_count, emitted_findings)
                if not page.findings:
                    if force_final:
                        if page.raw_output_inline:
                            last_raw_output_inline = page.raw_output_inline
                        if page.raw_output_s3_url:
                            last_raw_output_s3_url = page.raw_output_s3_url
                    if parsed_data_payload is not None and parsed_data_signature != last_parsed_data_signature:
                        last_parsed_data_payload = parsed_data_payload
                        last_parsed_data_signature = parsed_data_signature
                        result_payload = _build_basic_result_payload(
                            job_id=job_id,
                            page=page,
                            offset=emitted_findings,
                            parsed_data_payload=parsed_data_payload,
                        )
                        if page.raw_output_inline:
                            last_raw_output_inline = page.raw_output_inline
                        if page.raw_output_s3_url:
                            last_raw_output_s3_url = page.raw_output_s3_url
                        yield f"event: result\ndata: {json.dumps(result_payload)}\n\n"
                    return

                result_payload = _build_basic_result_payload(
                    job_id=job_id,
                    page=page,
                    offset=emitted_findings,
                    parsed_data_payload=parsed_data_payload,
                )
                if page.raw_output_inline:
                    last_raw_output_inline = page.raw_output_inline
                if page.raw_output_s3_url:
                    last_raw_output_s3_url = page.raw_output_s3_url
                if parsed_data_payload is not None:
                    last_parsed_data_payload = parsed_data_payload
                    last_parsed_data_signature = parsed_data_signature
                yield f"event: result\ndata: {json.dumps(result_payload)}\n\n"

                emitted_findings += len(page.findings)
                observed_total_findings = max(observed_total_findings, emitted_findings)
                if not page.has_more:
                    return

        def resolved_total_findings(job_total_findings: int) -> int:
            return max(job_total_findings, observed_total_findings, emitted_findings)

        try:
            try:
                client = redis_async.from_url(redis_url, decode_responses=True)
                pubsub = client.pubsub()
                await pubsub.subscribe(channel)
            except Exception as exc:
                payload = json.dumps({"type": "log_stream_unavailable", "message": str(exc)})
                yield f"event: warning\ndata: {payload}\n\n"
                await _close_async_resource(pubsub)
                await _close_async_resource(client)
                pubsub = None
                client = None

            if pubsub is None:
                while True:
                    job = await fetch_job_status()
                    effective_total_findings = resolved_total_findings(job.total_findings)
                    if job.status != last_status or effective_total_findings != last_reported_total_findings:
                        status_payload = {
                            "job_id": job_id,
                            "status": job.status,
                            "total_findings": effective_total_findings,
                        }
                        yield f"event: status\ndata: {json.dumps(status_payload)}\n\n"
                        last_status = job.status
                        last_reported_total_findings = effective_total_findings

                    async for result_event in stream_pending_results(force_final=job.status in terminal_statuses):
                        yield result_event

                    if job.status in terminal_statuses:
                        effective_total_findings = resolved_total_findings(job.total_findings)
                        if effective_total_findings != last_reported_total_findings:
                            status_payload = {
                                "job_id": job_id,
                                "status": job.status,
                                "total_findings": effective_total_findings,
                            }
                            yield f"event: status\ndata: {json.dumps(status_payload)}\n\n"
                            last_reported_total_findings = effective_total_findings
                        done_payload = {
                            "job_id": job_id,
                            "status": job.status,
                            "total_findings": effective_total_findings,
                            "finished_at": job.finished_at.isoformat() if job.finished_at else "",
                            "raw_output_inline": last_raw_output_inline,
                            "raw_output_s3_url": last_raw_output_s3_url,
                            "parsed_data": last_parsed_data_payload,
                        }
                        yield f"event: done\ndata: {json.dumps(done_payload)}\n\n"
                        return

                    ping_payload = json.dumps({"type": "heartbeat", "ts": int(time.time())})
                    yield f"event: ping\ndata: {ping_payload}\n\n"
                    await asyncio.sleep(poll_interval)

            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message is None:
                    ping_payload = json.dumps({"type": "heartbeat", "ts": int(time.time())})
                    yield f"event: ping\ndata: {ping_payload}\n\n"
                    await asyncio.sleep(poll_interval)
                    continue

                payload, log_event = _decode_pubsub_payload(message.get("data"))
                yield f"event: log\ndata: {payload}\n\n"

                is_final_chunk = False
                completion_status = None
                if log_event is not None:
                    candidate = log_event.get("completion_status")
                    if isinstance(candidate, str) and candidate:
                        completion_status = candidate
                    is_final_chunk = bool(log_event.get("is_final_chunk"))

                if completion_status and completion_status != last_step_completion_status:
                    last_step_completion_status = completion_status
                    job = await fetch_job_status()
                    effective_total_findings = resolved_total_findings(job.total_findings)
                    if job.status != last_status or effective_total_findings != last_reported_total_findings:
                        status_payload = {
                            "job_id": job_id,
                            "status": job.status,
                            "total_findings": effective_total_findings,
                        }
                        yield f"event: status\ndata: {json.dumps(status_payload)}\n\n"
                        last_status = job.status
                        last_reported_total_findings = effective_total_findings

                now_monotonic = time.monotonic()
                if is_final_chunk or now_monotonic-last_result_sync_at >= poll_interval:
                    async for result_event in stream_pending_results(force_final=is_final_chunk):
                        yield result_event
                    last_result_sync_at = time.monotonic()

                if not is_final_chunk:
                    continue

                job = await fetch_job_status()
                effective_total_findings = resolved_total_findings(job.total_findings)
                if job.status != last_status or effective_total_findings != last_reported_total_findings:
                    status_payload = {
                        "job_id": job_id,
                        "status": job.status,
                        "total_findings": effective_total_findings,
                    }
                    yield f"event: status\ndata: {json.dumps(status_payload)}\n\n"
                    last_status = job.status
                    last_reported_total_findings = effective_total_findings

                async for result_event in stream_pending_results(force_final=True):
                    yield result_event

                effective_total_findings = resolved_total_findings(job.total_findings)
                if effective_total_findings != last_reported_total_findings:
                    status_payload = {
                        "job_id": job_id,
                        "status": job.status,
                        "total_findings": effective_total_findings,
                    }
                    yield f"event: status\ndata: {json.dumps(status_payload)}\n\n"
                    last_reported_total_findings = effective_total_findings

                done_payload = {
                    "job_id": job_id,
                    "status": job.status,
                    "total_findings": effective_total_findings,
                    "finished_at": job.finished_at.isoformat() if job.finished_at else "",
                    "raw_output_inline": last_raw_output_inline,
                    "raw_output_s3_url": last_raw_output_s3_url,
                    "parsed_data": last_parsed_data_payload,
                }
                yield f"event: done\ndata: {json.dumps(done_payload)}\n\n"
                return
        except Exception as exc:
            error_payload = {
                "job_id": job_id,
                "status": "JOB_STATUS_FAILED",
                "error": str(exc),
            }
            yield f"event: error\ndata: {json.dumps(error_payload)}\n\n"
        finally:
            if pubsub is not None:
                try:
                    await pubsub.unsubscribe(channel)
                except Exception:
                    pass
            await _close_async_resource(pubsub)
            await _close_async_resource(client)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
