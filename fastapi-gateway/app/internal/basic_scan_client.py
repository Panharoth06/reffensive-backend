from __future__ import annotations

import base64
import shlex
from datetime import datetime, timezone
from typing import List, Optional

import grpc
from fastapi import HTTPException, status

from app.gen import basic_scan_pb2, basic_scan_pb2_grpc
from app.internal.advanced_scan_client import advanced_scan_client
from app.internal.tool_client import tool_client
from app.schemas.basic_scan_schemas import (
    BasicFinding,
    BasicJobStatusResponse,
    BasicParsedDataColumn,
    BasicParsedDataResponse,
    BasicResultsResponse,
    BasicScanSubmitRequest,
    BasicScanSubmitResponse,
    BasicStepStatusResponse,
    BasicStepSummary,
)
from app.schemas.tool_schemas import ScanPreset, ToolResponse
from app.utils.grpc_errors import raise_for_grpc_error

KEYWORD_LIGHT = "light"
KEYWORD_DEEP = "deep"

_LIGHT_PRESET_ALIASES = {
    "light",
    "fast",
    "quick",
    "basic",
    "default",
    "passive",
    "safe",
    "recon",
}

_DEEP_PRESET_ALIASES = {
    "deep",
    "full",
    "comprehensive",
    "aggressive",
    "thorough",
    "complete",
    "detailed",
    "all",
}


def _ts(proto_ts) -> Optional[datetime]:
    if proto_ts is None or (proto_ts.seconds == 0 and proto_ts.nanos == 0):
        return None
    return datetime.fromtimestamp(proto_ts.seconds, tz=timezone.utc)


def _enum_name(enum_cls, value: int) -> str:
    try:
        return enum_cls.Name(value)
    except Exception:
        return str(value)


def _normalize_text(value: str) -> str:
    return value.strip()


def _normalize_name(value: str) -> str:
    return _normalize_text(value).lower()


def _tokenize_preset_fragment(raw: str) -> list[str]:
    try:
        return shlex.split(raw)
    except ValueError as exc:
        raise ValueError(f"invalid preset flag fragment {raw!r}: {exc}") from exc


def _expand_keyword_preset_flags(preset_name: str, raw_flags: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(raw_flags):
        fragment = _normalize_text(raw_flags[i])
        i += 1
        if not fragment:
            continue

        tokens = _tokenize_preset_fragment(fragment)
        if not tokens:
            continue
        if not tokens[0].startswith("-"):
            raise ValueError(
                f"invalid preset {preset_name!r}: flag fragment must start with '-' (got {fragment!r})"
            )

        # Support "-flag value" as a single fragment.
        if len(tokens) > 1:
            if any(token.startswith("-") for token in tokens[1:]):
                raise ValueError(
                    f"invalid preset {preset_name!r}: unsupported flag fragment {fragment!r}"
                )
            out.append(f"{tokens[0]}={' '.join(tokens[1:])}")
            continue

        token = tokens[0]
        if "=" in token:
            out.append(token)
            continue

        # Support token-pair list form: ["-p", "22,8080,5432"].
        if i < len(raw_flags):
            next_fragment = _normalize_text(raw_flags[i])
            if next_fragment:
                next_tokens = _tokenize_preset_fragment(next_fragment)
                if len(next_tokens) == 1 and not next_tokens[0].startswith("-"):
                    out.append(f"{token}={next_tokens[0]}")
                    i += 1
                    continue

        out.append(token)
    return out


def _resolve_tool_by_name(tool_name: str) -> ToolResponse:
    normalized = _normalize_name(tool_name)
    if not normalized:
        raise ValueError("tool is required")

    tools = tool_client.list_tools(active_only=True)
    for item in tools:
        if _normalize_name(item.tool_name) == normalized:
            return item

    raise ValueError(f"tool {tool_name!r} is not available")


def _resolve_preset_flags(*, tool: ToolResponse, preset: Optional[str]) -> list[str]:
    """Resolve a preset name to its expanded flag list.

    Resolution order:
    1. Exact match against scan_config.basic.presets[].name (case-insensitive).
    2. Light/deep alias matching for backward compat.
    3. Defaults to the first preset when preset is None.
    Raises ValueError listing available presets if the name is not matched.
    """
    presets: list[ScanPreset] = []
    if tool.scan_config is not None and tool.scan_config.basic is not None:
        presets = list(tool.scan_config.basic.presets)

    if not presets:
        return []

    # Default: use first preset.
    if not preset:
        p = presets[0]
        return _expand_keyword_preset_flags(p.name, p.flags)

    normalized = _normalize_name(preset)

    # Pass 1: exact name match.
    for p in presets:
        if _normalize_name(p.name) == normalized:
            return _expand_keyword_preset_flags(p.name, p.flags)

    # Pass 2: light/deep alias fallback.
    if normalized in _LIGHT_PRESET_ALIASES:
        selected = _select_profile_preset(presets, KEYWORD_LIGHT)
    elif normalized in _DEEP_PRESET_ALIASES:
        selected = _select_profile_preset(presets, KEYWORD_DEEP)
    else:
        available = ", ".join(f"{p.name!r}" for p in presets)
        raise ValueError(
            f"unknown preset {preset!r} for tool {tool.tool_name!r}. "
            f"Available: {available}"
        )

    if selected is None:
        return []
    return _expand_keyword_preset_flags(selected.name, selected.flags)


def _select_profile_preset(presets: list[ScanPreset], profile: str) -> Optional[ScanPreset]:
    if not presets:
        return None

    aliases = _LIGHT_PRESET_ALIASES if profile == KEYWORD_LIGHT else _DEEP_PRESET_ALIASES
    exact = KEYWORD_LIGHT if profile == KEYWORD_LIGHT else KEYWORD_DEEP

    # First pass: exact match.
    for preset in presets:
        if _normalize_name(preset.name) == exact:
            return preset

    # Second pass: alias token match.
    for preset in presets:
        name = _normalize_name(preset.name)
        tokens = set(name.replace("-", " ").replace("_", " ").split())
        if tokens & aliases:
            return preset

    # Fallback: first preset for light, second (or first) for deep.
    if profile == KEYWORD_LIGHT:
        return presets[0]
    if len(presets) >= 2:
        return presets[1]
    return presets[0]


class BasicScanClient:
    def __init__(self) -> None:
        import os

        grpc_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051")
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = basic_scan_pb2_grpc.BasicScanServiceStub(self.channel)

    def _make_stub_with_user(
        self,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
        quota_remaining: int | None = None,
    ) -> basic_scan_pb2_grpc.BasicScanServiceStub:
        interceptor = _UserIdMetadataInterceptor(
            user_id,
            api_key_id=api_key_id,
            api_project_id=api_project_id,
            quota_remaining=quota_remaining,
        )
        intercepted_channel = grpc.intercept_channel(self.channel, interceptor)
        return basic_scan_pb2_grpc.BasicScanServiceStub(intercepted_channel)

    def submit_basic_scan(
        self,
        body: BasicScanSubmitRequest,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
        quota_remaining: int | None = None,
    ) -> BasicScanSubmitResponse:
        tool = _resolve_tool_by_name(body.tool)
        preset_flags = _resolve_preset_flags(tool=tool, preset=body.preset)

        req = basic_scan_pb2.SubmitScanRequest(
            project_id=body.project_id,
            target=body.target,
            target_id="",
            tool_name=tool.tool_name,
            tool_args={},
            custom_flags=preset_flags,
            idempotency_key="",
        )
        try:
            stub = self._make_stub_with_user(
                user_id,
                api_key_id=api_key_id,
                api_project_id=api_project_id,
                quota_remaining=quota_remaining,
            )
            resp = stub.SubmitScan(req)
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                raise HTTPException(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    detail=e.details() or "gRPC request timed out",
                ) from e
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=e.details() or "gRPC request failed",
            ) from e

        return BasicScanSubmitResponse(
            job_id=resp.job_id,
            step_id=resp.step_id,
            status=_enum_name(basic_scan_pb2.StepStatus, resp.status),
            is_idempotent_replay=resp.is_idempotent_replay,
            original_request_id=resp.original_request_id or None,
            queued_at=_ts(resp.queued_at),
        )

    def get_step_status(
        self,
        step_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> BasicStepStatusResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.GetStepStatus(basic_scan_pb2.GetStepStatusRequest(step_id=step_id))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        return BasicStepStatusResponse(
            step_id=resp.step_id,
            job_id=resp.job_id,
            tool_name=resp.tool_name,
            status=_enum_name(basic_scan_pb2.StepStatus, resp.status),
            exit_code=resp.exit_code,
            error_message=resp.error_message or None,
            queued_at=_ts(resp.queued_at),
            started_at=_ts(resp.started_at),
            finished_at=_ts(resp.finished_at),
            duration_ms=resp.duration_ms,
            findings_count=resp.findings_count,
            raw_output_location=resp.raw_output_location or None,
            has_parsed_results=resp.has_parsed_results,
        )

    def get_job_status(
        self,
        job_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> BasicJobStatusResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.GetJobStatus(basic_scan_pb2.GetJobStatusRequest(job_id=job_id))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        steps: List[BasicStepSummary] = []
        for step in resp.steps:
            steps.append(
                BasicStepSummary(
                    step_id=step.step_id,
                    tool_name=step.tool_name,
                    step_order=step.step_order,
                    status=_enum_name(basic_scan_pb2.StepStatus, step.status),
                    findings_count=step.findings_count,
                    started_at=_ts(step.started_at),
                    finished_at=_ts(step.finished_at),
                )
            )

        return BasicJobStatusResponse(
            job_id=resp.job_id,
            project_id=resp.project_id,
            status=_enum_name(basic_scan_pb2.JobStatus, resp.status),
            total_steps=resp.total_steps,
            completed_steps=resp.completed_steps,
            failed_steps=resp.failed_steps,
            pending_steps=resp.pending_steps,
            total_findings=resp.total_findings,
            created_at=_ts(resp.created_at),
            started_at=_ts(resp.started_at),
            finished_at=_ts(resp.finished_at),
            steps=steps,
        )

    def get_results(
        self,
        *,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
        job_id: Optional[str] = None,
        step_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> BasicResultsResponse:
        if not job_id and not step_id:
            raise ValueError("job_id or step_id is required")

        scope = {"step_id": step_id} if step_id else {"job_id": job_id}
        req = basic_scan_pb2.GetResultsRequest(
            **scope,
            pagination=basic_scan_pb2.Pagination(limit=max(1, limit), offset=max(0, offset)),
        )
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.GetResults(req)
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        findings: List[BasicFinding] = []
        for item in resp.findings:
            findings.append(
                BasicFinding(
                    finding_id=item.finding_id,
                    step_id=item.step_id,
                    job_id=item.job_id,
                    title=item.title,
                    severity=_enum_name(basic_scan_pb2.Severity, item.severity),
                    fingerprint=item.fingerprint,
                    host=item.host,
                    port=item.port,
                    protocol=item.protocol,
                    url=item.url,
                    description=item.description,
                    remediation=item.remediation,
                    references=list(item.references),
                    metadata=dict(item.metadata),
                    tags=dict(item.tags),
                    created_at=_ts(item.created_at),
                )
            )

        raw_output_inline: Optional[str] = None
        raw_output_s3_url: Optional[str] = None
        raw_variant = resp.WhichOneof("raw_output")
        if raw_variant == "raw_output_inline":
            raw_output_inline = base64.b64encode(resp.raw_output_inline).decode("ascii")
        elif raw_variant == "raw_output_s3_url":
            raw_output_s3_url = resp.raw_output_s3_url

        pagination = resp.pagination
        parsed_data: Optional[BasicParsedDataResponse] = None
        resolved_step_id = step_id
        if not resolved_step_id and job_id:
            job = self.get_job_status(
                job_id,
                user_id=user_id,
                api_key_id=api_key_id,
                api_project_id=api_project_id,
            )
            if job.steps:
                resolved_step_id = job.steps[0].step_id

        if resolved_step_id:
            try:
                advanced_parsed = advanced_scan_client.get_parsed_data(
                    resolved_step_id,
                    user_id=user_id,
                    api_key_id=api_key_id,
                    api_project_id=api_project_id,
                )
                parsed_data = BasicParsedDataResponse(
                    step_id=advanced_parsed.step_id,
                    job_id=advanced_parsed.job_id,
                    tool_name=advanced_parsed.tool_name,
                    parse_method=advanced_parsed.parse_method,
                    line_count=advanced_parsed.line_count,
                    findings_count=advanced_parsed.findings_count,
                    lines=list(advanced_parsed.lines),
                    findings=[
                        BasicFinding(
                            finding_id=item.finding_id,
                            step_id=item.step_id,
                            job_id=item.job_id,
                            title=item.title,
                            severity=item.severity,
                            fingerprint=item.fingerprint,
                            host=item.host,
                            port=item.port,
                            protocol=item.protocol,
                            url=item.url,
                            description=item.description,
                            remediation=item.remediation,
                            references=list(item.references),
                            metadata=dict(item.metadata),
                            tags=dict(item.tags),
                            created_at=item.created_at,
                        )
                        for item in advanced_parsed.findings
                    ],
                    columns=[
                        BasicParsedDataColumn(
                            key=col.key,
                            label=col.label,
                            type=col.type,
                            description=col.description,
                            default_visible=col.default_visible,
                            order=col.order,
                            known=col.known,
                            render_hints=dict(col.render_hints),
                        )
                        for col in advanced_parsed.columns
                    ],
                    discovered_columns=[
                        BasicParsedDataColumn(
                            key=col.key,
                            label=col.label,
                            type=col.type,
                            description=col.description,
                            default_visible=col.default_visible,
                            order=col.order,
                            known=col.known,
                            render_hints=dict(col.render_hints),
                        )
                        for col in advanced_parsed.discovered_columns
                    ],
                    data=[dict(row) for row in advanced_parsed.data],
                    created_at=advanced_parsed.created_at,
                )
            except Exception:
                parsed_data = None

        return BasicResultsResponse(
            scope_id=resp.scope_id,
            findings=findings,
            total_count=resp.total_count,
            limit=pagination.limit if pagination else 0,
            offset=pagination.offset if pagination else 0,
            has_more=pagination.has_more if pagination else False,
            next_cursor=(pagination.next_cursor if pagination else None) or None,
            raw_output_inline=raw_output_inline,
            raw_output_s3_url=raw_output_s3_url,
            parsed_data=parsed_data,
        )


basic_scan_client = BasicScanClient()


class _UserIdMetadataInterceptor(grpc.UnaryUnaryClientInterceptor):
    def __init__(
        self,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
        quota_remaining: int | None = None,
    ) -> None:
        self._user_id = user_id
        self._api_key_id = (api_key_id or "").strip()
        self._api_project_id = (api_project_id or "").strip()
        self._quota_remaining = quota_remaining

    def intercept_unary_unary(self, continuation, client_call_details, request):
        metadata = list(client_call_details.metadata or [])
        metadata.append(("x-user-id", self._user_id))
        if self._api_key_id:
            metadata.append(("x-api-key-id", self._api_key_id))
        if self._api_project_id:
            metadata.append(("x-api-project-id", self._api_project_id))
        if self._quota_remaining is not None:
            metadata.append(("x-quota-remaining", str(self._quota_remaining)))
        new_details = _ClientCallDetails(
            client_call_details.method,
            client_call_details.timeout,
            metadata,
            client_call_details.credentials,
            client_call_details.wait_for_ready,
            client_call_details.compression,
        )
        return continuation(new_details, request)


class _ClientCallDetails(grpc.ClientCallDetails):
    def __init__(self, method, timeout, metadata, credentials, wait_for_ready, compression):
        self.method = method
        self.timeout = timeout
        self.metadata = metadata
        self.credentials = credentials
        self.wait_for_ready = wait_for_ready
        self.compression = compression
