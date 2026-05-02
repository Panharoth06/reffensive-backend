from __future__ import annotations

import base64
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import grpc
from google.protobuf import struct_pb2
from fastapi import HTTPException, status
from google.protobuf.timestamp_pb2 import Timestamp

from app.gen import advanced_scan_pb2, advanced_scan_pb2_grpc
from app.schemas.advanced_scan_schemas import (
    AdvancedFinding,
    AdvancedFindingsResponse,
    AdvancedJobStatusResponse,
    AdvancedParsingMetadata,
    AdvancedRawOutputResponse,
    AdvancedResultsResponse,
    AdvancedResultsSummaryResponse,
    AdvancedScanSubmitRequest,
    AdvancedScanSubmitResponse,
    AdvancedStepSummary,
    AdvancedStepStatusResponse,
    QueueStatusResponse,
    JobQueuePositionResponse,
    CancelQueuedJobResponse,
    ParsedDataResponse,
    ParsedDataColumn,
    JobParsedDataResponse,
)
from app.utils.grpc_errors import raise_for_grpc_error


def _ts(proto_ts) -> Optional[datetime]:
    if proto_ts is None or (proto_ts.seconds == 0 and proto_ts.nanos == 0):
        return None
    return datetime.fromtimestamp(proto_ts.seconds, tz=timezone.utc)


def _structpb_to_dict(value: struct_pb2.Value) -> Any:
    """Convert a protobuf Value to a Python native type."""
    kind = value.WhichOneof("kind")
    if kind == "null_value":
        return None
    if kind == "number_value":
        n = value.number_value
        return int(n) if n == int(n) else n
    if kind == "string_value":
        return value.string_value
    if kind == "bool_value":
        return value.bool_value
    if kind == "struct_value":
        return {k: _structpb_to_dict(v) for k, v in value.struct_value.fields.items()}
    if kind == "list_value":
        return [_structpb_to_dict(v) for v in value.list_value.values]
    return None


def _enum_name(enum_cls, value: int) -> str:
    try:
        return enum_cls.Name(value)
    except Exception:
        return str(value)


def _proto_ts(dt: Optional[datetime]) -> Optional[Timestamp]:
    if dt is None:
        return None
    normalized = dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
    normalized = normalized.astimezone(timezone.utc)
    out = Timestamp()
    out.FromDatetime(normalized)
    return out


def _severity_values(values: Optional[Sequence[str]]) -> List[int]:
    out: List[int] = []
    for raw in values or []:
        normalized = raw.strip().upper()
        if not normalized:
            continue
        if not normalized.startswith("SEVERITY_"):
            normalized = f"SEVERITY_{normalized}"
        try:
            out.append(advanced_scan_pb2.Severity.Value(normalized))
        except ValueError as exc:
            raise ValueError(f"invalid severity: {raw}") from exc
    return out


class _IdentityMetadataInterceptor(grpc.UnaryUnaryClientInterceptor):
    """Attaches identity metadata to every unary-unary call."""

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


class _ClientCallDetails(
    grpc.ClientCallDetails,
):
    def __init__(self, method, timeout, metadata, credentials, wait_for_ready, compression):
        self.method = method
        self.timeout = timeout
        self.metadata = metadata
        self.credentials = credentials
        self.wait_for_ready = wait_for_ready
        self.compression = compression


class AdvancedScanClient:
    def __init__(self) -> None:
        import os

        grpc_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051")
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = advanced_scan_pb2_grpc.AdvancedScanServiceStub(self.channel)

    def _make_stub_with_user(
        self,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
        quota_remaining: int | None = None,
    ) -> advanced_scan_pb2_grpc.AdvancedScanServiceStub:
        """Return a stub that attaches identity metadata to every unary call."""
        interceptor = _IdentityMetadataInterceptor(
            user_id,
            api_key_id=api_key_id,
            api_project_id=api_project_id,
            quota_remaining=quota_remaining,
        )
        intercepted_channel = grpc.intercept_channel(self.channel, interceptor)
        return advanced_scan_pb2_grpc.AdvancedScanServiceStub(intercepted_channel)

    def submit_advanced_scan(
        self,
        body: AdvancedScanSubmitRequest,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
        quota_remaining: int | None = None,
    ) -> AdvancedScanSubmitResponse:
        idempotency_key = body.idempotency_key or ""

        req = advanced_scan_pb2.SubmitScanRequest(
            project_id=body.project_id,
            idempotency_key=idempotency_key,
            command=body.command,
            execution_mode=getattr(advanced_scan_pb2, "EXECUTION_MODE_WEB", 1),
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

        return AdvancedScanSubmitResponse(
            job_id=resp.job_id,
            step_id=resp.step_id,
            status=_enum_name(advanced_scan_pb2.StepStatus, resp.status),
            is_idempotent_replay=resp.is_idempotent_replay,
            original_request_id=resp.original_request_id or None,
            queued_at=_ts(resp.queued_at),
            retry_after_seconds=resp.retry_after_seconds if resp.retry_after_seconds > 0 else None,
        )

    def get_step_status(
        self,
        step_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> AdvancedStepStatusResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.GetStepStatus(advanced_scan_pb2.GetStepStatusRequest(step_id=step_id))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        return AdvancedStepStatusResponse(
            step_id=resp.step_id,
            job_id=resp.job_id,
            tool_name=resp.tool_name,
            status=_enum_name(advanced_scan_pb2.StepStatus, resp.status),
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
    ) -> AdvancedJobStatusResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.GetJobStatus(advanced_scan_pb2.GetJobStatusRequest(job_id=job_id))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        steps: List[AdvancedStepSummary] = []
        for step in resp.steps:
            steps.append(
                AdvancedStepSummary(
                    step_id=step.step_id,
                    tool_name=step.tool_name,
                    step_order=step.step_order,
                    status=_enum_name(advanced_scan_pb2.StepStatus, step.status),
                    findings_count=step.findings_count,
                    started_at=_ts(step.started_at),
                    finished_at=_ts(step.finished_at),
                )
            )

        return AdvancedJobStatusResponse(
            job_id=resp.job_id,
            project_id=resp.project_id,
            status=_enum_name(advanced_scan_pb2.JobStatus, resp.status),
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

    def _map_finding(self, item) -> AdvancedFinding:
        return AdvancedFinding(
            finding_id=item.finding_id,
            step_id=item.step_id,
            job_id=item.job_id,
            title=item.title,
            severity=_enum_name(advanced_scan_pb2.Severity, item.severity),
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

    def _map_parsing_metadata(self, resp) -> Optional[AdvancedParsingMetadata]:
        if not resp.HasField("parsing_metadata"):
            return None
        meta = resp.parsing_metadata
        return AdvancedParsingMetadata(
            parser_name=meta.parser_name,
            parser_version=meta.parser_version,
            parsed_at=_ts(meta.parsed_at),
            raw_size_bytes=meta.raw_size_bytes,
            parsed_size_bytes=meta.parsed_size_bytes,
            parsing_error=meta.parsing_error or None,
            is_partial=meta.is_partial,
        )

    def _build_results_request(
        self,
        *,
        job_id: Optional[str] = None,
        step_id: Optional[str] = None,
        severity_in: Optional[Sequence[str]] = None,
        host_contains: Optional[str] = None,
        port_eq: Optional[int] = None,
        fingerprint_eq: Optional[str] = None,
        created_after: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ):
        if not job_id and not step_id:
            raise ValueError("job_id or step_id is required")

        scope = {}
        if step_id:
            scope["step_id"] = step_id
        else:
            scope["job_id"] = job_id

        filter_kwargs = {}
        severity_values = _severity_values(severity_in)
        if severity_values:
            filter_kwargs["severity_in"] = severity_values
        if host_contains:
            filter_kwargs["host_contains"] = host_contains
        if port_eq and port_eq > 0:
            filter_kwargs["port_eq"] = port_eq
        if fingerprint_eq:
            filter_kwargs["fingerprint_eq"] = fingerprint_eq
        created_after_ts = _proto_ts(created_after)
        if created_after_ts is not None:
            filter_kwargs["created_after"] = created_after_ts

        pagination = advanced_scan_pb2.Pagination(
            limit=max(1, limit),
            offset=max(0, offset),
        )

        req_kwargs = {
            **scope,
            "pagination": pagination,
        }
        if filter_kwargs:
            req_kwargs["filter"] = advanced_scan_pb2.ResultsFilter(**filter_kwargs)
        return advanced_scan_pb2.GetResultsRequest(**req_kwargs)

    def _get_results_proto(
        self,
        *,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
        job_id: Optional[str] = None,
        step_id: Optional[str] = None,
        severity_in: Optional[Sequence[str]] = None,
        host_contains: Optional[str] = None,
        port_eq: Optional[int] = None,
        fingerprint_eq: Optional[str] = None,
        created_after: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ):
        req = self._build_results_request(
            job_id=job_id,
            step_id=step_id,
            severity_in=severity_in,
            host_contains=host_contains,
            port_eq=port_eq,
            fingerprint_eq=fingerprint_eq,
            created_after=created_after,
            limit=limit,
            offset=offset,
        )
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            return stub.GetResults(req)
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def _map_findings_response(self, resp) -> AdvancedFindingsResponse:
        findings = [self._map_finding(item) for item in resp.findings]
        pagination = resp.pagination
        return AdvancedFindingsResponse(
            scope_id=resp.scope_id,
            findings=findings,
            total_count=resp.total_count,
            limit=pagination.limit if pagination else 0,
            offset=pagination.offset if pagination else 0,
            has_more=pagination.has_more if pagination else False,
            next_cursor=(pagination.next_cursor if pagination else None) or None,
        )

    def get_findings(
        self,
        *,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
        job_id: Optional[str] = None,
        step_id: Optional[str] = None,
        severity_in: Optional[Sequence[str]] = None,
        host_contains: Optional[str] = None,
        port_eq: Optional[int] = None,
        fingerprint_eq: Optional[str] = None,
        created_after: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> AdvancedFindingsResponse:
        resp = self._get_results_proto(
            user_id=user_id,
            api_key_id=api_key_id,
            api_project_id=api_project_id,
            job_id=job_id,
            step_id=step_id,
            severity_in=severity_in,
            host_contains=host_contains,
            port_eq=port_eq,
            fingerprint_eq=fingerprint_eq,
            created_after=created_after,
            limit=limit,
            offset=offset,
        )
        return self._map_findings_response(resp)

    def get_results(
        self,
        *,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
        job_id: Optional[str] = None,
        step_id: Optional[str] = None,
        severity_in: Optional[Sequence[str]] = None,
        host_contains: Optional[str] = None,
        port_eq: Optional[int] = None,
        fingerprint_eq: Optional[str] = None,
        created_after: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> AdvancedResultsResponse:
        resp = self._get_results_proto(
            user_id=user_id,
            api_key_id=api_key_id,
            api_project_id=api_project_id,
            job_id=job_id,
            step_id=step_id,
            severity_in=severity_in,
            host_contains=host_contains,
            port_eq=port_eq,
            fingerprint_eq=fingerprint_eq,
            created_after=created_after,
            limit=limit,
            offset=offset,
        )
        findings_response = self._map_findings_response(resp)

        raw_output_inline: Optional[str] = None
        raw_output_s3_url: Optional[str] = None
        raw_variant = resp.WhichOneof("raw_output")
        if raw_variant == "raw_output_inline":
            raw_output_inline = base64.b64encode(resp.raw_output_inline).decode("ascii")
        elif raw_variant == "raw_output_s3_url":
            raw_output_s3_url = resp.raw_output_s3_url

        return AdvancedResultsResponse(
            scope_id=findings_response.scope_id,
            findings=findings_response.findings,
            total_count=findings_response.total_count,
            limit=findings_response.limit,
            offset=findings_response.offset,
            has_more=findings_response.has_more,
            next_cursor=findings_response.next_cursor,
            raw_output_inline=raw_output_inline,
            raw_output_s3_url=raw_output_s3_url,
            parsing_metadata=self._map_parsing_metadata(resp),
        )

    def _collect_findings(
        self,
        *,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
        job_id: Optional[str] = None,
        step_id: Optional[str] = None,
        severity_in: Optional[Sequence[str]] = None,
        host_contains: Optional[str] = None,
        port_eq: Optional[int] = None,
        fingerprint_eq: Optional[str] = None,
        created_after: Optional[datetime] = None,
        page_size: int = 500,
    ) -> List[AdvancedFinding]:
        findings: List[AdvancedFinding] = []
        offset = 0
        while True:
            page = self.get_findings(
                user_id=user_id,
                api_key_id=api_key_id,
                api_project_id=api_project_id,
                job_id=job_id,
                step_id=step_id,
                severity_in=severity_in,
                host_contains=host_contains,
                port_eq=port_eq,
                fingerprint_eq=fingerprint_eq,
                created_after=created_after,
                limit=page_size,
                offset=offset,
            )
            findings.extend(page.findings)
            if not page.has_more or not page.findings:
                return findings
            offset += page.limit or len(page.findings)

    def _summarize_findings(self, findings: Sequence[AdvancedFinding]) -> tuple[dict[str, int], int, int, int, int]:
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

    def get_job_summary(
        self,
        job_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> AdvancedResultsSummaryResponse:
        job = self.get_job_status(job_id, user_id, api_key_id=api_key_id, api_project_id=api_project_id)
        findings = self._collect_findings(
            user_id=user_id,
            api_key_id=api_key_id,
            api_project_id=api_project_id,
            job_id=job_id,
        )
        severity_counts, unique_hosts, unique_ports, unique_services, unique_fingerprints = self._summarize_findings(findings)
        return AdvancedResultsSummaryResponse(
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

    def get_step_summary(
        self,
        step_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> AdvancedResultsSummaryResponse:
        step = self.get_step_status(step_id, user_id, api_key_id=api_key_id, api_project_id=api_project_id)
        job = self.get_job_status(step.job_id, user_id, api_key_id=api_key_id, api_project_id=api_project_id)
        findings = self._collect_findings(
            user_id=user_id,
            api_key_id=api_key_id,
            api_project_id=api_project_id,
            step_id=step_id,
        )
        severity_counts, unique_hosts, unique_ports, unique_services, unique_fingerprints = self._summarize_findings(findings)
        steps = [item for item in job.steps if item.step_id == step_id]
        if not steps:
            steps = [
                AdvancedStepSummary(
                    step_id=step.step_id,
                    tool_name=step.tool_name,
                    step_order=0,
                    status=step.status,
                    findings_count=step.findings_count,
                    started_at=step.started_at,
                    finished_at=step.finished_at,
                )
            ]
        return AdvancedResultsSummaryResponse(
            scope_id=step_id,
            scope_type="step",
            job_id=step.job_id,
            step_id=step_id,
            status=step.status,
            total_steps=len(steps),
            total_findings=len(findings),
            unique_hosts=unique_hosts,
            unique_ports=unique_ports,
            unique_services=unique_services,
            unique_fingerprints=unique_fingerprints,
            severity_counts=severity_counts,
            created_at=step.queued_at,
            started_at=step.started_at,
            finished_at=step.finished_at,
            steps=steps,
        )

    def get_step_raw_output(
        self,
        step_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> AdvancedRawOutputResponse:
        step = self.get_step_status(step_id, user_id, api_key_id=api_key_id, api_project_id=api_project_id)
        results = self.get_results(
            user_id=user_id,
            api_key_id=api_key_id,
            api_project_id=api_project_id,
            step_id=step_id,
            limit=1,
            offset=0,
        )
        return AdvancedRawOutputResponse(
            step_id=step_id,
            job_id=step.job_id,
            raw_output_inline=results.raw_output_inline,
            raw_output_s3_url=results.raw_output_s3_url,
            parsing_metadata=results.parsing_metadata,
        )

    def get_parsed_data(
        self,
        step_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> ParsedDataResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.GetParsedData(advanced_scan_pb2.GetParsedDataRequest(step_id=step_id))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        findings = [self._map_finding(item) for item in resp.findings]

        # Map columns
        columns = [
            ParsedDataColumn(
                key=c.key,
                label=c.label,
                type=c.type,
                description=c.description,
                default_visible=c.default_visible,
                order=c.order,
                known=c.known,
                render_hints=dict(c.render_hints),
            )
            for c in resp.columns
        ]

        # Map discovered columns
        discovered_columns = [
            ParsedDataColumn(
                key=c.key,
                label=c.label,
                type=c.type,
                description=c.description,
                default_visible=c.default_visible,
                order=c.order,
                known=c.known,
                render_hints=dict(c.render_hints),
            )
            for c in resp.discovered_columns
        ]

        # Map data rows from protobuf Struct to plain dicts
        data = []
        for struct in resp.data:
            row = {}
            for k, v in struct.fields.items():
                row[k] = _structpb_to_dict(v)
            data.append(row)

        return ParsedDataResponse(
            step_id=resp.step_id,
            job_id=resp.job_id,
            tool_name=resp.tool_name,
            parse_method=resp.parse_method,
            line_count=resp.line_count,
            findings_count=resp.findings_count,
            lines=list(resp.lines),
            findings=findings,
            columns=columns,
            discovered_columns=discovered_columns,
            data=data,
            created_at=_ts(resp.created_at),
        )

    def get_job_parsed_data(
        self,
        job_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> JobParsedDataResponse:
        """Fetch parsed data for every step in a job, ordered by step_order.

        Steps with no stored parsed data are silently skipped so the caller
        always receives a clean list of usable table results.
        """
        job = self.get_job_status(
            job_id,
            user_id,
            api_key_id=api_key_id,
            api_project_id=api_project_id,
        )
        # Sort by step_order so tables appear in pipeline order.
        steps = sorted(job.steps, key=lambda s: s.step_order)
        results: list[ParsedDataResponse] = []
        for step in steps:
            if not step.step_id:
                continue
            try:
                parsed = self.get_parsed_data(
                    step.step_id,
                    user_id,
                    api_key_id=api_key_id,
                    api_project_id=api_project_id,
                )
                results.append(parsed)
            except Exception:
                # Step has no parsed data yet (pending/failed) — skip silently.
                pass
        return JobParsedDataResponse(
            job_id=job_id,
            total_steps=job.total_steps,
            steps=results,
        )

    def get_queue_status(
        self,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> QueueStatusResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.GetQueueStatus(advanced_scan_pb2.QueueStatusRequest())
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        return QueueStatusResponse(
            queued_jobs=resp.queued_jobs,
            processing_jobs=resp.processing_jobs,
            total_jobs=resp.total_jobs,
            max_concurrent=resp.max_concurrent,
            max_queue_capacity=resp.max_queue_capacity,
        )

    def get_job_queue_position(
        self,
        job_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> JobQueuePositionResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.GetJobQueuePosition(advanced_scan_pb2.JobQueuePositionRequest(job_id=job_id))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        return JobQueuePositionResponse(
            job_id=resp.job_id,
            status=resp.status,
            position=resp.position,
        )

    def cancel_queued_job(
        self,
        job_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> CancelQueuedJobResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.CancelQueuedJob(advanced_scan_pb2.CancelQueuedJobRequest(job_id=job_id))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        return CancelQueuedJobResponse(
            success=resp.success,
            message=resp.message,
        )


advanced_scan_client = AdvancedScanClient()
