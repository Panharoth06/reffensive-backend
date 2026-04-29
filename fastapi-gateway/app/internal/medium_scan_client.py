from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

import grpc
from google.protobuf import struct_pb2
from fastapi import HTTPException, status

from app.gen import medium_scan_pb2, medium_scan_pb2_grpc
from app.schemas.medium_scan_schemas import (
    MediumJobParsedDataResponse,
    MediumParsedDataColumn,
    MediumParsedDataResponse,
    MediumScanFinding,
    MediumScanJobStatusResponse,
    MediumScanResultsResponse,
    MediumScanStepRequest,
    MediumScanStepStatusResponse,
    MediumScanStepSummary,
    MediumScanSubmitRequest,
    MediumScanSubmitResponse,
)
from app.utils.grpc_errors import raise_for_grpc_error


def _ts(proto_ts) -> Optional[datetime]:
    if proto_ts is None or (proto_ts.seconds == 0 and proto_ts.nanos == 0):
        return None
    return datetime.fromtimestamp(proto_ts.seconds, tz=timezone.utc)


def _enum_name(enum_cls, value: int) -> str:
    try:
        return enum_cls.Name(value)
    except Exception:
        return str(value)


def _structpb_to_dict(value: struct_pb2.Value):
    kind = value.WhichOneof("kind")
    if kind == "null_value":
        return None
    if kind == "number_value":
        number = value.number_value
        return int(number) if number == int(number) else number
    if kind == "string_value":
        return value.string_value
    if kind == "bool_value":
        return value.bool_value
    if kind == "struct_value":
        return {k: _structpb_to_dict(v) for k, v in value.struct_value.fields.items()}
    if kind == "list_value":
        return [_structpb_to_dict(v) for v in value.list_value.values]
    return None


def _to_proto_option_value(value) -> medium_scan_pb2.MediumOptionValue:
    if isinstance(value, bool):
        return medium_scan_pb2.MediumOptionValue(bool_value=value)
    if isinstance(value, int):
        return medium_scan_pb2.MediumOptionValue(int_value=value)
    if isinstance(value, list):
        return medium_scan_pb2.MediumOptionValue(str_value=json.dumps(value, ensure_ascii=True))
    return medium_scan_pb2.MediumOptionValue(str_value=str(value))


def _step_to_proto(step: MediumScanStepRequest) -> medium_scan_pb2.MediumScanStepRequest:
    return medium_scan_pb2.MediumScanStepRequest(
        tool_id=step.tool_id or "",
        tool_name=step.tool_name or "",
        runtime_timeout_seconds=step.runtime_timeout_seconds or 0,
        tool_options={
            key: _to_proto_option_value(value)
            for key, value in step.tool_options.items()
        },
    )


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


class MediumScanClient:
    def __init__(self) -> None:
        import os

        grpc_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051")
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = medium_scan_pb2_grpc.MediumScanServiceStub(self.channel)

    def _make_stub_with_user(
        self,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
        quota_remaining: int | None = None,
    ) -> medium_scan_pb2_grpc.MediumScanServiceStub:
        interceptor = _UserIdMetadataInterceptor(
            user_id,
            api_key_id=api_key_id,
            api_project_id=api_project_id,
            quota_remaining=quota_remaining,
        )
        intercepted_channel = grpc.intercept_channel(self.channel, interceptor)
        return medium_scan_pb2_grpc.MediumScanServiceStub(intercepted_channel)

    def submit_medium_scan(
        self,
        body: MediumScanSubmitRequest,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
        quota_remaining: int | None = None,
    ) -> MediumScanSubmitResponse:
        tool_options: Dict[str, medium_scan_pb2.MediumOptionValue] = {
            key: _to_proto_option_value(value)
            for key, value in body.tool_options.items()
        }
        steps = [_step_to_proto(step) for step in body.steps]

        execution_mode_map = {
            "WEB": medium_scan_pb2.EXECUTION_MODE_WEB,
            "CLI": medium_scan_pb2.EXECUTION_MODE_CLI,
            "CICD": medium_scan_pb2.EXECUTION_MODE_CICD,
        }
        exec_mode = execution_mode_map.get(body.execution_mode or "WEB", medium_scan_pb2.EXECUTION_MODE_WEB)

        req = medium_scan_pb2.MediumScanSubmitRequest(
            project_id=body.project_id,
            target_id=body.target_id or "",
            target_value=body.target_value,
            tool_id=body.tool_id or "",
            tool_name=body.tool_name or "",
            tool_options=tool_options,
            idempotency_key=body.idempotency_key or "",
            execution_mode=exec_mode,
            steps=steps,
            runtime_timeout_seconds=body.runtime_timeout_seconds or 0,
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

        return MediumScanSubmitResponse(
            job_id=resp.job_id,
            step_id=resp.step_id,
            status=_enum_name(medium_scan_pb2.ScanStatus, resp.status),
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
    ) -> MediumScanStepStatusResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.GetStepStatus(medium_scan_pb2.GetStepStatusRequest(step_id=step_id))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        return MediumScanStepStatusResponse(
            step_id=resp.step_id,
            job_id=resp.job_id,
            tool_name=resp.tool_name,
            status=_enum_name(medium_scan_pb2.ScanStatus, resp.status),
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
    ) -> MediumScanJobStatusResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.GetJobStatus(medium_scan_pb2.GetJobStatusRequest(job_id=job_id))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        steps: List[MediumScanStepSummary] = [
            MediumScanStepSummary(
                step_id=item.step_id,
                tool_name=item.tool_name,
                step_order=item.step_order,
                status=_enum_name(medium_scan_pb2.ScanStatus, item.status),
                findings_count=item.findings_count,
                started_at=_ts(item.started_at),
                finished_at=_ts(item.finished_at),
            )
            for item in resp.steps
        ]

        return MediumScanJobStatusResponse(
            job_id=resp.job_id,
            project_id=resp.project_id,
            status=_enum_name(medium_scan_pb2.JobStatus, resp.status),
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
        job_id: Optional[str] = None,
        step_id: Optional[str] = None,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> MediumScanResultsResponse:
        if not job_id and not step_id:
            raise ValueError("job_id or step_id is required")

        scope = {"step_id": step_id} if step_id else {"job_id": job_id}
        req = medium_scan_pb2.GetResultsRequest(
            **scope,
            pagination=medium_scan_pb2.Pagination(limit=100, offset=0),
        )
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.GetResults(req)
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        findings: List[MediumScanFinding] = []
        for item in resp.findings:
            findings.append(
                MediumScanFinding(
                    finding_id=item.finding_id,
                    step_id=item.step_id,
                    job_id=item.job_id,
                    title=item.title,
                    severity=_enum_name(medium_scan_pb2.Severity, item.severity),
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
        return MediumScanResultsResponse(
            scope_id=resp.scope_id,
            findings=findings,
            total_count=resp.total_count,
            limit=pagination.limit if pagination else 0,
            offset=pagination.offset if pagination else 0,
            has_more=pagination.has_more if pagination else False,
            next_cursor=(pagination.next_cursor if pagination else None) or None,
            raw_output_inline=raw_output_inline,
            raw_output_s3_url=raw_output_s3_url,
        )

    def get_parsed_data(
        self,
        step_id: str,
        *,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> MediumParsedDataResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            resp = stub.GetParsedData(medium_scan_pb2.GetParsedDataRequest(step_id=step_id))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

        findings = [
            MediumScanFinding(
                finding_id=item.finding_id,
                step_id=item.step_id,
                job_id=item.job_id,
                title=item.title,
                severity=_enum_name(medium_scan_pb2.Severity, item.severity),
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
            for item in resp.findings
        ]

        columns = [
            MediumParsedDataColumn(
                key=col.key,
                label=col.label,
                type=col.type,
                description=col.description,
                default_visible=col.default_visible,
                order=col.order,
                known=col.known,
                render_hints=dict(col.render_hints),
            )
            for col in resp.columns
        ]
        discovered_columns = [
            MediumParsedDataColumn(
                key=col.key,
                label=col.label,
                type=col.type,
                description=col.description,
                default_visible=col.default_visible,
                order=col.order,
                known=col.known,
                render_hints=dict(col.render_hints),
            )
            for col in resp.discovered_columns
        ]

        data = []
        for item in resp.data:
            row = {}
            for key, value in item.fields.items():
                row[key] = _structpb_to_dict(value)
            data.append(row)

        return MediumParsedDataResponse(
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
        *,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> MediumJobParsedDataResponse:
        job = self.get_job_status(
            job_id,
            user_id=user_id,
            api_key_id=api_key_id,
            api_project_id=api_project_id,
        )
        steps = sorted(job.steps, key=lambda item: item.step_order)
        parsed_steps: List[MediumParsedDataResponse] = []
        for step in steps:
            if not step.step_id:
                continue
            try:
                parsed_steps.append(
                    self.get_parsed_data(
                        step.step_id,
                        user_id=user_id,
                        api_key_id=api_key_id,
                        api_project_id=api_project_id,
                    )
                )
            except Exception:
                continue

        return MediumJobParsedDataResponse(
            job_id=job_id,
            total_steps=job.total_steps,
            steps=parsed_steps,
        )


medium_scan_client = MediumScanClient()
