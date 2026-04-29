from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Iterable

import grpc

from app.gen import sonarqube_pb2, sonarqube_pb2_grpc
from app.schemas.sonarqube_scan_schemas import (
    ActivityChangeResponse,
    ActivityCommentResponse,
    ActivityDiffResponse,
    DescriptionSectionResponse,
    DependencySummaryResponse,
    EcosystemSummaryResponse,
    FileIssuesResponse,
    IssueActivityResponse,
    IssueDetailResponse,
    IssueMoreInfoResponse,
    IssueResponse,
    IssueWhereResponse,
    IssueWhyResponse,
    ListIssuesResponse,
    ProjectScanResponse,
    ProjectScansResponse,
    ScanLogChunkResponse,
    ScanLogsResponse,
    ScanStatusResponse,
    ScanSummaryResponse,
    TextRangeResponse,
    TriggerScanRequest,
    TriggerScanResponse,
)
from app.utils.grpc_errors import raise_for_grpc_error


class _IdentityMetadataInterceptor(grpc.UnaryUnaryClientInterceptor):
    def __init__(
        self,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> None:
        self._user_id = user_id
        self._api_key_id = (api_key_id or "").strip()
        self._api_project_id = (api_project_id or "").strip()

    def intercept_unary_unary(self, continuation, client_call_details, request):
        metadata = list(client_call_details.metadata or [])
        metadata.append(("x-user-id", self._user_id))
        if self._api_key_id:
            metadata.append(("x-api-key-id", self._api_key_id))
        if self._api_project_id:
            metadata.append(("x-api-project-id", self._api_project_id))
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


class _RetryUnaryUnaryInterceptor(grpc.UnaryUnaryClientInterceptor):
    def intercept_unary_unary(self, continuation, client_call_details, request):
        attempts = 3
        delay = 0.2
        for attempt in range(attempts):
            try:
                return continuation(client_call_details, request)
            except grpc.RpcError as exc:
                if exc.code() not in {grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED}:
                    raise
                if attempt == attempts - 1:
                    raise
                time.sleep(delay)
                delay *= 2


def _ts(value) -> datetime | None:
    if value is None or (value.seconds == 0 and value.nanos == 0):
        return None
    return datetime.fromtimestamp(value.seconds, tz=timezone.utc)


def _status_name(value: int) -> str:
    mapping = {
        sonarqube_pb2.SCAN_STATUS_PENDING: "PENDING",
        sonarqube_pb2.SCAN_STATUS_IN_PROGRESS: "IN_PROGRESS",
        sonarqube_pb2.SCAN_STATUS_SUCCESS: "SUCCESS",
        sonarqube_pb2.SCAN_STATUS_FAILED: "FAILED",
        sonarqube_pb2.SCAN_STATUS_PARTIAL: "PARTIAL",
    }
    return mapping.get(value, "FAILED")


def _quality_gate_name(value: int) -> str:
    mapping = {
        sonarqube_pb2.QUALITY_GATE_STATUS_OK: "OK",
        sonarqube_pb2.QUALITY_GATE_STATUS_WARN: "WARN",
        sonarqube_pb2.QUALITY_GATE_STATUS_ERROR: "ERROR",
    }
    return mapping.get(value, "ERROR")


def _issue_from_proto(item) -> IssueResponse:
    return IssueResponse(
        key=item.key,
        type=item.type,
        severity=item.severity,
        rule_key=item.rule_key,
        message=item.message,
        file_path=item.file_path,
        line=item.line,
        status=item.status,
        tags=list(item.tags),
    )


def _scan_status_from_proto(item) -> ScanStatusResponse:
    return ScanStatusResponse(
        scan_id=item.scan_id,
        status=_status_name(item.status),
        progress=item.progress,
        started_at=_ts(item.started_at),
        finished_at=_ts(item.finished_at),
        error_message=item.error_message,
        phases=[
            {
                "key": phase.key,
                "status": phase.status,
                "error_message": phase.error_message,
            }
            for phase in item.phases
        ],
    )


def _scan_log_chunk_from_proto(item) -> ScanLogChunkResponse:
    completion_status = None
    if item.completion_status != sonarqube_pb2.SCAN_STATUS_UNSPECIFIED:
        completion_status = _status_name(item.completion_status)
    return ScanLogChunkResponse(
        scan_id=item.scan_id,
        phase=item.phase,
        level=item.level or "INFO",
        line=item.line,
        timestamp=_ts(item.timestamp),
        sequence_num=item.sequence_num,
        is_final_chunk=item.is_final_chunk,
        completion_status=completion_status,
    )


def _dependency_summary_from_proto(item) -> DependencySummaryResponse:
    return DependencySummaryResponse(
        scan_id=item.scan_id,
        total=item.total,
        vulnerable=item.vulnerable,
        outdated=item.outdated,
        license_issues=item.license_issues,
        critical=item.critical,
        high=item.high,
        medium=item.medium,
        low=item.low,
        by_ecosystem=[
            EcosystemSummaryResponse(ecosystem=row.ecosystem, total=row.total)
            for row in item.by_ecosystem
        ],
    )


@lru_cache(maxsize=1)
def _channel() -> grpc.Channel:
    grpc_addr = os.getenv("GRPC_SERVER_ADDR", "go-service:50051")
    base = grpc.insecure_channel(grpc_addr)
    return grpc.intercept_channel(base, _RetryUnaryUnaryInterceptor())


@lru_cache(maxsize=1)
def _stub() -> sonarqube_pb2_grpc.SonarqubeServiceStub:
    return sonarqube_pb2_grpc.SonarqubeServiceStub(_channel())


class SonarqubeScanClient:
    def __init__(self) -> None:
        self.channel = _channel()
        self.stub = _stub()

    def _make_stub_with_user(
        self,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> sonarqube_pb2_grpc.SonarqubeServiceStub:
        interceptor = _IdentityMetadataInterceptor(
            user_id,
            api_key_id=api_key_id,
            api_project_id=api_project_id,
        )
        intercepted_channel = grpc.intercept_channel(self.channel, interceptor)
        return sonarqube_pb2_grpc.SonarqubeServiceStub(intercepted_channel)

    @staticmethod
    def _metadata(
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> list[tuple[str, str]]:
        metadata = [("x-user-id", user_id)]
        if api_key_id:
            metadata.append(("x-api-key-id", api_key_id))
        if api_project_id:
            metadata.append(("x-api-project-id", api_project_id))
        return metadata

    def trigger_scan(
        self,
        body: TriggerScanRequest,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> TriggerScanResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            response = stub.TriggerScan(
                sonarqube_pb2.TriggerScanRequest(
                    project_key=body.project_key,
                    branch=body.branch or "",
                    repo_url=body.repo_url,
                ),
                timeout=10.0,
            )
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)
        return TriggerScanResponse(
            scan_id=response.scan_id,
            status=_status_name(response.status),
            created_at=_ts(response.created_at),
        )

    def get_scan_status(
        self,
        scan_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> ScanStatusResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            response = stub.GetScanStatus(
                sonarqube_pb2.ScanStatusRequest(scan_id=scan_id),
                timeout=10.0,
            )
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)
        return _scan_status_from_proto(response)

    def get_scan_logs(
        self,
        scan_id: str,
        after_sequence_num: int,
        limit: int,
        phases: list[str],
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> ScanLogsResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            response = stub.GetScanLogs(
                sonarqube_pb2.ScanLogsRequest(
                    scan_id=scan_id,
                    after_sequence_num=after_sequence_num,
                    limit=limit,
                    phases=phases,
                ),
                timeout=10.0,
            )
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)
        return ScanLogsResponse(
            logs=[_scan_log_chunk_from_proto(item) for item in response.logs],
            is_terminal=response.is_terminal,
            status=_status_name(response.status),
            next_sequence_num=response.next_sequence_num,
        )

    def get_scan_summary(
        self,
        scan_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> ScanSummaryResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            response = stub.GetScanSummary(
                sonarqube_pb2.ScanSummaryRequest(scan_id=scan_id),
                timeout=20.0,
            )
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)
        return ScanSummaryResponse(
            scan_id=response.scan_id,
            quality_gate=_quality_gate_name(response.quality_gate),
            bugs=response.bugs,
            vulnerabilities=response.vulnerabilities,
            code_smells=response.code_smells,
            coverage=response.coverage,
            duplications=response.duplications,
            security_hotspots=response.security_hotspots,
            dependency_summary=_dependency_summary_from_proto(response.dependency_summary)
            if response.HasField("dependency_summary")
            else None,
        )

    def list_issues(
        self,
        scan_id: str,
        type_filter: str | None,
        severity_filter: str | None,
        page: int,
        page_size: int,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> ListIssuesResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            response = stub.ListIssues(
                sonarqube_pb2.ListIssuesRequest(
                    scan_id=scan_id,
                    type_filter=type_filter or "",
                    severity_filter=severity_filter or "",
                    page=page,
                    page_size=page_size,
                ),
                timeout=20.0,
            )
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)
        return ListIssuesResponse(
            issues=[_issue_from_proto(item) for item in response.issues],
            page=response.page,
            page_size=response.page_size,
            total=response.total,
        )

    def get_issue_detail(
        self,
        scan_id: str,
        issue_key: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> IssueDetailResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            response = stub.GetIssueDetail(
                sonarqube_pb2.IssueDetailRequest(scan_id=scan_id, issue_key=issue_key),
                timeout=20.0,
            )
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)
        return IssueDetailResponse(
            where_is_issue=IssueWhereResponse(
                component_key=response.where_is_issue.component_key,
                file_path=response.where_is_issue.file_path,
                line=response.where_is_issue.line,
                text_range=TextRangeResponse(
                    start_line=response.where_is_issue.text_range.start_line,
                    end_line=response.where_is_issue.text_range.end_line,
                    start_offset=response.where_is_issue.text_range.start_offset,
                    end_offset=response.where_is_issue.text_range.end_offset,
                ),
                code_snippet=response.where_is_issue.code_snippet,
            ),
            why_is_issue=IssueWhyResponse(
                issue_message=response.why_is_issue.issue_message,
                severity=response.why_is_issue.severity,
                status=response.why_is_issue.status,
                tags=list(response.why_is_issue.tags),
                rule_key=response.why_is_issue.rule_key,
                rule_name=response.why_is_issue.rule_name,
                html_desc=response.why_is_issue.html_desc,
            ),
            activity=IssueActivityResponse(
                comments=[
                    ActivityCommentResponse(
                        key=item.key,
                        login=item.login,
                        html_text=item.html_text,
                        created_at=item.created_at,
                    )
                    for item in response.activity.comments
                ],
                changelog=[
                    ActivityChangeResponse(
                        created_at=item.created_at,
                        user=item.user,
                        diffs=[
                            ActivityDiffResponse(
                                key=diff.key,
                                old_value=diff.old_value,
                                new_value=diff.new_value,
                            )
                            for diff in item.diffs
                        ],
                    )
                    for item in response.activity.changelog
                ],
            ),
            more_info=IssueMoreInfoResponse(
                documentation_url=response.more_info.documentation_url,
                description_sections=[
                    DescriptionSectionResponse(key=item.key, content=item.content)
                    for item in response.more_info.description_sections
                ],
            ),
        )

    def get_file_issues(
        self,
        scan_id: str,
        file_path: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> FileIssuesResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            response = stub.GetFileIssues(
                sonarqube_pb2.FileIssuesRequest(scan_id=scan_id, file_path=file_path),
                timeout=20.0,
            )
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)
        return FileIssuesResponse(issues=[_issue_from_proto(item) for item in response.issues])

    def list_project_scans(
        self,
        project_key: str,
        page: int,
        page_size: int,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> ProjectScansResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            response = stub.ListProjectScans(
                sonarqube_pb2.ProjectScansRequest(project_key=project_key, page=page, page_size=page_size),
                timeout=10.0,
            )
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)
        return ProjectScansResponse(
            scans=[
                ProjectScanResponse(
                    scan_id=item.scan_id,
                    project_key=item.project_key,
                    branch=item.branch,
                    status=_status_name(item.status),
                    progress=item.progress,
                    created_at=_ts(item.created_at),
                    started_at=_ts(item.started_at),
                    finished_at=_ts(item.finished_at),
                    error_message=item.error_message,
                )
                for item in response.scans
            ],
            page=response.page,
            page_size=response.page_size,
            total=response.total,
        )

    def list_user_scans(
        self,
        project_key: str | None,
        page: int,
        page_size: int,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> ProjectScansResponse:
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            response = stub.ListUserScans(
                sonarqube_pb2.UserScansRequest(
                    project_key=project_key or "",
                    page=page,
                    page_size=page_size,
                ),
                timeout=10.0,
            )
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)
        return ProjectScansResponse(
            scans=[
                ProjectScanResponse(
                    scan_id=item.scan_id,
                    project_key=item.project_key,
                    branch=item.branch,
                    status=_status_name(item.status),
                    progress=item.progress,
                    created_at=_ts(item.created_at),
                    started_at=_ts(item.started_at),
                    finished_at=_ts(item.finished_at),
                    error_message=item.error_message,
                )
                for item in response.scans
            ],
            page=response.page,
            page_size=response.page_size,
            total=response.total,
        )

    def stream_scan_status(
        self,
        scan_id: str,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> Iterable[ScanStatusResponse]:
        stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
        responses = stub.StreamScanStatus(
            sonarqube_pb2.ScanStatusRequest(scan_id=scan_id),
            timeout=0,
        )
        for item in responses:
            yield _scan_status_from_proto(item)

    def stream_scan_logs(
        self,
        scan_id: str,
        include_history: bool,
        history_limit: int,
        phases: list[str],
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> Iterable[ScanLogChunkResponse]:
        metadata = self._metadata(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
        responses = self.stub.StreamScanLogs(
            sonarqube_pb2.StreamScanLogsRequest(
                scan_id=scan_id,
                include_history=include_history,
                history_limit=history_limit,
                phases=phases,
            ),
            metadata=metadata,
            timeout=0,
        )
        for item in responses:
            yield _scan_log_chunk_from_proto(item)

    @staticmethod
    def to_sse_payload(status: ScanStatusResponse) -> str:
        return json.dumps(status.model_dump(mode="json"), default=str)


sonarqube_scan_client = SonarqubeScanClient()
