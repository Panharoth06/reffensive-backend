import functools

import grpc

from app.core.config import get_settings
from app.gen import user_pb2, user_pb2_grpc


@functools.lru_cache(maxsize=4)
def _get_user_stub(grpc_server_addr: str) -> user_pb2_grpc.UserServiceStub:
    channel = grpc.insecure_channel(grpc_server_addr)
    return user_pb2_grpc.UserServiceStub(channel)


def get_user_stub() -> user_pb2_grpc.UserServiceStub:
    settings = get_settings()
    return _get_user_stub(settings.grpc_server_addr)


def check_user_exists(user_id: str = "", email: str = "", username: str = "", timeout: float = 3.0):
    request = user_pb2.CheckUserExistsRequest(
        user_id=user_id,
        email=email,
        username=username,
    )
    return get_user_stub().CheckUserExists(request, timeout=timeout)


def create_user(
    user_id: str,
    username: str,
    email: str,
    alias_name: str = "",
    avatar_profile: str = "",
    timeout: float = 5.0,
):
    request = user_pb2.CreateUserRequest(
        user_id=user_id,
        username=username,
        email=email,
        alias_name=alias_name,
        avatar_profile=avatar_profile,
    )
    return get_user_stub().CreateUser(request, timeout=timeout)


def get_user(user_id: str, timeout: float = 3.0):
    request = user_pb2.GetUserRequest(user_id=user_id)
    return get_user_stub().GetUser(request, timeout=timeout)


def list_users(timeout: float = 5.0):
    request = user_pb2.ListUsersRequest()
    return get_user_stub().ListUsers(request, timeout=timeout)


def update_user(
    user_id: str,
    username: str = "",
    email: str = "",
    alias_name: str | None = None,
    avatar_profile: str | None = None,
    timeout: float = 5.0,
):
    request = user_pb2.UpdateUserRequest(
        user_id=user_id,
        username=username,
        email=email,
    )
    if alias_name is not None:
        request.alias_name = alias_name
    if avatar_profile is not None:
        request.avatar_profile = avatar_profile
    return get_user_stub().UpdateUser(request, timeout=timeout)


def delete_user(user_id: str, timeout: float = 3.0):
    request = user_pb2.DeleteUserRequest(user_id=user_id)
    return get_user_stub().DeleteUser(request, timeout=timeout)


def upsert_github_provider_account(
    user_id: str,
    provider_account_id: str,
    provider_username: str,
    provider_email: str,
    access_token: str,
    refresh_token: str | None = None,
    timeout: float = 5.0,
):
    return upsert_provider_account(
        user_id=user_id,
        provider_type="github",
        provider_account_id=provider_account_id,
        provider_username=provider_username,
        provider_email=provider_email,
        access_token=access_token,
        refresh_token=refresh_token,
        timeout=timeout,
    )


def upsert_provider_account(
    user_id: str,
    provider_type: str,
    provider_account_id: str,
    provider_username: str,
    provider_email: str = "",
    access_token: str | None = None,
    refresh_token: str | None = None,
    timeout: float = 5.0,
):
    request = user_pb2.UpsertProviderAccountRequest(
        user_id=user_id,
        provider_type=provider_type,
        provider_account_id=provider_account_id,
        provider_username=provider_username,
        provider_email=provider_email,
    )
    if access_token is not None:
        request.access_token = access_token
    if refresh_token is not None:
        request.refresh_token = refresh_token
    return get_user_stub().UpsertProviderAccount(request, timeout=timeout)


def list_provider_accounts(user_id: str, timeout: float = 5.0):
    request = user_pb2.ListProviderAccountsRequest(user_id=user_id)
    return get_user_stub().ListProviderAccounts(request, timeout=timeout)


def list_provider_auth_accounts(
    user_id: str,
    provider_type: str,
    timeout: float = 5.0,
):
    request = user_pb2.ListProviderAuthAccountsRequest(
        user_id=user_id,
        provider_type=provider_type,
    )
    return get_user_stub().ListProviderAuthAccounts(request, timeout=timeout)


def persist_code_scan_context(
    user_id: str,
    provider_type: str,
    provider_account_id: str,
    repository_full_name: str,
    repository_is_private: bool,
    repository_default_branch: str,
    branch_name: str,
    commit_sha: str,
    source_snapshot_hash: str,
    scan_type: str,
    scan_config_hash: str,
    provider_repository_id: str = "",
    dependency_hash: str | None = None,
    timeout: float = 5.0,
):
    request = user_pb2.PersistCodeScanContextRequest(
        user_id=user_id,
        provider_type=provider_type,
        provider_account_id=provider_account_id,
        provider_repository_id=provider_repository_id,
        repository_full_name=repository_full_name,
        repository_is_private=repository_is_private,
        repository_default_branch=repository_default_branch,
        branch_name=branch_name,
        commit_sha=commit_sha,
        source_snapshot_hash=source_snapshot_hash,
        scan_type=scan_type,
        scan_config_hash=scan_config_hash,
    )
    if dependency_hash is not None:
        request.dependency_hash = dependency_hash
    return get_user_stub().PersistCodeScanContext(request, timeout=timeout)


def finish_code_scan_job(
    code_scan_job_id: str,
    status: str,
    error_message: str | None = None,
    timeout: float = 5.0,
):
    request = user_pb2.FinishCodeScanJobRequest(
        code_scan_job_id=code_scan_job_id,
        status=status,
    )
    if error_message is not None:
        request.error_message = error_message
    return get_user_stub().FinishCodeScanJob(request, timeout=timeout)


def upsert_sonar_project_context(
    repository_id: str,
    sonar_project_key: str,
    sonar_project_name: str,
    sonar_host_url: str,
    main_branch: str,
    repository_hash: str,
    status: str = "ACTIVE",
    sonar_external_id: str | None = None,
    timeout: float = 5.0,
):
    request = user_pb2.UpsertSonarProjectContextRequest(
        repository_id=repository_id,
        sonar_project_key=sonar_project_key,
        sonar_project_name=sonar_project_name,
        sonar_host_url=sonar_host_url,
        main_branch=main_branch,
        repository_hash=repository_hash,
        status=status,
    )
    if sonar_external_id is not None:
        request.sonar_external_id = sonar_external_id
    return get_user_stub().UpsertSonarProjectContext(request, timeout=timeout)


def get_cached_sonar_result(
    repository_id: str,
    repository_hash: str,
    scan_config_hash: str,
    timeout: float = 5.0,
):
    request = user_pb2.GetCachedSonarResultRequest(
        repository_id=repository_id,
        repository_hash=repository_hash,
        scan_config_hash=scan_config_hash,
    )
    return get_user_stub().GetCachedSonarResult(request, timeout=timeout)


def upsert_sonar_scan_step(
    code_scan_job_id: str,
    step_key: str,
    step_order: int,
    status: str,
    sonar_project_id: str | None = None,
    message: str | None = None,
    stdout_log: str | None = None,
    stderr_log: str | None = None,
    payload_json: str | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
    timeout: float = 5.0,
):
    request = user_pb2.UpsertSonarScanStepRequest(
        code_scan_job_id=code_scan_job_id,
        step_key=step_key,
        step_order=step_order,
        status=status,
    )
    if sonar_project_id is not None:
        request.sonar_project_id = sonar_project_id
    if message is not None:
        request.message = message
    if stdout_log is not None:
        request.stdout_log = stdout_log
    if stderr_log is not None:
        request.stderr_log = stderr_log
    if payload_json is not None:
        request.payload_json = payload_json
    if started_at is not None:
        request.started_at = started_at
    if finished_at is not None:
        request.finished_at = finished_at
    return get_user_stub().UpsertSonarScanStep(request, timeout=timeout)


def persist_sonar_final_result(
    code_scan_job_id: str,
    sonar_project_id: str,
    analysis_key: str,
    quality_gate_status: str,
    bugs_count: int,
    vulnerabilities_count: int,
    code_smells_count: int,
    quality_gate_payload_json: str,
    measures_payload_json: str,
    repository_hash: str,
    scan_config_hash: str,
    job_status: str,
    ce_task_id: str | None = None,
    coverage: float | None = None,
    duplicated_lines_density: float | None = None,
    error_message: str | None = None,
    analysis_hash: str = "",
    timeout: float = 6.0,
):
    request = user_pb2.PersistSonarFinalResultRequest(
        code_scan_job_id=code_scan_job_id,
        sonar_project_id=sonar_project_id,
        analysis_key=analysis_key,
        quality_gate_status=quality_gate_status,
        bugs_count=bugs_count,
        vulnerabilities_count=vulnerabilities_count,
        code_smells_count=code_smells_count,
        quality_gate_payload_json=quality_gate_payload_json,
        measures_payload_json=measures_payload_json,
        repository_hash=repository_hash,
        scan_config_hash=scan_config_hash,
        job_status=job_status,
        analysis_hash=analysis_hash,
    )
    if ce_task_id is not None:
        request.ce_task_id = ce_task_id
    if coverage is not None:
        request.coverage = coverage
    if duplicated_lines_density is not None:
        request.duplicated_lines_density = duplicated_lines_density
    if error_message is not None:
        request.error_message = error_message
    return get_user_stub().PersistSonarFinalResult(request, timeout=timeout)


def list_sonar_scan_histories(
    user_id: str,
    repository_full_name: str | None = None,
    project_key: str | None = None,
    status: str | None = None,
    limit: int = 50,
    timeout: float = 6.0,
):
    request = user_pb2.ListSonarScanHistoriesRequest(
        user_id=user_id,
        limit=limit,
    )
    if repository_full_name is not None:
        request.repository_full_name = repository_full_name
    if project_key is not None:
        request.project_key = project_key
    if status is not None:
        request.status = status
    return get_user_stub().ListSonarScanHistories(request, timeout=timeout)


def get_sonar_scan_history_detail(
    user_id: str,
    code_scan_job_id: str,
    timeout: float = 6.0,
):
    request = user_pb2.GetSonarScanHistoryDetailRequest(
        user_id=user_id,
        code_scan_job_id=code_scan_job_id,
    )
    return get_user_stub().GetSonarScanHistoryDetail(request, timeout=timeout)


def get_sonarqube_health(timeout: float = 5.0):
    request = user_pb2.GetSonarQubeHealthRequest()
    return get_user_stub().GetSonarQubeHealth(request, timeout=timeout)


def provision_sonar_project_gateway(
    project_key: str | None = None,
    project_name: str | None = None,
    repository_full_name: str | None = None,
    main_branch: str | None = None,
    visibility: str | None = None,
    timeout: float = 6.0,
):
    request = user_pb2.ProvisionSonarProjectGatewayRequest()
    if project_key is not None:
        request.project_key = project_key
    if project_name is not None:
        request.project_name = project_name
    if repository_full_name is not None:
        request.repository_full_name = repository_full_name
    if main_branch is not None:
        request.main_branch = main_branch
    if visibility is not None:
        request.visibility = visibility
    return get_user_stub().ProvisionSonarProjectGateway(request, timeout=timeout)


def get_sonar_project_summary_gateway(project_key: str, timeout: float = 6.0):
    request = user_pb2.GetSonarProjectSummaryGatewayRequest(project_key=project_key)
    return get_user_stub().GetSonarProjectSummaryGateway(request, timeout=timeout)


def get_sonar_issue_detail_gateway(issue_key: str, timeout: float = 6.0):
    request = user_pb2.GetSonarIssueDetailGatewayRequest(issue_key=issue_key)
    return get_user_stub().GetSonarIssueDetailGateway(request, timeout=timeout)


def start_sonar_analysis_gateway(
    user_id: str,
    repository_url: str,
    branch: str | None = None,
    project_key: str | None = None,
    project_name: str | None = None,
    scan_dependency: bool = False,
    timeout: float = 6.0,
):
    request = user_pb2.StartSonarAnalysisGatewayRequest(
        user_id=user_id,
        repository_url=repository_url,
        scan_dependency=scan_dependency,
    )
    if branch is not None:
        request.branch = branch
    if project_key is not None:
        request.project_key = project_key
    if project_name is not None:
        request.project_name = project_name
    return get_user_stub().StartSonarAnalysisGateway(request, timeout=timeout)


def list_sonar_analyses_gateway(
    user_id: str,
    repository_full_name: str | None = None,
    project_key: str | None = None,
    status: str | None = None,
    limit: int = 50,
    timeout: float = 6.0,
):
    request = user_pb2.ListSonarAnalysesGatewayRequest(
        user_id=user_id,
        limit=limit,
    )
    if repository_full_name is not None:
        request.repository_full_name = repository_full_name
    if project_key is not None:
        request.project_key = project_key
    if status is not None:
        request.status = status
    return get_user_stub().ListSonarAnalysesGateway(request, timeout=timeout)


def get_sonar_analysis_gateway(
    requester_user_id: str,
    job_id: str,
    requester_is_admin: bool = False,
    timeout: float = 6.0,
):
    request = user_pb2.GetSonarAnalysisGatewayRequest(
        requester_user_id=requester_user_id,
        job_id=job_id,
        requester_is_admin=requester_is_admin,
    )
    return get_user_stub().GetSonarAnalysisGateway(request, timeout=timeout)
