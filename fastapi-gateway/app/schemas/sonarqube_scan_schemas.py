from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


ScanStatusLiteral = Literal["PENDING", "IN_PROGRESS", "SUCCESS", "FAILED", "PARTIAL"]
QualityGateLiteral = Literal["OK", "WARN", "ERROR"]


class TriggerScanRequest(BaseModel):
    project_key: str = Field(..., min_length=1)
    branch: str | None = None
    repo_url: str = Field(..., min_length=1)


class TriggerScanResponse(BaseModel):
    scan_id: str
    status: ScanStatusLiteral
    created_at: datetime | None = None


class ScanPhaseResponse(BaseModel):
    key: str
    status: str
    error_message: str = ""


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: ScanStatusLiteral
    progress: int
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_message: str = ""
    phases: list[ScanPhaseResponse] = []


class ScanLogChunkResponse(BaseModel):
    scan_id: str
    phase: str = ""
    level: str = "INFO"
    line: str
    timestamp: datetime | None = None
    sequence_num: int
    is_final_chunk: bool = False
    completion_status: ScanStatusLiteral | None = None


class ScanLogsResponse(BaseModel):
    logs: list[ScanLogChunkResponse]
    is_terminal: bool
    status: ScanStatusLiteral
    next_sequence_num: int


class LanguageSummaryResponse(BaseModel):
    language: str
    total_dependencies: int = 0
    vulnerable_dependencies: int = 0
    outdated_dependencies: int = 0
    license_issues: int = 0


class DependencySummaryResponse(BaseModel):
    scan_id: str
    total: int = 0
    vulnerable: int = 0
    outdated: int = 0
    license_issues: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    by_language: list[LanguageSummaryResponse] = []


class ScanSummaryResponse(BaseModel):
    scan_id: str
    quality_gate: QualityGateLiteral
    bugs: int
    vulnerabilities: int
    code_smells: int
    coverage: float
    duplications: float
    security_hotspots: int
    dependency_summary: DependencySummaryResponse | None = None


class IssueResponse(BaseModel):
    key: str
    type: str
    severity: str
    rule_key: str
    message: str
    file_path: str
    line: int
    status: str
    tags: list[str] = []


class ListIssuesResponse(BaseModel):
    issues: list[IssueResponse]
    page: int
    page_size: int
    total: int


class TextRangeResponse(BaseModel):
    start_line: int = 0
    end_line: int = 0
    start_offset: int = 0
    end_offset: int = 0


class IssueWhereResponse(BaseModel):
    component_key: str = ""
    file_path: str = ""
    line: int = 0
    text_range: TextRangeResponse = TextRangeResponse()
    code_snippet: str = ""


class IssueWhyResponse(BaseModel):
    issue_message: str = ""
    severity: str = ""
    status: str = ""
    tags: list[str] = []
    rule_key: str = ""
    rule_name: str = ""
    html_desc: str = ""


class ActivityDiffResponse(BaseModel):
    key: str = ""
    old_value: str = ""
    new_value: str = ""


class ActivityCommentResponse(BaseModel):
    key: str = ""
    login: str = ""
    html_text: str = ""
    created_at: str = ""


class ActivityChangeResponse(BaseModel):
    created_at: str = ""
    user: str = ""
    diffs: list[ActivityDiffResponse] = []


class IssueActivityResponse(BaseModel):
    comments: list[ActivityCommentResponse] = []
    changelog: list[ActivityChangeResponse] = []


class DescriptionSectionResponse(BaseModel):
    key: str = ""
    content: str = ""


class IssueMoreInfoResponse(BaseModel):
    documentation_url: str = ""
    description_sections: list[DescriptionSectionResponse] = []


class IssueDetailResponse(BaseModel):
    where_is_issue: IssueWhereResponse
    why_is_issue: IssueWhyResponse
    activity: IssueActivityResponse
    more_info: IssueMoreInfoResponse


class FileIssuesResponse(BaseModel):
    issues: list[IssueResponse]


class DependencyResponse(BaseModel):
    package_name: str
    ecosystem: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    latest_version: str = ""
    cve_id: str = ""
    severity: str = ""
    license: str = ""
    is_outdated: bool = False
    is_vulnerable: bool = False
    has_license_issue: bool = False
    description: str = ""
    tool: str = ""
    language: str = ""


class ListDependenciesResponse(BaseModel):
    dependencies: list[DependencyResponse]
    page: int
    page_size: int
    total: int


class ProjectScanResponse(BaseModel):
    scan_id: str
    project_key: str
    branch: str = ""
    status: ScanStatusLiteral
    progress: int
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_message: str = ""


class ProjectScansResponse(BaseModel):
    scans: list[ProjectScanResponse]
    page: int
    page_size: int
    total: int


class ScanTaskRefResponse(BaseModel):
    scan_id: str
    project_key: str


class UserScanTaskRefsResponse(BaseModel):
    tasks: list[ScanTaskRefResponse]
    project_keys: list[str]
    page: int
    page_size: int
    total: int


# Backward-compatible aliases used by routers.
IssueListResponse = ListIssuesResponse
DependencyListResponse = ListDependenciesResponse
