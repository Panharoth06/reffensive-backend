from __future__ import annotations

from enum import Enum
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

class ExecutionMode(str, Enum):
    WEB = "web"
    CLI = "cli"
    CICD = "cicd"

class AdvancedScanSubmitRequest(BaseModel):
    project_id: str
    command: str
    idempotency_key: Optional[str] = None
    execution_mode: ExecutionMode


class AdvancedScanSubmitResponse(BaseModel):
    job_id: str
    step_id: str
    status: str
    is_idempotent_replay: bool
    original_request_id: Optional[str] = None
    queued_at: Optional[datetime] = None
    retry_after_seconds: Optional[int] = None


class AdvancedStepStatusResponse(BaseModel):
    step_id: str
    job_id: str
    tool_name: str
    status: str
    exit_code: int
    error_message: Optional[str] = None
    queued_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_ms: int = 0
    findings_count: int = 0
    raw_output_location: Optional[str] = None
    has_parsed_results: bool = False


class AdvancedStepSummary(BaseModel):
    step_id: str
    tool_name: str
    step_order: int
    status: str
    findings_count: int = 0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class AdvancedJobStatusResponse(BaseModel):
    job_id: str
    project_id: str
    status: str
    total_steps: int
    completed_steps: int
    failed_steps: int
    pending_steps: int
    total_findings: int = 0
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    steps: List[AdvancedStepSummary] = Field(default_factory=list)


class AdvancedFinding(BaseModel):
    finding_id: str
    step_id: str
    job_id: str
    title: str = ""
    severity: str
    fingerprint: str = ""
    host: str = ""
    port: int = 0
    protocol: str = ""
    url: str = ""
    description: str = ""
    remediation: str = ""
    references: List[str] = Field(default_factory=list)
    metadata: Dict[str, str] = Field(default_factory=dict)
    tags: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[datetime] = None


class AdvancedParsingMetadata(BaseModel):
    parser_name: str = ""
    parser_version: str = ""
    parsed_at: Optional[datetime] = None
    raw_size_bytes: int = 0
    parsed_size_bytes: int = 0
    parsing_error: Optional[str] = None
    is_partial: bool = False


class AdvancedFindingsResponse(BaseModel):
    scope_id: str
    findings: List[AdvancedFinding] = Field(default_factory=list)
    total_count: int = 0
    limit: int = 0
    offset: int = 0
    has_more: bool = False
    next_cursor: Optional[str] = None


class AdvancedResultsResponse(AdvancedFindingsResponse):
    raw_output_inline: Optional[str] = None
    raw_output_s3_url: Optional[str] = None
    parsing_metadata: Optional[AdvancedParsingMetadata] = None


class AdvancedResultsSummaryResponse(BaseModel):
    scope_id: str
    scope_type: str
    job_id: str
    step_id: Optional[str] = None
    status: str
    total_steps: int = 0
    total_findings: int = 0
    unique_hosts: int = 0
    unique_ports: int = 0
    unique_services: int = 0
    unique_fingerprints: int = 0
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    steps: List[AdvancedStepSummary] = Field(default_factory=list)


class AdvancedRawOutputResponse(BaseModel):
    step_id: str
    job_id: str
    raw_output_inline: Optional[str] = None
    raw_output_s3_url: Optional[str] = None
    parsing_metadata: Optional[AdvancedParsingMetadata] = None


class RedisLogEvent(BaseModel):
    step_id: str
    job_id: str
    tool_name: str
    source: str
    line: str
    timestamp: str
    sequence_num: int
    is_final_chunk: bool | None = None
    completion_status: str | None = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class QueueStatusResponse(BaseModel):
    queued_jobs: int
    processing_jobs: int
    total_jobs: int
    max_concurrent: int = 20
    max_queue_capacity: int = 20


class JobQueuePositionResponse(BaseModel):
    job_id: str
    status: str  # "queued", "processing", "not_in_queue"
    position: int  # 0-indexed position in queue


class CancelQueuedJobResponse(BaseModel):
    success: bool
    message: str


class ParsedDataColumn(BaseModel):
    key: str
    label: str = ""
    type: str = "string"             # string | integer | number | array | boolean | object
    description: str = ""
    default_visible: bool = True
    order: int = 0
    known: bool = True               # True = from schema, False = auto-discovered
    render_hints: Dict[str, str] = Field(default_factory=dict)


class ParsedDataResponse(BaseModel):
    step_id: str
    job_id: str
    tool_name: str
    parse_method: str = "line"       # "xml", "json_array", "jsonl", "line"
    line_count: int = 0
    findings_count: int = 0
    lines: List[str] = Field(default_factory=list)   # backward compat: JSON strings of rows
    findings: List[AdvancedFinding] = Field(default_factory=list)
    columns: List[ParsedDataColumn] = Field(default_factory=list)          # known from schema
    discovered_columns: List[ParsedDataColumn] = Field(default_factory=list)  # auto-discovered
    data: List[Dict[str, Any]] = Field(default_factory=list)  # structured JSON objects (rows)
    created_at: Optional[datetime] = None


class JobParsedDataResponse(BaseModel):
    """Aggregated parsed data for all steps in a job, ordered by step_order."""
    job_id: str
    total_steps: int
    steps: List[ParsedDataResponse] = Field(default_factory=list)
