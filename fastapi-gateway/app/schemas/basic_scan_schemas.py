from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class BasicScanSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    target: str
    tool: str
    preset: Optional[str] = Field(
        None,
        description=(
            "Preset name to apply. Use the exact name from the tool's scan_config.basic.presets "
            "(e.g. 'top-ports', 'service-detect') or the generic aliases 'light' / 'deep'. "
            "Defaults to the first available preset when omitted."
        ),
    )


class BasicPresetOption(BaseModel):
    name: str
    description: str
    flags: List[str] = Field(default_factory=list)


class BasicScanConfigBasic(BaseModel):
    presets: List[BasicPresetOption] = Field(default_factory=list)


class BasicScanConfig(BaseModel):
    basic: BasicScanConfigBasic


class BasicScanOptionsResponse(BaseModel):
    scan_config: BasicScanConfig


class BasicScanSubmitResponse(BaseModel):
    job_id: str
    step_id: str
    status: str
    is_idempotent_replay: bool
    original_request_id: Optional[str] = None
    queued_at: Optional[datetime] = None


class BasicStepStatusResponse(BaseModel):
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


class BasicStepSummary(BaseModel):
    step_id: str
    tool_name: str
    step_order: int
    status: str
    findings_count: int = 0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class BasicJobStatusResponse(BaseModel):
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
    steps: List[BasicStepSummary] = Field(default_factory=list)


class BasicFinding(BaseModel):
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


class BasicParsedDataColumn(BaseModel):
    key: str
    label: str = ""
    type: str = "string"
    description: str = ""
    default_visible: bool = True
    order: int = 0
    known: bool = True
    render_hints: Dict[str, str] = Field(default_factory=dict)


class BasicParsedDataResponse(BaseModel):
    step_id: str
    job_id: str
    tool_name: str
    parse_method: str = "line"
    line_count: int = 0
    findings_count: int = 0
    lines: List[str] = Field(default_factory=list)
    findings: List[BasicFinding] = Field(default_factory=list)
    columns: List[BasicParsedDataColumn] = Field(default_factory=list)
    discovered_columns: List[BasicParsedDataColumn] = Field(default_factory=list)
    data: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: Optional[datetime] = None


class BasicResultsResponse(BaseModel):
    scope_id: str
    findings: List[BasicFinding] = Field(default_factory=list)
    total_count: int = 0
    limit: int = 0
    offset: int = 0
    has_more: bool = False
    next_cursor: Optional[str] = None
    raw_output_inline: Optional[str] = None
    raw_output_s3_url: Optional[str] = None
    parsed_data: Optional[BasicParsedDataResponse] = None


class BasicFindingsResponse(BaseModel):
    scope_id: str
    findings: List[BasicFinding] = Field(default_factory=list)
    total_count: int = 0
    limit: int = 0
    offset: int = 0
    has_more: bool = False
    next_cursor: Optional[str] = None


class BasicResultsSummaryResponse(BaseModel):
    scope_id: str
    scope_type: str
    job_id: str
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
    steps: List[BasicStepSummary] = Field(default_factory=list)
