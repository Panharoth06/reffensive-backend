from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator


MediumOptionScalar = Union[int, str, bool]
MediumOptionValueType = Union[MediumOptionScalar, List[MediumOptionScalar]]


class MediumScanOptionDefinition(BaseModel):
    key: str
    flag: str
    type: str  # "integer", "string", "boolean", "array"
    required: bool = False
    description: Optional[str] = None


class MediumScanConfig(BaseModel):
    options: List[MediumScanOptionDefinition] = Field(default_factory=list)


class MediumScanToolConfig(BaseModel):
    """Represents the scan_config.medium structure from tool JSON."""
    medium: MediumScanConfig


class MediumScanOption(BaseModel):
    """A single user-supplied medium scan option value."""
    key: str
    value: MediumOptionValueType


class MediumScanStepRequest(BaseModel):
    tool_id: Optional[str] = None
    tool_name: Optional[str] = None
    runtime_timeout_seconds: Optional[int] = Field(default=None, ge=1)
    tool_options: Dict[str, MediumOptionValueType] = Field(
        default_factory=dict,
        description="User-supplied medium scan options for this step",
    )

    @field_validator("tool_options")
    @classmethod
    def validate_tool_options(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        for key, value in v.items():
            if not key:
                raise ValueError("tool_options keys must not be empty")
            if isinstance(value, list):
                for item in value:
                    if not isinstance(item, (int, str, bool)):
                        raise ValueError(
                            f"tool_options['{key}'] list items must be int, str, or bool, got {type(item).__name__}"
                        )
                continue
            if not isinstance(value, (int, str, bool)):
                raise ValueError(
                    f"tool_options['{key}'] must be int, str, bool, or list, got {type(value).__name__}"
                )
        return v

    @model_validator(mode="after")
    def validate_tool_reference(self) -> "MediumScanStepRequest":
        if not (self.tool_id or self.tool_name):
            raise ValueError("tool_id or tool_name is required for each step")
        return self


class MediumScanSubmitRequest(BaseModel):
    project_id: str
    target_id: Optional[str] = None
    target_value: str
    tool_id: Optional[str] = None
    tool_name: Optional[str] = None
    tool_options: Dict[str, MediumOptionValueType] = Field(
        default_factory=dict,
        description="User-supplied medium scan options (keyed by option key name)",
    )
    steps: List[MediumScanStepRequest] = Field(default_factory=list)
    idempotency_key: Optional[str] = None
    execution_mode: Optional[str] = "WEB"
    runtime_timeout_seconds: Optional[int] = Field(default=None, ge=1)

    @field_validator("tool_options")
    @classmethod
    def validate_tool_options(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        for key, value in v.items():
            if not key:
                raise ValueError("tool_options keys must not be empty")
            if isinstance(value, list):
                for item in value:
                    if not isinstance(item, (int, str, bool)):
                        raise ValueError(
                            f"tool_options['{key}'] list items must be int, str, or bool, got {type(item).__name__}"
                        )
                continue
            if not isinstance(value, (int, str, bool)):
                raise ValueError(
                    f"tool_options['{key}'] must be int, str, bool, or list, got {type(value).__name__}"
                )
        return v

    @model_validator(mode="after")
    def validate_step_shape(self) -> "MediumScanSubmitRequest":
        if self.steps:
            if self.tool_id or self.tool_name or self.tool_options:
                raise ValueError("use either steps or legacy tool fields, not both")
            return self

        if not (self.tool_id or self.tool_name):
            raise ValueError("tool_id or tool_name is required when steps is empty")
        return self


class MediumScanSubmitResponse(BaseModel):
    job_id: str
    step_id: str
    status: str
    is_idempotent_replay: bool
    original_request_id: Optional[str] = None
    queued_at: Optional[datetime] = None


class MediumScanStepStatusResponse(BaseModel):
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


class MediumScanJobStatusResponse(BaseModel):
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
    steps: List["MediumScanStepSummary"] = Field(default_factory=list)


class MediumScanStepSummary(BaseModel):
    step_id: str
    tool_name: str
    step_order: int
    status: str
    findings_count: int = 0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class MediumScanFinding(BaseModel):
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


class MediumParsedDataColumn(BaseModel):
    key: str
    label: str = ""
    type: str = "string"
    description: str = ""
    default_visible: bool = True
    order: int = 0
    known: bool = True
    render_hints: Dict[str, str] = Field(default_factory=dict)


class MediumParsedDataResponse(BaseModel):
    step_id: str
    job_id: str
    tool_name: str
    parse_method: str = "line"
    line_count: int = 0
    findings_count: int = 0
    lines: List[str] = Field(default_factory=list)
    findings: List[MediumScanFinding] = Field(default_factory=list)
    columns: List[MediumParsedDataColumn] = Field(default_factory=list)
    discovered_columns: List[MediumParsedDataColumn] = Field(default_factory=list)
    data: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: Optional[datetime] = None


class MediumJobParsedDataResponse(BaseModel):
    job_id: str
    total_steps: int
    steps: List[MediumParsedDataResponse] = Field(default_factory=list)


class MediumScanResultsResponse(BaseModel):
    scope_id: str
    findings: List[MediumScanFinding] = Field(default_factory=list)
    total_count: int = 0
    limit: int = 0
    offset: int = 0
    has_more: bool = False
    next_cursor: Optional[str] = None
    raw_output_inline: Optional[str] = None
    raw_output_s3_url: Optional[str] = None
