from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


def _normalize_install_method(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip().lower()
    if not normalized:
        return None
    if normalized in {"docker", "official", "official_image", "registry", "image"}:
        return "official_image"
    if normalized in {"custom", "custom_build", "source", "binary"}:
        return "custom_build"
    return normalized


def _normalize_shadow_path_mode(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip().lower()
    if not normalized:
        return None
    if normalized == "stdout":
        return "streaming"
    return normalized


def _normalize_parser_type(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip().lower()
    if not normalized:
        return None
    if normalized == "line":
        return "lines"
    return normalized


# ─── Structured schema field types ────────────────────────────────────────────

class InputField(BaseModel):
    key: str
    type: str
    required: Optional[bool] = None
    flag: Optional[str] = None
    format: Optional[str] = None
    enum: Optional[List[Any]] = None
    description: Optional[str] = None


class PipelineInputTransport(BaseModel):
    multi_mode: Literal["first", "list_file"] = "first"
    list_flag: Optional[str] = None
    target_field: Optional[str] = None


class InputSchema(BaseModel):
    type: Literal["object"] = "object"
    fields: List[InputField]
    pipeline_input: Optional[PipelineInputTransport] = None


class OptionFlag(BaseModel):
    flag: str
    key: str
    type: Literal["integer", "string", "boolean", "array"]
    description: Optional[str] = None
    enum: Optional[List[Any]] = None
    required: Optional[bool] = None


class ScanPreset(BaseModel):
    name: str
    description: Optional[str] = None
    flags: List[str] = Field(default_factory=list)


class ScanModeOptions(BaseModel):
    options: List[OptionFlag] = Field(default_factory=list)


class ScanBasicMode(BaseModel):
    presets: List[ScanPreset] = Field(default_factory=list)


class ScanConfig(BaseModel):
    basic: ScanBasicMode = Field(default_factory=ScanBasicMode)
    medium: ScanModeOptions = Field(default_factory=ScanModeOptions)
    # Advanced mode can be a raw terminal-style command flow, so this section is
    # optional metadata for known/common flags rather than a full allowlist.
    advanced: ScanModeOptions = Field(default_factory=ScanModeOptions)
    runtime: Optional["ToolRuntimeConfig"] = None


class ToolRuntimeConfig(BaseModel):
    use_gvisor: Optional[bool] = Field(
        None,
        description="Override whether this tool should run under gVisor"
    )
    network_mode: Optional[Literal["bridge", "host", "none"]] = Field(
        None,
        description="Optional Docker network mode override for this tool"
    )
    privileged: Optional[bool] = Field(
        None,
        description="Whether this tool requires privileged execution"
    )
    cap_add: List[str] = Field(
        default_factory=list,
        description="Optional Linux capabilities to add for tools that need raw socket access"
    )


class OutputField(BaseModel):
    key: str
    type: str
    label: Optional[str] = None
    description: Optional[str] = None
    finding_title: Optional[bool] = None
    finding_severity: Optional[bool] = None
    finding_host: Optional[bool] = None
    finding_description: Optional[bool] = None
    pipeline_extract: Optional[bool] = None
    items: Optional[OutputSchema] = None
    fields: Optional[List[OutputField]] = None


class PipelineOutputTransport(BaseModel):
    mode: Literal["lines", "jsonl", "json_array", "xml"] = "lines"
    entity: Optional[str] = None
    extract_field: Optional[str] = None
    dedupe: bool = True


class OutputSchema(BaseModel):
    type: str
    description: Optional[str] = None
    fields: Optional[List[OutputField]] = None
    items: Optional[OutputSchema] = None
    pipeline_output: Optional[PipelineOutputTransport] = None


OutputField.model_rebuild()
OutputSchema.model_rebuild()


# ─── Shadow Output Configuration ──────────────────────────────────────────────

class ShadowOutputConfig(BaseModel):
    """Configuration for shadow output pattern - allows dynamic tool execution without code changes"""
    preferred_format: str = Field(
        ...,
        description="Default structured output format key to use from the formats map"
    )
    formats: Dict[str, "ShadowOutputFormat"] = Field(
        default_factory=dict,
        description="Per-format transport metadata used for internal flag injection"
    )
    default_path: str = Field(
        "/tmp/shadow",
        description="Default directory for shadow output files"
    )
    filename_template: Optional[str] = Field(
        None,
        description="Template for filename generation. Use {job_id}, {step_id}, {tool_name}, {timestamp}"
    )
    parse_timeout_seconds: int = Field(
        30,
        description="Timeout for parsing shadow output after tool completion"
    )
    fallback_to_stdout: bool = Field(
        True,
        description="If true, parse stdout when file output fails"
    )
    is_streaming: bool = Field(
        True,
        description="If true, stream logs to Redis in real-time"
    )
    json_flag: Optional[str] = Field(
        None,
        description="Legacy stdout-format enable flag retained for backward compatibility"
    )
    file_flag: Optional[str] = Field(
        None,
        description="Legacy file-output flag retained for backward compatibility"
    )
    alternative_formats: List[str] = Field(
        default_factory=list,
        description="Legacy alternative format list retained for backward compatibility"
    )


class ShadowOutputFormat(BaseModel):
    transport: Literal["stdout", "file"] = Field(
        ...,
        description="How the selected format is produced by the tool"
    )
    enable_flags: List[str] = Field(
        default_factory=list,
        description="Additional flags injected before execution, e.g. ['-json']"
    )
    path_flag: Optional[str] = Field(
        None,
        description="Flag used to pass an output path when transport='file'"
    )
    parser: Literal["json", "jsonl", "json_array", "xml", "lines", "raw"] = Field(
        "raw",
        description="Parser family to use when consuming the captured output"
    )
    path_mode: Literal["file", "basename", "streaming"] = Field(
        "file",
        description="Whether file output expects a full file path or a basename"
    )
    file_extension: Optional[str] = Field(
        None,
        description="Suggested file extension for generated outputs, e.g. '.xml'"
    )

    @field_validator("path_mode", mode="before")
    @classmethod
    def normalize_path_mode(cls, value: Optional[str]) -> Optional[str]:
        return _normalize_shadow_path_mode(value)


ShadowOutputConfig.model_rebuild()
ScanConfig.model_rebuild()


# ─── Parser Configuration ─────────────────────────────────────────────────────

class ParserFieldMappings(BaseModel):
    title: List[str] = Field(default_factory=list)
    severity: Optional[str] = None
    host: List[str] = Field(default_factory=list)
    description: List[str] = Field(default_factory=list)
    metadata: List[str] = Field(default_factory=list)


class InterestingRule(BaseModel):
    field: str
    condition: Literal["gte", "lte", "eq", "in", "neq"]
    value: Any


class ParserConfig(BaseModel):
    type: Literal["jsonl", "json_array", "xml", "lines"]
    field_mappings: ParserFieldMappings = Field(default_factory=ParserFieldMappings)
    default_severity: Optional[str] = None
    fingerprint_fields: List[str] = Field(default_factory=list)
    interesting_rule: Optional[InterestingRule] = None

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, value: Optional[str]) -> Optional[str]:
        return _normalize_parser_type(value)


# ─── Shared tool response ─────────────────────────────────────────────────────

class ToolResponse(BaseModel):
    tool_id: str
    category_name: Optional[str] = None
    tool_name: str
    tool_description: Optional[str] = None
    tool_long_description: Optional[str] = None
    examples: List[dict[str, Any]] = Field(default_factory=list)
    input_schema: Optional[InputSchema] = None
    output_schema: Optional[OutputSchema] = None
    scan_config: Optional[ScanConfig] = None
    install_method: Optional[str] = None
    version: Optional[str] = None
    image_ref: Optional[str] = None
    image_source: Optional[str] = None
    is_active: bool
    denied_options: List[str] = Field(default_factory=list)
    shadow_output_config: Optional[ShadowOutputConfig] = None
    parser_config: Optional[ParserConfig] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @field_validator("install_method", mode="before")
    @classmethod
    def normalize_install_method(cls, value: Optional[str]) -> Optional[str]:
        return _normalize_install_method(value)


# ─── Create ───────────────────────────────────────────────────────────────────

class CreateToolRequest(BaseModel):
    category_name: Optional[str] = Field(None, description="Category name (must exist in DB)")
    tool_name: str = Field(..., min_length=1)
    tool_description: Optional[str] = None
    tool_long_description: Optional[str] = None
    examples: List[dict[str, Any]] = Field(default_factory=list)
    input_schema: Optional[InputSchema] = None
    output_schema: Optional[OutputSchema] = None
    scan_config: Optional[ScanConfig] = None
    install_method: Optional[str] = None
    version: Optional[str] = Field(None, description="Version string e.g. '7.94'. Created if not found.")
    image_ref: Optional[str] = None
    image_source: Optional[str] = None
    build_config: Optional[Dict[str, Any]] = None
    is_active: bool = True
    denied_options: List[str] = Field(default_factory=list)
    shadow_output_config: Optional[ShadowOutputConfig] = Field(
        None,
        description="Shadow output configuration for dynamic tool execution"
    )
    parser_config: Optional[ParserConfig] = Field(
        None,
        description="Optional parser configuration used to extract structured rows and findings"
    )

    @field_validator("install_method", mode="before")
    @classmethod
    def normalize_install_method(cls, value: Optional[str]) -> Optional[str]:
        return _normalize_install_method(value)


# ─── Update (partial — empty string = keep existing) ─────────────────────────

class UpdateToolRequest(BaseModel):
    category_name: Optional[str] = None
    tool_name: Optional[str] = None
    tool_description: Optional[str] = None
    tool_long_description: Optional[str] = None
    examples: Optional[List[dict[str, Any]]] = None
    input_schema: Optional[InputSchema] = None
    output_schema: Optional[OutputSchema] = None
    scan_config: Optional[ScanConfig] = None
    install_method: Optional[str] = None
    version: Optional[str] = None
    image_ref: Optional[str] = None
    image_source: Optional[str] = None
    build_config: Optional[Dict[str, Any]] = None
    denied_options: Optional[List[str]] = None
    shadow_output_config: Optional[ShadowOutputConfig] = None
    parser_config: Optional[ParserConfig] = None

    @field_validator("install_method", mode="before")
    @classmethod
    def normalize_install_method(cls, value: Optional[str]) -> Optional[str]:
        return _normalize_install_method(value)


# ─── Soft-delete / activate response ─────────────────────────────────────────

class SetToolActiveResponse(BaseModel):
    tool_id: str
    is_active: bool
