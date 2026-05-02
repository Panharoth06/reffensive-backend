from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


ExecutionParamScalar = int | str | bool
ExecutionParamValue = ExecutionParamScalar | List[ExecutionParamScalar]


class SecureExecutionTargetScope(BaseModel):
    targets: List[str] = Field(
        default_factory=list,
        description="Authorized target list. Current execution path supports one target per request.",
    )
    allow_internal_targets: bool = Field(
        False,
        description="Require an explicit opt-in before private, loopback, or reserved targets are accepted.",
    )

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, value: List[str]) -> List[str]:
        normalized = [item.strip() for item in value if isinstance(item, str) and item.strip()]
        if not normalized:
            raise ValueError("target_scope.targets must include at least one target")
        if len(normalized) > 1:
            raise ValueError("only one target is supported per secure execution request")
        return normalized


class SecureExecutionResourceLimits(BaseModel):
    memory_limit_bytes: Optional[int] = Field(default=None, ge=1)
    cpu_limit_nano: Optional[int] = Field(default=None, ge=1)


class SecureGVisorConfig(BaseModel):
    platform: Literal["kvm"] = "kvm"
    net_raw: bool = False
    caps_dropped: bool = True


class SecureExecutionSecurityMetadata(BaseModel):
    sbom_url: Optional[str] = None
    scan_status: Literal["clean", "warnings", "blocked"] = "warnings"
    provenance: Optional[str] = None


class SecureExecutionRequest(BaseModel):
    project_id: str
    tool_name: str
    version: Optional[str] = None
    source_url: Optional[str] = None
    target_scope: SecureExecutionTargetScope
    execution_params: Dict[str, ExecutionParamValue] = Field(default_factory=dict)
    timeout: int = Field(default=300, ge=1, le=7200)
    resource_limits: SecureExecutionResourceLimits = Field(default_factory=SecureExecutionResourceLimits)
    execution_mode: Literal["WEB", "CLI", "CICD"] = "WEB"
    net_raw: bool = False
    device_access: bool = False
    dry_run: bool = False

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("tool_name is required")
        return normalized

    @field_validator("source_url")
    @classmethod
    def validate_source_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("execution_params")
    @classmethod
    def validate_execution_params(cls, value: Dict[str, Any]) -> Dict[str, ExecutionParamValue]:
        for key, item in value.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("execution_params keys must be non-empty strings")
            if isinstance(item, list):
                for entry in item:
                    if not isinstance(entry, (bool, int, str)):
                        raise ValueError(
                            f"execution_params['{key}'] list items must be bool, int, or str, got {type(entry).__name__}"
                        )
                continue
            if not isinstance(item, (bool, int, str)):
                raise ValueError(
                    f"execution_params['{key}'] must be a bool, int, str, or list, got {type(item).__name__}"
                )
        return value

    @model_validator(mode="after")
    def validate_capability_requests(self) -> "SecureExecutionRequest":
        if self.net_raw:
            raise ValueError("net_raw requires explicit human approval and is blocked by default")
        if self.device_access:
            raise ValueError("device access requires explicit human approval and is blocked by default")
        return self


class SecureExecutionResponse(BaseModel):
    status: Literal["ready", "building", "executing", "completed", "failed"]
    tool_image: Optional[str] = None
    execution_id: Optional[str] = None
    gvisor_config: SecureGVisorConfig = Field(default_factory=SecureGVisorConfig)
    security_metadata: SecureExecutionSecurityMetadata = Field(default_factory=SecureExecutionSecurityMetadata)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    sanitized_logs: str = ""
    duration_ms: int = 0
    error: Optional[str] = None
