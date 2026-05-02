from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse

from app.schemas.medium_scan_schemas import MediumScanSubmitRequest
from app.schemas.secure_execution_schemas import (
    SecureExecutionRequest,
    SecureExecutionResponse,
    SecureExecutionSecurityMetadata,
)
from app.schemas.tool_schemas import ToolResponse

SAFE_PARAM_KEY_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
JWT_PATTERN = re.compile(r"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SECRET_PATTERNS = (
    re.compile(r"(?i)\b(authorization)\s*:\s*bearer\s+[A-Za-z0-9._=-]+"),
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|access[_-]?key)\b\s*[:=]\s*([^\s,;]+)"),
)
DENIED_EXECUTION_KEYS = {
    "debug",
    "device",
    "docker_socket",
    "env",
    "host_network",
    "interactive",
    "log",
    "log_file",
    "net_raw",
    "network",
    "output",
    "password",
    "privileged",
    "proxy",
    "secret",
    "shell",
    "stderr",
    "stdin",
    "stdout",
    "token",
    "trace",
    "tty",
}
def submit_secure_execution(body: SecureExecutionRequest, user_id: str) -> SecureExecutionResponse:
    try:
        tool = resolve_tool_definition(body.tool_name, body.version)
        target = validate_target_scope(body)
    except ValueError as exc:
        return failed_response(None, error=str(exc))

    source_mismatch = validate_source_alignment(body.source_url, tool)
    if source_mismatch:
        return failed_response(tool, error=source_mismatch)

    params_error = validate_execution_params(body.execution_params)
    if params_error:
        return failed_response(tool, error=params_error)

    if not tool.image_ref:
        return failed_response(
            tool,
            error="tool image is not ready for execution; secure build and promotion must complete first",
        )

    if body.dry_run:
        return SecureExecutionResponse(
            status="ready",
            tool_image=tool.image_ref,
            security_metadata=build_security_metadata(tool),
        )

    submit_resp = get_medium_scan_client().submit_medium_scan(
        MediumScanSubmitRequest(
            project_id=body.project_id,
            target_value=target,
            tool_name=tool.tool_name,
            tool_options=body.execution_params,
            execution_mode=body.execution_mode,
            runtime_timeout_seconds=body.timeout,
        ),
        user_id=user_id,
    )

    return SecureExecutionResponse(
        status="executing",
        tool_image=tool.image_ref,
        execution_id=submit_resp.job_id,
        security_metadata=build_security_metadata(tool),
    )


def get_secure_execution_status(execution_id: str, user_id: str) -> SecureExecutionResponse:
    medium_scan_client = get_medium_scan_client()
    job = medium_scan_client.get_job_status(execution_id, user_id=user_id)

    first_step = job.steps[0] if job.steps else None
    step_status = None
    if first_step is not None:
        step_status = medium_scan_client.get_step_status(first_step.step_id, user_id=user_id)

    tool = None
    if first_step is not None:
        tool = resolve_tool_definition(first_step.tool_name, version=None, allow_missing=True)

    findings: list[dict[str, Any]] = []
    sanitized_logs = ""
    if job.status in {"JOB_STATUS_COMPLETED", "JOB_STATUS_PARTIAL", "JOB_STATUS_FAILED", "JOB_STATUS_CANCELLED"}:
        results = medium_scan_client.get_results(job_id=execution_id, user_id=user_id)
        findings = [sanitize_structure(item.model_dump(mode="json")) for item in results.findings]
        if results.raw_output_inline:
            sanitized_logs = sanitize_text(decode_raw_output(results.raw_output_inline))

    duration_ms = 0
    error = None
    if step_status is not None:
        duration_ms = step_status.duration_ms
        error = step_status.error_message

    return SecureExecutionResponse(
        status=map_job_status(job.status),
        tool_image=tool.image_ref if tool else None,
        execution_id=execution_id,
        security_metadata=build_security_metadata(tool),
        findings=findings,
        sanitized_logs=sanitized_logs,
        duration_ms=duration_ms,
        error=error or None,
    )


def resolve_tool_definition(tool_name: str, version: Optional[str], allow_missing: bool = False) -> Optional[ToolResponse]:
    tool_client = get_tool_client()
    candidates = [
        tool
        for tool in tool_client.list_tools(active_only=True)
        if tool.tool_name.strip().lower() == tool_name.strip().lower()
    ]
    if version:
        candidates = [tool for tool in candidates if (tool.version or "").strip() == version.strip()]

    if not candidates:
        if allow_missing:
            return None
        raise ValueError(f"active tool '{tool_name}' was not found")

    candidates.sort(key=lambda item: (not bool(item.image_ref), item.version or "", item.tool_id))
    return candidates[0]


def validate_source_alignment(source_url: Optional[str], tool: ToolResponse) -> Optional[str]:
    if not source_url:
        return None

    normalized_source = source_url.strip().lower()
    image_ref = (tool.image_ref or "").strip().lower()
    image_source = (tool.image_source or "").strip().lower()
    if normalized_source in {image_ref, image_source}:
        return None

    return "requested source_url does not match the registered tool image/source"


def validate_execution_params(params: Dict[str, Any]) -> Optional[str]:
    for raw_key, raw_value in params.items():
        key = raw_key.strip()
        if not SAFE_PARAM_KEY_PATTERN.match(key):
            return f"execution parameter '{raw_key}' is not allowed"
        if key.lower() in DENIED_EXECUTION_KEYS:
            return f"execution parameter '{raw_key}' violates platform policy"
        if isinstance(raw_value, list):
            if not raw_value:
                return f"execution parameter '{raw_key}' cannot be an empty list"
            for item in raw_value:
                if not isinstance(item, (bool, int, str)):
                    return f"execution parameter '{raw_key}' contains an unsupported list item type"
                if isinstance(item, str):
                    stripped_item = item.strip()
                    if not stripped_item:
                        return f"execution parameter '{raw_key}' cannot contain empty string items"
                    if any(marker in stripped_item for marker in ("\n", "\r", "\x00")):
                        return f"execution parameter '{raw_key}' contains unsafe control characters"
            continue
        if isinstance(raw_value, str):
            stripped = raw_value.strip()
            if not stripped:
                return f"execution parameter '{raw_key}' cannot be empty"
            if any(marker in stripped for marker in ("\n", "\r", "\x00")):
                return f"execution parameter '{raw_key}' contains unsafe control characters"
    return None


def validate_target_scope(body: SecureExecutionRequest) -> str:
    target = body.target_scope.targets[0]
    host = extract_host(target)
    if host is None:
        return target

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        if host.lower() in {"localhost"} and not body.target_scope.allow_internal_targets:
            raise ValueError("localhost is outside the default allowed target scope")
        return target

    if is_sensitive_address(addr) and not body.target_scope.allow_internal_targets:
        raise ValueError("private, loopback, link-local, and reserved targets require explicit approval")
    return target


def extract_host(target: str) -> Optional[str]:
    normalized = target.strip()
    if not normalized:
        return None

    parsed = urlparse(normalized if "://" in normalized else f"//{normalized}")
    return parsed.hostname


def is_sensitive_address(addr: ipaddress._BaseAddress) -> bool:
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def build_security_metadata(tool: Optional[ToolResponse]) -> SecureExecutionSecurityMetadata:
    if tool is None:
        return SecureExecutionSecurityMetadata(scan_status="blocked", provenance="tool-unavailable")

    image_ref = (tool.image_ref or "").strip()
    image_source = (tool.image_source or "").strip()
    if not image_ref:
        return SecureExecutionSecurityMetadata(
            scan_status="blocked",
            provenance=image_source or tool.install_method or "image-missing",
        )

    scan_status = "clean" if "@sha256:" in image_ref else "warnings"
    provenance = image_source or tool.install_method or "registered-image"
    return SecureExecutionSecurityMetadata(
        sbom_url=None,
        scan_status=scan_status,
        provenance=provenance,
    )


def map_job_status(status: str) -> str:
    if status in {"JOB_STATUS_COMPLETED", "JOB_STATUS_PARTIAL"}:
        return "completed"
    if status in {"JOB_STATUS_FAILED", "JOB_STATUS_CANCELLED"}:
        return "failed"
    if status in {"JOB_STATUS_PENDING", "JOB_STATUS_RUNNING"}:
        return "executing"
    return "executing"


def decode_raw_output(raw_output_inline: str) -> str:
    try:
        return base64.b64decode(raw_output_inline).decode("utf-8", errors="replace")
    except (ValueError, binascii.Error):
        return raw_output_inline


def sanitize_text(value: str) -> str:
    sanitized = value
    for pattern in SECRET_PATTERNS:
        sanitized = pattern.sub(lambda match: redact_secret_match(match), sanitized)
    sanitized = JWT_PATTERN.sub("[REDACTED_JWT]", sanitized)
    sanitized = IP_PATTERN.sub(redact_ip_match, sanitized)
    return sanitized


def sanitize_structure(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, list):
        return [sanitize_structure(item) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_structure(item) for key, item in value.items()}
    return value


def redact_secret_match(match: re.Match[str]) -> str:
    groups = match.groups()
    if len(groups) == 1:
        return f"{groups[0]}: Bearer [REDACTED]"
    if len(groups) >= 2:
        return f"{groups[0]}=[REDACTED]"
    return "[REDACTED]"


def redact_ip_match(match: re.Match[str]) -> str:
    raw = match.group(0)
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if is_sensitive_address(addr):
        return "[REDACTED_IP]"
    return raw


def failed_response(tool: Optional[ToolResponse], error: str) -> SecureExecutionResponse:
    return SecureExecutionResponse(
        status="failed",
        tool_image=tool.image_ref if tool else None,
        security_metadata=build_security_metadata(tool),
        error=error,
    )


def get_medium_scan_client():
    from app.internal.medium_scan_client import medium_scan_client

    return medium_scan_client


def get_tool_client():
    from app.internal.tool_client import tool_client

    return tool_client
