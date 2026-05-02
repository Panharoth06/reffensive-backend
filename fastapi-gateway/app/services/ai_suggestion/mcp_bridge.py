from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urlparse

from app.schemas.ai_suggestion_schemas import InternalMCPContextResponse, SuggestionMode

_SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _normalize_text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    return ""


def _normalize_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _normalize_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _context_findings(context: dict[str, Any]) -> list[dict[str, Any]]:
    raw_findings = context.get("top_findings", context.get("findings"))
    findings = _normalize_list(raw_findings)
    return [item for item in findings if isinstance(item, dict)]


def _context_results(context: dict[str, Any]) -> list[dict[str, Any]]:
    raw_results = context.get("results", context.get("scan_results"))
    results = _normalize_list(raw_results)
    return [item for item in results if isinstance(item, dict)]


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: _SEVERITY_RANK.get(_normalize_text(item.get("severity")).lower(), 0),
        reverse=True,
    )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = _normalize_text(value)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def _is_web_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _linked_assets(context: dict[str, Any]) -> list[str]:
    assets: list[str] = []
    target = _normalize_dict(context.get("target"))
    target_name = _normalize_text(target.get("name"))
    if target_name:
        assets.append(target_name)

    for host in _normalize_list(context.get("hosts")):
        if isinstance(host, str) and host.strip():
            assets.append(host.strip())

    for finding in _context_findings(context):
        host = _normalize_text(finding.get("host"))
        if host:
            assets.append(host)

    return _dedupe(assets)


def _exposed_services(context: dict[str, Any]) -> list[str]:
    services: list[str] = []
    linked_assets = _linked_assets(context)
    ports = [port for port in _normalize_list(context.get("ports")) if isinstance(port, int)]

    if linked_assets and ports:
        primary = linked_assets[0]
        services.extend(f"{primary}:{port}" for port in ports[:8])

    for finding in _context_findings(context):
        host = _normalize_text(finding.get("host"))
        port = finding.get("port")
        if host and isinstance(port, int):
            services.append(f"{host}:{port}")

    return _dedupe(services)[:10]


def _findings_by_host(context: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in _context_findings(context):
        host = _normalize_text(finding.get("host")) or "unknown"
        grouped[host].append(
            {
                "title": _normalize_text(finding.get("title")),
                "severity": _normalize_text(finding.get("severity")).lower() or "unknown",
                "port": finding.get("port"),
                "fingerprint": _normalize_text(finding.get("fingerprint")),
            }
        )

    return {host: _sort_findings(items) for host, items in grouped.items()}


def _tool_observations(context: dict[str, Any]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    grouped: defaultdict[str, Counter] = defaultdict(Counter)

    for result in _context_results(context):
        tool = _normalize_text(result.get("tool")) or _normalize_text(result.get("tool_name")) or "unknown"
        severity = _normalize_text(result.get("severity")).lower() or "unknown"
        grouped[tool][severity] += 1

    for tool, counts in grouped.items():
        observations.append(
            {
                "tool": tool,
                "severity_counts": dict(counts),
                "result_count": int(sum(counts.values())),
            }
        )

    observations.sort(key=lambda item: item["result_count"], reverse=True)
    return observations[:8]


def _candidate_urls(context: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for result in _context_results(context):
        parsed_data = _normalize_dict(result.get("parsed_data"))
        for key in ("url", "endpoint"):
            value = _normalize_text(parsed_data.get(key))
            if _is_web_url(value):
                urls.append(value)
        for key in ("urls", "endpoints"):
            values = _normalize_list(parsed_data.get(key))
            urls.extend(value for value in values if isinstance(value, str) and _is_web_url(value))

        scheme = _normalize_text(parsed_data.get("scheme")).lower()
        host = _normalize_text(parsed_data.get("host"))
        path = _normalize_text(parsed_data.get("path"))
        port = parsed_data.get("port")
        if scheme in {"http", "https"} and host:
            suffix = path if path.startswith("/") else f"/{path}" if path else ""
            if isinstance(port, int) and port > 0 and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
                urls.append(f"{scheme}://{host}:{port}{suffix}")
            else:
                urls.append(f"{scheme}://{host}{suffix}")
    return _dedupe(urls)[:10]


def _candidate_paths(context: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for result in _context_results(context):
        parsed_data = _normalize_dict(result.get("parsed_data"))
        path = _normalize_text(parsed_data.get("path"))
        if path:
            paths.append(path)
        for item in _normalize_list(parsed_data.get("paths")):
            if isinstance(item, str) and item.strip():
                paths.append(item.strip())
    return _dedupe(paths)[:10]


def _executed_tools(tool_observations: list[dict[str, Any]]) -> list[str]:
    return _dedupe([_normalize_text(item.get("tool")) for item in tool_observations])[:8]


def _workflow_hints(context: dict[str, Any], linked_assets: list[str], tool_observations: list[dict[str, Any]], candidate_urls: list[str]) -> list[str]:
    executed = set(_executed_tools(tool_observations))
    hints: list[str] = []
    if {"subfinder", "amass"} & executed:
        hints.append("Discovery already ran on this target; avoid repeating enumeration unless new scope appears.")
    if len(linked_assets) > 1 and "httpx" not in executed:
        hints.append("Multiple assets are already known; validate live web exposure before broadening discovery.")
    if candidate_urls:
        hints.append("Concrete URLs exist; prefer endpoint-specific verification over generic host-level probing.")
    if _normalize_dict(context.get("severity_counts")).get("high"):
        hints.append("Highest-severity findings should drive the first follow-up step.")
    return _dedupe(hints)[:6]


def _focus_areas(mode: SuggestionMode, context: dict[str, Any]) -> list[str]:
    severity_counts = _normalize_dict(context.get("severity_counts"))
    top_findings = _context_findings(context)
    ports = [port for port in _normalize_list(context.get("ports")) if isinstance(port, int)]

    areas: list[str] = []
    if severity_counts.get("critical"):
        areas.append("Prioritize critical findings first and validate exploitability on exposed services.")
    if severity_counts.get("high"):
        areas.append("Reduce externally reachable attack surface on the highest-risk hosts and ports.")
    if 22 in ports:
        areas.append("Review administrative exposure on SSH and restrict access to trusted networks.")
    if top_findings:
        top = top_findings[0]
        if isinstance(top, dict):
            title = _normalize_text(top.get("title"))
            if title:
                areas.append(f"Use the strongest finding as the lead thread: {title}.")

    if mode == "next_steps":
        areas.append("Convert evidence into short, ordered remediation steps with verification actions.")

    deduped: list[str] = []
    seen: set[str] = set()
    for area in areas:
        if area not in seen:
            seen.add(area)
            deduped.append(area)
    return deduped[:6]


def _summary(mode: SuggestionMode, context: dict[str, Any], linked_assets: list[str], exposed_services: list[str]) -> str:
    severity_counts = _normalize_dict(context.get("severity_counts"))
    total_findings = len(_context_findings(context))
    asset_text = linked_assets[0] if linked_assets else "the scanned target"
    severity_text = ", ".join(f"{value} {key}" for key, value in severity_counts.items() if value) or "no severity counts"
    service_text = ", ".join(exposed_services[:3]) if exposed_services else "no exposed services identified"
    mode_label = {
        "next_steps": "remediation planning",
    }[mode]
    return (
        f"MCP bridge prepared {mode_label} context for {asset_text}. "
        f"It includes {total_findings} top findings, severity distribution ({severity_text}), "
        f"and exposed services such as {service_text}."
    )


def build_mcp_context_payload(mode: SuggestionMode, context: dict[str, Any]) -> InternalMCPContextResponse:
    linked_assets = _linked_assets(context)
    exposed_services = _exposed_services(context)
    findings_by_host = _findings_by_host(context)
    tool_observations = _tool_observations(context)
    candidate_urls = _candidate_urls(context)
    candidate_paths = _candidate_paths(context)
    executed_tools = _executed_tools(tool_observations)
    workflow_hints = _workflow_hints(context, linked_assets, tool_observations, candidate_urls)
    focus_areas = _focus_areas(mode, context)

    enriched_context = {
        "scan_job": {
            "job_id": _normalize_text(context.get("job_id")),
            "project_id": _normalize_text(context.get("project_id")),
            "status": _normalize_text(context.get("status")),
            "created_at": _normalize_text(context.get("created_at")),
            "finished_at": _normalize_text(context.get("finished_at")),
        },
        "target_profile": _normalize_dict(context.get("target")),
        "linked_assets": linked_assets,
        "exposed_services": exposed_services,
        "candidate_urls": candidate_urls,
        "candidate_paths": candidate_paths,
        "executed_tools": executed_tools,
        "findings_by_host": findings_by_host,
        "tool_observations": tool_observations,
        "workflow_hints": workflow_hints,
        "focus_areas": focus_areas,
        "scan_metadata": _normalize_dict(context.get("metadata")),
    }

    return InternalMCPContextResponse(
        summary=_summary(mode, context, linked_assets, exposed_services),
        resources=[
            "scan_jobs",
            "targets",
            "findings",
            "scan_results",
        ],
        context=enriched_context,
    )
