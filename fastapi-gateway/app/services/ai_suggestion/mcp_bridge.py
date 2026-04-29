from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

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


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: _SEVERITY_RANK.get(_normalize_text(item.get("severity")).lower(), 0),
        reverse=True,
    )


def _linked_assets(context: dict[str, Any]) -> list[str]:
    assets: list[str] = []
    target = _normalize_dict(context.get("target"))
    target_name = _normalize_text(target.get("name"))
    if target_name:
        assets.append(target_name)

    for host in _normalize_list(context.get("hosts")):
        if isinstance(host, str) and host.strip():
            assets.append(host.strip())

    for finding in _normalize_list(context.get("top_findings")):
        if not isinstance(finding, dict):
            continue
        host = _normalize_text(finding.get("host"))
        if host:
            assets.append(host)

    seen: set[str] = set()
    deduped: list[str] = []
    for asset in assets:
        if asset not in seen:
            seen.add(asset)
            deduped.append(asset)
    return deduped


def _exposed_services(context: dict[str, Any]) -> list[str]:
    services: list[str] = []
    linked_assets = _linked_assets(context)
    ports = [port for port in _normalize_list(context.get("ports")) if isinstance(port, int)]

    if linked_assets and ports:
        primary = linked_assets[0]
        services.extend(f"{primary}:{port}" for port in ports[:8])

    for finding in _normalize_list(context.get("top_findings")):
        if not isinstance(finding, dict):
            continue
        host = _normalize_text(finding.get("host"))
        port = finding.get("port")
        if host and isinstance(port, int):
            services.append(f"{host}:{port}")

    seen: set[str] = set()
    deduped: list[str] = []
    for service in services:
        if service not in seen:
            seen.add(service)
            deduped.append(service)
    return deduped[:10]


def _findings_by_host(context: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in _normalize_list(context.get("top_findings")):
        if not isinstance(finding, dict):
            continue
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

    for result in _normalize_list(context.get("results")):
        if not isinstance(result, dict):
            continue
        tool = _normalize_text(result.get("tool")) or "unknown"
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


def _focus_areas(mode: SuggestionMode, context: dict[str, Any]) -> list[str]:
    severity_counts = _normalize_dict(context.get("severity_counts"))
    top_findings = _normalize_list(context.get("top_findings"))
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
    total_findings = len(_normalize_list(context.get("top_findings")))
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
        "findings_by_host": findings_by_host,
        "tool_observations": tool_observations,
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
