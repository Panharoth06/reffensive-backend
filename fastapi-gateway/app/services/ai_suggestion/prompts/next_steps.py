from __future__ import annotations

import re
import shlex
from typing import Any
from urllib.parse import urlparse

from app.services.ai_suggestion.prompts.shared import (
    bullet_lines,
    compact_value,
    compact_context,
    example_block,
    include_optional_context,
    json_block,
    trim_text,
    trim_list,
)

_ALLOWED_TOOLS = {
    "nuclei",
    "ffuf",
    "sqlmap",
    "httpx",
    "subfinder",
    "amass",
    "jwt_tool",
    "xsstrike",
}

_ALLOWED_PRIORITIES = {"low", "medium", "high", "critical"}

_SCHEMA_TEXT = """{
  "suggestions": [
    {
      "id": string,
      "title": string,
      "category": "recon" | "auth" | "fuzzing" | "vuln_scan" | "misconfig" | "api" | "logic",
      "priority": "critical" | "high" | "medium" | "low",
      "why_now": string,
      "target_analysis": {
        "target_type": "sso" | "api" | "static" | "admin" | "unknown",
        "attack_surface": [string]
      },
      "action": {
        "tool_id": string,
        "command": string,
        "params": object
      },
      "expected_outcome": string,
      "next_if_success": string,
      "next_if_failure": string,
      "score": {
        "relevance": number,
        "impact": number,
        "confidence": number,
        "noise": number
      },
      "reasoning": string,
    }
  ]
}"""

_MAX_FINDINGS = 5
_MAX_RESULTS = 5
_PLACEHOLDER_TOKENS = {"TARGET", "URL", "DOMAIN", "JWT", "INPUT_FILE", "OUTPUT_FILE", "WORDLIST"}
_ALLOWED_CATEGORIES = {"recon", "auth", "fuzzing", "vuln_scan", "misconfig", "api", "logic"}
_ALLOWED_TARGET_TYPES = {"sso", "api", "static", "admin", "unknown"}
_PRIORITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_WORKFLOW_PHASE = {
    "asset_discovery": 10,
    "live_validation": 20,
    "content_discovery": 30,
    "template_scan": 40,
    "jwt_validation": 50,
    "xss_validation": 50,
    "sqli_validation": 50,
    "other": 90,
}
_TOOL_FAMILY = {
    "subfinder": "asset_discovery",
    "amass": "asset_discovery",
    "httpx": "live_validation",
    "ffuf": "content_discovery",
    "nuclei": "template_scan",
    "jwt_tool": "jwt_validation",
    "xsstrike": "xss_validation",
    "sqlmap": "sqli_validation",
}
_TOOL_CATEGORY = {
    "subfinder": "recon",
    "amass": "recon",
    "httpx": "recon",
    "ffuf": "fuzzing",
    "nuclei": "vuln_scan",
    "jwt_tool": "auth",
    "xsstrike": "logic",
    "sqlmap": "api",
}
_PARAM_ALIASES = {
    "cdn": "cdn_detect",
    "input_file": "input",
    "output_file": "output",
    "list_file": "input",
}


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def _is_probable_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _is_probable_domain(value: str) -> bool:
    text = value.strip().lower()
    if not text or " " in text or "/" in text or ":" in text:
        return False
    return bool(re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", text))


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().upper()
    return normalized in _PLACEHOLDER_TOKENS


def _append_candidate(collection: list[str], value: Any) -> None:
    if isinstance(value, str) and value.strip():
        collection.append(value.strip())


def _append_file_candidate(collection: list[str], value: Any) -> None:
    if not isinstance(value, str):
        return
    text = value.strip()
    if not text or _is_probable_url(text):
        return
    if "/" in text or text.endswith((".txt", ".json", ".csv", ".lst", ".log")):
        collection.append(text)


def _extract_observed_signals(context: dict[str, Any]) -> dict[str, Any]:
    assets: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    paths: list[str] = []
    technologies: list[str] = []
    executed_tools: list[str] = []
    artifact_files: list[str] = []

    target = context.get("target")
    if isinstance(target, dict):
        target_name = str(target.get("name", "")).strip()
        if _is_probable_url(target_name):
            urls.append(target_name)
        else:
            assets.append(target_name)
            if _is_probable_domain(target_name):
                domains.append(target_name)

    all_findings = context.get("findings", context.get("top_findings", [])) or []
    for finding in all_findings:
        if not isinstance(finding, dict):
            continue
        host = str(finding.get("host", "")).strip()
        fingerprint = str(finding.get("fingerprint", "")).strip()
        if host:
            assets.append(host)
            if _is_probable_domain(host):
                domains.append(host)
        if fingerprint:
            technologies.append(fingerprint)

    all_results = context.get("scan_results", context.get("results", [])) or []
    for result in all_results:
        if not isinstance(result, dict):
            continue
        tool_name = str(result.get("tool_name", result.get("tool", ""))).strip().lower()
        if tool_name:
            executed_tools.append(tool_name)
        parsed_data = result.get("parsed_data")
        if not isinstance(parsed_data, dict):
            continue
        for key in ("input", "list", "output", "file", "path", "raw_output_location"):
            _append_file_candidate(artifact_files, parsed_data.get(key))
        for key in ("url", "endpoint"):
            _append_candidate(urls, parsed_data.get(key))
        for key in ("host", "hostname", "domain"):
            candidate = str(parsed_data.get(key, "")).strip()
            if candidate:
                assets.append(candidate)
                if _is_probable_domain(candidate):
                    domains.append(candidate)
        for key in ("path", "route"):
            _append_candidate(paths, parsed_data.get(key))
        for key in ("tech", "technology"):
            _append_candidate(technologies, parsed_data.get(key))
        for key in ("urls", "endpoints", "hosts", "domains", "paths", "technologies"):
            values = parsed_data.get(key)
            if not isinstance(values, list):
                continue
            for item in values:
                if key in {"urls", "endpoints"}:
                    _append_candidate(urls, item)
                elif key in {"hosts", "domains"}:
                    candidate = str(item).strip()
                    if candidate:
                        assets.append(candidate)
                        if _is_probable_domain(candidate):
                            domains.append(candidate)
                elif key == "paths":
                    _append_candidate(paths, item)
                elif key == "technologies":
                    _append_candidate(technologies, item)
                elif key in {"files", "artifacts"}:
                    _append_file_candidate(artifact_files, item)

        host = str(parsed_data.get("host", "")).strip()
        scheme = str(parsed_data.get("scheme", "")).strip().lower()
        port = parsed_data.get("port")
        path = str(parsed_data.get("path", "")).strip()
        if host and scheme in {"http", "https"}:
            suffix = path if path.startswith("/") else f"/{path}" if path else ""
            if isinstance(port, int) and port > 0:
                default_port = 443 if scheme == "https" else 80
                if port != default_port:
                    urls.append(f"{scheme}://{host}:{port}{suffix}")
                else:
                    urls.append(f"{scheme}://{host}{suffix}")
            else:
                urls.append(f"{scheme}://{host}{suffix}")

    mcp_context = context.get("mcp_context")
    if isinstance(mcp_context, dict):
        for asset in mcp_context.get("linked_assets", []):
            _append_candidate(assets, asset)
            if isinstance(asset, str) and _is_probable_domain(asset):
                domains.append(asset)
        for observation in mcp_context.get("tool_observations", []):
            if isinstance(observation, dict):
                tool_name = str(observation.get("tool", "")).strip().lower()
                if tool_name:
                    executed_tools.append(tool_name)
        for url in mcp_context.get("candidate_urls", []):
            _append_candidate(urls, url)
        for path in mcp_context.get("candidate_paths", []):
            _append_candidate(paths, path)
        for artifact in mcp_context.get("artifact_files", []):
            _append_file_candidate(artifact_files, artifact)

    metadata = context.get("metadata")
    if isinstance(metadata, dict):
        for key in ("raw_output_location", "artifact_path", "artifact_file", "input_file", "output_file"):
            _append_file_candidate(artifact_files, metadata.get(key))
        for key in ("raw_output_locations", "artifact_paths", "artifact_files"):
            values = metadata.get(key)
            if isinstance(values, list):
                for item in values:
                    _append_file_candidate(artifact_files, item)

    deduped_assets = _dedupe_strings(assets)
    deduped_domains = _dedupe_strings([item for item in domains if _is_probable_domain(item)])
    deduped_urls = _dedupe_strings([item for item in urls if _is_probable_url(item)])
    deduped_paths = _dedupe_strings([item for item in paths if isinstance(item, str) and item.strip()])
    deduped_technologies = _dedupe_strings([item for item in technologies if item and not _is_placeholder(item)])
    deduped_tools = _dedupe_strings(executed_tools)
    deduped_files = _dedupe_strings(artifact_files)

    workflow_hints: list[str] = []
    if {"subfinder", "amass"} & set(deduped_tools):
        workflow_hints.append("Asset discovery already ran; avoid repeating subdomain enumeration unless there is new scope.")
    if len(deduped_assets) > 1 and "httpx" not in deduped_tools:
        workflow_hints.append("Multiple assets are already known; prioritize live validation before broad discovery repeats.")
    if deduped_urls:
        workflow_hints.append("Concrete URLs are available; prefer endpoint-specific validation over generic target placeholders.")
    if deduped_paths:
        workflow_hints.append("Known paths are available; reuse them directly in follow-up commands.")

    return {
        "candidate_assets": deduped_assets[:10],
        "candidate_domains": deduped_domains[:8],
        "candidate_urls": deduped_urls[:8],
        "candidate_paths": deduped_paths[:8],
        "observed_technologies": deduped_technologies[:8],
        "executed_tools": deduped_tools[:8],
        "artifact_files": deduped_files[:10],
        "workflow_hints": workflow_hints[:6],
    }


def _infer_target_type(context: dict[str, Any], evidence: dict[str, Any]) -> str:
    target = context.get("target")
    target_name = ""
    target_type = ""
    if isinstance(target, dict):
        target_name = str(target.get("name", "")).strip().lower()
        target_type = str(target.get("type", "")).strip().lower()

    combined = " ".join(
        [
            target_name,
            target_type,
            " ".join(str(item).lower() for item in evidence.get("candidate_urls") or []),
            " ".join(str(item).lower() for item in evidence.get("candidate_paths") or []),
            " ".join(str(item).lower() for item in evidence.get("observed_technologies") or []),
            " ".join(str(item.get("title", "")).lower() for item in context.get("findings", context.get("top_findings", [])) if isinstance(item, dict)),
        ]
    )
    if any(token in combined for token in ("sso", "oauth", "openid", "keycloak", "auth", "login", "jwt")):
        return "sso"
    if "api" in combined or any("/api" in str(item).lower() for item in evidence.get("candidate_urls") or []):
        return "api"
    if "admin" in combined or any("/admin" in str(item).lower() for item in evidence.get("candidate_paths") or []):
        return "admin"
    if any(item for item in evidence.get("candidate_urls") or []):
        return "static"
    return "unknown"


def _infer_phase(context: dict[str, Any], evidence: dict[str, Any]) -> str:
    executed = set(evidence.get("executed_tools") or [])
    if not executed:
        return "discovery"
    if {"subfinder", "amass"} & executed and "httpx" not in executed:
        return "validation"
    if "httpx" in executed and (evidence.get("candidate_paths") or evidence.get("candidate_urls")):
        return "focused_testing"
    if "nuclei" in executed or "ffuf" in executed:
        return "follow_up"
    return "assessment"


def _derive_attack_surface(context: dict[str, Any], evidence: dict[str, Any], target_type: str) -> list[str]:
    surfaces: list[str] = []
    urls = evidence.get("candidate_urls") or []
    paths = evidence.get("candidate_paths") or []
    techs = evidence.get("observed_technologies") or []
    if target_type == "sso":
        surfaces.append("authentication workflow")
        surfaces.append("token handling")
    if target_type == "api":
        surfaces.append("API routes")
        surfaces.append("parameter handling")
    if target_type == "admin":
        surfaces.append("administrative interface")
    if urls:
        surfaces.append("web endpoints")
    if any("/admin" in str(path).lower() for path in paths):
        surfaces.append("admin content discovery")
    if any("/login" in str(url).lower() or "/auth" in str(url).lower() for url in urls):
        surfaces.append("login entrypoints")
    if techs:
        surfaces.append("technology fingerprint exposure")
    return _dedupe_strings(surfaces)[:5] or ["unknown web surface"]


def _compact_notes(context: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
    notes = list(evidence.get("workflow_hints") or [])
    metadata = context.get("metadata") if isinstance(context.get("metadata"), dict) else {}
    mcp_summary = trim_text(metadata.get("mcp_summary", ""), max_chars=140)
    if mcp_summary:
        notes.append(mcp_summary)
    for finding in context.get("findings", context.get("top_findings", [])) or []:
        if not isinstance(finding, dict):
            continue
        title = trim_text(finding.get("title", ""), max_chars=120)
        if title:
            notes.append(title)
    return _dedupe_strings(notes)[:6]


def _decision_input_context(context: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    target = context.get("target") if isinstance(context.get("target"), dict) else {}
    target_name = trim_text(target.get("name", "") or "unknown", max_chars=160)
    target_type = _infer_target_type(context, evidence)
    history = []
    for tool in evidence.get("executed_tools") or []:
        history.append(f"executed:{tool}")
    for hint in evidence.get("workflow_hints") or []:
        history.append(trim_text(hint, max_chars=140))

    metadata = context.get("metadata") if isinstance(context.get("metadata"), dict) else {}
    mcp_summary = trim_text(metadata.get("mcp_summary", ""), max_chars=140)
    if mcp_summary:
        history.append(mcp_summary)
    return {
        "target": target_name,
        "phase": _infer_phase(context, evidence),
        "observations": {
            "hosts": evidence.get("candidate_assets") or [],
            "technologies": evidence.get("observed_technologies") or [],
            "endpoints": (evidence.get("candidate_urls") or []) + (evidence.get("candidate_paths") or []),
            "notes": _compact_notes(context, evidence),
        },
        "history": history[:8],
        "constraints": {
            "noise_level": trim_text(metadata.get("noise_level", "") or "low", max_chars=32).lower(),
            "engagement_type": trim_text(metadata.get("engagement_type", "") or "blackbox", max_chars=32).lower(),
        },
        "supporting_context": {
            "target_type": target_type,
            "attack_surface": _derive_attack_surface(context, evidence, target_type),
        },
    }


def _compact_target(target: Any) -> dict[str, Any]:
    if not isinstance(target, dict):
        return {}
    compacted = {
        "name": trim_text(target.get("name", ""), max_chars=160),
        "type": trim_text(target.get("type", ""), max_chars=80),
        "description": trim_text(target.get("description", ""), max_chars=120),
    }
    return {key: value for key, value in compacted.items() if value not in ("", None)}


def _compact_finding(finding: Any) -> dict[str, Any]:
    if not isinstance(finding, dict):
        return {}
    compacted = {
        "title": trim_text(finding.get("title", ""), max_chars=120),
        "severity": trim_text(finding.get("severity", ""), max_chars=32),
        "host": trim_text(finding.get("host", ""), max_chars=120),
        "port": finding.get("port"),
        "fingerprint": trim_text(finding.get("fingerprint", ""), max_chars=80),
        "tool_name": trim_text(finding.get("tool_name", finding.get("tool", "")), max_chars=64),
    }
    return {key: value for key, value in compacted.items() if value not in ("", None)}


def _compact_result(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {}
    parsed_data = compact_value(result.get("parsed_data"), max_depth=2, max_items=4, max_string=80)
    compacted = {
        "tool_name": trim_text(result.get("tool_name", result.get("tool", "")), max_chars=64),
        "severity": trim_text(result.get("severity", ""), max_chars=32),
        "parsed_data": parsed_data,
        "raw_preview": "" if parsed_data not in (None, "", [], {}, ()) else trim_text(result.get("raw_preview", ""), max_chars=100),
    }
    return {key: value for key, value in compacted.items() if value not in ("", None, [], {}, ())}


def prepare_context(context: dict[str, Any]) -> dict[str, Any]:
    prepared = compact_context(
        context,
        keys=[
            "job_id",
            "project_id",
            "status",
            "user_input",
            "request",
            "prompt",
            "query",
            "severity_counts",
            "metadata",
        ],
    )
    for key in ("job_id", "project_id", "status"):
        if key in prepared:
            prepared[key] = trim_text(prepared[key], max_chars=80)
    for key in ("user_input", "request", "prompt", "query"):
        if key in prepared:
            prepared[key] = trim_text(prepared[key], max_chars=200)
    if "severity_counts" in prepared:
        prepared["severity_counts"] = compact_value(prepared["severity_counts"], max_depth=1, max_items=8, max_string=24)
    if "metadata" in prepared:
        prepared["metadata"] = compact_value(prepared["metadata"], max_depth=2, max_items=8, max_string=120)

    all_findings = context.get("findings", context.get("top_findings", [])) or []
    all_results = context.get("scan_results", context.get("results", [])) or []

    prepared["target"] = _compact_target(context.get("target", {}))
    prepared["findings"] = [
        item
        for item in (_compact_finding(finding) for finding in trim_list(all_findings, limit=_MAX_FINDINGS))
        if item
    ]
    prepared["scan_results"] = [
        item
        for item in (_compact_result(result) for result in trim_list(all_results, limit=_MAX_RESULTS))
        if item
    ]

    metadata = dict(prepared.get("metadata") or {})
    metadata["prompt_context"] = {
        "total_findings": len(all_findings),
        "included_findings": len(prepared["findings"]),
        "total_results": len(all_results),
        "included_results": len(prepared["scan_results"]),
    }
    prepared["metadata"] = metadata
    evidence = _extract_observed_signals(context)
    prepared["evidence"] = compact_value(evidence, max_depth=2, max_items=8, max_string=100)
    prepared["decision_input"] = compact_value(_decision_input_context(context, evidence), max_depth=3, max_items=10, max_string=120)

    return include_optional_context(
        prepared,
        {"mcp_context": compact_value(context.get("mcp_context"), max_depth=2, max_items=6, max_string=80)},
        "mcp_context",
    )


def system_prompt() -> str:
    return (
        "You are a senior penetration testing assistant. "
        "Your role is to determine the highest-value next action in a penetration test based on the current context. "
        "Behave like an experienced human pentester: understand the target type, infer likely attack surfaces from limited evidence, prioritize actions that maximize useful findings while minimizing noise, and avoid generic or repetitive tool suggestions. "
        "You are not a tool suggester. You are a decision engine. "
        "Output MUST be valid JSON only with no markdown, no explanations, and no code fences. "
        "Follow the exact schema and return the exact top-level shape {\"suggestions\": [...]} only. "
        "Each suggestion object must contain exactly these keys: id, title, category, priority, why_now, target_analysis, action, expected_outcome, next_if_success, next_if_failure, score, reasoning. "
        "Only use these tool_id values: nuclei, ffuf, sqlmap, httpx, subfinder, amass, jwt_tool, xsstrike. "
        "Do not hallucinate unknown tools. "
        "Prefer targeted follow-up actions over generic broad scans when the input already contains paths, parameters, hosts, ports, fingerprints, headers, or technologies. "
        "Prefer no more than 3 suggestions. "
        "Do not repeat actions already performed. "
        "Prefer low-noise, high-signal actions first. "
        "Avoid generic suggestions like blind fuzzing unless justified by context. "
        "Use realistic executable params when possible and avoid placeholders unless necessary. "
        "Each suggestion must include a realistic Linux terminal command inside action.command that matches action.params and the selected tool. "
        "Commands must be runnable and use real flags, not fake syntax. "
        "Use placeholders like TARGET, URL, DOMAIN, JWT, INPUT_FILE, or OUTPUT_FILE only when the concrete value is unavailable. "
        "If the context includes executed_tools, candidate_urls, candidate_paths, workflow_hints, or history, treat them as hard guidance for sequencing and deduplication. "
        "When discovery has already been performed and multiple assets are known, prefer validation or focused follow-up before repeating discovery. "
        "Do not invent input or output filenames. Only use artifact files already present in the context. "
        "Prefer concrete params such as url, target, domain, headers, cookies, wordlist, match_status, risk, level, tags, templates, crawl, threads, path, method, and batch when they fit the selected tool. "
        "If a host, scheme, path, query parameter, or port is known, include it in params. "
        "If auth context is present, preserve it in params through headers or cookies when appropriate. "
        "priority must be one of critical, high, medium, low. "
        "category must be one of recon, auth, fuzzing, vuln_scan, misconfig, api, logic. "
        "target_analysis.target_type must be one of sso, api, static, admin, unknown. "
        "score must include relevance, impact, confidence, and noise as numbers between 0.0 and 1.0. "
        "Explain why the action is relevant to this specific target, why it should happen now, the expected outcome, and what to do next depending on success or failure. "
        "Each suggestion must be tied to observed target details, findings, paths, technologies, or services from the input context. "
        "Never invent assets, endpoints, parameters, headers, vulnerabilities, or technologies that are not supported by the input. "
        "Never return invalid JSON."
    )


def _few_shot_examples() -> str:
    examples = [
        example_block(
            title="Example 1",
            context={
                "target": "api.example.com",
                "phase": "focused_testing",
                "observations": {
                    "hosts": ["api.example.com"],
                    "technologies": ["nginx", "php"],
                    "endpoints": ["https://api.example.com/search?q=test", "https://api.example.com/products?id=1"],
                    "notes": ["Reflected XSS in search parameter", "SQL error leakage on /products?id=1"],
                },
                "history": ["executed:httpx"],
                "constraints": {"noise_level": "low", "engagement_type": "blackbox"},
            },
            response="""
{
  "suggestions": [
    {
      "id": "xsstrike-search-validation",
      "title": "Validate reflected input handling on the search endpoint",
      "category": "logic",
      "priority": "high",
      "why_now": "A concrete reflected parameter already exists, so a targeted XSS validation step is higher signal than broader enumeration.",
      "target_analysis": {
        "target_type": "api",
        "attack_surface": ["search parameter", "reflected response handling", "web endpoints"]
      },
      "action": {
        "tool_id": "xsstrike",
        "command": "python3 xsstrike.py -u 'https://api.example.com/search?q=test' --crawl --skip-dom",
        "params": {
          "url": "https://api.example.com/search?q=test",
          "crawl": true,
          "skip_dom": true
        }
      },
      "expected_outcome": "Confirm whether reflected input can be escalated into executable XSS with minimal additional noise.",
      "next_if_success": "Preserve the payload and pivot into session impact and authenticated-user exposure.",
      "next_if_failure": "Move to the SQLi lead because the XSS hypothesis did not validate.",
      "score": {
        "relevance": 0.96,
        "impact": 0.82,
        "confidence": 0.93,
        "noise": 0.18
      },
      "reasoning": "The target already exposes a single high-value parameterized endpoint, so focused validation is the best immediate use of effort."
    },
    {
      "id": "sqlmap-product-validation",
      "title": "Validate the product id parameter for SQL injection",
      "category": "api",
      "priority": "high",
      "why_now": "Observed SQL error leakage makes this endpoint a strong candidate for a quiet, targeted validation step.",
      "target_analysis": {
        "target_type": "api",
        "attack_surface": ["product id parameter", "backend query handling"]
      },
      "action": {
        "tool_id": "sqlmap",
        "command": "sqlmap -u 'https://api.example.com/products?id=1' --risk=2 --level=3 --batch",
        "params": {
          "url": "https://api.example.com/products?id=1",
          "risk": 2,
          "level": 3,
          "batch": true
        }
      },
      "expected_outcome": "Determine whether the observed error leakage corresponds to exploitable SQL injection rather than noisy error handling.",
      "next_if_success": "Constrain exploitation and enumerate minimally to map the trust boundary affected by the query.",
      "next_if_failure": "Deprioritize SQLi on this endpoint and shift to the next strongest evidence thread.",
      "score": {
        "relevance": 0.94,
        "impact": 0.9,
        "confidence": 0.95,
        "noise": 0.25
      },
      "reasoning": "The evidence points to a narrow and testable injection point, making this one of the highest-value next actions."
    }
  ]
}
""",
        ),
        example_block(
            title="Example 2",
            context={
                "target": "corp.example.com",
                "phase": "focused_testing",
                "observations": {
                    "hosts": ["corp.example.com"],
                    "technologies": ["apache"],
                    "endpoints": ["http://corp.example.com:8080/admin"],
                    "notes": ["Admin panel discovered"],
                },
                "history": ["executed:httpx"],
                "constraints": {"noise_level": "low", "engagement_type": "blackbox"},
            },
            response="""
{
  "suggestions": [
    {
      "id": "admin-content-enumeration",
      "title": "Enumerate hidden content under the known admin surface",
      "category": "fuzzing",
      "priority": "high",
      "why_now": "A confirmed admin path already exists, so constrained content discovery on that path is justified and more precise than wider fuzzing.",
      "target_analysis": {
        "target_type": "admin",
        "attack_surface": ["administrative interface", "hidden admin content"]
      },
      "action": {
        "tool_id": "ffuf",
        "command": "ffuf -u 'http://corp.example.com:8080/admin/FUZZ' -w raft-small-directories.txt -mc 200,204,301,302,307,401,403",
        "params": {
          "url": "http://corp.example.com:8080/admin/FUZZ",
          "wordlist": "raft-small-directories.txt",
          "match_status": [200, 204, 301, 302, 307, 401, 403]
        }
      },
      "expected_outcome": "Identify protected or undocumented admin resources without broad host-wide fuzzing.",
      "next_if_success": "Validate the newly discovered admin resources for auth bypass, debug exposure, or sensitive actions.",
      "next_if_failure": "Treat the visible admin path as the primary surface and pivot into auth or misconfiguration testing.",
      "score": {
        "relevance": 0.88,
        "impact": 0.74,
        "confidence": 0.84,
        "noise": 0.34
      },
      "reasoning": "The action is tightly scoped to a known sensitive path, which keeps noise controlled while maximizing the chance of meaningful findings."
    }
  ]
}
""",
        ),
    ]
    return "\n\n".join(examples)


def user_prompt(context: dict[str, Any]) -> str:
    decision_input = context.get("decision_input") if isinstance(context.get("decision_input"), dict) else {}
    return (
        "Determine the highest-value next action from the current penetration testing context.\n\n"
        "STRICT OUTPUT RULES:\n"
        "- Output MUST be valid JSON only (no markdown, no explanations)\n"
        "- Follow the exact schema below\n"
        "- Do NOT include code blocks\n"
        "- Do NOT hallucinate unknown tools\n"
        "- Return no more than 3 suggestions\n"
        "- Prefer low-noise, high-signal actions first\n"
        "- Do not repeat already performed actions\n"
        "- Commands must be realistic and runnable in a Linux terminal\n"
        "- action.command must reflect action.params\n"
        "- Keep reasoning concise and technical\n"
        "- score.relevance, score.impact, score.confidence, and score.noise must be between 0.0 and 1.0\n\n"
        f"SCHEMA:\n{_SCHEMA_TEXT}\n\n"
        "ALLOWED TOOLS:\n"
        "- nuclei\n"
        "- ffuf\n"
        "- sqlmap\n"
        "- httpx\n"
        "- subfinder\n"
        "- amass\n"
        "- jwt_tool\n"
        "- xsstrike\n\n"
        "GUIDELINES:\n"
        "- Explain why the action is relevant to this specific target\n"
        "- Explain why the action should be performed now\n"
        "- Describe the expected outcome\n"
        "- Provide next steps for both success and failure\n"
        "- Prefer constrained validation before noisier discovery when the context already includes assets or endpoints\n"
        "- Avoid generic suggestions like blind fuzzing unless the context strongly justifies it\n"
        "- Use realistic parameters and flags\n"
        "- Ensure title and why_now are meaningful\n"
        "- Never output invalid JSON\n\n"
        f"{_few_shot_examples()}\n\n"
        f"Available input context:\n{json_block(decision_input)}\n\n"
        "Respond with ONLY valid JSON matching the required schema. "
        "Choose the smallest set of high-value next actions for this specific target and testing phase."
    )


def _quote(value: Any) -> str:
    return shlex.quote(str(value))


def _string_param(params: dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = params.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default


def _bool_param(params: dict[str, Any], key: str) -> bool:
    return bool(params.get(key))


def _list_param(params: dict[str, Any], key: str) -> list[Any]:
    value = params.get(key)
    return value if isinstance(value, list) else []


def _join_csv(values: list[Any]) -> str:
    return ",".join(str(value) for value in values if str(value).strip())


def _build_subfinder_command(params: dict[str, Any]) -> str:
    domain = _string_param(params, "domain", "target", default="DOMAIN")
    command = ["subfinder", "-d", domain]
    if _bool_param(params, "all"):
        command.append("-all")
    if _bool_param(params, "silent"):
        command.append("-silent")
    output = _string_param(params, "output", "output_file")
    if output:
        command.extend(["-o", output])
    return " ".join(_quote(part) for part in command)


def _build_amass_command(params: dict[str, Any]) -> str:
    domain = _string_param(params, "domain", "target", default="DOMAIN")
    command = ["amass", "enum"]
    if _bool_param(params, "passive"):
        command.append("-passive")
    command.extend(["-d", domain])
    output = _string_param(params, "output", "output_file")
    if output:
        command.extend(["-o", output])
    return " ".join(_quote(part) for part in command)


def _build_httpx_command(params: dict[str, Any]) -> str:
    command = ["httpx"]
    input_file = _string_param(params, "input", "list", "input_file")
    if input_file:
        command.extend(["-l", input_file])
    else:
        target = _string_param(params, "target", "url", default="TARGET")
        command.extend(["-u", target])
    if _bool_param(params, "silent"):
        command.append("-silent")
    if _bool_param(params, "status_code"):
        command.append("-sc")
    if _bool_param(params, "title"):
        command.append("-title")
    if _bool_param(params, "tech_detect"):
        command.append("-td")
    if _bool_param(params, "cdn_detect"):
        command.append("-cdn")
    path = _string_param(params, "path")
    if path:
        command.extend(["-path", path])
    output = _string_param(params, "output", "output_file")
    if output:
        command.extend(["-o", output])
    return " ".join(_quote(part) for part in command)


def _build_nuclei_command(params: dict[str, Any]) -> str:
    command = ["nuclei"]
    input_file = _string_param(params, "input", "list", "input_file")
    if input_file:
        command.extend(["-l", input_file])
    else:
        target = _string_param(params, "target", "url", default="TARGET")
        command.extend(["-u", target])
    severities = _list_param(params, "severity")
    if severities:
        command.extend(["-severity", _join_csv(severities)])
    tags = _list_param(params, "tags")
    if tags:
        command.extend(["-tags", _join_csv(tags)])
    templates = params.get("templates")
    if isinstance(templates, list) and templates:
        command.extend(["-t", _join_csv(templates)])
    elif isinstance(templates, str) and templates.strip():
        command.extend(["-t", templates.strip()])
    else:
        template = _string_param(params, "template")
        if template:
            command.extend(["-t", template])
    workers = params.get("workers")
    if isinstance(workers, int | float):
        command.extend(["-c", str(int(workers))])
    output = _string_param(params, "output", "output_file")
    if output:
        command.extend(["-o", output])
    return " ".join(_quote(part) for part in command)


def _build_ffuf_command(params: dict[str, Any]) -> str:
    url = _string_param(params, "url", default="URL")
    wordlist = _string_param(params, "wordlist", default="WORDLIST")
    command = ["ffuf", "-u", url, "-w", wordlist]
    method = _string_param(params, "method")
    if method:
        command.extend(["-X", method.upper()])
    match_status = _list_param(params, "match_status")
    if match_status:
        command.extend(["-mc", _join_csv(match_status)])
    headers = params.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            command.extend(["-H", f"{key}: {value}"])
    cookies = _string_param(params, "cookies", "cookie")
    if cookies:
        command.extend(["-b", cookies])
    output = _string_param(params, "output", "output_file")
    if output:
        command.extend(["-o", output])
    return " ".join(_quote(part) for part in command)


def _build_sqlmap_command(params: dict[str, Any]) -> str:
    url = _string_param(params, "url", "target", default="URL")
    command = ["sqlmap", "-u", url]
    risk = params.get("risk")
    if isinstance(risk, int | float):
        command.append(f"--risk={int(risk)}")
    level = params.get("level")
    if isinstance(level, int | float):
        command.append(f"--level={int(level)}")
    data = _string_param(params, "data")
    if data:
        command.extend(["--data", data])
    cookie = _string_param(params, "cookie", "cookies")
    if cookie:
        command.append(f"--cookie={cookie}")
    if _bool_param(params, "batch"):
        command.append("--batch")
    return " ".join(_quote(part) for part in command)


def _build_xsstrike_command(params: dict[str, Any]) -> str:
    url = _string_param(params, "url", "target", default="URL")
    command = ["python3", "xsstrike.py", "-u", url]
    data = _string_param(params, "data")
    if data:
        command.extend(["--data", data])
    threads = params.get("threads")
    if isinstance(threads, int | float):
        command.extend(["-t", str(int(threads))])
    level = params.get("level")
    if isinstance(level, int | float):
        command.extend(["-l", str(int(level))])
    if _bool_param(params, "crawl"):
        command.append("--crawl")
    if _bool_param(params, "params"):
        command.append("--params")
    if _bool_param(params, "skip_dom"):
        command.append("--skip-dom")
    if _bool_param(params, "json"):
        command.append("--json")
    return " ".join(_quote(part) for part in command)


def _build_jwt_tool_command(params: dict[str, Any]) -> str:
    target = _string_param(params, "target", "url", default="URL")
    token = _string_param(params, "token", default="JWT")
    command = ["python3", "jwt_tool.py"]
    if target:
        command.extend(["-t", target])
    request_cookie = _string_param(params, "request_cookie")
    request_header = _string_param(params, "request_header")
    if request_cookie:
        command.extend(["-rc", request_cookie])
    elif request_header:
        command.extend(["-rh", request_header])
    else:
        command.extend(["-rc", f"jwt={token}"])
    scan_mode = _string_param(params, "scan_mode", default="at")
    command.extend(["-M", scan_mode])
    return " ".join(_quote(part) for part in command)


def _build_command(tool_id: str, params: dict[str, Any]) -> str:
    builders = {
        "subfinder": _build_subfinder_command,
        "amass": _build_amass_command,
        "httpx": _build_httpx_command,
        "nuclei": _build_nuclei_command,
        "ffuf": _build_ffuf_command,
        "sqlmap": _build_sqlmap_command,
        "xsstrike": _build_xsstrike_command,
        "jwt_tool": _build_jwt_tool_command,
    }
    builder = builders.get(tool_id)
    if builder is None:
        return tool_id
    return builder(params)


def _normalize_params(params: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in params.items():
        canonical = _PARAM_ALIASES.get(str(key).strip(), str(key).strip())
        if canonical == "templates" and isinstance(value, str) and value.strip():
            normalized["template"] = value.strip()
            continue
        normalized[canonical] = value
    return normalized


def _pick_preferred_target(context: dict[str, Any]) -> dict[str, str]:
    evidence = _extract_observed_signals(context)
    urls = evidence.get("candidate_urls") or []
    domains = evidence.get("candidate_domains") or []
    assets = evidence.get("candidate_assets") or []
    preferred_url = urls[0] if len(urls) == 1 else ""
    preferred_domain = domains[0] if len(domains) == 1 else ""
    preferred_asset = assets[0] if len(assets) == 1 else preferred_domain or ""
    return {
        "url": preferred_url,
        "domain": preferred_domain,
        "asset": preferred_asset,
        "executed_tools": ",".join(evidence.get("executed_tools") or []),
    }


def _looks_like_generated_filename(value: str) -> bool:
    name = value.strip().lower().rsplit("/", 1)[-1]
    return bool(re.fullmatch(r"(httpx|nuclei|subfinder|amass|ffuf|sqlmap|xsstrike|jwt)[-_]?(input|output|results?)\.[a-z0-9]+", name))


def _sanitize_file_params(tool_id: str, params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    evidence = _extract_observed_signals(context)
    known_files = set(evidence.get("artifact_files") or [])
    sanitized = dict(params)
    for key in ("input", "list", "output"):
        value = _string_param(sanitized, key)
        if not value:
            continue
        if value not in known_files and _looks_like_generated_filename(value):
            sanitized.pop(key, None)
    return sanitized


def _fill_missing_params(tool_id: str, params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(params, dict):
        return {}

    filled = dict(params)
    preferred = _pick_preferred_target(context)
    target = _string_param(filled, "target", "url", "domain")
    if tool_id in {"subfinder", "amass"}:
        if (not target or _is_placeholder(target)) and preferred["domain"]:
            filled["domain"] = preferred["domain"]
    elif tool_id in {"httpx", "nuclei"}:
        if (not _string_param(filled, "input", "list") and not target) or _is_placeholder(target):
            if preferred["url"]:
                filled["url"] = preferred["url"]
            elif preferred["asset"]:
                filled["target"] = preferred["asset"]
    elif tool_id in {"ffuf", "sqlmap", "xsstrike", "jwt_tool"}:
        if (not _string_param(filled, "url", "target") or _is_placeholder(target)) and preferred["url"]:
            filled["url"] = preferred["url"]
    return filled


def _slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
    return cleaned.strip("-") or "next-action"


def _tool_target_type(tool_id: str, context: dict[str, Any]) -> str:
    evidence = _extract_observed_signals(context)
    inferred = _infer_target_type(context, evidence)
    if tool_id == "jwt_tool":
        return "sso"
    if tool_id in {"sqlmap"} and inferred == "unknown":
        return "api"
    if tool_id == "ffuf" and inferred == "unknown":
        return "admin" if any("/admin" in str(path).lower() for path in evidence.get("candidate_paths") or []) else "static"
    return inferred if inferred in _ALLOWED_TARGET_TYPES else "unknown"


def _default_why_now(tool_id: str, context: dict[str, Any]) -> str:
    evidence = _extract_observed_signals(context)
    if tool_id == "httpx":
        return "Multiple assets are known, and live validation now reduces noise before deeper testing."
    if tool_id == "ffuf":
        return "A concrete path or sensitive surface already exists, so constrained discovery is justified now."
    if tool_id == "nuclei":
        return "The context includes a concrete host and technology clues, making a targeted verification step timely."
    if tool_id == "sqlmap":
        return "A parameterized endpoint exists, so quiet validation of injection risk is higher value than broader scanning."
    if tool_id == "xsstrike":
        return "A concrete reflected or input-driven endpoint exists, so direct validation is the best next step."
    if tool_id == "jwt_tool":
        return "Authentication context is present, so token trust assumptions should be tested before wider probing."
    if tool_id in {"subfinder", "amass"}:
        return "Discovery is only worthwhile now if current scope is too thin to support focused validation."
    return trim_text("This step best matches the current evidence and testing phase.", max_chars=140)


def _default_expected_outcome(tool_id: str) -> str:
    mapping = {
        "httpx": "Confirm which candidate assets are live and collect enough fingerprinting to choose the next focused test.",
        "ffuf": "Identify hidden resources on the known surface without broad host-wide noise.",
        "nuclei": "Verify whether the observed target matches known exposures or misconfigurations worth escalating.",
        "sqlmap": "Determine whether the identified parameter is actually injectable.",
        "xsstrike": "Confirm whether input reflection can be escalated into executable client-side impact.",
        "jwt_tool": "Determine whether token handling weaknesses are present in the authentication flow.",
        "subfinder": "Expand scoped asset inventory only if existing targets are insufficient for focused testing.",
        "amass": "Cross-check asset inventory if additional discovery is still needed.",
    }
    return mapping.get(tool_id, "Produce a concrete decision about whether this path deserves deeper follow-up.")


def _default_next_success(tool_id: str) -> str:
    mapping = {
        "httpx": "Use the validated live hosts and fingerprints to choose the most specific next probe.",
        "ffuf": "Validate newly discovered resources for access control, sensitive actions, or data exposure.",
        "nuclei": "Confirm the finding manually and pivot into the affected trust boundary or exposed functionality.",
        "sqlmap": "Constrain exploitation and enumerate minimally to understand impact without unnecessary noise.",
        "xsstrike": "Preserve the working vector and test whether it affects authentication or privileged workflows.",
        "jwt_tool": "Map the trust boundary and test the most credible token abuse path with minimal expansion.",
        "subfinder": "Validate the newly identified assets and prioritize the most exposed web surfaces.",
        "amass": "Validate any new assets and merge only the meaningful additions into the active target list.",
    }
    return mapping.get(tool_id, "Escalate into the smallest follow-up step that confirms impact.")


def _default_next_failure(tool_id: str) -> str:
    mapping = {
        "httpx": "Drop dead assets and pivot to the strongest remaining validated surface.",
        "ffuf": "Treat the known endpoint as the primary surface and switch to auth, logic, or misconfiguration testing.",
        "nuclei": "Deprioritize broad template scanning and move to the next evidence-driven hypothesis.",
        "sqlmap": "Deprioritize injection on this path and move to the next strongest endpoint-specific lead.",
        "xsstrike": "Shift to the next evidence-backed web hypothesis rather than widening scope.",
        "jwt_tool": "Deprioritize token abuse and pivot to surrounding auth workflow or access control checks.",
        "subfinder": "Stop repeating discovery and use the current validated scope for focused testing.",
        "amass": "Stop broadening scope and work from the current asset set.",
    }
    return mapping.get(tool_id, "Move to the next highest-signal hypothesis without widening scope unnecessarily.")


def _noise_score(tool_id: str) -> float:
    mapping = {
        "httpx": 0.16,
        "jwt_tool": 0.2,
        "xsstrike": 0.24,
        "sqlmap": 0.28,
        "nuclei": 0.34,
        "ffuf": 0.42,
        "subfinder": 0.22,
        "amass": 0.3,
    }
    return mapping.get(tool_id, 0.35)


def _normalize_score_block(item: dict[str, Any], confidence: float, tool_id: str, suggestion_score: float) -> dict[str, float]:
    raw_score = item.get("score") if isinstance(item.get("score"), dict) else {}
    def _float_value(key: str, fallback: float) -> float:
        value = raw_score.get(key, fallback)
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return fallback
    return {
        "relevance": _float_value("relevance", max(0.0, min(1.0, suggestion_score))),
        "impact": _float_value("impact", 0.82 if tool_id in {"sqlmap", "jwt_tool", "nuclei"} else 0.7),
        "confidence": _float_value("confidence", confidence),
        "noise": _float_value("noise", _noise_score(tool_id)),
    }


def _suggestion_focus(tool_id: str, params: dict[str, Any]) -> str:
    family = _TOOL_FAMILY.get(tool_id, "other")
    if family == "asset_discovery":
        return _string_param(params, "domain", "target", default=tool_id).lower()
    if family in {"live_validation", "content_discovery", "xss_validation", "sqli_validation", "jwt_validation"}:
        return _string_param(params, "input", "list", "url", "target", default=tool_id).lower()
    if family == "template_scan":
        target = _string_param(params, "input", "list", "url", "target", default="")
        template = _string_param(params, "template", default=_join_csv(_list_param(params, "templates")))
        return f"{target.lower()}::{template.lower()}"
    return tool_id


def _specificity_score(suggestion: dict[str, Any]) -> float:
    score = 0.0
    params = suggestion.get("params") if isinstance(suggestion.get("params"), dict) else {}
    for value in params.values():
        if isinstance(value, str):
            score += 0.08 if not _is_placeholder(value) else -0.04
            if _looks_like_generated_filename(value):
                score -= 0.18
        elif isinstance(value, (bool, int, float)):
            score += 0.03
        elif isinstance(value, list) and value:
            score += 0.05
    if suggestion.get("command") and not any(token in suggestion["command"] for token in _PLACEHOLDER_TOKENS):
        score += 0.12
    return score


def _suggestion_score(suggestion: dict[str, Any], context: dict[str, Any]) -> float:
    evidence = _extract_observed_signals(context)
    family = _TOOL_FAMILY.get(suggestion["tool_id"], "other")
    base = float(suggestion["confidence"])
    base += _PRIORITY_SCORE.get(suggestion["priority"], 2) * 0.08
    base += _specificity_score(suggestion)
    executed_tools = set(evidence.get("executed_tools") or [])
    candidate_assets = evidence.get("candidate_assets") or []
    candidate_urls = evidence.get("candidate_urls") or []
    candidate_paths = evidence.get("candidate_paths") or []
    if family == "asset_discovery" and suggestion["tool_id"] in executed_tools:
        base -= 0.2
    if family == "asset_discovery" and len(candidate_assets) > 1:
        base -= 0.05
    if family == "live_validation" and len(candidate_assets) > 1 and "httpx" not in executed_tools:
        base += 0.18
    if family == "content_discovery" and "httpx" not in executed_tools and len(candidate_assets) > 1:
        base -= 0.18
    if family == "content_discovery" and not candidate_paths:
        base -= 0.08
    if family == "template_scan":
        params = suggestion.get("params") if isinstance(suggestion.get("params"), dict) else {}
        has_targeted_template = bool(_string_param(params, "template")) or bool(_list_param(params, "templates")) or bool(_list_param(params, "tags"))
        if not has_targeted_template:
            base -= 0.16
        if len(candidate_urls) > 1 and "httpx" not in executed_tools:
            base -= 0.08
    return base


def _post_process_suggestions(suggestions: list[dict[str, Any]], context: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not suggestions:
        return []

    effective_context = context or {}
    evidence = _extract_observed_signals(effective_context)
    best_by_signature: dict[tuple[str, str], dict[str, Any]] = {}
    scores: dict[tuple[str, str], float] = {}

    for suggestion in suggestions:
        action = suggestion.get("action") if isinstance(suggestion.get("action"), dict) else {}
        tool_id = str(action.get("tool_id", suggestion.get("tool_id", ""))).strip().lower()
        params = _fill_missing_params(
            tool_id,
            _normalize_params(action.get("params") if isinstance(action.get("params"), dict) else suggestion.get("params") if isinstance(suggestion.get("params"), dict) else {}),
            effective_context,
        )
        params = _sanitize_file_params(tool_id, params, effective_context)
        params = _fill_missing_params(tool_id, params, effective_context)
        command = _build_command(tool_id, params)
        raw_priority = str(suggestion.get("priority", "")).strip().lower()
        priority = raw_priority if raw_priority in _ALLOWED_PRIORITIES else "medium"

        suggestion_score = _suggestion_score(
            {
                "tool_id": tool_id,
                "priority": priority,
                "confidence": float(suggestion.get("confidence", suggestion.get("score", {}).get("confidence", 0.0)) or 0.0),
                "params": params,
                "command": command,
            },
            effective_context,
        )
        target_type = str(suggestion.get("target_analysis", {}).get("target_type", "")).strip().lower()
        if target_type not in _ALLOWED_TARGET_TYPES:
            target_type = _tool_target_type(tool_id, effective_context)
        attack_surface = suggestion.get("target_analysis", {}).get("attack_surface")
        if not isinstance(attack_surface, list) or not any(isinstance(item, str) and item.strip() for item in attack_surface):
            attack_surface = _derive_attack_surface(effective_context, evidence, target_type)

        normalized = {
            "id": str(suggestion.get("id", "")).strip() or _slugify(f"{tool_id}-{suggestion.get('title', '')}"),
            "title": str(suggestion.get("title", "")).strip(),
            "category": str(suggestion.get("category", "")).strip().lower() or _TOOL_CATEGORY.get(tool_id, "recon"),
            "priority": priority,
            "why_now": str(suggestion.get("why_now", "")).strip() or _default_why_now(tool_id, effective_context),
            "target_analysis": {
                "target_type": target_type,
                "attack_surface": [str(item).strip() for item in attack_surface if isinstance(item, str) and item.strip()][:5],
            },
            "action": {
                "tool_id": tool_id,
                "command": command,
                "params": params,
            },
            "expected_outcome": str(suggestion.get("expected_outcome", "")).strip() or _default_expected_outcome(tool_id),
            "next_if_success": str(suggestion.get("next_if_success", "")).strip() or _default_next_success(tool_id),
            "next_if_failure": str(suggestion.get("next_if_failure", "")).strip() or _default_next_failure(tool_id),
            "score": _normalize_score_block(
                suggestion,
                float(suggestion.get("confidence", suggestion.get("score", {}).get("confidence", 0.0)) or 0.0),
                tool_id,
                suggestion_score,
            ),
            "reasoning": str(suggestion.get("reasoning", "")).strip() or str(suggestion.get("why_now", "")).strip() or _default_why_now(tool_id, effective_context),
        }
        if normalized["category"] not in _ALLOWED_CATEGORIES:
            normalized["category"] = _TOOL_CATEGORY.get(tool_id, "recon")

        family = _TOOL_FAMILY.get(tool_id, "other")
        signature = (family, _suggestion_focus(tool_id, params))
        score = _suggestion_score(
            {
                "tool_id": tool_id,
                "priority": normalized["priority"],
                "confidence": normalized["score"]["confidence"],
                "params": params,
                "command": command,
            },
            effective_context,
        )
        current = best_by_signature.get(signature)
        if current is None or score > scores[signature]:
            best_by_signature[signature] = normalized
            scores[signature] = score

    refined = list(best_by_signature.values())
    refined = [
        item
        for item in refined
        if _suggestion_score(
            {
                "tool_id": item["action"]["tool_id"],
                "priority": item["priority"],
                "confidence": item["score"]["confidence"],
                "params": item["action"]["params"],
                "command": item["action"]["command"],
            },
            effective_context,
        ) >= 0.45
    ]
    refined.sort(
        key=lambda item: (
            -_suggestion_score(
                {
                    "tool_id": item["action"]["tool_id"],
                    "priority": item["priority"],
                    "confidence": item["score"]["confidence"],
                    "params": item["action"]["params"],
                    "command": item["action"]["command"],
                },
                effective_context,
            ),
            _WORKFLOW_PHASE.get(_TOOL_FAMILY.get(item["action"]["tool_id"], "other"), 90),
            item["title"].lower(),
        )
    )
    return refined[:3]


def _normalize_suggestions(value: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue

        action = item.get("action") if isinstance(item.get("action"), dict) else {}
        raw_tool_id = action.get("tool_id", item.get("tool_id", item.get("tool", item.get("tool_name", ""))))
        params = action.get("params", item.get("params"))
        command = action.get("command", item.get("command"))
        score_block = item.get("score") if isinstance(item.get("score"), dict) else {}
        confidence = item.get("confidence", score_block.get("confidence"))
        try:
            normalized_confidence = float(confidence)
        except (TypeError, ValueError):
            normalized_confidence = 0.0
        normalized_confidence = max(0.0, min(1.0, normalized_confidence))

        normalized_params = _normalize_params(params) if isinstance(params, dict) else {}
        normalized_tool_id = str(raw_tool_id).strip().lower()
        normalized_command = str(command).strip() if isinstance(command, str) else ""

        suggestion = {
            "id": str(item.get("id", "")).strip(),
            "title": str(item.get("title", "")).strip(),
            "tool_id": normalized_tool_id,
            "command": normalized_command,
            "category": str(item.get("category", "")).strip().lower(),
            "priority": str(item.get("priority", "")).strip().lower(),
            "why_now": str(item.get("why_now", "")).strip(),
            "target_analysis": item.get("target_analysis") if isinstance(item.get("target_analysis"), dict) else {},
            "expected_outcome": str(item.get("expected_outcome", "")).strip(),
            "next_if_success": str(item.get("next_if_success", "")).strip(),
            "next_if_failure": str(item.get("next_if_failure", "")).strip(),
            "score": score_block,
            "reasoning": str(item.get("reasoning", "")).strip(),
            "confidence": normalized_confidence,
            "action": {
                "tool_id": normalized_tool_id,
                "command": normalized_command,
                "params": normalized_params,
            },
        }
        if suggestion["priority"] not in _ALLOWED_PRIORITIES:
            suggestion["priority"] = "medium"
        if suggestion["tool_id"] not in _ALLOWED_TOOLS:
            continue
        if not suggestion["action"]["command"]:
            suggestion["action"]["command"] = _build_command(suggestion["tool_id"], normalized_params)
        if suggestion["title"] and suggestion["tool_id"]:
            normalized.append(suggestion)

    return _post_process_suggestions(normalized, context)


def normalize_output(text: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    import json

    try:
        parsed = json.loads(text.strip())
        suggestions = _normalize_suggestions(parsed.get("suggestions"), context)
        return {
            "suggestions": suggestions,
        }
    except json.JSONDecodeError:
        steps = bullet_lines(text)[:10]
        return {
            "suggestions": [
                {
                    "id": _slugify(step[:40]),
                    "title": step[:120],
                    "category": "vuln_scan",
                    "priority": "medium",
                    "why_now": "Recovered from unstructured AI output and converted into a cautious follow-up action.",
                    "target_analysis": {
                        "target_type": _tool_target_type("nuclei", context or {}),
                        "attack_surface": _derive_attack_surface(context or {}, _extract_observed_signals(context or {}), _tool_target_type("nuclei", context or {})),
                    },
                    "action": {
                        "tool_id": "nuclei",
                        "command": "nuclei -u TARGET",
                        "params": {},
                    },
                    "expected_outcome": _default_expected_outcome("nuclei"),
                    "next_if_success": _default_next_success("nuclei"),
                    "next_if_failure": _default_next_failure("nuclei"),
                    "score": {
                        "relevance": 0.3,
                        "impact": 0.5,
                        "confidence": 0.3,
                        "noise": _noise_score("nuclei"),
                    },
                    "reasoning": "Recovered from unstructured AI output.",
                }
                for step in steps
                if step
            ] if steps else [],
        }
