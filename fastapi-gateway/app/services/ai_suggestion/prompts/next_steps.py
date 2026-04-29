from __future__ import annotations

import shlex
from typing import Any

from app.services.ai_suggestion.prompts.shared import (
    bullet_lines,
    compact_context,
    example_block,
    include_optional_context,
    json_block,
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

_ALLOWED_PRIORITIES = {"low", "medium", "high"}

_SCHEMA_TEXT = """{
  "suggestions": [
    {
      "title": string,
      "tool_id": string,
      "command": string,
      "params": object,
      "priority": "low" | "medium" | "high",
      "reasoning": string,
      "confidence": number
    }
  ]
}"""


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
    prepared["target"] = context.get("target", {})
    prepared["findings"] = trim_list(context.get("findings", context.get("top_findings", [])), limit=12)
    prepared["scan_results"] = trim_list(context.get("scan_results", context.get("results", [])), limit=12)
    return include_optional_context(prepared, context, "mcp_context")


def system_prompt() -> str:
    return (
        "You are a cybersecurity automation agent that generates structured task suggestions for security testing workflows. "
        "Your expertise includes recon, injection, authentication flaws, logic bugs, and API testing. "
        "Given a user input and supporting target context, generate a list of actionable tool-based suggestions. "
        "Output MUST be valid JSON only with no markdown, no explanations, and no code fences. "
        "Follow the exact schema and return the exact top-level shape {\"suggestions\": [...]} only. "
        "Each suggestion object must contain exactly these keys: title, tool_id, command, params, priority, reasoning, confidence. "
        "Only use these tool_id values: nuclei, ffuf, sqlmap, httpx, subfinder, amass, jwt_tool, xsstrike. "
        "Do not hallucinate unknown tools. "
        "Match the tool to the vulnerability category and keep reasoning concise and technical. "
        "Prefer targeted follow-up actions over generic broad scans when the input already contains paths, parameters, hosts, ports, fingerprints, headers, or technologies. "
        "If the input suggests recon, prefer subfinder or amass for asset discovery and httpx for live web validation and fingerprinting. "
        "If the input suggests exposed web paths, hidden content, vhosts, or parameter bruteforce, prefer ffuf. "
        "If the input suggests XSS, prefer xsstrike. "
        "If the input suggests SQL injection, prefer sqlmap. "
        "If the input suggests JWT weaknesses, token tampering, alg confusion, or auth token trust issues, prefer jwt_tool. "
        "If the input suggests known CVEs, misconfigurations, exposed technologies, or broad HTTP verification, prefer nuclei. "
        "Use httpx when URL probing, title/status capture, TLS fingerprinting, or tech detection is the best next step. "
        "Use multiple suggestions when distinct vulnerability classes are present, but avoid redundant variations of the same action. "
        "Bias toward 2 to 5 high-signal suggestions when enough evidence exists; return fewer if the context is sparse. "
        "Use realistic executable params when possible and avoid placeholders unless necessary. "
        "Each suggestion must include a realistic Linux terminal command that matches the params and selected tool. "
        "Commands must be runnable and use real flags, not fake syntax. "
        "Use placeholders like TARGET, URL, DOMAIN, JWT, INPUT_FILE, or OUTPUT_FILE only when the concrete value is unavailable. "
        "When suggestions form a natural sequence, prefer a logical workflow such as recon to validation to scanning. "
        "Prefer concrete params such as url, target, domain, headers, cookies, wordlist, match_status, risk, level, tags, templates, crawl, threads, path, method, and batch when they fit the selected tool. "
        "If a host, scheme, path, query parameter, or port is known, include it in params. "
        "If auth context is present, preserve it in params through headers or cookies when appropriate. "
        "priority must be one of low, medium, high. "
        "confidence must be a number between 0.0 and 1.0. "
        "params must be a JSON object. "
        "Ensure title is meaningful and non-empty. "
        "Each suggestion must be tied to observed target details, findings, paths, technologies, or services from the input context. "
        "Never invent assets, endpoints, parameters, headers, vulnerabilities, or technologies that are not supported by the input. "
        "Avoid placeholders unless necessary. "
        "Never return invalid JSON."
    )


def _few_shot_examples() -> str:
    examples = [
        example_block(
            title="Example 1",
            context={
                "user_input": "Test a target for XSS and SQL injection vulnerabilities",
                "target": {"name": "api.example.com", "type": "domain"},
                "severity_counts": {"high": 2},
                "findings": [
                    {"title": "Reflected XSS in search parameter", "severity": "high", "host": "api.example.com", "port": 443},
                    {"title": "SQL error leakage on /products?id=1", "severity": "high", "host": "api.example.com", "port": 443},
                ],
                "scan_results": [
                    {
                        "tool_name": "httpx",
                        "severity": "high",
                        "parsed_data": {"host": "api.example.com", "port": 443, "scheme": "https", "path": "/search?q=test"},
                    },
                ],
            },
            response="""
{
  "suggestions": [
    {
      "title": "Scan reflected input on search endpoint with XSStrike",
      "tool_id": "xsstrike",
      "command": "python3 xsstrike.py -u 'https://api.example.com/search?q=test' --crawl --skip-dom",
      "params": {
        "url": "https://api.example.com/search?q=test",
        "crawl": true,
        "skip_dom": true
      },
      "priority": "high",
      "reasoning": "The scan context already indicates reflected XSS behavior on the search parameter, making XSStrike the most direct validation tool.",
      "confidence": 0.93
    },
    {
      "title": "Probe SQL injection on product endpoint with sqlmap",
      "tool_id": "sqlmap",
      "command": "sqlmap -u 'https://api.example.com/products?id=1' --risk=2 --level=3 --batch",
      "params": {
        "url": "https://api.example.com/products?id=1",
        "risk": 2,
        "level": 3,
        "batch": true
      },
      "priority": "high",
      "reasoning": "Observed SQL error leakage on an id parameter is a strong indicator for targeted sqlmap testing on that endpoint.",
      "confidence": 0.95
    }
  ]
}
""",
        ),
        example_block(
            title="Example 2",
            context={
                "target": {"name": "corp.example.com", "type": "domain"},
                "severity_counts": {"medium": 1},
                "findings": [
                    {"title": "Admin panel /admin discovered", "severity": "medium", "host": "corp.example.com", "port": 8080},
                ],
                "scan_results": [
                    {"tool_name": "httpx", "severity": "medium", "parsed_data": {"path": "/admin"}},
                ],
            },
            response="""
{
  "suggestions": [
    {
      "title": "Enumerate hidden admin content with ffuf",
      "tool_id": "ffuf",
      "command": "ffuf -u 'http://corp.example.com:8080/admin/FUZZ' -w raft-small-directories.txt -mc 200,204,301,302,307,401,403",
      "params": {
        "url": "http://corp.example.com:8080/admin/FUZZ",
        "wordlist": "raft-small-directories.txt",
        "match_status": [200, 204, 301, 302, 307, 401, 403]
      },
      "priority": "high",
      "reasoning": "An exposed admin path was already identified, so focused content discovery is a realistic next step on the same surface.",
      "confidence": 0.84
    }
  ]
}
""",
        ),
        example_block(
            title="Example 3",
            context={
                "target": {"name": "example.com", "type": "domain"},
                "severity_counts": {"low": 1},
                "findings": [
                    {"title": "External attack surface incomplete", "severity": "low", "host": "example.com"},
                ],
                "scan_results": [],
            },
            response="""
{
  "suggestions": [
    {
      "title": "Expand subdomain coverage with subfinder",
      "tool_id": "subfinder",
      "command": "subfinder -d example.com -all -silent",
      "params": {
        "domain": "example.com",
        "all": true,
        "silent": true
      },
      "priority": "medium",
      "reasoning": "The context indicates incomplete external coverage, so subfinder is an appropriate recon step to expand discovered assets.",
      "confidence": 0.82
    }
  ]
}
""",
        ),
        example_block(
            title="Example 4",
            context={
                "target": {"name": "auth.example.com", "type": "domain"},
                "severity_counts": {"high": 1},
                "findings": [
                    {
                        "title": "JWT accepted with weak validation indicators",
                        "severity": "high",
                        "host": "auth.example.com",
                        "port": 443,
                    },
                ],
                "scan_results": [
                    {
                        "tool_name": "httpx",
                        "severity": "high",
                        "parsed_data": {"host": "auth.example.com", "port": 443, "scheme": "https", "path": "/api/profile"},
                    },
                ],
            },
            response="""
{
  "suggestions": [
    {
      "title": "Test JWT validation weaknesses with jwt_tool",
      "tool_id": "jwt_tool",
      "command": "python3 jwt_tool.py -t 'https://auth.example.com/api/profile' -rc 'jwt=JWT' -M at",
      "params": {
        "target": "https://auth.example.com/api/profile",
        "request_cookie": "jwt=JWT",
        "scan_mode": "at"
      },
      "priority": "high",
      "reasoning": "The context indicates JWT trust issues on an authenticated API surface, making jwt_tool the most relevant validation step.",
      "confidence": 0.9
    }
  ]
}
""",
        ),
        example_block(
            title="Example 5",
            context={
                "target": {"name": "shop.example.com", "type": "domain"},
                "severity_counts": {"medium": 2},
                "findings": [
                    {
                        "title": "Multiple virtual hosts and login surface detected",
                        "severity": "medium",
                        "host": "shop.example.com",
                        "port": 443,
                    }
                ],
                "scan_results": [
                    {
                        "tool_name": "httpx",
                        "severity": "medium",
                        "parsed_data": {"host": "shop.example.com", "port": 443, "scheme": "https"},
                    }
                ],
            },
            response="""
{
  "suggestions": [
    {
      "title": "Probe live web metadata with httpx",
      "tool_id": "httpx",
      "command": "httpx -u https://shop.example.com -sc -title -td",
      "params": {
        "target": "https://shop.example.com",
        "status_code": true,
        "title": true,
        "tech_detect": true
      },
      "priority": "medium",
      "reasoning": "The context suggests a live multi-surface web target, so httpx can quickly validate reachability and fingerprint exposed services.",
      "confidence": 0.83
    },
    {
      "title": "Fuzz hidden application paths with ffuf",
      "tool_id": "ffuf",
      "command": "ffuf -u 'https://shop.example.com/FUZZ' -w raft-small-words.txt -mc 200,204,301,302,307,401,403",
      "params": {
        "url": "https://shop.example.com/FUZZ",
        "wordlist": "raft-small-words.txt",
        "match_status": [200, 204, 301, 302, 307, 401, 403]
      },
      "priority": "medium",
      "reasoning": "A detected login surface and multiple virtual hosts justify content discovery for additional reachable endpoints.",
      "confidence": 0.8
    }
  ]
}
""",
        ),
    ]
    return "\n\n".join(examples)


def user_prompt(context: dict[str, Any]) -> str:
    return (
        "Generate suggestions from the available user intent and scan-derived context.\n\n"
        "STRICT OUTPUT RULES:\n"
        "- Output MUST be valid JSON only (no markdown, no explanations)\n"
        "- Follow the exact schema below\n"
        "- Do NOT include code blocks\n"
        "- Do NOT hallucinate unknown tools\n"
        "- Commands must be realistic and runnable in a Linux terminal\n"
        "- Commands must reflect the params\n"
        "- Use placeholders like TARGET, URL, DOMAIN when needed\n"
        "- Keep reasoning concise and technical\n"
        "- Confidence must be between 0.0 and 1.0\n\n"
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
        "- Match tools to the vulnerability category\n"
        "- Suggestions should form a logical workflow when possible\n"
        "- Use realistic parameters when possible\n"
        "- Use realistic flags, not random or fake ones\n"
        "- Avoid destructive flags unless clearly relevant\n"
        "- Avoid placeholders unless necessary\n"
        "- Ensure title is meaningful\n"
        "- Never output invalid JSON\n\n"
        f"{_few_shot_examples()}\n\n"
        f"Available input context:\n{json_block(context)}\n\n"
        "Respond with ONLY valid JSON matching the required schema. "
        "Choose the best tool for each distinct testing objective, prefer concrete target-specific params, and avoid duplicate or overlapping suggestions."
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
    output = _string_param(params, "output")
    if output:
        command.extend(["-o", output])
    return " ".join(_quote(part) for part in command)


def _build_amass_command(params: dict[str, Any]) -> str:
    domain = _string_param(params, "domain", "target", default="DOMAIN")
    command = ["amass", "enum"]
    if _bool_param(params, "passive"):
        command.append("-passive")
    command.extend(["-d", domain])
    output = _string_param(params, "output")
    if output:
        command.extend(["-o", output])
    return " ".join(_quote(part) for part in command)


def _build_httpx_command(params: dict[str, Any]) -> str:
    command = ["httpx"]
    input_file = _string_param(params, "input", "list")
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
    path = _string_param(params, "path")
    if path:
        command.extend(["-path", path])
    output = _string_param(params, "output")
    if output:
        command.extend(["-o", output])
    return " ".join(_quote(part) for part in command)


def _build_nuclei_command(params: dict[str, Any]) -> str:
    command = ["nuclei"]
    input_file = _string_param(params, "input", "list")
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
    else:
        template = _string_param(params, "template")
        if template:
            command.extend(["-t", template])
    output = _string_param(params, "output")
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
    output = _string_param(params, "output")
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


def _normalize_suggestions(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue

        raw_tool_id = item.get("tool_id", item.get("tool", item.get("tool_name", "")))
        params = item.get("params")
        command = item.get("command")
        confidence = item.get("confidence")
        try:
            normalized_confidence = float(confidence)
        except (TypeError, ValueError):
            normalized_confidence = 0.0
        normalized_confidence = max(0.0, min(1.0, normalized_confidence))

        normalized_params = params if isinstance(params, dict) else {}
        normalized_tool_id = str(raw_tool_id).strip().lower()
        normalized_command = str(command).strip() if isinstance(command, str) else ""

        suggestion = {
            "title": str(item.get("title", "")).strip(),
            "tool_id": normalized_tool_id,
            "command": normalized_command,
            "priority": str(item.get("priority", "")).strip().lower(),
            "reasoning": str(item.get("reasoning", "")).strip(),
            "confidence": normalized_confidence,
            "params": normalized_params,
        }
        if suggestion["priority"] not in _ALLOWED_PRIORITIES:
            suggestion["priority"] = "medium"
        if suggestion["tool_id"] not in _ALLOWED_TOOLS:
            continue
        if not suggestion["command"]:
            suggestion["command"] = _build_command(suggestion["tool_id"], suggestion["params"])
        if suggestion["title"] and suggestion["tool_id"]:
            normalized.append(suggestion)

    return normalized


def normalize_output(text: str) -> dict[str, Any]:
    import json

    try:
        parsed = json.loads(text.strip())
        suggestions = _normalize_suggestions(parsed.get("suggestions"))
        return {
            "suggestions": suggestions,
        }
    except json.JSONDecodeError:
        steps = bullet_lines(text)[:10]
        return {
            "suggestions": [
                {
                    "title": step[:120],
                    "tool_id": "nuclei",
                    "command": "nuclei -u TARGET",
                    "reasoning": "Recovered from unstructured AI output.",
                    "priority": "medium",
                    "confidence": 0.3,
                    "params": {},
                }
                for step in steps
                if step
            ] if steps else [],
        }
