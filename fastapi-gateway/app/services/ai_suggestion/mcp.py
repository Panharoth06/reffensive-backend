from __future__ import annotations

import os
from typing import Any

import httpx

from app.schemas.ai_suggestion_schemas import SuggestionMode


class MCPContextError(Exception):
    """Raised when MCP context enrichment is required but fails."""


def _mcp_enabled() -> bool:
    raw = os.getenv("AI_SUGGESTION_MCP_ENABLED", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _mcp_strict() -> bool:
    raw = os.getenv("AI_SUGGESTION_MCP_STRICT", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _mcp_url() -> str:
    return os.getenv("AI_SUGGESTION_MCP_CONTEXT_URL", "").strip()


def _mcp_timeout_seconds() -> float:
    raw = os.getenv("AI_SUGGESTION_MCP_TIMEOUT_SECONDS", "10").strip()
    try:
        return max(float(raw), 1.0)
    except ValueError:
        return 10.0


def _merge_context(base: dict[str, Any], mcp_payload: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    metadata = dict(base.get("metadata") or {})
    metadata["mcp_enabled"] = True

    extra_context = mcp_payload.get("context")
    if isinstance(extra_context, dict):
        merged["mcp_context"] = extra_context

    resources = mcp_payload.get("resources")
    if isinstance(resources, list):
        metadata["mcp_resources"] = resources

    summary = mcp_payload.get("summary")
    if isinstance(summary, str) and summary.strip():
        metadata["mcp_summary"] = summary.strip()

    merged["metadata"] = metadata
    return merged


async def enrich_context_with_mcp(mode: SuggestionMode, context: dict[str, Any]) -> dict[str, Any]:
    if not _mcp_enabled():
        return context

    url = _mcp_url()
    if not url:
        if _mcp_strict():
            raise MCPContextError("AI suggestion MCP is enabled but AI_SUGGESTION_MCP_CONTEXT_URL is not set")
        return context

    headers: dict[str, str] = {"content-type": "application/json"}
    secret = os.getenv("AI_SUGGESTION_MCP_SECRET", "").strip()
    if secret:
        headers["x-mcp-secret"] = secret

    payload = {
        "mode": mode,
        "context": context,
    }

    try:
        timeout = httpx.Timeout(_mcp_timeout_seconds(), connect=min(_mcp_timeout_seconds(), 5.0))
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        if _mcp_strict():
            raise MCPContextError(f"MCP context enrichment failed: {exc}") from exc
        return context

    try:
        data = response.json()
    except ValueError as exc:
        if _mcp_strict():
            raise MCPContextError("MCP context enrichment returned invalid JSON") from exc
        return context

    if not isinstance(data, dict):
        if _mcp_strict():
            raise MCPContextError("MCP context enrichment returned an invalid payload")
        return context

    return _merge_context(context, data)
