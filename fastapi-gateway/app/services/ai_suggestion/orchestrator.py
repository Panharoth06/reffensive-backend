from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any

import httpx
from redis.exceptions import RedisError

from app.quota import get_redis_client
from app.schemas.ai_suggestion_schemas import InternalAISuggestionResponse, InternalAISuggestionUsage, SuggestionMode
from app.services.ai_suggestion.mcp import MCPContextError, enrich_context_with_mcp
from app.services.ai_suggestion.prompts import build_prompt_bundle, normalize_output


GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
CACHE_TTL_SECONDS = int(os.getenv("AI_SUGGESTION_CACHE_TTL_SECONDS", "1800"))


@dataclass
class ProviderResult:
    provider: str
    model: str
    content: str
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class AISuggestionProviderError(Exception):
    status_code: int
    detail: str
    headers: dict[str, str] | None = None


@dataclass(frozen=True)
class ProviderRoute:
    provider: str
    model: str
    api_key: str


def _provider_display_name(provider: str) -> str:
    normalized = (provider or "AI").strip()
    return normalized[:1].upper() + normalized[1:]


def _extract_retry_headers(response: httpx.Response) -> dict[str, str] | None:
    retry_after = response.headers.get("retry-after", "").strip()
    if retry_after:
        return {"Retry-After": retry_after}
    return None


def _extract_provider_error_detail(response: httpx.Response) -> str | None:
    try:
        payload = response.json()
    except ValueError:
        text = response.text.strip()
        return text or None

    if isinstance(payload, dict):
        error_value = payload.get("error")
        if isinstance(error_value, dict):
            for key in ("message", "detail", "error"):
                value = error_value.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        if isinstance(error_value, str) and error_value.strip():
            return error_value.strip()
        for key in ("detail", "message"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    return None


def _translate_provider_error(provider: str, exc: httpx.HTTPError) -> AISuggestionProviderError:
    provider_name = _provider_display_name(provider)

    if isinstance(exc, httpx.HTTPStatusError):
        status_code = exc.response.status_code
        headers = _extract_retry_headers(exc.response)
        provider_detail = _extract_provider_error_detail(exc.response)
        if status_code == 429:
            return AISuggestionProviderError(
                status_code=503,
                detail=f"{provider_name} AI provider is temporarily rate limited. Please try again later.",
                headers=headers,
            )
        if 500 <= status_code < 600:
            return AISuggestionProviderError(
                status_code=503,
                detail=f"{provider_name} AI provider is temporarily unavailable. Please try again later.",
                headers=headers,
            )
        return AISuggestionProviderError(
            status_code=502,
            detail=(
                f"{provider_name} AI provider request failed with status {status_code}: {provider_detail}"
                if provider_detail
                else f"{provider_name} AI provider request failed with status {status_code}."
            ),
            headers=headers,
        )

    return AISuggestionProviderError(
        status_code=503,
        detail=f"{provider_name} AI provider request failed. Please try again later.",
    )

def _provider_model(provider: str, mode: SuggestionMode) -> str:
    if mode != "next_steps":
        raise ValueError(f"unsupported suggestion mode: {mode}")

    model_env_map = {
        "groq": ("AI_SUGGESTION_MODEL_NEXT_STEPS", "llama-3.3-70b-versatile"),
        "gemini": ("AI_SUGGESTION_MODEL_NEXT_STEPS_GEMINI", "gemini-2.0-flash"),
        "anthropic": ("AI_SUGGESTION_MODEL_NEXT_STEPS_ANTHROPIC", "claude-3-5-haiku-20241022"),
    }
    env_key, fallback = model_env_map[provider]
    return os.getenv(env_key, fallback).strip() or fallback


def _provider_routes_for_mode(mode: SuggestionMode) -> list[ProviderRoute]:
    if mode != "next_steps":
        raise ValueError(f"unsupported suggestion mode: {mode}")

    key_map = {
        "groq": os.getenv("AI_SUGGESTION_GROQ_API_KEY", "").strip(),
        "gemini": os.getenv("AI_SUGGESTION_GEMINI_API_KEY", "").strip(),
        "anthropic": os.getenv("AI_SUGGESTION_ANTHROPIC_API_KEY", "").strip(),
    }
    preferred = os.getenv("AI_SUGGESTION_PROVIDER_NEXT_STEPS", "groq").strip().lower() or "groq"
    provider_order = [preferred] + [name for name in ("groq", "gemini", "anthropic") if name != preferred]

    routes: list[ProviderRoute] = []
    for provider in provider_order:
        api_key = key_map.get(provider, "")
        if not api_key:
            continue
        routes.append(
            ProviderRoute(
                provider=provider,
                model=_provider_model(provider, mode),
                api_key=api_key,
            )
        )
    return routes


def _cache_key(*, mode: SuggestionMode, provider: str, model: str, context: dict[str, Any]) -> str:
    import json

    serialized = json.dumps(
        {
            "mode": mode,
            "provider": provider,
            "model": model,
            "context": context,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"ai:suggestion:{mode}:{provider}:{model}:{digest}"


def _is_retryable_provider_error(exc: AISuggestionProviderError) -> bool:
    return exc.status_code == 503


async def _get_cached_response(key: str) -> InternalAISuggestionResponse | None:
    import json

    try:
        raw = await get_redis_client().get(key)
    except (RedisError, OSError, TimeoutError):
        return None
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return InternalAISuggestionResponse.model_validate(payload)


async def _set_cached_response(key: str, response: InternalAISuggestionResponse) -> None:
    try:
        await get_redis_client().setex(
            key,
            CACHE_TTL_SECONDS,
            response.model_dump_json(),
        )
    except (RedisError, OSError, TimeoutError):
        return None


async def _call_groq(system_prompt: str, user_prompt: str, model: str, api_key: str) -> ProviderResult:
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    timeout = httpx.Timeout(45.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(GROQ_URL, headers=headers, json=payload)
        response.raise_for_status()
    data = response.json()
    content = data["choices"][0]["message"]["content"]
    usage = data.get("usage", {})
    return ProviderResult(
        provider="groq",
        model=model,
        content=content,
        input_tokens=int(usage.get("prompt_tokens", 0)),
        output_tokens=int(usage.get("completion_tokens", 0)),
    )


async def _call_gemini(system_prompt: str, user_prompt: str, model: str, api_key: str) -> ProviderResult:
    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {"temperature": 0.2},
    }
    timeout = httpx.Timeout(45.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            GEMINI_URL.format(model=model),
            params={"key": api_key},
            json=payload,
        )
        response.raise_for_status()
    data = response.json()
    parts = data["candidates"][0]["content"]["parts"]
    content = "\n".join(part.get("text", "") for part in parts if part.get("text"))
    usage = data.get("usageMetadata", {})
    return ProviderResult(
        provider="gemini",
        model=model,
        content=content,
        input_tokens=int(usage.get("promptTokenCount", 0)),
        output_tokens=int(usage.get("candidatesTokenCount", 0)),
    )


async def _call_anthropic(system_prompt: str, user_prompt: str, model: str, api_key: str) -> ProviderResult:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": 1400,
        "temperature": 0.2,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    timeout = httpx.Timeout(45.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(ANTHROPIC_URL, headers=headers, json=payload)
        response.raise_for_status()
    data = response.json()
    content = "\n".join(item.get("text", "") for item in data.get("content", []) if item.get("type") == "text")
    usage = data.get("usage", {})
    return ProviderResult(
        provider="anthropic",
        model=model,
        content=content,
        input_tokens=int(usage.get("input_tokens", 0)),
        output_tokens=int(usage.get("output_tokens", 0)),
    )


async def generate_ai_suggestion(mode: SuggestionMode, context: dict[str, Any]) -> InternalAISuggestionResponse:
    routes = _provider_routes_for_mode(mode)
    if not routes:
        raise ValueError("missing API key for AI suggestion provider")

    try:
        effective_context = await enrich_context_with_mcp(mode, context)
    except MCPContextError as exc:
        raise ValueError(str(exc)) from exc

    prompt_bundle = build_prompt_bundle(mode, effective_context)
    last_error: AISuggestionProviderError | None = None
    for route in routes:
        key = _cache_key(
            mode=mode,
            provider=route.provider,
            model=route.model,
            context=prompt_bundle.prepared_context,
        )
        cached = await _get_cached_response(key)
        if cached is not None:
            return cached

        try:
            if route.provider == "groq":
                result = await _call_groq(prompt_bundle.system_prompt, prompt_bundle.user_prompt, route.model, route.api_key)
            elif route.provider == "gemini":
                result = await _call_gemini(prompt_bundle.system_prompt, prompt_bundle.user_prompt, route.model, route.api_key)
            elif route.provider == "anthropic":
                result = await _call_anthropic(prompt_bundle.system_prompt, prompt_bundle.user_prompt, route.model, route.api_key)
            else:
                raise ValueError(f"unsupported AI provider: {route.provider}")
        except httpx.HTTPError as exc:
            translated = _translate_provider_error(route.provider, exc)
            last_error = translated
            if _is_retryable_provider_error(translated):
                continue
            raise translated from exc

        response = InternalAISuggestionResponse(
            mode=mode,
            provider=result.provider,
            model=result.model,
            content="",
            output=normalize_output(mode, result.content),
            usage=InternalAISuggestionUsage(
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
            ),
        )
        await _set_cached_response(key, response)
        return response

    if last_error is not None:
        raise last_error
    raise ValueError("no available AI suggestion provider")
