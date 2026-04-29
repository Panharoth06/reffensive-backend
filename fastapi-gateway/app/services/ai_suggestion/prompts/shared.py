from __future__ import annotations

import json
from typing import Any


def compact_context(context: dict[str, Any], *, keys: list[str]) -> dict[str, Any]:
    return {key: context[key] for key in keys if key in context and context[key] not in (None, "", [], {}, ())}


def include_optional_context(prepared: dict[str, Any], source: dict[str, Any], *keys: str) -> dict[str, Any]:
    for key in keys:
        value = source.get(key)
        if value not in (None, "", [], {}, ()):
            prepared[key] = value
    return prepared


def trim_list(items: list[Any], *, limit: int) -> list[Any]:
    return list(items[:limit]) if items else []


def json_block(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True)


def example_block(*, title: str, context: dict[str, Any], response: str) -> str:
    return (
        f"{title}\n"
        f"Example context:\n{json_block(context)}\n"
        f"Example response:\n{response.strip()}"
    )


def first_sentence(text: str) -> str:
    clean = " ".join(text.strip().split())
    if not clean:
        return ""
    for delimiter in (". ", "! ", "? "):
        if delimiter in clean:
            return clean.split(delimiter, 1)[0].strip() + delimiter.strip()
    return clean[:220].strip()


def bullet_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        normalized = raw.strip().lstrip("-*0123456789. ").strip()
        if normalized:
            lines.append(normalized)
    return lines
