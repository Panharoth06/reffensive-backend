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


def trim_text(value: Any, *, max_chars: int) -> str:
    text = " ".join(str(value).split())
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def compact_value(
    value: Any,
    *,
    max_depth: int = 2,
    max_items: int = 6,
    max_string: int = 180,
) -> Any:
    if value in (None, "", [], {}, ()):
        return value
    if isinstance(value, str):
        return trim_text(value, max_chars=max_string)
    if isinstance(value, bool | int | float):
        return value
    if max_depth <= 0:
        return trim_text(json.dumps(value, ensure_ascii=True, default=str), max_chars=max_string)
    if isinstance(value, dict):
        compacted: dict[str, Any] = {}
        items = list(value.items())
        for key, item in items[:max_items]:
            reduced = compact_value(item, max_depth=max_depth - 1, max_items=max_items, max_string=max_string)
            if reduced not in (None, "", [], {}, ()):
                compacted[str(key)] = reduced
        if len(items) > max_items:
            compacted["_truncated_items"] = len(items) - max_items
        return compacted
    if isinstance(value, (list, tuple, set)):
        values = list(value)
        compacted_items = [
            reduced
            for item in values[:max_items]
            if (reduced := compact_value(item, max_depth=max_depth - 1, max_items=max_items, max_string=max_string))
            not in (None, "", [], {}, ())
        ]
        if len(values) > max_items:
            compacted_items.append({"_truncated_items": len(values) - max_items})
        return compacted_items
    return trim_text(repr(value), max_chars=max_string)


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
