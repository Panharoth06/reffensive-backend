from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.schemas.ai_suggestion_schemas import SuggestionMode
from app.services.ai_suggestion.prompts import next_steps


@dataclass
class PromptBundle:
    prepared_context: dict[str, Any]
    system_prompt: str
    user_prompt: str


def build_prompt_bundle(mode: SuggestionMode, context: dict[str, Any]) -> PromptBundle:
    if mode != "next_steps":
        raise ValueError(f"unsupported suggestion mode: {mode}")
    prepared_context = next_steps.prepare_context(context)
    return PromptBundle(
        prepared_context=prepared_context,
        system_prompt=next_steps.system_prompt(),
        user_prompt=next_steps.user_prompt(prepared_context),
    )


def normalize_output(mode: SuggestionMode, text: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    if mode != "next_steps":
        raise ValueError(f"unsupported suggestion mode: {mode}")
    return next_steps.normalize_output(text, context)
