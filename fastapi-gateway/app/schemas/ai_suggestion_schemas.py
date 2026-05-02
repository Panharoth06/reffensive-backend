from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


SuggestionMode = Literal["next_steps"]


class GenerateAISuggestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str = Field(
        ...,
        title="Job ID",
        description="Scan job UUID used as the reference key for loading scan results.",
        examples=["11111111-1111-1111-1111-111111111111"],
    )
    mode: SuggestionMode = Field(
        ...,
        title="Mode",
        description="Choose which AI output to generate.",
        examples=["next_steps"],
    )


class UpdateAISuggestionFeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: SuggestionMode = Field(
        ...,
        title="Mode",
        description="Which saved suggestion to update feedback for.",
        examples=["next_steps"],
    )
    feedback: str = Field(..., min_length=1, max_length=5000)


class AISuggestionResponse(BaseModel):
    id: str
    job_id: str
    mode: SuggestionMode
    provider: str
    model: str
    content: str
    output: dict[str, Any] = Field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0
    feedback: str = ""
    is_suggested: bool = True
    created_at: datetime | None = None
    updated_at: datetime | None = None


class InternalAISuggestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str = Field(
        ...,
        title="Job ID",
        description="Scan job UUID used as the reference key.",
    )
    mode: SuggestionMode = Field(
        ...,
        title="Mode",
        description="Choose which AI output to generate.",
    )
    context: dict[str, Any]


class InternalMCPContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: SuggestionMode = Field(
        ...,
        title="Mode",
        description="Which AI suggestion mode is requesting MCP enrichment.",
    )
    context: dict[str, Any]


class InternalMCPContextResponse(BaseModel):
    summary: str = ""
    resources: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)


class InternalAISuggestionUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0


class InternalAISuggestionResponse(BaseModel):
    mode: SuggestionMode
    provider: str
    model: str
    content: str
    output: dict[str, Any] = Field(default_factory=dict)
    usage: InternalAISuggestionUsage = Field(default_factory=InternalAISuggestionUsage)
