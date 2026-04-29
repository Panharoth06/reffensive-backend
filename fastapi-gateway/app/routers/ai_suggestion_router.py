from __future__ import annotations

import os

from fastapi import APIRouter, Depends, Header, HTTPException, status

from app.dependencies.auth import CurrentUser, get_current_user
from app.internal.ai_suggestion_client import ai_suggestion_client
from app.schemas.ai_suggestion_schemas import (
    AISuggestionResponse,
    GenerateAISuggestionRequest,
    InternalMCPContextRequest,
    InternalMCPContextResponse,
    InternalAISuggestionRequest,
    InternalAISuggestionResponse,
    UpdateAISuggestionFeedbackRequest,
)
from app.services.ai_suggestion.mcp_bridge import build_mcp_context_payload
from app.services.ai_suggestion.orchestrator import AISuggestionProviderError, generate_ai_suggestion

router = APIRouter(prefix="/ai-suggestions", tags=["AI Suggestions"])
legacy_router = APIRouter(prefix="/ai", tags=["AI Suggestions"])
internal_router = APIRouter(prefix="/internal/ai")


@router.post(
    "/generate",
    response_model=AISuggestionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate AI suggestion for a scan job",
)
@legacy_router.post(
    "/suggestion/generate",
    response_model=AISuggestionResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
def generate_suggestion(
    body: GenerateAISuggestionRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> AISuggestionResponse:
    return ai_suggestion_client.generate_suggestion(
        body,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.get(
    "/{suggestion_id}",
    response_model=AISuggestionResponse,
    summary="Get saved AI suggestion",
)
def get_suggestion(
    suggestion_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> AISuggestionResponse:
    return ai_suggestion_client.get_suggestion(
        suggestion_id,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@router.patch(
    "/{job_id}/feedback",
    response_model=AISuggestionResponse,
    summary="Update AI suggestion feedback",
)
def update_feedback(
    job_id: str,
    body: UpdateAISuggestionFeedbackRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> AISuggestionResponse:
    return ai_suggestion_client.update_feedback(
        job_id,
        body,
        user_id=current_user.user_id,
        api_key_id=current_user.api_key_id,
        api_project_id=current_user.project_id,
    )


@internal_router.post(
    "/suggest",
    response_model=InternalAISuggestionResponse,
    summary="Internal suggestion provider endpoint",
)
async def internal_generate_suggestion(
    body: InternalAISuggestionRequest,
    x_internal_secret: str | None = Header(default=None),
) -> InternalAISuggestionResponse:
    configured_secret = os.getenv("AI_SUGGESTION_INTERNAL_SECRET", "").strip()
    if configured_secret and x_internal_secret != configured_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid internal secret")

    try:
        return await generate_ai_suggestion(body.mode, body.context)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except AISuggestionProviderError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.detail,
            headers=exc.headers,
        ) from exc


@internal_router.post(
    "/mcp/ai-suggestion/context",
    response_model=InternalMCPContextResponse,
    summary="Internal MCP-style context bridge for suggestions",
)
async def internal_mcp_ai_suggestion_context(
    body: InternalMCPContextRequest,
    x_mcp_secret: str | None = Header(default=None),
) -> InternalMCPContextResponse:
    configured_secret = os.getenv("AI_SUGGESTION_MCP_SECRET", "").strip()
    if configured_secret and x_mcp_secret != configured_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid mcp secret")

    return build_mcp_context_payload(body.mode, body.context)
