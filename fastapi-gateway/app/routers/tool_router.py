import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from app.dependencies.auth import CurrentUser
from app.dependencies.rbac import require_web_admin
from app.internal.tool_client import tool_client
from app.schemas.tool_schemas import (
    CreateToolRequest,
    SetToolActiveResponse,
    ToolResponse,
    UpdateToolRequest,
)

router = APIRouter(prefix="/tools", tags=["Tools"])


def _load_tool_request_examples() -> Dict[str, Dict[str, Any]]:
    repo_root = Path(__file__).resolve().parents[3]
    examples: Dict[str, Dict[str, Any]] = {}
    ignored_files = {"test.json", "sub-test.json"}

    for json_path in sorted(repo_root.glob("*.json")):
        if json_path.name in ignored_files:
            continue
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            continue

        key = json_path.stem.replace("-", "_")
        examples[key] = {
            "summary": tool_name,
            "description": f"Example loaded from {json_path.name}",
            "value": payload,
        }

    return examples


TOOL_REQUEST_EXAMPLES = _load_tool_request_examples()


@router.post("", response_model=ToolResponse, status_code=201, summary="Create a tool")
def create_tool(
    body: CreateToolRequest = Body(..., openapi_examples=TOOL_REQUEST_EXAMPLES),
    # current_user: CurrentUser = Depends(require_web_user),
) -> ToolResponse:
    # ensure_self_or_admin(current_user, current_user.user_id)
    return tool_client.create_tool(body)


@router.get("", summary="List tools")
async def list_tools(
    active_only: bool = Query(False, description="Return only active tools"),
    category_name: Optional[str] = Query(None, description="Filter by category name"),
    # _: CurrentUser = Depends(require_scan_permission),
) -> JSONResponse:
    tools = await asyncio.to_thread(
        tool_client.list_tools,
        active_only=active_only,
        category_name=category_name or "",
    )
    return JSONResponse(content=jsonable_encoder(tools))


@router.get("/{tool_id}", summary="Get a tool by ID")
async def get_tool(
    tool_id: str,
    # _: CurrentUser = Depends(require_scan_permission),
) -> JSONResponse:
    tool = await asyncio.to_thread(tool_client.get_tool, tool_id)
    return JSONResponse(content=jsonable_encoder(tool))


@router.put("/{tool_id}", response_model=ToolResponse, summary="Update a tool (partial — omit fields to keep existing)")
def update_tool(
    tool_id: str,
    body: UpdateToolRequest,
    # current_user: CurrentUser = Depends(require_web_user),
) -> ToolResponse:
    # ensure_self_or_admin(current_user, current_user.user_id)
    return tool_client.update_tool(tool_id, body)


@router.delete("/{tool_id}", response_model=SetToolActiveResponse, summary="Soft-delete a tool (sets is_active=false)")
def deactivate_tool(
    tool_id: str,
    current_user: CurrentUser = Depends(require_web_admin),
) -> SetToolActiveResponse:
    # ensure_self_or_admin(current_user, current_user.user_id)
    return tool_client.set_tool_active(tool_id, is_active=False)


@router.patch("/{tool_id}/activate", response_model=SetToolActiveResponse, summary="Reactivate a tool")
def activate_tool(
    tool_id: str,
    # current_user: CurrentUser = Depends(require_web_user),
) -> SetToolActiveResponse:
    # ensure_self_or_admin(current_user, current_user.user_id)
    return tool_client.set_tool_active(tool_id, is_active=True)
