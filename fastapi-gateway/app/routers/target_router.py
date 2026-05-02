from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.dependencies.auth import CurrentUser, require_project_access
from app.internal.target_client import target_client
from app.schemas.target_schemas import (
    CreateTargetRequest,
    TargetResponse,
    UpdateTargetRequest,
)

router = APIRouter(prefix="/projects/{project_id}/targets", tags=["Targets"])


@router.post(
    "",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a target within a project",
)
def create_target(
    project_id: str,
    body: CreateTargetRequest,
    current_user: CurrentUser = Depends(require_project_access),
) -> TargetResponse:
    return target_client.create_target(project_id, body, user_id=current_user.user_id)


@router.get(
    "",
    response_model=list[TargetResponse],
    summary="List all targets for a project",
)
def list_targets(
    project_id: str,
    current_user: CurrentUser = Depends(require_project_access),
) -> list[TargetResponse]:
    return target_client.list_targets(project_id, user_id=current_user.user_id)


@router.get(
    "/{target_id}",
    response_model=TargetResponse,
    summary="Get a target by ID",
)
def get_target(
    project_id: str,
    target_id: str,
    current_user: CurrentUser = Depends(require_project_access),
) -> TargetResponse:
    return target_client.get_target(project_id, target_id, user_id=current_user.user_id)


@router.patch(
    "/{target_id}",
    response_model=TargetResponse,
    summary="Update a target",
)
def update_target(
    project_id: str,
    target_id: str,
    body: UpdateTargetRequest,
    current_user: CurrentUser = Depends(require_project_access),
) -> TargetResponse:
    return target_client.update_target(project_id, target_id, body, user_id=current_user.user_id)


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a target",
)
def delete_target(
    project_id: str,
    target_id: str,
    current_user: CurrentUser = Depends(require_project_access),
) -> None:
    target_client.delete_target(project_id, target_id, user_id=current_user.user_id)
