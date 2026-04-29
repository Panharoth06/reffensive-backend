from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query, status

from app.dependencies.auth import CurrentUser, require_project_access
from app.internal.project_client import project_client
from app.schemas.project_schemas import (
    CreateProjectRequest,
    ProjectResponse,
    UpdateProjectRequest,
)

router = APIRouter(prefix="/projects", tags=["Projects"])


@router.post(
    "",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new project",
)
def create_project(
    body: CreateProjectRequest = Body(...),
    current_user: CurrentUser = Depends(require_project_access),
) -> ProjectResponse:
    return project_client.create_project(body, user_id=current_user.user_id)


@router.get(
    "",
    response_model=list[ProjectResponse],
    summary="List all projects for current user",
)
def list_projects(
    current_user: CurrentUser = Depends(require_project_access),
) -> list[ProjectResponse]:
    return project_client.list_projects(user_id=current_user.user_id)


@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    summary="Get project by ID",
)
def get_project(
    project_id: str,
    current_user: CurrentUser = Depends(require_project_access),
) -> ProjectResponse:
    return project_client.get_project_by_id(project_id, user_id=current_user.user_id)


@router.patch(
    "/{project_id}",
    response_model=ProjectResponse,
    summary="Update project",
)
def update_project(
    project_id: str,
    body: UpdateProjectRequest = Body(...),
    current_user: CurrentUser = Depends(require_project_access),
) -> ProjectResponse:
    return project_client.update_project(project_id, body, user_id=current_user.user_id)


@router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete project",
)
def delete_project(
    project_id: str,
    cascade: bool = Query(default=True),
    current_user: CurrentUser = Depends(require_project_access),
) -> None:
    project_client.delete_project(project_id, user_id=current_user.user_id, cascade=cascade)
