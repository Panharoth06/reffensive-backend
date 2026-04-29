"""FastAPI router for API key management endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Path, Query, status
from app.dependencies.auth import CurrentUser
from app.dependencies.rbac import require_web_or_cli_platform_user
from app.internal.apikey_client import APIKeyClient
from app.schemas.apikey_schemas import (
    APIKeyListResponse,
    APIKeyResponse,
    CreateAPIKeyRequest,
    CreateAPIKeyResponse,
    RevokeAPIKeyResponse,
    ValidateAPIKeyRequest,
    ValidateAPIKeyResponse,
)

router = APIRouter(prefix="/api/v1/apikeys", tags=["API Keys"])


@router.post(
    "/create",
    response_model=CreateAPIKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new API key",
)
async def create_api_key(
    body: CreateAPIKeyRequest,
    project_id: str = Query(..., description="Project ID"),
    current_user: CurrentUser = Depends(require_web_or_cli_platform_user),
) -> CreateAPIKeyResponse:
    """Create a new API key for a project.

    The returned `plain_key` is shown only once and cannot be retrieved later.
    Store it securely in your CI/CD pipeline.
    """
    client = APIKeyClient()
    return client.create_api_key(
        project_id=project_id,
        name=body.name,
        description=body.description or "",
        scopes=body.scopes,
        user_id=current_user.user_id,
    )


@router.post(
    "/validate",
    response_model=ValidateAPIKeyResponse,
    summary="Validate an API key",
)
async def validate_api_key(
    body: ValidateAPIKeyRequest,
    _: CurrentUser = Depends(require_web_or_cli_platform_user),
) -> ValidateAPIKeyResponse:
    """Validate an API key and check if it has permissions for a specific action."""
    client = APIKeyClient()
    return client.validate_api_key(key=body.key, action=body.action)


@router.post(
    "/{key_id}/revoke",
    response_model=RevokeAPIKeyResponse,
    summary="Revoke an API key",
)
async def revoke_api_key(
    key_id: str = Path(..., description="ID of the key to revoke"),
    current_user: CurrentUser = Depends(require_web_or_cli_platform_user),
) -> RevokeAPIKeyResponse:
    """Revoke an API key, immediately invalidating it."""
    client = APIKeyClient()
    return client.revoke_api_key(key_id=key_id, user_id=current_user.user_id)


@router.get(
    "/project/{project_id}",
    response_model=APIKeyListResponse,
    summary="List API keys for a project",
)
async def list_project_api_keys(
    project_id: str = Path(..., description="Project ID"),
    active_only: bool = Query(False, description="Only return active keys"),
    current_user: CurrentUser = Depends(require_web_or_cli_platform_user),
) -> APIKeyListResponse:
    """List all API keys for a project.

    Set `active_only=true` to only return keys that haven't been revoked.
    """
    client = APIKeyClient()
    return client.list_project_api_keys(
        project_id=project_id, active_only=active_only, user_id=current_user.user_id
    )


@router.get(
    "/{key_id}",
    response_model=APIKeyResponse,
    summary="Get a specific API key",
)
async def get_api_key(
    key_id: str = Path(..., description="ID of the key"),
    current_user: CurrentUser = Depends(require_web_or_cli_platform_user),
) -> APIKeyResponse:
    """Get details of a specific API key."""
    client = APIKeyClient()
    return client.get_api_key(key_id=key_id, user_id=current_user.user_id)
