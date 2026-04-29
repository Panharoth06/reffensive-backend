from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException, status

from app.dependencies.auth import (
    PLATFORM_ROLE_ADMIN,
    PLATFORM_ROLE_USER,
    CurrentUser,
    get_current_user,
    has_any_role,
    require_web_user,
)


def _normalize_required_roles(roles: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                role.strip().upper()
                for role in roles
                if isinstance(role, str) and role.strip()
            }
        )
    )


def require_roles(*required_roles: str) -> Callable[..., CurrentUser]:
    normalized = _normalize_required_roles(required_roles)

    def dependency(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not normalized or has_any_role(current_user, *normalized):
            return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required role. Need one of: {', '.join(normalized)}",
        )

    return dependency


def require_web_roles(*required_roles: str) -> Callable[..., CurrentUser]:
    normalized = _normalize_required_roles(required_roles)

    def dependency(current_user: CurrentUser = Depends(require_web_user)) -> CurrentUser:
        if not normalized or has_any_role(current_user, *normalized):
            return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required web role. Need one of: {', '.join(normalized)}",
        )

    return dependency


def require_web_or_cli_roles(*required_roles: str) -> Callable[..., CurrentUser]:
    from app.dependencies.auth import require_web_or_cli_user

    normalized = _normalize_required_roles(required_roles)

    def dependency(current_user: CurrentUser = Depends(require_web_or_cli_user)) -> CurrentUser:
        if not normalized or has_any_role(current_user, *normalized):
            return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required role. Need one of: {', '.join(normalized)}",
        )

    return dependency


require_platform_user = require_roles(PLATFORM_ROLE_USER, PLATFORM_ROLE_ADMIN)
require_web_platform_user = require_web_roles(PLATFORM_ROLE_USER, PLATFORM_ROLE_ADMIN)
require_web_or_cli_platform_user = require_web_or_cli_roles(PLATFORM_ROLE_USER, PLATFORM_ROLE_ADMIN)
require_web_admin = require_web_roles(PLATFORM_ROLE_ADMIN)


def ensure_self_or_admin(current_user: CurrentUser, target_user_id: str) -> None:
    target = target_user_id.strip()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target user_id is required",
        )
    if target == current_user.user_id.strip():
        return
    if has_any_role(current_user, PLATFORM_ROLE_ADMIN):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Only ADMIN can access another user's resources",
    )


def resolve_effective_user_id(current_user: CurrentUser, requested_user_id: str | None) -> str:
    candidate = (requested_user_id or "").strip()
    if not candidate:
        return current_user.user_id
    if candidate == current_user.user_id.strip():
        return current_user.user_id
    if has_any_role(current_user, PLATFORM_ROLE_ADMIN):
        return candidate
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Only ADMIN can act on behalf of another user",
    )

