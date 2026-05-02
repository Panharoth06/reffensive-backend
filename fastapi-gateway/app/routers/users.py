import grpc
from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies.auth import CurrentUser, PLATFORM_ROLE_USER, require_web_user
from app.dependencies.rbac import ensure_self_or_admin, require_web_admin, require_web_platform_user
from app.internal.grpc import user_client
from app.internal.keycloak.admin_client import get_keycloak_admin_client
from app.schemas.user_api_schemas import RegisterUserPayload, UpdateUserPayload
from app.utils.grpc_errors import raise_for_grpc_error

router = APIRouter(prefix="/users", tags=["users"])


def _map_proto_user(user) -> dict:
    return {
        "user_id": user.user_id,
        "username": user.username,
        "email": user.email,
        "alias_name": user.alias_name,
        "avatar_profile": user.avatar_profile,
        "created_at": user.created_at,
        "last_modified": user.last_modified,
    }


# ─── Create User ───────────────────────────────────────────────────────────────
@router.post("")
def create_user(
    payload: RegisterUserPayload,
) -> dict:
    # Public registration flow:
    # 1) Create user in Keycloak
    # 2) Create user in Go DB using the returned keycloak user_id
    # 3) If DB step fails, compensate by removing Keycloak user
    keycloak_client = get_keycloak_admin_client()
    keycloak_user_id = keycloak_client.create_user(
        username=payload.username,
        email=payload.email,
        password=payload.password,
        first_name=payload.first_name,
        last_name=payload.last_name,
        enabled=True,
    )
    try:
        keycloak_client.assign_realm_role(keycloak_user_id, PLATFORM_ROLE_USER)
    except HTTPException as exc:
        rollback_errors: list[str] = []
        try:
            keycloak_client.delete_user(keycloak_user_id)
        except HTTPException:
            rollback_errors.append("keycloak rollback failed")

        if rollback_errors:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"User role assignment failed and rollback was partial: {', '.join(rollback_errors)}",
            ) from exc
        raise

    try:
        response = user_client.create_user(
            user_id=keycloak_user_id,
            username=payload.username,
            email=payload.email,
            alias_name=payload.alias_name or "",
            avatar_profile=payload.avatar_profile or "",
        )
    except grpc.RpcError as exc:
        rollback_errors: list[str] = []

        # Defensive rollback for possible partial DB writes.
        try:
            user_client.delete_user(user_id=keycloak_user_id)
        except grpc.RpcError as cleanup_exc:
            if cleanup_exc.code() != grpc.StatusCode.NOT_FOUND:
                rollback_errors.append("database rollback failed")

        try:
            keycloak_client.delete_user(keycloak_user_id)
        except HTTPException:
            rollback_errors.append("keycloak rollback failed")

        if rollback_errors:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"User create failed and rollback was partial: {', '.join(rollback_errors)}",
            ) from exc

        raise_for_grpc_error(exc)

    return _map_proto_user(response.user)

# ─── List User ───────────────────────────────────────────────────────────────
@router.get("")
def list_users(_: CurrentUser = Depends(require_web_admin)) -> list[dict]:
    try:
        response = user_client.list_users()
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    return [_map_proto_user(item) for item in response.users]

# ─── Get User By ID ───────────────────────────────────────────────────────────────
@router.get("/{user_id}")
def get_user(user_id: str, current_user: CurrentUser = Depends(require_web_platform_user)) -> dict:
    ensure_self_or_admin(current_user, user_id)
    try:
        response = user_client.get_user(user_id=user_id)
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    return _map_proto_user(response.user)


# ─── Update User By ID ───────────────────────────────────────────────────────────────
@router.patch("/{user_id}")
def update_user(
    user_id: str,
    payload: UpdateUserPayload,
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> dict:
    ensure_self_or_admin(current_user, user_id)
    fields_set = payload.model_fields_set

    try:
        response = user_client.update_user(
            user_id=user_id,
            username=payload.username or "",
            email=payload.email or "",
            alias_name=payload.alias_name if "alias_name" in fields_set else None,
            avatar_profile=payload.avatar_profile if "avatar_profile" in fields_set else None,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)

    return _map_proto_user(response.user)

# ─── Delete User By ID ───────────────────────────────────────────────────────────────
@router.delete("/{user_id}")
def delete_user(user_id: str, current_user: CurrentUser = Depends(require_web_platform_user)) -> dict:
    ensure_self_or_admin(current_user, user_id)
    try:
        response = user_client.delete_user(user_id=user_id)
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)

    return {"deleted": response.deleted, "user_id": user_id}
