import grpc
from fastapi import APIRouter, Depends, HTTPException

from app.dependencies.auth import CurrentUser
from app.dependencies.rbac import require_platform_user
from app.internal.grpc import user_client
from app.internal.keycloak.admin_client import get_keycloak_admin_client
from app.utils.grpc_errors import raise_for_grpc_error

router = APIRouter(prefix="/auth", tags=["auth"])


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


def _map_identity_provider(raw: str) -> str | None:
    value = raw.strip().lower()
    if not value:
        return None
    if "github" in value:
        return "github"
    if "gitlab" in value:
        return "gitlab"
    return None


def _sync_provider_accounts_from_keycloak(user_id: str) -> dict:
    synced: list[dict] = []
    errors: list[str] = []

    try:
        keycloak_admin = get_keycloak_admin_client()
        identities = keycloak_admin.list_federated_identities(user_id)
    except HTTPException as exc:
        return {"synced": synced, "errors": [str(exc.detail)]}
    except Exception as exc:
        return {"synced": synced, "errors": [f"unexpected provider sync failure: {exc}"]}

    for identity in identities:
        identity_provider = str(identity.get("identityProvider", "")).strip()
        provider_type = _map_identity_provider(identity_provider)
        if provider_type is None:
            continue

        provider_account_id = str(identity.get("userId", "")).strip()
        provider_username = str(identity.get("userName", "")).strip() or provider_account_id
        if not provider_account_id or not provider_username:
            continue

        try:
            response = user_client.upsert_provider_account(
                user_id=user_id,
                provider_type=provider_type,
                provider_account_id=provider_account_id,
                provider_username=provider_username,
                provider_email="",
                access_token=None,
                refresh_token=None,
                timeout=5.0,
            )
            account = response.account
            synced.append(
                {
                    "provider_type": account.provider_type,
                    "provider_account_id": account.provider_account_id,
                    "provider_username": account.provider_username,
                    "status": account.status,
                }
            )
        except grpc.RpcError as exc:
            details = exc.details() or "provider sync failed"
            errors.append(details)

    return {"synced": synced, "errors": errors}


@router.get("/me")
def get_me(current_user: CurrentUser = Depends(require_platform_user)) -> dict:
    provider_sync = _sync_provider_accounts_from_keycloak(current_user.user_id)
    try:
        response = user_client.get_user(user_id=current_user.user_id, timeout=5.0)
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)
    return {
        "user_id": current_user.user_id,
        "azp": current_user.azp,
        "actor_type": current_user.actor_type,
        "roles": sorted(current_user.roles),
        "scopes": sorted(current_user.scopes),
        "user": _map_proto_user(response.user),
        "provider_sync": provider_sync,
    }
