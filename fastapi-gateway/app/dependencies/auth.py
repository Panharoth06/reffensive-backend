import base64
import json
from dataclasses import dataclass
from typing import Callable, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

import grpc
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import get_settings
from app.core.security import extract_user_id, verify_access_token
from app.internal.apikey_client import APIKeyClient
from app.internal.grpc import user_client
from app.quota import build_anon_fingerprint
from app.utils.grpc_errors import raise_for_grpc_error

bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
ActorType = Literal["web_user", "cli_user", "api_key", "anonymous"]
PLATFORM_ROLE_USER = "USER"
PLATFORM_ROLE_ADMIN = "ADMIN"


@dataclass
class CurrentUser:
    user_id: str
    azp: str
    actor_type: ActorType
    roles: set[str]
    scopes: set[str]
    claims: dict
    project_id: str | None = None
    api_key_id: str | None = None
    auth_method: str = "jwt"


def _decode_jwt_payload_simple(token: str) -> dict:
    """Simple JWT parsing without signature verification (for testing only)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}

        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return {}


def _looks_like_jwt(token: str) -> bool:
    return token.count(".") == 2


def _get_current_claims_from_credentials(
    credentials: HTTPAuthorizationCredentials | None,
) -> dict:
    settings = get_settings()
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token",
        )

    if settings.keycloak_issuer and settings.keycloak_jwks_url:
        return verify_access_token(credentials.credentials)

    claims = _decode_jwt_payload_simple(credentials.credentials)
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token format",
        )
    return claims


def get_current_claims(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    return _get_current_claims_from_credentials(credentials)


def get_roles(claims: dict) -> set[str]:
    normalized: set[str] = set()

    realm_values = claims.get("realm_access", {}).get("roles", [])
    if isinstance(realm_values, list):
        for role in realm_values:
            if isinstance(role, str) and role.strip():
                normalized.add(role.strip().upper())

    # Also include client roles from resource_access to support deployments
    # where roles are assigned at client scope instead of realm scope.
    resource_access = claims.get("resource_access", {})
    if isinstance(resource_access, dict):
        for value in resource_access.values():
            if not isinstance(value, dict):
                continue
            client_roles = value.get("roles", [])
            if not isinstance(client_roles, list):
                continue
            for role in client_roles:
                if isinstance(role, str) and role.strip():
                    normalized.add(role.strip().upper())

    return normalized


def get_scopes(claims: dict) -> set[str]:
    scope_values = claims.get("scope", "")
    if isinstance(scope_values, str):
        return {scope for scope in scope_values.split() if scope}
    if isinstance(scope_values, list):
        return {scope for scope in scope_values if isinstance(scope, str) and scope.strip()}
    return set()


def get_azp(claims: dict) -> str:
    azp = claims.get("azp")
    if not isinstance(azp, str) or not azp.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing azp claim",
        )
    return azp


def get_actor_type(azp: str) -> ActorType:
    settings = get_settings()

    if azp in settings.keycloak_web_client_ids:
        return "web_user"
    if azp == settings.keycloak_cli_client_id:
        return "cli_user"

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Unauthorized client: {azp}",
    )


def build_current_user(claims: dict) -> CurrentUser:
    azp = get_azp(claims)
    actor_type = get_actor_type(azp)
    user_id = extract_user_id(claims)

    return CurrentUser(
        user_id=user_id,
        azp=azp,
        actor_type=actor_type,
        roles=get_roles(claims),
        scopes=get_scopes(claims),
        claims=claims,
    )


def build_api_key_user(api_key: str) -> CurrentUser:
    normalized_key = api_key.strip()
    if not normalized_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )

    validation = APIKeyClient().validate_api_key(normalized_key, action="")
    if not validation.valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=validation.reason or "Invalid API key",
        )

    settings = get_settings()
    azp = f"{settings.keycloak_ci_client_prefix}apikey"
    claims = {
        "azp": azp,
        "sub": validation.user_id,
        "user_id": validation.user_id,
        "scope": " ".join(validation.scopes),
        "api_key_id": validation.key_id,
        "project_id": validation.project_id,
    }
    return CurrentUser(
        user_id=validation.user_id,
        azp=azp,
        actor_type="api_key",
        roles=set(),
        scopes=set(validation.scopes),
        claims=claims,
        project_id=validation.project_id,
        api_key_id=validation.key_id,
        auth_method="api_key",
    )


def _build_anon_user_id(fingerprint: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"anon-scan:{fingerprint}"))


def build_anon_current_user(request: Request) -> CurrentUser:
    fingerprint = build_anon_fingerprint(request)
    anon_user_id = _build_anon_user_id(fingerprint)
    anon_name = f"anon-{anon_user_id.replace('-', '')[:12]}"
    claims = {
        "sub": anon_user_id,
        "user_id": anon_user_id,
        "preferred_username": anon_name,
        "email": f"{anon_name}@anonymous.local",
        "anon_fingerprint": fingerprint,
    }
    request.state.anon_fingerprint = fingerprint
    return CurrentUser(
        user_id=anon_user_id,
        azp="anonymous",
        actor_type="anonymous",
        roles=set(),
        scopes=set(),
        claims=claims,
        auth_method="anonymous",
    )


def has_any_role(current_user: CurrentUser, *roles: str) -> bool:
    expected = {role.strip().upper() for role in roles if isinstance(role, str) and role.strip()}
    if not expected:
        return True
    return len(current_user.roles.intersection(expected)) > 0


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
        return True
    except Exception:
        return False


def _extract_identity_from_claims(claims: dict) -> tuple[str, str]:
    email = claims.get("email", "")
    username = claims.get("preferred_username", "")
    normalized_email = email.strip() if isinstance(email, str) else ""
    normalized_username = username.strip() if isinstance(username, str) else ""
    return normalized_email, normalized_username


def _sync_user_to_core(current_user: CurrentUser) -> None:
    if current_user.actor_type == "api_key":
        return

    email, username = _extract_identity_from_claims(current_user.claims)
    if not _is_uuid(current_user.user_id):
        # Core user_id is UUID-backed; do not attempt auto-provision with non-UUID IDs.
        return
    if not email or not username:
        # Core CreateUser requires both fields.
        return

    user_client.create_user(
        user_id=current_user.user_id,
        username=username,
        email=email,
        alias_name="",
        avatar_profile="",
        timeout=5.0,
    )


def ensure_user_exists(current_user: CurrentUser) -> CurrentUser:
    if current_user.actor_type == "api_key":
        return current_user

    normalized_user_id = current_user.user_id.strip() if isinstance(current_user.user_id, str) else ""
    normalized_email, normalized_username = _extract_identity_from_claims(current_user.claims)

    if not normalized_user_id and not normalized_email and not normalized_username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token has no usable identifier for user lookup",
        )

    def _check_exists():
        return user_client.check_user_exists(
            user_id=normalized_user_id,
            email=normalized_email,
            username=normalized_username,
            timeout=3.0,
        )

    try:
        response = _check_exists()
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)

    if not response.exists:
        try:
            _sync_user_to_core(current_user)
            response = _check_exists()
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)

    if not response.exists:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User does not exist in core service",
        )

    resolved_user_id = response.resolved_user_id.strip() if isinstance(response.resolved_user_id, str) else ""
    if resolved_user_id:
        current_user.user_id = resolved_user_id

    return current_user


def _resolve_current_user(
    credentials: HTTPAuthorizationCredentials | None,
    x_api_key: str | None,
) -> CurrentUser:
    api_key = (x_api_key or "").strip()
    if not api_key and credentials is not None and credentials.scheme.lower() == "bearer":
        bearer_value = credentials.credentials.strip()
        if bearer_value and not _looks_like_jwt(bearer_value):
            api_key = bearer_value

    if api_key:
        current_user = build_api_key_user(api_key)
        return ensure_user_exists(current_user)

    claims = _get_current_claims_from_credentials(credentials)
    current_user = build_current_user(claims)
    return ensure_user_exists(current_user)


def request_has_auth_credentials(request: Request) -> bool:
    authorization = request.headers.get("authorization", "").strip()
    api_key = request.headers.get("x-api-key", "").strip()
    return bool(authorization or api_key)


async def resolve_current_user_from_request(request: Request) -> CurrentUser:
    cached_user = getattr(request.state, "current_user", None)
    if isinstance(cached_user, CurrentUser):
        return cached_user

    credentials = await bearer_scheme(request)
    x_api_key = await api_key_header(request)
    current_user = _resolve_current_user(credentials, x_api_key)
    request.state.current_user = current_user
    return current_user


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_api_key: str | None = Depends(api_key_header),
) -> CurrentUser:
    cached_user = getattr(request.state, "current_user", None)
    if isinstance(cached_user, CurrentUser):
        return cached_user

    current_user = _resolve_current_user(credentials, x_api_key)
    request.state.current_user = current_user
    return current_user


def get_scan_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_api_key: str | None = Depends(api_key_header),
) -> CurrentUser:
    cached_user = getattr(request.state, "current_user", None)
    if isinstance(cached_user, CurrentUser):
        return cached_user

    try:
        current_user = _resolve_current_user(credentials, x_api_key)
    except HTTPException:
        if request_has_auth_credentials(request):
            raise
        current_user = ensure_user_exists(build_anon_current_user(request))

    request.state.current_user = current_user
    return current_user


def get_current_web_claims(claims: dict = Depends(get_current_claims)) -> dict:
    azp = get_azp(claims)
    actor_type = get_actor_type(azp)
    if actor_type != "web_user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Web client token required, got: {actor_type}",
        )
    return claims


def require_actor_types(*allowed_actor_types: ActorType) -> Callable[..., CurrentUser]:
    allowed = set(allowed_actor_types)

    def dependency(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.actor_type not in allowed:
            allowed_text = ", ".join(sorted(allowed))
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden actor type: {current_user.actor_type}. Allowed: {allowed_text}",
            )
        return current_user

    return dependency


require_web_user = require_actor_types("web_user")
require_cli_user = require_actor_types("cli_user")
require_api_key_client = require_actor_types("api_key")
require_web_or_cli_user = require_actor_types("web_user", "cli_user")
require_all_clients = require_actor_types("web_user", "cli_user", "api_key")


def require_scan_permission(current_user: CurrentUser = Depends(get_scan_current_user)) -> CurrentUser:
    if current_user.actor_type in {"api_key", "anonymous"}:
        return current_user

    if current_user.actor_type not in {"web_user", "cli_user"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    if not has_any_role(current_user, PLATFORM_ROLE_USER, PLATFORM_ROLE_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="USER or ADMIN role is required for scan endpoints",
        )

    return current_user


def require_user_scan_permission(current_user: CurrentUser = Depends(require_scan_permission)) -> CurrentUser:
    if current_user.actor_type == "api_key":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key cannot access destructive scan actions",
        )
    if current_user.actor_type == "anonymous":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Anonymous scan users cannot access destructive scan actions",
        )
    return current_user


def require_project_access(current_user: CurrentUser = Depends(get_scan_current_user)) -> CurrentUser:
    if current_user.actor_type == "anonymous":
        return current_user

    if current_user.actor_type not in {"web_user", "cli_user"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    return current_user
