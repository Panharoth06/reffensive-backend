import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

import grpc
import httpx
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.responses import RedirectResponse

from app.core.config import Settings, get_settings
from app.dependencies.auth import CurrentUser
from app.dependencies.rbac import require_web_platform_user, resolve_effective_user_id
from app.internal.grpc import user_client
from app.utils.grpc_errors import raise_for_grpc_error

router = APIRouter(prefix="/integrations", tags=["integrations"])
SUPPORTED_GIT_PROVIDERS = {"github", "gitlab"}


@dataclass(frozen=True)
class ProviderOAuthConfig:
    provider: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    api_base_url: str
    redirect_uri: str
    scope: str
    state_secret: str
    success_redirect_url: str
    error_redirect_url: str


def _base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _base64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def _validate_provider(provider: str) -> str:
    cleaned = provider.strip().lower()
    if cleaned not in SUPPORTED_GIT_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unsupported provider: {provider}",
        )
    return cleaned


def _build_provider_state(
    *,
    user_id: str,
    provider: str,
    secret: str,
    ttl_seconds: int = 600,
) -> str:
    payload = {
        "user_id": user_id,
        "provider": provider,
        "exp": int(time.time()) + ttl_seconds,
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_part = _base64url_encode(payload_json)
    signature = hmac.new(secret.encode("utf-8"), payload_part.encode("utf-8"), hashlib.sha256).digest()
    signature_part = _base64url_encode(signature)
    return f"{payload_part}.{signature_part}"


def _parse_provider_state(raw_state: str, *, provider: str, secret: str) -> dict:
    try:
        payload_part, signature_part = raw_state.split(".", 1)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {provider} OAuth state format",
        ) from exc

    expected_signature = hmac.new(
        secret.encode("utf-8"),
        payload_part.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    actual_signature = _base64url_decode(signature_part)
    if not hmac.compare_digest(expected_signature, actual_signature):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {provider} OAuth state signature",
        )

    try:
        payload = json.loads(_base64url_decode(payload_part).decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {provider} OAuth state payload",
        ) from exc

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {provider} OAuth state claims",
        )

    expires_at = payload.get("exp")
    if not isinstance(expires_at, int) or expires_at < int(time.time()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Expired {provider} OAuth state",
        )

    user_id = payload.get("user_id")
    if not isinstance(user_id, str) or not user_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {provider} OAuth state user",
        )

    payload_provider = payload.get("provider")
    if payload_provider != provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {provider} OAuth state provider",
        )
    return payload


def _with_query(url: str, **params: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update({key: value for key, value in params.items() if value is not None})
    return urlunparse(parsed._replace(query=urlencode(query)))


def _provider_config(provider: str, settings: Settings) -> ProviderOAuthConfig:
    if provider == "github":
        return ProviderOAuthConfig(
            provider="github",
            client_id=settings.github_oauth_client_id,
            client_secret=settings.github_oauth_client_secret,
            authorize_url=settings.github_oauth_authorize_url,
            token_url=settings.github_oauth_token_url,
            api_base_url=settings.github_oauth_api_base_url,
            redirect_uri=settings.github_oauth_redirect_uri,
            scope=settings.github_oauth_scope,
            state_secret=settings.github_oauth_state_secret,
            success_redirect_url=settings.github_connect_success_redirect_url,
            error_redirect_url=settings.github_connect_error_redirect_url,
        )

    return ProviderOAuthConfig(
        provider="gitlab",
        client_id=settings.gitlab_oauth_client_id,
        client_secret=settings.gitlab_oauth_client_secret,
        authorize_url=settings.gitlab_oauth_authorize_url,
        token_url=settings.gitlab_oauth_token_url,
        api_base_url=settings.gitlab_oauth_api_base_url,
        redirect_uri=settings.gitlab_oauth_redirect_uri,
        scope=settings.gitlab_oauth_scope,
        state_secret=settings.gitlab_oauth_state_secret,
        success_redirect_url=settings.gitlab_connect_success_redirect_url,
        error_redirect_url=settings.gitlab_connect_error_redirect_url,
    )


def _ensure_oauth_config(config: ProviderOAuthConfig) -> None:
    missing = []
    if not config.client_id:
        missing.append(f"{config.provider.upper()}_OAUTH_CLIENT_ID")
    if not config.client_secret:
        missing.append(f"{config.provider.upper()}_OAUTH_CLIENT_SECRET")
    if not config.state_secret:
        missing.append(f"{config.provider.upper()}_OAUTH_STATE_SECRET")
    if missing:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"{config.provider} OAuth is not configured. Missing: {', '.join(missing)}",
        )


def _error_redirect(config: ProviderOAuthConfig, message: str) -> RedirectResponse:
    redirect_url = _with_query(
        config.error_redirect_url,
        provider=config.provider,
        message=message,
    )
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)


async def _fetch_github_identity(
    *,
    client: httpx.AsyncClient,
    config: ProviderOAuthConfig,
    code: str,
) -> tuple[str, str, str, str, str | None]:
    token_response = await client.post(
        config.token_url,
        headers={"Accept": "application/json"},
        data={
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "code": code,
            "redirect_uri": config.redirect_uri,
        },
    )
    if token_response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub token exchange failed",
        )

    try:
        token_payload = token_response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub token response was not JSON",
        ) from exc

    access_token = str(token_payload.get("access_token", "")).strip()
    refresh_token_value = token_payload.get("refresh_token")
    refresh_token = str(refresh_token_value).strip() if isinstance(refresh_token_value, str) else None
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing GitHub access token",
        )

    api_headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {access_token}",
    }
    user_response = await client.get(f"{config.api_base_url.rstrip('/')}/user", headers=api_headers)
    if user_response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to fetch GitHub user profile",
        )

    try:
        user_payload = user_response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub user response was not JSON",
        ) from exc

    provider_account_id = str(user_payload.get("id", "")).strip()
    provider_username = str(user_payload.get("login", "")).strip()
    if not provider_account_id or not provider_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid GitHub profile data",
        )

    provider_email = ""
    email_value = user_payload.get("email")
    if isinstance(email_value, str) and email_value.strip():
        provider_email = email_value.strip()
    else:
        emails_response = await client.get(f"{config.api_base_url.rstrip('/')}/user/emails", headers=api_headers)
        if emails_response.status_code < 400:
            try:
                emails_payload = emails_response.json()
            except ValueError:
                emails_payload = []
            if isinstance(emails_payload, list):
                for item in emails_payload:
                    if not isinstance(item, dict):
                        continue
                    email_text = item.get("email")
                    if isinstance(email_text, str) and email_text.strip():
                        is_primary = bool(item.get("primary"))
                        is_verified = bool(item.get("verified"))
                        if is_primary and is_verified:
                            provider_email = email_text.strip()
                            break
                        if is_verified and not provider_email:
                            provider_email = email_text.strip()
                        elif not provider_email:
                            provider_email = email_text.strip()

    return provider_account_id, provider_username, provider_email, access_token, refresh_token


async def _fetch_gitlab_identity(
    *,
    client: httpx.AsyncClient,
    config: ProviderOAuthConfig,
    code: str,
) -> tuple[str, str, str, str, str | None]:
    token_response = await client.post(
        config.token_url,
        data={
            "grant_type": "authorization_code",
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "code": code,
            "redirect_uri": config.redirect_uri,
        },
    )
    if token_response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitLab token exchange failed",
        )

    try:
        token_payload = token_response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitLab token response was not JSON",
        ) from exc

    access_token = str(token_payload.get("access_token", "")).strip()
    refresh_token_value = token_payload.get("refresh_token")
    refresh_token = str(refresh_token_value).strip() if isinstance(refresh_token_value, str) else None
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing GitLab access token",
        )

    api_headers = {"Authorization": f"Bearer {access_token}"}
    user_response = await client.get(f"{config.api_base_url.rstrip('/')}/user", headers=api_headers)
    if user_response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to fetch GitLab user profile",
        )

    try:
        user_payload = user_response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitLab user response was not JSON",
        ) from exc

    provider_account_id = str(user_payload.get("id", "")).strip()
    provider_username = str(user_payload.get("username", "")).strip()
    provider_email = str(user_payload.get("email", "")).strip()
    if not provider_account_id or not provider_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid GitLab profile data",
        )
    return provider_account_id, provider_username, provider_email, access_token, refresh_token


async def _list_github_repositories_for_account(
    *,
    client: httpx.AsyncClient,
    config: ProviderOAuthConfig,
    account,
) -> list[dict]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {account.access_token}",
    }
    repositories: list[dict] = []
    page = 1
    per_page = 100
    while True:
        response = await client.get(
            f"{config.api_base_url.rstrip('/')}/user/repos",
            headers=headers,
            params={
                "per_page": per_page,
                "page": page,
                "sort": "updated",
                "direction": "desc",
                "affiliation": "owner,collaborator,organization_member",
            },
        )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"GitHub repository listing failed for account {account.provider_username}",
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"GitHub repository response was not JSON for account {account.provider_username}",
            ) from exc

        if not isinstance(payload, list) or len(payload) == 0:
            break

        for item in payload:
            if not isinstance(item, dict):
                continue
            repositories.append(
                {
                    "provider_type": "github",
                    "provider_account_id": account.provider_account_id,
                    "provider_username": account.provider_username,
                    "repository_id": str(item.get("id", "")),
                    "name": str(item.get("name", "")),
                    "full_name": str(item.get("full_name", "")),
                    "is_private": bool(item.get("private")),
                    "default_branch": str(item.get("default_branch", "")),
                    "web_url": str(item.get("html_url", "")),
                    "updated_at": str(item.get("updated_at", "")),
                    "clone_url": str(item.get("clone_url", "")),
                    "ssh_url": str(item.get("ssh_url", "")),
                }
            )

        if len(payload) < per_page:
            break
        page += 1

    return repositories


async def _list_gitlab_repositories_for_account(
    *,
    client: httpx.AsyncClient,
    config: ProviderOAuthConfig,
    account,
) -> list[dict]:
    headers = {
        "Authorization": f"Bearer {account.access_token}",
    }
    repositories: list[dict] = []
    page = 1
    per_page = 100
    while True:
        response = await client.get(
            f"{config.api_base_url.rstrip('/')}/projects",
            headers=headers,
            params={
                "membership": "true",
                "per_page": per_page,
                "page": page,
                "order_by": "last_activity_at",
                "sort": "desc",
                "simple": "true",
            },
        )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"GitLab repository listing failed for account {account.provider_username}",
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"GitLab repository response was not JSON for account {account.provider_username}",
            ) from exc

        if not isinstance(payload, list) or len(payload) == 0:
            break

        for item in payload:
            if not isinstance(item, dict):
                continue
            visibility = str(item.get("visibility", "")).lower()
            repositories.append(
                {
                    "provider_type": "gitlab",
                    "provider_account_id": account.provider_account_id,
                    "provider_username": account.provider_username,
                    "repository_id": str(item.get("id", "")),
                    "name": str(item.get("name", "")),
                    "full_name": str(item.get("path_with_namespace", "")),
                    "is_private": visibility != "public",
                    "default_branch": str(item.get("default_branch", "")),
                    "web_url": str(item.get("web_url", "")),
                    "updated_at": str(item.get("last_activity_at", "")),
                    "clone_url": str(item.get("http_url_to_repo", "")),
                    "ssh_url": str(item.get("ssh_url_to_repo", "")),
                }
            )

        if len(payload) < per_page:
            break
        page += 1

    return repositories


async def _list_github_branches_for_account(
    *,
    client: httpx.AsyncClient,
    config: ProviderOAuthConfig,
    account,
    repository_full_name: str,
) -> tuple[str, list[dict]]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {account.access_token}",
    }

    repo_response = await client.get(
        f"{config.api_base_url.rstrip('/')}/repos/{repository_full_name}",
        headers=headers,
    )
    if repo_response.status_code in {401, 403, 404}:
        raise HTTPException(
            status_code=repo_response.status_code,
            detail="Repository not accessible with this GitHub account",
        )
    if repo_response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub repository lookup failed for account {account.provider_username}",
        )
    try:
        repo_payload = repo_response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub repository payload was not JSON for account {account.provider_username}",
        ) from exc
    default_branch = str(repo_payload.get("default_branch", "")).strip() if isinstance(repo_payload, dict) else ""

    branches: list[dict] = []
    page = 1
    per_page = 100
    while True:
        response = await client.get(
            f"{config.api_base_url.rstrip('/')}/repos/{repository_full_name}/branches",
            headers=headers,
            params={"per_page": per_page, "page": page},
        )
        if response.status_code in {401, 403, 404}:
            raise HTTPException(
                status_code=response.status_code,
                detail="Repository branches not accessible with this GitHub account",
            )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"GitHub branch listing failed for account {account.provider_username}",
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"GitHub branch response was not JSON for account {account.provider_username}",
            ) from exc

        if not isinstance(payload, list) or len(payload) == 0:
            break

        for item in payload:
            if not isinstance(item, dict):
                continue
            branch_name = str(item.get("name", "")).strip()
            if not branch_name:
                continue
            branches.append(
                {
                    "name": branch_name,
                    "is_default": branch_name == default_branch,
                    "protected": bool(item.get("protected", False)),
                }
            )

        if len(payload) < per_page:
            break
        page += 1

    return default_branch, branches


async def _list_gitlab_branches_for_account(
    *,
    client: httpx.AsyncClient,
    config: ProviderOAuthConfig,
    account,
    repository_full_name: str,
) -> tuple[str, list[dict]]:
    headers = {"Authorization": f"Bearer {account.access_token}"}
    encoded_repository = quote(repository_full_name, safe="")

    repo_response = await client.get(
        f"{config.api_base_url.rstrip('/')}/projects/{encoded_repository}",
        headers=headers,
    )
    if repo_response.status_code in {401, 403, 404}:
        raise HTTPException(
            status_code=repo_response.status_code,
            detail="Repository not accessible with this GitLab account",
        )
    if repo_response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitLab repository lookup failed for account {account.provider_username}",
        )
    try:
        repo_payload = repo_response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitLab repository payload was not JSON for account {account.provider_username}",
        ) from exc
    default_branch = str(repo_payload.get("default_branch", "")).strip() if isinstance(repo_payload, dict) else ""

    branches: list[dict] = []
    page = 1
    per_page = 100
    while True:
        response = await client.get(
            f"{config.api_base_url.rstrip('/')}/projects/{encoded_repository}/repository/branches",
            headers=headers,
            params={"per_page": per_page, "page": page},
        )
        if response.status_code in {401, 403, 404}:
            raise HTTPException(
                status_code=response.status_code,
                detail="Repository branches not accessible with this GitLab account",
            )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"GitLab branch listing failed for account {account.provider_username}",
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"GitLab branch response was not JSON for account {account.provider_username}",
            ) from exc

        if not isinstance(payload, list) or len(payload) == 0:
            break

        for item in payload:
            if not isinstance(item, dict):
                continue
            branch_name = str(item.get("name", "")).strip()
            if not branch_name:
                continue
            is_default = bool(item.get("default", False)) or branch_name == default_branch
            branches.append(
                {
                    "name": branch_name,
                    "is_default": is_default,
                    "protected": bool(item.get("protected", False)),
                }
            )

        if len(payload) < per_page:
            break
        page += 1

    return default_branch, branches


def _dedupe_repositories(items: list[dict]) -> list[dict]:
    seen: set[str] = set()
    deduped: list[dict] = []
    for item in items:
        provider_type = str(item.get("provider_type", "")).strip()
        repository_id = str(item.get("repository_id", "")).strip()
        full_name = str(item.get("full_name", "")).strip()
        key = f"{provider_type}:{repository_id}:{full_name}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


@router.get("/{provider}/connect-url")
def provider_connect_url(
    provider: str = Path(..., description="Provider name: github|gitlab"),
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> dict:
    normalized_provider = _validate_provider(provider)
    settings = get_settings()
    config = _provider_config(normalized_provider, settings)
    _ensure_oauth_config(config)

    state = _build_provider_state(
        user_id=current_user.user_id,
        provider=normalized_provider,
        secret=config.state_secret,
    )
    query = urlencode(
        {
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "response_type": "code",
            "scope": config.scope,
            "state": state,
        }
    )
    auth_url = f"{config.authorize_url}?{query}"
    return {"provider": normalized_provider, "connect_url": auth_url}


@router.get("/{provider}/callback")
async def provider_callback(
    provider: str = Path(..., description="Provider name: github|gitlab"),
    code: str | None = Query(default=None),
    state_value: str | None = Query(default=None, alias="state"),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
):
    normalized_provider = _validate_provider(provider)
    settings = get_settings()
    config = _provider_config(normalized_provider, settings)
    _ensure_oauth_config(config)

    if error:
        message = error_description or error
        return _error_redirect(config, message)

    if not code or not state_value:
        return _error_redirect(config, "Missing code or state")

    try:
        state_claims = _parse_provider_state(
            state_value,
            provider=normalized_provider,
            secret=config.state_secret,
        )
    except HTTPException as exc:
        return _error_redirect(config, str(exc.detail))

    user_id = state_claims["user_id"]
    timeout = httpx.Timeout(20.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            if normalized_provider == "github":
                provider_account_id, provider_username, provider_email, access_token, refresh_token = await _fetch_github_identity(
                    client=client,
                    config=config,
                    code=code,
                )
            else:
                provider_account_id, provider_username, provider_email, access_token, refresh_token = await _fetch_gitlab_identity(
                    client=client,
                    config=config,
                    code=code,
                )
        except HTTPException as exc:
            return _error_redirect(config, str(exc.detail))

    try:
        user_client.upsert_provider_account(
            user_id=user_id,
            provider_type=normalized_provider,
            provider_account_id=provider_account_id,
            provider_username=provider_username,
            provider_email=provider_email,
            access_token=access_token,
            refresh_token=refresh_token,
            timeout=8.0,
        )
    except grpc.RpcError as exc:
        return _error_redirect(config, exc.details() or "Failed to save provider account")

    redirect_url = _with_query(
        config.success_redirect_url,
        provider=normalized_provider,
        username=provider_username,
    )
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)


@router.get("/{provider}/accounts")
def list_provider_accounts(
    provider: str = Path(..., description="Provider name: github|gitlab"),
    user_id: str | None = Query(default=None, description="ADMIN only: list provider accounts for this user_id"),
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> list[dict]:
    normalized_provider = _validate_provider(provider)
    effective_user_id = resolve_effective_user_id(current_user, user_id)
    try:
        response = user_client.list_provider_accounts(user_id=effective_user_id, timeout=5.0)
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)

    results: list[dict] = []
    for account in response.accounts:
        if account.provider_type != normalized_provider:
            continue
        results.append(
            {
                "id": account.id,
                "user_id": account.user_id,
                "provider_type": account.provider_type,
                "provider_account_id": account.provider_account_id,
                "provider_username": account.provider_username,
                "provider_email": account.provider_email,
                "status": account.status,
                "connected_at": account.connected_at,
                "updated_at": account.updated_at,
            }
        )
    return results


@router.get("/accounts")
def list_all_provider_accounts(
    user_id: str | None = Query(default=None, description="ADMIN only: list all provider accounts for this user_id"),
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> list[dict]:
    effective_user_id = resolve_effective_user_id(current_user, user_id)
    try:
        response = user_client.list_provider_accounts(user_id=effective_user_id, timeout=5.0)
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)

    return [
        {
            "id": account.id,
            "user_id": account.user_id,
            "provider_type": account.provider_type,
            "provider_account_id": account.provider_account_id,
            "provider_username": account.provider_username,
            "provider_email": account.provider_email,
            "status": account.status,
            "connected_at": account.connected_at,
            "updated_at": account.updated_at,
        }
        for account in response.accounts
    ]


@router.get("/{provider}/repositories")
async def list_provider_repositories(
    provider: str = Path(..., description="Provider name: github|gitlab"),
    user_id: str | None = Query(default=None, description="ADMIN only: list repositories for this user_id"),
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> list[dict]:
    normalized_provider = _validate_provider(provider)
    effective_user_id = resolve_effective_user_id(current_user, user_id)
    settings = get_settings()
    config = _provider_config(normalized_provider, settings)

    try:
        auth_accounts_response = user_client.list_provider_auth_accounts(
            user_id=effective_user_id,
            provider_type=normalized_provider,
            timeout=5.0,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)

    accounts = [
        account
        for account in auth_accounts_response.accounts
        if isinstance(account.access_token, str) and account.access_token.strip()
    ]
    if len(accounts) == 0:
        return []

    timeout = httpx.Timeout(30.0, connect=10.0)
    repositories: list[dict] = []
    async with httpx.AsyncClient(timeout=timeout) as client:
        for account in accounts:
            if normalized_provider == "github":
                account_repositories = await _list_github_repositories_for_account(
                    client=client,
                    config=config,
                    account=account,
                )
            else:
                account_repositories = await _list_gitlab_repositories_for_account(
                    client=client,
                    config=config,
                    account=account,
                )
            repositories.extend(account_repositories)

    return _dedupe_repositories(repositories)


@router.get("/{provider}/repositories/branches")
async def list_provider_repository_branches(
    provider: str = Path(..., description="Provider name: github|gitlab"),
    full_name: str = Query(..., description="Repository full name, e.g. owner/repo"),
    user_id: str | None = Query(default=None, description="ADMIN only: list branches for this user_id"),
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> dict:
    normalized_provider = _validate_provider(provider)
    effective_user_id = resolve_effective_user_id(current_user, user_id)
    repository_full_name = full_name.strip()
    if not repository_full_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="full_name is required",
        )

    settings = get_settings()
    config = _provider_config(normalized_provider, settings)

    try:
        auth_accounts_response = user_client.list_provider_auth_accounts(
            user_id=effective_user_id,
            provider_type=normalized_provider,
            timeout=5.0,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)

    accounts = [
        account
        for account in auth_accounts_response.accounts
        if isinstance(account.access_token, str) and account.access_token.strip()
    ]
    if len(accounts) == 0:
        return {
            "provider": normalized_provider,
            "full_name": repository_full_name,
            "default_branch": "",
            "branches": [],
        }

    timeout = httpx.Timeout(30.0, connect=10.0)
    default_branch = ""
    branches: list[dict] = []
    last_access_error = ""
    async with httpx.AsyncClient(timeout=timeout) as client:
        for account in accounts:
            try:
                if normalized_provider == "github":
                    account_default, account_branches = await _list_github_branches_for_account(
                        client=client,
                        config=config,
                        account=account,
                        repository_full_name=repository_full_name,
                    )
                else:
                    account_default, account_branches = await _list_gitlab_branches_for_account(
                        client=client,
                        config=config,
                        account=account,
                        repository_full_name=repository_full_name,
                    )
            except HTTPException as exc:
                if exc.status_code in {401, 403, 404}:
                    last_access_error = str(exc.detail)
                    continue
                raise

            default_branch = account_default
            branches = account_branches
            break

    if len(branches) == 0 and not default_branch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=last_access_error or "Repository not found or not accessible",
        )

    deduped_branches_map: dict[str, dict] = {}
    for branch in branches:
        branch_name = str(branch.get("name", "")).strip()
        if not branch_name:
            continue
        existing = deduped_branches_map.get(branch_name)
        if existing is None:
            deduped_branches_map[branch_name] = {
                "name": branch_name,
                "is_default": bool(branch.get("is_default", False)),
                "protected": bool(branch.get("protected", False)),
            }
            continue
        existing["is_default"] = bool(existing["is_default"]) or bool(branch.get("is_default", False))
        existing["protected"] = bool(existing["protected"]) or bool(branch.get("protected", False))

    deduped_branches = list(deduped_branches_map.values())
    deduped_branches.sort(
        key=lambda item: (
            0 if bool(item.get("is_default", False)) else 1,
            str(item.get("name", "")).lower(),
        )
    )

    if not default_branch and len(deduped_branches) > 0:
        default_branch = str(deduped_branches[0].get("name", "")).strip()

    return {
        "provider": normalized_provider,
        "full_name": repository_full_name,
        "default_branch": default_branch,
        "branches": deduped_branches,
    }