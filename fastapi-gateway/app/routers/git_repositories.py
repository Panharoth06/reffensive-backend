import grpc
import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.config import get_settings
from app.dependencies.auth import CurrentUser
from app.dependencies.rbac import require_web_platform_user
from app.internal.grpc import user_client
from app.routers.integrations_git_account import (
    _dedupe_repositories,
    _list_github_branches_for_account,
    _list_github_repositories_for_account,
    _list_gitlab_branches_for_account,
    _list_gitlab_repositories_for_account,
    _provider_config,
)
from app.utils.grpc_errors import raise_for_grpc_error

router = APIRouter(prefix="/git", tags=["git"])


class Repository(BaseModel):
    id: str
    name: str
    full_name: str
    url: str
    is_private: bool
    default_branch: str
    description: str | None = None


class Branch(BaseModel):
    name: str
    is_default: bool


async def _load_provider_repositories(
    *,
    user_id: str,
    provider: str,
) -> list[dict]:
    settings = get_settings()
    config = _provider_config(provider, settings)

    try:
        auth_accounts_response = user_client.list_provider_auth_accounts(
            user_id=user_id,
            provider_type=provider,
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

    repositories: list[dict] = []
    timeout = httpx.Timeout(30.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        for account in accounts:
            if provider == "github":
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


async def _load_provider_branches(
    *,
    user_id: str,
    provider: str,
    repository_full_name: str,
) -> list[dict]:
    settings = get_settings()
    config = _provider_config(provider, settings)

    try:
        auth_accounts_response = user_client.list_provider_auth_accounts(
            user_id=user_id,
            provider_type=provider,
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

    branches: list[dict] = []
    last_access_error = ""
    timeout = httpx.Timeout(30.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        for account in accounts:
            try:
                if provider == "github":
                    _, account_branches = await _list_github_branches_for_account(
                        client=client,
                        config=config,
                        account=account,
                        repository_full_name=repository_full_name,
                    )
                else:
                    _, account_branches = await _list_gitlab_branches_for_account(
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

            branches = account_branches
            break

    if len(branches) == 0 and last_access_error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=last_access_error,
        )

    return branches


@router.get("/github/repositories", response_model=list[Repository])
async def get_github_repositories(
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> list[Repository]:
    repositories = await _load_provider_repositories(
        user_id=current_user.user_id,
        provider="github",
    )
    return [
        Repository(
            id=str(repo.get("repository_id", "")),
            name=str(repo.get("name", "")),
            full_name=str(repo.get("full_name", "")),
            url=str(repo.get("web_url", "")),
            is_private=bool(repo.get("is_private", False)),
            default_branch=str(repo.get("default_branch", "")),
            description=None,
        )
        for repo in repositories
    ]


@router.get("/gitlab/repositories", response_model=list[Repository])
async def get_gitlab_repositories(
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> list[Repository]:
    repositories = await _load_provider_repositories(
        user_id=current_user.user_id,
        provider="gitlab",
    )
    return [
        Repository(
            id=str(repo.get("repository_id", "")),
            name=str(repo.get("name", "")),
            full_name=str(repo.get("full_name", "")),
            url=str(repo.get("web_url", "")),
            is_private=bool(repo.get("is_private", False)),
            default_branch=str(repo.get("default_branch", "")),
            description=None,
        )
        for repo in repositories
    ]


@router.get("/github/repositories/{owner}/{repo}/branches", response_model=list[Branch])
async def get_github_branches(
    owner: str,
    repo: str,
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> list[Branch]:
    branches = await _load_provider_branches(
        user_id=current_user.user_id,
        provider="github",
        repository_full_name=f"{owner}/{repo}",
    )
    return [
        Branch(
            name=str(branch.get("name", "")),
            is_default=bool(branch.get("is_default", False)),
        )
        for branch in branches
    ]


@router.get("/gitlab/repositories/{project_id}/branches", response_model=list[Branch])
async def get_gitlab_branches(
    project_id: str,
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> list[Branch]:
    branches = await _load_provider_branches(
        user_id=current_user.user_id,
        provider="gitlab",
        repository_full_name=project_id,
    )
    return [
        Branch(
            name=str(branch.get("name", "")),
            is_default=bool(branch.get("is_default", False)),
        )
        for branch in branches
    ]
