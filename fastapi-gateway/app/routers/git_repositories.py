from typing import Any
import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.dependencies.auth import CurrentUser
from app.dependencies.rbac import require_web_platform_user
from app.internal.grpc import user_client
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


@router.get("/github/repositories", response_model=list[Repository])
async def get_github_repositories(
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> list[Repository]:
    """Fetch user's GitHub repositories"""
    try:
        response = user_client.list_provider_repositories_gateway(
            user_id=current_user.user_id,
            provider="github",
            timeout=10.0,
        )
    except Exception as exc:
        raise_for_grpc_error(exc)

    try:
        import json
        repos_data = json.loads(response.json_payload) if response.json_payload else []
    except (ValueError, json.JSONDecodeError):
        repos_data = []

    repositories = []
    if isinstance(repos_data, list):
        for repo in repos_data:
            if isinstance(repo, dict):
                repositories.append(
                    Repository(
                        id=str(repo.get("id", "")),
                        name=repo.get("name", ""),
                        full_name=repo.get("full_name", ""),
                        url=repo.get("html_url", repo.get("url", "")),
                        is_private=bool(repo.get("private", False)),
                        default_branch=repo.get("default_branch", "main"),
                        description=repo.get("description"),
                    )
                )

    return repositories


@router.get("/gitlab/repositories", response_model=list[Repository])
async def get_gitlab_repositories(
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> list[Repository]:
    """Fetch user's GitLab repositories"""
    try:
        response = user_client.list_provider_repositories_gateway(
            user_id=current_user.user_id,
            provider="gitlab",
            timeout=10.0,
        )
    except Exception as exc:
        raise_for_grpc_error(exc)

    try:
        import json
        repos_data = json.loads(response.json_payload) if response.json_payload else []
    except (ValueError, json.JSONDecodeError):
        repos_data = []

    repositories = []
    if isinstance(repos_data, list):
        for repo in repos_data:
            if isinstance(repo, dict):
                repositories.append(
                    Repository(
                        id=str(repo.get("id", "")),
                        name=repo.get("name", ""),
                        full_name=repo.get("path_with_namespace", repo.get("full_name", "")),
                        url=repo.get("web_url", repo.get("url", "")),
                        is_private=repo.get("visibility", "private") != "public",
                        default_branch=repo.get("default_branch", "main"),
                        description=repo.get("description"),
                    )
                )

    return repositories


@router.get("/github/repositories/{owner}/{repo}/branches", response_model=list[Branch])
async def get_github_branches(
    owner: str,
    repo: str,
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> list[Branch]:
    """Fetch branches for a GitHub repository"""
    try:
        response = user_client.list_repository_branches_gateway(
            user_id=current_user.user_id,
            provider="github",
            repository=f"{owner}/{repo}",
            timeout=10.0,
        )
    except Exception as exc:
        raise_for_grpc_error(exc)

    try:
        import json
        branches_data = json.loads(response.json_payload) if response.json_payload else []
    except (ValueError, json.JSONDecodeError):
        branches_data = []

    branches = []
    if isinstance(branches_data, list):
        for branch in branches_data:
            if isinstance(branch, dict):
                branches.append(
                    Branch(
                        name=branch.get("name", ""),
                        is_default=bool(branch.get("protected", False)),
                    )
                )

    return branches


@router.get("/gitlab/repositories/{project_id}/branches", response_model=list[Branch])
async def get_gitlab_branches(
    project_id: str,
    current_user: CurrentUser = Depends(require_web_platform_user),
) -> list[Branch]:
    """Fetch branches for a GitLab repository"""
    try:
        response = user_client.list_repository_branches_gateway(
            user_id=current_user.user_id,
            provider="gitlab",
            repository=project_id,
            timeout=10.0,
        )
    except Exception as exc:
        raise_for_grpc_error(exc)

    try:
        import json
        branches_data = json.loads(response.json_payload) if response.json_payload else []
    except (ValueError, json.JSONDecodeError):
        branches_data = []

    branches = []
    if isinstance(branches_data, list):
        for branch in branches_data:
            if isinstance(branch, dict):
                branches.append(
                    Branch(
                        name=branch.get("name", ""),
                        is_default=bool(branch.get("default", False)),
                    )
                )

    return branches
