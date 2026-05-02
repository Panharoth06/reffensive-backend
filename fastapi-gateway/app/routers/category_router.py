from fastapi import APIRouter, Depends

from app.dependencies.auth import CurrentUser
from app.dependencies.rbac import require_web_admin
from app.internal.category_client import category_client
from app.schemas.category_schemas import (
    CategoryResponse,
    CreateCategoryRequest,
    ListCategoriesResponse,
    UpdateCategoryRequest,
)

router = APIRouter(prefix="/categories", tags=["Categories"])


@router.post("", response_model=CategoryResponse, status_code=201, summary="Create a category")
def create_category(
    body: CreateCategoryRequest,
    current_user: CurrentUser = Depends(require_web_admin),
) -> CategoryResponse:
    return category_client.create_category(body)


@router.get("", response_model=ListCategoriesResponse, summary="List all categories")
def list_categories() -> ListCategoriesResponse:
    return ListCategoriesResponse(categories=category_client.list_categories())


@router.get("/{category_id}", response_model=CategoryResponse, summary="Get a category by ID")
def get_category(category_id: str) -> CategoryResponse:
    return category_client.get_category(category_id)


@router.put("/{category_id}", response_model=CategoryResponse, summary="Update a category")
def update_category(
    category_id: str,
    body: UpdateCategoryRequest,
    current_user: CurrentUser = Depends(require_web_admin),
) -> CategoryResponse:
    return category_client.update_category(category_id, body)


@router.delete("/{category_id}", summary="Hard-delete a category")
def delete_category(
    category_id: str,
    current_user: CurrentUser = Depends(require_web_admin),
) -> dict:
    return category_client.delete_category(category_id)

