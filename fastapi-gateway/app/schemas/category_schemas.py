from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class CreateCategoryRequest(BaseModel):
    name: str = Field(..., min_length=1, description="Unique category name")
    description: Optional[str] = None


class UpdateCategoryRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class CategoryResponse(BaseModel):
    category_id: str
    name: str
    description: Optional[str] = None
    created_at: Optional[datetime] = None
    last_modified: Optional[datetime] = None


class ListCategoriesResponse(BaseModel):
    categories: List[CategoryResponse]
