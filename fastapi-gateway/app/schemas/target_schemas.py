from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class TargetResponse(BaseModel):
    target_id: str
    project_id: str
    name: str
    type: str
    description: Optional[str] = None
    created_at: Optional[datetime] = None


class CreateTargetRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., min_length=1, max_length=64)
    description: Optional[str] = Field(None, max_length=1000)


class UpdateTargetRequest(BaseModel):
    description: Optional[str] = Field(None, max_length=1000)


class ListTargetsResponse(BaseModel):
    targets: List[TargetResponse]
