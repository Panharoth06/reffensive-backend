from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class ProjectResponse(BaseModel):
    project_id: str
    name: str
    description: Optional[str] = None
    owner_id: str
    created_at: Optional[datetime] = None
    last_modified: Optional[datetime] = None


class CreateProjectRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)


class UpdateProjectRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)


class ListProjectsResponse(BaseModel):
    projects: List[ProjectResponse]
