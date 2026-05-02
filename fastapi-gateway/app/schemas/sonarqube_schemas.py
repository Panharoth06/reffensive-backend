from typing import Literal

from pydantic import BaseModel, Field


class ProvisionSonarProjectRequest(BaseModel):
    project_key: str | None = Field(default=None, description="SonarQube project key")
    project_name: str | None = Field(default=None, description="SonarQube project display name")
    repository_full_name: str | None = Field(
        default=None,
        description="Fallback source for key/name (example: owner/repo)",
    )
    main_branch: str | None = Field(default=None, description="Main branch name")
    visibility: Literal["private", "public"] | None = Field(default="private")


class StartSonarAnalysisRequest(BaseModel):
    repository_url: str = Field(..., description="Repository URL pasted by user")
    branch: str | None = Field(default=None, description="Optional branch to scan")
    project_key: str | None = Field(default=None, description="Optional explicit SonarQube project key")
    project_name: str | None = Field(default=None, description="Optional explicit SonarQube project name")
    scan_dependency: bool = Field(
        default=False,
        description="When true, run dependency-focused scan mode (used in cache key separation)",
    )


class GenerateAnalysisReportRequest(BaseModel):
    job_id: str = Field(..., description="Sonar analysis job ID")
    file_name_prefix: str | None = Field(
        default=None,
        description="Optional report file prefix. Defaults to repository+job ID based name.",
    )
