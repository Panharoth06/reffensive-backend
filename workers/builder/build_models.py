from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass
class BuildTask:
    tool_id: str
    build_job_id: str
    install_method: str
    image_source: str
    build_json: dict


@dataclass
class CustomBuildConfig:
    strategy: str
    source_url: str
    version: str
    repository: str
    binary_name: str
    runtime_base_image: str
    go_builder_image: str
    artifact_sha256: str | None
    source_commit: str | None
    archive_member: str | None
    source_subdir: str
    go_build_package: str
    gpg_signature_url: str | None
    gpg_public_key_url: str | None
    cosign_signature_url: str | None
    cosign_public_key_url: str | None
    command_alias: str | None
    command_alias_args: Sequence[str]
    allow_critical_cves: bool


@dataclass
class StagedBuildInput:
    strategy: str
    binary_name: str
    material_sha256: str
    context_subdir: str
    go_build_package: str
    source_subdir: str


@dataclass
class ImageSecurityMetadata:
    sbom_path: Path
    scan_path: Path
    scan_status: str
