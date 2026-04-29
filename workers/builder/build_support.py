from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from build_models import ImageSecurityMetadata

DOCKERHUB_USER = os.getenv("DOCKERHUB_USER", "").strip()
DOCKERHUB_TOKEN = os.getenv("DOCKERHUB_TOKEN", "").strip()
PRIVATE_REGISTRY = os.getenv("PRIVATE_REGISTRY", "").strip()
BUILDER_WORK_ROOT = Path(os.getenv("BUILDER_WORK_ROOT", "/tmp/builder-work"))
DEFAULT_RUNTIME_BASE_IMAGE = os.getenv("BUILDER_RUNTIME_BASE_IMAGE", "alpine:3.20").strip() or "alpine:3.20"
DEFAULT_GO_BUILDER_IMAGE = os.getenv("BUILDER_GO_IMAGE", "golang:1.24-alpine").strip() or "golang:1.24-alpine"
DOCKER_BIN = os.getenv("DOCKER_BIN", "docker").strip() or "docker"
GIT_BIN = os.getenv("GIT_BIN", "git").strip() or "git"
GPG_BIN = os.getenv("GPG_BIN", "gpg").strip() or "gpg"
COSIGN_BIN = os.getenv("COSIGN_BIN", "cosign").strip() or "cosign"
SYFT_BIN = os.getenv("SYFT_BIN", "syft").strip() or "syft"
TRIVY_BIN = os.getenv("TRIVY_BIN", "trivy").strip() or "trivy"

_SAFE_REPO_COMPONENT = re.compile(r"[^a-z0-9._-]+")
_SAFE_TAG_COMPONENT = re.compile(r"[^A-Za-z0-9._-]+")
_TOO_MANY_REQUESTS_MARKERS = ("toomanyrequests", "too many requests", "rate limit")


class BuildPolicyBlockedError(RuntimeError):
    """Raised when a build is intentionally blocked by policy rather than by an unexpected crash."""


def validate_registry_login_config(username: str, token: str) -> tuple[bool, str]:
    normalized_user = (username or "").strip()
    normalized_token = (token or "").strip()

    if not normalized_user and not normalized_token:
        return False, "DOCKERHUB_USER/DOCKERHUB_TOKEN not set, skipping docker login"
    if normalized_user and not normalized_token:
        return False, "DOCKERHUB_USER is set but DOCKERHUB_TOKEN is missing"
    if normalized_token and not normalized_user:
        return False, "DOCKERHUB_TOKEN is set but DOCKERHUB_USER is missing"
    return True, ""


def require_private_registry() -> str:
    if not PRIVATE_REGISTRY:
        raise RuntimeError("PRIVATE_REGISTRY must be configured before secure images can be pushed")
    return PRIVATE_REGISTRY


def docker_login(log) -> None:
    should_login, reason = validate_registry_login_config(DOCKERHUB_USER, DOCKERHUB_TOKEN)
    if not should_login:
        if "missing" in reason:
            raise RuntimeError(reason)
        log.warning(reason)
        return
    result = subprocess.run(
        [DOCKER_BIN, "login", "-u", DOCKERHUB_USER, "--password-stdin"],
        input=DOCKERHUB_TOKEN,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker login failed: {result.stderr.strip()}")
    log.info("Logged in to DockerHub as %s", DOCKERHUB_USER)


def require_command(binary: str) -> None:
    if shutil.which(binary) is None:
        raise RuntimeError(f"required command {binary!r} is not available")


def run_checked(args: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, timeout: int | None = None) -> str:
    result = subprocess.run(
        args,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({' '.join(args)}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


def inspect_repo_digest(image_ref: str) -> str:
    inspect = subprocess.run(
        [DOCKER_BIN, "inspect", "--format", "{{index .RepoDigests 0}}", image_ref],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    return inspect.stdout.strip()


def build_image_with_retry(target_tag: str, dockerfile_path: Path, context_dir: Path) -> None:
    build_cmd = [
        DOCKER_BIN,
        "build",
        "-t",
        target_tag,
        "-f",
        str(dockerfile_path),
        str(context_dir),
    ]
    first = subprocess.run(build_cmd, capture_output=True, text=True, timeout=1800, check=False)
    if first.returncode == 0:
        return

    retry_cmd = build_cmd[:1] + ["build", "--no-cache"] + build_cmd[2:]
    retry = subprocess.run(retry_cmd, capture_output=True, text=True, timeout=1800, check=False)
    if retry.returncode != 0:
        raise RuntimeError(
            "docker build failed after retry: "
            f"first={first.stderr.strip() or first.stdout.strip()} "
            f"retry={retry.stderr.strip() or retry.stdout.strip()}"
        )


def generate_sbom(image_ref: str, workspace: Path) -> Path:
    require_command(SYFT_BIN)
    sbom_path = workspace / "sbom.syft.json"
    run_checked([
        SYFT_BIN,
        image_ref,
        "-o",
        f"json={sbom_path}",
    ], timeout=900)
    return sbom_path


def scan_image(image_ref: str, workspace: Path, *, allow_critical_override: bool) -> ImageSecurityMetadata:
    require_command(TRIVY_BIN)
    scan_path = workspace / "trivy-report.json"
    run_checked([
        TRIVY_BIN,
        "image",
        "--quiet",
        "--format",
        "json",
        "--output",
        str(scan_path),
        image_ref,
    ], timeout=1800)
    blocking_count = count_blocking_vulnerabilities(scan_path)
    scan_status = "clean" if blocking_count == 0 else "blocked"
    if blocking_count > 0 and not allow_critical_override:
        raise BuildPolicyBlockedError(
            f"trivy blocked image push: found {blocking_count} HIGH/CRITICAL vulnerabilities"
        )
    if blocking_count > 0:
        scan_status = "warnings"
    return ImageSecurityMetadata(
        sbom_path=workspace / "sbom.syft.json",
        scan_path=scan_path,
        scan_status=scan_status,
    )


def count_blocking_vulnerabilities(scan_path: Path) -> int:
    if not scan_path.exists():
        return 0
    payload = json.loads(scan_path.read_text(encoding="utf-8"))
    count = 0
    for result in payload.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            if str(vuln.get("Severity", "")).upper() in {"HIGH", "CRITICAL"}:
                count += 1
    return count


def push_image_with_retries(target_tag: str, log) -> str:
    docker_login(log)
    backoff_seconds = 2
    for attempt in range(1, 4):
        push = subprocess.run([DOCKER_BIN, "push", target_tag], capture_output=True, text=True, timeout=1800, check=False)
        if push.returncode == 0:
            digest_ref = inspect_repo_digest(target_tag)
            return digest_ref or target_tag
        stderr = (push.stderr or "") + "\n" + (push.stdout or "")
        if attempt < 3 and any(marker in stderr.lower() for marker in _TOO_MANY_REQUESTS_MARKERS):
            time.sleep(backoff_seconds)
            backoff_seconds *= 2
            continue
        raise RuntimeError(f"docker push failed: {stderr.strip()}")
    raise RuntimeError("docker push failed after retry")


def verify_gpg_signature(artifact_path: Path, signature_path: Path, public_key_path: Path) -> None:
    require_command(GPG_BIN)
    gnupg_home = artifact_path.parent / ".gnupg"
    gnupg_home.mkdir(parents=True, exist_ok=True)
    os.chmod(gnupg_home, 0o700)
    env = os.environ.copy()
    env["GNUPGHOME"] = str(gnupg_home)
    run_checked([GPG_BIN, "--batch", "--import", str(public_key_path)], env=env, timeout=120)
    run_checked([GPG_BIN, "--batch", "--verify", str(signature_path), str(artifact_path)], env=env, timeout=120)


def verify_cosign_blob(artifact_path: Path, signature_path: Path, public_key_path: Path) -> None:
    require_command(COSIGN_BIN)
    run_checked([
        COSIGN_BIN,
        "verify-blob",
        "--key",
        str(public_key_path),
        "--signature",
        str(signature_path),
        str(artifact_path),
    ], timeout=120)


def clone_source_repo(source_url: str, source_commit: str, destination: Path) -> str:
    require_command(GIT_BIN)
    run_checked([GIT_BIN, "clone", source_url, str(destination)], timeout=1800)
    head = run_checked([GIT_BIN, "rev-parse", "HEAD"], cwd=destination, timeout=60).strip()
    if source_commit:
        run_checked([GIT_BIN, "checkout", source_commit], cwd=destination, timeout=300)
        head = run_checked([GIT_BIN, "rev-parse", "HEAD"], cwd=destination, timeout=60).strip()
    if source_commit and not head.startswith(source_commit):
        raise RuntimeError(f"source commit mismatch: expected {source_commit}, got {head}")
    return head


def extract_archive_member(archive_path: Path, output_binary: Path, archive_member: str | None, binary_name: str) -> None:
    output_binary.parent.mkdir(parents=True, exist_ok=True)

    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.namelist()
            member = pick_archive_member(members, archive_member, binary_name)
            with archive.open(member) as src, output_binary.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        return

    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path) as archive:
            members = [member.name for member in archive.getmembers() if member.isfile()]
            member_name = pick_archive_member(members, archive_member, binary_name)
            member = archive.getmember(member_name)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"failed to extract archive member {member_name}")
            with extracted, output_binary.open("wb") as dst:
                shutil.copyfileobj(extracted, dst)
        return

    raise RuntimeError(f"unsupported archive format: {archive_path}")


def pick_archive_member(members: list[str], requested_member: str | None, binary_name: str) -> str:
    if requested_member:
        requested_member = requested_member.strip()
        for member in members:
            if member == requested_member or member.endswith("/" + requested_member):
                return member
        raise RuntimeError(f"archive member {requested_member!r} was not found")

    for member in members:
        if member.endswith("/" + binary_name) or member == binary_name:
            return member
    raise RuntimeError(f"could not locate binary {binary_name!r} in archive; specify archive_member")


def download_file(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as response, destination.open("wb") as dst:  # noqa: S310
        shutil.copyfileobj(response, dst)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_tarball(source_dir: Path, archive_path: Path) -> None:
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(source_dir, arcname=".")


def build_immutable_image_tag(*, version: str, digest_source: str, tag_prefix: str | None = None) -> str:
    prefix_part = _SAFE_TAG_COMPONENT.sub("-", (tag_prefix or "").strip().lower()).strip("-")
    version_part = _SAFE_TAG_COMPONENT.sub("-", version.strip() or "v0")
    digest_part = _SAFE_TAG_COMPONENT.sub("", digest_source.strip().lower())[:12] or "unknown"
    date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
    if prefix_part:
        return f"{prefix_part}-{version_part}-{date_part}-sha256-{digest_part}"
    return f"{version_part}-{date_part}-sha256-{digest_part}"


def extract_tag(image_ref: str) -> str:
    ref = image_ref.split("@", 1)[0]
    last_slash = ref.rfind("/")
    last_colon = ref.rfind(":")
    if last_colon <= last_slash:
        return ""
    return ref[last_colon + 1:].strip().lower()


def filename_from_url(url: str, *, default_name: str) -> str:
    path = urlparse(url).path
    name = Path(path).name.strip()
    return name or default_name


def digest_suffix(value: str) -> str:
    if "@sha256:" in value:
        return value.split("@sha256:", 1)[1]
    return value


def strip_or_none(value: Any) -> str | None:
    normalized = str(value or "").strip()
    return normalized or None


def normalized_hex(value: Any) -> str | None:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return None
    if not all(ch in "0123456789abcdef" for ch in normalized):
        raise RuntimeError("artifact_sha256 must be a lowercase hexadecimal digest")
    if len(normalized) != 64:
        raise RuntimeError("artifact_sha256 must be a 64-character sha256 digest")
    return normalized


def sanitize_repo_component(value: str) -> str:
    normalized = _SAFE_REPO_COMPONENT.sub("-", value.strip().lower()).strip("-")
    return normalized or "tool"


def is_distroless_image(image_ref: str) -> bool:
    lowered = image_ref.lower()
    return "distroless" in lowered or "chainguard" in lowered
