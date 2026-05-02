from __future__ import annotations

import importlib
import logging
import os
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import grpc

from build_models import BuildTask, CustomBuildConfig, StagedBuildInput
from build_support import (
    BUILDER_WORK_ROOT,
    BuildPolicyBlockedError,
    DEFAULT_GO_BUILDER_IMAGE,
    DEFAULT_RUNTIME_BASE_IMAGE,
    DOCKER_BIN,
    build_image_with_retry,
    build_immutable_image_tag,
    clone_source_repo,
    create_tarball,
    digest_suffix,
    docker_login,
    download_file,
    extract_archive_member,
    extract_tag,
    filename_from_url,
    generate_sbom,
    inspect_repo_digest,
    is_distroless_image,
    normalized_hex,
    push_image_with_retries,
    require_private_registry,
    require_command,
    run_checked,
    sanitize_repo_component,
    scan_image,
    sha256_file,
    strip_or_none,
    verify_cosign_blob,
    verify_gpg_signature,
)

log = logging.getLogger(__name__)

GO_SERVER_ADDR = os.getenv("GO_SERVER_ADDR", "go-server:50051")


def process(task: BuildTask) -> None:
    """Entry point called by the queue consumer."""
    tool_pb2, tool_pb2_grpc = _load_tool_proto()
    channel = grpc.insecure_channel(GO_SERVER_ADDR)
    stub = tool_pb2_grpc.ToolServiceStub(channel)

    stub.UpdateBuildJobStatus(tool_pb2.UpdateBuildJobStatusRequest(
        id=task.build_job_id,
        status=tool_pb2.RUNNING,
    ))

    try:
        if normalize_install_method(task.install_method) == "official_image":
            image_ref = mirror_official_image(task)
        else:
            image_ref = build_custom_image(task)

        stub.UpdateToolImageRef(tool_pb2.UpdateToolImageRefRequest(
            id=task.tool_id,
            image_ref=image_ref,
        ))
        stub.FinishBuildJob(tool_pb2.FinishBuildJobRequest(
            id=task.build_job_id,
            status=tool_pb2.SUCCEEDED,
            error="",
        ))
        log.info("Build succeeded for tool %s -> %s", task.tool_id, image_ref)
    except BuildPolicyBlockedError as exc:
        log.warning("Build blocked by policy for tool %s: %s", task.tool_id, exc)
        stub.FinishBuildJob(tool_pb2.FinishBuildJobRequest(
            id=task.build_job_id,
            status=tool_pb2.JOB_FAILED,
            error=str(exc),
        ))
    except Exception as exc:  # noqa: BLE001
        log.exception("Build failed for tool %s", task.tool_id)
        stub.FinishBuildJob(tool_pb2.FinishBuildJobRequest(
            id=task.build_job_id,
            status=tool_pb2.JOB_FAILED,
            error=str(exc),
        ))
    finally:
        channel.close()


def _load_tool_proto():
    try:
        tool_pb2 = importlib.import_module("create_tool_pb2")
        tool_pb2_grpc = importlib.import_module("create_tool_pb2_grpc")
    except ModuleNotFoundError:
        try:
            tool_pb2 = importlib.import_module("proto.create_tool_pb2")
            tool_pb2_grpc = importlib.import_module("proto.create_tool_pb2_grpc")
        except ModuleNotFoundError:
            sys.path.insert(0, str(Path(__file__).parent))
            try:
                tool_pb2 = importlib.import_module("create_tool_pb2")
                tool_pb2_grpc = importlib.import_module("create_tool_pb2_grpc")
            except ModuleNotFoundError:
                tool_pb2 = importlib.import_module("proto.create_tool_pb2")
                tool_pb2_grpc = importlib.import_module("proto.create_tool_pb2_grpc")
    return tool_pb2, tool_pb2_grpc


def mirror_official_image(task: BuildTask) -> str:
    image = resolve_official_image_ref(task)
    normalized = image.strip().lower()
    if not normalized or "://" in normalized:
        raise RuntimeError("official images must be provided as registry image references")
    if not is_pinned_image_reference(normalized):
        raise RuntimeError("official images must be pinned to an immutable version tag or digest")

    require_command(DOCKER_BIN)
    log.info("Pulling official image: %s", image)
    run_checked([DOCKER_BIN, "pull", image], timeout=600)

    upstream_digest = inspect_repo_digest(image)
    if not upstream_digest:
        raise RuntimeError("official image digest could not be resolved")
    try:
        require_private_registry()
    except RuntimeError:
        return upstream_digest

    repository = resolve_repository(task, task.build_json)
    version = resolve_version(task.build_json, image)
    immutable_tag = build_immutable_image_tag(
        version=version,
        digest_source=digest_suffix(upstream_digest),
        tag_prefix=resolve_tool_tag_prefix(task),
    )
    target_tag = f"{repository}:{immutable_tag}"

    run_checked([DOCKER_BIN, "tag", image, target_tag], timeout=120)
    with tempfile.TemporaryDirectory(dir=BUILDER_WORK_ROOT) as tmp_dir:
        workspace = Path(tmp_dir)
        generate_sbom(target_tag, workspace)
        scan_image(target_tag, workspace, allow_critical_override=bool(task.build_json.get("allow_critical_cves", False)))
        return push_image_with_retries(target_tag, log)


def build_custom_image(task: BuildTask) -> str:
    require_command(DOCKER_BIN)
    BUILDER_WORK_ROOT.mkdir(parents=True, exist_ok=True)

    cfg = resolve_custom_build_config(task)
    with tempfile.TemporaryDirectory(dir=BUILDER_WORK_ROOT) as tmp_dir:
        workspace = Path(tmp_dir)
        staged = stage_custom_build_input(cfg, workspace)
        dockerfile_path = write_generated_dockerfile(task, cfg, staged, workspace)
        target_tag = build_target_tag(task, cfg, staged)
        build_image_with_retry(target_tag, dockerfile_path, workspace)
        generate_sbom(target_tag, workspace)
        scan_image(target_tag, workspace, allow_critical_override=cfg.allow_critical_cves)
        return push_image_with_retries(target_tag, log)


def resolve_custom_build_config(task: BuildTask) -> CustomBuildConfig:
    build_cfg = task.build_json or {}
    source_url = (task.image_source or build_cfg.get("source_url", "")).strip()
    if not source_url:
        raise RuntimeError("custom builds require image_source or build_json.source_url")

    parsed = urlparse(source_url)
    if parsed.scheme != "https":
        raise RuntimeError("custom sources must use HTTPS")

    if build_cfg.get("dockerfile") or build_cfg.get("build_args"):
        raise RuntimeError("raw Dockerfile and build-arg inputs are blocked in the secure build pipeline")

    strategy = resolve_build_strategy(build_cfg.get("build_strategy"), source_url)
    version = resolve_version(build_cfg, source_url)
    binary_name = resolve_binary_name(build_cfg, source_url)
    repository = resolve_repository(task, build_cfg)
    artifact_sha256 = normalized_hex(build_cfg.get("artifact_sha256"))
    source_commit = (build_cfg.get("source_commit") or build_cfg.get("commit_sha") or build_cfg.get("git_ref") or "").strip() or None
    archive_member = (build_cfg.get("archive_member") or build_cfg.get("binary_path") or "").strip() or None
    source_subdir = (build_cfg.get("source_subdir") or ".").strip() or "."
    go_build_package = (build_cfg.get("go_build_package") or build_cfg.get("build_package") or ".").strip() or "."
    gpg_signature_url = strip_or_none(build_cfg.get("gpg_signature_url") or build_cfg.get("signature_url"))
    gpg_public_key_url = strip_or_none(build_cfg.get("gpg_public_key_url") or build_cfg.get("public_key_url"))
    cosign_signature_url = strip_or_none(build_cfg.get("cosign_signature_url"))
    cosign_public_key_url = strip_or_none(build_cfg.get("cosign_public_key_url"))
    command_alias = sanitize_command_alias(build_cfg.get("command_alias") or build_cfg.get("wrapper_command") or build_cfg.get("tool_command"))
    command_alias_args = normalize_command_alias_args(
        build_cfg.get("command_alias_args")
        or build_cfg.get("wrapper_args")
        or build_cfg.get("tool_command_args")
    )
    runtime_base_image = (build_cfg.get("runtime_base_image") or DEFAULT_RUNTIME_BASE_IMAGE).strip() or DEFAULT_RUNTIME_BASE_IMAGE

    validate_signature_pair("gpg_signature_url", gpg_signature_url, "gpg_public_key_url", gpg_public_key_url)
    validate_signature_pair("cosign_signature_url", cosign_signature_url, "cosign_public_key_url", cosign_public_key_url)
    if command_alias_args and not command_alias:
        raise RuntimeError("command_alias_args require command_alias or wrapper_command")
    if command_alias and is_distroless_image(runtime_base_image):
        raise RuntimeError("command_alias requires a shell-capable runtime image; distroless bases are not supported")

    if strategy in {"download_binary", "download_archive"} and not artifact_sha256:
        log.warning("Custom build for %s has no artifact_sha256; continuing with HTTPS source and runtime scanning only", task.tool_id)
    if strategy == "go_build" and not source_commit:
        log.warning("Custom build for %s has no source_commit pin; builder will use the source repository default branch HEAD", task.tool_id)
    if not has_signature_material(gpg_signature_url, gpg_public_key_url, cosign_signature_url, cosign_public_key_url):
        log.warning("Custom build for %s has no GPG/cosign verification metadata; continuing in unverified-source mode", task.tool_id)

    return CustomBuildConfig(
        strategy=strategy,
        source_url=source_url,
        version=version,
        repository=repository,
        binary_name=binary_name,
        runtime_base_image=runtime_base_image,
        go_builder_image=(build_cfg.get("go_builder_image") or DEFAULT_GO_BUILDER_IMAGE).strip() or DEFAULT_GO_BUILDER_IMAGE,
        artifact_sha256=artifact_sha256,
        source_commit=source_commit,
        archive_member=archive_member,
        source_subdir=source_subdir,
        go_build_package=go_build_package,
        gpg_signature_url=gpg_signature_url,
        gpg_public_key_url=gpg_public_key_url,
        cosign_signature_url=cosign_signature_url,
        cosign_public_key_url=cosign_public_key_url,
        command_alias=command_alias,
        command_alias_args=command_alias_args,
        allow_critical_cves=bool(build_cfg.get("allow_critical_cves", False)),
    )


def stage_custom_build_input(cfg: CustomBuildConfig, workspace: Path) -> StagedBuildInput:
    downloads_dir = workspace / "downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)

    if cfg.strategy == "download_binary":
        artifact_path = downloads_dir / cfg.binary_name
        download_file(cfg.source_url, artifact_path)
        verify_downloaded_material(artifact_path, cfg, downloads_dir)
        payload_dir = workspace / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)
        runtime_binary = payload_dir / cfg.binary_name
        runtime_binary.write_bytes(artifact_path.read_bytes())
        runtime_binary.chmod(0o755)
        return StagedBuildInput(
            strategy=cfg.strategy,
            binary_name=cfg.binary_name,
            material_sha256=sha256_file(runtime_binary),
            context_subdir="payload",
            go_build_package=cfg.go_build_package,
            source_subdir=cfg.source_subdir,
        )

    if cfg.strategy == "download_archive":
        archive_path = downloads_dir / filename_from_url(cfg.source_url, default_name="artifact.tgz")
        download_file(cfg.source_url, archive_path)
        verify_downloaded_material(archive_path, cfg, downloads_dir)
        payload_dir = workspace / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)
        runtime_binary = payload_dir / cfg.binary_name
        extract_archive_member(archive_path, runtime_binary, cfg.archive_member, cfg.binary_name)
        runtime_binary.chmod(0o755)
        return StagedBuildInput(
            strategy=cfg.strategy,
            binary_name=cfg.binary_name,
            material_sha256=sha256_file(runtime_binary),
            context_subdir="payload",
            go_build_package=cfg.go_build_package,
            source_subdir=cfg.source_subdir,
        )

    if cfg.strategy == "go_build":
        source_dir = workspace / "source"
        resolved_commit = clone_source_repo(cfg.source_url, cfg.source_commit or "", source_dir)
        verify_source_signature_if_present(cfg, source_dir, downloads_dir)
        return StagedBuildInput(
            strategy=cfg.strategy,
            binary_name=cfg.binary_name,
            material_sha256=resolved_commit,
            context_subdir="source",
            go_build_package=cfg.go_build_package,
            source_subdir=cfg.source_subdir,
        )

    raise RuntimeError(f"unsupported custom build strategy: {cfg.strategy}")


def write_generated_dockerfile(task: BuildTask, cfg: CustomBuildConfig, staged: StagedBuildInput, workspace: Path) -> Path:
    dockerfile_path = workspace / "Dockerfile.generated"
    if cfg.command_alias:
        write_command_alias_wrapper(workspace, cfg, staged)
    if staged.strategy == "go_build":
        dockerfile = render_go_build_dockerfile(cfg, staged)
    else:
        dockerfile = render_binary_runtime_dockerfile(cfg, staged)
    dockerfile_path.write_text(dockerfile, encoding="utf-8")
    log.info("Generated secure Dockerfile for tool %s at %s", task.tool_id, dockerfile_path)
    return dockerfile_path


def render_binary_runtime_dockerfile(cfg: CustomBuildConfig, staged: StagedBuildInput) -> str:
    if is_distroless_image(cfg.runtime_base_image):
        return "\n".join([
            "FROM alpine:3.20 AS prepared",
            "WORKDIR /workspace",
            f"COPY {staged.context_subdir}/{staged.binary_name} /out/{staged.binary_name}",
            f"RUN chmod 0755 /out/{staged.binary_name}",
            f"FROM {cfg.runtime_base_image}",
            "WORKDIR /app",
            f"COPY --from=prepared /out/{staged.binary_name} /usr/local/bin/{staged.binary_name}",
            "USER 65532:65532",
            f'ENTRYPOINT ["/usr/local/bin/{staged.binary_name}"]',
            "",
        ])

    return "\n".join([
        "FROM alpine:3.20 AS prepared",
        "WORKDIR /workspace",
        f"COPY {staged.context_subdir}/{staged.binary_name} /out/{staged.binary_name}",
        f"RUN chmod 0755 /out/{staged.binary_name}",
        f"FROM {cfg.runtime_base_image}",
        "RUN addgroup -S app && adduser -S -u 1000 -G app app",
        "WORKDIR /app",
        f"COPY --from=prepared /out/{staged.binary_name} /usr/local/bin/{staged.binary_name}",
        *render_command_alias_copy_lines(cfg),
        "USER 1000:1000",
        f'ENTRYPOINT ["/usr/local/bin/{cfg.command_alias or staged.binary_name}"]',
        "",
    ])


def render_go_build_dockerfile(cfg: CustomBuildConfig, staged: StagedBuildInput) -> str:
    source_copy = staged.context_subdir
    build_dir = cfg.source_subdir if cfg.source_subdir not in {"", "."} else "."
    if is_distroless_image(cfg.runtime_base_image):
        runtime_lines = [
            f"FROM {cfg.runtime_base_image}",
            "WORKDIR /app",
            f"COPY --from=builder /out/{staged.binary_name} /usr/local/bin/{staged.binary_name}",
            "USER 65532:65532",
            f'ENTRYPOINT ["/usr/local/bin/{staged.binary_name}"]',
        ]
    else:
        runtime_lines = [
            f"FROM {cfg.runtime_base_image}",
            "RUN addgroup -S app && adduser -S -u 1000 -G app app",
            "WORKDIR /app",
            f"COPY --from=builder /out/{staged.binary_name} /usr/local/bin/{staged.binary_name}",
            *render_command_alias_copy_lines(cfg),
            "USER 1000:1000",
            f'ENTRYPOINT ["/usr/local/bin/{cfg.command_alias or staged.binary_name}"]',
        ]
    return "\n".join([
        f"FROM {cfg.go_builder_image} AS builder",
        "WORKDIR /src",
        f"COPY {source_copy}/ /src/",
        f"WORKDIR /src/{build_dir}",
        f"RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/{staged.binary_name} {cfg.go_build_package}",
        *runtime_lines,
        "",
    ])


def build_target_tag(task: BuildTask, cfg: CustomBuildConfig, staged: StagedBuildInput) -> str:
    immutable_tag = build_immutable_image_tag(
        version=cfg.version,
        digest_source=staged.material_sha256,
        tag_prefix=resolve_tool_tag_prefix(task),
    )
    return f"{cfg.repository}:{immutable_tag}"


def verify_downloaded_material(path: Path, cfg: CustomBuildConfig, downloads_dir: Path) -> None:
    if cfg.artifact_sha256:
        actual = sha256_file(path)
        if actual.lower() != cfg.artifact_sha256.lower():
            raise RuntimeError(f"sha256 mismatch for {path.name}: expected {cfg.artifact_sha256}, got {actual}")
    else:
        log.warning("Skipping sha256 verification for %s because artifact_sha256 was not provided", path.name)

    verified = False
    if cfg.gpg_signature_url and cfg.gpg_public_key_url:
        signature_path = downloads_dir / filename_from_url(cfg.gpg_signature_url, default_name=f"{path.name}.asc")
        public_key_path = downloads_dir / filename_from_url(cfg.gpg_public_key_url, default_name="signing-key.asc")
        download_file(cfg.gpg_signature_url, signature_path)
        download_file(cfg.gpg_public_key_url, public_key_path)
        verify_gpg_signature(path, signature_path, public_key_path)
        verified = True
    if cfg.cosign_signature_url and cfg.cosign_public_key_url:
        signature_path = downloads_dir / filename_from_url(cfg.cosign_signature_url, default_name=f"{path.name}.sig")
        public_key_path = downloads_dir / filename_from_url(cfg.cosign_public_key_url, default_name="cosign.pub")
        download_file(cfg.cosign_signature_url, signature_path)
        download_file(cfg.cosign_public_key_url, public_key_path)
        verify_cosign_blob(path, signature_path, public_key_path)
        verified = True
    if not verified:
        log.warning("Skipping signature verification for %s because no GPG/cosign verification metadata was provided", path.name)


def verify_source_signature_if_present(cfg: CustomBuildConfig, source_dir: Path, downloads_dir: Path) -> None:
    verified = False
    if cfg.gpg_signature_url and cfg.gpg_public_key_url:
        source_archive = downloads_dir / "source.tar.gz"
        create_tarball(source_dir, source_archive)
        signature_path = downloads_dir / filename_from_url(cfg.gpg_signature_url, default_name="source.tar.gz.asc")
        public_key_path = downloads_dir / filename_from_url(cfg.gpg_public_key_url, default_name="signing-key.asc")
        download_file(cfg.gpg_signature_url, signature_path)
        download_file(cfg.gpg_public_key_url, public_key_path)
        verify_gpg_signature(source_archive, signature_path, public_key_path)
        verified = True
    if cfg.cosign_signature_url and cfg.cosign_public_key_url:
        source_archive = downloads_dir / "source.tar.gz"
        create_tarball(source_dir, source_archive)
        signature_path = downloads_dir / filename_from_url(cfg.cosign_signature_url, default_name="source.tar.gz.sig")
        public_key_path = downloads_dir / filename_from_url(cfg.cosign_public_key_url, default_name="cosign.pub")
        download_file(cfg.cosign_signature_url, signature_path)
        download_file(cfg.cosign_public_key_url, public_key_path)
        verify_cosign_blob(source_archive, signature_path, public_key_path)
        verified = True
    if not verified:
        log.warning("Skipping source signature verification for %s because no GPG/cosign verification metadata was provided", cfg.source_url)


def resolve_repository(task: BuildTask, build_cfg: dict[str, Any]) -> str:
    explicit = (build_cfg.get("repository") or build_cfg.get("registry_repository") or "").strip()
    if explicit:
        return explicit.rstrip("/")
    private_registry = require_private_registry()
    return f"{private_registry.rstrip('/')}/tools/{sanitize_repo_component(task.tool_id)}"


def resolve_tool_tag_prefix(task: BuildTask) -> str:
    build_cfg = task.build_json or {}
    explicit = str(build_cfg.get("tag_prefix") or "").strip()
    if explicit:
        return explicit
    tool_name = str(build_cfg.get("tool_name") or "").strip()
    if tool_name:
        return tool_name
    return task.tool_id


def resolve_version(build_cfg: dict[str, Any], source_hint: str) -> str:
    value = (build_cfg.get("version") or "").strip()
    if value:
        return value
    source_tag = extract_tag(source_hint)
    if source_tag:
        return source_tag
    raise RuntimeError("build version is required")


def resolve_binary_name(build_cfg: dict[str, Any], source_hint: str) -> str:
    value = (build_cfg.get("binary_name") or build_cfg.get("runtime_binary") or build_cfg.get("entrypoint") or "").strip()
    if value:
        return Path(value).name
    candidate = filename_from_url(source_hint, default_name="")
    if candidate and "." not in candidate:
        return candidate
    raise RuntimeError("custom builds require binary_name, runtime_binary, or entrypoint")


def resolve_build_strategy(raw_value: Any, source_url: str) -> str:
    normalized = str(raw_value or "").strip().lower()
    if normalized in {"download_binary", "download_archive", "go_build"}:
        return normalized
    lowered = source_url.lower()
    if lowered.endswith(".git"):
        return "go_build"
    if lowered.endswith((".zip", ".tgz", ".tar.gz", ".tar.xz", ".tar.bz2")):
        return "download_archive"
    return "download_binary"


def sanitize_command_alias(value: Any) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    name = Path(raw).name.strip()
    if not name or name in {".", ".."} or "/" in name:
        raise RuntimeError("command_alias must be a simple executable name")
    return name


def normalize_command_alias_args(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RuntimeError("command_alias_args must be a list of strings")
    normalized: list[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, str):
            raise RuntimeError(f"command_alias_args[{idx}] must be a string")
        trimmed = item.strip()
        if not trimmed:
            raise RuntimeError(f"command_alias_args[{idx}] must not be empty")
        normalized.append(trimmed)
    return normalized


def write_command_alias_wrapper(workspace: Path, cfg: CustomBuildConfig, staged: StagedBuildInput) -> None:
    if not cfg.command_alias:
        return
    wrapper_dir = workspace / "runtime-wrapper"
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    wrapper_path = wrapper_dir / cfg.command_alias
    fixed_args = " ".join(shlex.quote(arg) for arg in cfg.command_alias_args)
    exec_parts = [f"/usr/local/bin/{staged.binary_name}"]
    if fixed_args:
        exec_parts.append(fixed_args)
    exec_parts.append('"$@"')
    wrapper_path.write_text(
        "#!/bin/sh\n"
        f"exec {' '.join(exec_parts)}\n",
        encoding="utf-8",
    )
    wrapper_path.chmod(0o755)


def render_command_alias_copy_lines(cfg: CustomBuildConfig) -> list[str]:
    if not cfg.command_alias:
        return []
    return [
        f"COPY runtime-wrapper/{cfg.command_alias} /usr/local/bin/{cfg.command_alias}",
        f"RUN chmod 0755 /usr/local/bin/{cfg.command_alias}",
    ]


def resolve_official_image_ref(task: BuildTask) -> str:
    candidates = [
        task.image_source,
        task.build_json.get("image_ref", ""),
        task.build_json.get("upstream_image_ref", ""),
    ]
    for candidate in candidates:
        normalized = (candidate or "").strip()
        if normalized and "://" not in normalized and "/" in normalized:
            return normalized
    raise RuntimeError("official image build tasks require a concrete upstream image reference")


def normalize_install_method(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized in {"docker", "official", "official_image", "registry", "image"}:
        return "official_image"
    if normalized in {"custom", "custom_build", "source", "binary"}:
        return "custom_build"
    return normalized


def is_pinned_image_reference(image_ref: str) -> bool:
    if "@sha256:" in image_ref:
        return True
    tag = extract_tag(image_ref)
    return bool(tag) and tag != "latest"


def has_signature_material(
    gpg_signature_url: str | None,
    gpg_public_key_url: str | None,
    cosign_signature_url: str | None,
    cosign_public_key_url: str | None,
) -> bool:
    return bool((gpg_signature_url and gpg_public_key_url) or (cosign_signature_url and cosign_public_key_url))


def validate_signature_pair(name_a: str, value_a: str | None, name_b: str, value_b: str | None) -> None:
    if bool(value_a) != bool(value_b):
        raise RuntimeError(f"{name_a} and {name_b} must be provided together")
