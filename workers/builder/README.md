# Builder Worker

This worker handles the tool-image lifecycle for two onboarding modes:

- `official_image`: mirror an official upstream registry image into the private registry
- `custom_build`: fetch, optionally verify, build, scan, and push a custom tool image

It does not change the existing basic / medium / advanced scan flow semantics. It only prepares runnable images for those flows.

## Required Environment

The builder container expects these tools and env vars:

- `GO_SERVER_ADDR`
- `PRIVATE_REGISTRY`
- `DOCKERHUB_USER`
- `DOCKERHUB_TOKEN`
- `docker`
- `git`
- `gpg`
- `cosign`
- `syft`
- `trivy`

The worker image installs the command-line tools in [Dockerfile](/home/aintantony/11-11/researches/CyberSecurity/PROJECTS/ITP/official/auto-offensive-backend/workers/builder/Dockerfile).

## Official Image Contract

Use this when the tool already has an upstream container image.

`BuildTask`
- `install_method`: `official_image` or alias like `docker`
- `image_source`: full upstream image reference, for example `docker.io/projectdiscovery/httpx:v1.9.0`
- `build_json.image_ref` or `build_json.upstream_image_ref`: optional fallback upstream image reference

Rules:
- upstream image must be a real registry image reference
- it must be pinned by tag or digest
- if `PRIVATE_REGISTRY` is configured, the worker retags and pushes an immutable mirrored image

## Custom Build Contract

Use this when the tool must be built from an upstream binary, archive, or source repo.

`BuildTask`
- `install_method`: `custom_build`
- `image_source`: HTTPS source URL
- `build_json`: build metadata, plus optional verification metadata

Supported strategies:
- `download_binary`
- `download_archive`
- `go_build`

### Shared Required Fields

- `version`
- `repository` or `PRIVATE_REGISTRY`

Optional verification fields:
- `artifact_sha256`
- `gpg_signature_url` + `gpg_public_key_url`
- `cosign_signature_url` + `cosign_public_key_url`

If verification fields are provided, the builder enforces them.
If they are omitted, the builder continues in reduced-trust mode with HTTPS-only source fetching, SBOM generation, Trivy scanning, and immutable registry pushes still enforced.

When multiple tools share the same registry repository, the generated immutable tag is automatically prefixed with the tool name when available, for example `gitleaks-8.30.1-YYYYMMDD-sha256-...`.

### Strategy: `download_binary`

Required:
- `binary_name`

Optional:
- `artifact_sha256`
- `runtime_base_image`

### Strategy: `download_archive`

Required:
- `binary_name`

Optional:
- `artifact_sha256`
- `archive_member`
- `runtime_base_image`

### Strategy: `go_build`

Required:
- `binary_name`

Optional:
- `source_commit` or `git_ref`
- `source_subdir`
- `go_build_package`
- `go_builder_image`
- `runtime_base_image`
- `command_alias`
- `command_alias_args`

### Optional Command Alias Wrapper

For subcommand-oriented tools like `gobuster dir`, the secure builder can expose a
wrapper command inside the final image without changing scan-mode semantics.

Fields:
- `command_alias`: executable name to create in `/usr/local/bin`
- `command_alias_args`: fixed args prepended before runtime args

Example:
- binary built as `gobuster`
- wrapper command `gobuster-dir`
- fixed args `["dir"]`

This produces a runtime command equivalent to:

`gobuster dir "$@"`

Notes:
- requires a shell-capable runtime image such as Alpine
- not supported with distroless runtime bases

## Generated Build Flow

For `custom_build`, the worker:

1. Downloads or clones the source material.
2. Verifies checksum when provided.
3. Verifies GPG or cosign signature material when provided.
4. Generates a multi-stage Dockerfile.
5. Builds the image with one retry using `--no-cache`.
6. Generates an SBOM with `syft`.
7. Scans the image with `trivy`.
8. Pushes to the private registry with an immutable tag.

## Scan Policy

`trivy` is currently configured inline in the builder code, not via a standalone config file.

Current policy:
- HIGH and CRITICAL vulnerabilities block the push
- unless `build_json.allow_critical_cves` is `true`

## Examples

See:
- [examples/official_image_build.json](/home/aintantony/11-11/researches/CyberSecurity/PROJECTS/ITP/official/auto-offensive-backend/workers/builder/examples/official_image_build.json)
- [examples/custom_build_archive.json](/home/aintantony/11-11/researches/CyberSecurity/PROJECTS/ITP/official/auto-offensive-backend/workers/builder/examples/custom_build_archive.json)
- [examples/custom_build_go.json](/home/aintantony/11-11/researches/CyberSecurity/PROJECTS/ITP/official/auto-offensive-backend/workers/builder/examples/custom_build_go.json)
- [examples/custom_build_gobuster_dir.json](/home/aintantony/11-11/researches/CyberSecurity/PROJECTS/ITP/official/auto-offensive-backend/workers/builder/examples/custom_build_gobuster_dir.json)
