from __future__ import annotations

import tarfile
import tempfile
import unittest
import zipfile
import json
from pathlib import Path

from build_pipeline import render_go_build_dockerfile
from build_support import count_blocking_vulnerabilities, validate_registry_login_config
from builder import (
    BuildTask,
    _build_immutable_image_tag,
    _extract_archive_member,
    _normalize_install_method,
    _resolve_build_strategy,
    _resolve_custom_build_config,
)


class BuilderHelperTests(unittest.TestCase):
    def test_validate_registry_login_config(self) -> None:
        self.assertEqual(
            validate_registry_login_config("", ""),
            (False, "DOCKERHUB_USER/DOCKERHUB_TOKEN not set, skipping docker login"),
        )
        self.assertEqual(
            validate_registry_login_config("user", ""),
            (False, "DOCKERHUB_USER is set but DOCKERHUB_TOKEN is missing"),
        )
        self.assertEqual(
            validate_registry_login_config("", "token"),
            (False, "DOCKERHUB_TOKEN is set but DOCKERHUB_USER is missing"),
        )
        self.assertEqual(
            validate_registry_login_config("user", "token"),
            (True, ""),
        )

    def test_normalize_install_method_supports_aliases(self) -> None:
        self.assertEqual(_normalize_install_method("docker"), "official_image")
        self.assertEqual(_normalize_install_method("custom"), "custom_build")

    def test_resolve_build_strategy_detects_archive_and_git(self) -> None:
        self.assertEqual(_resolve_build_strategy("", "https://example.com/tool.tar.gz"), "download_archive")
        self.assertEqual(_resolve_build_strategy("", "https://github.com/acme/tool.git"), "go_build")
        self.assertEqual(_resolve_build_strategy("", "https://example.com/tool"), "download_binary")

    def test_build_immutable_image_tag_includes_date_and_digest(self) -> None:
        tag = _build_immutable_image_tag(version="v1.2.3", digest_source="abcdef0123456789")
        self.assertIn("v1.2.3-", tag)
        self.assertTrue(tag.endswith("-sha256-abcdef012345"))

    def test_build_immutable_image_tag_includes_tool_prefix_when_provided(self) -> None:
        tag = _build_immutable_image_tag(
            version="v1.2.3",
            digest_source="abcdef0123456789",
            tag_prefix="Gitleaks",
        )
        self.assertTrue(tag.startswith("gitleaks-v1.2.3-"))

    def test_resolve_custom_build_config_allows_unverified_downloads(self) -> None:
        task = BuildTask(
            tool_id="tool-1",
            build_job_id="job-1",
            install_method="custom_build",
            image_source="https://example.com/tool.tar.gz",
            build_json={
                "version": "1.0.0",
                "binary_name": "tool",
                "repository": "registry.internal/tools/tool-1",
            },
        )
        cfg = _resolve_custom_build_config(task)
        self.assertEqual(cfg.strategy, "download_archive")
        self.assertIsNone(cfg.artifact_sha256)

    def test_resolve_custom_build_config_accepts_gpg_metadata(self) -> None:
        task = BuildTask(
            tool_id="tool-1",
            build_job_id="job-1",
            install_method="custom_build",
            image_source="https://example.com/tool.tar.gz",
            build_json={
                "version": "1.0.0",
                "binary_name": "tool",
                "artifact_sha256": "a" * 64,
                "repository": "registry.internal/tools/tool-1",
                "gpg_signature_url": "https://example.com/tool.tar.gz.asc",
                "gpg_public_key_url": "https://example.com/pubkey.asc",
            },
        )
        cfg = _resolve_custom_build_config(task)
        self.assertEqual(cfg.strategy, "download_archive")
        self.assertEqual(cfg.binary_name, "tool")

    def test_resolve_custom_build_config_requires_complete_gpg_pair(self) -> None:
        task = BuildTask(
            tool_id="tool-1",
            build_job_id="job-1",
            install_method="custom_build",
            image_source="https://example.com/tool.tar.gz",
            build_json={
                "version": "1.0.0",
                "binary_name": "tool",
                "repository": "registry.internal/tools/tool-1",
                "gpg_signature_url": "https://example.com/tool.tar.gz.asc",
            },
        )
        with self.assertRaisesRegex(RuntimeError, "must be provided together"):
            _resolve_custom_build_config(task)

    def test_resolve_custom_build_config_accepts_command_alias(self) -> None:
        task = BuildTask(
            tool_id="tool-1",
            build_job_id="job-1",
            install_method="custom_build",
            image_source="https://example.com/tool.git",
            build_json={
                "version": "1.0.0",
                "binary_name": "tool",
                "repository": "registry.internal/tools/tool-1",
                "command_alias": "tool-dir",
                "command_alias_args": ["dir"],
            },
        )
        cfg = _resolve_custom_build_config(task)
        self.assertEqual(cfg.command_alias, "tool-dir")
        self.assertEqual(list(cfg.command_alias_args), ["dir"])
        self.assertIsNone(cfg.source_commit)

    def test_render_go_build_dockerfile_uses_command_alias_entrypoint(self) -> None:
        task = BuildTask(
            tool_id="tool-1",
            build_job_id="job-1",
            install_method="custom_build",
            image_source="https://example.com/tool.git",
            build_json={
                "version": "1.0.0",
                "binary_name": "tool",
                "source_commit": "a" * 40,
                "repository": "registry.internal/tools/tool-1",
                "gpg_signature_url": "https://example.com/source.tar.gz.asc",
                "gpg_public_key_url": "https://example.com/pubkey.asc",
                "command_alias": "tool-dir",
                "command_alias_args": ["dir"],
            },
        )
        cfg = _resolve_custom_build_config(task)
        dockerfile = render_go_build_dockerfile(
            cfg,
            type("Staged", (), {
                "context_subdir": "source",
                "binary_name": "tool",
                "source_subdir": ".",
                "go_build_package": ".",
            })(),
        )
        self.assertIn("COPY runtime-wrapper/tool-dir /usr/local/bin/tool-dir", dockerfile)
        self.assertIn('ENTRYPOINT ["/usr/local/bin/tool-dir"]', dockerfile)

    def test_extract_archive_member_from_zip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            archive_path = root / "tool.zip"
            output_path = root / "tool"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("release/tool", b"#!/bin/sh\necho hi\n")

            _extract_archive_member(archive_path, output_path, None, "tool")
            self.assertEqual(output_path.read_bytes(), b"#!/bin/sh\necho hi\n")

    def test_extract_archive_member_from_tar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            archive_path = root / "tool.tar.gz"
            payload = root / "tool"
            payload.write_bytes(b"binary-data")
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(payload, arcname="dist/tool")

            output_path = root / "out-tool"
            _extract_archive_member(archive_path, output_path, None, "tool")
            self.assertEqual(output_path.read_bytes(), b"binary-data")

    def test_count_blocking_vulnerabilities_counts_only_high_and_critical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            report = Path(tmp_dir) / "trivy-report.json"
            report.write_text(json.dumps({
                "Results": [
                    {
                        "Vulnerabilities": [
                            {"Severity": "LOW"},
                            {"Severity": "MEDIUM"},
                            {"Severity": "HIGH"},
                            {"Severity": "CRITICAL"},
                        ]
                    }
                ]
            }), encoding="utf-8")
            self.assertEqual(count_blocking_vulnerabilities(report), 2)


if __name__ == "__main__":
    unittest.main()
