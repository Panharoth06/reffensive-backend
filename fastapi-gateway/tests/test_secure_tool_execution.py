from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pydantic import ValidationError

from app.schemas.medium_scan_schemas import (
    MediumScanJobStatusResponse,
    MediumScanResultsResponse,
    MediumScanStepStatusResponse,
    MediumScanStepSummary,
    MediumScanSubmitResponse,
)
from app.schemas.secure_execution_schemas import SecureExecutionRequest
from app.schemas.tool_schemas import ToolResponse
from app.utils.secure_tool_execution import (
    decode_raw_output,
    get_secure_execution_status,
    sanitize_text,
    submit_secure_execution,
)


def make_tool(*, image_ref: str | None = "docker.io/acme/httpx@sha256:abc", version: str | None = "1.0.0") -> ToolResponse:
    return ToolResponse(
        tool_id="tool-1",
        tool_name="httpx",
        version=version,
        image_ref=image_ref,
        image_source="docker.io/acme/httpx:1.0.0",
        install_method="official_image",
        is_active=True,
    )


class SecureExecutionSchemaTests(unittest.TestCase):
    def test_schema_rejects_blocked_capability_requests(self) -> None:
        with self.assertRaises(ValidationError):
            SecureExecutionRequest(
                project_id="project-1",
                tool_name="httpx",
                target_scope={"targets": ["https://example.com"]},
                net_raw=True,
            )

    def test_schema_rejects_multiple_targets(self) -> None:
        with self.assertRaises(ValidationError):
            SecureExecutionRequest(
                project_id="project-1",
                tool_name="httpx",
                target_scope={"targets": ["https://a.example", "https://b.example"]},
            )


class SecureExecutionHelpersTests(unittest.TestCase):
    def test_sanitize_text_redacts_secrets_and_private_ips(self) -> None:
        raw = (
            "Authorization: Bearer topsecret\n"
            "token=abc123\n"
            "callback=10.0.0.9\n"
            "public=8.8.8.8"
        )
        sanitized = sanitize_text(raw)
        self.assertIn("Bearer [REDACTED]", sanitized)
        self.assertIn("token=[REDACTED]", sanitized)
        self.assertIn("[REDACTED_IP]", sanitized)
        self.assertIn("8.8.8.8", sanitized)

    def test_decode_raw_output_handles_base64(self) -> None:
        self.assertEqual(decode_raw_output("aGVsbG8="), "hello")


class SecureExecutionBehaviorTests(unittest.TestCase):
    @patch("app.utils.secure_tool_execution.get_medium_scan_client")
    @patch("app.utils.secure_tool_execution.get_tool_client")
    def test_submit_executes_ready_tool(self, get_tool_client_mock, get_medium_scan_client_mock) -> None:
        get_tool_client_mock.return_value = SimpleNamespace(list_tools=lambda active_only=True: [make_tool()])
        get_medium_scan_client_mock.return_value = SimpleNamespace(
            submit_medium_scan=lambda body, user_id: MediumScanSubmitResponse(
                job_id="job-1",
                step_id="step-1",
                status="SCAN_STATUS_QUEUED",
                is_idempotent_replay=False,
            )
        )

        response = submit_secure_execution(
            SecureExecutionRequest(
                project_id="project-1",
                tool_name="httpx",
                version="1.0.0",
                target_scope={"targets": ["https://example.com"]},
                execution_params={"rate": 100},
            ),
            user_id="user-1",
        )

        self.assertEqual(response.status, "executing")
        self.assertEqual(response.execution_id, "job-1")
        self.assertEqual(response.tool_image, "docker.io/acme/httpx@sha256:abc")
        self.assertEqual(response.security_metadata.scan_status, "clean")

    @patch("app.utils.secure_tool_execution.get_tool_client")
    def test_submit_blocks_tool_without_ready_image(self, get_tool_client_mock) -> None:
        get_tool_client_mock.return_value = SimpleNamespace(list_tools=lambda active_only=True: [make_tool(image_ref=None)])

        response = submit_secure_execution(
            SecureExecutionRequest(
                project_id="project-1",
                tool_name="httpx",
                target_scope={"targets": ["https://example.com"]},
            ),
            user_id="user-1",
        )

        self.assertEqual(response.status, "failed")
        self.assertIn("not ready", response.error or "")
        self.assertEqual(response.security_metadata.scan_status, "blocked")

    @patch("app.utils.secure_tool_execution.get_medium_scan_client")
    @patch("app.utils.secure_tool_execution.get_tool_client")
    def test_get_status_sanitizes_output(self, get_tool_client_mock, get_medium_scan_client_mock) -> None:
        get_tool_client_mock.return_value = SimpleNamespace(list_tools=lambda active_only=True: [make_tool()])
        get_medium_scan_client_mock.return_value = SimpleNamespace(
            get_job_status=lambda execution_id, user_id: MediumScanJobStatusResponse(
                job_id="job-1",
                project_id="project-1",
                status="JOB_STATUS_COMPLETED",
                total_steps=1,
                completed_steps=1,
                failed_steps=0,
                pending_steps=0,
                steps=[
                    MediumScanStepSummary(
                        step_id="step-1",
                        tool_name="httpx",
                        step_order=1,
                        status="SCAN_STATUS_COMPLETED",
                    )
                ],
            ),
            get_step_status=lambda step_id, user_id: MediumScanStepStatusResponse(
                step_id="step-1",
                job_id="job-1",
                tool_name="httpx",
                status="SCAN_STATUS_COMPLETED",
                exit_code=0,
                duration_ms=1200,
                error_message=None,
            ),
            get_results=lambda job_id, user_id: MediumScanResultsResponse(
                scope_id="job-1",
                findings=[],
                total_count=0,
                raw_output_inline="QXV0aG9yaXphdGlvbjogQmVhcmVyIHRvcHNlY3JldCBmcm9tIDEwLjAuMC4x",
            ),
        )

        response = get_secure_execution_status("job-1", user_id="user-1")

        self.assertEqual(response.status, "completed")
        self.assertEqual(response.duration_ms, 1200)
        self.assertIn("Bearer [REDACTED]", response.sanitized_logs)
        self.assertIn("[REDACTED_IP]", response.sanitized_logs)


if __name__ == "__main__":
    unittest.main()
