from __future__ import annotations

import unittest

from app.schemas.medium_scan_schemas import MediumScanSubmitRequest
from app.schemas.secure_execution_schemas import SecureExecutionRequest
from app.schemas.tool_schemas import CreateToolRequest


class ToolContractTests(unittest.TestCase):
    def test_create_tool_normalizes_docker_install_method(self) -> None:
        body = CreateToolRequest(
            category_name="Reconnaissance",
            tool_name="httpx",
            install_method="docker",
            image_ref="docker.io/acme/httpx:v1.9.0",
            image_source="dockerhub",
        )
        self.assertEqual(body.install_method, "official_image")

    def test_create_tool_accepts_legacy_tool_json_aliases(self) -> None:
        body = CreateToolRequest.model_validate(
            {
                "tool_name": "legacy-tool",
                "shadow_output_config": {
                    "preferred_format": "txt",
                    "formats": {
                        "txt": {
                            "transport": "stdout",
                            "parser": "lines",
                            "path_mode": "stdout",
                        }
                    },
                },
                "parser_config": {
                    "type": "line",
                },
            }
        )

        self.assertEqual(body.shadow_output_config.formats["txt"].path_mode, "streaming")
        self.assertEqual(body.parser_config.type, "lines")

    def test_medium_scan_request_accepts_array_tool_options(self) -> None:
        body = MediumScanSubmitRequest(
            project_id="project-1",
            target_value="https://example.com",
            tool_name="httpx",
            tool_options={"custom_headers": ["X-Test: one", "Authorization: Bearer xyz"]},
        )
        self.assertEqual(body.tool_options["custom_headers"], ["X-Test: one", "Authorization: Bearer xyz"])

    def test_secure_execution_request_accepts_array_params(self) -> None:
        body = SecureExecutionRequest(
            project_id="project-1",
            tool_name="httpx",
            target_scope={"targets": ["https://example.com"]},
            execution_params={"custom_headers": ["X-Test: one", "X-Test: two"]},
        )
        self.assertEqual(body.execution_params["custom_headers"], ["X-Test: one", "X-Test: two"])


if __name__ == "__main__":
    unittest.main()
