from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.schemas.basic_scan_schemas import (
    BasicParsedDataColumn,
    BasicParsedDataResponse,
    BasicResultsResponse,
)
from app.utils.scan_helpers import _build_basic_result_payload, _parsed_data_signature, _serialize_basic_parsed_data


def test_build_basic_result_payload_includes_parsed_data_for_structured_tools() -> None:
    created_at = datetime.now(timezone.utc)
    parsed_data = BasicParsedDataResponse(
        step_id="step-1",
        job_id="job-1",
        tool_name="subfinder",
        parse_method="jsonl",
        line_count=1,
        findings_count=0,
        lines=['{"host":"api.example.com"}'],
        columns=[
            BasicParsedDataColumn(
                key="host",
                label="Subdomain",
                type="string",
                render_hints={"role": "host", "piped_to_next": "true"},
            )
        ],
        data=[{"host": "api.example.com"}],
        created_at=created_at,
    )
    page = BasicResultsResponse(
        scope_id="job-1",
        findings=[],
        total_count=0,
        limit=100,
        offset=0,
        has_more=False,
        next_cursor=None,
        raw_output_inline="cmF3LW91dHB1dA==",
        parsed_data=parsed_data,
    )

    parsed_payload = _serialize_basic_parsed_data(parsed_data)
    payload = _build_basic_result_payload(
        job_id="job-1",
        page=page,
        offset=0,
        parsed_data_payload=parsed_payload,
    )

    assert payload["job_id"] == "job-1"
    assert payload["count"] == 0
    assert payload["findings"] == []
    assert payload["raw_output_inline"] == "cmF3LW91dHB1dA=="
    assert payload["parsed_data"]["tool_name"] == "subfinder"
    assert payload["parsed_data"]["data"] == [{"host": "api.example.com"}]
    assert _parsed_data_signature(parsed_data) == _parsed_data_signature(parsed_payload)
