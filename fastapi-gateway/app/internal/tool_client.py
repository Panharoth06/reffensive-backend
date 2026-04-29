from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional, Type, TypeVar

import grpc
from google.protobuf.json_format import MessageToDict, ParseDict
from pydantic import BaseModel

from app.gen import create_tool_pb2, create_tool_pb2_grpc
from app.schemas.tool_schemas import (
    CreateToolRequest,
    InputSchema,
    ParserConfig,
    ScanConfig,
    OutputSchema,
    ShadowOutputConfig,
    SetToolActiveResponse,
    ToolResponse,
    UpdateToolRequest,
)
from app.utils.grpc_errors import raise_for_grpc_error

M = TypeVar("M", bound=BaseModel)


def _to_json(value) -> str:
    if value is None:
        return ""
    if isinstance(value, BaseModel):
        return value.model_dump_json(exclude_none=True)
    return json.dumps(value, ensure_ascii=True)


def _from_json(raw: str, cls: Type[M]) -> Optional[M]:
    if not raw:
        return None
    try:
        return cls.model_validate_json(raw)
    except Exception:
        return None


def _from_json_examples(raw: str) -> List[dict]:
    if not raw:
        return []
    try:
        val = json.loads(raw)
    except Exception:
        return []
    return val if isinstance(val, list) else []


def _ts(proto_ts) -> Optional[datetime]:
    if proto_ts is None or (proto_ts.seconds == 0 and proto_ts.nanos == 0):
        return None
    return datetime.fromtimestamp(proto_ts.seconds, tz=timezone.utc)


def _proto_to_tool(resp) -> ToolResponse:
    shadow_output_config = None
    if resp.HasField("shadow_output_config"):
        try:
            shadow_output_config = ShadowOutputConfig.model_validate(
                MessageToDict(resp.shadow_output_config, preserving_proto_field_name=True)
            )
        except Exception:
            shadow_output_config = None
    return ToolResponse(
        tool_id=resp.tool_id,
        category_name=resp.category_name or None,
        tool_name=resp.tool_name,
        tool_description=resp.tool_description or None,
        tool_long_description=resp.tool_long_description or None,
        examples=_from_json_examples(resp.examples),
        input_schema=_from_json(resp.input_schema, InputSchema),
        output_schema=_from_json(resp.output_schema, OutputSchema),
        scan_config=_from_json(resp.scan_config, ScanConfig),
        install_method=resp.install_method or None,
        version=resp.version or None,
        image_ref=resp.image_ref or None,
        image_source=resp.image_source or None,
        is_active=resp.is_active,
        denied_options=list(resp.denied_options),
        shadow_output_config=shadow_output_config,
        parser_config=_from_json(resp.parser_config, ParserConfig),
        created_at=_ts(resp.created_at),
        updated_at=_ts(resp.updated_at),
    )


class ToolClient:
    """gRPC client for ToolService (full CRUD)."""

    def __init__(self) -> None:
        import os
        grpc_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051")
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = create_tool_pb2_grpc.ToolServiceStub(self.channel)

    # ── Create ────────────────────────────────────────────────────────────────
    def create_tool(self, body: CreateToolRequest) -> ToolResponse:
        req = create_tool_pb2.CreateToolRequest(
            category_name=body.category_name or "",
            tool_name=body.tool_name,
            tool_description=body.tool_description or "",
            tool_long_description=body.tool_long_description or "",
            examples=_to_json(body.examples),
            input_schema=_to_json(body.input_schema),
            output_schema=_to_json(body.output_schema),
            scan_config=_to_json(body.scan_config),
            install_method=body.install_method or "",
            version=body.version or "",
            image_ref=body.image_ref or "",
            image_source=body.image_source or "",
            build_config_json=_to_json(body.build_config),
            is_active=body.is_active,
            denied_options=body.denied_options,
            parser_config=_to_json(body.parser_config),
        )
        if body.shadow_output_config is not None:
            ParseDict(
                body.shadow_output_config.model_dump(exclude_none=True),
                req.shadow_output_config,
            )
        try:
            return _proto_to_tool(self.stub.CreateTool(req))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    # ── Get ───────────────────────────────────────────────────────────────────
    def get_tool(self, tool_id: str) -> ToolResponse:
        try:
            return _proto_to_tool(self.stub.GetTool(create_tool_pb2.GetToolRequest(tool_id=tool_id)))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    # ── List ──────────────────────────────────────────────────────────────────
    def list_tools(self, active_only: bool = False, category_name: str = "") -> List[ToolResponse]:
        req = create_tool_pb2.ListToolsRequest(active_only=active_only, category_name=category_name)
        try:
            resp = self.stub.ListTools(req)
            return [_proto_to_tool(t) for t in resp.tools]
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    # ── Update ────────────────────────────────────────────────────────────────
    def update_tool(self, tool_id: str, body: UpdateToolRequest) -> ToolResponse:
        req = create_tool_pb2.UpdateToolRequest(
            tool_id=tool_id,
            category_name=body.category_name or "",
            tool_name=body.tool_name or "",
            tool_description=body.tool_description or "",
            tool_long_description=body.tool_long_description or "",
            examples=_to_json(body.examples),
            input_schema=_to_json(body.input_schema),
            output_schema=_to_json(body.output_schema),
            scan_config=_to_json(body.scan_config),
            install_method=body.install_method or "",
            version=body.version or "",
            image_ref=body.image_ref or "",
            image_source=body.image_source or "",
            build_config_json=_to_json(body.build_config),
            denied_options=body.denied_options or [],
            parser_config=_to_json(body.parser_config),
        )
        if body.shadow_output_config is not None:
            ParseDict(
                body.shadow_output_config.model_dump(exclude_none=True),
                req.shadow_output_config,
            )
        try:
            return _proto_to_tool(self.stub.UpdateTool(req))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    # ── Soft-delete / activate ────────────────────────────────────────────────
    def set_tool_active(self, tool_id: str, is_active: bool) -> SetToolActiveResponse:
        req = create_tool_pb2.SetToolActiveRequest(tool_id=tool_id, is_active=is_active)
        try:
            resp = self.stub.SetToolActive(req)
            return SetToolActiveResponse(tool_id=resp.tool_id, is_active=resp.is_active)
        except grpc.RpcError as e:
            raise_for_grpc_error(e)



tool_client = ToolClient()
