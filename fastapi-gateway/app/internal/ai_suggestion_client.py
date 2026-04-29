from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import grpc

from app.gen import ai_suggestion_pb2, ai_suggestion_pb2_grpc
from app.schemas.ai_suggestion_schemas import (
    AISuggestionResponse,
    GenerateAISuggestionRequest,
    UpdateAISuggestionFeedbackRequest,
)
from app.services.ai_suggestion.prompts import normalize_output
from app.utils.grpc_errors import raise_for_grpc_error


def _ts(proto_ts) -> datetime | None:
    if proto_ts is None or (proto_ts.seconds == 0 and proto_ts.nanos == 0):
        return None
    return datetime.fromtimestamp(proto_ts.seconds, tz=timezone.utc)


def _mode_to_proto(mode: str) -> int:
    normalized = (mode or "").strip().lower()
    mapping = {
        "next_steps": ai_suggestion_pb2.SUGGESTION_MODE_NEXT_STEPS,
    }
    if normalized not in mapping:
        raise ValueError(f"invalid mode: {mode}")
    return mapping[normalized]


def _mode_from_proto(value: int) -> str:
    mapping = {
        ai_suggestion_pb2.SUGGESTION_MODE_NEXT_STEPS: "next_steps",
    }
    return mapping.get(value, "next_steps")


class _IdentityMetadataInterceptor(grpc.UnaryUnaryClientInterceptor):
    def __init__(self, user_id: str, api_key_id: str | None = None, api_project_id: str | None = None) -> None:
        self._user_id = user_id
        self._api_key_id = (api_key_id or "").strip()
        self._api_project_id = (api_project_id or "").strip()

    def intercept_unary_unary(self, continuation, client_call_details, request):
        metadata = list(client_call_details.metadata or [])
        metadata.append(("x-user-id", self._user_id))
        if self._api_key_id:
            metadata.append(("x-api-key-id", self._api_key_id))
        if self._api_project_id:
            metadata.append(("x-api-project-id", self._api_project_id))
        new_details = _ClientCallDetails(
            client_call_details.method,
            client_call_details.timeout,
            metadata,
            client_call_details.credentials,
            client_call_details.wait_for_ready,
            client_call_details.compression,
        )
        return continuation(new_details, request)


class _ClientCallDetails(grpc.ClientCallDetails):
    def __init__(self, method, timeout, metadata, credentials, wait_for_ready, compression):
        self.method = method
        self.timeout = timeout
        self.metadata = metadata
        self.credentials = credentials
        self.wait_for_ready = wait_for_ready
        self.compression = compression


def _proto_to_response(resp) -> AISuggestionResponse:
    try:
        output = json.loads(resp.output_json) if resp.output_json else {}
    except json.JSONDecodeError:
        output = {"raw": resp.output_json}

    normalized_mode = _mode_from_proto(resp.mode)
    if resp.output_json:
        try:
            output = normalize_output(normalized_mode, resp.output_json)
        except (ValueError, TypeError):
            pass

    return AISuggestionResponse(
        id=resp.id,
        job_id=resp.job_id,
        mode=normalized_mode,
        provider=resp.provider,
        model=resp.model,
        content=resp.content,
        output=output if isinstance(output, dict) else {"data": output},
        input_tokens=resp.input_tokens,
        output_tokens=resp.output_tokens,
        feedback=resp.feedback or "",
        is_suggested=resp.is_suggested,
        created_at=_ts(resp.created_at),
        updated_at=_ts(resp.updated_at),
    )


class AISuggestionClient:
    def __init__(self) -> None:
        grpc_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051")
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = ai_suggestion_pb2_grpc.SuggestionServiceStub(self.channel)

    def _make_stub_with_user(
        self,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> ai_suggestion_pb2_grpc.SuggestionServiceStub:
        interceptor = _IdentityMetadataInterceptor(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
        intercepted_channel = grpc.intercept_channel(self.channel, interceptor)
        return ai_suggestion_pb2_grpc.SuggestionServiceStub(intercepted_channel)

    def generate_suggestion(
        self,
        body: GenerateAISuggestionRequest,
        *,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> AISuggestionResponse:
        req = ai_suggestion_pb2.GenerateSuggestionRequest(
            job_id=body.job_id,
            mode=_mode_to_proto(body.mode),
        )
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            return _proto_to_response(stub.GenerateSuggestion(req))
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)

    def get_suggestion(
        self,
        suggestion_id: str,
        *,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> AISuggestionResponse:
        req = ai_suggestion_pb2.GetSuggestionRequest(
            suggestion_id=suggestion_id,
        )
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            return _proto_to_response(stub.GetSuggestion(req))
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)

    def update_feedback(
        self,
        job_id: str,
        body: UpdateAISuggestionFeedbackRequest,
        *,
        user_id: str,
        api_key_id: str | None = None,
        api_project_id: str | None = None,
    ) -> AISuggestionResponse:
        req = ai_suggestion_pb2.UpdateSuggestionFeedbackRequest(
            job_id=job_id,
            mode=_mode_to_proto(body.mode),
            feedback=body.feedback,
        )
        try:
            stub = self._make_stub_with_user(user_id, api_key_id=api_key_id, api_project_id=api_project_id)
            return _proto_to_response(stub.UpdateSuggestionFeedback(req))
        except grpc.RpcError as exc:
            raise_for_grpc_error(exc)


ai_suggestion_client = AISuggestionClient()
