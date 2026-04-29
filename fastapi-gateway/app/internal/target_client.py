from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, Optional

import grpc

from app.gen import target_pb2, target_pb2_grpc
from app.schemas.target_schemas import (
    CreateTargetRequest,
    TargetResponse,
    UpdateTargetRequest,
)
from app.utils.grpc_errors import raise_for_grpc_error


def _ts(proto_ts) -> Optional[datetime]:
    if proto_ts is None or (proto_ts.seconds == 0 and proto_ts.nanos == 0):
        return None
    return datetime.fromtimestamp(proto_ts.seconds, tz=timezone.utc)


def _proto_to_target(resp) -> TargetResponse:
    return TargetResponse(
        target_id=resp.target_id,
        project_id=resp.project_id,
        name=resp.name,
        type=resp.type,
        description=resp.description or None,
        created_at=_ts(resp.created_at),
    )


class _UserIdMetadataInterceptor(grpc.UnaryUnaryClientInterceptor):
    """Attaches x-user-id to every unary-unary call."""

    def __init__(self, user_id: str) -> None:
        self._user_id = user_id

    def intercept_unary_unary(self, continuation, client_call_details, request):
        metadata = list(client_call_details.metadata or [])
        metadata.append(("x-user-id", self._user_id))
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


class TargetClient:
    """gRPC client for TargetService (full CRUD)."""

    def __init__(self) -> None:
        grpc_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051")
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = target_pb2_grpc.TargetServiceStub(self.channel)

    def _make_stub_with_user(self, user_id: str) -> target_pb2_grpc.TargetServiceStub:
        """Return a stub that attaches x-user-id metadata to every unary call."""
        interceptor = _UserIdMetadataInterceptor(user_id)
        intercepted_channel = grpc.intercept_channel(self.channel, interceptor)
        return target_pb2_grpc.TargetServiceStub(intercepted_channel)

    def create_target(
        self, project_id: str, body: CreateTargetRequest, user_id: str
    ) -> TargetResponse:
        req = target_pb2.CreateTargetRequest(
            project_id=project_id,
            name=body.name,
            type=body.type,
            description=body.description or "",
        )
        try:
            stub = self._make_stub_with_user(user_id)
            return _proto_to_target(stub.CreateTarget(req))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def get_target(self, project_id: str, target_id: str, user_id: str) -> TargetResponse:
        req = target_pb2.GetTargetRequest(target_id=target_id, project_id=project_id)
        try:
            stub = self._make_stub_with_user(user_id)
            return _proto_to_target(stub.GetTarget(req))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def list_targets(self, project_id: str, user_id: str) -> List[TargetResponse]:
        req = target_pb2.ListTargetsRequest(project_id=project_id)
        try:
            stub = self._make_stub_with_user(user_id)
            resp = stub.ListTargets(req)
            return [_proto_to_target(t) for t in resp.targets]
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def update_target(
        self, project_id: str, target_id: str, body: UpdateTargetRequest, user_id: str
    ) -> TargetResponse:
        req = target_pb2.UpdateTargetRequest(
            target_id=target_id,
            project_id=project_id,
        )
        if body.description is not None:
            req.description = body.description
        try:
            stub = self._make_stub_with_user(user_id)
            return _proto_to_target(stub.UpdateTarget(req))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def delete_target(self, project_id: str, target_id: str, user_id: str) -> bool:
        req = target_pb2.DeleteTargetRequest(target_id=target_id, project_id=project_id)
        try:
            stub = self._make_stub_with_user(user_id)
            resp = stub.DeleteTarget(req)
            return resp.success
        except grpc.RpcError as e:
            raise_for_grpc_error(e)


target_client = TargetClient()
