from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, Optional

import grpc

from app.gen import project_pb2, project_pb2_grpc
from app.schemas.project_schemas import (
    CreateProjectRequest,
    ProjectResponse,
    UpdateProjectRequest,
)
from app.utils.grpc_errors import raise_for_grpc_error


def _ts(proto_ts) -> Optional[datetime]:
    if proto_ts is None or (proto_ts.seconds == 0 and proto_ts.nanos == 0):
        return None
    return datetime.fromtimestamp(proto_ts.seconds, tz=timezone.utc)


def _proto_to_project(resp) -> ProjectResponse:
    return ProjectResponse(
        project_id=resp.project_id,
        name=resp.name,
        description=resp.description or None,
        owner_id=resp.owner_id,
        created_at=_ts(resp.created_at),
        last_modified=_ts(resp.last_modified),
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


class _ClientCallDetails(
    grpc.ClientCallDetails,
):
    def __init__(self, method, timeout, metadata, credentials, wait_for_ready, compression):
        self.method = method
        self.timeout = timeout
        self.metadata = metadata
        self.credentials = credentials
        self.wait_for_ready = wait_for_ready
        self.compression = compression


class ProjectClient:
    """gRPC client for ProjectService (full CRUD)."""

    def __init__(self) -> None:
        grpc_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051")
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = project_pb2_grpc.ProjectServiceStub(self.channel)

    def _make_stub_with_user(self, user_id: str) -> project_pb2_grpc.ProjectServiceStub:
        """Return a stub that attaches x-user-id metadata to every unary call."""
        interceptor = _UserIdMetadataInterceptor(user_id)
        intercepted_channel = grpc.intercept_channel(self.channel, interceptor)
        return project_pb2_grpc.ProjectServiceStub(intercepted_channel)

    def create_project(self, body: CreateProjectRequest, user_id: str) -> ProjectResponse:
        req = project_pb2.CreateProjectRequest(
            name=body.name,
            description=body.description or "",
        )
        try:
            stub = self._make_stub_with_user(user_id)
            return _proto_to_project(stub.CreateProject(req))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def get_project_by_id(self, project_id: str, user_id: str) -> ProjectResponse:
        req = project_pb2.GetProjectRequest(
            project_id=project_id,
        )
        try:
            stub = self._make_stub_with_user(user_id)
            return _proto_to_project(stub.GetProject(req))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def get_project_by_name(self, project_name: str, user_id: str) -> ProjectResponse:
        req = project_pb2.GetProjectRequest(
            project_name=project_name,
        )
        try:
            stub = self._make_stub_with_user(user_id)
            return _proto_to_project(stub.GetProject(req))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def list_projects(self, user_id: str) -> List[ProjectResponse]:
        req = project_pb2.ListProjectsRequest()
        try:
            stub = self._make_stub_with_user(user_id)
            resp = stub.ListProjects(req)
            return [_proto_to_project(p) for p in resp.projects]
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def update_project(self, project_id: str, body: UpdateProjectRequest, user_id: str) -> ProjectResponse:
        req = project_pb2.UpdateProjectRequest(
            project_id=project_id,
        )
        if body.name is not None:
            req.name = body.name
        if body.description is not None:
            req.description = body.description
        try:
            stub = self._make_stub_with_user(user_id)
            return _proto_to_project(stub.UpdateProject(req))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def delete_project(self, project_id: str, user_id: str, cascade: bool = True) -> bool:
        req = project_pb2.DeleteProjectRequest(
            project_id=project_id,
            cascade=cascade,
        )
        try:
            stub = self._make_stub_with_user(user_id)
            resp = stub.DeleteProject(req)
            return resp.success
        except grpc.RpcError as e:
            raise_for_grpc_error(e)


project_client = ProjectClient()
