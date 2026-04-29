"""gRPC client for APIKeyService."""
from __future__ import annotations

import json
import os
from typing import Optional

import grpc

from app.gen import api_key_pb2, api_key_pb2_grpc
from app.schemas.apikey_schemas import (
    APIKeyListResponse,
    APIKeyResponse,
    CreateAPIKeyResponse,
    RevokeAPIKeyResponse,
    ValidateAPIKeyRequest as ValidateKeyRequest,
    ValidateAPIKeyResponse,
)
from app.utils.grpc_errors import raise_for_grpc_error


class APIKeyClient:
    """gRPC client for APIKeyService (API key management)."""

    def __init__(self) -> None:
        grpc_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051")
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = api_key_pb2_grpc.APIKeyServiceStub(self.channel)

    def _make_stub_with_user(self, user_id: str) -> api_key_pb2_grpc.APIKeyServiceStub:
        interceptor = _UserIdMetadataInterceptor(user_id)
        intercepted_channel = grpc.intercept_channel(self.channel, interceptor)
        return api_key_pb2_grpc.APIKeyServiceStub(intercepted_channel)

    def create_api_key(
        self,
        project_id: str,
        name: str,
        description: str = "",
        scopes: Optional[list[str]] = None,
        user_id: str = "",
    ) -> CreateAPIKeyResponse:
        """Create a new API key for a project."""
        scopes_json = json.dumps(scopes or [])
        req = api_key_pb2.CreateAPIKeyRequest(
            project_id=project_id,
            name=name,
            description=description,
            scopes_json=scopes_json,
        )
        try:
            stub = self._make_stub_with_user(user_id)
            resp = stub.CreateAPIKey(req)
            return CreateAPIKeyResponse(
                key_id=resp.key_id,
                plain_key=resp.plain_key,
                prefix=resp.prefix,
                name=resp.name,
                description=resp.description,
                created_at=resp.created_at.ToDatetime() if resp.created_at else None,
            )
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def validate_api_key(self, key: str, action: str) -> ValidateAPIKeyResponse:
        """Validate an API key and check if it has the required scope."""
        req = api_key_pb2.ValidateAPIKeyRequest(key=key, action=action)
        try:
            resp = self.stub.ValidateAPIKey(req)
            scopes = json.loads(resp.scopes_json) if resp.scopes_json else []
            return ValidateAPIKeyResponse(
                valid=resp.valid,
                project_id=resp.project_id,
                user_id=resp.user_id,
                scopes=scopes,
                reason=resp.reason,
                key_id=resp.key_id or None,
            )
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def revoke_api_key(self, key_id: str, user_id: str) -> RevokeAPIKeyResponse:
        """Revoke an API key."""
        req = api_key_pb2.RevokeAPIKeyRequest(key_id=key_id)
        try:
            stub = self._make_stub_with_user(user_id)
            resp = stub.RevokeAPIKey(req)
            return RevokeAPIKeyResponse(key_id=resp.key_id, success=resp.success)
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def list_project_api_keys(
        self, project_id: str, active_only: bool = False, user_id: str = ""
    ) -> APIKeyListResponse:
        """List API keys for a project."""
        req = api_key_pb2.ListProjectAPIKeysRequest(
            project_id=project_id, active_only=active_only
        )
        try:
            stub = self._make_stub_with_user(user_id)
            resp = stub.ListProjectAPIKeys(req)
            keys = [
                APIKeyResponse(
                    key_id=k.key_id,
                    project_id=k.project_id,
                    user_id=k.user_id,
                    name=k.name,
                    prefix=k.prefix,
                    description=k.description,
                    scopes=json.loads(k.scopes_json) if k.scopes_json else [],
                    is_active=k.is_active,
                    revoked_at=k.revoked_at.ToDatetime()
                    if k.revoked_at and k.revoked_at.seconds
                    else None,
                    expired_at=k.expired_at.ToDatetime()
                    if k.expired_at and k.expired_at.seconds
                    else None,
                )
                for k in resp.keys
            ]
            return APIKeyListResponse(keys=keys)
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def get_api_key(self, key_id: str, user_id: str) -> APIKeyResponse:
        """Get a specific API key by ID."""
        req = api_key_pb2.GetAPIKeyRequest(key_id=key_id)
        try:
            stub = self._make_stub_with_user(user_id)
            resp = stub.GetAPIKey(req)
            return APIKeyResponse(
                key_id=resp.key_id,
                project_id=resp.project_id,
                user_id=resp.user_id,
                name=resp.name,
                prefix=resp.prefix,
                description=resp.description,
                scopes=json.loads(resp.scopes_json) if resp.scopes_json else [],
                is_active=resp.is_active,
                revoked_at=resp.revoked_at.ToDatetime()
                if resp.revoked_at and resp.revoked_at.seconds
                else None,
                expired_at=resp.expired_at.ToDatetime()
                if resp.expired_at and resp.expired_at.seconds
                else None,
            )
        except grpc.RpcError as e:
            raise_for_grpc_error(e)


class _UserIdMetadataInterceptor(grpc.UnaryUnaryClientInterceptor):
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
