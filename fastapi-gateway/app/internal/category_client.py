from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, Optional

import grpc

from app.gen import category_pb2, category_pb2_grpc
from app.schemas.category_schemas import (
    CategoryResponse,
    CreateCategoryRequest,
    UpdateCategoryRequest,
)
from app.utils.grpc_errors import raise_for_grpc_error


def _ts(proto_ts) -> Optional[datetime]:
    if proto_ts is None or (proto_ts.seconds == 0 and proto_ts.nanos == 0):
        return None
    return datetime.fromtimestamp(proto_ts.seconds, tz=timezone.utc)


def _proto_to_category(resp) -> CategoryResponse:
    return CategoryResponse(
        category_id=resp.category_id,
        name=resp.name,
        description=resp.description or None,
        created_at=_ts(resp.created_at),
        last_modified=_ts(resp.last_modified),
    )


class CategoryClient:
    """gRPC client for CategoryService (full CRUD)."""

    def __init__(self) -> None:
        grpc_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051")
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = category_pb2_grpc.CategoryServiceStub(self.channel)

    def create_category(self, body: CreateCategoryRequest) -> CategoryResponse:
        req = category_pb2.CreateCategoryRequest(
            name=body.name,
            description=body.description or "",
        )
        try:
            return _proto_to_category(self.stub.CreateCategory(req))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def get_category(self, category_id: str) -> CategoryResponse:
        req = category_pb2.GetCategoryRequest(category_id=category_id)
        try:
            return _proto_to_category(self.stub.GetCategory(req))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def list_categories(self) -> List[CategoryResponse]:
        try:
            resp = self.stub.ListCategories(category_pb2.ListCategoriesRequest())
            return [_proto_to_category(c) for c in resp.categories]
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def update_category(self, category_id: str, body: UpdateCategoryRequest) -> CategoryResponse:
        req = category_pb2.UpdateCategoryRequest(
            category_id=category_id,
            name=body.name or "",
            description=body.description or "",
        )
        try:
            return _proto_to_category(self.stub.UpdateCategory(req))
        except grpc.RpcError as e:
            raise_for_grpc_error(e)

    def delete_category(self, category_id: str) -> dict:
        req = category_pb2.DeleteCategoryRequest(category_id=category_id)
        try:
            resp = self.stub.DeleteCategory(req)
            return {"category_id": resp.category_id, "deleted": resp.deleted}
        except grpc.RpcError as e:
            raise_for_grpc_error(e)


category_client = CategoryClient()
