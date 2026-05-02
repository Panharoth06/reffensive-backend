"""Pydantic schemas for API key operations."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class CreateAPIKeyRequest(BaseModel):
    """Request to create a new API key."""

    name: str = Field(..., description="Name of the API key")
    description: Optional[str] = Field(None, description="Description of the key")
    scopes: Optional[list[str]] = Field(None, description="List of scopes for the key")


class CreateAPIKeyResponse(BaseModel):
    """Response after creating an API key."""

    key_id: str = Field(..., description="Unique ID of the key")
    plain_key: str = Field(..., description="The full key (shown only once!)")
    prefix: str = Field(..., description="Prefix of the key")
    name: str = Field(..., description="Name of the key")
    description: Optional[str] = Field(None, description="Description of the key")
    created_at: Optional[datetime] = Field(None, description="When the key was created")


class ValidateAPIKeyRequest(BaseModel):
    """Request to validate an API key."""

    key: str = Field(..., description="The API key to validate")
    action: str = Field(..., description="The action to validate for")


class ValidateAPIKeyResponse(BaseModel):
    """Response after validating an API key."""

    valid: bool = Field(..., description="Whether the key is valid")
    project_id: str = Field(..., description="Project ID associated with the key")
    user_id: str = Field(..., description="User ID owning the key")
    scopes: list[str] = Field(..., description="List of scopes for the key")
    reason: Optional[str] = Field(None, description="Reason if invalid")
    key_id: Optional[str] = Field(None, description="Key ID when validation matched a stored API key")


class RevokeAPIKeyRequest(BaseModel):
    """Request to revoke an API key."""

    key_id: str = Field(..., description="ID of the key to revoke")


class RevokeAPIKeyResponse(BaseModel):
    """Response after revoking an API key."""

    key_id: str = Field(..., description="ID of the revoked key")
    success: bool = Field(..., description="Whether revocation was successful")


class APIKeyResponse(BaseModel):
    """Response representing an API key."""

    key_id: str = Field(..., description="Unique ID of the key")
    project_id: str = Field(..., description="Project ID")
    user_id: str = Field(..., description="User ID")
    name: str = Field(..., description="Name of the key")
    prefix: str = Field(..., description="Prefix of the key (public part)")
    description: Optional[str] = Field(None, description="Description")
    scopes: list[str] = Field(..., description="List of scopes")
    is_active: bool = Field(..., description="Whether the key is active")
    revoked_at: Optional[datetime] = Field(None, description="When the key was revoked")
    expired_at: Optional[datetime] = Field(None, description="When the key expires")


class APIKeyListResponse(BaseModel):
    """Response containing a list of API keys."""

    keys: list[APIKeyResponse] = Field(..., description="List of API keys")
