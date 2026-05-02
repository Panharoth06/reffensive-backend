from __future__ import annotations

from datetime import timedelta
from io import BytesIO

from minio import Minio
from minio.error import S3Error

from app.core.config import Settings


def minio_enabled(settings: Settings) -> bool:
    return bool(settings.minio_endpoint and settings.minio_access_key and settings.minio_secret_key)


def _new_client(settings: Settings) -> Minio:
    return Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_use_ssl,
        region=settings.minio_region,
    )


def put_report_object(settings: Settings, object_name: str, report_bytes: bytes) -> str:
    client = _new_client(settings)
    if not client.bucket_exists(settings.minio_bucket):
        client.make_bucket(settings.minio_bucket)
    payload = BytesIO(report_bytes)
    client.put_object(
        settings.minio_bucket,
        object_name,
        payload,
        length=len(report_bytes),
        content_type="application/pdf",
    )
    return object_name


def create_report_download_url(settings: Settings, object_name: str) -> str:
    client = _new_client(settings)
    if settings.minio_secure_public_base_url:
        return f"{settings.minio_secure_public_base_url}/{settings.minio_bucket}/{object_name}"
    return client.presigned_get_object(
        settings.minio_bucket,
        object_name,
        expires=timedelta(seconds=settings.minio_presigned_expiry_seconds),
    )


def safe_minio_message(exc: Exception) -> str:
    if isinstance(exc, S3Error):
        return f"{exc.code}: {exc.message}"
    return str(exc)
