import base64
import functools
import json

import jwt
from fastapi import HTTPException, status
from jwt import PyJWKClient, PyJWTError

from app.core.config import get_settings


@functools.lru_cache(maxsize=4)
def get_jwks_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(
        jwks_url,
        headers={
            "Accept": "application/json",
            "User-Agent": "auto-offensive-fastapi-gateway/1.0",
        },
        timeout=10,
    )


def _is_missing_crypto_backend(exc: Exception) -> bool:
    message = str(exc).lower()
    return "cryptography" in message and any(
        algorithm in message for algorithm in ("rs256", "rs384", "rs512")
    )


def decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid JWT format")

    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        claims = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid JWT payload")

    if not isinstance(claims, dict):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid JWT claims")

    return claims


def _extract_audiences(claims: dict) -> set[str]:
    aud_claim = claims.get("aud")
    if isinstance(aud_claim, str) and aud_claim.strip():
        return {aud_claim.strip()}
    if isinstance(aud_claim, list):
        return {
            item.strip()
            for item in aud_claim
            if isinstance(item, str) and item.strip()
        }
    return set()


def _validate_expected_clients(claims: dict, expected_clients: list[str]) -> None:
    if not expected_clients:
        return

    audiences = _extract_audiences(claims)
    azp = claims.get("azp")

    if audiences.intersection(expected_clients):
        return
    if isinstance(azp, str) and azp.strip() in expected_clients:
        return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=(
            f"Invalid token: audience/client mismatch for {expected_clients}. "
            f"aud={claims.get('aud')}, azp={azp}"
        ),
    )


def verify_access_token(token: str) -> dict:
    settings = get_settings()
    expected_clients = list(settings.keycloak_audiences)
    for client_id in settings.keycloak_web_client_ids:
        if client_id and client_id not in expected_clients:
            expected_clients.append(client_id)
    if settings.keycloak_cli_client_id and settings.keycloak_cli_client_id not in expected_clients:
        expected_clients.append(settings.keycloak_cli_client_id)

    if not settings.keycloak_issuer or not settings.keycloak_jwks_url:
        missing = []
        if not settings.keycloak_issuer:
            missing.append("KEYCLOAK_ISSUER")
        if not settings.keycloak_jwks_url:
            missing.append("KEYCLOAK_JWKS_URL")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"JWT verifier is not configured. Missing: {', '.join(missing)}.",
        )

    decode_jwt_payload(token)

    try:
        jwks_client = get_jwks_client(settings.keycloak_jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512"],
            issuer=settings.keycloak_issuer,
            options={"verify_aud": False},
        )
        _validate_expected_clients(claims, expected_clients)
        return claims

    except PyJWTError as exc:
        if _is_missing_crypto_backend(exc):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="JWT verifier is missing RSA crypto support. Install `pyjwt[crypto]`.",
            ) from exc
        message = str(exc)
        if "Fail to fetch data from the url" in message:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    "JWT verifier could not fetch Keycloak JWKS. "
                    f"Check KEYCLOAK_JWKS_URL/network access. Source error: {message}"
                ),
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from exc


def extract_user_id(claims: dict) -> str:
    user_id = claims.get("sub") or claims.get("user_id") or claims.get("uid")
    if not isinstance(user_id, str) or not user_id.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user_id claim not found in token",
        )
    return user_id
