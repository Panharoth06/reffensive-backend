import functools
from dataclasses import dataclass

import httpx
from fastapi import HTTPException, status

from app.core.config import get_settings


@dataclass(frozen=True)
class KeycloakIssuerParts:
    base_url: str
    realm: str


def _parse_issuer(issuer: str) -> KeycloakIssuerParts:
    marker = "/realms/"
    if marker not in issuer:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid KEYCLOAK_ISSUER. Expected format: <base>/realms/<realm>",
        )

    base_url, realm = issuer.split(marker, 1)
    cleaned_base = base_url.rstrip("/")
    cleaned_realm = realm.strip().strip("/")
    if not cleaned_base or not cleaned_realm:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid KEYCLOAK_ISSUER. Missing base URL or realm.",
        )

    return KeycloakIssuerParts(base_url=cleaned_base, realm=cleaned_realm)


class KeycloakAdminClient:
    def __init__(self) -> None:
        settings = get_settings()
        self._settings = settings
        self._static_token = settings.keycloak_admin_token.strip()
        if not settings.keycloak_issuer:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Missing KEYCLOAK_ISSUER",
            )
        has_static_token = bool(self._static_token)
        has_credentials = bool(settings.keycloak_admin_client_id and settings.keycloak_admin_client_secret)
        if not has_static_token and not has_credentials:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Missing KEYCLOAK_ADMIN_TOKEN or KEYCLOAK_ADMIN_CLIENT_ID/KEYCLOAK_ADMIN_CLIENT_SECRET",
            )

        issuer = _parse_issuer(settings.keycloak_issuer)
        self._base_url = issuer.base_url
        self._realm = issuer.realm
        self._token_url = f"{self._base_url}/realms/{self._realm}/protocol/openid-connect/token"
        self._realm_url = f"{self._base_url}/admin/realms/{self._realm}"
        self._users_url = f"{self._base_url}/admin/realms/{self._realm}/users"
        self._roles_url = f"{self._realm_url}/roles"

    def _get_admin_access_token(self) -> str:
        if self._static_token:
            return self._static_token

        form_data = {
            "grant_type": "client_credentials",
            "client_id": self._settings.keycloak_admin_client_id,
            "client_secret": self._settings.keycloak_admin_client_secret,
        }
        try:
            response = httpx.post(self._token_url, data=form_data, timeout=10.0)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to get Keycloak admin token: {exc}",
            ) from exc

        token = response.json().get("access_token")
        if not token:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Keycloak admin token response is missing access_token",
            )
        return token

    def _build_auth_headers(self, access_token: str, *, include_json: bool = False) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {access_token}"}
        if include_json:
            headers["Content-Type"] = "application/json"
        return headers

    def create_user(
        self,
        *,
        username: str,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        enabled: bool = True,
    ) -> str:
        access_token = self._get_admin_access_token()
        payload = {
            "username": username,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": enabled,
            "emailVerified": True,
            "credentials": [
                {
                    "type": "password",
                    "value": password,
                    "temporary": False,
                }
            ],
            "requiredActions": [],
        }
        headers = self._build_auth_headers(access_token, include_json=True)
        try:
            response = httpx.post(self._users_url, json=payload, headers=headers, timeout=10.0)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text.strip() or str(exc)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Keycloak create user failed: {detail}",
            ) from exc
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Keycloak create user request failed: {exc}",
            ) from exc

        location = response.headers.get("Location", "").rstrip("/")
        if location and "/" in location:
            user_id = location.rsplit("/", 1)[-1]
            if user_id:
                return user_id

        found = self.find_user_by_username(username)
        if found:
            return found

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Keycloak created user but user_id could not be resolved",
        )

    def find_user_by_username(self, username: str) -> str | None:
        access_token = self._get_admin_access_token()
        headers = self._build_auth_headers(access_token)
        try:
            response = httpx.get(
                self._users_url,
                headers=headers,
                params={"username": username, "exact": "true"},
                timeout=10.0,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return None

        items = response.json()
        if not isinstance(items, list):
            return None
        for item in items:
            if isinstance(item, dict) and item.get("username") == username and item.get("id"):
                return str(item["id"])
        return None

    def delete_user(self, user_id: str) -> None:
        cleaned = user_id.strip()
        if not cleaned:
            return
        access_token = self._get_admin_access_token()
        headers = self._build_auth_headers(access_token)
        try:
            response = httpx.delete(f"{self._users_url}/{cleaned}", headers=headers, timeout=10.0)
            if response.status_code in (204, 404):
                return
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Keycloak rollback delete failed: {exc}",
            ) from exc

    def list_federated_identities(self, user_id: str) -> list[dict]:
        cleaned = user_id.strip()
        if not cleaned:
            return []

        access_token = self._get_admin_access_token()
        headers = self._build_auth_headers(access_token)
        url = f"{self._users_url}/{cleaned}/federated-identity"
        try:
            response = httpx.get(url, headers=headers, timeout=10.0)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return []
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Keycloak federated identity lookup failed: {exc}",
            ) from exc
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Keycloak federated identity request failed: {exc}",
            ) from exc

        payload = response.json()
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, dict)]

    def get_realm_role(self, role_name: str) -> dict:
        cleaned_role_name = role_name.strip()
        if not cleaned_role_name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role name is required",
            )

        access_token = self._get_admin_access_token()
        headers = self._build_auth_headers(access_token)
        try:
            response = httpx.get(f"{self._roles_url}/{cleaned_role_name}", headers=headers, timeout=10.0)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Keycloak realm role not found: {cleaned_role_name}",
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Keycloak role lookup failed: {exc}",
            ) from exc
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Keycloak role lookup request failed: {exc}",
            ) from exc

        payload = response.json()
        if not isinstance(payload, dict) or not payload.get("name"):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Keycloak returned an invalid role payload for: {cleaned_role_name}",
            )
        return payload

    def assign_realm_roles(self, user_id: str, role_names: list[str]) -> None:
        cleaned_user_id = user_id.strip()
        cleaned_role_names = [role_name.strip() for role_name in role_names if isinstance(role_name, str) and role_name.strip()]
        if not cleaned_user_id or not cleaned_role_names:
            return

        role_representations = [self.get_realm_role(role_name) for role_name in cleaned_role_names]

        access_token = self._get_admin_access_token()
        headers = self._build_auth_headers(access_token, include_json=True)
        url = f"{self._users_url}/{cleaned_user_id}/role-mappings/realm"
        try:
            response = httpx.post(url, json=role_representations, headers=headers, timeout=10.0)
            if response.status_code in (200, 204):
                return
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text.strip() or str(exc)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Keycloak role assignment failed: {detail}",
            ) from exc
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Keycloak role assignment request failed: {exc}",
            ) from exc

    def assign_realm_role(self, user_id: str, role_name: str) -> None:
        self.assign_realm_roles(user_id, [role_name])


@functools.lru_cache(maxsize=1)
def get_keycloak_admin_client() -> KeycloakAdminClient:
    return KeycloakAdminClient()
