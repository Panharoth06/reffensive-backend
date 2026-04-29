from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
from fastapi import HTTPException
from fastapi.responses import JSONResponse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import main as gateway_main
import pytest
from app.dependencies.auth import CurrentUser
from app.quota import build_anon_fingerprint, check_anon_scan_quota, check_scan_quota
import app.quota as quota_module
from starlette.requests import Request


class _FakeRedis:
    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    def register_script(self, script: str):
        return SimpleNamespace(sha="quota-script-sha", script=script)

    async def evalsha(self, sha: str, numkeys: int, key: str, ttl: int, limit: int):
        current = self._counts.get(key, 0) + 1
        self._counts[key] = current
        return [current, 1 if current > int(limit) else 0]

    async def eval(self, script: str, numkeys: int, key: str, ttl: int, limit: int):
        return await self.evalsha("quota-script-sha", numkeys, key, ttl, limit)

    async def ping(self) -> bool:
        return True


def _make_current_user() -> CurrentUser:
    return CurrentUser(
        user_id="user-1",
        azp="nextjs_user",
        actor_type="web_user",
        roles={"USER"},
        scopes=set(),
        claims={"sub": "user-1"},
    )


def _patch_fake_quota_backend(monkeypatch: pytest.MonkeyPatch) -> _FakeRedis:
    fake_redis = _FakeRedis()
    monkeypatch.setattr(quota_module, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(
        quota_module,
        "_get_quota_script",
        lambda: fake_redis.register_script(quota_module.LUA_QUOTA_SCRIPT),
    )
    return fake_redis


def _make_request(
    *,
    method: str = "POST",
    path: str = "/scans/advanced/submit",
    headers: dict[str, str] | None = None,
    client: tuple[str, int] = ("203.0.113.42", 12345),
) -> Request:
    header_pairs = [
        (key.lower().encode("latin-1"), value.encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "http_version": "1.1",
        "scheme": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": header_pairs,
        "client": client,
        "server": ("testserver", 80),
        "state": {},
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_quota_allows_under_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fake_quota_backend(monkeypatch)

    remaining = 0
    exceeded = False
    for _ in range(49):
        remaining, exceeded = await check_scan_quota("user-1")

    assert remaining == 1
    assert exceeded is False


@pytest.mark.asyncio
async def test_quota_blocks_at_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fake_quota_backend(monkeypatch)

    remaining = 0
    exceeded = False
    for _ in range(51):
        remaining, exceeded = await check_scan_quota("user-1")

    assert remaining == 0
    assert exceeded is True


@pytest.mark.asyncio
async def test_quota_resets_on_new_day(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fake_quota_backend(monkeypatch)
    keys = iter(
        [
            "quota:scan:{user-1}:2026-04-12",
            "quota:scan:{user-1}:2026-04-13",
        ]
    )
    monkeypatch.setattr(
        quota_module,
        "_get_quota_key",
        lambda *, user_id, now=None: next(keys),
    )

    day_one_remaining, day_one_exceeded = await check_scan_quota("user-1")
    day_two_remaining, day_two_exceeded = await check_scan_quota("user-1")

    assert day_one_remaining == 49
    assert day_one_exceeded is False
    assert day_two_remaining == 49
    assert day_two_exceeded is False


@pytest.mark.asyncio
async def test_anon_quota_allows_under_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fake_quota_backend(monkeypatch)

    remaining = 0
    exceeded = False
    for _ in range(2):
        remaining, exceeded = await check_anon_scan_quota("fingerprint-1")

    assert remaining == 1
    assert exceeded is False


@pytest.mark.asyncio
async def test_anon_quota_blocks_at_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fake_quota_backend(monkeypatch)

    remaining = 0
    exceeded = False
    for _ in range(4):
        remaining, exceeded = await check_anon_scan_quota("fingerprint-1")

    assert remaining == 0
    assert exceeded is True


@pytest.mark.asyncio
async def test_anon_quota_different_fingerprints_are_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fake_quota_backend(monkeypatch)

    fingerprint_a_remaining = 0
    fingerprint_a_exceeded = False
    for _ in range(4):
        fingerprint_a_remaining, fingerprint_a_exceeded = await check_anon_scan_quota("fingerprint-a")

    fingerprint_b_remaining, fingerprint_b_exceeded = await check_anon_scan_quota("fingerprint-b")

    assert fingerprint_a_remaining == 0
    assert fingerprint_a_exceeded is True
    assert fingerprint_b_remaining == 2
    assert fingerprint_b_exceeded is False


@pytest.mark.asyncio
async def test_anon_and_auth_quotas_are_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fake_quota_backend(monkeypatch)

    anon_remaining = 0
    anon_exceeded = False
    for _ in range(4):
        anon_remaining, anon_exceeded = await check_anon_scan_quota("fingerprint-1")

    auth_remaining, auth_exceeded = await check_scan_quota("user-1")

    assert anon_remaining == 0
    assert anon_exceeded is True
    assert auth_remaining == 49
    assert auth_exceeded is False


def test_build_anon_fingerprint_uses_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANON_FINGERPRINT_OVERRIDE", "test-fp-1")

    request = _make_request()

    assert build_anon_fingerprint(request) == "test-fp-1"


def test_build_anon_fingerprint_hashes_signals(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANON_FINGERPRINT_OVERRIDE", raising=False)
    request = _make_request(
        headers={
            "X-JA3-Fingerprint": "ja3-1",
            "User-Agent": "scanner-ui/1.0",
            "Accept-Language": "en-US,en;q=0.9",
        },
        client=("203.0.113.42", 12345),
    )

    fingerprint = build_anon_fingerprint(request)
    expected = hashlib.sha256(
        "ja3-1:203.0.113.0/24:scanner-ui/1.0:en-US,en;q=0.9".encode()
    ).hexdigest()

    assert fingerprint == expected
    assert len(fingerprint) == 64
    int(fingerprint, 16)


async def _auth_side_effect(request) -> CurrentUser:
    current_user = _make_current_user()
    request.state.current_user = current_user
    return current_user


@pytest.mark.asyncio
async def test_middleware_returns_429_when_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway_main, "resolve_current_user_from_request", _auth_side_effect)
    monkeypatch.setattr(gateway_main, "is_redis_healthy", AsyncMock(return_value=True))
    monkeypatch.setattr(gateway_main, "check_scan_quota", AsyncMock(return_value=(0, True)))

    transport = httpx.ASGITransport(app=gateway_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/scans/advanced/submit",
            json={"project_id": "project-1", "command": "nmap -sV scanme.nmap.org"},
        )

    assert response.status_code == 429
    assert response.json()["error"] == "Daily scan quota exceeded"
    assert "Daily scan quota exceeded." in response.json()["detail"]
    assert response.json()["limit"] == 50
    assert response.json()["remaining"] == 0
    assert response.headers["X-RateLimit-Limit"] == "50"
    assert response.headers["X-RateLimit-Remaining"] == "0"
    assert "X-RateLimit-Reset" in response.headers
    assert "Retry-After" in response.headers


@pytest.mark.asyncio
async def test_middleware_returns_503_when_redis_down(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway_main, "resolve_current_user_from_request", _auth_side_effect)
    monkeypatch.setattr(gateway_main, "is_redis_healthy", AsyncMock(return_value=False))

    transport = httpx.ASGITransport(app=gateway_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/scans/advanced/submit",
            json={"project_id": "project-1", "command": "nmap -sV scanme.nmap.org"},
        )

    assert response.status_code == 503
    assert response.json() == {"error": "Service temporarily unavailable"}


@pytest.mark.asyncio
async def test_middleware_anon_returns_429_when_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gateway_main,
        "resolve_current_user_from_request",
        AsyncMock(side_effect=HTTPException(status_code=401, detail="Missing Bearer token")),
    )
    monkeypatch.setattr(gateway_main, "is_redis_healthy", AsyncMock(return_value=True))
    monkeypatch.setattr(gateway_main, "get_utc_midnight_reset_timestamp", lambda: 1_760_000_000)
    monkeypatch.setattr(gateway_main, "build_anon_fingerprint", lambda request: "fingerprint-1")
    monkeypatch.setattr(gateway_main, "check_anon_scan_quota", AsyncMock(return_value=(0, True)))

    request = _make_request()

    async def call_next(_request: Request):
        raise AssertionError("call_next should not be reached when anon quota is exceeded")

    response = await gateway_main.scan_quota_middleware(request, call_next)
    payload = json.loads(response.body)

    assert response.status_code == 429
    assert payload["error"] == "Daily scan quota exceeded. Please register for more scans."
    assert payload["retry_after"] == 1_760_000_000
    assert response.headers["X-RateLimit-Limit"] == "3"
    assert response.headers["X-RateLimit-Remaining"] == "0"
    assert response.headers["X-RateLimit-Reset"] == "1760000000"


@pytest.mark.asyncio
async def test_middleware_preserves_auth_error_when_auth_header_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gateway_main,
        "resolve_current_user_from_request",
        AsyncMock(side_effect=HTTPException(status_code=401, detail="Invalid token format")),
    )
    monkeypatch.setattr(gateway_main, "is_redis_healthy", AsyncMock(return_value=True))

    request = _make_request(headers={"Authorization": "Bearer a.b.c"})

    async def call_next(_request: Request):
        raise AssertionError("call_next should not be reached when auth fails")

    response = await gateway_main.scan_quota_middleware(request, call_next)
    payload = json.loads(response.body)

    assert response.status_code == 401
    assert payload == {"detail": "Invalid token format"}


@pytest.mark.asyncio
async def test_middleware_anon_passes_when_under_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gateway_main,
        "resolve_current_user_from_request",
        AsyncMock(side_effect=HTTPException(status_code=401, detail="Missing Bearer token")),
    )
    monkeypatch.setattr(gateway_main, "is_redis_healthy", AsyncMock(return_value=True))
    monkeypatch.setattr(gateway_main, "get_utc_midnight_reset_timestamp", lambda: 1_760_000_000)
    monkeypatch.setattr(gateway_main, "build_anon_fingerprint", lambda request: "fingerprint-1")
    monkeypatch.setattr(gateway_main, "check_anon_scan_quota", AsyncMock(return_value=(2, False)))

    request = _make_request()

    async def call_next(inner_request: Request):
        assert inner_request.state.quota_remaining == 2
        return JSONResponse(status_code=200, content={"ok": True})

    response = await gateway_main.scan_quota_middleware(request, call_next)
    payload = json.loads(response.body)

    assert response.status_code == 200
    assert payload == {"ok": True}
    assert response.headers["X-RateLimit-Limit"] == "3"
    assert response.headers["X-RateLimit-Remaining"] == "2"
    assert response.headers["X-RateLimit-Reset"] == "1760000000"


@pytest.mark.asyncio
async def test_headers_present_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, int | None] = {}

    monkeypatch.setattr(gateway_main, "resolve_current_user_from_request", _auth_side_effect)
    monkeypatch.setattr(gateway_main, "is_redis_healthy", AsyncMock(return_value=True))
    monkeypatch.setattr(gateway_main, "check_scan_quota", AsyncMock(return_value=(49, False)))
    request = _make_request()

    async def call_next(inner_request: Request):
        captured["quota_remaining"] = inner_request.state.quota_remaining
        return JSONResponse(status_code=200, content={"ok": True})

    response = await gateway_main.scan_quota_middleware(request, call_next)
    payload = json.loads(response.body)

    assert response.status_code == 200
    assert payload == {"ok": True}
    assert response.headers["X-RateLimit-Limit"] == "50"
    assert response.headers["X-RateLimit-Remaining"] == "49"
    assert "X-RateLimit-Reset" in response.headers
    assert captured["quota_remaining"] == 49
