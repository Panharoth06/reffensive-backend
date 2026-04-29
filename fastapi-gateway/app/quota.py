from __future__ import annotations

import asyncio
import hashlib
import os
from ipaddress import ip_address
from datetime import datetime, timedelta, timezone
from pathlib import Path

import redis.asyncio as redis_async
from fastapi import Request
from redis.exceptions import NoScriptError, RedisError

try:
    from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_fixed
except ImportError:  # pragma: no cover - local fallback until dependencies are installed
    AsyncRetrying = None
    retry_if_exception_type = None
    stop_after_attempt = None
    wait_fixed = None

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0").strip() or "redis://localhost:6379/0"
SCAN_QUOTA_LIMIT = int(os.getenv("SCAN_QUOTA_LIMIT", "50"))
ANON_SCAN_QUOTA_LIMIT = int(os.getenv("ANON_SCAN_QUOTA_LIMIT", "3"))
SCAN_QUOTA_TTL_SECONDS = 86400

_lua_script_path = Path(__file__).parent / "scripts" / "quota.lua"
LUA_QUOTA_SCRIPT = _lua_script_path.read_text()

_redis_client: redis_async.Redis | None = None
_quota_script = None


def get_redis_client() -> redis_async.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis_async.from_url(
            REDIS_URL,
            decode_responses=False,
            max_connections=50,
            socket_timeout=1.0,
            retry_on_timeout=True,
        )
    return _redis_client


def _get_quota_script():
    global _quota_script
    if _quota_script is None:
        _quota_script = get_redis_client().register_script(LUA_QUOTA_SCRIPT)
    return _quota_script


def _get_quota_key(*, user_id: str, now: datetime | None = None) -> str:
    current_utc = now or datetime.now(timezone.utc)
    day_key = current_utc.astimezone(timezone.utc).date().isoformat()
    return f"quota:scan:{{{user_id}}}:{day_key}"


def _get_anon_quota_key(*, fingerprint: str, now: datetime | None = None) -> str:
    current_utc = now or datetime.now(timezone.utc)
    day_key = current_utc.astimezone(timezone.utc).date().isoformat()
    return f"quota:scan:anon:{{{fingerprint}}}:{day_key}"


def _build_client_subnet(request: Request) -> str:
    client_host = request.client.host if request.client else ""
    if not client_host:
        return ""

    try:
        client_ip = ip_address(client_host)
    except ValueError:
        return client_host

    if client_ip.version == 4:
        octets = client_ip.exploded.split(".")
        return ".".join([*octets[:3], "0"]) + "/24"

    return ":".join(client_ip.exploded.split(":")[:4])


def build_anon_fingerprint(request: Request) -> str:
    if override := os.getenv("ANON_FINGERPRINT_OVERRIDE"):
        return override

    ja3 = request.headers.get("X-JA3-Fingerprint", "")
    subnet = _build_client_subnet(request)
    user_agent = request.headers.get("User-Agent", "")
    accept_lang = request.headers.get("Accept-Language", "")
    raw = f"{ja3}:{subnet}:{user_agent}:{accept_lang}"
    return hashlib.sha256(raw.encode()).hexdigest()


def get_utc_midnight_reset_timestamp() -> int:
    now = datetime.now(timezone.utc)
    next_midnight = datetime.combine(
        now.date() + timedelta(days=1),
        datetime.min.time(),
        tzinfo=timezone.utc,
    )
    return int(next_midnight.timestamp())


async def _check_quota(quota_key: str, *, limit: int) -> tuple[int, bool]:
    redis_client = get_redis_client()
    quota_script = _get_quota_script()
    ttl = SCAN_QUOTA_TTL_SECONDS

    if AsyncRetrying is None:
        result = None
        for attempt in range(2):
            try:
                try:
                    result = await redis_client.evalsha(quota_script.sha, 1, quota_key, ttl, limit)
                except NoScriptError:
                    result = await redis_client.eval(LUA_QUOTA_SCRIPT, 1, quota_key, ttl, limit)
                break
            except (RedisError, TimeoutError, OSError):
                if attempt == 1:
                    raise
                await asyncio.sleep(0.05)
    else:
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(2),
            wait=wait_fixed(0.05),
            retry=retry_if_exception_type((RedisError, TimeoutError, OSError)),
            reraise=True,
        ):
            with attempt:
                try:
                    result = await redis_client.evalsha(quota_script.sha, 1, quota_key, ttl, limit)
                except NoScriptError:
                    result = await redis_client.eval(LUA_QUOTA_SCRIPT, 1, quota_key, ttl, limit)

    count = int(result[0])
    exceeded = bool(int(result[1]))
    remaining = max(0, limit - count)
    return remaining, exceeded


async def check_scan_quota(user_id: str) -> tuple[int, bool]:
    return await _check_quota(_get_quota_key(user_id=user_id), limit=SCAN_QUOTA_LIMIT)


async def check_anon_scan_quota(fingerprint: str) -> tuple[int, bool]:
    return await _check_quota(_get_anon_quota_key(fingerprint=fingerprint), limit=ANON_SCAN_QUOTA_LIMIT)


async def is_redis_healthy() -> bool:
    try:
        await get_redis_client().ping()
        return True
    except Exception:
        return False
