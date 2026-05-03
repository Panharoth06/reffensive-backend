from pathlib import Path
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.routers import tool_router, category_router, project_router, apikey_router, ai_suggestion_router
from app.routers.auth import router as auth_router
from app.routers.integrations_git_account import router as integrations_router
from app.routers.scanner import router as scanner_router
from app.routers.users import router as users_router
from app.routers.advanced_scan_router import router as advanced_scan_router
from app.routers.basic_scan_router import router as basic_scan_router
from app.routers.medium_scan_router import router as medium_scan_router
from app.routers.target_router import router as target_router
from app.routers.scanner import router as scanner_router

from app.dependencies.auth import request_has_auth_credentials, resolve_current_user_from_request
from app.quota import (
    ANON_SCAN_QUOTA_LIMIT,
    SCAN_QUOTA_LIMIT,
    build_anon_fingerprint,
    check_anon_scan_quota,
    check_scan_quota,
    get_utc_midnight_reset_timestamp,
    is_redis_healthy,
)

app = FastAPI(
    title="Auto-Offensive API Gateway",
    description="FastAPI gateway proxying requests to Go gRPC micro-services.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCAN_QUOTA_PATHS = {
    "/scans/advanced/submit",
    "/scans/basic/submit",
    "/scans/medium/submit",
}


def _scan_quota_headers(*, limit: int, remaining: int, reset_ts: int) -> dict[str, str]:
    return {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(max(0, remaining)),
        "X-RateLimit-Reset": str(reset_ts),
    }


@app.middleware("http")
async def scan_quota_middleware(request: Request, call_next):
    if request.method != "POST" or request.url.path not in SCAN_QUOTA_PATHS:
        return await call_next(request)

    if not await is_redis_healthy():
        return JSONResponse(
            status_code=503,
            content={"error": "Service temporarily unavailable"},
        )

    reset_ts = get_utc_midnight_reset_timestamp()

    try:
        current_user = await resolve_current_user_from_request(request)
    except HTTPException as exc:
        if request_has_auth_credentials(request):
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=exc.headers or None,
            )
        current_user = None

    try:
        if current_user is None:
            fingerprint = build_anon_fingerprint(request)
            limit = ANON_SCAN_QUOTA_LIMIT
            remaining, exceeded = await check_anon_scan_quota(fingerprint)
        else:
            limit = SCAN_QUOTA_LIMIT
            remaining, exceeded = await check_scan_quota(current_user.user_id)
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"error": "Service temporarily unavailable"},
        )
    quota_headers = _scan_quota_headers(limit=limit, remaining=remaining, reset_ts=reset_ts)

    if exceeded:
        if current_user is None:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Daily scan quota exceeded. Please register for more scans.",
                    "retry_after": reset_ts,
                },
                headers=quota_headers,
            )

        retry_after = max(0, reset_ts - int(time.time()))
        detail = (
            f"Daily scan quota exceeded. You have reached the limit of {SCAN_QUOTA_LIMIT} "
            "scan submissions for today. Please try again after the quota resets."
        )
        return JSONResponse(
            status_code=429,
            content={
                "error": "Daily scan quota exceeded",
                "detail": detail,
                "limit": SCAN_QUOTA_LIMIT,
                "remaining": 0,
                "reset_at": reset_ts,
                "retry_after": retry_after,
            },
            headers={**quota_headers, "Retry-After": str(retry_after)},
        )

    request.state.quota_remaining = remaining
    response = await call_next(request)
    for header_name, header_value in quota_headers.items():
        response.headers[header_name] = header_value
    return response

app.include_router(project_router.router)
app.include_router(target_router)
app.include_router(apikey_router.router)
app.include_router(tool_router.router)
app.include_router(category_router.router)
app.include_router(advanced_scan_router)
app.include_router(basic_scan_router)
app.include_router(medium_scan_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(integrations_router)
app.include_router(ai_suggestion_router.router)
app.include_router(ai_suggestion_router.legacy_router)
app.include_router(ai_suggestion_router.internal_router, include_in_schema=False)
app.include_router(scanner_router)

@app.get("/health", tags=["Health"])
def health() -> dict:
    return {"status": "ok"}
