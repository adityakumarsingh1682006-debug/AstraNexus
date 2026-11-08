import sys
import types
from pathlib import Path

# ==============================================================================
# Dynamic Environment & Import Resolution Bootstrap
# Resolves package hierarchy whether deployed via:
# - Monorepo root (Local dev & test runners: `from backend.app...`)
# - Standalone directory / Serverless container (/var/task where `backend/` is root)
# ==============================================================================
_main_dir = Path(__file__).resolve().parent          # .../app
_backend_dir = _main_dir.parent                     # .../backend (or /var/task)
_repo_root = _backend_dir.parent                    # .../repo_root

for _p in [str(_backend_dir), str(_repo_root), str(_main_dir)]:
    if _p and _p not in sys.path:
        sys.path.insert(0, _p)

if "backend" not in sys.modules:
    try:
        import backend  # noqa: F401
    except ImportError:
        _backend_pkg = types.ModuleType("backend")
        _backend_pkg.__path__ = [str(_backend_dir)]
        sys.modules["backend"] = _backend_pkg

if "app" in sys.modules and "backend.app" not in sys.modules:
    sys.modules["backend.app"] = sys.modules["app"]
    if hasattr(sys.modules.get("backend"), "__dict__"):
        sys.modules["backend"].app = sys.modules["app"]

import time
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from backend.app.core.config import settings
from backend.app.core.exceptions import (
    SSRFSecurityViolation,
    TargetResolutionError,
    ScanTimeoutError,
    TargetPayloadTooLargeError,
)
from backend.app.api.v1.router import api_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AstraNexus: AI-powered Digital Trust and Threat Intelligence Platform API",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pure ASGI Middleware: High-Performance Security & Timing Headers
class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        start_time = time.time()

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                process_time = time.time() - start_time
                headers = list(message.get("headers", []))
                headers.append((b"x-process-time", f"{process_time:.4f}s".encode("latin1")))
                headers.append((b"x-content-type-options", b"nosniff"))
                headers.append((b"x-frame-options", b"DENY"))
                headers.append((b"x-xss-protection", b"1; mode=block"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


app.add_middleware(SecurityHeadersMiddleware)


# Global Exception Handlers for Security Violations
@app.exception_handler(SSRFSecurityViolation)
async def ssrf_exception_handler(request: Request, exc: SSRFSecurityViolation):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": "SSRF_VIOLATION",
            "message": exc.message,
            "blocked": True,
            "path": request.url.path,
        },
    )


@app.exception_handler(TargetResolutionError)
async def dns_exception_handler(request: Request, exc: TargetResolutionError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "DNS_RESOLUTION_ERROR",
            "message": exc.message,
            "path": request.url.path,
        },
    )


@app.exception_handler(ScanTimeoutError)
async def timeout_exception_handler(request: Request, exc: ScanTimeoutError):
    return JSONResponse(
        status_code=status.HTTP_504_GATEWAY_TIMEOUT,
        content={
            "error": "SCAN_TIMEOUT",
            "message": exc.message,
            "path": request.url.path,
        },
    )


@app.exception_handler(TargetPayloadTooLargeError)
async def payload_too_large_handler(request: Request, exc: TargetPayloadTooLargeError):
    return JSONResponse(
        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        content={
            "error": "PAYLOAD_TOO_LARGE",
            "message": exc.message,
            "path": request.url.path,
        },
    )


# Register API v1 routes
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", tags=["Root"])
async def root():
    return {
        "platform": "AstraNexus",
        "tagline": "AI-Powered Digital Trust & Threat Intelligence",
        "version": settings.VERSION,
        "docs_url": f"{settings.API_V1_STR}/docs",
        "health_url": f"{settings.API_V1_STR}/health",
    }


@app.get("/favicon.ico", include_in_schema=False)
@app.get("/icon.svg", include_in_schema=False)
async def favicon():
    return Response(status_code=status.HTTP_204_NO_CONTENT)
