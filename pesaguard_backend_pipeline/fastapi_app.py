"""FastAPI control plane with the existing Flask API mounted below it."""

from __future__ import annotations

import os
from typing import Any, Dict

try:
    from fastapi import FastAPI
    from fastapi.middleware.wsgi import WSGIMiddleware
    from fastapi.responses import JSONResponse
except ImportError as exc:  # pragma: no cover - exercised in dependency installation
    raise RuntimeError("FastAPI control plane requires fastapi and uvicorn dependencies") from exc

from .api.dashboard_app import create_app as create_dashboard_app
from .health import build_health_payload, sanitize_health_payload


app = FastAPI(
    title="PesaGuard Control Plane",
    version=os.getenv("PESAGUARD_RELEASE", "1"),
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.get("/livez")
def livez() -> Dict[str, str]:
    """Liveness probe: the process is up and serving. Checks no dependencies.

    Used by the container HEALTHCHECK, which runs often and must not depend on
    Kafka, Redis or Safaricom being reachable.
    """
    return {"status": "alive"}


@app.get("/health")
def health() -> JSONResponse:
    """Expose sanitized dependency states and signal database failures to probes."""
    payload = sanitize_health_payload(build_health_payload())
    return JSONResponse(payload, status_code=503 if payload.get("status") == "failed" else 200)


class _RestoreMountPrefix:
    """Preserve the mounted prefix for legacy Flask routes that include it."""

    def __init__(self, app, prefix: str) -> None:
        self.app = app
        self.prefix = prefix

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            scope = dict(scope)
            path = scope.get("path", "/")
            root_path = scope.get("root_path", "").rstrip("/")
            if root_path and path.startswith(root_path):
                path = path[len(root_path):] or "/"
            path = f"{self.prefix.rstrip('/')}/{path.lstrip('/')}"
            scope["path"] = path
            scope["root_path"] = ""
            scope["raw_path"] = scope["path"].encode("utf-8")
        await self.app(scope, receive, send)


# Authentication routes remain in their legacy Flask module; mount only their
# path prefix so their existing request hooks and security decorators execute.
from . import app_4_advanced_features as _advanced_features  # noqa: E402

app.mount(
    "/auth",
    _RestoreMountPrefix(WSGIMiddleware(_advanced_features.app), "/auth"),
)
app.mount(
    "/api/v1/auth",
    _RestoreMountPrefix(WSGIMiddleware(_advanced_features.app), "/auth"),
)
# The dashboard Flask application owns the remaining dashboard API routes.
app.mount("/", WSGIMiddleware(create_dashboard_app()))