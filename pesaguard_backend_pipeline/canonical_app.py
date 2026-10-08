"""Canonical PesaGuard API entry point."""

from __future__ import annotations

import os

import uvicorn

from .fastapi_app import app


if __name__ == "__main__":
    uvicorn.run(
        "pesaguard_backend_pipeline.fastapi_app:app",
        host=os.getenv("PESAGUARD_BIND_HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "5001")),
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )
