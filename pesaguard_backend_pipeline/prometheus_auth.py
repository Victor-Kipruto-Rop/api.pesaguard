"""Authentication for Prometheus scraping on private API networks."""

from __future__ import annotations

import hmac
import logging
import os
from pathlib import Path

from flask import Request

logger = logging.getLogger("pesaguard.prometheus_auth")


def prometheus_token_matches(request: Request) -> bool:
    """Check the dedicated scrape token without weakening user-token validation."""
    authorization = request.headers.get("Authorization", "")
    scheme, _, supplied = authorization.partition(" ")
    if scheme.lower() != "bearer" or not supplied.strip():
        return False

    token_path = os.getenv("PESAGUARD_PROMETHEUS_TOKEN_FILE", "").strip()
    if not token_path:
        return False
    try:
        expected = Path(token_path).read_text(encoding="utf-8").strip()
    except OSError:
        logger.exception("Unable to read the Prometheus scrape token file")
        return False
    if not expected:
        logger.error("Prometheus scrape token file is empty")
        return False
    return hmac.compare_digest(supplied.strip(), expected)
