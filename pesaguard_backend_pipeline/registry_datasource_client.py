"""Server-side client for PesaGuard Datasource registry lookups.

Credentials are read only from the backend process environment. This module
never logs identifiers, response bodies, or API-key material.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

import requests


class DatasourceNotConfigured(RuntimeError):
    """Raised when the registry datasource integration is not configured."""


class DatasourceUpstreamError(RuntimeError):
    """Safe upstream failure that carries a status/code without secret data."""

    def __init__(self, message: str, status_code: int = 502, code: str = "DATASOURCE_UPSTREAM_ERROR"):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


def _settings() -> tuple[str, str, str]:
    base_url = os.getenv("PESAGUARD_DATASOURCE_BASE_URL", "").strip().rstrip("/")
    api_key = os.getenv("PESAGUARD_DATASOURCE_API_KEY", "").strip()
    environment = os.getenv("PESAGUARD_DATASOURCE_ENVIRONMENT", "sandbox").strip().lower()
    if not base_url or not api_key:
        raise DatasourceNotConfigured("Datasource registry lookup is not configured.")
    if environment not in {"sandbox", "production"}:
        raise DatasourceNotConfigured("Datasource environment must be sandbox or production.")
    expected_prefix = "pg_sandbox_" if environment == "sandbox" else "pg_live_"
    if not api_key.startswith(expected_prefix):
        raise DatasourceNotConfigured("Datasource API key prefix does not match the configured environment.")
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise DatasourceNotConfigured("Datasource base URL must be a valid HTTP(S) URL.")
    if environment == "production" and parsed.scheme != "https":
        raise DatasourceNotConfigured("Production Datasource connections require HTTPS.")
    return base_url, api_key, environment


def lookup_registry_record(*, registration_number: str | None = None, tax_pin: str | None = None,
                           correlation_id: str | None = None) -> dict:
    """Look up one identifier and return the Datasource's evidence payload."""
    if bool(registration_number) == bool(tax_pin):
        raise ValueError("Provide exactly one registration number or tax PIN.")
    identifier = registration_number if registration_number is not None else tax_pin
    if not isinstance(identifier, str) or not identifier.strip() or len(identifier.strip()) > 200:
        raise ValueError("The registry identifier must be a non-empty string of at most 200 characters.")

    base_url, api_key, _environment = _settings()
    params = {"reg_no": identifier.strip()} if registration_number is not None else {"tax_pin": identifier.strip()}
    headers = {
        "X-API-Key": api_key,
        "X-Caller-Service": "pesaguard-backend",
    }
    if correlation_id:
        headers["X-Correlation-ID"] = correlation_id[:100]

    try:
        response = requests.get(
            f"{base_url}/api/v1/registry/lookup",
            params=params,
            headers=headers,
            timeout=(2.0, 8.0),
            allow_redirects=False,
        )
    except requests.Timeout as exc:
        raise DatasourceUpstreamError("Datasource registry lookup timed out.", 504, "DATASOURCE_TIMEOUT") from exc
    except requests.RequestException as exc:
        raise DatasourceUpstreamError("Datasource registry lookup is unavailable.", 502, "DATASOURCE_UNAVAILABLE") from exc

    if 300 <= response.status_code < 400:
        raise DatasourceUpstreamError("Datasource returned an unexpected redirect.", 502, "DATASOURCE_REDIRECT_REJECTED")
    try:
        payload = response.json()
    except ValueError as exc:
        raise DatasourceUpstreamError("Datasource returned an invalid response.", 502, "DATASOURCE_INVALID_RESPONSE") from exc

    if response.status_code == 403:
        detail = payload.get("detail", {}) if isinstance(payload, dict) else {}
        code = detail.get("code") if isinstance(detail, dict) else None
        if code == "API_KEY_ENVIRONMENT_MISMATCH":
            raise DatasourceUpstreamError("Datasource rejected the key for this environment.", 502, code)
        if code == "API_KEY_SCOPE_DENIED":
            raise DatasourceUpstreamError("Datasource API key lacks registry read permission.", 502, code)
        raise DatasourceUpstreamError("Datasource denied the registry lookup.", 502, "DATASOURCE_ACCESS_DENIED")
    if response.status_code >= 500:
        raise DatasourceUpstreamError("Datasource registry service is temporarily unavailable.", 502, "DATASOURCE_UNAVAILABLE")
    if response.status_code >= 400:
        raise DatasourceUpstreamError("Datasource rejected the registry lookup request.", 502, "DATASOURCE_REQUEST_REJECTED")
    if not isinstance(payload, dict) or payload.get("status") not in {"record_found", "not_found"}:
        raise DatasourceUpstreamError("Datasource response did not match the registry lookup contract.", 502, "DATASOURCE_INVALID_RESPONSE")
    return payload
