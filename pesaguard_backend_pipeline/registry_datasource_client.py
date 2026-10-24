"""Server-side client for the PesaGuard datasource registry lookup API.

This client returns imported registry evidence only. It never verifies an
organization and never logs registration numbers, tax PINs, API keys, or bodies.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import requests


class DatasourceError(RuntimeError):
    """Base class for safe, user-facing datasource integration failures."""


class DatasourceNotConfigured(DatasourceError):
    pass


class DatasourceUnavailable(DatasourceError):
    pass


class DatasourceContractError(DatasourceError):
    pass


@dataclass(frozen=True)
class DatasourceSettings:
    base_url: str
    api_key: str
    connect_timeout: float = 2.0
    read_timeout: float = 5.0

    @classmethod
    def from_env(cls) -> "DatasourceSettings":
        base_url = os.getenv("PESAGUARD_DATASOURCE_BASE_URL", "").strip().rstrip("/")
        api_key = os.getenv("PESAGUARD_DATASOURCE_API_KEY", "").strip()
        if not base_url or not api_key:
            raise DatasourceNotConfigured("Datasource registry lookup is not configured.")
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise DatasourceNotConfigured("Datasource base URL is invalid.")
        environment = os.getenv("PESAGUARD_ENVIRONMENT", os.getenv("ENVIRONMENT", "development")).strip().lower()
        local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "host.docker.internal", "registry-api"}
        if parsed.scheme != "https" and not (environment in {"development", "dev", "test", "testing"} and local_http):
            raise DatasourceNotConfigured("HTTPS is required for the configured datasource outside local development.")
        try:
            connect_timeout = float(os.getenv("PESAGUARD_DATASOURCE_CONNECT_TIMEOUT_SECONDS", "2"))
            read_timeout = float(os.getenv("PESAGUARD_DATASOURCE_READ_TIMEOUT_SECONDS", "5"))
        except ValueError as exc:
            raise DatasourceNotConfigured("Datasource timeouts must be numeric.") from exc
        if not (0.1 <= connect_timeout <= 15 and 0.1 <= read_timeout <= 30):
            raise DatasourceNotConfigured("Datasource timeouts are outside the allowed range.")
        return cls(base_url, api_key, connect_timeout, read_timeout)


class RegistryDatasourceClient:
    def __init__(self, settings: DatasourceSettings | None = None, session: Any = None):
        self.settings = settings or DatasourceSettings.from_env()
        self.session = session or requests.Session()

    def lookup(self, *, registration_number: str | None = None, tax_pin: str | None = None,
               correlation_id: str | None = None) -> dict[str, Any]:
        reg = (registration_number or "").strip()
        pin = (tax_pin or "").strip()
        if bool(reg) == bool(pin):
            raise ValueError("Provide exactly one registration number or tax PIN.")
        if len(reg or pin) > 128:
            raise ValueError("Registry identifier is too long.")
        params = {"reg_no": reg} if reg else {"tax_pin": pin}
        headers = {"X-API-Key": self.settings.api_key, "Accept": "application/json"}
        if correlation_id:
            headers["X-Correlation-ID"] = correlation_id[:100]
        try:
            response = self.session.get(
                f"{self.settings.base_url}/api/v1/registry/lookup",
                params=params,
                headers=headers,
                timeout=(self.settings.connect_timeout, self.settings.read_timeout),
            )
        except requests.RequestException as exc:
            raise DatasourceUnavailable("Datasource registry service could not be reached.") from exc
        if response.status_code in {401, 403}:
            raise DatasourceNotConfigured("Datasource rejected its server credentials.")
        if response.status_code == 429:
            raise DatasourceUnavailable("Datasource rate limit was reached.")
        if response.status_code >= 500 or response.status_code in {408, 425}:
            raise DatasourceUnavailable("Datasource registry service is temporarily unavailable.")
        if response.status_code != 200:
            raise DatasourceContractError(f"Datasource returned unexpected HTTP status {response.status_code}.")
        try:
            payload = response.json()
        except (ValueError, requests.JSONDecodeError) as exc:
            raise DatasourceContractError("Datasource returned invalid JSON.") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("found"), bool):
            raise DatasourceContractError("Datasource response did not match the registry lookup contract.")
        if payload["found"] and not isinstance(payload.get("organization"), dict):
            raise DatasourceContractError("Datasource response omitted the organization record.")
        if not payload["found"] and payload.get("organization") is not None:
            raise DatasourceContractError("Datasource returned an inconsistent not-found result.")
        # This is imported data, not an authoritative identity or business check.
        payload["evidence_only"] = True
        payload["verification_note"] = (
            "Imported registry data is evidence for review only. It does not verify the organization."
        )
        return payload
