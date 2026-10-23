from types import SimpleNamespace

import pytest
import requests

from registry_datasource_client import (
    DatasourceNotConfigured,
    DatasourceUpstreamError,
    lookup_registry_record,
)


def _configure(monkeypatch, *, base_url="http://127.0.0.1:8000", api_key="pg_sandbox_test-secret", environment="sandbox"):
    monkeypatch.setenv("PESAGUARD_DATASOURCE_BASE_URL", base_url)
    monkeypatch.setenv("PESAGUARD_DATASOURCE_API_KEY", api_key)
    monkeypatch.setenv("PESAGUARD_DATASOURCE_ENVIRONMENT", environment)


def test_lookup_requires_exactly_one_identifier():
    with pytest.raises(ValueError, match="exactly one"):
        lookup_registry_record()
    with pytest.raises(ValueError, match="exactly one"):
        lookup_registry_record(registration_number="ABC-123", tax_pin="A12345678")


def test_lookup_refuses_missing_configuration(monkeypatch):
    monkeypatch.delenv("PESAGUARD_DATASOURCE_BASE_URL", raising=False)
    monkeypatch.delenv("PESAGUARD_DATASOURCE_API_KEY", raising=False)
    with pytest.raises(DatasourceNotConfigured):
        lookup_registry_record(registration_number="ABC-123")


def test_lookup_refuses_wrong_environment_key_prefix(monkeypatch):
    _configure(monkeypatch, api_key="pg_sandbox_test-secret", environment="production", base_url="https://datasource.example.test")
    with pytest.raises(DatasourceNotConfigured, match="prefix"):
        lookup_registry_record(registration_number="ABC-123")


def test_production_requires_https(monkeypatch):
    _configure(monkeypatch, api_key="pg_live_test-secret", environment="production", base_url="http://datasource.example.test")
    with pytest.raises(DatasourceNotConfigured, match="HTTPS"):
        lookup_registry_record(registration_number="ABC-123")


def test_lookup_calls_datasource_server_side_and_returns_payload(monkeypatch):
    _configure(monkeypatch)
    observed = {}

    def fake_get(url, **kwargs):
        observed["url"] = url
        observed.update(kwargs)
        return SimpleNamespace(
            status_code=200,
            json=lambda: {
                "status": "record_found",
                "found": True,
                "organization": {"legal_name": "Example Limited"},
                "source": "internal_registry",
            },
        )

    monkeypatch.setattr("registry_datasource_client.requests.get", fake_get)
    result = lookup_registry_record(registration_number=" ABC-123 ", correlation_id="req-123")

    assert result["status"] == "record_found"
    assert observed["url"] == "http://127.0.0.1:8000/api/v1/registry/lookup"
    assert observed["params"] == {"reg_no": "ABC-123"}
    assert observed["headers"]["X-API-Key"] == "pg_sandbox_test-secret"
    assert observed["headers"]["X-Correlation-ID"] == "req-123"
    assert observed["timeout"] == (2.0, 8.0)
    assert observed["allow_redirects"] is False


def test_environment_mismatch_is_returned_as_safe_error(monkeypatch):
    _configure(monkeypatch)

    def fake_get(*args, **kwargs):
        return SimpleNamespace(
            status_code=403,
            json=lambda: {
                "detail": {
                    "code": "API_KEY_ENVIRONMENT_MISMATCH",
                    "message": "This is a sandbox API key.",
                }
            },
        )

    monkeypatch.setattr("registry_datasource_client.requests.get", fake_get)
    with pytest.raises(DatasourceUpstreamError) as caught:
        lookup_registry_record(registration_number="ABC-123")
    assert caught.value.code == "API_KEY_ENVIRONMENT_MISMATCH"
    assert caught.value.status_code == 502


def test_timeout_is_sanitized(monkeypatch):
    _configure(monkeypatch)

    def fake_get(*args, **kwargs):
        raise requests.Timeout("internal timeout details")

    monkeypatch.setattr("registry_datasource_client.requests.get", fake_get)
    with pytest.raises(DatasourceUpstreamError) as caught:
        lookup_registry_record(tax_pin="A12345678")
    assert caught.value.code == "DATASOURCE_TIMEOUT"
    assert "internal timeout details" not in str(caught.value)
