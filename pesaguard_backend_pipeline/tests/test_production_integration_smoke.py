"""Unit tests for the read-only production integration smoke checker."""
from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "operations" / "production_integration_smoke.py"
SPEC = importlib.util.spec_from_file_location("production_integration_smoke", SCRIPT)
assert SPEC and SPEC.loader
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def configure_minimal_environment(monkeypatch):
    monkeypatch.setenv("PESAGUARD_BASE_URL", "https://api.example.invalid")
    monkeypatch.delenv("PESAGUARD_AUTHENTICATED_READ_PATH", raising=False)
    monkeypatch.delenv("PESAGUARD_SMOKE_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    monkeypatch.delenv("PESAGUARD_REQUIRE_OTEL", raising=False)
    monkeypatch.delenv("PESAGUARD_SMOKE_TIMEOUT_SECONDS", raising=False)


def fake_healthy_request(url, token=None, timeout=10.0):
    if url.endswith("/public/status"):
        return 200, {"overall": {"status": "operational"}}, 12
    if url.endswith("/livez"):
        return 200, {"status": "alive"}, 4
    return 200, {"status": "ok"}, 8


def test_smoke_requires_a_base_url(monkeypatch, capsys):
    monkeypatch.delenv("PESAGUARD_BASE_URL", raising=False)
    assert smoke.main() == 2
    assert "PESAGUARD_BASE_URL" in capsys.readouterr().out


def test_smoke_rejects_base_url_with_credentials_or_query(monkeypatch, capsys):
    for value in ("https://user:secret@example.invalid", "https://example.invalid?token=secret", "file:///tmp/api"):
        monkeypatch.setenv("PESAGUARD_BASE_URL", value)
        assert smoke.main() == 2
    output = capsys.readouterr().out
    assert "secret" not in output
    assert "without credentials" in output


def test_smoke_rejects_invalid_timeout(monkeypatch, capsys):
    configure_minimal_environment(monkeypatch)
    for value in ("NaN", "inf", "0", "-1", "61", "not-a-number"):
        monkeypatch.setenv("PESAGUARD_SMOKE_TIMEOUT_SECONDS", value)
        assert smoke.main() == 2
    assert "SMOKE_TIMEOUT_SECONDS" in capsys.readouterr().out


def test_smoke_checks_actual_liveness_readiness_and_public_status_contracts(monkeypatch, capsys):
    configure_minimal_environment(monkeypatch)
    monkeypatch.setattr(smoke, "request", fake_healthy_request)

    assert smoke.main() == 0
    output = capsys.readouterr().out
    assert "PASS liveness" in output
    assert "PASS readiness" in output
    assert "PASS public status" in output
    assert "Smoke result: PASS" in output


def test_smoke_fails_on_degraded_readiness_even_with_http_200(monkeypatch, capsys):
    configure_minimal_environment(monkeypatch)

    def fake_request(url, token=None, timeout=10.0):
        if url.endswith("/health"):
            return 200, {"status": "degraded"}, 5
        return fake_healthy_request(url, token, timeout)

    monkeypatch.setattr(smoke, "request", fake_request)
    assert smoke.main() == 1
    assert "FAIL readiness: HTTP 200" in capsys.readouterr().out


def test_smoke_fails_if_public_status_contract_is_not_operational(monkeypatch, capsys):
    configure_minimal_environment(monkeypatch)

    def fake_request(url, token=None, timeout=10.0):
        if url.endswith("/public/status"):
            return 200, {"overall": {"status": "degraded"}}, 5
        return fake_healthy_request(url, token, timeout)

    monkeypatch.setattr(smoke, "request", fake_request)
    assert smoke.main() == 1
    assert "FAIL public status: HTTP 200" in capsys.readouterr().out


def test_smoke_never_prints_malformed_sentry_dsn(monkeypatch, capsys):
    configure_minimal_environment(monkeypatch)
    monkeypatch.setenv("SENTRY_DSN", "not-a-valid-dsn-secret")
    monkeypatch.setattr(smoke, "request", fake_healthy_request)

    assert smoke.main() == 1
    output = capsys.readouterr().out
    assert "FAIL Sentry DSN syntax" in output
    assert "not-a-valid-dsn-secret" not in output


def test_authenticated_read_requires_token(monkeypatch, capsys):
    configure_minimal_environment(monkeypatch)
    monkeypatch.setenv("PESAGUARD_AUTHENTICATED_READ_PATH", "/api/v1/dashboard/overview")
    assert smoke.main() == 2
    assert "no smoke bearer token supplied" in capsys.readouterr().out


def test_otel_endpoint_validation_does_not_claim_delivery(monkeypatch, capsys):
    configure_minimal_environment(monkeypatch)
    monkeypatch.setenv("PESAGUARD_REQUIRE_OTEL", "true")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "not-a-url")
    monkeypatch.setattr(smoke, "request", fake_healthy_request)
    assert smoke.main() == 1
    assert "FAIL OpenTelemetry endpoint configuration" in capsys.readouterr().out
