"""Unit tests for the read-only production integration smoke checker."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "operations" / "production_integration_smoke.py"
SPEC = importlib.util.spec_from_file_location("production_integration_smoke", SCRIPT)
assert SPEC and SPEC.loader
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def test_smoke_requires_a_base_url(monkeypatch, capsys):
    monkeypatch.delenv("PESAGUARD_BASE_URL", raising=False)
    assert smoke.main() == 2
    assert "PESAGUARD_BASE_URL" in capsys.readouterr().out


def test_smoke_checks_liveness_readiness_and_public_status(monkeypatch, capsys):
    monkeypatch.setenv("PESAGUARD_BASE_URL", "https://api.example.invalid")
    monkeypatch.delenv("PESAGUARD_AUTHENTICATED_READ_PATH", raising=False)
    monkeypatch.delenv("PESAGUARD_SMOKE_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    monkeypatch.delenv("PESAGUARD_REQUIRE_OTEL", raising=False)
    monkeypatch.setattr(
        smoke,
        "request",
        lambda url, token=None, timeout=10.0: (
            200,
            {"status": "ok"},
            12,
        ),
    )

    assert smoke.main() == 0
    output = capsys.readouterr().out
    assert "PASS liveness" in output
    assert "PASS readiness" in output
    assert "PASS public status" in output
    assert "Smoke result: PASS" in output


def test_smoke_fails_on_degraded_readiness_even_with_http_200(monkeypatch, capsys):
    monkeypatch.setenv("PESAGUARD_BASE_URL", "https://api.example.invalid")
    monkeypatch.delenv("PESAGUARD_AUTHENTICATED_READ_PATH", raising=False)
    monkeypatch.delenv("PESAGUARD_SMOKE_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    monkeypatch.delenv("PESAGUARD_REQUIRE_OTEL", raising=False)

    def fake_request(url, token=None, timeout=10.0):
        if url.endswith("/health"):
            return 200, {"status": "degraded"}, 5
        return 200, {"status": "ok"}, 5

    monkeypatch.setattr(smoke, "request", fake_request)
    assert smoke.main() == 1
    assert "FAIL readiness: HTTP 200" in capsys.readouterr().out


def test_smoke_never_prints_malformed_sentry_dsn(monkeypatch, capsys):
    monkeypatch.setenv("PESAGUARD_BASE_URL", "https://api.example.invalid")
    monkeypatch.setenv("SENTRY_DSN", "not-a-valid-dsn-secret")
    monkeypatch.delenv("PESAGUARD_AUTHENTICATED_READ_PATH", raising=False)
    monkeypatch.delenv("PESAGUARD_SMOKE_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("PESAGUARD_REQUIRE_OTEL", raising=False)
    monkeypatch.setattr(smoke, "request", lambda *args, **kwargs: (200, {"status": "ok"}, 1))

    assert smoke.main() == 1
    output = capsys.readouterr().out
    assert "FAIL Sentry DSN syntax" in output
    assert "not-a-valid-dsn-secret" not in output


def test_authenticated_read_requires_token(monkeypatch, capsys):
    monkeypatch.setenv("PESAGUARD_BASE_URL", "https://api.example.invalid")
    monkeypatch.setenv("PESAGUARD_AUTHENTICATED_READ_PATH", "/api/v1/dashboard/overview")
    monkeypatch.delenv("PESAGUARD_SMOKE_BEARER_TOKEN", raising=False)
    assert smoke.main() == 2
    assert "no smoke bearer token supplied" in capsys.readouterr().out
