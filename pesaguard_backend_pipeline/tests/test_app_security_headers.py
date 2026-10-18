"""Regression tests for baseline API response security headers."""

from __future__ import annotations

from flask import Response

import app as webhook_app


def test_security_headers_are_added_to_api_responses(monkeypatch):
    monkeypatch.setattr(webhook_app, "get_correlation_id", lambda: "corr-test")
    monkeypatch.setattr(webhook_app, "get_observability_context", lambda: {})
    monkeypatch.setattr(webhook_app, "record_http_request", lambda *args, **kwargs: None)

    with webhook_app.app.test_request_context(
        "/api/v1/example", method="GET", base_url="https://api.example.test"
    ):
        response = webhook_app.add_correlation_id_header(Response("{}", mimetype="application/json"))

    assert response.headers["X-Correlation-ID"] == "corr-test"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert response.headers["Permissions-Policy"] == (
        "camera=(), microphone=(), geolocation=(), payment=()"
    )
    assert response.headers["Strict-Transport-Security"] == "max-age=15552000"


def test_auth_responses_are_not_cacheable(monkeypatch):
    monkeypatch.setattr(webhook_app, "get_correlation_id", lambda: "corr-test")
    monkeypatch.setattr(webhook_app, "get_observability_context", lambda: {})
    monkeypatch.setattr(webhook_app, "record_http_request", lambda *args, **kwargs: None)

    with webhook_app.app.test_request_context("/auth/login", method="POST"):
        response = webhook_app.add_correlation_id_header(Response("{}", mimetype="application/json"))

    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_alertmanager_receiver_fails_closed_without_secret_in_production(monkeypatch):
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", "production")
    for name in ("PESAGUARD_ENV", "ENVIRONMENT", "FLASK_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("PESAGUARD_ALERTMANAGER_WEBHOOK_SECRET", raising=False)

    response = webhook_app.app.test_client().post("/ops/alerts", json={"alerts": []})

    assert response.status_code == 503
    assert response.get_json()["error"] == "alertmanager_auth_not_configured"


def test_alertmanager_receiver_rejects_wrong_secret(monkeypatch):
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", "production")
    for name in ("PESAGUARD_ENV", "ENVIRONMENT", "FLASK_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PESAGUARD_ALERTMANAGER_WEBHOOK_SECRET", "test-secret-value-that-is-long-enough")

    response = webhook_app.app.test_client().post(
        "/ops/alerts",
        json={"alerts": []},
        headers={"X-Alertmanager-Secret": "wrong"},
    )

    assert response.status_code == 401
