from __future__ import annotations

import importlib

import pytest
from flask import Flask, g, request


def test_runtime_environment_rejects_conflicting_aliases(monkeypatch):
    from environment import runtime_environment

    for name in ("PESAGUARD_ENVIRONMENT", "PESAGUARD_ENV", "ENVIRONMENT", "FLASK_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", "production")
    monkeypatch.setenv("FLASK_ENV", "development")

    with pytest.raises(RuntimeError, match="Conflicting application environment"):
        runtime_environment()


def test_runtime_environment_normalizes_supported_aliases(monkeypatch):
    from environment import runtime_environment

    for name in ("PESAGUARD_ENVIRONMENT", "PESAGUARD_ENV", "ENVIRONMENT", "FLASK_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", "prod")
    monkeypatch.setenv("FLASK_ENV", "production")

    assert runtime_environment() == "production"


def test_rate_limit_identity_uses_proxy_resolved_ip_not_query_tenant(monkeypatch):
    import rate_limiter

    monkeypatch.setenv("PESAGUARD_TRUSTED_PROXY_COUNT", "1")
    app = Flask("rate-limit-identity-test")
    with app.test_request_context(
        "/resource?tenant_id=attacker-tenant",
        headers={"X-Forwarded-For": "198.51.100.44, 203.0.113.10"},
        environ_base={"REMOTE_ADDR": "10.0.0.8"},
    ):
        assert rate_limiter._get_client_identifier() == "ip_203.0.113.10"
        g.tenant_id = "tenant-a"
        assert rate_limiter._get_client_identifier() == "tenant_tenant-a_203.0.113.10"


def test_invalid_forwarded_ip_falls_back_to_remote_addr(monkeypatch):
    from security_helpers import get_client_ip

    monkeypatch.setenv("PESAGUARD_TRUSTED_PROXY_COUNT", "1")
    app = Flask("forwarded-ip-test")
    with app.test_request_context(
        "/",
        headers={"X-Forwarded-For": "not-an-ip"},
        environ_base={"REMOTE_ADDR": "10.0.0.8"},
    ):
        assert get_client_ip(request) == "10.0.0.8"


def test_production_rate_limit_fails_closed_without_redis(monkeypatch):
    import rate_limiter

    for name in ("PESAGUARD_ENVIRONMENT", "PESAGUARD_ENV", "ENVIRONMENT", "FLASK_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", "production")
    monkeypatch.setattr(rate_limiter, "ENABLE_REDIS_RATE_LIMITING", False)

    app = Flask("production-rate-limit-test")

    @app.get("/limited")
    @rate_limiter.rate_limit()
    def limited():
        return "ok"

    response = app.test_client().get("/limited")

    assert response.status_code == 503
    assert response.get_json()["error"] == "rate_limiter_unavailable"


@pytest.fixture
def audit_dashboard_client(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'audit-dashboard.db'}")
    monkeypatch.setenv("PESAGUARD_API_AUTH_REQUIRED", "1")
    import app_2

    app_module = importlib.reload(app_2)
    app_module.Base.metadata.create_all(app_module.engine)
    from action_audit import Base as AuditBase
    from auth_rbac import _RevocationBase

    AuditBase.metadata.create_all(app_module.primary_engine)
    _RevocationBase.metadata.create_all(app_module.primary_engine)
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as client:
        yield client, app_module
    app_module.primary_engine.dispose()


def test_dashboard_cors_allows_expected_app_origin_and_headers(audit_dashboard_client, monkeypatch):
    client, _ = audit_dashboard_client
    monkeypatch.setenv("PESAGUARD_CORS_ALLOWED_ORIGINS", "https://app.pesaguard.co.ke")
    response = client.options(
        "/discrepancies",
        headers={
            "Origin": "https://app.pesaguard.co.ke",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "authorization,content-type,idempotency-key,x-request-id,traceparent"
            ),
        },
    )

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.pesaguard.co.ke"
    allowed_headers = response.headers["Access-Control-Allow-Headers"].lower()
    assert "idempotency-key" in allowed_headers
    assert "x-request-id" in allowed_headers
    assert "traceparent" in allowed_headers
    exposed_headers = response.headers["Access-Control-Expose-Headers"].lower()
    assert "x-request-id" in exposed_headers
    assert "retry-after" in exposed_headers


def test_dashboard_rejects_unapproved_cors_origin(audit_dashboard_client, monkeypatch):
    client, _ = audit_dashboard_client
    monkeypatch.setenv("PESAGUARD_CORS_ALLOWED_ORIGINS", "https://app.pesaguard.co.ke")
    response = client.options(
        "/discrepancies",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 403
    assert response.get_json()["error"] == "cors_origin_denied"


def test_health_route_redacts_dependency_error_details(audit_dashboard_client, monkeypatch):
    client, app_module = audit_dashboard_client
    monkeypatch.setattr(app_module, "build_health_payload", lambda: {
        "status": "degraded",
        "service": "pesaguard",
        "checks": {
            "database": {"status": "failed", "error": "postgres://user:secret@db.internal"},
            "redis": {"status": "ok"},
        },
    })

    response = client.get("/health")

    assert response.status_code == 503
    assert response.get_json()["checks"] == {
        "database": {"status": "failed"},
        "redis": {"status": "ok"},
    }
    assert b"secret" not in response.data
    assert b"db.internal" not in response.data


def test_metrics_scraper_uses_dedicated_bearer_file(audit_dashboard_client, monkeypatch, tmp_path):
    client, _ = audit_dashboard_client
    token_file = tmp_path / "prometheus.token"
    token_file.write_text("local-scrape-token\n", encoding="utf-8")
    monkeypatch.setenv("PESAGUARD_PROMETHEUS_TOKEN_FILE", str(token_file))

    unauthorized = client.get("/metrics")
    authorized = client.get(
        "/metrics",
        headers={"Authorization": "Bearer local-scrape-token", "Accept": "text/plain"},
    )

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200
    assert authorized.mimetype == "text/plain"
    assert "# HELP" in authorized.get_data(as_text=True)


def test_canonical_asgi_entrypoint_serves_auth_and_dashboard_contract(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'canonical.db'}")
    monkeypatch.setenv("PESAGUARD_API_AUTH_REQUIRED", "1")
    monkeypatch.setenv("PESAGUARD_PUBLIC_API_DOCS", "1")
    from fastapi.testclient import TestClient
    from pesaguard_backend_pipeline.canonical_app import app as canonical_app

    with TestClient(canonical_app) as client:
        login_response = client.post("/auth/login", json={})
        versioned_login_response = client.post("/api/v1/auth/login", json={})
        refresh_response = client.post("/auth/refresh", json={})
        versioned_refresh_response = client.post("/api/v1/auth/refresh", json={})
        session_response = client.get("/auth/sessions")
        contract_response = client.get("/openapi.json")
        docs_response = client.get("/docs")

    assert login_response.status_code in {400, 401}
    assert versioned_login_response.status_code in {400, 401}
    assert refresh_response.status_code in {400, 401}
    assert versioned_refresh_response.status_code in {400, 401}
    assert session_response.status_code == 401
    assert contract_response.status_code == 200
    assert contract_response.json()["openapi"] == "3.0.3"
    assert docs_response.status_code == 200
    assert b"PesaGuard Dashboard API" in docs_response.content
