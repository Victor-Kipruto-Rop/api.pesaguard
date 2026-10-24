"""Security regression tests for tenant settings authentication context."""

from types import SimpleNamespace

from flask import Flask, g

from pesaguard_backend_pipeline import tenant_settings as settings_module


def _client(authenticated_user=None):
    app = Flask(__name__)
    app.register_blueprint(settings_module.settings_bp)

    @app.before_request
    def inject_test_authentication_context():
        # This simulates trusted auth middleware. The request's X-Tenant-ID header
        # is intentionally not used to populate g.user or g.tenant_id.
        if authenticated_user is not None:
            g.user = authenticated_user

    return app.test_client()


def test_settings_get_does_not_treat_tenant_header_as_authentication(monkeypatch):
    monkeypatch.setattr(
        settings_module.settings_store,
        "get",
        lambda tenant_id: {"marker": tenant_id},
    )
    monkeypatch.setattr(
        settings_module.settings_store,
        "get_residency_context",
        lambda tenant_id: {"tenant_id": tenant_id},
    )

    response = _client().get(
        "/api/v1/settings",
        headers={"X-Tenant-ID": "tenant-attacker"},
    )

    assert response.status_code == 401
    assert response.get_json()["error"] == "unauthorized"


def test_settings_get_uses_authenticated_tenant_not_spoofed_header(monkeypatch):
    calls = []
    monkeypatch.setattr(
        settings_module.settings_store,
        "get",
        lambda tenant_id: calls.append(("get", tenant_id)) or {"marker": tenant_id},
    )
    monkeypatch.setattr(
        settings_module.settings_store,
        "get_residency_context",
        lambda tenant_id: calls.append(("residency", tenant_id)) or {"tenant_id": tenant_id},
    )

    response = _client(
        SimpleNamespace(tenant_id="tenant-authenticated", role="admin")
    ).get(
        "/api/v1/settings",
        headers={"X-Tenant-ID": "tenant-attacker"},
    )

    assert response.status_code == 200
    assert response.get_json()["tenant_id"] == "tenant-authenticated"
    assert calls == [
        ("get", "tenant-authenticated"),
        ("residency", "tenant-authenticated"),
    ]


def test_settings_mutation_routes_reject_missing_authenticated_context():
    client = _client()

    patch_response = client.patch(
        "/api/v1/settings",
        headers={"X-Tenant-ID": "tenant-attacker"},
        json={"alerts": {"enabled": False}},
    )
    alert_response = client.post(
        "/api/v1/settings/test-alert",
        headers={"X-Tenant-ID": "tenant-attacker"},
        json={"channel": "email"},
    )

    assert patch_response.status_code == 401
    assert alert_response.status_code == 401


def test_settings_rejects_placeholder_tenant_context(monkeypatch):
    monkeypatch.setattr(
        settings_module.settings_store,
        "get",
        lambda _tenant_id: (_ for _ in ()).throw(AssertionError("must not query placeholder tenant")),
    )

    response = _client(
        SimpleNamespace(tenant_id="default", role="admin")
    ).get("/api/v1/settings")

    assert response.status_code == 401
