"""Tenant identifiers in API response envelopes must come from request auth."""

import app_4_advanced_features as advanced_features


def test_response_tenant_id_does_not_fall_back_to_process_configuration(monkeypatch):
    monkeypatch.setenv("TENANT_ID", "shared-process-tenant")
    with advanced_features.app.test_request_context(
        "/api/v1/example",
        headers={"X-Tenant-ID": "attacker-selected-tenant"},
    ):
        assert advanced_features._response_tenant_id() == ""


def test_response_tenant_id_uses_trusted_request_context(monkeypatch):
    monkeypatch.setenv("TENANT_ID", "shared-process-tenant")
    with advanced_features.app.test_request_context(
        "/api/v1/example",
        headers={"X-Tenant-ID": "attacker-selected-tenant"},
    ):
        advanced_features.g.tenant_id = "authenticated-tenant"
        assert advanced_features._response_tenant_id() == "authenticated-tenant"


def test_response_tenant_id_rejects_placeholder_auth_context():
    for value in ("", "default", "unknown", "none", "null"):
        with advanced_features.app.test_request_context("/api/v1/example"):
            advanced_features.g.tenant_id = value
            assert advanced_features._response_tenant_id() == ""
