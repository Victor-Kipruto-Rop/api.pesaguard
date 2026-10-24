"""Observability must not trust caller-controlled tenant headers."""

from pesaguard_backend_pipeline.app import _trusted_runtime_tenant_id


def test_runtime_tenant_context_ignores_request_headers_by_design(monkeypatch):
    # This helper reads only server environment configuration; an HTTP header
    # cannot affect the value it returns.
    monkeypatch.setenv("TENANT_ID", "tenant-configured")
    assert _trusted_runtime_tenant_id() == "tenant-configured"


def test_runtime_tenant_context_rejects_placeholder_values(monkeypatch):
    for value in ("", "default", "unknown", "none", "null", "  "):
        monkeypatch.setenv("TENANT_ID", value)
        assert _trusted_runtime_tenant_id() == ""
