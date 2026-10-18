"""SSO trust policy lookup must not derive tenant scope from request selectors."""

import app_4_advanced_features as advanced_features


def test_sso_policy_lookup_ignores_query_tenant_selector(monkeypatch):
    calls = []
    monkeypatch.setattr(
        advanced_features.settings_store,
        "get",
        lambda tenant_id: calls.append(tenant_id) or {"external_idp_policy": {"marker": tenant_id}},
    )
    with advanced_features.app.test_request_context("/auth/sso/policy?tenant_id=tenant-attacker"):
        policy = advanced_features._provider_trust_policy_for_tenant()

    assert calls == []
    assert "marker" not in policy


def test_sso_policy_lookup_uses_only_explicit_trusted_tenant(monkeypatch):
    calls = []
    monkeypatch.setattr(
        advanced_features.settings_store,
        "get",
        lambda tenant_id: calls.append(tenant_id) or {
            "external_idp_policy": {"review_required": True, "approved_by": "security-admin"}
        },
    )
    with advanced_features.app.test_request_context("/auth/sso/policy?tenant_id=tenant-attacker"):
        policy = advanced_features._provider_trust_policy_for_tenant("tenant-authenticated")

    assert calls == ["tenant-authenticated"]
    assert policy["review_required"] is True
    assert policy["approved_by"] == "security-admin"

def test_entra_policy_does_not_use_process_tenant_as_issuer_scope(monkeypatch):
    monkeypatch.setenv("OIDC_PROVIDER_FAMILY", "microsoft_entra")
    monkeypatch.setenv("TENANT_ID", "process-global-tenant")
    policy = advanced_features._provider_trust_policy_for_tenant()

    assert "https://login.microsoftonline.com/process-global-tenant/v2.0" not in policy["allowed_issuers"]
    assert "https://login.microsoftonline.com/" not in policy["allowed_issuers"]

def test_policy_update_invalidates_existing_approval_on_trust_change():
    current = {
        "allowed_issuers": ["https://idp.example/old"],
        "approved_by": "reviewer-1",
        "approved_at": "2026-10-01T00:00:00+00:00",
        "review_required": False,
    }

    policy, changed = advanced_features._apply_external_idp_policy_update(
        current,
        {
            "allowed_issuers": ["https://idp.example/new"],
            "approved_by": "attacker-supplied-reviewer",
            "approved_at": "2099-01-01T00:00:00+00:00",
            "review_required": False,
        },
    )

    assert changed is True
    assert policy["allowed_issuers"] == ["https://idp.example/new"]
    assert policy["approved_by"] is None
    assert policy["approved_at"] is None
    assert policy["review_required"] is True


def test_policy_update_does_not_invalidate_approval_when_values_are_unchanged():
    current = {
        "allowed_issuers": ["https://idp.example/issuer"],
        "approved_by": "reviewer-1",
        "approved_at": "2026-10-01T00:00:00+00:00",
        "review_required": False,
    }

    policy, changed = advanced_features._apply_external_idp_policy_update(
        current,
        {
            "allowed_issuers": ["https://idp.example/issuer"],
            "approved_by": "attacker-supplied-reviewer",
            "review_required": False,
        },
    )

    assert changed is False
    assert policy["approved_by"] == "reviewer-1"
    assert policy["approved_at"] == "2026-10-01T00:00:00+00:00"
    assert policy["review_required"] is False

