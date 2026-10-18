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
