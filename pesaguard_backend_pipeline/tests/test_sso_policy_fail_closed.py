"""Regression tests for fail-closed external IdP trust validation."""

import app_4_advanced_features as advanced_features


def test_oidc_requires_an_explicit_issuer_allowlist():
    policy = {
        "provider_type": "oidc",
        "allowed_issuers": [],
        "allowed_jwks_hosts": ["idp.example"],
        "pin_jwks": False,
    }
    metadata = {
        "issuer": "https://idp.example",
        "jwks_uri": "https://idp.example/.well-known/jwks.json",
    }
    assert not advanced_features._validate_provider_trust_policy("tenant-a", policy, metadata)


def test_oidc_requires_https_jwks_on_an_allowlisted_host():
    policy = {
        "provider_type": "oidc",
        "allowed_issuers": ["https://idp.example"],
        "allowed_jwks_hosts": ["idp.example"],
        "pin_jwks": False,
    }
    valid = {
        "issuer": "https://idp.example",
        "jwks_uri": "https://idp.example/.well-known/jwks.json",
    }
    insecure = {
        "issuer": "https://idp.example",
        "jwks_uri": "http://idp.example/.well-known/jwks.json",
    }
    unlisted_host = {
        "issuer": "https://idp.example",
        "jwks_uri": "https://keys.other.example/.well-known/jwks.json",
    }
    assert advanced_features._validate_provider_trust_policy("tenant-a", policy, valid)
    assert not advanced_features._validate_provider_trust_policy("tenant-a", policy, insecure)
    assert not advanced_features._validate_provider_trust_policy("tenant-a", policy, unlisted_host)


def test_sso_approval_requires_a_different_configurator():
    policy = {"configured_by": "security-admin"}
    assert advanced_features._external_idp_reviewer_is_independent(policy, "second-admin")
    assert not advanced_features._external_idp_reviewer_is_independent(policy, "security-admin")
    assert not advanced_features._external_idp_reviewer_is_independent({}, "security-admin")
