"""Least-privilege authorization regression tests (deny by default)."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve()
TREE_ROOT = HERE.parents[1]  # pesaguard_backend_pipeline/
REPO_ROOT = HERE.parents[2]  # repo root
# Prefer the working-tree files over any installed/top-level copies.
for candidate in (str(TREE_ROOT), str(REPO_ROOT)):
    if candidate in sys.path:
        sys.path.remove(candidate)
    sys.path.insert(0, candidate)

import pytest

from authorization_policy import (
    ENDPOINT_EXEMPTIONS,
    ENDPOINT_PERMISSIONS,
    ROUTE_AUDIT_RESOLVED_CONFLICTS,
    ROUTE_AUDIT_UNMAPPED_WITH_RUNTIME_PERMISSION,
    is_forbidden_customer_scope,
    is_internal_scope,
    required_permission_for,
    safe_public_error,
    validate_customer_scopes,
    validate_route_audit_records,
)
import authorization_policy as tree_policy


def test_registry_rejects_wildcards_and_internal_scopes():
    for scope in ["*", "manage:*", "internal:key-sync", "internal:core-api",
                  "admin:users", "database:read", "system:admin",
                  "service:publish", "unknown:permission"]:
        if scope == "unknown:permission":
            assert not is_forbidden_customer_scope(scope)
        else:
            assert is_forbidden_customer_scope(scope), scope
        with pytest.raises(ValueError):
            validate_customer_scopes([scope])


def test_internal_scopes_never_customer_visible():
    assert is_internal_scope("internal:key-sync")
    assert is_internal_scope("service:publish")
    assert not is_internal_scope("read:analytics")


def test_customer_scopes_must_be_known_and_sorted():
    assert validate_customer_scopes(["read:discrepancies", "read:analytics"]) == [
        "read:analytics", "read:discrepancies"]
    with pytest.raises(ValueError):
        validate_customer_scopes([])
    with pytest.raises(ValueError):
        validate_customer_scopes(["read:analytics", "nope:missing"])


def test_safe_errors_never_leak_internal_reasons():
    assert safe_public_error("tenant_mismatch") == "access_denied"
    assert safe_public_error("missing_scope") == "insufficient_scope"
    assert safe_public_error("credential_revoked") == "authentication_required"
    assert safe_public_error("something_new") == "access_denied"


def test_every_mapped_endpoint_requires_known_permission():
    # ENDPOINT_PERMISSIONS and CORE_PERMISSIONS come from the same tree
    # module object (bulk:operations exists in the working tree).
    assert len(ENDPOINT_PERMISSIONS) >= 20
    assert "bulk:operations" in tree_policy.CORE_PERMISSIONS
    for endpoint, permission in ENDPOINT_PERMISSIONS.items():
        assert permission in tree_policy.CORE_PERMISSIONS, endpoint


def test_unmapped_endpoint_denies():
    assert required_permission_for("GET", "/nope/missing") is None


def test_normalize_machine_scopes_rejects_privileged():
    from auth_rbac import AuthRBAC
    assert AuthRBAC.normalize_machine_scopes(["read:analytics"]) == ["read:analytics"]
    # Security-critical violations still raise (fail closed at issuance).
    for bad in (["*"], ["manage:*"], ["internal:key-sync"], ["admin:x"],
                ["manage:all_tenants"], ["manage:security"], ["audit:read"],
                ["events:read"], ["fraud:write"], ["service:publish"]):
        with pytest.raises(ValueError):
            AuthRBAC.normalize_machine_scopes(bad)
    assert AuthRBAC.normalize_machine_scopes(["usage:read"]) == ["read:usage"]
    assert AuthRBAC.normalize_machine_scopes(["transactions:read"]) == ["read:transactions"]
    with pytest.raises(ValueError):
        AuthRBAC.normalize_machine_scopes(["transactions:read", "audit:read"])


def test_role_grants_are_subset_of_registry():
    """Every permission a role can grant must exist in the registry."""
    from auth_rbac import AuthRBAC
    missing = {
        permission
        for grants in AuthRBAC.ROLE_PERMISSIONS.values()
        for permission in grants
        if permission not in tree_policy.CORE_PERMISSIONS
    }
    assert missing == set(), f"role grants missing from registry: {sorted(missing)}"


def test_machine_denied_scopes_never_issue():
    from auth_rbac import AuthRBAC
    for scope in ["manage:all_tenants", "manage:tenant_isolation"]:
        with pytest.raises(ValueError):
            AuthRBAC.normalize_machine_scopes([scope])
        with pytest.raises(ValueError):
            validate_customer_scopes([scope])


def _read_route_audit():
    data = (REPO_ROOT / "routes_audit.txt").read_bytes()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("utf-16")
    return text.splitlines()


def test_route_inventory_has_explicit_permissions_or_exemptions():
    counts = validate_route_audit_records(_read_route_audit())

    assert counts == {"routes": 208, "mapped": 162, "exempt": 46}
    assert not (set(ENDPOINT_PERMISSIONS) & set(ENDPOINT_EXEMPTIONS))
    assert all(
        required_permission_for(*endpoint.split(" ", 1)) is None
        for endpoint in ENDPOINT_EXEMPTIONS
    )


def test_route_inventory_validator_rejects_new_and_inconsistent_routes():
    audit = _read_route_audit()
    with pytest.raises(ValueError, match="unclassified route"):
        validate_route_audit_records(audit + ["GET /new/route -> UNMAPPED"])

    with pytest.raises(ValueError, match="inconsistent classification"):
        validate_route_audit_records(
            audit + ["GET /health -> read:analytics"]
        )


def test_runtime_resource_decorators_resolve_stale_unmapped_audit_rows():
    source = (TREE_ROOT / "app_4_advanced_features.py").read_text(
        encoding="utf-8"
    ).splitlines()
    reconciled = {
        **ROUTE_AUDIT_UNMAPPED_WITH_RUNTIME_PERMISSION,
        **ROUTE_AUDIT_RESOLVED_CONFLICTS,
    }

    for endpoint, permission in reconciled.items():
        method, path = endpoint.split(" ", 1)
        decorator = (
            f'@_idempotent_route("{path}", methods=["{method}"])'
        )
        route_indexes = [
            index for index, line in enumerate(source)
            if line.strip() == decorator
        ]
        assert route_indexes, f"runtime route not found: {endpoint}"
        assert any(
            any(
                f'@require_resource_access("{permission}",' in line
                for line in source[index + 1:index + 7]
            )
            for index in route_indexes
        ), f"runtime scope decorator missing for {endpoint}"
