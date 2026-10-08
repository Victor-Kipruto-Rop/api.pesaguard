"""Least-privilege permission registry for the PesaGuard Core API.

Single authoritative source for customer-visible permissions, internal
service scopes, endpoint->permission mapping, and safe error mapping.

Deny by default: unknown/wildcard/internal scopes are rejected, never
granted to customer principals.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional

PUBLIC_AUTH_ERRORS = frozenset({
    "authentication_required",
    "insufficient_scope",
    "access_denied",
    "resource_not_found",
})

INTERNAL_DENY_REASONS = frozenset({
    "missing_scope",
    "invalid_organization",
    "invalid_project",
    "invalid_environment",
    "tenant_mismatch",
    "resource_denied",
    "credential_revoked",
    "credential_expired",
    "credential_inactive",
    "internal_scope_rejected",
    "wildcard_rejected",
    "unknown_permission",
})


@dataclass(frozen=True)
class PermissionDefinition:
    """Canonical definition of one permission."""

    name: str
    description: str
    category: str
    resource: str
    action: str
    risk_level: str
    customer_visible: bool
    internal_only: bool = False

CORE_PERMISSIONS: Dict[str, PermissionDefinition] = {
    "read:discrepancies": PermissionDefinition(
        "read:discrepancies", "Read reconciliation discrepancies.",
        "Reconciliation", "discrepancies", "read", "Low", True),
    "write:discrepancies": PermissionDefinition(
        "write:discrepancies", "Create or update discrepancy records.",
        "Reconciliation", "discrepancies", "write", "Medium", True),
    "delete:discrepancies": PermissionDefinition(
        "delete:discrepancies", "Delete discrepancy records (restricted).",
        "Reconciliation", "discrepancies", "delete", "High", True),
    "read:analytics": PermissionDefinition(
        "read:analytics", "Read analytics and report metadata.",
        "Reports", "analytics", "read", "Low", True),
    "read:transactions": PermissionDefinition(
        "read:transactions", "Read transactions within authorized tenant.",
        "Transactions", "transactions", "read", "Low", True),
    "write:transactions": PermissionDefinition(
        "write:transactions", "Create transaction records (restricted).",
        "Transactions", "transactions", "write", "High", True),
    "read:reports": PermissionDefinition(
        "read:reports", "Read generated reports.",
        "Reports", "reports", "read", "Low", True),
    "read:revenue": PermissionDefinition(
        "read:revenue", "Read revenue summaries.",
        "Reports", "revenue", "read", "Medium", True),
    "read:audit_logs": PermissionDefinition(
        "read:audit_logs", "Read tenant audit log entries.",
        "Audit", "audit_logs", "read", "Medium", True),
    "read:settings": PermissionDefinition(
        "read:settings", "Read tenant settings.",
        "Settings", "settings", "read", "Low", True),
    "write:settings": PermissionDefinition(
        "write:settings", "Update tenant settings.",
        "Settings", "settings", "write", "Medium", True),
    "write:escalation_rules": PermissionDefinition(
        "write:escalation_rules", "Manage escalation rules.",
        "Operations", "escalation_rules", "write", "Medium", True),
    "manage:webhooks": PermissionDefinition(
        "manage:webhooks", "Manage webhook endpoints and secrets.",
        "Webhooks", "webhooks", "manage", "High", True),
    "read:providers": PermissionDefinition(
        "read:providers", "Read provider configs (secrets redacted).",
        "Integrations", "providers", "read", "Low", True),
    "manage:providers": PermissionDefinition(
        "manage:providers", "Connect/disconnect providers (prod-gated).",
        "Integrations", "providers", "manage", "High", True),
    "manage:on_call": PermissionDefinition(
        "manage:on_call", "Manage on-call schedules.",
        "Operations", "on_call", "manage", "Medium", True),
    "manage:settings": PermissionDefinition(
        "manage:settings", "Administrative settings management.",
        "Settings", "settings", "manage", "High", True),
    "manage:users": PermissionDefinition(
        "manage:users", "Manage users and sessions.",
        "Users", "users", "manage", "High", True),
    "manage:teams": PermissionDefinition(
        "manage:teams", "Manage teams.",
        "Organizations", "teams", "manage", "Medium", True),
    "manage:departments": PermissionDefinition(
        "manage:departments", "Manage departments.",
        "Organizations", "departments", "manage", "Medium", True),
    "manage:organizations": PermissionDefinition(
        "manage:organizations", "Manage organizations (tenant-scoped).",
        "Organizations", "organizations", "manage", "High", True),
    "manage:billing": PermissionDefinition(
        "manage:billing", "Manage billing (restricted).",
        "Billing", "billing", "manage", "Critical", True),
    "manage:api_keys": PermissionDefinition(
        "manage:api_keys", "Manage tenant API keys.",
        "Security", "api_keys", "manage", "Critical", True),
    "manage:mfa": PermissionDefinition(
        "manage:mfa", "Manage MFA policies.",
        "Security", "mfa", "manage", "High", True),
    "manage:security": PermissionDefinition(
        "manage:security", "Security administration (restricted).",
        "Security", "security", "manage", "Critical", True),
    "manage:sso": PermissionDefinition(
        "manage:sso", "Manage SSO configuration (restricted).",
        "Security", "sso", "manage", "Critical", True),
    "manage:tenant_isolation": PermissionDefinition(
        "manage:tenant_isolation", "Tenant isolation policy (operators only).",
        "Security", "tenant_isolation", "manage", "Critical", False),
    "read:usage": PermissionDefinition(
        "read:usage", "Read usage summaries.",
        "Usage", "usage", "read", "Low", True),
    "read:metrics": PermissionDefinition(
        "read:metrics", "Read operational metrics.",
        "Observability", "metrics", "read", "Low", True),
    "bulk:operations": PermissionDefinition(
        "bulk:operations", "Bulk assign/escalate (rate-limited).",
        "Operations", "bulk", "execute", "High", True),
    "send:communications": PermissionDefinition(
        "send:communications", "Send communications.",
        "Notifications", "communications", "send", "Medium", True),
    "read:communications": PermissionDefinition(
        "read:communications", "Read communications.",
        "Notifications", "communications", "read", "Low", True),
    "export:communications": PermissionDefinition(
        "export:communications", "Export communications data.",
        "Notifications", "communications", "export", "Medium", True),
    "resolve:discrepancies": PermissionDefinition(
        "resolve:discrepancies", "Resolve discrepancies and replay dead letters.",
        "Reconciliation", "discrepancies", "resolve", "High", True),
    "manage:communications": PermissionDefinition(
        "manage:communications", "Administer communication templates and campaigns.",
        "Notifications", "communications", "manage", "High", True),
    "manage:all_tenants": PermissionDefinition(
        "manage:all_tenants", "Cross-tenant administration. Never grant to integration credentials.",
        "Security", "all_tenants", "manage", "Critical", False),
}

INTERNAL_SERVICE_SCOPES: Dict[str, PermissionDefinition] = {
    "internal:developer-platform": PermissionDefinition(
        "internal:developer-platform", "Developer Platform service identity.",
        "Internal", "developer-platform", "service", "Critical", False, True),
    "internal:core-api": PermissionDefinition(
        "internal:core-api", "Core API service identity.",
        "Internal", "core-api", "service", "Critical", False, True),
    "internal:key-sync": PermissionDefinition(
        "internal:key-sync", "API-key synchronization channel.",
        "Internal", "key-sync", "service", "Critical", False, True),
    "service:publish": PermissionDefinition(
        "service:publish", "Publish platform lifecycle events.",
        "Internal", "events", "publish", "High", False, True),
    "service:consume": PermissionDefinition(
        "service:consume", "Consume platform lifecycle events.",
        "Internal", "events", "consume", "High", False, True),
}

FORBIDDEN_CUSTOMER_PATTERNS = ("*", "internal:", "admin:", "database:", "system:", "service:")

# Registered in the catalog (human roles may hold these) but never grantable
# to a machine/customer credential: cross-tenant bypass must stay human-only.
MACHINE_DENIED = frozenset({
    "manage:all_tenants",
    "manage:tenant_isolation",
    "manage:security",
    "manage:sso",
    "manage:mfa",
})


def is_internal_scope(scope: str) -> bool:
    """True when a scope belongs to the internal-only namespace."""
    if not isinstance(scope, str):
        return False
    value = scope.strip()
    return (
        value in INTERNAL_SERVICE_SCOPES
        or value.startswith("internal:")
        or value in {"service:publish", "service:consume",
                     "service:read", "service:write"}
    )


def is_forbidden_customer_scope(scope: str) -> bool:
    """Wildcards and privileged namespaces can never go to customers."""
    if not isinstance(scope, str):
        return True
    value = scope.strip()
    if not value or "*" in value:
        return True
    return value.lower().startswith(FORBIDDEN_CUSTOMER_PATTERNS)


def validate_customer_scopes(scopes: List[str]) -> List[str]:
    """Validate + normalize machine/customer scopes. Raises ValueError on violation.

    Deny by default: unknown permissions, wildcards, internal scopes, and
    machine-denied privileges (cross-tenant/security admin) are rejected
    rather than filtered silently.
    """
    if not isinstance(scopes, list) or not scopes:
        raise ValueError("Scopes must be a non-empty list.")
    normalized: List[str] = []
    for scope in scopes:
        if not isinstance(scope, str) or not scope.strip():
            raise ValueError("Scope entries must be non-empty strings.")
        value = scope.strip()
        if is_forbidden_customer_scope(value):
            raise ValueError(f"Scope is not grantable to customers: {value}")
        if value in MACHINE_DENIED:
            raise ValueError(f"Scope is restricted to human roles: {value}")
        if value not in CORE_PERMISSIONS:
            raise ValueError(f"Unknown permission: {value}")
        if value not in normalized:
            normalized.append(value)
    return sorted(normalized)


def safe_public_error(internal_reason: str) -> str:
    """Map an internal deny reason to a safe customer-visible error code."""
    mapping = {
        "missing_scope": "insufficient_scope",
        "internal_scope_rejected": "insufficient_scope",
        "wildcard_rejected": "insufficient_scope",
        "unknown_permission": "insufficient_scope",
        "tenant_mismatch": "access_denied",
        "resource_denied": "access_denied",
        "invalid_organization": "access_denied",
        "invalid_project": "access_denied",
        "invalid_environment": "access_denied",
        "credential_revoked": "authentication_required",
        "credential_expired": "authentication_required",
        "credential_inactive": "authentication_required",
    }
    return mapping.get(internal_reason, "access_denied")


ENDPOINT_PERMISSIONS: Dict[str, str] = {
    "DELETE /api/v1/communications/saved-filters/<filter_id>": "read:communications",
    "GET /activity-feed": "read:discrepancies",
    "GET /analytics/incident-trends": "read:discrepancies",
    "GET /analytics/operator-stats": "read:discrepancies",
    "GET /analytics/reconciliation-report": "read:discrepancies",
    "GET /analytics/resolution-times": "read:discrepancies",
    "GET /analytics/sla-metrics": "read:discrepancies",
    "GET /api/v1/catalog/datasets": "read:analytics",
    "GET /api/v1/catalog/datasets/<dataset_name>": "read:analytics",
    "GET /api/v1/communications/analytics": "read:communications",
    "GET /api/v1/communications/analytics/costs": "read:communications",
    "GET /api/v1/communications/dead-letters": "read:communications",
    "GET /api/v1/communications/export": "export:communications",
    "GET /api/v1/communications/flags": "read:communications",
    "GET /api/v1/communications/incidents": "read:communications",
    "GET /api/v1/communications/messages": "read:communications",
    "GET /api/v1/communications/messages/<message_id>": "read:communications",
    "GET /api/v1/communications/providers/health": "read:communications",
    "GET /api/v1/communications/quotas": "read:communications",
    "GET /api/v1/communications/saved-filters": "read:communications",
    "GET /api/v1/communications/search": "read:communications",
    "GET /api/v1/communications/templates": "read:communications",
    "GET /api/v1/communications/webhook-events": "read:communications",
    "GET /api/v1/customers/<tenant_id>/audit": "read:settings",
    "GET /api/v1/customers/<tenant_id>/deadletters": "read:discrepancies",
    "GET /api/v1/customers/<tenant_id>/reports": "read:analytics",
    "GET /api/v1/customers/<tenant_id>/transactions": "read:discrepancies",
    "GET /api/v1/customers/<tenant_id>/transactions/<trans_id>": "read:discrepancies",
    "GET /api/v1/export/csv": "read:discrepancies",
    "GET /api/v1/iam/api-clients": "manage:api_keys",
    "GET /api/v1/iam/external-identities": "manage:users",
    "GET /api/v1/iam/password-policy": "manage:settings",
    "GET /api/v1/iam/service-identities": "manage:users",
    "GET /api/v1/imports/<import_id>": "read:transactions",
    "GET /api/v1/lineage/transactions/<transaction_id>": "read:analytics",
    "GET /api/v1/metrics/merchants": "read:analytics",
    "GET /api/v1/operations/outbox": "read:analytics",
    "GET /api/v1/organizations": "read:settings",
    "GET /api/v1/organizations/<organization_id>": "read:settings",
    "GET /api/v1/organizations/<organization_id>/departments": "manage:departments",
    "GET /api/v1/organizations/<organization_id>/teams": "manage:teams",
    "GET /api/v1/organizations/<organization_id>/usage": "read:usage",
    "GET /assignment-queue": "read:discrepancies",
    "GET /auth/account/lockouts": "manage:users",
    "GET /auth/sso/oidc/authorize": "manage:sso",
    "GET /auth/sso/oidc/config": "manage:sso",
    "GET /auth/sso/policy": "manage:sso",
    "GET /auth/sso/providers": "manage:sso",
    "GET /auth/users": "manage:users",
    "GET /discrepancies": "read:discrepancies",
    "GET /discrepancies/export/csv": "read:discrepancies",
    "GET /emails/history": "read:discrepancies",
    "GET /escalation-rules": "read:discrepancies",
    "GET /incidents/filters/presets": "read:discrepancies",
    "GET /incidents/search": "read:discrepancies",
    "GET /metrics": "read:metrics",
    "GET /on-call/rotations/active": "read:discrepancies",
    "GET /on-call/schedule/<operator_id>": "read:discrepancies",
    "GET /providers": "read:providers",
    "GET /providers/<provider_id>": "read:providers",
    "GET /public/customers/<tenant_id>/reconciliations": "read:discrepancies",
    "GET /public/customers/<tenant_id>/reports": "read:analytics",
    "GET /search": "read:discrepancies",
    "GET /search/filters": "read:discrepancies",
    "GET /search/structured": "read:discrepancies",
    "GET /tenant/current": "read:settings",
    "GET /tenant/current/locale": "read:settings",
    "GET /tenants/<tenant_id>/settings": "read:settings",
    "GET /v1/customers/<tenant_id>/audit": "read:settings",
    "GET /v1/customers/<tenant_id>/deadletters": "read:discrepancies",
    "GET /v1/customers/<tenant_id>/reports": "read:analytics",
    "GET /v1/customers/<tenant_id>/transactions": "read:discrepancies",
    "GET /v1/customers/<tenant_id>/transactions/<trans_id>": "read:discrepancies",
    "GET /v1/export/csv": "read:discrepancies",
    "GET /v1/settings": "read:settings",
    "GET /webhooks": "manage:webhooks",
    "GET /webhooks/<webhook_id>/deliveries": "manage:webhooks",
    "PATCH /api/v1/iam/api-clients/<client_id>": "manage:api_keys",
    "PATCH /api/v1/iam/service-identities/<identity_id>": "manage:users",
    "PATCH /api/v1/organizations/<organization_id>": "read:settings",
    "PATCH /providers/<provider_id>": "manage:providers",
    "POST /api/v1/communications/campaigns": "send:communications",
    "POST /api/v1/communications/campaigns/<campaign_id>/cancel": "manage:communications",
    "POST /api/v1/communications/campaigns/<campaign_id>/estimate": "send:communications",
    "POST /api/v1/communications/campaigns/<campaign_id>/pause": "manage:communications",
    "POST /api/v1/communications/campaigns/<campaign_id>/resume": "manage:communications",
    "POST /api/v1/communications/dead-letters/<entry_id>/replay": "manage:communications",
    "POST /api/v1/communications/email": "send:communications",
    "POST /api/v1/communications/incidents/<incident_id>/status": "manage:communications",
    "POST /api/v1/communications/otp": "send:communications",
    "POST /api/v1/communications/otp/<challenge_id>/verify": "send:communications",
    "POST /api/v1/communications/policy/preview": "read:communications",
    "POST /api/v1/communications/saved-filters": "read:communications",
    "POST /api/v1/communications/sms": "send:communications",
    "POST /api/v1/communications/templates": "send:communications",
    "POST /api/v1/communications/templates/<template_id>/approve": "manage:communications",
    "POST /api/v1/communications/webhook-events/<event_id>/ignore": "manage:communications",
    "POST /api/v1/communications/webhook-events/<event_id>/replay": "manage:communications",
    "POST /api/v1/iam/api-clients": "manage:api_keys",
    "POST /api/v1/iam/api-clients/<client_id>/rotate-secret": "manage:api_keys",
    "POST /api/v1/iam/external-identities": "manage:users",
    "POST /api/v1/iam/platforms": "manage:all_tenants",
    "POST /api/v1/iam/role-bindings": "manage:users",
    "POST /api/v1/iam/roles": "manage:users",
    "POST /api/v1/iam/service-identities": "manage:users",
    "POST /api/v1/iam/service-identities/<identity_id>/rotate-secret": "manage:users",
    "POST /api/v1/iam/tenants": "manage:all_tenants",
    "POST /api/v1/imports": "write:transactions",
    "POST /api/v1/operations/dead-letters/<dead_letter_id>/replay": "resolve:discrepancies",
    "POST /api/v1/organizations": "manage:organizations",
    "POST /api/v1/organizations/<organization_id>/approvals": "manage:organizations",
    "POST /api/v1/organizations/<organization_id>/approvals/<approval_id>/review": "manage:organizations",
    "POST /api/v1/organizations/<organization_id>/departments": "manage:departments",
    "POST /api/v1/organizations/<organization_id>/members": "manage:organizations",
    "POST /api/v1/organizations/<organization_id>/teams": "manage:teams",
    "POST /auth/account/unlock": "manage:users",
    "POST /auth/admin/users/<user_id>/emergency-credential-rotation": "manage:security",
    "POST /auth/admin/users/<user_id>/password-reset": "manage:users",
    "POST /auth/api-keys": "manage:api_keys",
    "POST /auth/api-keys/<key_id>/revoke": "manage:api_keys",
    "POST /auth/api-keys/<key_id>/rotate": "manage:api_keys",
    "POST /auth/mfa/challenge": "manage:mfa",
    "POST /auth/mfa/verify": "manage:mfa",
    "POST /auth/passwordless/challenge": "manage:users",
    "POST /auth/passwordless/verify": "manage:users",
    "POST /auth/revoke": "manage:users",
    "POST /auth/revoke/user": "manage:users",
    "POST /auth/security/global-revoke": "manage:settings",
    "POST /auth/service-credentials/<credential_id>/revoke": "manage:settings",
    "POST /auth/sso/oidc/validate": "manage:sso",
    "POST /auth/sso/policy": "manage:sso",
    "POST /auth/sso/policy/review": "manage:sso",
    "POST /auth/sso/providers": "manage:sso",
    "POST /bulk/assign": "bulk:operations",
    "POST /bulk/escalate": "bulk:operations",
    "POST /discrepancies/<discrepancy_id>/assign": "write:discrepancies",
    "POST /discrepancies/<discrepancy_id>/notes": "write:discrepancies",
    "POST /discrepancies/<discrepancy_id>/resolve": "write:discrepancies",
    "POST /discrepancies/bulk-resolve": "bulk:operations",
    "POST /emails/escalation": "write:discrepancies",
    "POST /emails/reconciliation": "write:discrepancies",
    "POST /escalation-rules": "write:escalation_rules",
    "POST /incidents/auto-escalate": "bulk:operations",
    "POST /incidents/bulk-assign": "bulk:operations",
    "POST /incidents/filters/presets": "read:discrepancies",
    "POST /on-call/bulk": "manage:on_call",
    "POST /on-call/rotations": "manage:on_call",
    "POST /providers": "manage:providers",
    "POST /providers/<provider_id>/connection": "manage:providers",
    "POST /providers/<provider_id>/health": "manage:providers",
    "POST /tenant/current/locale": "write:settings",
    "POST /tenant/current/user-locale": "write:settings",
    "POST /tenants/<tenant_id>/settings": "write:settings",
    "POST /v1/settings": "write:settings",
    "POST /webhooks": "manage:webhooks",
    "PUT /api/v1/communications/consent/<path:recipient>": "manage:communications",
    "PUT /api/v1/communications/preferences/<path:recipient>": "manage:communications",
    "PUT /api/v1/communications/quotas/<scope>": "manage:communications",
    "PUT /api/v1/iam/password-policy": "manage:settings",
    "PUT /auth/mfa/policy": "manage:mfa",
    "PUT /escalation-rules/<rule_id>": "write:escalation_rules",
    "PUT /webhooks/<webhook_id>": "manage:webhooks",
}

# Unmapped routes are explicit exceptions, not implicit permissions. These
# labels describe the route's authentication boundary; they never grant a
# customer API scope.
ENDPOINT_EXEMPTIONS: Dict[str, str] = {
    "GET /api/v1/iam/identity": "session",
    "GET /auth/devices": "session",
    "GET /auth/mfa/factors": "session",
    "GET /auth/mfa/policy": "session",
    "GET /auth/sessions": "session",
    "GET /auth/sso/oidc/callback": "session",
    "GET /auth/verify": "session",
    "GET /docs": "public",
    "GET /health": "public",
    "GET /internal/v1/tenants/resolve": "internal",
    "GET /openapi.json": "public",
    "POST /api/v1/webhooks/africastalking/delivery": "public",
    "POST /auth/client-token": "session",
    "POST /auth/devices/<device_id>/logout": "session",
    "POST /auth/devices/<device_id>/rename": "session",
    "POST /auth/devices/<device_id>/revoke": "session",
    "POST /auth/devices/<device_id>/trust": "session",
    "POST /auth/login": "session",
    "POST /auth/logout": "session",
    "POST /auth/logout-all": "session",
    "POST /auth/mfa/email/request": "session",
    "POST /auth/mfa/email/verify": "session",
    "POST /auth/mfa/enroll": "session",
    "POST /auth/mfa/enroll/verify": "session",
    "POST /auth/mfa/factors/<factor_id>/revoke": "session",
    "POST /auth/mfa/recovery-codes/regenerate": "session",
    "POST /auth/mfa/reset/confirm": "session",
    "POST /auth/mfa/reset/request": "session",
    "POST /auth/mfa/webauthn/enroll/options": "session",
    "POST /auth/mfa/webauthn/enroll/verify": "session",
    "POST /auth/mfa/webauthn/login/verify": "session",
    "POST /auth/mfa/webauthn/step-up/options": "session",
    "POST /auth/mfa/webauthn/step-up/verify": "session",
    "POST /auth/password/change": "session",
    "POST /auth/password-reset/confirm": "session",
    "POST /auth/password-reset/request": "session",
    "POST /auth/register": "session",
    "POST /auth/revoke/device": "session",
    "POST /auth/revoke/refresh": "session",
    "POST /auth/sessions/<session_id>/renew": "session",
    "POST /auth/sessions/<session_id>/revoke": "session",
    "POST /auth/sso/oidc/callback": "session",
    "POST /auth/sso/oidc/token": "session",
    "POST /auth/verify-email": "session",
    "POST /auth/verify-email/resend": "session",
    "POST /internal/v1/developer-api-keys/sync": "service",
}

# The checked-in audit snapshot predates resource-level decorators in the
# runtime route definitions. These exact UNMAPPED observations are reconciled
# to the permissions required by those decorators.
ROUTE_AUDIT_UNMAPPED_WITH_RUNTIME_PERMISSION: Dict[str, str] = {
    "PATCH /api/v1/iam/api-clients/<client_id>": "manage:api_keys",
    "PATCH /api/v1/iam/service-identities/<identity_id>": "manage:users",
    "POST /api/v1/iam/api-clients/<client_id>/rotate-secret": "manage:api_keys",
    "POST /api/v1/iam/service-identities/<identity_id>/rotate-secret": "manage:users",
    "POST /auth/api-keys/<key_id>/revoke": "manage:api_keys",
    "POST /auth/api-keys/<key_id>/rotate": "manage:api_keys",
}

# Four duplicate audit rows disagree only because the older route scanner
# missed @require_resource_access; app_4_advanced_features.py confirms each
# permission explicitly. All other conflicting duplicates fail validation.
ROUTE_AUDIT_RESOLVED_CONFLICTS: Dict[str, str] = {
    "GET /on-call/schedule/<operator_id>": "read:discrepancies",
    "GET /webhooks/<webhook_id>/deliveries": "manage:webhooks",
    "PUT /escalation-rules/<rule_id>": "write:escalation_rules",
    "PUT /webhooks/<webhook_id>": "manage:webhooks",
}


def validate_route_audit_records(records: Iterable[str]) -> Dict[str, int]:
    """Validate that each audited route has one explicit, evidence-backed class.

    Returns counts for the unique route inventory. ``UNMAPPED`` is only
    accepted for routes listed in ENDPOINT_EXEMPTIONS; the small reconciliation
    allowlists above account for known stale scanner observations.
    """
    known_routes = set(ENDPOINT_PERMISSIONS) | set(ENDPOINT_EXEMPTIONS)
    if set(ENDPOINT_PERMISSIONS) & set(ENDPOINT_EXEMPTIONS):
        raise ValueError("routes cannot be both permission-mapped and exempt")
    if set(ROUTE_AUDIT_UNMAPPED_WITH_RUNTIME_PERMISSION) - set(ENDPOINT_PERMISSIONS):
        raise ValueError("runtime permission reconciliation is missing a policy mapping")
    if set(ROUTE_AUDIT_RESOLVED_CONFLICTS) - set(ENDPOINT_PERMISSIONS):
        raise ValueError("resolved audit conflict is missing a policy mapping")

    observed: Dict[str, List[str]] = {}
    for number, raw in enumerate(records, start=1):
        line = raw.strip()
        if not line:
            continue
        if "->" not in line:
            raise ValueError(f"invalid route audit row {number}: {line}")
        endpoint, classification = (part.strip() for part in line.rsplit("->", 1))
        if not endpoint or not classification:
            raise ValueError(f"invalid route audit row {number}: {line}")
        if endpoint not in known_routes:
            raise ValueError(f"unclassified route in audit row {number}: {endpoint}")
        observed.setdefault(endpoint, []).append(classification)

    missing = known_routes - set(observed)
    if missing:
        raise ValueError(f"classified routes missing from audit: {sorted(missing)}")

    for endpoint, values in observed.items():
        unique_values = set(values)
        expected_permission = ENDPOINT_PERMISSIONS.get(endpoint)
        if endpoint in ROUTE_AUDIT_RESOLVED_CONFLICTS:
            expected_values = {ROUTE_AUDIT_RESOLVED_CONFLICTS[endpoint], "UNMAPPED"}
        elif endpoint in ROUTE_AUDIT_UNMAPPED_WITH_RUNTIME_PERMISSION:
            expected_values = {"UNMAPPED"}
        elif expected_permission is not None:
            expected_values = {expected_permission}
        else:
            expected_values = {"UNMAPPED"}
        if unique_values != expected_values:
            raise ValueError(
                f"inconsistent classification for {endpoint}: "
                f"observed={sorted(unique_values)}, expected={sorted(expected_values)}"
            )

    return {
        "routes": len(observed),
        "mapped": sum(endpoint in ENDPOINT_PERMISSIONS for endpoint in observed),
        "exempt": sum(endpoint in ENDPOINT_EXEMPTIONS for endpoint in observed),
    }


CUSTOMER_SCOPE_CATALOG: FrozenSet[str] = frozenset(CORE_PERMISSIONS.keys())


def required_permission_for(method: str, path_template: str) -> Optional[str]:
    """Required permission for an endpoint. None = unmapped -> deny."""
    if not method or not path_template:
        return None
    return ENDPOINT_PERMISSIONS.get(f"{method.upper()} {path_template}")
