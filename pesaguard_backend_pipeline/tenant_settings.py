"""
Flask REST API Blueprint for PesaGuard Tenant Settings & Alert Testing.

Exposes management routes for retrieving tenant configuration parameters, patching
notification thresholds and data residency preferences, and dispatching test alerts.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from flask import Blueprint, jsonify, request, g

from pesaguard_backend_pipeline.alerting_service import AlertingService
from pesaguard_backend_pipeline.rbac import PERM_MANAGE_SETTINGS, PERM_VIEW_SETTINGS, enforce_permission, has_permission
from pesaguard_backend_pipeline.security_helpers import is_payload_within_limit, sanitize_error_message
from pesaguard_backend_pipeline.tenant_settings_store import TenantSettingsStore

logger = logging.getLogger("pesaguard.settings_api")

settings_bp = Blueprint("settings_api", __name__, url_prefix="/api/v1/settings")
settings_store = TenantSettingsStore()


def _get_current_context() -> tuple[str | None, str | None]:
    """Resolve tenant and role only from trusted authentication middleware.

    A caller-controlled X-Tenant-ID header is a selector, not proof of membership.
    This settings blueprint must not grant an implicit admin role when auth context
    is missing. Authentication middleware may populate g.tenant_id/g.user, or the
    authenticated principal may carry tenant_id and role directly.
    """
    user = getattr(g, "user", None)
    tenant_id = (
        str(getattr(g, "tenant_id", "") or "").strip()
        or str(getattr(user, "tenant_id", "") or "").strip()
        or None
    )
    role = (
        str(getattr(user, "role", "") or "").strip()
        or str(getattr(g, "role", "") or "").strip()
        or None
    )
    if not tenant_id or not role:
        return None, None
    if tenant_id.lower() in {"default", "unknown", "none", "null"}:
        return None, None
    return tenant_id, role


def _context_error(tenant_id: str | None, role: str | None):
    """Return a safe auth error when trusted tenant context is unavailable."""
    if not tenant_id or not role:
        return jsonify({
            "error": "unauthorized",
            "message": "Authenticated tenant context is required.",
        }), 401
    return None

@settings_bp.route("", methods=["GET"])
def get_tenant_settings():
    """Retrieve full merged settings configuration for the active tenant."""
    tenant_id, role = _get_current_context()

    if not has_permission(role, PERM_VIEW_SETTINGS):
        return jsonify({"error": "forbidden", "message": "Insufficient permissions to view settings."}), 403

    try:
        cfg = settings_store.get(tenant_id)
        residency = settings_store.get_residency_context(tenant_id)
        
        return jsonify({
            "status": "success",
            "tenant_id": tenant_id,
            "settings": cfg,
            "residency_compliance": residency,
        }), 200
    except Exception as exc:
        logger.exception("Error retrieving settings for tenant_id=%s: %s", tenant_id, exc)
        return jsonify({"error": "internal_error", "message": sanitize_error_message(exc)}), 500


@settings_bp.route("", methods=["PATCH"])
def update_tenant_settings():
    """Update settings parameters for the active tenant."""
    if not is_payload_within_limit(request):
        return jsonify({"error": "payload_too_large", "message": "Request payload exceeds size limit."}), 413

    tenant_id, role = _get_current_context()

    try:
        enforce_permission(role, PERM_MANAGE_SETTINGS, tenant_id=tenant_id)
    except PermissionError as exc:
        return jsonify({"error": "forbidden", "message": str(exc)}), 403

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_json", "message": "Request body must be a valid JSON object."}), 400

    try:
        updated_cfg = settings_store.update(tenant_id, payload)
        logger.info("Successfully updated settings for tenant_id=%s by role=%s", tenant_id, role)
        
        return jsonify({
            "status": "success",
            "message": "Tenant settings updated successfully.",
            "tenant_id": tenant_id,
            "settings": updated_cfg,
        }), 200
    except Exception as exc:
        logger.exception("Error updating settings for tenant_id=%s: %s", tenant_id, exc)
        return jsonify({"error": "update_failed", "message": sanitize_error_message(exc)}), 500


@settings_bp.route("/test-alert", methods=["POST"])
def trigger_test_alert():
    """Send a test verification notification to tenant's configured alert channels."""
    tenant_id, role = _get_current_context()

    try:
        enforce_permission(role, PERM_MANAGE_SETTINGS, tenant_id=tenant_id)
    except PermissionError as exc:
        return jsonify({"error": "forbidden", "message": str(exc)}), 403

    payload = request.get_json(silent=True) or {}
    target_channel = payload.get("channel")  # Optional override: 'slack', 'sms', 'email'

    try:
        tenant_cfg = settings_store.get(tenant_id)
        alert_service = AlertingService(tenant_settings=tenant_cfg)

        test_evaluation: Dict[str, Any] = {
            "trans_id": "TEST-PING-001",
            "tenant_id": tenant_id,
            "status": "needs_review",
            "severity": "warning",
            "anomalies": ["test_alert_verification"],
            "match": {"match_type": "none", "reason": "System verification test ping"},
        }

        dispatch_result = alert_service.handle_discrepancy(test_evaluation, override_channel=target_channel)

        return jsonify({
            "status": "success",
            "message": "Test alert successfully dispatched.",
            "tenant_id": tenant_id,
            "result": dispatch_result,
        }), 200

    except Exception as exc:
        logger.exception("Failed to dispatch test alert for tenant_id=%s: %s", tenant_id, exc)
        return jsonify({"error": "alert_dispatch_failed", "message": sanitize_error_message(exc)}), 500
