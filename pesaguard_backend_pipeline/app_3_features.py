"""Enterprise-grade, highly optimized, production-ready PesaGuard Advanced Features & API Gateway."""

from __future__ import annotations

from environment import required_env

import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from flask import Flask, Response, jsonify, request, g
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from werkzeug.exceptions import HTTPException

from action_audit import ActionAuditEntry
from auth_rbac import AuthRBAC, get_current_user, require_auth, require_tenant_access
from email_service import EmailService
from escalation_engine import EscalationEngine
from models import Base, DeadLetter, Discrepancy, Report
from on_call_service import OnCallService
from rate_limiter import get_rate_limit_status, rate_limit
from search_engine import AdvancedSearchEngine
from tenant_settings import TenantSettingsStore
from webhook_manager import WebhookManager

configure_logging = lambda: None  # Import from logging_utils if available
logger = logging.getLogger("pesaguard.advanced_features")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("PESAGUARD_ADVANCED_MAX_BODY_BYTES", "1048576"))
app.config["JSON_SORT_KEYS"] = False

DATABASE_URL = required_env("DATABASE_URL")


def create_db_engine(url: str):
    """Create a robust database engine with appropriate pooling and timeout settings."""
    if url.startswith("sqlite"):
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    else:
        engine = create_engine(
            url,
            pool_pre_ping=True,
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
            connect_args={"connect_timeout": 5} if "postgresql" in url else {},
        )
    try:
        from metrics import instrument_engine_query_timing
        instrument_engine_query_timing(engine)
    except Exception:
        logger.debug("Engine query timing instrumentation skipped.", exc_info=True)
    return engine


engine = create_db_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

email_service = EmailService()
settings_store = TenantSettingsStore()


def resolve_email_locale(tenant_id: Optional[str], user_id: Optional[str] = None, settings_path=None) -> str:
    """Resolve the localization preference for email notifications."""
    tenant = tenant_id or "default"
    store = TenantSettingsStore(str(settings_path)) if settings_path is not None else settings_store
    return store.resolve_locale(str(tenant), user_id=user_id, fallback_locale="en")


def _record_action_audit(session, tenant_id: str, actor: str, action: str, details: Optional[Dict[str, Any]] = None) -> None:
    """Record an immutable audit trail entry for privileged operations."""
    try:
        entry = ActionAuditEntry(
            id=f"audit_{int(datetime.now(timezone.utc).timestamp() * 1000)}_{uuid.uuid4().hex[:8]}",
            tenant_id=tenant_id,
            actor=actor,
            action=action,
            details=details or {},
            created_at=datetime.now(timezone.utc),
        )
        session.add(entry)
        session.commit()
    except Exception as exc:
        logger.exception("Failed to persist action audit entry: %s", exc)
        if session:
            session.rollback()


def _incident_belongs_to_tenant(session, incident_id: str, tenant_id: str) -> Optional[Discrepancy]:
    """Fetch a discrepancy record ensuring absolute tenant isolation (IDOR protection)."""
    return (
        session.query(Discrepancy)
        .filter(Discrepancy.id == incident_id, Discrepancy.tenant_id == tenant_id)
        .first()
    )


@app.after_request
def _inject_security_headers(response: Response) -> Response:
    """Inject robust security and CORS headers into all API responses."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(HTTPException)
def handle_http_exception(error: HTTPException) -> Response:
    return jsonify({
        "error": error.name.lower().replace(" ", "_"),
        "message": error.description,
        "status_code": error.code,
    }), error.code


@app.errorhandler(Exception)
def handle_internal_error(error: Exception) -> Response:
    logger.exception("Unhandled exception in Advanced Features API: %s", error)
    return jsonify({
        "error": "internal_server_error",
        "message": "An unexpected error occurred. Our engineering team has been notified.",
    }), 500


# ============================================================================
# AUTHENTICATION & TOKENS
# ============================================================================

_PBKDF2_ITERATIONS = 200_000


def _hash_password(password: str, salt_hex: str) -> str:
    """Compute secure PBKDF2-HMAC-SHA256 password hashes."""
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS).hex()


def _load_auth_users() -> Dict[str, Dict[str, Any]]:
    """Load authorized user database from secure environment variables."""
    raw = os.getenv("PESAGUARD_AUTH_USERS_JSON", "")
    if not raw:
        logger.error("PESAGUARD_AUTH_USERS_JSON environment variable is not configured.")
        return {}
    try:
        users = json.loads(raw)
        return {u["username"]: u for u in users if "username" in u}
    except (json.JSONDecodeError, TypeError, KeyError):
        logger.exception("PESAGUARD_AUTH_USERS_JSON payload is malformed.")
        return {}


def _verify_credentials(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Verify user credentials in constant time to prevent timing attacks."""
    users = _load_auth_users()
    user = users.get(username)
    if not user:
        return None
    try:
        computed = _hash_password(password, user["salt_hex"])
    except (KeyError, ValueError):
        logger.exception("Malformed auth record for username=%s", username)
        return None

    if not hmac.compare_digest(computed, user.get("password_hash_hex", "")):
        return None
    return user


if "login" not in app.view_functions:
    @app.route("/auth/login", methods=["POST"])
    def login():
        data = request.json or {}
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "missing_credentials", "message": "Username and password are required."}), 400

        user = _verify_credentials(username, password)
        if not user:
            from metrics import record_security_event
            record_security_event()
            logger.warning("Failed login attempt for username=%s", username)
            return jsonify({"error": "invalid_credentials", "message": "Invalid username or password."}), 401

        token = AuthRBAC.generate_token(
            user_id=f"user_{username}",
            username=username,
            tenant_id=user["tenant_id"],
            roles=user.get("roles", ["operator"]),
        )

        logger.info("Successful login for username=%s tenant_id=%s", username, user["tenant_id"])
        return jsonify({
            "token": token,
            "user_id": f"user_{username}",
            "username": username,
            "tenant_id": user["tenant_id"],
            "roles": user.get("roles", ["operator"]),
            "expires_in": AuthRBAC.ACCESS_TOKEN_TTL_MINUTES * 60,
        }), 200


@app.route("/auth/verify", methods=["GET"])
@require_auth()
def verify_token():
    """Verify current authentication token state and permissions."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "not_authenticated", "message": "Authentication context missing."}), 401

    return jsonify({
        "user_id": user.user_id,
        "username": user.username,
        "tenant_id": user.tenant_id,
        "roles": user.roles,
        "permissions": user.permissions,
    }), 200


@app.route("/auth/revoke", methods=["POST"])
@require_auth("manage:users")
def revoke_token():
    """Revoke an active authentication token."""
    payload = request.json or {}
    token = payload.get("token")
    if not token:
        return jsonify({"error": "missing_token", "message": "Token parameter is required."}), 400

    AuthRBAC.revoke_token(token)
    logger.info("Authentication token revoked successfully.")
    return jsonify({"status": "revoked"}), 200


# ============================================================================
# WEBHOOK MANAGEMENT
# ============================================================================

@app.route("/webhooks", methods=["POST"])
@require_auth("manage:webhooks")
@require_tenant_access()
def create_webhook():
    """Register a new outbound webhook configuration for a tenant."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    session = SessionLocal()

    try:
        webhook_mgr = WebhookManager(session)
        result = webhook_mgr.register_webhook(
            tenant_id=tenant_id,
            url=data.get("url"),
            event_types=data.get("event_types", ["escalation"]),
            retry_attempts=data.get("retry_attempts", 3),
            timeout_seconds=data.get("timeout_seconds", 10),
        )
        if "error" in result:
            return jsonify(result), 400

        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="create_webhook",
            details={"webhook_id": result.get("id"), "url": data.get("url"), "event_types": result.get("event_types")},
        )
        return jsonify(result), 201
    finally:
        session.close()


@app.route("/webhooks", methods=["GET"])
@require_auth("manage:webhooks")
@require_tenant_access()
def list_webhooks():
    """List all registered webhooks for a tenant."""
    tenant_id = request.args.get("tenant_id")
    session = SessionLocal()

    try:
        webhook_mgr = WebhookManager(session)
        webhooks = webhook_mgr.get_webhooks(tenant_id)
        return jsonify({
            "tenant_id": tenant_id,
            "webhooks": [
                {
                    "id": w.id,
                    "url": w.url,
                    "event_types": w.event_types,
                    "active": w.active,
                    "created_at": w.created_at.isoformat() if w.created_at else None,
                }
                for w in webhooks
            ],
        }), 200
    finally:
        session.close()


@app.route("/webhooks/<webhook_id>", methods=["PUT"])
@require_auth("manage:webhooks")
def update_webhook(webhook_id: str):
    """Update webhook configuration details."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    session = SessionLocal()

    try:
        webhook_mgr = WebhookManager(session)
        result = webhook_mgr.update_webhook(webhook_id, tenant_id=tenant_id, **data)
        if result.get("error") == "webhook_not_found":
            return jsonify(result), 404

        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id or getattr(current_user, "tenant_id", "default"),
            actor=getattr(current_user, "user_id", "system"),
            action="update_webhook",
            details={"webhook_id": webhook_id, **data},
        )
        return jsonify(result), 200
    finally:
        session.close()


@app.route("/webhooks/<webhook_id>/deliveries", methods=["GET"])
@require_auth("manage:webhooks")
def get_webhook_deliveries(webhook_id: str):
    """Retrieve delivery history logs for a specific webhook."""
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    tenant_id = request.args.get("tenant_id")
    session = SessionLocal()

    try:
        webhook_mgr = WebhookManager(session)
        deliveries = webhook_mgr.get_delivery_history(webhook_id, tenant_id=tenant_id, limit=limit)
        return jsonify({
            "webhook_id": webhook_id,
            "deliveries": deliveries,
        }), 200
    finally:
        session.close()


# ============================================================================
# ESCALATION RULES
# ============================================================================

@app.route("/escalation-rules", methods=["POST"])
@require_auth("write:escalation_rules")
@require_tenant_access()
def create_escalation_rule():
    """Create a custom automated escalation rule for a tenant."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    session = SessionLocal()

    try:
        engine_instance = EscalationEngine(session)
        result = engine_instance.create_rule(
            tenant_id=tenant_id,
            name=data.get("name"),
            description=data.get("description"),
            condition_field=data.get("condition_field"),
            condition_operator=data.get("condition_operator"),
            condition_value=data.get("condition_value"),
            action=data.get("action"),
            target=data.get("target"),
            webhook_url=data.get("webhook_url"),
            priority=data.get("priority", 0),
        )
        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="create_escalation_rule",
            details={"rule_id": result.get("id"), "name": data.get("name")},
        )
        return jsonify(result), 201
    finally:
        session.close()


@app.route("/escalation-rules", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def list_escalation_rules():
    """List active escalation rules for a tenant."""
    tenant_id = request.args.get("tenant_id")
    session = SessionLocal()

    try:
        engine_instance = EscalationEngine(session)
        rules = engine_instance.get_rules(tenant_id)
        return jsonify({
            "tenant_id": tenant_id,
            "rules": rules,
        }), 200
    finally:
        session.close()


@app.route("/escalation-rules/<rule_id>", methods=["PUT"])
@require_auth("write:escalation_rules")
def update_escalation_rule(rule_id: str):
    """Update an existing escalation rule configuration."""
    data = request.json or {}
    session = SessionLocal()

    try:
        engine_instance = EscalationEngine(session)
        result = engine_instance.update_rule(rule_id, **data)
        return jsonify(result), 200
    finally:
        session.close()


# ============================================================================
# ON-CALL ROTATIONS
# ============================================================================

@app.route("/on-call/rotations", methods=["POST"])
@require_auth("manage:on_call")
@require_tenant_access()
def create_on_call_rotation():
    """Create an on-call schedule rotation entry."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    session = SessionLocal()

    try:
        service = OnCallService(session)
        shift_start = datetime.fromisoformat(data.get("shift_start"))
        shift_end = datetime.fromisoformat(data.get("shift_end"))

        result = service.create_rotation(
            tenant_id=tenant_id,
            operator_id=data.get("operator_id"),
            operator_name=data.get("operator_name"),
            operator_email=data.get("operator_email"),
            operator_phone=data.get("operator_phone"),
            shift_start=shift_start,
            shift_end=shift_end,
            escalation_level=data.get("escalation_level", 1),
        )
        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="create_on_call_rotation",
            details={"operator_id": data.get("operator_id"), "shift_start": shift_start.isoformat(), "shift_end": shift_end.isoformat()},
        )
        return jsonify(result), 201
    finally:
        session.close()


@app.route("/on-call/rotations/active", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def get_active_on_call():
    """Retrieve active on-call coverage status for a tenant."""
    tenant_id = request.args.get("tenant_id")
    session = SessionLocal()

    try:
        service = OnCallService(session)
        rotations = service.get_active_rotations(tenant_id)
        coverage = service.get_coverage_status(tenant_id)

        return jsonify({
            "tenant_id": tenant_id,
            "coverage": coverage,
            "active_rotations": rotations,
        }), 200
    finally:
        session.close()


@app.route("/on-call/schedule/<operator_id>", methods=["GET"])
@require_auth("read:discrepancies")
def get_operator_schedule(operator_id: str):
    """Retrieve an operator's on-call schedule window."""
    tenant_id = request.args.get("tenant_id")
    days = request.args.get("days", 30, type=int)
    session = SessionLocal()

    try:
        service = OnCallService(session)
        schedule = service.get_operator_schedule(tenant_id, operator_id, days)
        return jsonify({
            "operator_id": operator_id,
            "tenant_id": tenant_id,
            "days": days,
            "schedule": schedule,
        }), 200
    finally:
        session.close()


@app.route("/on-call/bulk", methods=["POST"])
@require_auth("manage:on_call")
@require_tenant_access()
def bulk_create_on_call():
    """Bulk create multiple on-call schedule rotations."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    rotations_data = data.get("rotations", [])
    session = SessionLocal()

    try:
        service = OnCallService(session)
        result = service.bulk_create_rotations(tenant_id, rotations_data)
        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="bulk_create_on_call_rotations",
            details={"created": result.get("created", 0)},
        )
        return jsonify(result), 201
    finally:
        session.close()


# ============================================================================
# EMAIL NOTIFICATIONS
# ============================================================================

@app.route("/emails/reconciliation", methods=["POST"])
@require_auth("write:discrepancies")
@require_tenant_access()
def send_reconciliation_email():
    """Dispatch structured reconciliation report via email."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    recipient = data.get("recipient_email")
    report_data = data.get("report_data", {})
    session = SessionLocal()

    try:
        current_user = get_current_user()
        locale = resolve_email_locale(
            tenant_id,
            user_id=getattr(current_user, "user_id", None) or data.get("user_id") or request.args.get("user_id"),
        )
        result = email_service.send_reconciliation_report(
            session, tenant_id, recipient, report_data, locale=locale
        )
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="send_reconciliation_email",
            details={"recipient": recipient, "report_data": report_data},
        )
        return jsonify(result), 200
    finally:
        session.close()


@app.route("/emails/escalation", methods=["POST"])
@require_auth("write:discrepancies")
@require_tenant_access()
def send_escalation_email():
    """Dispatch critical incident escalation alert via email."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    recipient = data.get("recipient_email")
    incident = data.get("incident_data", {})
    session = SessionLocal()

    try:
        current_user = get_current_user()
        locale = resolve_email_locale(
            tenant_id,
            user_id=getattr(current_user, "user_id", None) or data.get("user_id") or request.args.get("user_id"),
        )
        result = email_service.send_escalation_notification(
            session, tenant_id, recipient, incident, locale=locale
        )
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="send_escalation_email",
            details={"recipient": recipient, "incident": incident},
        )
        return jsonify(result), 200
    finally:
        session.close()


@app.route("/emails/history", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def get_email_history():
    """Retrieve historical email notification delivery logs."""
    tenant_id = request.args.get("tenant_id")
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    session = SessionLocal()

    try:
        history = email_service.get_email_history(session, tenant_id, limit)
        return jsonify({
            "tenant_id": tenant_id,
            "emails": history,
        }), 200
    finally:
        session.close()


# ============================================================================
# ADVANCED SEARCH
# ============================================================================

@app.route("/search", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def advanced_search():
    """Execute advanced boolean text queries across discrepancies."""
    tenant_id = request.args.get("tenant_id")
    query = request.args.get("q", "")
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    session = SessionLocal()

    try:
        search = AdvancedSearchEngine(session)
        result = search.search(tenant_id, query, limit=limit, offset=offset)
        return jsonify(result), 200
    finally:
        session.close()


@app.route("/search/filters", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def search_filters():
    """Retrieve available filter facets for advanced search."""
    tenant_id = request.args.get("tenant_id")
    session = SessionLocal()

    try:
        search = AdvancedSearchEngine(session)
        filters = search.suggest_filters(tenant_id)
        return jsonify({
            "tenant_id": tenant_id,
            "available_filters": filters,
        }), 200
    finally:
        session.close()


@app.route("/search/structured", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def structured_search():
    """Execute structured filtering queries against reconciliation records."""
    tenant_id = request.args.get("tenant_id")
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    session = SessionLocal()

    try:
        search = AdvancedSearchEngine(session)
        result = search.search_by_filters(
            tenant_id=tenant_id,
            severity=request.args.get("severity"),
            status=request.args.get("status"),
            anomaly_type=request.args.get("anomaly_type"),
            resolved=request.args.get("resolved", type=lambda x: x.lower() == "true"),
            assignee=request.args.get("assignee"),
            days_back=request.args.get("days_back", 30, type=int),
            limit=limit,
            offset=offset,
        )
        return jsonify(result), 200
    finally:
        session.close()


# ============================================================================
# PUBLIC CUSTOMER-FACING ENDPOINTS
# ============================================================================

@app.route("/public/customers/<tenant_id>/reconciliations", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def public_get_reconciliations(tenant_id: str):
    """Retrieve secure, tenant-scoped recent reconciliation outcomes."""
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    session = SessionLocal()

    try:
        q = (
            session.query(Discrepancy)
            .filter(Discrepancy.tenant_id == tenant_id)
            .order_by(Discrepancy.detected_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = q.all()
        return jsonify({
            "tenant_id": tenant_id,
            "count": len(rows),
            "reconciliations": [
                {
                    "id": r.id,
                    "trans_id": r.trans_id,
                    "anomaly_type": r.anomaly_type,
                    "status": r.status,
                    "severity": r.severity,
                    "details": r.details,
                    "detected_at": r.detected_at.isoformat() if r.detected_at else None,
                    "resolved": bool(r.resolved),
                }
                for r in rows
            ],
        }), 200
    finally:
        session.close()


@app.route("/public/customers/<tenant_id>/reports", methods=["GET"])
@require_auth("read:analytics")
@require_tenant_access()
def public_get_reports(tenant_id: str):
    """Retrieve generated financial discrepancy reports for a tenant."""
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    session = SessionLocal()

    try:
        q = (
            session.query(Report)
            .filter(Report.tenant_id == tenant_id)
            .order_by(Report.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = q.all()
        return jsonify({
            "tenant_id": tenant_id,
            "count": len(rows),
            "reports": [
                {
                    "id": r.id,
                    "report_type": r.report_type,
                    "period_start": r.period_start.isoformat() if r.period_start else None,
                    "period_end": r.period_end.isoformat() if r.period_end else None,
                    "status": r.status,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "content": r.content,
                }
                for r in rows
            ],
        }), 200
    finally:
        session.close()


# ============================================================================
# RATE LIMITED BULK OPERATIONS
# ============================================================================

@app.route("/bulk/assign", methods=["POST"])
@require_auth("bulk:operations")
@rate_limit(max_requests_per_minute=5, tokens_per_request=1, endpoint_name="bulk_assign")
@require_tenant_access()
def bulk_assign_incidents():
    """Bulk assign incidents securely with rate limiting and strict tenant scoping."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    incident_ids = data.get("incident_ids", [])
    assignee = data.get("assignee")
    session = SessionLocal()

    try:
        updated = 0
        skipped_ids = []
        for incident_id in incident_ids[:100]:  # Hard cap at 100 per request
            incident = _incident_belongs_to_tenant(session, incident_id, tenant_id)
            if incident:
                incident.assignee = assignee
                updated += 1
            else:
                skipped_ids.append(incident_id)

        session.commit()
        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="bulk_assign_incidents",
            details={"updated": updated, "skipped_ids": skipped_ids, "assignee": assignee},
        )
        return jsonify({
            "updated": updated,
            "skipped_ids": skipped_ids,
            "rate_limit": get_rate_limit_status(),
        }), 200
    finally:
        session.close()


@app.route("/bulk/escalate", methods=["POST"])
@require_auth("bulk:operations")
@rate_limit(max_requests_per_minute=3, tokens_per_request=2, endpoint_name="bulk_escalate")
@require_tenant_access()
def bulk_escalate_incidents():
    """Bulk escalate incidents securely with rate limiting and strict tenant scoping."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    incident_ids = data.get("incident_ids", [])
    session = SessionLocal()

    try:
        escalated = []
        skipped_ids = []
        engine_instance = EscalationEngine(session)

        for incident_id in incident_ids[:50]:  # Hard cap at 50 per request
            incident = _incident_belongs_to_tenant(session, incident_id, tenant_id)
            if incident:
                result = engine_instance.evaluate_and_escalate(tenant_id, incident)
                escalated.append(result)
            else:
                skipped_ids.append(incident_id)

        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="bulk_escalate_incidents",
            details={"escalated_count": len(escalated), "skipped_ids": skipped_ids},
        )
        return jsonify({
            "escalated": len(escalated),
            "details": escalated,
            "skipped_ids": skipped_ids,
            "rate_limit": get_rate_limit_status(),
        }), 200
    finally:
        session.close()


if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    if debug_mode:
        logger.warning("Running with debug=True â€” never do this in production.")
    port = int(os.getenv("PORT", 5002))
    app.run(debug=debug_mode, host=os.getenv("PESAGUARD_BIND_HOST", "127.0.0.1"), port=port)
