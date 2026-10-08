"""Robust M-Pesa webhook ingestion gateway for PesaGuard with rate limiting and verification."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional

import redis
from flask import Flask, Response, abort, jsonify, request, g
from werkzeug.exceptions import HTTPException

from observability import build_traceparent, init_opentelemetry, init_sentry, new_span_id, new_trace_id, trace_span
from otel_tracing import extract_trace_context

from background_tasks import enqueue_transaction_outbox_drain
from event_store import EventStore, ProcessResult, provider_account_id
from health import build_health_payload
from idempotency import derive_idempotency_key
from logging_utils import bind_observability_context, clear_observability_context, configure_logging, get_correlation_id, get_observability_context, set_correlation_id
from metrics import build_metrics_payload, record_http_request, record_business_metric, record_pipeline_event, record_security_event
from prometheus_auth import prometheus_token_matches
from rate_limiter import RateLimiter
from security_helpers import (
    get_client_ip,
    is_allowed_source,
    is_payload_within_limit,
    sanitize_error_message,
)
from shared.daraja.validator import validate_daraja_callback
from tenant_settings import TenantSettingsStore
from validators import validate_daraja_payload
from ingestion import IngestionError, IngestionService
from auth_rbac import AuthRBAC, get_current_user, require_auth
from transaction_routes import create_transaction_blueprint

configure_logging()
logger = logging.getLogger("pesaguard.webhook")

app = Flask(__name__)
init_opentelemetry(app=app)
init_sentry(service="webhook", provider="mpesa")
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("PESAGUARD_WEBHOOK_MAX_BODY_BYTES", "1048576"))

event_store = EventStore()
ingestion_service = IngestionService(event_store)
webhook_rate_limiter = RateLimiter()
webhook_rate_limiter.set_limits(int(os.getenv("PESAGUARD_WEBHOOK_RATE_LIMIT_PER_MINUTE", "30")))


def _transaction_read_session():
    event_store._ensure_ready()
    return event_store.Session()


app.register_blueprint(
    create_transaction_blueprint(event_store, _transaction_read_session)
)


tenant_store = TenantSettingsStore()


def _require_admin() -> None:
    """Enforce admin token authentication on sensitive configuration endpoints."""
    token = request.headers.get("X-Admin-Token")
    admin_api_token = os.getenv("PESAGUARD_ADMIN_API_TOKEN")
    if not admin_api_token or token != admin_api_token:
        record_security_event()
        logger.warning(
            "Admin API token authentication failed",
            extra={"source_ip": get_client_ip(request)},
        )
        abort(403)


@app.route("/admin/tenant/<tenant_id>", methods=["GET"])
def admin_get_tenant(tenant_id: str):
    _require_admin()
    return jsonify(tenant_store.get(tenant_id)), 200


@app.route("/admin/tenant/<tenant_id>", methods=["POST"])
def admin_update_tenant(tenant_id: str):
    _require_admin()
    payload = request.get_json(silent=True) or {}
    updated = tenant_store.update(tenant_id, payload)
    return jsonify(updated), 200


@app.route("/admin/tenant/<tenant_id>/residency", methods=["GET"])
def admin_get_residency(tenant_id: str):
    _require_admin()
    return jsonify(tenant_store.get_residency_context(tenant_id)), 200


@app.route("/admin/tenant/<tenant_id>/locale", methods=["POST"])
def admin_set_locale(tenant_id: str):
    _require_admin()
    payload = request.get_json(silent=True) or {}
    preferred = payload.get("preferred_locale")
    if not preferred:
        return jsonify({"error": "preferred_locale required"}), 400
    updated = tenant_store.update(tenant_id, {"preferred_locale": preferred})
    return jsonify(updated), 200


@app.route("/tenant/current", methods=["GET"])
@require_auth("read:settings")
def public_get_current_tenant():
    """Public, read-only endpoint returning limited tenant preferences for the current runtime tenant."""
    tenant_id = get_current_user().tenant_id
    settings = tenant_store.get(tenant_id)
    public = {
        "tenant_id": tenant_id,
        "preferred_locale": settings.get("preferred_locale"),
        "deployment_region": settings.get("deployment_region"),
    }
    return jsonify(public), 200


@app.route("/tenant/current/locale", methods=["GET"])
@require_auth("read:settings")
def public_get_current_locale():
    """Return tenant default, optional user override, and effective locale."""
    current_user = get_current_user()
    tenant_id = current_user.tenant_id
    user_id = current_user.user_id
    settings = tenant_store.get(tenant_id)
    user_locale = None
    if user_id:
        overrides = settings.get("user_locale_overrides") or {}
        if isinstance(overrides, dict):
            user_locale = overrides.get(user_id) or overrides.get(str(user_id))
    effective = tenant_store.resolve_locale(tenant_id, user_id)
    return jsonify({
        "tenant_id": tenant_id,
        "preferred_locale": settings.get("preferred_locale"),
        "user_locale": user_locale,
        "effective_locale": effective,
    }), 200


@app.route("/tenant/current/locale", methods=["POST"])
@require_auth("write:settings")
def public_set_current_tenant_locale():
    """Persist the current tenant's preferred locale through the public tenant endpoint."""
    payload = request.get_json(silent=True) or {}
    preferred = payload.get("preferred_locale")
    if not preferred:
        return jsonify({"error": "preferred_locale required"}), 400

    tenant_id = get_current_user().tenant_id
    updated = tenant_store.update(tenant_id, {"preferred_locale": preferred})
    return jsonify({"tenant_id": tenant_id, "preferred_locale": updated.get("preferred_locale")}), 200


@app.route("/tenant/current/user-locale", methods=["POST"])
@require_auth("write:settings")
def public_set_user_locale():
    """Persist a per-user locale override for the current tenant."""
    payload = request.get_json(silent=True) or {}
    user_id = payload.get("user_id")
    preferred = payload.get("preferred_locale")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    current_user = get_current_user()
    if str(user_id) != current_user.user_id and not AuthRBAC.check_permission(current_user, "manage:users"):
        return jsonify({"error": "user_access_denied"}), 403
    tenant_id = current_user.tenant_id
    existing = tenant_store.get(tenant_id)
    overrides = dict(existing.get("user_locale_overrides") or {})
    if preferred is None or preferred == "":
        overrides.pop(str(user_id), None)
    else:
        overrides[str(user_id)] = preferred
    tenant_store.update(tenant_id, {"user_locale_overrides": overrides})
    effective = tenant_store.resolve_locale(tenant_id, str(user_id))
    return jsonify({
        "tenant_id": tenant_id,
        "user_id": str(user_id),
        "user_locale": overrides.get(str(user_id)),
        "effective_locale": effective,
    }), 200


@app.errorhandler(413)
def handle_request_too_large(_error):
    return jsonify({"ResultCode": 1, "ResultDesc": "Request body too large"}), 413


@app.errorhandler(400)
def handle_bad_request(_error):
    return jsonify({"ResultCode": 1, "ResultDesc": "Invalid request"}), 400


@app.errorhandler(Exception)
def handle_internal_error(error):
    if isinstance(error, HTTPException):
        return error

    logger.exception("Unhandled exception in webhook receiver", exc_info=error)
    return jsonify({"ResultCode": 1, "ResultDesc": "Internal server error"}), 500


@app.before_request
def setup_request_context():
    """Set up a fresh per-request context including correlation ID for tracing."""
    clear_observability_context()
    request_id = request.headers.get("X-Request-ID") or str(__import__("uuid").uuid4())
    correlation_id = request.headers.get("X-Correlation-ID") or request_id
    incoming_trace = extract_trace_context({"traceparent": request.headers.get("traceparent", "")})
    header_trace_id = request.headers.get("X-Trace-ID", "").strip()
    valid_header_trace = len(header_trace_id) == 32 and all(char in "0123456789abcdef" for char in header_trace_id)
    trace_id = (incoming_trace or {}).get("trace_id") or (header_trace_id if valid_header_trace else new_trace_id())
    span_id = (incoming_trace or {}).get("span_id") or new_span_id()
    traceparent = build_traceparent(trace_id, span_id)
    set_correlation_id(correlation_id)
    bind_observability_context(
        request_id=request_id,
        correlation_id=correlation_id,
        trace_id=trace_id,
        span_id=span_id,
        traceparent=traceparent,
        tenant_id=request.headers.get("X-Tenant-ID") or os.getenv("TENANT_ID", ""),
    )
    g.request_started = __import__("time").perf_counter()


@app.after_request
def add_correlation_id_header(response):
    """Add correlation ID to response headers for client tracing."""
    correlation_id = get_correlation_id()
    response.headers["X-Correlation-ID"] = correlation_id
    context = get_observability_context()
    for header, key in (("X-Request-ID", "request_id"), ("X-Trace-ID", "trace_id")):
        if context.get(key):
            response.headers[header] = context[key]
    record_http_request(
        (__import__("time").perf_counter() - getattr(g, "request_started", __import__("time").perf_counter())) * 1000,
        status_code=response.status_code,
        timeout=response.status_code == 504,
    )
    return response




@app.teardown_request
def clear_request_context(_error=None):
    clear_observability_context()


@app.before_request
def enforce_webhook_security():
    if request.method == "OPTIONS":
        return None

    is_webhook_request = (
        request.path in {"/webhook", "/webhook/", "/webhook/mpesa/confirmation", "/webhook/mpesa/validation"}
        or request.path.startswith("/daraja")
        or request.path.startswith("/webhook/")
        or request.headers.get("X-Daraja-Shared-Secret") is not None
        or request.headers.get("X-PesaGuard-Signature") is not None
    )

    if not is_payload_within_limit(
        request,
        max_body_bytes=int(os.getenv("PESAGUARD_WEBHOOK_MAX_BODY_BYTES", "1048576"))
        if is_webhook_request
        else None,
    ):
        return jsonify({"ResultCode": 1, "ResultDesc": "Request body too large"}), 413

    if is_webhook_request:
        client_ip = get_client_ip(request)
        if not is_allowed_source(client_ip, request):
            record_security_event()
            logger.warning("Webhook request rejected: forbidden source IP", extra={"source_ip": client_ip})
            return jsonify({"ResultCode": 1, "ResultDesc": "Forbidden source"}), 403

        allowed, status = webhook_rate_limiter.is_allowed(
            client_ip,
            request.path,
        )
        if not allowed:
            record_security_event()
            logger.warning("Webhook request rejected: rate limit exceeded", extra={"source_ip": client_ip})
            response = jsonify({"ResultCode": 1, "ResultDesc": "Rate limit exceeded"})
            response.status_code = 429
            response.headers["Retry-After"] = str(status.get("retry_after", 60))
            return response

        daraja_signature = request.headers.get("X-Daraja-Signature")
        if daraja_signature:
            try:
                _verify_daraja_signature(request.data, daraja_signature)
            except Exception as e:
                record_security_event()
                logger.warning("Webhook signature verification failed", extra={"error": str(e)})
                return jsonify({"ResultCode": 1, "ResultDesc": "Invalid signature"}), 403


@require_auth("read:metrics")
def _authenticated_metrics():
    return Response(build_metrics_payload(), mimetype="text/plain; version=0.0.4")


@app.route("/metrics", methods=["GET"])
def metrics():
    if prometheus_token_matches(request):
        return Response(build_metrics_payload(), mimetype="text/plain; version=0.0.4")
    return _authenticated_metrics()


def _verify_daraja_signature(request_body: bytes, signature: str) -> None:
    """Verify incoming webhook signature from Daraja using constant-time comparison."""
    consumer_secret = os.getenv("DARAJA_CONSUMER_SECRET", "")
    if not consumer_secret:
        raise ValueError("DARAJA_CONSUMER_SECRET not configured")
    if not validate_daraja_callback(request_body, signature, consumer_secret):
        raise ValueError("Signature mismatch")


@app.route("/health", methods=["GET"])
def health():
    payload = build_health_payload()
    status_code = 200 if payload.get("status") == "ok" else 503
    return jsonify(payload), status_code


@app.route("/webhook/mpesa/confirmation", methods=["POST"])
def mpesa_confirmation():
    """Handles C2B confirmation callbacks from Daraja with strict idempotency and atomicity safeguards."""
    started = time.perf_counter()
    payload = request.get_json(silent=True)
    tenant_id = os.getenv("TENANT_ID", "").strip()

    if not tenant_id:
        logger.error("Webhook rejected because TENANT_ID is not configured")
        return jsonify({"ResultCode": 1, "ResultDesc": "Tenant context is required"}), 400

    if not payload:
        record_pipeline_event("entered", tenant_id=tenant_id or "default")
        record_pipeline_event("dead_lettered", tenant_id=tenant_id or "default", duration_ms=(time.perf_counter() - started) * 1000)
        logger.warning("Empty or invalid JSON payload received")
        try:
            event_store.write_dead_letter(None, reason="invalid_json", error_detail="empty_or_invalid_json", tenant_id=tenant_id)
        except Exception:
            logger.debug("Failed to persist dead-letter for invalid JSON payload", exc_info=True)
        return jsonify({"ResultCode": 1, "ResultDesc": "Invalid payload"}), 400

    if not is_payload_within_limit(request):
        return jsonify({"ResultCode": 1, "ResultDesc": "Request body too large"}), 413

    try:
        record_pipeline_event("entered", tenant_id=tenant_id)
        ingestion = ingestion_service.ingest("mpesa", payload, tenant_id=tenant_id)
    except IngestionError as error:
        record_pipeline_event("failed", tenant_id=tenant_id, duration_ms=(time.perf_counter() - started) * 1000)
        logger.warning("Payload validation failed: %s", error)
        try:
            event_store.write_dead_letter(payload, reason="validation_failed", error_detail=str(error), tenant_id=tenant_id)
        except Exception:
            logger.debug("Failed to persist dead-letter for validation failure", exc_info=True)
        return jsonify({"ResultCode": 1, "ResultDesc": sanitize_error_message(error)}), 400

    trans_id = ingestion.envelope.external_reference
    idempotency_key = ingestion.envelope.idempotency_key

    if ingestion.result == ProcessResult.DUPLICATE:
        record_pipeline_event("duplicate", tenant_id=tenant_id, duration_ms=(time.perf_counter() - started) * 1000)
        record_business_metric("duplicates")
        logger.info(
            "Duplicate transaction (pre-check)",
            extra={"tenant_id": tenant_id, "trans_id": trans_id, "idempotency_key": idempotency_key},
        )
        return jsonify({"ResultCode": 0, "ResultDesc": "Accepted (duplicate ignored)"}), 200

    result = ingestion.result

    if result == ProcessResult.DUPLICATE:
        record_pipeline_event("duplicate", tenant_id=tenant_id, duration_ms=(time.perf_counter() - started) * 1000)
        record_business_metric("duplicates")
        logger.info(
            "Duplicate transaction (caught at write time)",
            extra={"tenant_id": tenant_id, "trans_id": trans_id, "idempotency_key": idempotency_key},
        )
        return jsonify({"ResultCode": 0, "ResultDesc": "Accepted (duplicate ignored)"}), 200

    if result == ProcessResult.ERROR:
        record_pipeline_event("failed", tenant_id=tenant_id, duration_ms=(time.perf_counter() - started) * 1000)
        logger.error(
            "Failed to record transaction, requesting Daraja retry",
            extra={"tenant_id": tenant_id, "trans_id": trans_id, "idempotency_key": idempotency_key},
        )
        return jsonify({"ResultCode": 1, "ResultDesc": "Temporary processing error, please retry"}), 500

    record_business_metric("transactions_received")
    record_pipeline_event("succeeded", tenant_id=tenant_id, duration_ms=(time.perf_counter() - started) * 1000)

    # Best-effort Redis cache warm: maintain both the canonical idempotency key and
    # the legacy trans-id key expected by older callers and tests.
    try:
        redis_conn = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), socket_connect_timeout=2)
        cache_key = f"processed:{idempotency_key}"
        legacy_cache_key = f"processed_trans_id:{trans_id}"
        redis_conn.set(cache_key, "1", ex=86400)
        redis_conn.set(legacy_cache_key, "1", ex=86400)
    except Exception:
        pass

    queued = enqueue_transaction_outbox_drain()
    logger.info(
        "Transaction outbox delivery scheduled",
        extra={"trans_id": trans_id, "delivery_status": queued.get("status")},
    )

    return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"}), 200


@app.route("/api/v1/ingest/safaricom", methods=["POST"])
@require_auth("write:transactions")
def ingest_safaricom_api_transaction():
    """Accept a Safaricom API response through its provider adapter boundary."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_request", "message": "JSON object payload is required"}), 400
    tenant_id = str(get_current_user().tenant_id or "").strip()
    try:
        ingestion = ingestion_service.ingest("safaricom-api", payload, tenant_id=tenant_id)
    except IngestionError as exc:
        return jsonify({"error": "invalid_provider_payload", "message": str(exc)}), 400
    if ingestion.result == ProcessResult.ERROR:
        return jsonify({"error": "transaction_not_persisted"}), 500
    if ingestion.result == ProcessResult.STORED:
        enqueue_transaction_outbox_drain()
    return jsonify({
        "status": "accepted",
        "duplicate": ingestion.result == ProcessResult.DUPLICATE,
        "provider": ingestion.envelope.canonical.provider,
        "transaction_id": ingestion.envelope.canonical.transaction_id,
        "idempotency_key": ingestion.envelope.idempotency_key,
    }), 200


@app.route("/webhook/mpesa/validation", methods=["POST"])
def mpesa_validation():
    """Handles C2B validation callbacks (pre-confirmation)."""
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"ResultCode": 1, "ResultDesc": "Invalid payload"}), 400
    is_valid, error = validate_daraja_payload(payload)
    if not is_valid:
        logger.warning("Validation callback rejected: %s", error)
        return jsonify({"ResultCode": 1, "ResultDesc": sanitize_error_message(error)}), 400
    logger.info("Validation request for: %s", payload.get("TransID", "unknown"))
    return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"}), 200


@app.route("/ops/alerts", methods=["POST"])
def ops_alerts():
    """Receive Alertmanager webhook deliveries and account for them in telemetry.

    This endpoint closes the alerting loop: Prometheus rules -> Alertmanager
    routing -> PesaGuard webhook receiver. Every delivered alert is counted in
    business telemetry so the operational smoke test can verify end-to-end
    notification delivery without provider credentials.
    """
    import hmac as hmac_lib

    secret = os.getenv("PESAGUARD_ALERTMANAGER_WEBHOOK_SECRET", "").strip()
    if secret:
        provided = request.headers.get("X-Alertmanager-Secret", "")
        if not hmac_lib.compare_digest(provided, secret):
            record_security_event()
            logger.warning("Alertmanager webhook rejected: secret mismatch")
            return jsonify({"error": "invalid_alertmanager_secret"}), 401
    payload = request.get_json(silent=True) or {}
    alerts = payload.get("alerts") or []
    for alert in alerts:
        labels = alert.get("labels") or {}
        logger.warning(
            "Alertmanager alert delivered: alert=%s severity=%s status=%s",
            labels.get("alertname"),
            labels.get("severity"),
            alert.get("status") or payload.get("status"),
            extra={"alertname": labels.get("alertname"), "severity": labels.get("severity")},
        )
        record_business_metric("alertmanager_deliveries")
        if str(labels.get("severity")) == "critical":
            record_business_metric("alertmanager_critical_deliveries")
    return jsonify({"status": "accepted", "alerts": len(alerts)}), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host=os.getenv("PESAGUARD_BIND_HOST", "127.0.0.1"), port=port)
