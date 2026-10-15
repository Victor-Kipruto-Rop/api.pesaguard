"""Enterprise-grade, production-ready read-only reconciliation dashboard and API service."""

from __future__ import annotations

from environment import required_env

import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from flask import Flask, Response, abort, jsonify, request
from sqlalchemy import and_, create_engine, func, select
from sqlalchemy.orm import sessionmaker
from werkzeug.exceptions import HTTPException

# Ensure storage models can be located cleanly
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "storage", "models"))
from models import Base, Discrepancy, Transaction  # noqa: E402

# Configure structured logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pesaguard.dashboard_api")

DATABASE_URL = required_env("DATABASE_URL")

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Production-grade SQLAlchemy engine with robust pooling and pre-ping
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
        connect_args={"connect_timeout": 5} if "postgresql" in DATABASE_URL else {},
    )
try:
    from metrics import instrument_engine_query_timing
    instrument_engine_query_timing(engine)
except Exception:
    logger.debug("app_1 engine query timing instrumentation skipped.", exc_info=True)
Session = sessionmaker(bind=engine, expire_on_commit=False)

# Statuses representing genuine blocking reconciliation issues
BLOCKING_STATUSES = {"needs_review", "missing_payment"}


def _require_dashboard_auth() -> None:
    """Validate administrative dashboard access tokens for secure telemetry retrieval."""
    if request.path == "/health" or request.method == "OPTIONS":
        return

    token = request.headers.get("X-Admin-Token")
    admin_api_token = os.getenv("PESAGUARD_ADMIN_API_TOKEN")
    
    if not admin_api_token:
        logger.error("PESAGUARD_ADMIN_API_TOKEN is not configured in the environment.")
        abort(500, description="Dashboard API authentication is misconfigured.")

    if not token or token != admin_api_token:
        try:
            from metrics import record_security_event
            record_security_event()
        except Exception:
            logger.debug("Security event hook skipped for unauthorized dashboard access.", exc_info=True)
        logger.warning("Unauthorized dashboard API access attempt from IP: %s", request.remote_addr)
        abort(403, description="Forbidden: Invalid or missing administrator token.")


@app.before_request
def _enforce_security_and_auth() -> None:
    _require_dashboard_auth()


@app.after_request
def _inject_security_headers(response: Response) -> Response:
    """Inject robust security and tracing headers into all responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(HTTPException)
def handle_http_exception(error: HTTPException) -> Response:
    return jsonify({
        "error": error.name,
        "message": error.description,
        "status_code": error.code,
    }), error.code


@app.errorhandler(Exception)
def handle_unexpected_error(error: Exception) -> Response:
    logger.exception("Unexpected error in dashboard API: %s", error)
    return jsonify({
        "error": "Internal Server Error",
        "message": "An unexpected error occurred while processing the request.",
        "status_code": 500,
    }), 500


@app.route("/health", methods=["GET"])
def health_check() -> Response:
    """Deep health check endpoint verifying database connectivity."""
    try:
        with engine.connect() as connection:
            connection.execute(select(1))
        return jsonify({"status": "healthy", "service": "dashboard-api", "timestamp": datetime.now(timezone.utc).isoformat()}), 200
    except Exception as exc:
        logger.error("Health check failed: Database unreachable: %s", exc)
        return jsonify({"status": "unhealthy", "error": str(exc)}), 503


@app.route("/api/discrepancies", methods=["GET"])
def list_discrepancies() -> Response:
    """
    Advanced paginated list of discrepancies with filtering options.

    Query parameters:
      - limit: Max rows to return (default 50, max 200)
      - offset: Pagination offset (default 0)
      - severity: Optional filter (e.g., critical, warning, info)
      - resolved: Optional boolean filter (true/false, default false)
      - tenant_id: Optional multi-tenant filter scope
      - search: Optional transaction ID or text search match
    """
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return jsonify({"error": "Validation Error", "message": "limit and offset parameters must be integers."}), 400

    severity = request.args.get("severity")
    resolved_param = request.args.get("resolved", "false").lower()
    resolved = resolved_param in {"true", "1", "yes"}
    tenant_id = request.args.get("tenant_id")
    search_query = request.args.get("search")

    session = Session()
    try:
        query = select(Discrepancy)
        
        # Apply filters conditionally
        filters = [Discrepancy.resolved == resolved]
        if severity:
            filters.append(Discrepancy.severity == severity)
        if tenant_id:
            filters.append(Discrepancy.tenant_id == tenant_id)
        if search_query:
            filters.append(Discrepancy.trans_id.ilike(f"%{search_query}%"))

        query = query.where(and_(*filters))
        
        # Count total matching records for pagination metadata
        count_query = select(func.count(Discrepancy.id)).where(and_(*filters))
        total_matching = session.execute(count_query).scalar() or 0

        # Fetch paginated rows
        query = query.order_by(Discrepancy.detected_at.desc()).offset(offset).limit(limit)
        rows = session.execute(query).scalars().all()

        return jsonify({
            "results": [
                {
                    "id": r.id,
                    "trans_id": r.trans_id,
                    "tenant_id": getattr(r, "tenant_id", "default"),
                    "anomaly_type": r.anomaly_type,
                    "severity": r.severity,
                    "status": getattr(r, "status", "unknown"),
                    "details": r.details,
                    "resolved": r.resolved,
                    "detected_at": r.detected_at.isoformat() if r.detected_at else None,
                }
                for r in rows
            ],
            "pagination": {
                "total_matching": total_matching,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + limit) < total_matching,
            },
        }), 200
    finally:
        session.close()


@app.route("/api/stats/summary", methods=["GET"])
def summary() -> Response:
    """
    Comprehensive reconciliation summary and performance metrics.
    Supports tenant-scoped filtering via `?tenant_id=...`.
    """
    tenant_id = request.args.get("tenant_id")

    session = Session()
    try:
        # Base queries with optional tenant scope
        tx_query = select(func.count(Transaction.id))
        disc_query = select(func.count(Discrepancy.id)).where(Discrepancy.resolved.is_(False))
        blocked_query = (
            select(func.count(func.distinct(Discrepancy.trans_id)))
            .where(
                Discrepancy.resolved.is_(False),
                Discrepancy.anomaly_type.in_(BLOCKING_STATUSES),
            )
        )

        if tenant_id:
            tx_query = tx_query.where(Transaction.tenant_id == tenant_id)
            disc_query = disc_query.where(Discrepancy.tenant_id == tenant_id)
            blocked_query = blocked_query.where(Discrepancy.tenant_id == tenant_id)

        total_transactions = session.execute(tx_query).scalar() or 0
        open_discrepancies_total = session.execute(disc_query).scalar() or 0
        blocked_transaction_count = session.execute(blocked_query).scalar() or 0

        # Severity breakdown for active open discrepancies
        severity_breakdown_query = (
            select(Discrepancy.severity, func.count(Discrepancy.id))
            .where(Discrepancy.resolved.is_(False))
        )
        if tenant_id:
            severity_breakdown_query = severity_breakdown_query.where(Discrepancy.tenant_id == tenant_id)
        severity_breakdown_query = severity_breakdown_query.group_by(Discrepancy.severity)
        
        severity_counts = {sev: count for sev, count in session.execute(severity_breakdown_query).all()}

        reconciliation_rate = (
            round(1.0 - (blocked_transaction_count / total_transactions), 4)
            if total_transactions > 0 else 1.0
        )

        return jsonify({
            "tenant_id": tenant_id or "all_tenants",
            "metrics": {
                "total_transactions": total_transactions,
                "open_discrepancies_total": open_discrepancies_total,
                "blocked_transactions": blocked_transaction_count,
                "reconciliation_rate": reconciliation_rate,
                "severity_breakdown": {
                    "critical": severity_counts.get("critical", 0),
                    "warning": severity_counts.get("warning", 0),
                    "info": severity_counts.get("info", 0),
                },
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 200
    finally:
        session.close()


if __name__ == "__main__":
    port = int(os.getenv("DASHBOARD_API_PORT", 5001))
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() in {"true", "1", "yes"}
    app.run(host=os.getenv("PESAGUARD_BIND_HOST", "127.0.0.1"), port=port, debug=debug_mode)
