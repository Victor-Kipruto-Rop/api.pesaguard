"""
Enterprise Export and Customer Telemetry API Endpoints for PesaGuard.

Provides tenant-isolated data exports (CSV), audit histories, report listings,
dead-letter management views, and transaction lookup interfaces.
"""

from __future__ import annotations

import csv
import io
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from flask import Blueprint, Response, jsonify, request

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from action_audit import ActionAuditEntry
from auth_rbac import require_auth, require_tenant_access
from models import DeadLetter, Discrepancy, InternalRecord, Report, Transaction

logger = logging.getLogger("pesaguard.export_routes")

bp = Blueprint("export_routes", __name__, url_prefix="/v1")


def sanitize_csv_cell(value: Any) -> str:
    """Prefix spreadsheet formula starters before emitting user-controlled CSV cells."""
    if value is None:
        return ""
    text = str(value)
    return f"'{text}" if text.lstrip(" \t\r\n")[:1] in {"=", "+", "-", "@"} else text


def _get_db_session():
    """Lazily import and instantiate the database session factory."""
    try:
        from app_2 import SessionLocal
        return SessionLocal()
    except ImportError:
        from models import TaskSessionLocal
        return TaskSessionLocal()


@bp.route("/export/csv", methods=["GET"])
@require_auth(required_permission="read:discrepancies")
@require_tenant_access()
def export_csv():
    """Export tenant discrepancy records as a downloadable CSV stream."""
    tenant_id = request.args.get("tenant_id", "").strip()
    if not tenant_id:
        return jsonify({"error": "missing_tenant_id", "message": "tenant_id parameter is required."}), 400

    from_str = request.args.get("from", "").strip()
    to_str = request.args.get("to", "").strip()

    session = _get_db_session()
    try:
        query = session.query(Discrepancy).filter(Discrepancy.tenant_id == tenant_id)

        if from_str:
            try:
                from_dt = datetime.fromisoformat(from_str.replace("Z", "+00:00"))
                query = query.filter(Discrepancy.detected_at >= from_dt)
            except ValueError:
                return jsonify({"error": "invalid_date_format", "message": "Invalid 'from' ISO date format."}), 400

        if to_str:
            try:
                to_dt = datetime.fromisoformat(to_str.replace("Z", "+00:00"))
                query = query.filter(Discrepancy.detected_at <= to_dt)
            except ValueError:
                return jsonify({"error": "invalid_date_format", "message": "Invalid 'to' ISO date format."}), 400

        items = query.order_by(Discrepancy.detected_at.desc()).limit(5000).all()

        output = io.StringIO()
        fieldnames = ["id", "trans_id", "anomaly_type", "status", "severity", "resolved", "tenant_id", "detected_at"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for item in items:
            writer.writerow({
                "id": sanitize_csv_cell(item.id),
                "trans_id": sanitize_csv_cell(item.trans_id),
                "anomaly_type": sanitize_csv_cell(item.anomaly_type),
                "status": sanitize_csv_cell(item.status),
                "severity": sanitize_csv_cell(item.severity),
                "resolved": "true" if item.resolved else "false",
                "tenant_id": sanitize_csv_cell(item.tenant_id),
                "detected_at": sanitize_csv_cell(item.detected_at.isoformat() if item.detected_at else ""),
            })

        output.seek(0)
        filename = f"pesaguard-export-{tenant_id}-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as exc:
        logger.exception("Failed to generate CSV export for tenant_id=%s: %s", tenant_id, exc)
        return jsonify({"error": "export_failed", "message": "Failed to generate CSV export."}), 500
    finally:
        session.close()


@bp.route("/customers/<tenant_id>/deadletters", methods=["GET"])
@require_auth(required_permission="read:discrepancies")
@require_tenant_access()
def customer_deadletters(tenant_id: str):
    """Return dead-letter queue entries for a tenant."""
    session = _get_db_session()
    try:
        rows = (
            session.query(DeadLetter)
            .filter(DeadLetter.tenant_id == tenant_id)
            .order_by(getattr(DeadLetter, "created_at", getattr(DeadLetter, "received_at", None)).desc())
            .limit(200)
            .all()
        )
        items = []
        for r in rows:
            ts = getattr(r, "created_at", getattr(r, "received_at", None))
            items.append({
                "id": r.id,
                "reason": r.reason,
                "error_detail": r.error_detail,
                "processed": r.processed,
                "created_at": ts.isoformat() if ts else None,
            })
        return jsonify({"tenant_id": tenant_id, "items": items}), 200
    except Exception as exc:
        logger.exception("Failed fetching deadletters for tenant_id=%s: %s", tenant_id, exc)
        return jsonify({"error": "fetch_failed", "message": "Failed to retrieve dead-letter queue."}), 500
    finally:
        session.close()


@bp.route("/customers/<tenant_id>/reports", methods=["GET"])
@require_auth(required_permission="read:analytics")
@require_tenant_access()
def customer_reports(tenant_id: str):
    """List generated reconciliation reports for a tenant."""
    session = _get_db_session()
    try:
        rows = (
            session.query(Report)
            .filter(Report.tenant_id == tenant_id)
            .order_by(Report.period_start.desc())
            .limit(100)
            .all()
        )
        items = [{
            "id": r.id,
            "report_type": r.report_type,
            "period_start": r.period_start.isoformat() if r.period_start else None,
            "period_end": r.period_end.isoformat() if r.period_end else None,
            "content": r.content,
            "status": r.status,
        } for r in rows]
        return jsonify({"tenant_id": tenant_id, "items": items}), 200
    except Exception as exc:
        logger.exception("Failed fetching reports for tenant_id=%s: %s", tenant_id, exc)
        return jsonify({"error": "fetch_failed", "message": "Failed to retrieve reports."}), 500
    finally:
        session.close()


@bp.route("/customers/<tenant_id>/audit", methods=["GET"])
@require_auth(required_permission="read:settings")
@require_tenant_access()
def customer_audit(tenant_id: str):
    """Return historical action audit trail entries for a tenant."""
    session = _get_db_session()
    try:
        rows = (
            session.query(ActionAuditEntry)
            .filter(ActionAuditEntry.tenant_id == tenant_id)
            .order_by(ActionAuditEntry.created_at.desc())
            .limit(200)
            .all()
        )
        items = [{
            "id": a.id,
            "actor": a.actor,
            "action": a.action,
            "details": a.details,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        } for a in rows]
        return jsonify({"tenant_id": tenant_id, "items": items}), 200
    except Exception as exc:
        logger.exception("Failed fetching audit entries for tenant_id=%s: %s", tenant_id, exc)
        return jsonify({"error": "fetch_failed", "message": "Failed to retrieve audit trail."}), 500
    finally:
        session.close()


@bp.route("/customers/<tenant_id>/transactions", methods=["GET"])
@require_auth(required_permission="read:discrepancies")
@require_tenant_access()
def customer_transactions(tenant_id: str):
    """Return recent transaction events associated with the system."""
    since_str = request.args.get("since", "").strip()
    session = _get_db_session()
    try:
        query = (
            session.query(Transaction)
            .filter(Transaction.tenant_id == tenant_id)
            .order_by(Transaction.created_at.desc())
        )

        if since_str:
            try:
                cutoff = datetime.fromisoformat(since_str.replace("Z", "+00:00"))
                query = query.filter(Transaction.created_at >= cutoff)
            except ValueError:
                return jsonify({"error": "invalid_date_format", "message": "Invalid 'since' ISO timestamp."}), 400

        rows = query.limit(200).all()
        items = [{
            "trans_id": t.trans_id,
            "trans_amount": t.trans_amount,
            "msisdn": t.msisdn,
            "business_short_code": t.business_short_code,
            "trans_time": t.trans_time,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        } for t in rows]
        return jsonify({"tenant_id": tenant_id, "items": items}), 200
    except Exception as exc:
        logger.exception("Failed fetching transactions for tenant_id=%s: %s", tenant_id, exc)
        return jsonify({"error": "fetch_failed", "message": "Failed to retrieve transactions."}), 500
    finally:
        session.close()


@bp.route("/customers/<tenant_id>/transactions/<trans_id>", methods=["GET"])
@require_auth(required_permission="read:discrepancies")
@require_tenant_access()
def customer_transaction_detail(tenant_id: str, trans_id: str):
    """Return complete record for a transaction including raw payload and matched internal ledger record."""
    session = _get_db_session()
    try:
        txn = (
            session.query(Transaction)
            .filter(Transaction.tenant_id == tenant_id, Transaction.trans_id == trans_id)
            .first()
        )
        if not txn:
            return jsonify({"error": "not_found", "message": "Transaction record not found."}), 404

        matched_record = None
        candidate = (
            session.query(InternalRecord)
            .filter(
                InternalRecord.tenant_id == tenant_id,
                InternalRecord.phone_number == txn.msisdn,
            )
            .order_by(InternalRecord.synced_at.desc())
            .first()
        )
        if candidate is not None and abs((candidate.amount or 0.0) - (txn.trans_amount or 0.0)) < 0.01:
            matched_record = {
                "internal_ref": candidate.internal_ref,
                "amount": candidate.amount,
                "phone_number": candidate.phone_number,
                "status": candidate.status,
                "synced_at": candidate.synced_at.isoformat() if candidate.synced_at else None,
            }

        payload = {
            "tenant_id": tenant_id,
            "trans_id": txn.trans_id,
            "trans_amount": txn.trans_amount,
            "msisdn": txn.msisdn,
            "business_short_code": txn.business_short_code,
            "trans_time": txn.trans_time,
            "created_at": txn.created_at.isoformat() if txn.created_at else None,
            "raw_payload": txn.raw_payload,
            "matched_record": matched_record,
        }
        return jsonify(payload), 200
    except Exception as exc:
        logger.exception("Failed fetching transaction detail trans_id=%s for tenant_id=%s: %s", trans_id, tenant_id, exc)
        return jsonify({"error": "fetch_failed", "message": "Failed to retrieve transaction detail."}), 500
    finally:
        session.close()
