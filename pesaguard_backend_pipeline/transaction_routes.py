"""Tenant-scoped transaction HTTP routes shared by the API entry points."""

from __future__ import annotations

import hashlib
import json
from datetime import timezone
from typing import Callable

from flask import Blueprint, jsonify, request
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from api_validation import ApiContractError, validate_transaction_create, validate_transaction_response
from auth_rbac import TENANT_ID_PATTERN, get_current_user, require_auth
from event_store import EventStore, ProcessResult
from models import (
    Discrepancy,
    FraudRiskAssessment,
    IdempotencyRecord,
    ProcessedTransaction,
    ReconciliationMatch,
    Transaction,
    TransactionEvent,
)


def _tenant_context():
    user = get_current_user()
    requested_tenant = request.headers.get("X-Tenant-ID", "").strip()
    authenticated_tenant = str(getattr(user, "tenant_id", "") or "").strip()

    if authenticated_tenant and requested_tenant and requested_tenant != authenticated_tenant:
        return None, (jsonify({"error": "tenant_access_denied", "message": "Tenant access denied."}), 403)

    tenant_id = authenticated_tenant or requested_tenant
    if not tenant_id:
        return None, (jsonify({"error": "tenant_context_required", "message": "Tenant context is required."}), 400)
    if not TENANT_ID_PATTERN.fullmatch(tenant_id):
        return None, (jsonify({"error": "invalid_tenant_id", "message": "Tenant ID is invalid."}), 400)
    return tenant_id, None


def _transaction_payload(transaction: Transaction) -> dict:
    created_at = transaction.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return {
        "id": transaction.id,
        "tenant_id": transaction.tenant_id,
        "trans_id": transaction.trans_id,
        "status": transaction.status,
        "trans_amount": str(transaction.trans_amount),
        "currency": transaction.currency,
        "created_at": created_at.isoformat(),
    }


def _request_hash(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _reconciliation_payload(session: Session, tenant_id: str, transaction: Transaction) -> dict:
    match = session.query(ReconciliationMatch).filter(
        ReconciliationMatch.tenant_id == tenant_id,
        ReconciliationMatch.transaction_id == transaction.trans_id,
    ).one_or_none()
    processed = session.query(ProcessedTransaction).filter(
        ProcessedTransaction.tenant_id == tenant_id,
        ProcessedTransaction.provider_account_id == transaction.provider_account_id,
        ProcessedTransaction.daraja_trans_id == transaction.trans_id,
    ).one_or_none()
    status_map = {
        "MATCHED": "matched",
        "PARTIAL": "partial",
        "MISMATCH": "mismatch",
        "UNMATCHED": "unmatched",
        "DUPLICATE": "unmatched",
        "PENDING": "pending",
        "EXCEPTION": "failed",
    }
    if match is not None:
        status = status_map.get(match.status, "failed")
    elif processed is not None:
        status = {
            "pending": "pending",
            "processing": "processing",
            "completed": "unmatched",
            "failed": "failed",
        }.get(processed.reconciliation_status, "pending")
    else:
        status = "pending"

    discrepancies = session.query(Discrepancy).filter(
        Discrepancy.tenant_id == tenant_id,
        Discrepancy.trans_id == transaction.trans_id,
    ).order_by(Discrepancy.detected_at.asc()).limit(100).all()
    events = session.query(TransactionEvent).filter(
        TransactionEvent.tenant_id == tenant_id,
        or_(
            TransactionEvent.transaction_id == transaction.id,
            TransactionEvent.trans_id == transaction.trans_id,
        ),
    ).order_by(TransactionEvent.created_at.asc()).limit(100).all()
    return {
        "transaction_id": transaction.id,
        "status": status,
        "exceptions": [
            {
                "code": item.anomaly_type,
                "message": item.status,
                "severity": item.severity,
            }
            for item in discrepancies
        ],
        "history": [
            {
                "event_type": item.event_type,
                "from_state": item.from_state,
                "to_state": item.to_state,
                "created_at": (
                    item.created_at.replace(tzinfo=timezone.utc)
                    if item.created_at.tzinfo is None
                    else item.created_at
                ).isoformat(),
            }
            for item in events
        ],
    }


def _risk_score_payload(transaction_id: str, assessment: FraudRiskAssessment) -> dict:
    return {
        "transaction_id": transaction_id,
        "risk_score": float(assessment.risk_score),
        "risk_level": assessment.risk_level,
        "anomalies": list(assessment.reason_codes or []),
    }


def create_transaction_blueprint(
    event_store: EventStore,
    session_factory: Callable[[], Session],
    write_session_factory: Callable[[], Session] | None = None,
) -> Blueprint:
    """Create transaction endpoints using the supplied durable store and DB sessions."""
    blueprint = Blueprint("transaction_api", __name__, url_prefix="/api/v1")
    write_session_factory = write_session_factory or session_factory

    @blueprint.post("/transactions")
    @require_auth(required_permission="write:transactions")
    def create_transaction():
        tenant_id, error = _tenant_context()
        if error is not None:
            return error

        payload = request.get_json(silent=True)
        try:
            validate_transaction_create(payload)
        except ApiContractError as exc:
            return jsonify({"error": "invalid_request", "message": str(exc)}), 400

        idempotency_key = request.headers.get("Idempotency-Key", "").strip()
        if not idempotency_key or len(idempotency_key) > 255:
            return jsonify({"error": "invalid_idempotency_key", "message": "A valid Idempotency-Key header is required."}), 400

        provider_transaction_id = str(payload.get("provider_transaction_id") or payload.get("TransID") or "").strip()
        provider_account = str(payload.get("provider_account_id") or payload.get("BusinessShortCode") or "").strip()
        if not provider_transaction_id or not provider_account:
            return jsonify({
                "error": "invalid_request",
                "message": "provider_transaction_id and provider_account_id are required.",
            }), 400

        normalized = dict(payload)
        normalized.setdefault("TransID", provider_transaction_id)
        normalized.setdefault("BusinessShortCode", provider_account)
        result = event_store.mark_processed(
            normalized,
            tenant_id=tenant_id,
            idempotency_key_override=idempotency_key,
        )
        if result is ProcessResult.ERROR:
            return jsonify({"error": "transaction_not_persisted", "message": "Transaction could not be persisted."}), 500

        response_payload = {
            "status": "accepted",
            "duplicate": result is ProcessResult.DUPLICATE,
            "idempotency_key": idempotency_key,
        }
        validate_transaction_response(response_payload)
        return jsonify(response_payload), 200

    @blueprint.get("/transactions/search")
    @require_auth(required_permission="read:transactions")
    def search_transactions():
        tenant_id, error = _tenant_context()
        if error is not None:
            return error

        try:
            page = int(request.args.get("page", "1"))
            per_page = int(request.args.get("per_page", "20"))
        except ValueError:
            return jsonify({"error": "invalid_pagination", "message": "page and per_page must be integers."}), 400
        if page < 1 or per_page < 1 or per_page > 100:
            return jsonify({"error": "invalid_pagination", "message": "page must be positive and per_page must be between 1 and 100."}), 400

        sort = request.args.get("sort", "created_at:desc")
        sort_field, separator, sort_direction = sort.partition(":")
        sort_columns = {
            "created_at": Transaction.created_at,
            "status": Transaction.status,
            "trans_amount": Transaction.trans_amount,
            "trans_id": Transaction.trans_id,
        }
        if not separator or sort_field not in sort_columns or sort_direction not in {"asc", "desc"}:
            return jsonify({"error": "invalid_sort", "message": "sort must use an allowed field and asc or desc direction."}), 400

        filter_text = request.args.get("filter", "").strip()
        if len(filter_text) > 200:
            return jsonify({"error": "invalid_filter", "message": "filter must not exceed 200 characters."}), 400

        session = session_factory()
        try:
            query = session.query(Transaction).filter(Transaction.tenant_id == tenant_id)
            if filter_text:
                escaped = filter_text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                pattern = f"%{escaped}%"
                query = query.filter(or_(
                    Transaction.id.ilike(pattern, escape="\\"),
                    Transaction.trans_id.ilike(pattern, escape="\\"),
                    Transaction.provider_transaction_id.ilike(pattern, escape="\\"),
                    Transaction.external_reference.ilike(pattern, escape="\\"),
                    Transaction.provider.ilike(pattern, escape="\\"),
                    Transaction.status.ilike(pattern, escape="\\"),
                    Transaction.currency.ilike(pattern, escape="\\"),
                ))

            total = query.count()
            sort_column = sort_columns[sort_field]
            ordering = sort_column.asc() if sort_direction == "asc" else sort_column.desc()
            rows = (
                query.order_by(ordering, Transaction.id.asc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )
            return jsonify({
                "items": [_transaction_payload(row) for row in rows],
                "page": page,
                "per_page": per_page,
                "total": total,
            }), 200
        finally:
            session.close()

    @blueprint.get("/transactions/<transaction_id>/status")
    @require_auth(required_permission="read:transactions")
    def transaction_status(transaction_id: str):
        tenant_id, error = _tenant_context()
        if error is not None:
            return error

        session = session_factory()
        try:
            transaction = session.query(Transaction).filter(
                Transaction.id == transaction_id,
                Transaction.tenant_id == tenant_id,
            ).one_or_none()
            if transaction is None:
                return jsonify({"error": "not_found", "message": "Transaction not found."}), 404
            return jsonify({
                "transaction_id": transaction.id,
                "status": transaction.status,
            }), 200
        finally:
            session.close()

    @blueprint.get("/transactions/<transaction_id>")
    @require_auth(required_permission="read:transactions")
    def get_transaction(transaction_id: str):
        tenant_id, error = _tenant_context()
        if error is not None:
            return error

        session = session_factory()
        try:
            transaction = session.query(Transaction).filter(
                Transaction.id == transaction_id,
                Transaction.tenant_id == tenant_id,
            ).one_or_none()
            if transaction is None:
                return jsonify({"error": "not_found", "message": "Transaction not found."}), 404
            return jsonify(_transaction_payload(transaction)), 200
        finally:
            session.close()

    @blueprint.post("/reconciliation/requests")
    @require_auth(required_permission="write:transactions")
    def request_reconciliation():
        tenant_id, error = _tenant_context()
        if error is not None:
            return error

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "invalid_request", "message": "A JSON object is required."}), 400
        transaction_id = str(payload.get("transaction_id") or "").strip()
        if not transaction_id or len(transaction_id) > 255:
            return jsonify({"error": "invalid_request", "message": "transaction_id is required."}), 400
        if set(payload) - {"transaction_id", "provider_account_id", "force"}:
            return jsonify({"error": "invalid_request", "message": "Request contains unsupported fields."}), 400
        if "force" in payload and type(payload["force"]) is not bool:
            return jsonify({"error": "invalid_request", "message": "force must be a boolean."}), 400
        if payload.get("force") is True:
            return jsonify({
                "error": "force_reconciliation_unsupported",
                "message": "Completed reconciliations cannot currently be forced to rerun.",
            }), 409

        idempotency_key = request.headers.get("Idempotency-Key", "").strip()
        if not idempotency_key or len(idempotency_key) > 255:
            return jsonify({"error": "invalid_idempotency_key", "message": "A valid Idempotency-Key header is required."}), 400

        session = write_session_factory()
        try:
            transaction = session.query(Transaction).filter(
                Transaction.id == transaction_id,
                Transaction.tenant_id == tenant_id,
            ).one_or_none()
            if transaction is None:
                return jsonify({"error": "not_found", "message": "Transaction not found."}), 404
            requested_account = payload.get("provider_account_id")
            if requested_account and str(requested_account) != transaction.provider_account_id:
                return jsonify({"error": "provider_account_mismatch", "message": "Provider account does not match the transaction."}), 409

            current = _reconciliation_payload(session, tenant_id, transaction)
            if current["status"] not in {"pending", "processing"}:
                return jsonify(current), 200

            request_digest = _request_hash(payload)
            record = session.query(IdempotencyRecord).filter_by(
                tenant_id=tenant_id,
                provider="reconciliation-api",
                idempotency_key=idempotency_key,
            ).one_or_none()
            if record is not None and record.request_hash != request_digest:
                return jsonify({"error": "idempotency_conflict", "message": "Idempotency-Key was reused with a different request."}), 409

            if record is None:
                record = IdempotencyRecord(
                    id=f"recon_req_{hashlib.sha256(f'{tenant_id}:{idempotency_key}'.encode()).hexdigest()[:24]}",
                    tenant_id=tenant_id,
                    provider="reconciliation-api",
                    idempotency_key=idempotency_key,
                    external_reference=transaction.trans_id,
                    provider_transaction_id=hashlib.sha256(
                        f"{transaction.id}:{idempotency_key}".encode("utf-8")
                    ).hexdigest(),
                    request_hash=request_digest,
                    response={"transaction_id": transaction.id, "status": "pending"},
                )
                session.add(record)
                try:
                    session.commit()
                except IntegrityError:
                    session.rollback()
                    record = session.query(IdempotencyRecord).filter_by(
                        tenant_id=tenant_id,
                        provider="reconciliation-api",
                        idempotency_key=idempotency_key,
                    ).one_or_none()
                    if record is None or record.request_hash != request_digest:
                        return jsonify({"error": "idempotency_conflict", "message": "Idempotency-Key conflicts with another request."}), 409

            from background_tasks import enqueue_reconciliation_request

            queued = enqueue_reconciliation_request(tenant_id, transaction.id, idempotency_key)
            if queued.get("status") != "queued":
                return jsonify({"error": "queue_unavailable", "message": "Reconciliation could not be queued."}), 503
            response_payload = {
                "transaction_id": transaction.id,
                "status": "pending",
                "job_id": queued["job_id"],
            }
            record.response = response_payload
            session.commit()
            return jsonify(response_payload), 202
        except SQLAlchemyError:
            session.rollback()
            return jsonify({"error": "reconciliation_unavailable", "message": "Reconciliation could not be requested."}), 503
        finally:
            session.close()

    @blueprint.get("/reconciliation/<transaction_id>")
    @require_auth(required_permission="read:transactions")
    def get_reconciliation(transaction_id: str):
        tenant_id, error = _tenant_context()
        if error is not None:
            return error

        session = session_factory()
        try:
            transaction = session.query(Transaction).filter(
                Transaction.id == transaction_id,
                Transaction.tenant_id == tenant_id,
            ).one_or_none()
            if transaction is None:
                return jsonify({"error": "not_found", "message": "Transaction not found."}), 404
            return jsonify(_reconciliation_payload(session, tenant_id, transaction)), 200
        finally:
            session.close()

    @blueprint.post("/fraud/analyse")
    @require_auth(required_permission="write:transactions")
    def analyse_fraud():
        tenant_id, error = _tenant_context()
        if error is not None:
            return error

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "invalid_request", "message": "A JSON object is required."}), 400
        transaction_id = str(payload.get("transaction_id") or "").strip()
        if not transaction_id or len(transaction_id) > 255:
            return jsonify({"error": "invalid_request", "message": "transaction_id is required."}), 400
        if set(payload) - {"transaction_id", "features"}:
            return jsonify({"error": "invalid_request", "message": "Request contains unsupported fields."}), 400
        if payload.get("features") not in (None, {}):
            return jsonify({"error": "invalid_features", "message": "Risk features are derived from trusted transaction history."}), 400
        idempotency_key = request.headers.get("Idempotency-Key", "").strip()
        if not idempotency_key or len(idempotency_key) > 255:
            return jsonify({"error": "invalid_idempotency_key", "message": "A valid Idempotency-Key header is required."}), 400

        session = write_session_factory()
        try:
            transaction = session.query(Transaction).filter(
                Transaction.id == transaction_id,
                Transaction.tenant_id == tenant_id,
            ).one_or_none()
            if transaction is None:
                return jsonify({"error": "not_found", "message": "Transaction not found."}), 404

            request_digest = _request_hash(payload)
            record = session.query(IdempotencyRecord).filter_by(
                tenant_id=tenant_id,
                provider="fraud-analysis",
                idempotency_key=idempotency_key,
            ).one_or_none()
            if record is not None:
                if record.request_hash != request_digest:
                    return jsonify({"error": "idempotency_conflict", "message": "Idempotency-Key was reused with a different request."}), 409
                if record.response:
                    return jsonify(record.response), 200

            from fraud_risk_engine import assess_transaction, persist_assessment

            history_rows = session.query(Transaction).filter(
                Transaction.tenant_id == tenant_id,
                Transaction.provider_account_id == transaction.provider_account_id,
                Transaction.id != transaction.id,
            ).order_by(Transaction.created_at.desc()).limit(100).all()
            history = [
                {
                    "TransID": item.trans_id,
                    "TransAmount": item.trans_amount,
                    "MSISDN": item.msisdn,
                    "BusinessShortCode": item.business_short_code,
                    "TransTime": item.trans_time,
                }
                for item in history_rows
            ]
            transaction_data = {
                "TransID": transaction.trans_id,
                "TransAmount": transaction.trans_amount,
                "Currency": transaction.currency,
                "MSISDN": transaction.msisdn,
                "BusinessShortCode": transaction.business_short_code,
                "TransTime": transaction.trans_time,
            }
            decision = assess_transaction(transaction_data, history)
            assessment = persist_assessment(session, tenant_id, transaction.trans_id, decision)
            response_payload = _risk_score_payload(transaction.id, assessment)

            if record is None:
                record = IdempotencyRecord(
                    id=f"fraud_req_{hashlib.sha256(f'{tenant_id}:{idempotency_key}'.encode()).hexdigest()[:24]}",
                    tenant_id=tenant_id,
                    provider="fraud-analysis",
                    idempotency_key=idempotency_key,
                    external_reference=transaction.trans_id,
                    provider_transaction_id=hashlib.sha256(
                        f"{transaction.id}:{idempotency_key}".encode("utf-8")
                    ).hexdigest(),
                    request_hash=request_digest,
                )
                session.add(record)
            record.response = response_payload
            session.commit()
            return jsonify(response_payload), 200
        except SQLAlchemyError:
            session.rollback()
            return jsonify({"error": "risk_analysis_unavailable", "message": "Risk analysis could not be completed."}), 503
        finally:
            session.close()

    @blueprint.get("/fraud/<transaction_id>")
    @require_auth(required_permission="read:transactions")
    def get_fraud_assessment(transaction_id: str):
        tenant_id, error = _tenant_context()
        if error is not None:
            return error

        session = session_factory()
        try:
            transaction = session.query(Transaction).filter(
                Transaction.tenant_id == tenant_id,
                or_(
                    Transaction.id == transaction_id,
                    Transaction.trans_id == transaction_id,
                ),
            ).one_or_none()
            if transaction is None:
                return jsonify({"error": "not_found", "message": "Transaction not found."}), 404
            assessment = session.query(FraudRiskAssessment).filter(
                FraudRiskAssessment.tenant_id == tenant_id,
                FraudRiskAssessment.transaction_id == transaction.trans_id,
            ).one_or_none()
            if assessment is None:
                return jsonify({"error": "not_found", "message": "Risk assessment not found."}), 404
            return jsonify(_risk_score_payload(transaction.id, assessment)), 200
        finally:
            session.close()

    return blueprint
