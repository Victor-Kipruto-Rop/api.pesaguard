"""Tenant-scoped APIs for operational workflows surfaced in app.pesaguard.

These endpoints persist workflow state and validate transitions. Settlement and
refund/reversal routes create review requests only; they never move funds.
Scheduled jobs are registered but require a production scheduler/worker to run
at the configured time. Report runs execute a bounded persisted-data summary.
"""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from typing import Any

from flask import Blueprint, jsonify, request
from sqlalchemy import func

from auth_rbac import get_current_user, require_auth
from action_audit import ActionAuditRecord, persist_audit_event
from models import Discrepancy, Transaction
from workflow_models import TenantWorkflowRecord

DOMAIN_PATHS = {
    "reconciliation-runs": "reconciliation_run",
    "matching-rules": "matching_rule",
    "data-quality-findings": "data_quality_finding",
    "reconciliation-schedules": "scheduled_reconciliation",
    "settlement-reviews": "settlement_review",
    "refund-reversal-requests": "refund_reversal_request",
    "report-definitions": "report_definition",
    "report-runs": "report_run",
    "fraud-investigations": "fraud_investigation",
    "privacy-requests": "privacy_request",
    "support-cases": "support_case",
}
VALID_STATUSES = {
    "reconciliation_run": {"draft", "requested", "queued", "running", "completed", "failed", "cancelled"},
    "matching_rule": {"draft", "open", "disabled"},
    "data_quality_finding": {"open", "triage", "in_progress", "resolved", "closed"},
    "scheduled_reconciliation": {"draft", "scheduled", "disabled", "cancelled"},
    "settlement_review": {"open", "pending_review", "approved", "rejected", "resolved", "closed"},
    "refund_reversal_request": {"requested", "pending_review", "approved", "rejected", "resolved", "closed"},
    "report_definition": {"draft", "open", "scheduled", "disabled"},
    "report_run": {"requested", "queued", "running", "completed", "failed", "cancelled"},
    "fraud_investigation": {"open", "triage", "in_progress", "needs_information", "resolved", "closed"},
    "privacy_request": {"requested", "pending_review", "approved", "rejected", "completed", "failed"},
    "support_case": {"open", "triage", "in_progress", "needs_information", "resolved", "closed"},
}
TITLE_LIMIT = 200
DESCRIPTION_LIMIT = 4000

ALLOWED_TRANSITIONS = {
    "reconciliation_run": {
        "draft": {"requested", "cancelled"}, "requested": {"queued", "running", "failed", "cancelled"},
        "queued": {"running", "failed", "cancelled"}, "running": {"completed", "failed"},
        "completed": set(), "failed": {"requested"}, "cancelled": set(),
    },
    "matching_rule": {"draft": {"open", "disabled"}, "open": {"disabled"}, "disabled": {"open"}},
    "data_quality_finding": {
        "open": {"triage", "in_progress", "resolved", "closed"},
        "triage": {"in_progress", "resolved", "closed"},
        "in_progress": {"triage", "resolved", "closed"},
        "resolved": {"closed"}, "closed": set(),
    },
    "scheduled_reconciliation": {
        "draft": {"scheduled", "disabled", "cancelled"}, "scheduled": {"disabled", "cancelled"},
        "disabled": {"scheduled", "cancelled"}, "cancelled": set(),
    },
    "settlement_review": {
        "open": {"pending_review", "closed"}, "pending_review": {"approved", "rejected"},
        "approved": {"resolved", "closed"}, "rejected": {"closed"}, "resolved": {"closed"}, "closed": set(),
    },
    "refund_reversal_request": {
        "requested": {"pending_review", "closed"}, "pending_review": {"approved", "rejected"},
        "approved": {"resolved", "closed"}, "rejected": {"closed"}, "resolved": {"closed"}, "closed": set(),
    },
    "report_definition": {
        "draft": {"open", "scheduled", "disabled"}, "open": {"scheduled", "disabled"},
        "scheduled": {"open", "disabled"}, "disabled": {"open"}, 
    },
    "report_run": {
        "requested": {"queued", "running", "completed", "failed", "cancelled"},
        "queued": {"running", "failed", "cancelled"}, "running": {"completed", "failed"},
        "completed": set(), "failed": {"requested"}, "cancelled": set(),
    },
    "fraud_investigation": {
        "open": {"triage", "in_progress", "closed"}, "triage": {"in_progress", "needs_information", "resolved", "closed"},
        "in_progress": {"needs_information", "resolved", "closed"},
        "needs_information": {"in_progress", "closed"}, "resolved": {"closed"}, "closed": set(),
    },
    "privacy_request": {
        "requested": {"pending_review"}, "pending_review": {"approved", "rejected"},
        "approved": set(), "rejected": set(), "completed": set(), "failed": set(),
    },
    "support_case": {
        "open": {"triage", "in_progress", "closed"}, "triage": {"in_progress", "needs_information", "resolved", "closed"},
        "in_progress": {"needs_information", "resolved", "closed"},
        "needs_information": {"in_progress", "closed"}, "resolved": {"closed"}, "closed": set(),
    },
}


def _contains_sensitive_evidence(value):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = "".join(character for character in str(key).lower() if character.isalnum())
            if normalized in {"rawpayload", "msisdn", "phonenumber", "accesstoken", "refreshtoken", "secret", "password", "apikey", "authorization", "privatekey"}:
                return True
            if _contains_sensitive_evidence(child):
                return True
    elif isinstance(value, list):
        return any(_contains_sensitive_evidence(item) for item in value)
    return False


def create_workflow_blueprint(session_factory):
    bp = Blueprint("tenant_workflow_api", __name__)

    def _tenant_user():
        user = get_current_user()
        tenant_id = str(getattr(user, "tenant_id", "") or "").strip()
        user_id = str(getattr(user, "user_id", "") or getattr(user, "id", "") or "").strip()
        if not tenant_id or not user_id:
            return None, None
        return tenant_id, user_id

    def _record_workflow_audit(session, *, tenant_id: str, user_id: str, action: str, domain: str, record_id: str, operation: str, version: int) -> None:
        """Persist an append-only audit event in the same transaction as a workflow mutation."""
        request_id = (request.headers.get("X-Request-ID") or "").strip()[:128] or None
        correlation_id = (request.headers.get("X-Correlation-ID") or "").strip()[:128] or None
        audit = ActionAuditRecord(
            tenant_id=tenant_id,
            actor=user_id,
            actor_id=user_id,
            actor_type="user",
            action=action,
            category="operations",
            outcome="success",
            resource_type=domain,
            resource_id=record_id,
            request_id=request_id,
            correlation_id=correlation_id,
            idempotency_key=f"workflow:{record_id}:{operation}:{version}",
            details={"domain": domain, "operation": operation, "status_version": version},
        )
        persist_audit_event(session, audit, event_type=f"workflow.{operation}")

    def _serialize(record: TenantWorkflowRecord) -> dict[str, Any]:
        return {
            "id": record.id,
            "tenant_id": record.tenant_id,
            "domain": record.domain,
            "status": record.status,
            "title": record.title,
            "description": record.description,
            "payload": record.payload or {},
            "version": record.version,
            "created_by": record.created_by,
            "updated_by": record.updated_by,
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "updated_at": record.updated_at.isoformat() if record.updated_at else None,
        }

    def _json_object():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return None, (jsonify({"error": "invalid_json", "message": "A JSON object is required."}), 400)
        return body, None

    def _validate(domain, body, creating=False):
        title = body.get("title")
        if creating and (not isinstance(title, str) or not title.strip()):
            return None, "title is required"
        if title is not None and (not isinstance(title, str) or not title.strip() or len(title.strip()) > TITLE_LIMIT):
            return None, "title must be a non-empty string of at most 200 characters"
        description = body.get("description")
        if description is not None and (not isinstance(description, str) or len(description) > DESCRIPTION_LIMIT):
            return None, "description must be at most 4000 characters"
        payload = body.get("payload", {})
        if not isinstance(payload, dict):
            return None, "payload must be a JSON object"
        status = body.get("status")
        if status is not None and status not in VALID_STATUSES[domain]:
            return None, "unsupported status for this workflow"
        if domain == "matching_rule":
            for key in ("amount_tolerance", "time_window_minutes"):
                if key in payload and (not isinstance(payload[key], (int, float)) or isinstance(payload[key], bool) or payload[key] < 0):
                    return None, f"{key} must be a non-negative number"
            if payload.get("currency") and (not isinstance(payload["currency"], str) or len(payload["currency"]) != 3):
                return None, "currency must be a three-character ISO currency code"
        elif domain == "scheduled_reconciliation":
            cadence = payload.get("cadence")
            if cadence not in {"hourly", "daily", "weekly", "monthly"}:
                return None, "cadence must be hourly, daily, weekly or monthly"
            timezone_name = payload.get("timezone", "Africa/Nairobi")
            if not isinstance(timezone_name, str) or not timezone_name or len(timezone_name) > 64:
                return None, "timezone must be a valid timezone name"
            try:
                ZoneInfo(timezone_name)
            except (ZoneInfoNotFoundError, ValueError):
                return None, "timezone must be a valid IANA timezone"
            if not isinstance(payload.get("enabled", True), bool):
                return None, "enabled must be boolean"
        elif domain in {"settlement_review", "refund_reversal_request"}:
            amount = payload.get("amount")
            if amount is not None and (not isinstance(amount, (int, float)) or isinstance(amount, bool) or amount <= 0):
                return None, "amount must be a positive number"
            currency = payload.get("currency", "KES")
            if not isinstance(currency, str) or len(currency) != 3 or currency.upper() != currency:
                return None, "currency must be an uppercase three-character ISO code"
            # Explicitly reject fields that could imply external financial execution.
            forbidden = {"execute", "execute_payment", "provider_command", "destination_account", "settlement_instruction"}
            if forbidden.intersection(payload):
                return None, "financial execution fields are not accepted; this API only records review requests"
        elif domain == "report_definition":
            if payload.get("report_type") not in {"transactions", "discrepancies", "reconciliation_summary"}:
                return None, "report_type must be transactions, discrepancies or reconciliation_summary"
            if "schedule" in payload:
                schedule = payload["schedule"]
                if not isinstance(schedule, dict):
                    return None, "schedule must be an object"
                if schedule.get("cadence") not in {"hourly", "daily", "weekly", "monthly"}:
                    return None, "schedule cadence must be hourly, daily, weekly or monthly"
                timezone_name = schedule.get("timezone", "Africa/Nairobi")
                if not isinstance(timezone_name, str) or not timezone_name or len(timezone_name) > 64:
                    return None, "schedule timezone must be a valid timezone name"
                try:
                    ZoneInfo(timezone_name)
                except (ZoneInfoNotFoundError, ValueError):
                    return None, "schedule timezone must be a valid IANA timezone"
                if not isinstance(schedule.get("enabled", True), bool):
                    return None, "schedule enabled must be boolean"
        elif domain == "report_run":
            if payload.get("report_type") not in {"transactions", "discrepancies", "reconciliation_summary"}:
                return None, "report_type must be transactions, discrepancies or reconciliation_summary"
        elif domain == "privacy_request":
            if payload.get("request_type") not in {"access", "export", "correction", "deletion"}:
                return None, "request_type must be access, export, correction or deletion"
            if payload.get("request_type") == "deletion" and payload.get("execute_immediately"):
                return None, "deletion requires a reviewed, separately authorized execution workflow"
        elif domain == "fraud_investigation":
            evidence = payload.get("evidence", [])
            if not isinstance(evidence, list) or len(evidence) > 100:
                return None, "evidence must be a list with at most 100 items"
            if any(not isinstance(item, dict) for item in evidence):
                return None, "each evidence item must be an object"
        return {"title": title.strip() if isinstance(title, str) else None,
                "description": description,
                "payload": payload,
                "status": status}, None

    def _list_domain(domain):
        tenant_id, _ = _tenant_user()
        if not tenant_id:
            return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
        try:
            page = max(1, min(1000000, int(request.args.get("page", "1"))))
            per_page = max(1, min(100, int(request.args.get("per_page", "25"))))
        except ValueError:
            return jsonify({"error": "invalid_pagination", "message": "page and per_page must be integers."}), 400
        status = request.args.get("status", "").strip()
        statuses = [item.strip() for item in status.split(",") if item.strip()] if status else []
        if statuses and (not statuses or any(item not in VALID_STATUSES[domain] for item in statuses)):
            return jsonify({"error": "invalid_status", "message": "Unsupported status filter."}), 400
        search = request.args.get("q", "").strip()[:200]
        session = session_factory()
        try:
            query = session.query(TenantWorkflowRecord).filter(
                TenantWorkflowRecord.tenant_id == tenant_id,
                TenantWorkflowRecord.domain == domain,
            )
            if statuses:
                query = query.filter(TenantWorkflowRecord.status.in_(statuses))
            if search:
                query = query.filter(TenantWorkflowRecord.title.ilike(f"%{search}%"))
            total = query.count()
            records = query.order_by(TenantWorkflowRecord.created_at.desc(), TenantWorkflowRecord.id.desc()).offset((page - 1) * per_page).limit(per_page).all()
            return jsonify({"items": [_serialize(item) for item in records], "page": page, "per_page": per_page, "total": total})
        finally:
            session.close()

    def _create_domain(domain):
        tenant_id, user_id = _tenant_user()
        if not tenant_id:
            return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
        body, error = _json_object()
        if error:
            return error
        valid, message = _validate(domain, body, creating=True)
        if message:
            return jsonify({"error": "validation_error", "message": message}), 400
        status = valid["status"] or ("requested" if domain in {"reconciliation_run", "report_run", "refund_reversal_request", "privacy_request"} else "open")
        if domain == "scheduled_reconciliation":
            status = valid["status"] or ("scheduled" if valid["payload"].get("enabled", True) else "disabled")
        if domain == "report_run":
            # A bounded execution reads only persisted rows belonging to the authenticated tenant.
            report_type = valid["payload"]["report_type"]
            session = session_factory()
            try:
                if report_type == "transactions":
                    count = session.query(func.count(Transaction.id)).filter(Transaction.tenant_id == tenant_id).scalar() or 0
                    amounts = session.query(Transaction.currency, func.sum(Transaction.trans_amount)).filter(
                        Transaction.tenant_id == tenant_id
                    ).group_by(Transaction.currency).all()
                    result = {
                        "report_type": report_type,
                        "row_count": int(count),
                        "recorded_amount_by_currency": {str(currency): str(amount or 0) for currency, amount in amounts},
                    }
                elif report_type == "discrepancies":
                    count = session.query(func.count(Discrepancy.id)).filter(Discrepancy.tenant_id == tenant_id).scalar() or 0
                    open_count = session.query(func.count(Discrepancy.id)).filter(Discrepancy.tenant_id == tenant_id, Discrepancy.resolved.is_(False)).scalar() or 0
                    result = {"report_type": report_type, "row_count": int(count), "open_count": int(open_count)}
                else:
                    tx_count = session.query(func.count(Transaction.id)).filter(Transaction.tenant_id == tenant_id).scalar() or 0
                    discrepancy_count = session.query(func.count(Discrepancy.id)).filter(Discrepancy.tenant_id == tenant_id).scalar() or 0
                    result = {"report_type": report_type, "transaction_count": int(tx_count), "discrepancy_count": int(discrepancy_count)}
                valid["payload"] = {**valid["payload"], "result": result, "executed_at": datetime.now(timezone.utc).isoformat(), "execution_mode": "synchronous_summary"}
                status = "completed"
            except Exception:
                session.rollback()
                return jsonify({"error": "report_execution_failed", "message": "Report summary could not be generated."}), 500
            finally:
                session.close()
        session = session_factory()
        try:
            record = TenantWorkflowRecord(
                tenant_id=tenant_id, domain=domain, status=status,
                title=valid["title"], description=valid["description"],
                payload=valid["payload"], created_by=user_id, updated_by=user_id,
            )
            session.add(record)
            session.flush()
            _record_workflow_audit(
                session, tenant_id=tenant_id, user_id=user_id,
                action="configuration.created", domain=domain, record_id=record.id,
                operation="created", version=record.version,
            )
            session.commit()
            return jsonify({"item": _serialize(record)}), 201
        except Exception:
            session.rollback()
            return jsonify({"error": "workflow_persistence_failed", "message": "Workflow record could not be saved."}), 500
        finally:
            session.close()

    def _get_domain_record(domain, record_id):
        tenant_id, _ = _tenant_user()
        if not tenant_id:
            return None, (jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403)
        session = session_factory()
        record = session.query(TenantWorkflowRecord).filter_by(id=record_id, tenant_id=tenant_id, domain=domain).first()
        if record is None:
            session.close()
            return None, (jsonify({"error": "not_found", "message": "Workflow record was not found."}), 404)
        return (session, record), None

    def _update_domain(domain, record_id):
        tenant_id, user_id = _tenant_user()
        if not tenant_id:
            return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
        body, error = _json_object()
        if error:
            return error
        result, error = _get_domain_record(domain, record_id)
        if error:
            return error
        session, record = result
        try:
            if body.get("version") is not None and body["version"] != record.version:
                return jsonify({"error": "version_conflict", "message": "The record changed; reload it before retrying.", "current_version": record.version}), 409
            valid, message = _validate(domain, body, creating=False)
            if message:
                return jsonify({"error": "validation_error", "message": message}), 400
            if valid["title"] is not None:
                record.title = valid["title"]
            if valid["description"] is not None:
                record.description = valid["description"]
            if "payload" in body:
                record.payload = valid["payload"]
            if valid["status"] is not None and valid["status"] != record.status:
                allowed = ALLOWED_TRANSITIONS[domain].get(record.status, set())
                if valid["status"] not in allowed:
                    return jsonify({"error": "invalid_status_transition", "message": f"Cannot transition {domain} from {record.status} to {valid['status']}."}), 409
                if domain in {"settlement_review", "refund_reversal_request", "privacy_request"}:
                    current_user = get_current_user()
                    roles = {str(role).lower() for role in (getattr(current_user, "roles", []) or [])}
                    if not roles.intersection({"admin", "owner", "finance_manager", "compliance_officer", "security_admin"}):
                        return jsonify({"error": "review_permission_required", "message": "A privileged reviewer is required to change this request status."}), 403
                if domain == "privacy_request" and valid["status"] == "completed":
                    return jsonify({"error": "separate_execution_required", "message": "A privacy request cannot be marked completed until an approved export/deletion execution workflow confirms completion."}), 409
                record.status = valid["status"]
            if domain in {"settlement_review", "refund_reversal_request"} and record.status in {"approved", "rejected"}:
                # Approval is a review decision only; no provider call or money movement is triggered.
                record.payload = {**(record.payload or {}), "review_decision_at": datetime.now(timezone.utc).isoformat()}
            record.updated_by = user_id
            record.version += 1
            record.updated_at = datetime.now(timezone.utc)
            _record_workflow_audit(
                session, tenant_id=tenant_id, user_id=user_id,
                action="configuration.updated", domain=domain, record_id=record.id,
                operation="updated", version=record.version,
            )
            session.commit()
            return jsonify({"item": _serialize(record)})
        except Exception:
            session.rollback()
            return jsonify({"error": "workflow_update_failed", "message": "Workflow record could not be updated."}), 500
        finally:
            session.close()

    for slug, domain in DOMAIN_PATHS.items():
        endpoint = slug.replace("-", "_")
        read_permission = "read:analytics" if domain in {"report_definition", "report_run"} else ("read:settings" if domain in {"privacy_request", "support_case"} else "read:discrepancies")
        write_permission = "write:settings" if domain in {"privacy_request", "support_case", "report_definition", "report_run"} else "write:discrepancies"
        bp.add_url_rule(f"/api/v1/{slug}", endpoint=f"list_{endpoint}", view_func=require_auth(read_permission)(_make_list(domain, _list_domain)), methods=["GET"])
        bp.add_url_rule(f"/api/v1/{slug}", endpoint=f"create_{endpoint}", view_func=require_auth(write_permission)(_make_create(domain, _create_domain)), methods=["POST"])
        bp.add_url_rule(f"/api/v1/{slug}/<record_id>", endpoint=f"get_{endpoint}", view_func=require_auth(read_permission)(_make_get(domain, _get_domain_record, _serialize)), methods=["GET"])
        bp.add_url_rule(f"/api/v1/{slug}/<record_id>", endpoint=f"update_{endpoint}", view_func=require_auth(write_permission)(_make_update(domain, _update_domain)), methods=["PATCH"])

    # Matching-rule deletion is a soft-disable to preserve auditability of prior runs.
    @bp.delete("/api/v1/matching-rules/<record_id>")
    @require_auth("write:discrepancies")
    def disable_matching_rule(record_id):
        tenant_id, user_id = _tenant_user()
        if not tenant_id:
            return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
        result, error = _get_domain_record("matching_rule", record_id)
        if error:
            return error
        session, record = result
        try:
            if record.status == "disabled":
                return jsonify({"item": _serialize(record), "already_disabled": True})
            record.status = "disabled"
            record.updated_by = user_id
            record.updated_at = datetime.now(timezone.utc)
            record.version += 1
            _record_workflow_audit(
                session, tenant_id=tenant_id, user_id=user_id,
                action="configuration.updated", domain="matching_rule", record_id=record.id,
                operation="soft_disabled", version=record.version,
            )
            session.commit()
            return jsonify({"item": _serialize(record), "disabled": True})
        except Exception:
            session.rollback()
            return jsonify({"error": "matching_rule_disable_failed", "message": "Matching rule could not be disabled."}), 500
        finally:
            session.close()

    # Evidence is append-only metadata attached to a tenant-scoped investigation.
    @bp.post("/api/v1/fraud-investigations/<record_id>/evidence")
    @require_auth("write:discrepancies")
    def append_investigation_evidence(record_id):
        tenant_id, user_id = _tenant_user()
        if not tenant_id:
            return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
        body, error = _json_object()
        if error:
            return error
        evidence = body.get("evidence")
        if not isinstance(evidence, dict):
            return jsonify({"error": "validation_error", "message": "evidence must be a JSON object."}), 400
        if not isinstance(evidence.get("type"), str) or not evidence["type"].strip():
            return jsonify({"error": "validation_error", "message": "evidence.type is required."}), 400
        if _contains_sensitive_evidence(evidence):
            return jsonify({"error": "sensitive_evidence_rejected", "message": "Raw payment payloads and sensitive credentials cannot be attached."}), 400
        result, error = _get_domain_record("fraud_investigation", record_id)
        if error:
            return error
        session, record = result
        try:
            payload = dict(record.payload or {})
            evidence_items = list(payload.get("evidence") or [])
            if len(evidence_items) >= 100:
                return jsonify({"error": "evidence_limit_reached", "message": "A case can contain at most 100 evidence items."}), 409
            evidence_items.append({
                **evidence,
                "evidence_id": "ev_" + __import__("uuid").uuid4().hex,
                "added_by": user_id,
                "added_at": datetime.now(timezone.utc).isoformat(),
            })
            payload["evidence"] = evidence_items
            record.payload = payload
            record.updated_by = user_id
            record.updated_at = datetime.now(timezone.utc)
            record.version += 1
            _record_workflow_audit(
                session, tenant_id=tenant_id, user_id=user_id,
                action="configuration.updated", domain="fraud_investigation", record_id=record.id,
                operation="evidence_appended", version=record.version,
            )
            session.commit()
            return jsonify({"item": _serialize(record)}), 201
        except Exception:
            session.rollback()
            return jsonify({"error": "evidence_persistence_failed", "message": "Evidence could not be attached."}), 500
        finally:
            session.close()

    return bp


def _make_get(domain, handler, serializer):
    def view(record_id):
        result, error = handler(domain, record_id)
        if error:
            return error
        session, record = result
        try:
            return jsonify({"item": serializer(record)})
        finally:
            session.close()
    view.__name__ = f"get_{domain}"
    return view


def _make_list(domain, handler):
    def view():
        return handler(domain)
    view.__name__ = f"list_{domain}"
    return view


def _make_create(domain, handler):
    def view():
        return handler(domain)
    view.__name__ = f"create_{domain}"
    return view


def _make_update(domain, handler):
    def view(record_id):
        return handler(domain, record_id)
    view.__name__ = f"update_{domain}"
    return view
