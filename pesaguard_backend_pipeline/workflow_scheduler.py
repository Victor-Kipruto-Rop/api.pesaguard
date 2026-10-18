"""Durable dispatcher for scheduled reconciliation requests and report summaries.

The dispatcher is intentionally conservative: scheduled reconciliation creates a
queued workflow request for the reconciliation worker; it does not claim a run
has completed. Scheduled report summaries read persisted, tenant-scoped records
and store the bounded result in a report-run record. Neither path moves money.
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from calendar import monthrange
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import and_, create_engine, func
from sqlalchemy.orm import sessionmaker

from action_audit import ActionAuditRecord, persist_audit_event
from environment import required_env
from models import Base, Discrepancy, ProcessedTransaction, Transaction
from workflow_models import TenantWorkflowRecord

logger = logging.getLogger("pesaguard.workflow_scheduler")
CADENCES = {"hourly", "daily", "weekly", "monthly"}
MAX_BATCH = max(1, min(500, int(os.getenv("PESAGUARD_WORKFLOW_SCHEDULER_BATCH", "100"))))


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return _as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (TypeError, ValueError):
        return None


def _next_run(now: datetime, cadence: str, timezone_name: str) -> datetime:
    if cadence not in CADENCES:
        raise ValueError("Unsupported schedule cadence.")
    try:
        local = _as_utc(now).astimezone(ZoneInfo(timezone_name))
    except (ZoneInfoNotFoundError, ValueError, TypeError) as exc:
        raise ValueError("Invalid schedule timezone.") from exc
    if cadence == "hourly":
        following = local + timedelta(hours=1)
    elif cadence == "daily":
        following = local + timedelta(days=1)
    elif cadence == "weekly":
        following = local + timedelta(days=7)
    else:
        year = local.year + (1 if local.month == 12 else 0)
        month = 1 if local.month == 12 else local.month + 1
        day = min(local.day, monthrange(year, month)[1])
        following = local.replace(year=year, month=month, day=day)
    return following.astimezone(timezone.utc)


def _schedule_for(record: TenantWorkflowRecord) -> tuple[dict[str, Any], str] | None:
    payload = record.payload if isinstance(record.payload, dict) else {}
    if record.domain == "scheduled_reconciliation":
        config = payload
    elif record.domain == "report_definition":
        config = payload.get("schedule")
        if not isinstance(config, dict):
            return None
    else:
        return None
    if config.get("enabled", True) is not True:
        return None
    cadence = config.get("cadence")
    if cadence not in CADENCES:
        return None
    timezone_name = config.get("timezone", "Africa/Nairobi")
    if not isinstance(timezone_name, str):
        return None
    return config, timezone_name


def _report_summary(session, tenant_id: str, report_type: str) -> dict[str, Any]:
    if report_type == "transactions":
        count = session.query(Transaction.id).filter(Transaction.tenant_id == tenant_id).count()
        amounts = session.query(Transaction.currency, func.sum(Transaction.trans_amount)).filter(
            Transaction.tenant_id == tenant_id
        ).group_by(Transaction.currency).all()
        return {
            "report_type": report_type,
            "row_count": int(count),
            "recorded_amount_by_currency": {str(currency): str(amount or 0) for currency, amount in amounts},
        }
    if report_type == "discrepancies":
        count = session.query(Discrepancy.id).filter(Discrepancy.tenant_id == tenant_id).count()
        open_count = session.query(Discrepancy.id).filter(
            Discrepancy.tenant_id == tenant_id, Discrepancy.resolved.is_(False)
        ).count()
        return {"report_type": report_type, "row_count": int(count), "open_count": int(open_count)}
    if report_type == "reconciliation_summary":
        tx_count = session.query(Transaction.id).filter(Transaction.tenant_id == tenant_id).count()
        discrepancy_count = session.query(Discrepancy.id).filter(Discrepancy.tenant_id == tenant_id).count()
        return {
            "report_type": report_type,
            "transaction_count": int(tx_count),
            "discrepancy_count": int(discrepancy_count),
        }
    raise ValueError("Unsupported report type.")


def _audit(session, *, record: TenantWorkflowRecord, action: str, scheduled_for: str, run_id: str) -> None:
    audit = ActionAuditRecord(
        tenant_id=record.tenant_id,
        actor="workflow_scheduler",
        actor_id="workflow_scheduler",
        actor_type="system",
        action=action,
        category="operations",
        outcome="success",
        resource_type=record.domain,
        resource_id=record.id,
        idempotency_key=f"workflow-scheduler:{record.id}:{scheduled_for}",
        details={"schedule_id": record.id, "run_id": run_id, "scheduled_for": scheduled_for, "operation": "scheduled_run_dispatched"},
    )
    persist_audit_event(session, audit, event_type="workflow.scheduled_run_created")


def run_due_workflows(session_factory, *, now: datetime | None = None, limit: int = MAX_BATCH) -> dict[str, int]:
    """Dispatch due schedules atomically; safe to call repeatedly from multiple workers."""
    instant = _as_utc(now or datetime.now(timezone.utc))
    stats = {"scanned": 0, "dispatched": 0, "skipped": 0, "failed": 0}
    session = session_factory()
    try:
        candidates = (
            session.query(TenantWorkflowRecord)
            .filter(
                TenantWorkflowRecord.status == "scheduled",
                TenantWorkflowRecord.domain.in_(["scheduled_reconciliation", "report_definition"]),
            )
            .order_by(TenantWorkflowRecord.updated_at.asc(), TenantWorkflowRecord.id.asc())
            .limit(max(1000, min(10000, max(1, int(limit)) * 10)))
            .with_for_update(skip_locked=True)
            .all()
        )
        stats["scanned"] = len(candidates)
        for schedule in candidates:
            if stats["dispatched"] >= max(1, min(500, int(limit))):
                break
            try:
                selected = _schedule_for(schedule)
                if selected is None:
                    stats["skipped"] += 1
                    continue
                config, timezone_name = selected
                cadence = str(config["cadence"])
                payload = dict(schedule.payload or {})
                stored_next = config.get("next_run_at")
                due_at = _parse_datetime(stored_next)
                if due_at is None:
                    due_at = _next_run(schedule.created_at, cadence, timezone_name)
                if due_at > instant:
                    stats["skipped"] += 1
                    continue
                scheduled_for = due_at.isoformat()
                digest = hashlib.sha256(f"{schedule.tenant_id}:{schedule.id}:{scheduled_for}".encode("utf-8")).hexdigest()[:32]
                run_id = "wfr_" + digest
                existing = session.get(TenantWorkflowRecord, run_id)
                if existing is None and schedule.domain == "scheduled_reconciliation":
                    session.add(TenantWorkflowRecord(
                        id=run_id,
                        tenant_id=schedule.tenant_id,
                        domain="reconciliation_run",
                        status="queued",
                        title=(schedule.title + " — scheduled run")[:200],
                        description="Queued by the scheduler; completion requires the reconciliation worker.",
                        payload={
                            "schedule_id": schedule.id,
                            "scheduled_for": scheduled_for,
                            "cadence": cadence,
                            "execution_status": "queued_for_reconciliation_worker",
                        },
                        created_by="workflow_scheduler",
                        updated_by="workflow_scheduler",
                    ))
                elif existing is None and schedule.domain == "report_definition":
                    report_type = payload.get("report_type")
                    result = _report_summary(session, schedule.tenant_id, str(report_type or ""))
                    session.add(TenantWorkflowRecord(
                        id=run_id,
                        tenant_id=schedule.tenant_id,
                        domain="report_run",
                        status="completed",
                        title=(schedule.title + " — scheduled report")[:200],
                        description="Scheduled persisted-data summary; no downloadable artifact is implied.",
                        payload={
                            "report_type": report_type,
                            "result": result,
                            "definition_id": schedule.id,
                            "scheduled_for": scheduled_for,
                            "executed_at": instant.isoformat(),
                            "execution_mode": "scheduled_persisted_summary",
                        },
                        created_by="workflow_scheduler",
                        updated_by="workflow_scheduler",
                    ))
                payload["last_run_at"] = instant.isoformat()
                next_run_at = _next_run(instant, cadence, timezone_name).isoformat()
                if schedule.domain == "scheduled_reconciliation":
                    payload["next_run_at"] = next_run_at
                else:
                    config = dict(payload.get("schedule") or {})
                    config["next_run_at"] = next_run_at
                    payload["schedule"] = config
                schedule.payload = payload
                schedule.version += 1
                schedule.updated_at = instant
                schedule.updated_by = "workflow_scheduler"
                _audit(session, record=schedule, action="configuration.updated", scheduled_for=scheduled_for, run_id=run_id)
                session.commit()
                stats["dispatched"] += 1
            except Exception:
                session.rollback()
                stats["failed"] += 1
                logger.exception("Scheduled workflow dispatch failed; schedule will be retried.")
        return stats
    finally:
        session.close()


def _audit_run_transition(session, run: TenantWorkflowRecord, action: str, now: datetime, progress: dict[str, Any]) -> None:
    audit = ActionAuditRecord(
        tenant_id=run.tenant_id,
        actor="workflow_scheduler",
        actor_id="workflow_scheduler",
        actor_type="system",
        action="configuration.updated",
        category="operations",
        outcome="success",
        resource_type="reconciliation_run",
        resource_id=run.id,
        idempotency_key=f"workflow-run:{run.id}:{run.version}:{action}",
        details={"run_id": run.id, "status": run.status, "progress": progress, "worker_action": action},
    )
    persist_audit_event(session, audit, event_type="workflow.reconciliation_run")


def _pending_processed_query(session, tenant_id: str, payload: dict[str, Any]):
    query = session.query(ProcessedTransaction).filter(
        ProcessedTransaction.tenant_id == tenant_id,
        ProcessedTransaction.reconciliation_status == "pending",
        ProcessedTransaction.status.in_(["received", "validated", "stored"]),
    )
    provider_account_id = payload.get("provider_account_id")
    if provider_account_id:
        query = query.filter(ProcessedTransaction.provider_account_id == provider_account_id)
    for field_name, operator in (("start_at", ">="), ("end_at", "<=")):
        raw_value = payload.get(field_name)
        if raw_value is None:
            continue
        parsed = _parse_datetime(raw_value)
        if parsed is None:
            raise ValueError(f"{field_name} is not a valid timezone-aware timestamp")
        if operator == ">=":
            query = query.filter(ProcessedTransaction.received_at >= parsed)
        else:
            query = query.filter(ProcessedTransaction.received_at <= parsed)
    return query


def process_queued_reconciliation_runs(
    session_factory,
    *,
    now: datetime | None = None,
    max_runs: int = 5,
    batch_size: int = 100,
) -> dict[str, int]:
    """Execute queued runs over pending tenant transactions through the established reconciliation path."""
    import reconciliation_job

    instant = _as_utc(now or datetime.now(timezone.utc))
    max_runs = max(1, min(50, int(max_runs)))
    batch_size = max(1, min(500, int(batch_size)))
    stats = {"claimed": 0, "completed": 0, "continued": 0, "failed": 0, "skipped": 0, "transactions_attempted": 0}
    session = session_factory()
    try:
        candidate_ids = [
            item[0] for item in (
                session.query(TenantWorkflowRecord.id)
                .filter(
                    TenantWorkflowRecord.domain == "reconciliation_run",
                    TenantWorkflowRecord.status.in_(["requested", "queued", "running"]),
                )
                .order_by(TenantWorkflowRecord.created_at.asc(), TenantWorkflowRecord.id.asc())
                .limit(max_runs * 20)
                .all()
            )
        ]
        for run_id in candidate_ids:
            if stats["claimed"] >= max_runs:
                break
            run = (
                session.query(TenantWorkflowRecord)
                .filter_by(id=run_id, domain="reconciliation_run")
                .with_for_update(skip_locked=True)
                .first()
            )
            if run is None:
                continue
            payload = dict(run.payload or {})
            execution_status = payload.get("execution_status")
            if execution_status not in (None, "queued_for_reconciliation_worker", "running"):
                stats["skipped"] += 1
                session.rollback()
                continue
            lease_expiry = _parse_datetime(payload.get("lease_expires_at"))
            if run.status == "running" and lease_expiry is not None and lease_expiry > instant:
                stats["skipped"] += 1
                session.rollback()
                continue
            if run.status not in {"requested", "queued", "running"}:
                stats["skipped"] += 1
                session.rollback()
                continue

            payload["execution_status"] = "running"
            payload["started_at"] = payload.get("started_at") or instant.isoformat()
            payload["lease_expires_at"] = (instant + timedelta(minutes=5)).isoformat()
            run.status = "running"
            run.payload = payload
            run.updated_at = instant
            run.updated_by = "workflow_scheduler"
            run.version += 1
            _audit_run_transition(session, run, "reconciliation_run.started", instant, dict(payload.get("progress") or {}))
            session.commit()
            stats["claimed"] += 1

            tenant_id = run.tenant_id
            run_payload = dict(payload)
            try:
                pending_query = _pending_processed_query(session, tenant_id, run_payload)
                pending_count = pending_query.count()
                if pending_count == 0:
                    final_payload = dict(run_payload)
                    final_payload.update({
                        "execution_status": "completed",
                        "completed_at": instant.isoformat(),
                        "lease_expires_at": None,
                        "progress": {
                            **dict(final_payload.get("progress") or {}),
                            "pending_remaining": 0,
                            "last_batch_attempted": 0,
                        },
                    })
                    run.status = "completed"
                    run.payload = final_payload
                    run.updated_at = instant
                    run.updated_by = "workflow_scheduler"
                    run.version += 1
                    _audit_run_transition(session, run, "reconciliation_run.completed", instant, final_payload["progress"])
                    session.commit()
                    stats["completed"] += 1
                    continue

                joined_query = session.query(ProcessedTransaction, Transaction).join(
                    Transaction,
                    and_(
                        Transaction.tenant_id == ProcessedTransaction.tenant_id,
                        Transaction.provider_account_id == ProcessedTransaction.provider_account_id,
                        Transaction.trans_id == ProcessedTransaction.daraja_trans_id,
                    ),
                ).filter(
                    ProcessedTransaction.tenant_id == tenant_id,
                    ProcessedTransaction.reconciliation_status == "pending",
                    ProcessedTransaction.status.in_(["received", "validated", "stored"]),
                )
                if run_payload.get("provider_account_id"):
                    joined_query = joined_query.filter(
                        ProcessedTransaction.provider_account_id == run_payload["provider_account_id"]
                    )
                start_at = _parse_datetime(run_payload.get("start_at")) if run_payload.get("start_at") else None
                end_at = _parse_datetime(run_payload.get("end_at")) if run_payload.get("end_at") else None
                if start_at:
                    joined_query = joined_query.filter(ProcessedTransaction.received_at >= start_at)
                if end_at:
                    joined_query = joined_query.filter(ProcessedTransaction.received_at <= end_at)
                join_count = joined_query.count()
                if join_count < pending_count:
                    raise RuntimeError("pending_transaction_payload_missing")

                registry = reconciliation_job.ConnectorRegistry()
                connector = registry.get_connector(tenant_id)
                if connector is None:
                    raise RuntimeError("ledger_connector_unavailable")

                previous_progress = dict(run_payload.get("progress") or {})
                attempted_before = int(previous_progress.get("transactions_attempted", 0))
                max_transactions = max(1, min(5000, int(run_payload.get("max_transactions", 5000))))
                remaining_cap = max_transactions - attempted_before
                if remaining_cap <= 0:
                    raise RuntimeError("max_transactions_reached")
                rows = joined_query.order_by(
                    ProcessedTransaction.received_at.asc(),
                    ProcessedTransaction.id.asc(),
                ).limit(min(batch_size, remaining_cap)).all()
                attempted_this_batch = 0
                transaction_failed = False
                for processed_record, transaction in rows:
                    event = dict(transaction.raw_payload or {})
                    event.setdefault("TransID", processed_record.daraja_trans_id)
                    event["tenant_id"] = tenant_id
                    event.setdefault("provider_account_id", processed_record.provider_account_id)
                    if not reconciliation_job._process_message_unbounded(
                        event,
                        consumer=None,
                        producer=None,
                        connector_registry=registry,
                        reconciliation_run_id=run.id,
                    ):
                        transaction_failed = True
                        break
                    attempted_this_batch += 1
                    stats["transactions_attempted"] += 1

                session.expire_all()
                run = session.get(TenantWorkflowRecord, run_id)
                if run is None:
                    stats["failed"] += 1
                    continue
                current_payload = dict(run.payload or {})
                progress = dict(current_payload.get("progress") or {})
                attempted_total = int(progress.get("transactions_attempted", 0)) + attempted_this_batch
                pending_after = _pending_processed_query(session, tenant_id, run_payload).count()
                progress.update({
                    "transactions_attempted": attempted_total,
                    "last_batch_attempted": attempted_this_batch,
                    "pending_remaining": pending_after,
                    "last_batch_at": instant.isoformat(),
                })
                current_payload["progress"] = progress
                current_payload["lease_expires_at"] = None
                run.updated_at = instant
                run.updated_by = "workflow_scheduler"
                run.version += 1
                if transaction_failed:
                    run.status = "failed"
                    current_payload["execution_status"] = "failed"
                    current_payload["failure_reason"] = "transaction_processing_failed"
                    current_payload["completed_at"] = instant.isoformat()
                    stats["failed"] += 1
                    action = "reconciliation_run.failed"
                elif pending_after > 0 and attempted_total >= max_transactions:
                    run.status = "failed"
                    current_payload["execution_status"] = "failed"
                    current_payload["failure_reason"] = "max_transactions_reached"
                    current_payload["completed_at"] = instant.isoformat()
                    stats["failed"] += 1
                    action = "reconciliation_run.failed"
                elif pending_after > 0:
                    run.status = "queued"
                    current_payload["execution_status"] = "queued_for_reconciliation_worker"
                    stats["continued"] += 1
                    action = "reconciliation_run.continued"
                else:
                    run.status = "completed"
                    current_payload["execution_status"] = "completed"
                    current_payload["completed_at"] = instant.isoformat()
                    stats["completed"] += 1
                    action = "reconciliation_run.completed"
                run.payload = current_payload
                _audit_run_transition(session, run, action, instant, progress)
                session.commit()
            except Exception as exc:
                session.rollback()
                stats["failed"] += 1
                logger.exception("Scheduled reconciliation run failed run_id=%s error_type=%s", run_id, type(exc).__name__)
                failed_run = session.query(TenantWorkflowRecord).filter_by(
                    id=run_id, domain="reconciliation_run"
                ).with_for_update(skip_locked=True).first()
                if failed_run is not None:
                    failed_payload = dict(failed_run.payload or {})
                    failed_payload.update({
                        "execution_status": "failed",
                        "failure_reason": str(exc)[:100],
                        "completed_at": instant.isoformat(),
                        "lease_expires_at": None,
                    })
                    failed_run.status = "failed"
                    failed_run.payload = failed_payload
                    failed_run.updated_at = instant
                    failed_run.updated_by = "workflow_scheduler"
                    failed_run.version += 1
                    _audit_run_transition(session, failed_run, "reconciliation_run.failed", instant, dict(failed_payload.get("progress") or {}))
                    session.commit()
        return stats
    finally:
        session.close()


def main() -> None:
    import logging as _logging

    _logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
    database_url = required_env("DATABASE_URL")
    engine = create_engine(database_url, pool_pre_ping=True, pool_size=3, max_overflow=3)
    Base.metadata  # ensure model metadata is loaded before the worker starts
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    interval = max(5, int(os.getenv("PESAGUARD_WORKFLOW_SCHEDULER_INTERVAL_SECONDS", "30")))
    logger.info("Workflow scheduler started; interval=%s seconds", interval)
    try:
        while True:
            due_stats = run_due_workflows(session_factory)
            run_stats = process_queued_reconciliation_runs(session_factory)
            logger.info("Workflow scheduler cycle: schedules=%s reconciliation_runs=%s", due_stats, run_stats)
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Workflow scheduler stopping.")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
