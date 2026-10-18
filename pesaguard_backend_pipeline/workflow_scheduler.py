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

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

from action_audit import ActionAuditRecord, persist_audit_event
from environment import required_env
from models import Base, Discrepancy, Transaction
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
        details={"schedule_id": record.id, "run_id": run_id, "scheduled_for": scheduled_for},
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
            .limit(max(1, min(500, int(limit))))
            .with_for_update(skip_locked=True)
            .all()
        )
        stats["scanned"] = len(candidates)
        for schedule in candidates:
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
                    due_at = _as_utc(schedule.created_at) + {
                        "hourly": timedelta(hours=1),
                        "daily": timedelta(days=1),
                        "weekly": timedelta(days=7),
                        "monthly": timedelta(days=30),
                    }[cadence]
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
                _audit(session, record=schedule, action="scheduled_run_dispatched", scheduled_for=scheduled_for, run_id=run_id)
                session.commit()
                stats["dispatched"] += 1
            except Exception:
                session.rollback()
                stats["failed"] += 1
                logger.exception("Scheduled workflow dispatch failed; schedule will be retried.")
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
            logger.info("Workflow scheduler cycle: %s", run_due_workflows(session_factory))
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Workflow scheduler stopping.")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
