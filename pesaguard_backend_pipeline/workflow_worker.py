"""Long-running worker for durable tenant reconciliation/report workflows.

Run as a separate process/container after database migrations have been applied:
    python pesaguard_backend_pipeline/workflow_worker.py

The worker dispatches due schedules and processes queued reconciliation requests.
It does not initiate payments, post settlements, or execute refunds.
"""
from __future__ import annotations

import logging
import os
import signal
import time
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from environment import required_env
from action_audit import Base as AuditBase  # noqa: F401 - registers audit metadata for migrations/tests
from models import Base  # noqa: F401 - registers application metadata
from workflow_models import TenantWorkflowRecord  # noqa: F401 - registers workflow metadata
from workflow_scheduler import process_queued_reconciliation_runs, run_due_workflows

logger = logging.getLogger("pesaguard.workflow_worker")
_STOP = False


def run_worker_cycle(session_factory, *, now=None) -> dict[str, dict[str, int]]:
    """Run one bounded dispatcher/worker cycle; injectable for deterministic tests."""
    scheduled = run_due_workflows(session_factory, now=now)
    reconciliation = process_queued_reconciliation_runs(session_factory, now=now)
    return {"scheduled_workflows": scheduled, "reconciliation_runs": reconciliation}


def _request_stop(signum, _frame) -> None:
    global _STOP
    logger.info("Received signal %s; worker will stop after the current cycle.", signum)
    _STOP = True


def main() -> int:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    poll_seconds = max(1.0, min(300.0, float(os.getenv("PESAGUARD_WORKFLOW_POLL_SECONDS", "10"))))
    database_url = required_env("DATABASE_URL")
    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=max(1, min(10, int(os.getenv("PESAGUARD_WORKFLOW_DB_POOL_SIZE", "3")))),
        max_overflow=max(0, min(10, int(os.getenv("PESAGUARD_WORKFLOW_DB_MAX_OVERFLOW", "2")))),
    )
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)
    logger.info("Workflow worker started; poll interval %.1fs.", poll_seconds)
    try:
        while not _STOP:
            started = time.monotonic()
            try:
                stats: dict[str, Any] = run_worker_cycle(session_factory)
                logger.info("Workflow cycle finished: %s", stats)
            except Exception:
                # Keep the process alive for transient database/connector failures.
                # Per-run leases and deterministic schedule IDs protect retries.
                logger.exception("Workflow cycle failed; retrying after poll interval.")
            elapsed = time.monotonic() - started
            if not _STOP:
                time.sleep(max(0.0, poll_seconds - elapsed))
    finally:
        engine.dispose()
        logger.info("Workflow worker stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
