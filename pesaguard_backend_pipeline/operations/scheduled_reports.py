"""
Scheduled Reconciliation Reports Engine for PesaGuard.

Generates daily, weekly, or ad-hoc reconciliation performance summaries, calculating
discrepancy volumes, resolution rates, anomaly categories, and financial impact metrics.
"""

from __future__ import annotations

# Support direct script invocation as well as package execution.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from environment import required_env

import argparse
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import create_engine, distinct, func
from sqlalchemy.orm import sessionmaker

from localization_utils import format_ke_currency, format_ke_datetime
from models import Base, Discrepancy, Report, Transaction

logger = logging.getLogger("pesaguard.scheduled_reports")

DB_URL = required_env("DATABASE_URL")
if DB_URL.startswith("sqlite"):
    engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DB_URL, pool_pre_ping=True, pool_size=5, max_overflow=10)
try:
    from metrics import instrument_engine_query_timing
    instrument_engine_query_timing(engine)
except Exception:
    logger.debug("Scheduled reports engine query timing instrumentation skipped.", exc_info=True)
Session = sessionmaker(bind=engine, expire_on_commit=False)

def generate_report_for_tenant(
    tenant_id: str,
    days: int = 1,
    report_type: str = "daily",
) -> Dict[str, Any]:
    """Generate and persist a reconciliation summary report for a given tenant.

    Args:
        tenant_id: Target tenant identifier
        days: Lookback period window in days
        report_type: Report cadence type ('daily', 'weekly', 'monthly')

    Returns:
        Summary execution dict containing status and report_id
    """
    now = datetime.now(timezone.utc)
    period_end = now
    period_start = now - timedelta(days=days)

    with Session() as session:
        try:
            # Query discrepancies detected within the window
            discrepancies = (
                session.query(Discrepancy)
                .filter(
                    Discrepancy.tenant_id == tenant_id,
                    Discrepancy.detected_at >= period_start,
                    Discrepancy.detected_at <= period_end,
                )
                .all()
            )

            total_incidents = len(discrepancies)
            resolved_count = sum(bool(d.resolved)
                                 for d in discrepancies)
            open_count = total_incidents - resolved_count
            resolution_rate = (resolved_count / total_incidents * 100.0) if total_incidents > 0 else 100.0

            by_severity: Dict[str, int] = {}
            by_anomaly_type: Dict[str, int] = {}

            for d in discrepancies:
                sev = d.severity or "warning"
                by_severity[sev] = by_severity.get(sev, 0) + 1

                anom = d.anomaly_type or "unknown"
                by_anomaly_type[anom] = by_anomaly_type.get(anom, 0) + 1

            # Fetch total ingested transaction volume for context
            total_transactions = (
                session.query(func.count(Transaction.trans_id))
                .filter(
                    Transaction.tenant_id == tenant_id,
                    Transaction.created_at >= period_start,
                    Transaction.created_at <= period_end,
                )
                .scalar()
                or 0
            )

            content = {
                "generated_at": now.isoformat(),
                "generated_at_display": format_ke_datetime(now),
                "tenant_id": tenant_id,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat(),
                "report_type": report_type,
                "summary": {
                    "total_transactions_ingested": total_transactions,
                    "total_incidents": total_incidents,
                    "resolved_incidents": resolved_count,
                    "open_incidents": open_count,
                    "resolution_rate_percent": round(resolution_rate, 2),
                },
                "breakdown": {
                    "by_severity": by_severity,
                    "by_anomaly_type": by_anomaly_type,
                },
            }

            report_id = f"report_{uuid.uuid4().hex[:12]}"
            report = Report(
                id=report_id,
                tenant_id=tenant_id,
                report_type=report_type,
                period_start=period_start,
                period_end=period_end,
                content=content,
                status="generated",
                created_at=now,
            )
            session.add(report)
            session.commit()

            logger.info("Generated %s report_id=%s for tenant_id=%s", report_type, report_id, tenant_id)
            return {
                "status": "ok",
                "report_id": report_id,
                "tenant_id": tenant_id,
                "summary": content["summary"],
            }

        except Exception as exc:
            session.rollback()
            logger.exception("Failed generating report for tenant_id=%s: %s", tenant_id, exc)
            return {"status": "error", "tenant_id": tenant_id, "error": str(exc)}


def get_all_active_tenants() -> List[str]:
    """Retrieve all unique tenant identifiers across discrepancies and transactions."""
    with Session() as session:
        disc_tenants = session.query(distinct(Discrepancy.tenant_id)).filter(Discrepancy.tenant_id.isnot(None)).all()
        tenants = {t[0] for t in disc_tenants if t[0]}
        transaction_tenants = session.query(distinct(Transaction.tenant_id)).filter(Transaction.tenant_id.isnot(None)).all()
        tenants.update(t[0] for t in transaction_tenants if t[0])
        if not tenants:
            tenants.add("default")
        return sorted(list(tenants))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PesaGuard Scheduled Reconciliation Report Generator")
    parser.add_argument(
        "--tenant",
        default="all",
        help="Tenant ID to generate report for (use 'all' to process all tenants)",
    )
    parser.add_argument("--days", type=int, default=1, help="Lookback window in days (default: 1)")
    parser.add_argument("--type", default="daily", choices=["daily", "weekly", "monthly"], help="Report type cadence")
    args = parser.parse_args()

    target_tenants = get_all_active_tenants() if args.tenant.lower() == "all" else [args.tenant]

    logger.info("Starting report generation for %d tenant(s)...", len(target_tenants))
    results = [
        generate_report_for_tenant(tenant_id=t, days=args.days, report_type=args.type)
        for t in target_tenants
    ]

    print(json.dumps(results, indent=2))
