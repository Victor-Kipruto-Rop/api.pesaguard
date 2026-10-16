"""Register approved reconciliation cases and validate observed production outcomes."""
from __future__ import annotations

# Support direct script invocation as well as package execution.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from environment import required_env

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

try:
    from pesaguard_backend_pipeline.models import Base, ReconciliationGroundTruth, ReconciliationMatch
    from pesaguard_backend_pipeline.reconciliation_engine import measure_reconciliation, record_ground_truth
except ImportError:  # pragma: no cover - repo-root invocation fallback
    backend_root = Path(__file__).resolve().parents[1]
    if str(backend_root) not in sys.path:
        sys.path.insert(0, str(backend_root))
    from models import Base, ReconciliationGroundTruth, ReconciliationMatch
    from reconciliation_engine import measure_reconciliation, record_ground_truth


def load_cases(path: Path) -> list[dict[str, Any]]:
    cases = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise ValueError("ground-truth fixture must contain a non-empty JSON array")
    return cases


def register_cases(session: Any, cases: list[dict[str, Any]], tenant_id: str, approved_by: str, approval_reference: str) -> int:
    for case in cases:
        transaction_id = str(case["transaction_id"])
        row = record_ground_truth(
            session,
            tenant_id=tenant_id,
            transaction_id=transaction_id,
            expected_status=str(case["expected_status"]),
            approved_by=approved_by,
            approval_reference=approval_reference,
            notes=str(case.get("name") or ""),
        )
        row.source = "approved_business_case"
    session.commit()
    return len(cases)


def validate_cases(session: Any, tenant_id: str, validator: str) -> dict[str, Any]:
    rows = session.query(ReconciliationGroundTruth).filter_by(tenant_id=tenant_id).all()
    if not rows:
        raise ValueError("no approved ground-truth rows found for tenant")
    missing = []
    mismatches = []
    validated = 0
    actual_results = []
    expected_statuses = []
    for row in rows:
        expected_statuses.append(row.expected_status)
        match = session.query(ReconciliationMatch).filter_by(
            tenant_id=tenant_id,
            transaction_id=row.transaction_id,
        ).one_or_none()
        if match is None:
            missing.append(row.transaction_id)
            actual_results.append({"status": "MISSING"})
            continue
        row.actual_status = match.status
        row.validated_by = validator
        row.validated_at = datetime.now(timezone.utc)
        validated += 1
        actual_results.append({"status": match.status})
        if row.expected_status != match.status:
            mismatches.append({
                "transaction_id": row.transaction_id,
                "expected": row.expected_status,
                "actual": match.status,
            })
    session.commit()
    measured = measure_reconciliation(actual_results, expected_statuses)
    scorecard = {
        "precision": measured["precision"],
        "recall": measured["recall"],
        "false_positives": int(measured["false_positives"]),
        "false_negatives": int(measured["false_negatives"]),
        "known_cases": int(measured["known_cases"]),
        "correct_cases": int(measured["correct_cases"]),
    }
    certified = (
        not missing
        and not mismatches
        and scorecard["precision"] == 1.0
        and scorecard["recall"] == 1.0
        and scorecard["false_positives"] == 0
        and scorecard["false_negatives"] == 0
    )
    return {
        "approved_cases": len(rows),
        "validated_cases": validated,
        "missing_matches": missing,
        "mismatches": mismatches,
        "scorecard": scorecard,
        "certified": certified,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage approved reconciliation ground truth")
    parser.add_argument("command", choices=("register", "validate"))
    parser.add_argument("--fixture", type=Path, default=Path(__file__).parents[1] / "tests" / "fixtures" / "phase3_golden_dataset.json")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--database-url", default=required_env("DATABASE_URL"))
    parser.add_argument("--approved-by")
    parser.add_argument("--approval-reference")
    parser.add_argument("--validated-by")
    args = parser.parse_args()

    engine = create_engine(args.database_url, pool_pre_ping=True)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        if args.command == "register":
            if not args.approved_by or not args.approval_reference:
                parser.error("register requires --approved-by and --approval-reference")
            result = {
                "registered_cases": register_cases(
                    session,
                    load_cases(args.fixture),
                    args.tenant_id,
                    args.approved_by,
                    args.approval_reference,
                ),
                "tenant_id": args.tenant_id,
                "approval_reference": args.approval_reference,
            }
        else:
            if not args.validated_by:
                parser.error("validate requires --validated-by")
            result = validate_cases(session, args.tenant_id, args.validated_by)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("certified", True) else 2


if __name__ == "__main__":
    raise SystemExit(main())
