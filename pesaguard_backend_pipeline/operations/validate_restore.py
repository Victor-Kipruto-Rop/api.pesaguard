"""Validate a restored PesaGuard database against structural and integrity gates."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlparse


def _db_args(database_url: str) -> tuple[list[str], dict[str, str]]:
    parsed = urlparse(database_url)
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise ValueError("validate_restore requires a PostgreSQL DATABASE_URL")
    args = ["-h", parsed.hostname or "localhost", "-p", str(parsed.port or 5432), "-U", unquote(parsed.username or "postgres"), "-d", parsed.path.lstrip("/") or "postgres"]
    env = os.environ.copy()
    if parsed.password:
        env["PGPASSWORD"] = unquote(parsed.password)
    return args, env


def _query(database_url: str, sql: str) -> str:
    args, env = _db_args(database_url)
    result = subprocess.run(["psql", *args, "-At", "-v", "ON_ERROR_STOP=1", "-c", sql], capture_output=True, text=True, env=env, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def validate(database_url: str) -> dict[str, object]:
    """Post-restore integrity validation covering the Phase 8 exit gates.

    Returns a dict with status, record counts, constraint/index counts,
    transaction integrity, audit completeness, and amount checks.
    """
    tables = ["transactions", "processed_transactions", "transaction_outbox", "action_audit_entries", "fraud_risk_assessments"]
    counts = {table: int(_query(database_url, f"SELECT count(*) FROM {table}")) for table in tables}  # nosec B608: tables is a fixed internal allowlist.
    constraints = int(_query(database_url, "SELECT count(*) FROM pg_constraint WHERE conrelid = 'transactions'::regclass"))
    indexes = int(_query(database_url, "SELECT count(*) FROM pg_indexes WHERE tablename IN ('transactions', 'processed_transactions', 'transaction_outbox')"))
    audit_rows = int(_query(database_url, "SELECT count(*) FROM action_audit_entries"))
    reconciliation_rows = int(_query(database_url, "SELECT count(*) FROM reconciliation_matches"))

    # Transaction integrity: no processed_transaction may reference a missing transaction.
    orphaned_processed_transactions = int(
        _query(
            database_url,
            "SELECT count(*) FROM processed_transactions pt LEFT JOIN transactions t ON pt.transaction_id = t.id WHERE t.id IS NULL",
        )
    )

    # Audit completeness: every discrepancy must have at least one audit event.
    discrepancies_without_audit = int(
        _query(
            database_url,
            "SELECT count(*) FROM discrepancies d WHERE NOT EXISTS (SELECT 1 FROM action_audit_entries a WHERE a.details::text LIKE '%' || d.id::text || '%')",
        )
    )

    # Financial integrity: transaction and reconciliation totals must remain readable.
    transaction_amount_sum = float(_query(database_url, "SELECT COALESCE(SUM(trans_amount), 0) FROM transactions") or 0)
    reconciliation_amount_sum = float(
        _query(database_url, "SELECT COALESCE(SUM(amount), 0) FROM reconciliation_matches WHERE amount IS NOT NULL") or 0
    )

    integrity_ok = (
        constraints > 0
        and indexes > 0
        and counts["transactions"] >= counts["processed_transactions"]
        and orphaned_processed_transactions == 0
        and discrepancies_without_audit == 0
    )

    return {
        "status": "passed" if integrity_ok else "failed",
        "counts": counts,
        "constraints": constraints,
        "indexes": indexes,
        "audit_rows": audit_rows,
        "reconciliation_rows": reconciliation_rows,
        "orphaned_processed_transactions": orphaned_processed_transactions,
        "discrepancies_without_audit": discrepancies_without_audit,
        "transaction_amount_sum": transaction_amount_sum,
        "reconciliation_amount_sum": reconciliation_amount_sum,
        "application_functionality": "database_queries_succeeded",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default=os.getenv("DATABASE_URL", ""))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = validate(args.database_url)
    payload = json.dumps(result, indent=2, sort_keys=True)
    print(payload)
    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
