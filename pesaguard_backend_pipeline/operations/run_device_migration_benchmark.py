"""Benchmark the user-device migration against isolated PostgreSQL session history."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, text


_MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "20261001_add_user_devices.py"


def _load_migration():
    spec = importlib.util.spec_from_file_location("pesaguard_device_migration", _MIGRATION_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load migration at {_MIGRATION_PATH}")
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    return migration


def run(
    database_url: str,
    session_rows: int,
    users: int,
    devices_per_user: int,
    max_migration_seconds: float | None = None,
    min_migration_rows_per_second: float | None = None,
    keep_schema: bool = False,
) -> dict[str, Any]:
    if not database_url.startswith(("postgresql://", "postgres://", "postgresql+psycopg2://")):
        raise ValueError("device migration benchmark requires PostgreSQL")
    if session_rows < 1 or users < 1 or devices_per_user < 1:
        raise ValueError("session_rows, users, and devices_per_user must all be positive")

    schema = f"pesaguard_device_bench_{uuid.uuid4().hex[:16]}"
    group_count = users * devices_per_user
    engine = create_engine(database_url, pool_pre_ping=True)
    result: dict[str, Any] = {"schema": schema, "session_rows_requested": session_rows, "users": users, "devices_per_user": devices_per_user}
    schema_created = False
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            connection.commit()
            schema_created = True
            connection.exec_driver_sql(f'SET search_path TO "{schema}"')
            connection.commit()

            connection.exec_driver_sql(
                """CREATE TABLE user_sessions (
                    id varchar PRIMARY KEY,
                    tenant_id varchar NOT NULL,
                    user_id varchar,
                    device_id varchar,
                    user_agent text,
                    ip_address varchar(64),
                    issued_at timestamptz NOT NULL,
                    last_activity_at timestamptz
                )"""
            )
            connection.commit()

            seed_started = time.perf_counter()
            connection.execute(text("""
                INSERT INTO user_sessions (
                    id, tenant_id, user_id, device_id, user_agent, ip_address, issued_at, last_activity_at
                )
                SELECT
                    'session-' || n::text,
                    'tenant-' || ((dims.group_id / :devices_per_user) % 100)::text,
                    'user-' || (dims.group_id / :devices_per_user)::text,
                    'device-' || (dims.group_id % :devices_per_user)::text,
                    CASE WHEN dims.session_number = 0 THEN 'latest-agent' ELSE 'historical-agent' END,
                    '192.0.2.' || ((dims.group_id % 250) + 1)::text,
                    now() - dims.session_number * interval '1 second',
                    now() - dims.session_number * interval '1 second'
                FROM generate_series(1, :session_rows) AS series(n)
                CROSS JOIN LATERAL (
                    SELECT (n - 1) % :group_count AS group_id,
                           (n - 1) / :group_count AS session_number
                ) AS dims
            """), {
                "session_rows": session_rows,
                "group_count": group_count,
                "devices_per_user": devices_per_user,
            })
            connection.commit()
            seed_seconds = time.perf_counter() - seed_started
            connection.exec_driver_sql("ANALYZE user_sessions")
            connection.commit()

            migration = _load_migration()
            migration_started = time.perf_counter()
            with connection.begin():
                with Operations.context(MigrationContext.configure(connection)):
                    migration.upgrade()
            migration_seconds = time.perf_counter() - migration_started

            checks_started = time.perf_counter()
            values = connection.execute(text("""
                SELECT count(*) AS devices,
                       coalesce(sum(session_count), 0) AS sessions,
                       min(session_count) AS min_sessions_per_device,
                       max(session_count) AS max_sessions_per_device,
                       count(*) FILTER (WHERE trusted) AS trusted_devices
                FROM user_devices
            """)).mappings().one()
            latest = connection.execute(text("""
                SELECT user_agent, last_ip_address, session_count
                FROM user_devices
                WHERE user_id = 'user-0' AND device_id = 'device-0'
            """)).mappings().one_or_none()
            plan = connection.execute(text("""
                EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
                SELECT id FROM user_sessions
                WHERE tenant_id = 'tenant-0' AND user_id = 'user-0'
                ORDER BY last_activity_at DESC
                LIMIT 100
            """)).scalars().all()
            index_names = {
                row["indexname"]
                for row in connection.execute(text("""
                    SELECT indexname FROM pg_indexes WHERE schemaname = :schema
                """), {"schema": schema}).mappings()
            }
            check_seconds = time.perf_counter() - checks_started

            expected_devices = min(session_rows, group_count)
            expected_latest = session_rows >= group_count
            data_correct = (
                int(values["devices"]) == expected_devices
                and int(values["sessions"]) == session_rows
                and int(values["trusted_devices"]) == 0
                and (not expected_latest or (latest is not None and latest["user_agent"] == "latest-agent"))
                and "ix_user_sessions_owner_activity" in index_names
            )
            throughput = session_rows / migration_seconds if migration_seconds else 0.0
            slo_passed = (
                (max_migration_seconds is None or migration_seconds <= max_migration_seconds)
                and (min_migration_rows_per_second is None or throughput >= min_migration_rows_per_second)
            )
            result.update({
                "session_rows_actual": int(values["sessions"]),
                "device_identities": int(values["devices"]),
                "expected_device_identities": expected_devices,
                "sessions_per_device": {
                    "min": int(values["min_sessions_per_device"] or 0),
                    "max": int(values["max_sessions_per_device"] or 0),
                },
                "backfilled_devices_trusted": int(values["trusted_devices"]),
                "seed_seconds": round(seed_seconds, 3),
                "migration_seconds": round(migration_seconds, 3),
                "migration_sessions_per_second": round(throughput, 2),
                "verification_seconds": round(check_seconds, 3),
                "risk_history_query_plan": plan,
                "owner_activity_index_present": "ix_user_sessions_owner_activity" in index_names,
                "data_correct": data_correct,
                "configured_slo_passed": slo_passed,
                "passed": data_correct and slo_passed,
            })
            connection.commit()
            if keep_schema:
                result["schema_retained"] = True
            else:
                result["schema_retained"] = False
    finally:
        if schema_created and not keep_schema:
            with engine.begin() as cleanup:
                cleanup.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        engine.dispose()
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the device registry backfill on isolated PostgreSQL data")
    parser.add_argument("--session-rows", type=int, default=1_000_000)
    parser.add_argument("--users", type=int, default=20_000)
    parser.add_argument("--devices-per-user", type=int, default=10)
    parser.add_argument("--max-migration-seconds", type=float)
    parser.add_argument("--min-migration-rows-per-second", type=float)
    parser.add_argument("--keep-schema", action="store_true")
    parser.add_argument("--json-path", default="device_migration_benchmark.json")
    args = parser.parse_args()
    database_url = os.getenv("PESAGUARD_POSTGRES_TEST_URL", "").strip()
    if not database_url:
        raise SystemExit("PESAGUARD_POSTGRES_TEST_URL must point to a disposable PostgreSQL test database")
    result = run(
        database_url,
        args.session_rows,
        args.users,
        args.devices_per_user,
        args.max_migration_seconds,
        args.min_migration_rows_per_second,
        args.keep_schema,
    )
    with open(args.json_path, "w", encoding="utf-8") as output:
        json.dump(result, output, indent=2)
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit("Device migration benchmark failed correctness checks or configured SLOs")


if __name__ == "__main__":
    main()