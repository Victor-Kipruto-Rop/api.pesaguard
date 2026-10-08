"""Validate PostgreSQL write, index, and concurrent-read behavior at scale."""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import psycopg2
from psycopg2 import sql


def _connect(database_url: str):
    return psycopg2.connect(database_url)


def _read_probe(database_url: str, table_name: str, tenant_id: str, bucket: int) -> int:
    connection = _connect(database_url)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                sql.SQL(
                    "SELECT count(*) FROM {} WHERE tenant_id = %s "
                    "AND trans_id >= %s AND trans_id < %s"
                ).format(sql.Identifier(table_name)),
                (tenant_id, bucket * 1000, (bucket + 1) * 1000),
            )
            return int(cursor.fetchone()[0])
    finally:
        connection.close()


def run(database_url: str, count: int, concurrency: int, keep_table: bool) -> dict[str, Any]:
    table_name = f"pesaguard_pg_load_{uuid.uuid4().hex[:12]}"
    connection = _connect(database_url)
    started = time.perf_counter()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL(
                        "CREATE UNLOGGED TABLE {} ("
                        "id bigint PRIMARY KEY, tenant_id varchar(64) NOT NULL, "
                        "trans_id bigint NOT NULL, amount numeric(18, 2) NOT NULL, "
                        "created_at timestamptz NOT NULL)"
                    ).format(sql.Identifier(table_name))
                )
                cursor.execute(
                    sql.SQL(
                        "INSERT INTO {} (id, tenant_id, trans_id, amount, created_at) "
                        "SELECT n, 'tenant-' || (n %% 100), n, "
                        "(100 + (n %% 5000))::numeric(18, 2), now() - (n %% 86400) * interval '1 second' "
                        "FROM generate_series(1, %s) AS n"
                    ).format(sql.Identifier(table_name)),
                    (count,),
                )
                cursor.execute(
                    sql.SQL("CREATE INDEX {} ON {} (tenant_id, trans_id)").format(
                        sql.Identifier(f"{table_name}_tenant_trans"), sql.Identifier(table_name)
                    )
                )
                cursor.execute(sql.SQL("ANALYZE {}").format(sql.Identifier(table_name)))
                cursor.execute(sql.SQL("SELECT count(*), count(DISTINCT tenant_id) FROM {}").format(sql.Identifier(table_name)))
                row_count, tenant_count = cursor.fetchone()

        write_seconds = time.perf_counter() - started
        probe_started = time.perf_counter()
        probe_results = []
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
            futures = [
                executor.submit(_read_probe, database_url, table_name, f"tenant-{index % 100}", index % max(1, count // 1000))
                for index in range(max(1, concurrency) * 4)
            ]
            for future in as_completed(futures):
                probe_results.append(future.result())

        probe_seconds = time.perf_counter() - probe_started
        return {
            "table": table_name,
            "requested_rows": count,
            "actual_rows": int(row_count),
            "tenant_count": int(tenant_count),
            "write_seconds": round(write_seconds, 3),
            "write_rows_per_second": round(count / write_seconds, 2) if write_seconds else 0,
            "read_probe_count": len(probe_results),
            "read_probe_seconds": round(probe_seconds, 3),
            "read_probe_rows": sum(probe_results),
            "read_probe_rows_per_second": round(sum(probe_results) / probe_seconds, 2) if probe_seconds else 0,
            "concurrency": max(1, concurrency),
            "passed": int(row_count) == count and int(tenant_count) == 100,
        }
    finally:
        if not keep_table:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(table_name)))
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="PesaGuard PostgreSQL million-record validation")
    parser.add_argument("-n", "--count", type=int, default=1_000_000)
    parser.add_argument("-c", "--concurrency", type=int, default=8)
    parser.add_argument("--keep-table", action="store_true")
    parser.add_argument("--json-path", default="postgres_load_validation.json")
    args = parser.parse_args()
    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        raise SystemExit("DATABASE_URL must be configured for PostgreSQL load validation")
    result = run(
        database_url,
        max(1, args.count),
        max(1, args.concurrency),
        args.keep_table,
    )
    with open(args.json_path, "w", encoding="utf-8") as output:
        json.dump(result, output, indent=2)
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit("PostgreSQL load validation failed")


if __name__ == "__main__":
    main()