"""Opt-in PostgreSQL race coverage for tenant/provider idempotency constraints."""

from __future__ import annotations

import os
import threading
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

psycopg2 = pytest.importorskip("psycopg2")


@pytest.mark.skipif(
    os.getenv("PESAGUARD_RUN_POSTGRES_INTEGRATION") != "1"
    or not os.getenv("PESAGUARD_POSTGRES_TEST_URL", "").startswith(("postgresql://", "postgres://")),
    reason="set PESAGUARD_RUN_POSTGRES_INTEGRATION=1 and PESAGUARD_POSTGRES_TEST_URL",
)
def test_concurrent_same_transaction_has_one_winner():
    database_url = os.environ["PESAGUARD_POSTGRES_TEST_URL"]
    trans_id = f"concurrency-{uuid.uuid4().hex}"
    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    lock = threading.Lock()

    def attempt() -> None:
        connection = psycopg2.connect(database_url)
        try:
            with connection:
                with connection.cursor() as cursor:
                    barrier.wait(timeout=10)
                    cursor.execute(
                        "INSERT INTO transactions "
                        "(id, trans_id, tenant_id, provider_account_id, trans_amount, msisdn, "
                        "business_short_code, trans_time, raw_payload) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (f"txn_{uuid.uuid4().hex}", trans_id, "tenant-race", "provider-race", "10.00", "tok:v1:test", "600000", "20260913120000", "{}"),
                    )
                    with lock:
                        outcomes.append("stored")
        except psycopg2.errors.UniqueViolation:
            connection.rollback()
            with lock:
                outcomes.append("duplicate")
        finally:
            connection.close()

    workers = [threading.Thread(target=attempt) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=20)

    cleanup = psycopg2.connect(database_url)
    try:
        with cleanup:
            with cleanup.cursor() as cursor:
                cursor.execute("DELETE FROM transactions WHERE trans_id = %s", (trans_id,))
    finally:
        cleanup.close()

    assert sorted(outcomes) == ["duplicate", "stored"]


@pytest.mark.skipif(
    os.getenv("PESAGUARD_RUN_POSTGRES_INTEGRATION") != "1"
    or not os.getenv("PESAGUARD_POSTGRES_TEST_URL", "").startswith(("postgresql://", "postgres://")),
    reason="set PESAGUARD_RUN_POSTGRES_INTEGRATION=1 and PESAGUARD_POSTGRES_TEST_URL",
)
def test_concurrent_first_device_sessions_upsert_once_and_count_both():
    from sqlalchemy import create_engine, inspect
    from sqlalchemy.orm import sessionmaker

    database_url = os.environ["PESAGUARD_POSTGRES_TEST_URL"]
    original_database_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = database_url
    try:
        from app_4_advanced_features import _upsert_device_identity
    finally:
        if original_database_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = original_database_url
    from models import DeviceIdentity

    engine = create_engine(database_url, pool_pre_ping=True)
    assert inspect(engine).has_table("user_devices"), "run the device identity Alembic migration first"
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    tenant_id = f"device-race-{uuid.uuid4().hex[:12]}"
    user_id = f"user-race-{uuid.uuid4().hex[:12]}"
    device_id = f"browser-{uuid.uuid4().hex}"
    user = SimpleNamespace(tenant_id=tenant_id, id=user_id)
    barrier = threading.Barrier(2)
    errors = []
    guard = threading.Lock()

    def create_session() -> None:
        session = sessions()
        try:
            barrier.wait(timeout=10)
            _upsert_device_identity(
                session,
                user,
                device_id,
                "Mozilla/5.0 Chrome/130.0 Windows",
                "192.0.2.25",
                datetime.now(timezone.utc),
                {"risk_level": "low", "risk_score": 0.2, "signals": {}},
            )
            session.commit()
        except Exception as exc:
            session.rollback()
            with guard:
                errors.append(repr(exc))
        finally:
            session.close()

    workers = [threading.Thread(target=create_session) for _ in range(2)]
    try:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=20)
        assert all(not worker.is_alive() for worker in workers), "device upsert race timed out"
        assert not errors
        with sessions() as session:
            rows = session.query(DeviceIdentity).filter_by(
                tenant_id=tenant_id,
                user_id=user_id,
                device_id=device_id,
            ).all()
            assert len(rows) == 1
            assert rows[0].session_count == 2
    finally:
        with sessions() as session:
            session.query(DeviceIdentity).filter_by(
                tenant_id=tenant_id,
                user_id=user_id,
                device_id=device_id,
            ).delete(synchronize_session=False)
            session.commit()
        engine.dispose()
