from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from action_audit import Base as AuditBase
from models import Base, Transaction
from workflow_models import TenantWorkflowRecord
from workflow_scheduler import run_due_workflows


def test_due_reconciliation_schedule_queues_request_without_claiming_completion(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'scheduler.db'}")
    Base.metadata.create_all(engine)
    AuditBase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
    due = (now - timedelta(hours=1)).isoformat()

    with factory() as session:
        session.add(TenantWorkflowRecord(
            id="schedule-a",
            tenant_id="tenant-a",
            domain="scheduled_reconciliation",
            status="scheduled",
            title="Daily M-Pesa reconciliation",
            description=None,
            payload={"cadence": "daily", "timezone": "Africa/Nairobi", "enabled": True, "next_run_at": due},
            created_by="user-a",
            updated_by="user-a",
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        ))
        session.commit()

    stats = run_due_workflows(factory, now=now)
    assert stats["dispatched"] == 1
    with factory() as session:
        schedule = session.get(TenantWorkflowRecord, "schedule-a")
        runs = session.query(TenantWorkflowRecord).filter_by(tenant_id="tenant-a", domain="reconciliation_run").all()
        assert len(runs) == 1
        assert runs[0].status == "queued"
        assert runs[0].payload["execution_status"] == "queued_for_reconciliation_worker"
        assert schedule.payload["next_run_at"] > now.isoformat()

    # The advanced next-run timestamp prevents a second dispatcher cycle from duplicating this occurrence.
    second = run_due_workflows(factory, now=now)
    assert second["dispatched"] == 0
    with factory() as session:
        assert session.query(TenantWorkflowRecord).filter_by(tenant_id="tenant-a", domain="reconciliation_run").count() == 1
    engine.dispose()


def test_due_report_schedule_persists_tenant_scoped_summary(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'report-scheduler.db'}")
    Base.metadata.create_all(engine)
    AuditBase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)

    with factory() as session:
        session.add_all([
            Transaction(
                id="txn-tenant-a",
                trans_id="MPESA-A",
                tenant_id="tenant-a",
                provider_account_id="account-a",
                provider="mpesa",
                idempotency_key="transid:MPESA-A",
                provider_transaction_id="MPESA-A",
                external_reference="LEDGER-A",
                trans_amount="25.00",
                currency="KES",
                msisdn="254700000001",
                business_short_code="123456",
                trans_time="20261018120000",
                raw_payload={"TransID": "MPESA-A"},
                status="RECEIVED",
                lifecycle_stage="STORED",
                version=1,
                created_at=now - timedelta(minutes=10),
            ),
            Transaction(
                id="txn-tenant-b",
                trans_id="MPESA-B",
                tenant_id="tenant-b",
                provider_account_id="account-b",
                provider="mpesa",
                idempotency_key="transid:MPESA-B",
                provider_transaction_id="MPESA-B",
                external_reference="LEDGER-B",
                trans_amount="999.00",
                currency="KES",
                msisdn="254700000002",
                business_short_code="654321",
                trans_time="20261018120000",
                raw_payload={"TransID": "MPESA-B"},
                status="RECEIVED",
                lifecycle_stage="STORED",
                version=1,
                created_at=now - timedelta(minutes=10),
            ),
        ])
        session.add(TenantWorkflowRecord(
            id="report-definition-a",
            tenant_id="tenant-a",
            domain="report_definition",
            status="scheduled",
            title="Daily discrepancy summary",
            description=None,
            payload={
                "report_type": "reconciliation_summary",
                "schedule": {
                    "cadence": "daily",
                    "timezone": "Africa/Nairobi",
                    "enabled": True,
                    "next_run_at": (now - timedelta(minutes=1)).isoformat(),
                },
            },
            created_by="user-a",
            updated_by="user-a",
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        ))
        session.commit()

    stats = run_due_workflows(factory, now=now)
    assert stats["dispatched"] == 1
    with factory() as session:
        runs = session.query(TenantWorkflowRecord).filter_by(tenant_id="tenant-a", domain="report_run").all()
        assert len(runs) == 1
        assert runs[0].status == "completed"
        assert runs[0].payload["execution_mode"] == "scheduled_persisted_summary"
        assert runs[0].payload["result"]["report_type"] == "reconciliation_summary"
        assert runs[0].payload["result"]["transaction_count"] == 1
    engine.dispose()
