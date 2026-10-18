import importlib
import os
import tempfile

import pytest
from auth_rbac import AuthRBAC
from auth_seed import seed_account
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import workflow_models  # noqa: F401
from workflow_api import create_workflow_blueprint


@pytest.fixture()
def workflow_client(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "workflow_test.db")
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
        monkeypatch.setenv("PESAGUARD_API_AUTH_REQUIRED", "1")
        import app_2
        app_2 = importlib.reload(app_2)
        app_2.Base.metadata.create_all(app_2.engine)
        from action_audit import Base as AuditBase
        from auth_rbac import _RevocationBase
        AuditBase.metadata.create_all(app_2.primary_engine)
        _RevocationBase.metadata.create_all(app_2.primary_engine)
        app_2.app.config.update(TESTING=True)
        app_2.app.register_blueprint(create_workflow_blueprint(app_2.SessionLocal))
        with app_2.SessionLocal() as session:
            session.add(app_2.UserAccount(
                id="workflow-admin", tenant_id="tenant-a", username="workflow-admin",
                roles=["admin"], permissions=[], status="active", authorization_version=1,
            ))
            session.add(app_2.UserAccount(
                id="workflow-admin-b", tenant_id="tenant-b", username="workflow-admin-b",
                roles=["admin"], permissions=[], status="active", authorization_version=1,
            ))
            session.commit()
        seed_account(app_2.SessionLocal, user_id="workflow-admin", tenant_id="tenant-a", roles=["admin"])
        token = AuthRBAC.generate_token(
            user_id="workflow-admin", username="workflow-admin", tenant_id="tenant-a", roles=["admin"]
        )
        with app_2.app.test_client() as client:
            yield client, app_2, {"Authorization": f"Bearer {token}"}


def test_workflow_records_are_persisted_and_tenant_scoped(workflow_client):
    client, app_module, headers = workflow_client
    created = client.post(
        "/api/v1/data-quality-findings",
        headers=headers,
        json={"title": "Missing ledger reference", "payload": {"severity": "high", "finding_code": "LEDGER_REF_MISSING"}},
    )
    assert created.status_code == 201
    item = created.get_json()["item"]
    assert item["tenant_id"] == "tenant-a"
    assert item["status"] == "open"
    assert item["payload"]["finding_code"] == "LEDGER_REF_MISSING"

    listed = client.get("/api/v1/data-quality-findings?page=1&per_page=10", headers=headers)
    assert listed.status_code == 200
    assert listed.get_json()["total"] == 1
    assert listed.get_json()["items"][0]["id"] == item["id"]

    with app_module.SessionLocal() as session:
        from workflow_models import TenantWorkflowRecord
        session.add(TenantWorkflowRecord(
            id="wf-tenant-b", tenant_id="tenant-b", domain="data_quality_finding", status="open",
            title="Other tenant finding", payload={}, created_by="user-b", updated_by="user-b",
        ))
        session.commit()
    listed = client.get("/api/v1/data-quality-findings", headers=headers)
    assert listed.get_json()["total"] == 1
    assert all(row["tenant_id"] == "tenant-a" for row in listed.get_json()["items"])


def test_settlement_and_refund_apis_only_record_review_requests(workflow_client):
    client, _, headers = workflow_client
    rejected = client.post(
        "/api/v1/refund-reversal-requests",
        headers=headers,
        json={"title": "Refund request", "payload": {"amount": 100, "currency": "KES", "execute_payment": True}},
    )
    assert rejected.status_code == 400

    created = client.post(
        "/api/v1/refund-reversal-requests",
        headers=headers,
        json={"title": "Refund review request", "payload": {"amount": 100, "currency": "KES", "transaction_id": "txn_test"}},
    )
    assert created.status_code == 201
    assert created.get_json()["item"]["status"] == "requested"


def test_schedule_validation_and_report_summary_execution(workflow_client):
    client, _, headers = workflow_client
    invalid = client.post(
        "/api/v1/reconciliation-schedules",
        headers=headers,
        json={"title": "Nightly reconciliation", "payload": {"cadence": "whenever"}},
    )
    assert invalid.status_code == 400

    scheduled = client.post(
        "/api/v1/reconciliation-schedules",
        headers=headers,
        json={"title": "Nightly reconciliation", "payload": {"cadence": "daily", "timezone": "Africa/Nairobi", "enabled": True}},
    )
    assert scheduled.status_code == 201
    assert scheduled.get_json()["item"]["status"] == "scheduled"

    report = client.post(
        "/api/v1/report-runs",
        headers=headers,
        json={"title": "Reconciliation summary", "payload": {"report_type": "reconciliation_summary"}},
    )
    assert report.status_code == 201
    item = report.get_json()["item"]
    assert item["status"] == "completed"
    assert item["payload"]["result"]["report_type"] == "reconciliation_summary"
    assert item["payload"]["execution_mode"] == "synchronous_summary"


def test_workflow_update_uses_version_conflict_guard(workflow_client):
    client, _, headers = workflow_client
    created = client.post(
        "/api/v1/fraud-investigations",
        headers=headers,
        json={"title": "Review suspicious transaction", "payload": {"evidence": [{"type": "transaction", "reference": "txn_123"}]}},
    )
    assert created.status_code == 201
    item = created.get_json()["item"]
    updated = client.patch(
        f"/api/v1/fraud-investigations/{item['id']}",
        headers=headers,
        json={"version": 999, "status": "in_progress"},
    )
    assert updated.status_code == 409
    updated = client.patch(
        f"/api/v1/fraud-investigations/{item['id']}",
        headers=headers,
        json={"version": item["version"], "status": "in_progress"},
    )
    assert updated.status_code == 200
    assert updated.get_json()["item"]["status"] == "in_progress"



def test_matching_rule_delete_is_auditable_soft_disable(workflow_client):
    client, _, headers = workflow_client
    created = client.post(
        "/api/v1/matching-rules",
        headers=headers,
        json={"title": "M-Pesa exact reference", "payload": {"currency": "KES", "amount_tolerance": 0, "time_window_minutes": 5}},
    )
    assert created.status_code == 201
    item = created.get_json()["item"]
    deleted = client.delete("/api/v1/matching-rules/" + item["id"], headers=headers)
    assert deleted.status_code == 200
    assert deleted.get_json()["item"]["status"] == "disabled"
    assert deleted.get_json()["disabled"] is True
