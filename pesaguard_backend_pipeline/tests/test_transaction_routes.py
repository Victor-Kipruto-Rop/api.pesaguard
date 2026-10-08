from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def dashboard_api(tmp_path, monkeypatch):
    database_url = f"sqlite:///{tmp_path / 'transactions.db'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("PESAGUARD_API_AUTH_REQUIRED", "0")
    monkeypatch.setenv("JWT_SECRET_KEY", "transaction-route-test-secret-0123456789")

    dashboard = importlib.reload(importlib.import_module("api.dashboard_app"))
    dashboard.Base.metadata.create_all(dashboard.primary_engine)
    from auth_rbac import _RevocationBase

    _RevocationBase.metadata.create_all(dashboard.primary_engine)
    dashboard.transaction_event_store._ensure_ready()
    yield dashboard
    dashboard.primary_engine.dispose()
    dashboard.transaction_event_store.engine.dispose()


def _transaction_payload(transaction_id: str) -> dict[str, str]:
    return {
        "provider_transaction_id": transaction_id,
        "provider_account_id": "600000",
        "provider": "mpesa",
        "TransAmount": "25.00",
        "Currency": "KES",
        "MSISDN": "254700000000",
        "TransTime": "20260913120000",
    }


def _create(client, tenant_id: str, transaction_id: str, idempotency_key: str):
    return client.post(
        "/api/v1/transactions",
        headers={"Idempotency-Key": idempotency_key, "X-Tenant-ID": tenant_id},
        json=_transaction_payload(transaction_id),
    )


def test_canonical_asgi_mount_exposes_transaction_endpoint(dashboard_api, monkeypatch):
    from fastapi.testclient import TestClient

    canonical = importlib.reload(importlib.import_module("pesaguard_backend_pipeline.fastapi_app"))
    response = TestClient(canonical.app).post(
        "/api/v1/transactions",
        headers={"X-Tenant-ID": "tenant-a"},
        json={},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_dashboard_transaction_routes_are_tenant_scoped_and_idempotent(dashboard_api):
    client = dashboard_api.app.test_client()

    first = _create(client, "tenant-a", "route-tx-a", "route-key-a")
    replay = _create(client, "tenant-a", "route-tx-a", "route-key-a")
    other_tenant = _create(client, "tenant-b", "route-tx-b", "route-key-b")

    assert first.status_code == 200
    assert first.json["duplicate"] is False
    assert replay.status_code == 200
    assert replay.json["duplicate"] is True
    assert other_tenant.status_code == 200

    with dashboard_api.transaction_event_store.Session() as session:
        tenant_a_transaction = session.query(dashboard_api.Transaction).filter_by(
            tenant_id="tenant-a",
            trans_id="route-tx-a",
        ).one()

    transaction_id = tenant_a_transaction.id
    detail = client.get(f"/api/v1/transactions/{transaction_id}", headers={"X-Tenant-ID": "tenant-a"})
    status = client.get(f"/api/v1/transactions/{transaction_id}/status", headers={"X-Tenant-ID": "tenant-a"})
    hidden_detail = client.get(f"/api/v1/transactions/{transaction_id}", headers={"X-Tenant-ID": "tenant-b"})
    results = client.get("/api/v1/transactions/search?per_page=1", headers={"X-Tenant-ID": "tenant-a"})

    assert detail.status_code == 200
    assert detail.json["id"] == transaction_id
    assert detail.json["tenant_id"] == "tenant-a"
    assert status.status_code == 200
    assert status.json["transaction_id"] == transaction_id
    assert hidden_detail.status_code == 404
    assert results.status_code == 200
    assert results.json["total"] == 1
    assert len(results.json["items"]) == 1
    assert results.json["items"][0]["tenant_id"] == "tenant-a"


@pytest.mark.parametrize(
    ("query", "error"),
    [
        ("?page=0", "invalid_pagination"),
        ("?per_page=101", "invalid_pagination"),
        ("?sort=tenant_id:asc", "invalid_sort"),
    ],
)
def test_transaction_search_rejects_invalid_query_parameters(dashboard_api, query, error):
    response = dashboard_api.app.test_client().get(
        f"/api/v1/transactions/search{query}",
        headers={"X-Tenant-ID": "tenant-a"},
    )

    assert response.status_code == 400
    assert response.json["error"] == error


def test_reconciliation_request_is_idempotent_and_tenant_scoped(dashboard_api, monkeypatch):
    import background_tasks

    enqueued = []

    def enqueue(tenant_id, transaction_id, idempotency_key):
        enqueued.append((tenant_id, transaction_id, idempotency_key))
        return {"status": "queued", "job_id": "reconciliation-test-job", "queue": "test"}

    monkeypatch.setattr(background_tasks, "enqueue_reconciliation_request", enqueue)
    client = dashboard_api.app.test_client()
    created = _create(client, "tenant-a", "recon-request-tx", "create-recon-tx")
    second_created = _create(client, "tenant-a", "recon-request-tx-2", "create-recon-tx-2")
    assert created.status_code == 200
    assert second_created.status_code == 200
    with dashboard_api.transaction_event_store.Session() as session:
        transaction = session.query(dashboard_api.Transaction).filter_by(
            tenant_id="tenant-a",
            trans_id="recon-request-tx",
        ).one()
        transaction_id = transaction.id
        other_transaction = session.query(dashboard_api.Transaction).filter_by(
            tenant_id="tenant-a",
            trans_id="recon-request-tx-2",
        ).one()
        other_transaction_id = other_transaction.id

    headers = {"X-Tenant-ID": "tenant-a", "Idempotency-Key": "recon-request-key"}
    body = {"transaction_id": transaction_id}
    first = client.post("/api/v1/reconciliation/requests", headers=headers, json=body)
    replay = client.post("/api/v1/reconciliation/requests", headers=headers, json=body)
    conflict = client.post(
        "/api/v1/reconciliation/requests",
        headers={"X-Tenant-ID": "tenant-a", "Idempotency-Key": "recon-request-key"},
        json={"transaction_id": other_transaction_id},
    )
    hidden = client.post(
        "/api/v1/reconciliation/requests",
        headers={"X-Tenant-ID": "tenant-b", "Idempotency-Key": "other-tenant-key"},
        json=body,
    )

    assert first.status_code == replay.status_code == 202
    assert first.json["job_id"] == replay.json["job_id"] == "reconciliation-test-job"
    assert enqueued == [("tenant-a", transaction_id, "recon-request-key")] * 2
    assert conflict.status_code == 409
    assert conflict.json["error"] == "idempotency_conflict"
    assert hidden.status_code == 404
    status = client.get(
        f"/api/v1/reconciliation/{transaction_id}",
        headers={"X-Tenant-ID": "tenant-a"},
    )
    assert status.status_code == 200
    assert status.json["transaction_id"] == transaction_id
    assert status.json["status"] == "pending"
    assert status.json["history"]


def test_fraud_analysis_persists_and_replays_idempotently(dashboard_api):
    client = dashboard_api.app.test_client()
    created = _create(client, "tenant-risk", "risk-analysis-tx", "create-risk-tx")
    assert created.status_code == 200
    with dashboard_api.transaction_event_store.Session() as session:
        transaction = session.query(dashboard_api.Transaction).filter_by(
            tenant_id="tenant-risk",
            trans_id="risk-analysis-tx",
        ).one()
        transaction_id = transaction.id

    headers = {"X-Tenant-ID": "tenant-risk", "Idempotency-Key": "risk-analysis-key"}
    payload = {"transaction_id": transaction_id}
    first = client.post("/api/v1/fraud/analyse", headers=headers, json=payload)
    replay = client.post("/api/v1/fraud/analyse", headers=headers, json=payload)
    assert first.status_code == replay.status_code == 200
    assert first.json == replay.json
    assert first.json["transaction_id"] == transaction_id
    assert 0 <= first.json["risk_score"] <= 1

    retrieved = client.get(
        f"/api/v1/fraud/{transaction_id}",
        headers={"X-Tenant-ID": "tenant-risk"},
    )
    assert retrieved.status_code == 200
    assert retrieved.json == first.json

    invalid_features = client.post(
        "/api/v1/fraud/analyse",
        headers={"X-Tenant-ID": "tenant-risk", "Idempotency-Key": "risk-analysis-override"},
        json={"transaction_id": transaction_id, "features": {"risk_score": 0}},
    )
    assert invalid_features.status_code == 400
    assert invalid_features.json["error"] == "invalid_features"


def test_versioned_auth_aliases_are_registered(dashboard_api):
    from fastapi.testclient import TestClient

    canonical = importlib.reload(importlib.import_module("pesaguard_backend_pipeline.fastapi_app"))
    client = TestClient(canonical.app)

    login = client.post("/api/v1/auth/login", json={})
    refresh = client.post("/api/v1/auth/refresh", json={})

    assert login.status_code == 401
    assert login.json()["error"] in {"invalid_credentials", "mfa_required"}
    assert refresh.status_code == 400
    assert refresh.json()["error"]["code"] == "invalid_request"
