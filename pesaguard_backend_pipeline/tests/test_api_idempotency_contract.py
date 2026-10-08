import importlib
import hashlib

import pytest

from models import ApiKeyRecord, Base, IdempotencyRecord, ServiceIdentity, Transaction


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    """Create an isolated API client and bind authentication state to its database."""
    database_url = f"sqlite:///{tmp_path / 'api-idempotency.db'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("PESAGUARD_API_AUTH_REQUIRED", "0")
    monkeypatch.setenv("JWT_SECRET_KEY", "phase1-test-secret-012345678901234567890123")

    # EventStore lazily creates its schema, but AuthRBAC is imported with the
    # application and binds token verification to that same database. Create all
    # model tables before importing the app so authentication state is durable.
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    from auth_rbac import _RevocationBase, configure_revocation_store

    _RevocationBase.metadata.create_all(engine)
    configure_revocation_store(engine, sessionmaker(bind=engine, expire_on_commit=False))

    import app as webhook_app

    webhook_app = importlib.reload(webhook_app)
    webhook_app.app.config.update(TESTING=True)
    webhook_app.event_store._ensure_ready()
    Base.metadata.create_all(webhook_app.event_store.engine)
    with webhook_app.app.test_client() as client:
        yield client, webhook_app.event_store


def _request(client, key, transaction_id="api-contract-1"):
    return client.post(
        "/api/v1/transactions",
        headers={"Idempotency-Key": key, "X-Tenant-ID": "tenant-api"},
        json={
            "provider_transaction_id": transaction_id,
            "provider_account_id": "600000",
            "provider": "mpesa",
            "TransAmount": "25.00",
            "Currency": "KES",
            "MSISDN": "254700000000",
            "TransTime": "20260913120000",
        },
    )


def test_api_idempotency_key_replays_without_duplication(api_client):
    client, store = api_client
    first = _request(client, "api-key-1")
    second = _request(client, "api-key-1")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json["duplicate"] is False
    assert second.json["duplicate"] is True
    with store.Session() as session:
        assert session.query(Transaction).count() == 1
        assert session.query(IdempotencyRecord).count() == 1


def test_api_idempotency_requires_key_and_tenant(api_client):
    client, _ = api_client
    assert client.post("/api/v1/transactions", json={}).status_code == 400
    assert client.post(
        "/api/v1/transactions",
        headers={"Idempotency-Key": "missing-tenant"},
        json={},
    ).status_code == 400


def test_transaction_writes_require_write_scope(api_client, monkeypatch):
    client, store = api_client
    monkeypatch.setenv("PESAGUARD_API_AUTH_REQUIRED", "1")

    unauthenticated = _request(client, "unauthenticated-write")
    assert unauthenticated.status_code == 401

    raw_key = "pk_read_only_transaction_key"
    from auth_rbac import _RevocationSession

    session = _RevocationSession()
    try:
        session.add(ApiKeyRecord(
            id="read-only-transaction-key",
            tenant_id="tenant-api",
            key_hash=hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
            key_prefix=raw_key[:12],
            role="finance",
            scopes=["read:transactions"],
        ))
        session.commit()
    finally:
        session.close()

    denied = client.post(
        "/api/v1/transactions",
        headers={
            "X-API-Key": raw_key,
            "Idempotency-Key": "read-only-write",
            "X-Tenant-ID": "tenant-api",
        },
        json={
            "provider_transaction_id": "should-not-be-written",
            "provider_account_id": "600000",
            "provider": "mpesa",
            "TransAmount": "25.00",
            "Currency": "KES",
            "MSISDN": "254700000000",
            "TransTime": "20260913120000",
        },
    )
    assert denied.status_code == 403
    with store.Session() as event_session:
        assert event_session.query(Transaction).count() == 0

    denied_ingestion = client.post(
        "/api/v1/ingest/safaricom",
        headers={"X-API-Key": raw_key},
        json={"transaction_id": "should-not-be-ingested"},
    )
    assert denied_ingestion.status_code == 403

    service_id = "transaction-writer-service"
    session = _RevocationSession()
    try:
        session.add(ServiceIdentity(
            id=service_id,
            tenant_id="tenant-api",
            name="transaction-writer",
            identity_type="service",
            status="active",
            scopes=["write:transactions"],
            attributes={},
            authorization_version=1,
        ))
        session.commit()
    finally:
        session.close()

    from auth_rbac import AuthRBAC

    token = AuthRBAC.generate_machine_access_token(
        principal_id=service_id,
        principal_type="service",
        tenant_id="tenant-api",
        authorization_version=1,
        scopes=["transactions:write"],
    )
    accepted = client.post(
        "/api/v1/transactions",
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "scoped-service-write",
            "X-Tenant-ID": "tenant-api",
        },
        json={
            "provider_transaction_id": "authorized-service-write",
            "provider_account_id": "600000",
            "provider": "mpesa",
            "TransAmount": "25.00",
            "Currency": "KES",
            "MSISDN": "254700000000",
            "TransTime": "20260913120000",
        },
    )
    assert accepted.status_code == 200, accepted.get_data(as_text=True)
    with store.Session() as event_session:
        assert event_session.query(Transaction).count() == 1


def test_authenticated_principal_cannot_override_transaction_tenant(api_client, monkeypatch):
    client, store = api_client
    seed = _request(client, "tenant-bound-read-seed")
    assert seed.status_code == 200

    monkeypatch.setenv("PESAGUARD_API_AUTH_REQUIRED", "1")

    from auth_rbac import AuthRBAC, _RevocationSession

    service_id = "tenant-bound-writer-service"
    raw_key = "pk_tenant_bound_writer_key"
    session = _RevocationSession()
    try:
        session.add(ServiceIdentity(
            id=service_id,
            tenant_id="tenant-api",
            name="tenant-bound-writer",
            identity_type="service",
            status="active",
            scopes=["read:transactions", "write:transactions"],
            attributes={},
            authorization_version=1,
        ))
        session.add(ApiKeyRecord(
            id="tenant-bound-writer-key",
            tenant_id="tenant-api",
            key_hash=hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
            key_prefix=raw_key[:12],
            role="finance",
            scopes=["read:transactions", "write:transactions"],
        ))
        session.commit()
    finally:
        session.close()

    token = AuthRBAC.generate_machine_access_token(
        principal_id=service_id,
        principal_type="service",
        tenant_id="tenant-api",
        authorization_version=1,
        scopes=["read:transactions", "write:transactions"],
    )
    payload = {
        "provider_transaction_id": "cross-tenant-write",
        "provider_account_id": "600000",
        "provider": "mpesa",
        "TransAmount": "25.00",
        "Currency": "KES",
        "MSISDN": "254700000000",
        "TransTime": "20260913120000",
    }
    service_response = client.post(
        "/api/v1/transactions",
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "cross-tenant-service-write",
            "X-Tenant-ID": "tenant-other",
        },
        json=payload,
    )
    key_response = client.post(
        "/api/v1/transactions",
        headers={
            "X-API-Key": raw_key,
            "Idempotency-Key": "cross-tenant-key-write",
            "X-Tenant-ID": "tenant-other",
        },
        json=payload,
    )

    assert service_response.status_code == 403
    assert service_response.json["error"] == "tenant_access_denied"
    assert key_response.status_code == 403
    assert key_response.json["error"] == "tenant_access_denied"
    with store.Session() as event_session:
        assert event_session.query(Transaction).count() == 1

    service_read_denied = client.get(
        "/api/v1/transactions/search",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID": "tenant-other",
        },
    )
    key_read_denied = client.get(
        "/api/v1/transactions/search",
        headers={
            "X-API-Key": raw_key,
            "X-Tenant-ID": "tenant-other",
        },
    )
    service_read_scoped = client.get(
        "/api/v1/transactions/search",
        headers={"Authorization": f"Bearer {token}"},
    )
    key_read_scoped = client.get(
        "/api/v1/transactions/search",
        headers={"X-API-Key": raw_key},
    )

    assert service_read_denied.status_code == 403
    assert service_read_denied.json["error"] == "tenant_access_denied"
    assert key_read_denied.status_code == 403
    assert key_read_denied.json["error"] == "tenant_access_denied"
    for response in (service_read_scoped, key_read_scoped):
        assert response.status_code == 200
        assert response.json["total"] == 1
        assert {item["tenant_id"] for item in response.json["items"]} == {"tenant-api"}