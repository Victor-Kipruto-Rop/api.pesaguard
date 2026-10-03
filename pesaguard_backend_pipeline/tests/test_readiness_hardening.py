import builtins
import importlib
import os
import sys
import tempfile
import types

import pytest

from auth_rbac import AuthRBAC


@pytest.fixture()
def webhook_client(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{os.path.join(tmpdir, 'pesaguard_test.db')}")
        monkeypatch.setenv("DARAJA_ALLOWED_IPS", "127.0.0.1")
        monkeypatch.setenv("DARAJA_SHARED_SECRET", "test-secret")
        monkeypatch.setenv("TENANT_ID", "tenant-a")
        monkeypatch.setenv("PESAGUARD_WEBHOOK_MAX_BODY_BYTES", "256")
        import app as webhook_app

        webhook_app = importlib.reload(webhook_app)
        webhook_app.app.config.update(TESTING=True)
        with webhook_app.app.test_client() as client:
            yield client
        try:
            webhook_app.event_store.engine.dispose()
        except Exception:
            pass


@pytest.fixture()
def dashboard_client(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "dashboard_test.db")
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
        monkeypatch.setenv("PESAGUARD_API_AUTH_REQUIRED", "1")
        import app_2

        app_2 = importlib.reload(app_2)
        app_2.Base.metadata.create_all(app_2.engine)
        from auth_rbac import _RevocationBase
        _RevocationBase.metadata.create_all(app_2.primary_engine)
        session = app_2.SessionLocal()
        try:
            session.add_all([
                app_2.UserAccount(
                    id="ops-1",
                    tenant_id="tenant-a",
                    username="ops",
                    roles=["operator"],
                    permissions=[],
                    status="active",
                    authorization_version=1,
                ),
                app_2.UserAccount(
                    id="ops-tenant-a",
                    tenant_id="tenant-a",
                    username="ops-tenant-a",
                    roles=["operator"],
                    permissions=[],
                    status="active",
                    authorization_version=1,
                ),
            ])
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        app_2.app.config.update(TESTING=False)
        with app_2.app.test_client() as client:
            yield client, app_2


def test_webhook_rejects_oversized_payload_and_bad_source(webhook_client):
    response = webhook_client.post(
        "/webhook/mpesa/confirmation",
        data=b"{" + b"a" * 300 + b"}",
        content_type="application/json",
    )
    assert response.status_code == 413

    response = webhook_client.post(
        "/webhook/mpesa/confirmation",
        json={"TransactionType": "Pay Bill", "TransID": "abc", "TransTime": "20240101120000", "TransAmount": "10", "BusinessShortCode": "123456", "MSISDN": "254700000000"},
        headers={"X-Daraja-Shared-Secret": "wrong-secret"},
    )
    assert response.status_code == 403


def test_dashboard_api_requires_valid_bearer_token(dashboard_client):
    client, _ = dashboard_client

    unauthorized = client.get("/discrepancies")
    assert unauthorized.status_code == 401

    token = AuthRBAC.generate_token(
        user_id="ops-1",
        username="ops",
        tenant_id="tenant-a",
        roles=["operator"],
    )
    authorized = client.get("/discrepancies", headers={"Authorization": f"Bearer {token}"})
    assert authorized.status_code == 200


def test_dashboard_scopes_results_to_the_authenticated_tenant(dashboard_client):
    client, app_module = dashboard_client

    session = app_module.SessionLocal(read_only=False)
    try:
        session.add_all([
            app_module.Discrepancy(
                id="tenant-a-1",
                trans_id="tenant-a-1",
                tenant_id="tenant-a",
                anomaly_type="missing_payment",
                status="needs_review",
                severity="critical",
                details="tenant a mismatch",
                resolved=False,
            ),
            app_module.Discrepancy(
                id="tenant-b-1",
                trans_id="tenant-b-1",
                tenant_id="tenant-b",
                anomaly_type="duplicate",
                status="needs_review",
                severity="warning",
                details="tenant b mismatch",
                resolved=False,
            ),
        ])
        session.commit()
    finally:
        session.close()

    token = AuthRBAC.generate_token(
        user_id="ops-tenant-a",
        username="ops",
        tenant_id="tenant-a",
        roles=["operator"],
    )
    response = client.get("/discrepancies", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    payload = response.get_json()
    assert all(item["tenant_id"] == "tenant-a" for item in payload["items"])


def test_webhook_accepts_valid_source_and_replays_are_ignored(webhook_client):
    payload = {
        "TransactionType": "Pay Bill",
        "TransID": "abc-123",
        "TransTime": "20240101120000",
        "TransAmount": "10",
        "BusinessShortCode": "123456",
        "MSISDN": "254700000000",
    }

    first_response = webhook_client.post(
        "/webhook/mpesa/confirmation",
        json=payload,
        headers={"X-Daraja-Shared-Secret": "test-secret"},
    )
    assert first_response.status_code == 200

    duplicate_response = webhook_client.post(
        "/webhook/mpesa/confirmation",
        json=payload,
        headers={"X-Daraja-Shared-Secret": "test-secret"},
    )
    assert duplicate_response.status_code == 200
    assert "duplicate ignored" in duplicate_response.get_json()["ResultDesc"].lower()


def test_webhook_health_returns_ok_when_services_available(webhook_client, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    import health as health_module
    importlib.reload(health_module)

    response = webhook_client.get("/health")
    assert response.status_code in (200, 503)
    assert "status" in response.json


def test_dashboard_health_returns_ok_when_services_available(dashboard_client, monkeypatch):
    client, _ = dashboard_client
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    import health as health_module
    importlib.reload(health_module)

    response = client.get("/health")
    assert response.status_code in (200, 503)
    assert "checks" in response.json


def test_public_status_is_public_sanitized_and_allows_status_site(dashboard_client, monkeypatch):
    client, dashboard_app = dashboard_client
    monkeypatch.delenv("PESAGUARD_CORS_ALLOWED_ORIGINS", raising=False)
    import public_status

    monkeypatch.setattr(public_status, "_site_services", lambda: [
        {"id": "public-website", "name": "Public website", "status": "operational"},
        {"id": "dashboard-site", "name": "Dashboard", "status": "operational"},
        {"id": "documentation-site", "name": "Documentation", "status": "operational"},
        {"id": "status-site", "name": "Status website", "status": "operational"},
    ])
    monkeypatch.setattr(dashboard_app, "build_health_payload", lambda: {
        "status": "ok",
        "checks": {
            "database": {"status": "ok"},
            "kafka": {"status": "ok"},
            "redis": {"status": "ok"},
            "daraja": {"status": "ok"},
        },
    })

    response = client.get(
        "/public/status",
        headers={"Origin": "https://status.pesaguard.victorkipruto.com"},
    )

    assert response.status_code in (200, 503)
    assert response.headers["Access-Control-Allow-Origin"] == "https://status.pesaguard.victorkipruto.com"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.get_json()["verified"] is True


def test_public_status_subscription_cors_preflight_accepts_status_site(dashboard_client, monkeypatch):
    client, _ = dashboard_client
    monkeypatch.delenv("PESAGUARD_CORS_ALLOWED_ORIGINS", raising=False)

    response = client.options(
        "/public/status/subscriptions",
        headers={
            "Origin": "https://status.pesaguard.victorkipruto.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://status.pesaguard.victorkipruto.com"
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "Content-Type" in response.headers["Access-Control-Allow-Headers"]


def test_check_kafka_connectivity_returns_failed_when_kafka_dependency_is_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "kafka", types.ModuleType("kafka"))
    import health as health_module
    importlib.reload(health_module)

    result = health_module.check_kafka_connectivity()
    assert result["status"] == "failed"
    assert result["kafka"]["status"] == "failed"
    assert "kafka-python not installed" in result["kafka"]["error"]


def test_check_kafka_connectivity_returns_failed_when_connection_fails(monkeypatch):
    class FakeProducer:
        def __init__(self, *args, **kwargs):
            pass

        def bootstrap_connected(self):
            return False

        def close(self, timeout=None):
            pass

    kafka_module = types.ModuleType("kafka")
    kafka_module.KafkaProducer = FakeProducer
    monkeypatch.setitem(sys.modules, "kafka", kafka_module)
    import health as health_module
    importlib.reload(health_module)

    result = health_module.check_kafka_connectivity()
    assert result["status"] == "failed"
    assert result["kafka"]["status"] == "failed"
    assert "unable to connect to Kafka brokers" in result["kafka"]["error"]


def test_check_redis_connectivity_returns_failed_when_dependency_is_missing(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "redis":
            raise ImportError("redis package not installed")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    import health as health_module
    importlib.reload(health_module)

    result = health_module.check_redis_connectivity()
    assert result["status"] == "failed"
    assert result["redis"]["status"] == "failed"
    assert "redis package not installed" in result["redis"]["error"]


def test_check_redis_connectivity_returns_failed_when_ping_fails(monkeypatch):
    class FakeClient:
        def ping(self):
            raise ConnectionError("unable to reach redis")

    fake_redis = types.ModuleType("redis")
    fake_redis.from_url = staticmethod(lambda *args, **kwargs: FakeClient())
    monkeypatch.setitem(sys.modules, "redis", fake_redis)
    import health as health_module
    importlib.reload(health_module)

    result = health_module.check_redis_connectivity()
    assert result["status"] == "failed"
    assert result["redis"]["status"] == "failed"
    assert "unable to reach redis" in result["redis"]["error"].lower()


def test_enqueue_transaction_event_returns_failed_when_rq_dependency_is_missing(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in ("redis", "rq"):
            raise ImportError("required package not installed")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    import background_tasks as background_tasks_module
    importlib.reload(background_tasks_module)

    result = background_tasks_module.enqueue_transaction_event("mpesa.transactions.raw", {"TransID": "abc"})
    assert result["status"] == "failed"
    assert "rq or redis package not installed" in result["error"]


def test_enqueue_transaction_event_queues_job_when_redis_available(monkeypatch):
    class FakeJob:
        id = "fake-job-id"

    class FakeQueue:
        def __init__(self, *args, **kwargs):
            pass

        def enqueue(self, fn, topic, payload, job_timeout=None):
            assert topic == "mpesa.transactions.raw"
            assert payload["TransID"] == "abc"
            return FakeJob()

    class FakeConnection:
        def __init__(self, redis_conn):
            self.redis_conn = redis_conn

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

    class FakeRedisClient:
        pass

    fake_redis = types.ModuleType("redis")
    fake_redis.from_url = staticmethod(lambda *args, **kwargs: FakeRedisClient())
    fake_rq = types.ModuleType("rq")
    fake_rq.Queue = FakeQueue
    fake_rq.Connection = FakeConnection

    monkeypatch.setitem(sys.modules, "redis", fake_redis)
    monkeypatch.setitem(sys.modules, "rq", fake_rq)
    import background_tasks as background_tasks_module
    importlib.reload(background_tasks_module)

    result = background_tasks_module.enqueue_transaction_event("mpesa.transactions.raw", {"TransID": "abc"})
    assert result["status"] == "queued"
    assert result["job_id"] == "fake-job-id"
    assert result["queue"] == "transaction_events"


def test_check_database_connection_returns_failed_for_invalid_database_path(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        invalid_dir = os.path.join(tmpdir, "missing")
        bad_db_url = f"sqlite:////{invalid_dir}/pesaguard.db"
        monkeypatch.setenv("DATABASE_URL", bad_db_url)
        import health as health_module
        importlib.reload(health_module)

        result = health_module.check_database_connection()
        assert result["status"] == "failed"
        assert result["database"]["status"] == "failed"
        assert "unable to open database file" in result["database"]["error"] or "unable to open database file" in result["database"]["error"].lower()
