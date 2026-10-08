"""Test redis caching for duplicate check lookup."""
import sys
import os
import pytest
import tempfile
import importlib
sys.path.insert(0, os.path.dirname(__file__))

@pytest.fixture()
def webhook_client(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        # Set test DB BEFORE importing app
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{os.path.join(tmpdir, 'pesaguard_test.db')}")
        monkeypatch.setenv("DARAJA_ALLOWED_IPS", "127.0.0.1")
        monkeypatch.setenv("DARAJA_SHARED_SECRET", "test-secret")
        monkeypatch.setenv("TENANT_ID", "tenant-test")

        # Import and reload app with test DB
        import app
        app = importlib.reload(app)
        app.app.config.update(TESTING=True)
        
        # Initialize test DB
        from models import Base
        import app_2
        app_2 = importlib.reload(app_2)
        Base.metadata.create_all(app_2.primary_engine)
        
        try:
            with app.app.test_client() as client:
                yield client
        finally:
            # SQLite keeps file handles open on Windows; release every engine
            # created by this fixture before TemporaryDirectory cleanup.
            for engine in (
                getattr(getattr(app, "event_store", None), "engine", None),
                getattr(app_2, "engine", None),
                getattr(app_2, "primary_engine", None),
                getattr(getattr(getattr(app_2, "batch_import_service", None), "ingestion_service", None), "event_store", None),
            ):
                try:
                    if engine is not None and hasattr(engine, "dispose"):
                        engine.dispose()
                except Exception:
                    pass
            nested_store = getattr(getattr(getattr(app_2, "batch_import_service", None), "ingestion_service", None), "event_store", None)
            if nested_store is not None and hasattr(nested_store, "engine") and nested_store.engine is not None:
                nested_store.engine.dispose()

def test_redis_cache_used(webhook_client, monkeypatch):
    """Test that Redis cache is used for duplicate detection."""
    # Mock redis connection
    class FakeRedis:
        def __init__(self, *args, **kwargs):
            self.store = {}
        def get(self, key):
            return self.store.get(key)
        def setex(self, key, ttl, val):
            self.store[key] = val
        def set(self, key, val, ex=None):
            self.store[key] = val

        def pipeline(self):
            return self

        def execute(self):
            return []

    fake_redis_instance = FakeRedis()
    import redis
    monkeypatch.setattr(redis, "from_url", lambda *args, **kwargs: fake_redis_instance)


    payload = {
        "TransactionType": "Pay Bill",
        "TransID": "REDIS-123",
        "TransTime": "20240101120000",
        "TransAmount": "10",
        "BusinessShortCode": "123456",
        "MSISDN": "254700000000",
    }

    # First request
    r1 = webhook_client.post(
        "/webhook/mpesa/confirmation",
        json=payload,
        headers={"X-Daraja-Shared-Secret": "test-secret"}
    )
    assert r1.status_code == 200

    assert "processed_trans_id:REDIS-123" in fake_redis_instance.store

    # Second request should hit redis and return duplicate accepted
    r2 = webhook_client.post(
        "/webhook/mpesa/confirmation",
        json=payload,
        headers={"X-Daraja-Shared-Secret": "test-secret"}
    )
    assert r2.status_code == 200
    assert "duplicate ignored" in r2.json["ResultDesc"].lower()
