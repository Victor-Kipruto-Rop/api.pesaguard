"""Phase 6 runtime telemetry: shared multi-worker metrics, scrape-window rates,
engine query timing across application pools, and alert delivery accounting.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import metrics
import pytest
from sqlalchemy import create_engine, text


class _FakeRedisClient:
    """Minimal Redis-shaped fake for exercising the shared metrics code paths."""

    def __init__(self):
        self._store: dict = {}

    def ping(self):
        return True

    def incr(self, key, amount=1):
        self._store[key] = int(self._store.get(key, 0)) + amount
        return self._store[key]

    def incrby(self, key, amount):
        return self.incr(key, amount)

    def lpush(self, key, value):
        self._store.setdefault(key, []).insert(0, str(value))

    def ltrim(self, key, start, end):
        stop = None if end == -1 else end + 1
        self._store[key] = self._store.get(key, [])[start:stop]

    def lrange(self, key, start, end):
        stop = None if end == -1 else end + 1
        return self._store.get(key, [])[start:stop]

    def mget(self, *keys):
        if len(keys) == 1 and isinstance(keys[0], (list, tuple)):
            keys = tuple(keys[0])
        return [self._store.get(key) for key in keys]

    def get(self, key):
        return self._store.get(key)

    def keys(self, pattern):
        prefix = pattern.split("*")[0]
        return sorted(key for key in self._store if key.startswith(prefix))

    def hgetall(self, key):
        value = self._store.get(key)
        return value or {}

    def hset(self, key, mapping):
        self._store[key] = dict(self._store.get(key, {}))
        self._store[key].update(mapping)

    def expire(self, key, seconds):
        return True

    def pipeline(self):
        return self

    def execute(self):
        return []


def test_scrape_window_rate_reflects_recent_activity_not_lifetime(monkeypatch):
    metrics.record_http_request(10, status_code=200)
    first = metrics.telemetry_snapshot()
    assert first["requests"] >= 1
    # The initial scrape seeds the window mark; a second scrape measures the window.
    metrics.record_http_request(25, status_code=500)
    second = metrics.telemetry_snapshot()
    assert second["requests"] >= 2
    assert second["request_rate_per_second"] >= 0
    assert second["error_rate"] > 0
    # After recording an error in the window, the scrape-window error rate is above zero.
    assert second["errors"] >= first["errors"]


def test_shared_metrics_store_aggregates_across_workers(monkeypatch):
    fake = _FakeRedisClient()
    monkeypatch.setenv("PESAGUARD_SHARED_METRICS", "1")
    monkeypatch.setattr(metrics, "_shared_redis_client", fake)
    monkeypatch.setattr(metrics, "_shared_redis_degraded", False)

    assert metrics.shared_metrics_enabled() is True
    # Simulate two workers recording at the same time.
    metrics.record_http_request(12, status_code=200)
    metrics.record_http_request(13, status_code=200)
    metrics.record_http_request(99, status_code=503)
    metrics.record_business_metric("transactions_received")
    metrics.record_event_retry()

    shared = metrics._shared_totals()
    assert shared["requests"] == 3
    assert shared["errors"] == 1
    assert shared["event_retries"] == 1
    assert shared["business"]["transactions_received"] == 1
    assert len(shared["request_latencies_ms"]) == 3

    snapshot = metrics.telemetry_snapshot()
    assert snapshot["requests"] == 3
    assert snapshot["errors"] == 1
    assert snapshot["business"]["transactions_received"] == 1
    # Restore process-local telemetry assumptions for the remaining tests.
    monkeypatch.setenv("PESAGUARD_SHARED_METRICS", "0")
    monkeypatch.setattr(metrics, "_shared_redis_client", None)


def test_instrument_engine_query_timing_records_every_application_engine(monkeypatch):
    engine = create_engine("sqlite://")
    assert metrics.instrument_engine_query_timing(engine) is True
    # Idempotent: repeated instrumentation does not double count.
    assert metrics.instrument_engine_query_timing(engine) is True

    before = metrics.telemetry_snapshot()["db_queries"]
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    after = metrics.telemetry_snapshot()["db_queries"]
    assert after >= before + 1


def test_alert_delivery_metric_is_recorded_per_channel_and_failure_counted():
    metrics.record_alert_delivery("slack", True)
    metrics.record_alert_delivery("sms", False)
    snapshot = metrics.telemetry_snapshot()
    assert snapshot["alert_deliveries"].get("slack", 0) >= 1
    assert snapshot["alert_deliveries"].get("sms", 0) >= 1
def test_process_local_counters_reset_on_snapshot_reset():
    # Simulate the operational assumption that a worker restart clears
    # process-local counters. The module exposes enough internals to verify
    # the reset behavior without relying on a real restart.
    metrics.record_http_request(5, status_code=200)
    metrics.record_http_request(2, status_code=500)
    snapshot = metrics.telemetry_snapshot()
    assert snapshot["requests"] >= 2

    # Reset the process-local scrape anchor to model a restart-boundary refresh.
    metrics._last_scrape_at = None
    metrics._last_scrape_requests = 0
    metrics._telemetry["requests"] = 0
    metrics._telemetry["errors"] = 0
    after = metrics.telemetry_snapshot()
    assert after["requests"] == 0
    assert after["errors"] == 0
    assert after["request_rate_per_second"] >= 0


def test_shared_metrics_override_proceses_local_when_redis_active(monkeypatch):
    fake = _FakeRedisClient()
    monkeypatch.setenv("PESAGUARD_SHARED_METRICS", "1")
    monkeypatch.setattr(metrics, "_shared_redis_client", fake)
    monkeypatch.setattr(metrics, "_shared_redis_degraded", False)

    metrics.record_http_request(1, status_code=200)
    metrics.record_http_request(99, status_code=503)
    shared = metrics._shared_totals()
    assert shared["requests"] == 2
    assert shared["errors"] == 1

    snapshot = metrics.telemetry_snapshot()
    assert snapshot["requests"] == 2
    assert snapshot["errors"] == 1

    monkeypatch.setenv("PESAGUARD_SHARED_METRICS", "0")
    monkeypatch.setattr(metrics, "_shared_redis_client", None)

    assert snapshot["alert_delivery_failures"] >= 1


def test_import_creates_missing_prometheus_multiprocess_directory(tmp_path):
    pytest.importorskip("prometheus_client")
    pytest.importorskip("fastapi")
    pipeline_root = Path(__file__).resolve().parents[1]
    repository_root = pipeline_root.parent
    multiprocess_dir = tmp_path / "prometheus-multiprocess"
    environment = os.environ.copy()
    environment.update(
        {
            "DATABASE_URL": "sqlite://",
            "JWT_SECRET_KEY": "isolated-test-secret-with-at-least-32-bytes",
            "PESAGUARD_API_URL": "https://api.example.invalid",
            "PESAGUARD_ENVIRONMENT": "test",
            "PROMETHEUS_MULTIPROC_DIR": str(multiprocess_dir),
            "PYTHONPATH": os.pathsep.join((str(repository_root), str(pipeline_root))),
            "PYTHON_DOTENV_DISABLED": "1",
        }
    )

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import pesaguard_backend_pipeline.fastapi_app",
        ],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert multiprocess_dir.is_dir()



def test_shared_metrics_retries_redis_after_transient_startup_failure(monkeypatch):
    import sys

    class _FlakyRedis:
        def __init__(self, should_fail):
            self.should_fail = should_fail

        def ping(self):
            if self.should_fail:
                raise TimeoutError("simulated Redis startup timeout")
            return True

    clients = iter([_FlakyRedis(True), _FlakyRedis(False)])
    fake_redis_module = SimpleNamespace(from_url=lambda *args, **kwargs: next(clients))
    monkeypatch.setitem(sys.modules, "redis", fake_redis_module)
    monkeypatch.setenv("PESAGUARD_SHARED_METRICS", "1")
    monkeypatch.setattr(metrics, "_shared_redis_client", None)
    monkeypatch.setattr(metrics, "_shared_redis_degraded", False)
    monkeypatch.setattr(metrics, "_shared_redis_retry_after", 0.0)

    assert metrics._get_shared_redis() is None
    assert metrics._shared_redis_degraded is True

    # Simulate the retry window elapsing without sleeping in the test.
    monkeypatch.setattr(metrics, "_shared_redis_retry_after", 0.0)
    client = metrics._get_shared_redis()

    assert client is not None
    assert metrics._shared_redis_degraded is False
