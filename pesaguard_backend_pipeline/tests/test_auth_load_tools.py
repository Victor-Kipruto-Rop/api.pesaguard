from operations import run_auth_load_test
from operations import run_device_migration_benchmark
import pytest


def test_latency_histogram_uses_fixed_memory_and_reports_upper_bounds():
    histogram = run_auth_load_test.LatencyHistogram()
    for sample in range(100_000):
        histogram.observe(sample / 1000)

    assert histogram.count == 100_000
    assert len(histogram.counts) == len(run_auth_load_test._LATENCY_BUCKETS_MS) + 1
    assert histogram.percentile(0.95) <= 100


def test_auth_load_runner_accounts_for_login_and_device_requests(monkeypatch):
    def fake_request(url, method, payload, token, timeout):
        if url.endswith("/auth/login"):
            assert method == "POST"
            assert payload["tenant_id"] == "loadtest-tenant"
            return 200, {"access_token": "test-access"}, 4.0, None
        assert url.endswith("/auth/devices")
        assert method == "GET"
        assert token == "test-access"
        return 200, {"devices": []}, 2.0, None

    monkeypatch.setattr(run_auth_load_test, "_request_json", fake_request)
    result = run_auth_load_test.run(
        "http://localhost:5000",
        [{"username": "load-user", "password": "test-secret", "tenant_id": "loadtest-tenant"}],
        request_count=10,
        concurrency=3,
        timeout=1,
        probe_devices=True,
        max_server_error_rate=0.01,
    )

    assert result["passed"] is True
    assert result["completed_login_requests"] == 10
    assert result["login_statuses"] == {"200": 10}
    assert result["device_list_statuses"] == {"200": 10}
    assert result["device_list_latency"]["count"] == 10


def test_device_migration_benchmark_requires_postgresql():
    with pytest.raises(ValueError, match="requires PostgreSQL"):
        run_device_migration_benchmark.run(
            "sqlite:///:memory:",
            session_rows=1,
            users=1,
            devices_per_user=1,
        )