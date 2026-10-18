"""Regression tests for recovering Redis-backed security and telemetry clients."""

import metrics
from rate_limiter import RedisRateLimiter


class _ClosableClient:
    def __init__(self, *, fail=False):
        self.closed = False
        self.fail = fail

    def close(self):
        self.closed = True

    def mget(self, *keys):
        if self.fail:
            raise TimeoutError("simulated Redis timeout")
        return [None] * len(keys)


def test_rate_limiter_discards_stale_client_pool():
    limiter = RedisRateLimiter("redis://unused.invalid/0")
    client = _ClosableClient()
    limiter._client = client
    limiter._script = object()

    limiter._invalidate_client()

    assert client.closed is True
    assert limiter._client is None
    assert limiter._script is None


def test_shared_metrics_invalidates_stale_redis_client(monkeypatch):
    client = _ClosableClient(fail=True)
    monkeypatch.setenv("PESAGUARD_SHARED_METRICS", "1")
    monkeypatch.setattr(metrics, "_shared_redis_client", client)
    monkeypatch.setattr(metrics, "_shared_redis_degraded", False)
    monkeypatch.setattr(metrics, "_shared_redis_retry_after", 0.0)

    result = metrics._shared_totals()

    assert result["requests"] == 0
    assert client.closed is True
    assert metrics._shared_redis_client is None
    assert metrics._shared_redis_degraded is True
    assert metrics._shared_redis_retry_after > 0
