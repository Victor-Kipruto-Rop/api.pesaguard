"""Regression tests for Redis rate-limiter key-type separation and bounded state."""

from __future__ import annotations

from rate_limiter import (
    RedisRateLimiter,
    TokenBucketRateLimiter,
    _MAX_DISTINCT_VALUES_PER_BUCKET,
)


class _RedisClient:
    def __init__(self):
        self.eval_calls = []
        self.delete_calls = []

    def eval(self, script, numkeys, *args):
        self.eval_calls.append((script, numkeys, args))
        return 1

    def delete(self, *keys):
        self.delete_calls.append(keys)
        return len(keys)


def test_distinct_attempts_use_separate_bounded_key_from_token_bucket():
    client = _RedisClient()
    limiter = RedisRateLimiter("redis://unused")
    limiter._get_client = lambda: client
    limiter._script = lambda **kwargs: [1, 9, 10, 0]

    allowed, _ = limiter.is_allowed("tenant-a:user-1", "login", max_per_minute=10)
    assert allowed is True

    distinct_count = limiter.record_distinct(
        "tenant-a:user-1", "login", "attempt-1", window_seconds=60
    )

    bucket_key = "pesaguard:ratelimit:tenant-a:user-1:login"
    distinct_key = "pesaguard:ratelimit:distinct:tenant-a:user-1:login"
    assert distinct_count == 1
    assert bucket_key != distinct_key
    assert len(client.eval_calls) == 1
    script, numkeys, args = client.eval_calls[0]
    assert numkeys == 1
    assert args == (distinct_key, "attempt-1", 60, _MAX_DISTINCT_VALUES_PER_BUCKET)
    assert "SPOP" in script
    assert "EXPIRE" in script


def test_reset_clears_bucket_and_distinct_attempt_state():
    client = _RedisClient()
    limiter = RedisRateLimiter("redis://unused")
    limiter._get_client = lambda: client

    limiter.reset("tenant-a:user-1", "login")

    assert client.delete_calls == [
        (
            "pesaguard:ratelimit:tenant-a:user-1:login",
            "pesaguard:ratelimit:distinct:tenant-a:user-1:login",
        )
    ]


def test_in_memory_distinct_attempt_tracking_has_a_hard_cap(monkeypatch):
    limiter = TokenBucketRateLimiter(default_max_per_minute=10)
    for index in range(_MAX_DISTINCT_VALUES_PER_BUCKET + 25):
        count = limiter.record_distinct("client-a", "login", f"account-{index}", 60)

    key = "client-a:login"
    assert count == _MAX_DISTINCT_VALUES_PER_BUCKET
    assert len(limiter.distinct_values[key][0]) == _MAX_DISTINCT_VALUES_PER_BUCKET
