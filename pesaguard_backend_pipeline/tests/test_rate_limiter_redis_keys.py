"""Regression tests for Redis rate-limiter key-type separation."""

from __future__ import annotations

from rate_limiter import RedisRateLimiter


class _Pipeline:
    def __init__(self, client):
        self.client = client

    def sadd(self, key, value):
        self.client.sadd_calls.append((key, value))
        return self

    def expire(self, key, seconds):
        self.client.expire_calls.append((key, seconds))
        return self

    def scard(self, key):
        self.client.scard_calls.append(key)
        return self

    def execute(self):
        return [1, True, 1]


class _RedisClient:
    def __init__(self):
        self.sadd_calls = []
        self.expire_calls = []
        self.scard_calls = []
        self.delete_calls = []

    def pipeline(self, transaction=True):
        assert transaction is True
        return _Pipeline(self)

    def delete(self, *keys):
        self.delete_calls.append(keys)
        return len(keys)


def test_distinct_attempts_use_a_different_key_from_token_bucket():
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
    assert client.sadd_calls == [(distinct_key, "attempt-1")]
    assert client.expire_calls == [(distinct_key, 60)]
    assert client.scard_calls == [distinct_key]


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
