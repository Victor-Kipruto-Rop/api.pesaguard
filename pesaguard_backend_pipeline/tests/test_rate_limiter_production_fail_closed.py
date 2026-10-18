"""Production rate limiting must not downgrade to per-process memory."""

import rate_limiter as rate_limiter_module
from rate_limiter import RateLimiter


def test_production_rate_limiter_fails_closed_without_redis(monkeypatch):
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", "production")
    for name in ("PESAGUARD_ENV", "ENVIRONMENT", "FLASK_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(rate_limiter_module, "ENABLE_REDIS_RATE_LIMITING", False)

    limiter = RateLimiter()
    allowed, status = limiter.is_allowed("tenant-1", "login")

    assert limiter.fail_closed is True
    assert allowed is False
    assert status["unavailable"] is True
    assert status["retry_after"] == 1


def test_development_can_explicitly_use_memory_when_redis_unavailable(monkeypatch):
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", "development")
    for name in ("PESAGUARD_ENV", "ENVIRONMENT", "FLASK_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(rate_limiter_module, "ENABLE_REDIS_RATE_LIMITING", False)

    limiter = RateLimiter(fail_closed=False)
    allowed, status = limiter.is_allowed("local-client", "test")

    assert allowed is True
    assert "unavailable" not in status
