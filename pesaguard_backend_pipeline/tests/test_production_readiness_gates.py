import importlib


def _reload_health(monkeypatch, **environment):
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    import health

    return importlib.reload(health)


def test_production_requires_redis_and_kafka_for_readiness(monkeypatch):
    health = _reload_health(
        monkeypatch,
        PESAGUARD_ENVIRONMENT="production",
        DATABASE_URL="sqlite:///:memory:",
        DARAJA_CONSUMER_KEY="",
        DARAJA_CONSUMER_SECRET="",
    )
    monkeypatch.setattr(health, "check_database_connection", lambda: {
        "status": "ok",
        "database": {"status": "ok", "type": "sql"},
    })
    monkeypatch.setattr(health, "check_kafka_connectivity", lambda: {
        "status": "failed",
        "kafka": {"status": "failed", "error": "broker unavailable"},
    })
    monkeypatch.setattr(health, "check_redis_connectivity", lambda: {
        "status": "failed",
        "redis": {"status": "failed", "error": "redis unavailable"},
    })
    monkeypatch.setattr(health, "check_daraja_connectivity", lambda: {
        "status": "degraded",
        "daraja": {"status": "degraded", "reason": "credentials_not_configured"},
    })

    payload = health.build_health_payload()

    assert health.KAFKA_REQUIRED_FOR_OK is True
    assert health.REDIS_REQUIRED_FOR_OK is True
    assert payload["status"] == "degraded"
    assert payload["checks"]["kafka"]["status"] == "failed"
    assert payload["checks"]["redis"]["status"] == "failed"


def test_production_reports_ok_when_required_dependencies_are_healthy(monkeypatch):
    health = _reload_health(
        monkeypatch,
        PESAGUARD_ENVIRONMENT="production",
        DATABASE_URL="sqlite:///:memory:",
        DARAJA_CONSUMER_KEY="configured",
        DARAJA_CONSUMER_SECRET="configured",
    )
    monkeypatch.setattr(health, "check_database_connection", lambda: {
        "status": "ok",
        "database": {"status": "ok", "type": "sql"},
    })
    monkeypatch.setattr(health, "check_kafka_connectivity", lambda: {
        "status": "ok",
        "kafka": {"status": "ok"},
    })
    monkeypatch.setattr(health, "check_redis_connectivity", lambda: {
        "status": "ok",
        "redis": {"status": "ok"},
    })
    monkeypatch.setattr(health, "check_daraja_connectivity", lambda: {
        "status": "ok",
        "daraja": {"status": "ok"},
    })

    assert health.build_health_payload()["status"] == "ok"


def test_development_keeps_redis_and_kafka_optional(monkeypatch):
    health = _reload_health(
        monkeypatch,
        PESAGUARD_ENVIRONMENT="development",
        DATABASE_URL="sqlite:///:memory:",
    )
    monkeypatch.setattr(health, "check_database_connection", lambda: {
        "status": "ok",
        "database": {"status": "ok", "type": "sql"},
    })
    monkeypatch.setattr(health, "check_kafka_connectivity", lambda: {
        "status": "failed",
        "kafka": {"status": "failed", "error": "not configured"},
    })
    monkeypatch.setattr(health, "check_redis_connectivity", lambda: {
        "status": "failed",
        "redis": {"status": "failed", "error": "not configured"},
    })
    monkeypatch.setattr(health, "check_daraja_connectivity", lambda: {
        "status": "degraded",
        "daraja": {"status": "degraded", "reason": "credentials_not_configured"},
    })

    payload = health.build_health_payload()

    assert health.KAFKA_REQUIRED_FOR_OK is False
    assert health.REDIS_REQUIRED_FOR_OK is False
    assert payload["status"] == "degraded"


def test_explicit_health_gate_overrides_environment_default(monkeypatch):
    health = _reload_health(
        monkeypatch,
        PESAGUARD_ENVIRONMENT="development",
        PESAGUARD_HEALTH_REQUIRE_KAFKA="1",
        PESAGUARD_HEALTH_REQUIRE_REDIS="1",
        DATABASE_URL="sqlite:///:memory:",
    )

    assert health.KAFKA_REQUIRED_FOR_OK is True
    assert health.REDIS_REQUIRED_FOR_OK is True
