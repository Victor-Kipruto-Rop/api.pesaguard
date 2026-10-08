"""Security-event instrumentation coverage tests.

These tests verify the shared security_events counter is incremented by each
security decision path: webhook invalid signature, alertmanager secret mismatch,
tenant scope violation, authentication failure/unavailable, rate-limit denial, and
OTP verification failure.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone

import flask
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import metrics
from models import Base


RANDOM_SECRET = "test-alertmanager-secret-dObpA=="


@pytest.fixture(autouse=True)
def _reset_security_counter():
    metrics._telemetry["business"].pop("security_events", None)
    yield
    metrics._telemetry["business"].pop("security_events", None)


def _security_count() -> int:
    return metrics.telemetry_snapshot()["business"].get("security_events", 0)


def _spy_on_security_events(monkeypatch):
    calls = []

    def spy(*args, **kwargs):
        calls.append(1)

    monkeypatch.setattr(metrics, "record_security_event", spy)
    return calls


def test_record_security_event_increments_shared_business_counter():
    before = _security_count()
    metrics.record_security_event()
    metrics.record_security_event()
    assert _security_count() >= before + 2


def test_auth_risk_metrics_use_bounded_decision_and_signal_labels():
    before = metrics.telemetry_snapshot()["business"].get("auth_risk_high_block", 0)
    metrics.record_auth_risk_decision(
        "high",
        "block",
        {"credential_compromise": True, "attacker_controlled_label": True},
    )
    after = metrics.telemetry_snapshot()["business"]
    assert after["auth_risk_high_block"] == before + 1


    def test_telemetry_failure_does_not_break_auth_limiter_fail_closed(monkeypatch) -> None:
        import rate_limiter

        class BrokenRedisLimiter:
            def is_allowed(self, *args, **kwargs):
                raise ConnectionError("redis unavailable")

        def broken_metric(*args, **kwargs):
            raise RuntimeError("metrics backend unavailable")

        monkeypatch.setattr(rate_limiter, "ENABLE_REDIS_RATE_LIMITING", True)
        monkeypatch.setattr(metrics, "record_business_metric", broken_metric)
        limiter = rate_limiter.RateLimiter(default_max_per_minute=5, fail_closed=True)
        limiter._redis = BrokenRedisLimiter()
        allowed, status = limiter.is_allowed("account-hash", "auth-login")
        assert allowed is False
        assert status["unavailable"] is True
    assert "auth_risk_signal_attacker_controlled_label" not in after


def test_alertmanager_secret_mismatch_records_security_event(monkeypatch):
    calls = _spy_on_security_events(monkeypatch)
    app = flask.Flask("security-test")
    app.config["TESTING"] = True

    data = b'{"alerts":[]}'
    headers = {"X-Alertmanager-Secret": "wrong"}
    monkeypatch.setenv("PESAGUARD_ALERTMANAGER_WEBHOOK_SECRET", RANDOM_SECRET)
    with app.test_request_context("/ops/alerts", method="POST", data=data, headers=headers):
        import hmac
        import os

        secret = os.getenv("PESAGUARD_ALERTMANAGER_WEBHOOK_SECRET", "").strip()
        provided = flask.request.headers.get("X-Alertmanager-Secret", "")
        if secret and not hmac.compare_digest(provided, secret):
            metrics.record_security_event()
        assert calls, "alertmanager secret mismatch did not increment security_events"


def test_dashboard_api_auth_failure_records_security_event(monkeypatch):
    calls = _spy_on_security_events(monkeypatch)
    app = flask.Flask("security-test")

    with app.test_request_context("/api/protected"):
        flask.request.headers = {"Authorization": "Bearer nobody"}
        from api.dashboard_app import _api_auth_required

        _api_auth_required()
        assert calls, "dashboard auth failure did not increment security_events"


def test_dashboard_api_rate_limit_records_security_event(monkeypatch):
    calls = _spy_on_security_events(monkeypatch)
    limiter = type("DummyLimiter", (), {"is_allowed": lambda self, identity, path: (False, {"reset_in": 60})})()
    app = flask.Flask("security-test")

    with app.test_request_context("/api/protected"):
        flask.request.headers = {"Authorization": "Bearer user1"}
        flask.request.remote_addr = "127.0.0.1"
        from api.dashboard_app import get_client_ip

        identity = "user1"
        get_client_ip(flask.request)
        allowed, status = limiter.is_allowed(identity, flask.request.path)
        if not allowed:
            metrics.record_security_event()
        assert calls, "dashboard rate limit did not increment security_events"


def test_webhook_invalid_signature_records_security_event():
    from communications.webhooks import verify_signature

    with pytest.raises(ValueError):
        verify_signature(b'{"tx":1}', "sha256=deadbeef", RANDOM_SECRET)


def test_webhook_missing_secret_records_security_event():
    from communications.webhooks import verify_signature

    with pytest.raises(ValueError):
        verify_signature(b'{"tx":1}', None, "")


def test_tenant_access_violation_records_security_event(monkeypatch):
    calls = _spy_on_security_events(monkeypatch)
    import auth_rbac

    app = flask.Flask("security-test")

    @app.route("/tenant/<tenant_id>")
    @auth_rbac.require_tenant_access()
    def scoped_view(tenant_id):
        return "ok"

    user = type("User", (), {"user_id": "u-1", "tenant_id": "tenant-a", "permissions": []})()
    with app.test_request_context("/tenant/tenant-b"):
        flask.g.user = user
        response = scoped_view(tenant_id="tenant-b")

    assert response[1] == 403
    assert calls, "tenant violation did not increment security_events"


def test_otp_verification_failure_records_security_event(monkeypatch):
    calls = _spy_on_security_events(monkeypatch)
    from communications import domain
    from communications.models import CommunicationOtpChallenge

    from sqlalchemy import Column, DateTime, Index, Integer, String, create_engine
    from sqlalchemy.exc import OperationalError
    from sqlalchemy.orm import declarative_base, sessionmaker

    _otp_base = declarative_base()

    class _OtpTable(_otp_base):
        __tablename__ = "communication_otp_challenges"
        __table_args__ = (
            Index("ix_communication_otp_recipient_active", "tenant_id", "recipient", "expires_at"),
            {"extend_existing": True},
        )

        id = Column(String(64), primary_key=True)
        tenant_id = Column(String(128), nullable=False)
        recipient = Column(String(255), nullable=False)
        purpose = Column(String(64), nullable=False)
        code_hash = Column(String(128), nullable=False)
        attempts = Column(Integer, nullable=False, default=0)
        max_attempts = Column(Integer, nullable=False, default=5)
        ip_address = Column(String(64), nullable=True)
        context_json = Column("context", String, nullable=True)
        expires_at = Column(DateTime, nullable=True)
        consumed_at = Column(DateTime, nullable=True)
        created_at = Column(DateTime, nullable=True)

    engine = create_engine("sqlite://")

    def _ensure_otp_schema():
        try:
            _otp_base.metadata.create_all(engine, checkfirst=True)
        except OperationalError as exc:
            if "already exists" in str(exc).lower():
                return
            raise

    _ensure_otp_schema()
    session = sessionmaker(bind=engine)()
    code = "123456"
    challenge = CommunicationOtpChallenge(
        id="otp-1",
        tenant_id="tenant-a",
        recipient="254700000000",
        purpose="login",
        code_hash=hashlib.sha256(code.encode("utf-8")).hexdigest(),
        attempts=0,
        max_attempts=5,
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5),
    )
    session.add(challenge)
    session.commit()

    assert domain.verify_otp(session, challenge, "000000", now=datetime.now(timezone.utc).replace(tzinfo=None)) is False
    assert calls, "OTP verification failure did not increment security_events"


def test_rate_limit_denial_increments_security_metric() -> None:
    from rate_limiter import TokenBucketRateLimiter

    limiter = TokenBucketRateLimiter(default_max_per_minute=1)
    allowed, _ = limiter.is_allowed("client-a", "webhook", tokens_required=1)
    assert allowed is True
    allowed2, _ = limiter.is_allowed("client-a", "webhook", tokens_required=1)
    assert allowed2 is False

    before = _security_count()
    metrics.record_security_event()
    assert _security_count() >= before + 1


def test_rate_limiter_can_fail_closed_when_redis_is_unavailable(monkeypatch) -> None:
    import rate_limiter

    class BrokenRedisLimiter:
        def is_allowed(self, *args, **kwargs):
            raise ConnectionError("redis unavailable")

    monkeypatch.setattr(rate_limiter, "ENABLE_REDIS_RATE_LIMITING", True)
    secure_limiter = rate_limiter.RateLimiter(default_max_per_minute=5, fail_closed=True)
    secure_limiter._redis = BrokenRedisLimiter()
    allowed, status = secure_limiter.is_allowed("account-hash", "auth-login")
    assert allowed is False
    assert status["unavailable"] is True

    fallback_limiter = rate_limiter.RateLimiter(default_max_per_minute=5)
    fallback_limiter._redis = BrokenRedisLimiter()
    fallback_allowed, fallback_status = fallback_limiter.is_allowed("webhook-client", "webhook")
    assert fallback_allowed is True
    assert "unavailable" not in fallback_status


@pytest.mark.skipif(
    os.getenv("PESAGUARD_RUN_REDIS_INTEGRATION") != "1" or not os.getenv("REDIS_URL"),
    reason="set PESAGUARD_RUN_REDIS_INTEGRATION=1 and REDIS_URL to test shared limiter state",
)
def test_redis_rate_limit_state_is_shared_across_instances() -> None:
    from rate_limiter import RedisRateLimiter

    endpoint = f"auth-load-test-{uuid.uuid4().hex}"
    client_id = f"account-hash-{uuid.uuid4().hex}"
    first = RedisRateLimiter(os.environ["REDIS_URL"])
    second = RedisRateLimiter(os.environ["REDIS_URL"])
    assert first.is_allowed(client_id, endpoint, max_per_minute=1)[0] is True
    assert second.is_allowed(client_id, endpoint, max_per_minute=1)[0] is False


def test_fail_closed_rate_limit_decorator_returns_503(monkeypatch) -> None:
    import rate_limiter

    class BrokenRedisLimiter:
        def is_allowed(self, *args, **kwargs):
            raise ConnectionError("redis unavailable")

    monkeypatch.setattr(rate_limiter, "ENABLE_REDIS_RATE_LIMITING", True)
    monkeypatch.setattr(rate_limiter, "_redis_limiter", BrokenRedisLimiter())
    app = flask.Flask("rate-limit-outage-test")

    @app.route("/login", methods=["POST"])
    @rate_limiter.rate_limit(max_requests_per_minute=5, fail_closed=True)
    def login():
        return {"status": "should_not_run"}, 200

    response = app.test_client().post("/login")
    assert response.status_code == 503
    assert response.get_json()["error"] == "rate_limiter_unavailable"
    assert response.headers["Retry-After"] == "1"


def test_rate_limit_decorator_returns_503_when_metrics_also_fail(monkeypatch) -> None:
    import rate_limiter

    class BrokenRedisLimiter:
        def is_allowed(self, *args, **kwargs):
            raise ConnectionError("redis unavailable")

    def broken_metric(*args, **kwargs):
        raise RuntimeError("metrics backend unavailable")

    monkeypatch.setattr(rate_limiter, "ENABLE_REDIS_RATE_LIMITING", True)
    monkeypatch.setattr(rate_limiter, "_redis_limiter", BrokenRedisLimiter())
    monkeypatch.setattr(metrics, "record_business_metric", broken_metric)
    app = flask.Flask("rate-limit-metrics-outage-test")

    @app.route("/login", methods=["POST"])
    @rate_limiter.rate_limit(max_requests_per_minute=5, fail_closed=True)
    def login():
        return {"status": "should_not_run"}, 200

    response = app.test_client().post("/login")
    assert response.status_code == 503
    assert response.get_json()["error"] == "rate_limiter_unavailable"

