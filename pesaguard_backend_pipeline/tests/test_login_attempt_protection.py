import pytest
from datetime import datetime, timedelta, timezone

from test_config import configure_test_database

configure_test_database()

import app_4_advanced_features as advanced_features
from app_4_advanced_features import SessionLocal, app
from auth_rbac import AuthRBAC
from action_audit import ActionAuditEntry
from models import UserAccount, UserIdentity, UserSession
import rate_limiter as rate_limiter_module
from rate_limiter import RateLimiter


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def _clean(email: str, tenant_id: str = "login-protect-tenant"):
    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).first()
        if account is not None:
            session.query(UserSession).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
            session.query(UserIdentity).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
            session.query(UserAccount).filter_by(id=account.id).delete(synchronize_session=False)
        session.commit()


def test_per_account_lockout_and_admin_unlock(client, monkeypatch):
    monkeypatch.setenv("PESAGUARD_AUTH_RISK_POLICY", '{"privileged_operation_requires_mfa": false}')
    email = "login-protect-user@example.com"
    admin_email = "login-protect-admin@example.com"
    tenant_id = "login-protect-tenant"
    _clean(email, tenant_id)
    _clean(admin_email, tenant_id)
    registration = client.post(
        "/auth/register",
        json={"username": "login-protect-user", "email": email, "password": "StrongPass123!", "tenant_id": tenant_id},
    )
    assert registration.status_code == 201
    admin_registration = client.post(
        "/auth/register",
        json={"username": "login-protect-admin", "email": admin_email, "password": "StrongPass123!", "tenant_id": tenant_id, "roles": ["admin"]},
    )
    assert admin_registration.status_code == 201
    verify = client.post(
        "/auth/verify-email",
        json={"email": email, "token": registration.get_json()["verification_token"], "tenant_id": tenant_id},
    )
    assert verify.status_code == 200
    admin_verify = client.post(
        "/auth/verify-email",
        json={"email": admin_email, "token": admin_registration.get_json()["verification_token"], "tenant_id": tenant_id},
    )
    assert admin_verify.status_code == 200
    with SessionLocal() as session:
        user = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        admin_user = session.query(UserAccount).filter_by(email=admin_email, tenant_id=tenant_id).one()
        admin_token = AuthRBAC.generate_token(admin_user.id, admin_user.username, tenant_id, ["admin"])

    clock = [datetime.now(timezone.utc)]
    monkeypatch.setattr(advanced_features, "_now_utc", lambda: clock[0])
    failed_attempts = 0
    while failed_attempts < 5:
        resp = client.post(
            "/auth/login",
            json={"username": "login-protect-user", "password": "wrong-password", "tenant_id": tenant_id},
        )
        assert resp.status_code in {401, 423, 429}
        if resp.status_code == 423:
            break
        if resp.status_code == 429:
            clock[0] += timedelta(seconds=int(resp.get_json()["retry_after"]) + 1)
            continue
        failed_attempts += 1
        if resp.status_code == 401:
            clock[0] += timedelta(seconds=int(resp.headers.get("Retry-After", "1")))

    locked = resp if resp.status_code == 423 else client.post(
        "/auth/login",
        json={"username": "login-protect-user", "password": "wrong-password", "tenant_id": tenant_id},
    )
    assert locked.status_code == 423
    payload = locked.get_json()
    assert "locked_until" in payload or "retry_after" in payload
    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        assert account.status == "locked"
        assert account.attributes["lockout_count"] == 1

    visible = client.get(
        f"/auth/account/lockouts?tenant_id={tenant_id}",
        headers={"Authorization": "Bearer " + admin_token},
    )
    assert visible.status_code == 200, visible.get_data(as_text=True)
    assert any(item["user_id"] == user.id for item in visible.get_json()["items"])

    unlock = client.post(
        "/auth/account/unlock",
        json={"user_id": user.id, "tenant_id": tenant_id, "reason": "manual review complete"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert unlock.status_code == 200
    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        assert account.status == "active"
        assert account.attributes.get("lockout_count") is None
        unlock_event = session.query(ActionAuditEntry).filter_by(
            tenant_id=tenant_id,
            action="login.account_unlocked",
            resource_id=user.id,
            actor=admin_user.id,
        ).first()
        assert unlock_event is not None
        assert session.query(ActionAuditEntry).filter_by(
            tenant_id=tenant_id,
            action="login.brute_force_detected",
            resource_id=user.id,
        ).first() is not None

    ok = client.post(
        "/auth/login",
        json={"username": "login-protect-user", "password": "StrongPass123!", "tenant_id": tenant_id},
    )
    assert ok.status_code == 200

    _clean(email, tenant_id)
    _clean(admin_email, tenant_id)


def test_account_lockout_progresses_and_automatically_unlocks(client, monkeypatch):
    tenant_id = "progressive-lockout-tenant"
    email = "progressive-lockout@example.com"
    monkeypatch.setenv("PESAGUARD_LOGIN_FAILURE_LIMIT", "1")
    monkeypatch.setenv("PESAGUARD_ACCOUNT_LOCKOUT_MINUTES", "1")
    monkeypatch.setenv("PESAGUARD_ACCOUNT_LOCKOUT_MAX_MINUTES", "2")
    monkeypatch.setenv("PESAGUARD_LOGIN_ACCOUNT_RATE_LIMIT", "100")
    monkeypatch.setenv("PESAGUARD_LOGIN_IP_RATE_LIMIT", "100")
    monkeypatch.setenv("PESAGUARD_LOGIN_DEVICE_RATE_LIMIT", "100")
    _clean(email, tenant_id)
    registration = client.post(
        "/auth/register",
        json={"username": "progressive-lockout", "email": email, "password": "StrongPass123!", "tenant_id": tenant_id},
    )
    assert registration.status_code == 201
    assert client.post(
        "/auth/verify-email",
        json={"email": email, "token": registration.get_json()["verification_token"], "tenant_id": tenant_id},
    ).status_code == 200

    first_failure = client.post(
        "/auth/login",
        json={"username": email, "password": "incorrect", "tenant_id": tenant_id},
    )
    assert first_failure.status_code == 423
    first_deadline = datetime.fromisoformat(first_failure.get_json()["locked_until"])
    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        attrs = dict(account.attributes or {})
        attrs["locked_until"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        account.attributes = attrs
        session.commit()

    second_failure = client.post(
        "/auth/login",
        json={"username": email, "password": "incorrect", "tenant_id": tenant_id},
    )
    assert second_failure.status_code == 423
    second_deadline = datetime.fromisoformat(second_failure.get_json()["locked_until"])
    assert (second_deadline - datetime.now(timezone.utc)).total_seconds() > (
        first_deadline - datetime.now(timezone.utc)
    ).total_seconds()

    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        attrs = dict(account.attributes or {})
        attrs["locked_until"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        account.attributes = attrs
        session.commit()
    success = client.post(
        "/auth/login",
        json={"username": email, "password": "StrongPass123!", "tenant_id": tenant_id},
    )
    assert success.status_code == 200
    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        assert account.status == "active"
        assert account.attributes["failed_login_count"] == 0
        assert "locked_until" not in account.attributes
    _clean(email, tenant_id)


def test_per_ip_and_device_throttling(client, monkeypatch):
    tenant_id = "throttle-tenant"
    email_a = "throttle-user-a@example.com"
    email_b = "throttle-user-b@example.com"
    monkeypatch.setenv("PESAGUARD_LOGIN_DEVICE_RATE_LIMIT", "1")
    monkeypatch.setenv("PESAGUARD_LOGIN_IP_RATE_LIMIT", "100")
    monkeypatch.setenv("PESAGUARD_LOGIN_ACCOUNT_RATE_LIMIT", "100")
    _clean(email_a, tenant_id)
    _clean(email_b, tenant_id)

    for email in (email_a, email_b):
        registration = client.post(
            "/auth/register",
            json={"username": email.split("@")[0], "email": email, "password": "StrongPass123!", "tenant_id": tenant_id},
        )
        assert registration.status_code == 201
        verify = client.post(
            "/auth/verify-email",
            json={"email": email, "token": registration.get_json()["verification_token"], "tenant_id": tenant_id},
        )
        assert verify.status_code == 200

    attempts = [
        client.post(
            "/auth/login",
            json={"username": f"throttle-user-{chr(97 + (index % 2))}", "password": "wrong-password", "tenant_id": tenant_id, "device_id": "device-throttle-1"},
        )
        for index in range(6)
    ]

    throttled = [resp for resp in attempts if resp.status_code == 429]
    assert throttled
    assert throttled[0].get_json()["throttle_reason"] == "device"

    _clean(email_a, tenant_id)
    _clean(email_b, tenant_id)


def test_unknown_account_attempts_are_limited_across_changing_ips_and_devices(client, monkeypatch):
    tenant_id = "unknown-account-throttle-tenant"
    monkeypatch.setenv("PESAGUARD_LOGIN_ACCOUNT_RATE_LIMIT", "2")
    monkeypatch.setenv("PESAGUARD_LOGIN_IP_RATE_LIMIT", "100")
    monkeypatch.setenv("PESAGUARD_LOGIN_DEVICE_RATE_LIMIT", "100")
    attempts = []
    for index in range(3):
        attempts.append(client.post(
            "/auth/login",
            json={
                "username": "missing-account@example.com",
                "password": "wrong-password",
                "tenant_id": tenant_id,
                "device_id": f"device-{index}",
            },
            environ_base={"REMOTE_ADDR": f"192.0.2.{index + 1}"},
        ))
    assert [response.status_code for response in attempts] == [401, 401, 429]
    assert attempts[-1].get_json()["throttle_reason"] == "account"


def test_ip_throttle_limits_attempts_spread_across_unknown_accounts(client, monkeypatch):
    tenant_id = "ip-throttle-tenant"
    monkeypatch.setenv("PESAGUARD_LOGIN_ACCOUNT_RATE_LIMIT", "100")
    monkeypatch.setenv("PESAGUARD_LOGIN_IP_RATE_LIMIT", "2")
    monkeypatch.setenv("PESAGUARD_LOGIN_DEVICE_RATE_LIMIT", "100")
    attempts = []
    for index in range(3):
        attempts.append(client.post(
            "/auth/login",
            json={
                "username": f"ip-spray-{index}@example.com",
                "password": "wrong-password",
                "tenant_id": tenant_id,
                "device_id": f"distinct-device-{index}",
            },
            environ_base={"REMOTE_ADDR": "192.0.2.210"},
        ))
    assert [response.status_code for response in attempts] == [401, 401, 429]
    assert attempts[-1].get_json()["throttle_reason"] == "ip"


def test_credential_stuffing_attempts_are_audited_and_rate_limited(client, monkeypatch):
    tenant_id = "credential-stuffing-tenant"
    monkeypatch.setenv("PESAGUARD_LOGIN_ACCOUNT_RATE_LIMIT", "100")
    monkeypatch.setenv("PESAGUARD_LOGIN_IP_RATE_LIMIT", "100")
    monkeypatch.setenv("PESAGUARD_LOGIN_DEVICE_RATE_LIMIT", "100")
    monkeypatch.delenv("PESAGUARD_LOGIN_STUFFING_ACCOUNT_THRESHOLD", raising=False)
    monkeypatch.setenv("PESAGUARD_LOGIN_DETECTION_WINDOW_SECONDS", "600")
    with SessionLocal() as session:
        session.query(ActionAuditEntry).filter_by(
            tenant_id=tenant_id,
            action="login.credential_stuffing_detected",
        ).delete(synchronize_session=False)
        session.commit()

    for index in range(5):
        response = client.post(
            "/auth/login",
            json={
                "username": f"stuffed-account-{index}@example.com",
                "password": "wrong-password",
                "tenant_id": tenant_id,
                "device_id": "shared-device",
            },
            environ_base={"REMOTE_ADDR": "192.0.2.200"},
        )
        assert response.status_code == 401

    with SessionLocal() as session:
        event = session.query(ActionAuditEntry).filter_by(
            tenant_id=tenant_id,
            action="login.credential_stuffing_detected",
        ).first()
        assert event is not None
        assert event.details["reason"] == "multiple_identifiers_from_shared_source"


def test_rate_limiter_distinct_tracking_expires_and_can_reset(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("rate_limiter.time.time", lambda: now[0])
    limiter = RateLimiter(default_max_per_minute=2)
    assert limiter.record_distinct("device", "login", "account-a", 60) == 1
    assert limiter.record_distinct("device", "login", "account-b", 60) == 2
    now[0] += 61
    assert limiter.record_distinct("device", "login", "account-c", 60) == 1
    limiter.reset("device", "bucket")
    allowed, _ = limiter.is_allowed("device", "bucket")
    assert allowed


def test_login_limiter_uses_shared_distributed_backend(monkeypatch):
    class SharedBackend:
        def __init__(self):
            self.values = {}
            self.resets = set()

        def record_distinct(self, client_id, endpoint, value, _window_seconds):
            key = (client_id, endpoint)
            self.values.setdefault(key, set()).add(value)
            return len(self.values[key])

        def is_allowed(self, client_id, endpoint, max_per_minute, tokens_required=1):
            return True, {"remaining": max_per_minute - tokens_required, "limit": max_per_minute}

        def reset(self, client_id, endpoint):
            self.resets.add((client_id, endpoint))

    backend = SharedBackend()
    monkeypatch.setattr(rate_limiter_module, "ENABLE_REDIS_RATE_LIMITING", True)
    first = RateLimiter(default_max_per_minute=10, fail_closed=True)
    second = RateLimiter(default_max_per_minute=10, fail_closed=True)
    first._redis = backend
    second._redis = backend

    assert first.record_distinct("ip-key", "identifiers", "account-a", 600) == 1
    assert second.record_distinct("ip-key", "identifiers", "account-b", 600) == 2
    allowed, status = second.is_allowed("account-key", "login:account")
    assert allowed and status["limit"] == 10
    second.reset("account-key", "login:account")
    assert ("account-key", "login:account") in backend.resets


def test_production_login_fails_closed_without_distributed_rate_limiter(client, monkeypatch):
    monkeypatch.setattr(advanced_features, "_is_production_environment", lambda: True)
    monkeypatch.setattr(advanced_features, "ENABLE_REDIS_RATE_LIMITING", False)
    response = client.post(
        "/auth/login",
        json={"username": "unknown@example.com", "password": "wrong-password", "tenant_id": "prod-tenant"},
    )
    assert response.status_code == 503
    assert response.get_json()["error"] == "rate_limiter_unavailable"
