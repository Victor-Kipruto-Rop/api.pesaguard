import json
import time as real_time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import app_4_advanced_features as advanced_features
from test_config import configure_test_database

configure_test_database()

from app_4_advanced_features import (
    SessionLocal,
    _DEFAULT_AUTH_RISK_POLICY,
    _auth_risk_policy_for_tenant,
    _assess_login_risk,
    _evaluate_session_risk,
    _totp_code,
    app,
)
from models import DeviceIdentity, UserAccount, UserIdentity, UserSession


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def _clean(email: str, tenant_id: str):
    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).first()
        if account is not None:
            session.query(DeviceIdentity).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
            session.query(UserSession).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
            session.query(UserIdentity).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
            session.query(UserAccount).filter_by(id=account.id).delete(synchronize_session=False)
        session.commit()


def _create_user(client, username: str, email: str, tenant_id: str):
    registration = client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": "StrongPass123!", "tenant_id": tenant_id},
    )
    assert registration.status_code == 201
    payload = registration.get_json()
    verification = client.post(
        "/auth/verify-email",
        json={"email": email, "token": payload["verification_token"], "tenant_id": tenant_id},
    )
    assert verification.status_code == 200


def _login(
    client,
    username: str,
    tenant_id: str,
    device_id: str,
    remote_addr: str = "192.0.2.101",
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0) Chrome/131.0 Safari/537.36",
    **json_overrides,
):
    request_options = {"environ_base": {"REMOTE_ADDR": remote_addr}}
    response = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": "StrongPass123!",
            "tenant_id": tenant_id,
            "device_id": device_id,
            **json_overrides,
        },
        headers={"User-Agent": user_agent},
        **request_options,
    )
    return response


def test_device_registry_lifecycle_and_owner_scoping(client):
    tenant_id = "device-registry-tenant"
    email = "device-owner@example.com"
    other_email = "device-other@example.com"
    _clean(email, tenant_id)
    _clean(other_email, tenant_id)
    _create_user(client, "device-owner", email, tenant_id)
    _create_user(client, "device-other", other_email, tenant_id)

    first = _login(client, email, tenant_id, "shared-browser-id")
    other = _login(client, other_email, tenant_id, "shared-browser-id")
    assert first.status_code == other.status_code == 200
    first_payload = first.get_json()
    first_headers = {"Authorization": f"Bearer {first_payload['access_token']}"}

    listed = client.get("/auth/devices", headers=first_headers)
    assert listed.status_code == 200
    devices = listed.get_json()["devices"]
    assert len(devices) == 1
    assert devices[0]["device_id"] == "shared-browser-id"
    assert devices[0]["session_count"] == 1
    assert devices[0]["trusted"] is False
    assert devices[0]["user_id"] is not None
    assert devices[0]["browser"] == "Chrome"
    assert devices[0]["operating_system"] == "Windows"
    assert devices[0]["user_agent"].startswith("Mozilla/")
    assert devices[0]["first_seen"] and devices[0]["last_seen"]
    assert devices[0]["last_ip"] == "192.0.2.101"
    assert devices[0]["state"] == "active"

    renamed = client.post(
        "/auth/devices/shared-browser-id/rename",
        json={"device_name": "Finance laptop"},
        headers=first_headers,
    )
    assert renamed.status_code == 200
    assert renamed.get_json()["device_name"] == "Finance laptop"
    assert client.post(
        "/auth/devices/shared-browser-id/rename",
        json={"device_name": "Stolen rename"},
        headers={"Authorization": f"Bearer {other.get_json()['access_token']}"},
    ).status_code == 200
    assert client.get("/auth/devices", headers=first_headers).get_json()["devices"][0]["device_name"] == "Finance laptop"

    logged_out = client.post("/auth/devices/shared-browser-id/logout", json={}, headers=first_headers)
    assert logged_out.status_code == 200
    assert client.get("/auth/verify", headers=first_headers).status_code == 401

    second = _login(client, email, tenant_id, "shared-browser-id")
    assert second.status_code == 200
    assert client.post(
        "/auth/devices/shared-browser-id/revoke",
        json={},
        headers={"Authorization": f"Bearer {second.get_json()['access_token']}"},
    ).status_code == 200
    assert client.get("/auth/verify", headers={"Authorization": f"Bearer {second.get_json()['access_token']}"}).status_code == 401
    assert _login(client, email, tenant_id, "shared-browser-id").status_code == 403

    _clean(email, tenant_id)
    _clean(other_email, tenant_id)


def test_login_risk_policy_requires_step_up_or_blocks(client, monkeypatch):
    tenant_id = "device-risk-tenant"
    stepup_email = "risk-stepup@example.com"
    compromised_email = "risk-compromised@example.com"
    _clean(stepup_email, tenant_id)
    _clean(compromised_email, tenant_id)
    _create_user(client, "risk-stepup", stepup_email, tenant_id)
    _create_user(client, "risk-compromised", compromised_email, tenant_id)

    with SessionLocal() as session:
        stepup = session.query(UserAccount).filter_by(email=stepup_email, tenant_id=tenant_id).one()
        stepup.attributes = {**(stepup.attributes or {}), "failed_login_count": 3}
        compromised = session.query(UserAccount).filter_by(email=compromised_email, tenant_id=tenant_id).one()
        compromised.attributes = {**(compromised.attributes or {}), "credential_compromised": True}
        session.commit()

    stepup = _login(client, stepup_email, tenant_id, "new-stepup-device", "192.0.2.101")
    assert stepup.status_code == 403
    assert stepup.get_json()["error"] == "risk_mfa_enrollment_required"
    assert stepup.get_json()["risk_level"] == "medium"

    blocked = _login(client, compromised_email, tenant_id, "new-compromised-device", "192.0.2.101")
    assert blocked.status_code == 403
    assert blocked.get_json()["error"] == "login_blocked_for_review"

    _clean(stepup_email, tenant_id)
    _clean(compromised_email, tenant_id)


def test_risk_weights_and_actions_are_configurable(monkeypatch):
    configured = {
        "medium_threshold": 0.2,
        "high_threshold": 0.8,
        "weights": {"new_device": 0.3, "credential_compromise": 0.9},
    }
    monkeypatch.setenv("PESAGUARD_AUTH_RISK_POLICY", json.dumps(configured))
    policy = {
        **_DEFAULT_AUTH_RISK_POLICY,
        **configured,
        "weights": {**_DEFAULT_AUTH_RISK_POLICY["weights"], **configured["weights"]},
    }

    medium = _evaluate_session_risk(device_id="new-device", tenant_policy=policy)
    high = _evaluate_session_risk(
        signals_override={"credential_compromise": True},
        tenant_policy=policy,
    )
    assert medium["risk_level"] == "medium"
    assert medium["action"] == "require_mfa"
    assert high["risk_level"] == "high"
    assert high["action"] == "block"


def test_risk_policy_covers_all_configurable_signals():
    required_signals = {
        "new_device",
        "new_location",
        "impossible_travel",
        "unusual_login_time",
        "multiple_failed_attempts",
        "credential_compromise",
        "suspicious_ip",
        "high_risk_session",
        "privileged_operation",
    }
    policy = {
        **_DEFAULT_AUTH_RISK_POLICY,
        "weights": {signal: 0.1 for signal in required_signals},
        "medium_threshold": 0.2,
        "high_threshold": 0.8,
        "medium_action": "require_mfa",
        "high_action": "review",
    }

    result = _evaluate_session_risk(
        signals_override={signal: True for signal in required_signals},
        tenant_policy=policy,
    )

    assert set(result["signals"]) >= required_signals
    assert all(result["signals"][signal] for signal in required_signals)
    assert result["risk_score"] == 0.9
    assert result["risk_level"] == "high"
    assert result["action"] == "review"


def test_risk_assessment_derives_location_travel_time_compromise_and_ip_signals(client, monkeypatch):
    tenant_id = "derived-risk-signals-tenant"
    email = "derived-risk-signals@example.com"
    _clean(email, tenant_id)
    _create_user(client, "derived-risk-signals", email, tenant_id)
    now = datetime(2026, 10, 2, 16, 0, tzinfo=timezone.utc)
    monkeypatch.setattr("app_4_advanced_features._now_utc", lambda: now)
    monkeypatch.setenv(
        "PESAGUARD_AUTH_RISK_POLICY",
        json.dumps({
            "suspicious_ip_cidrs": ["203.0.113.0/24"],
            "impossible_travel_minimum_speed_kmh": 900,
            "unusual_login_minimum_samples": 5,
            "unusual_login_hour_deviation": 6,
        }),
    )

    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        account.attributes = {
            **(account.attributes or {}),
            "failed_login_count": 3,
            "credential_compromised": True,
        }
        for index in range(6):
            history_time = (now - timedelta(days=index + 1)).replace(hour=1, minute=0)
            session.add(UserSession(
                id=f"risk-history-{index}",
                tenant_id=tenant_id,
                user_id=account.id,
                device_id=f"old-device-{index}",
                state="ACTIVE",
                active=True,
                issued_at=history_time,
                last_activity_at=history_time,
                location_info={"country": "US", "latitude": 40.7128, "longitude": -74.0060},
            ))
        recent_time = now - timedelta(hours=3)
        session.add(UserSession(
            id="risk-recent-travel",
            tenant_id=tenant_id,
            user_id=account.id,
            device_id="known-us-device",
            state="ACTIVE",
            active=True,
            issued_at=recent_time,
            last_activity_at=recent_time,
            location_info={"country": "US", "latitude": 40.7128, "longitude": -74.0060},
        ))
        session.commit()

    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
    result, revoked = _assess_login_risk(
        account,
        "brand-new-device",
        "203.0.113.42",
        "Mozilla/5.0 Chrome/131.0",
        {"country": "KE", "latitude": -1.2864, "longitude": 36.8172},
    )
    assert revoked is False
    assert result["risk_level"] == "high"
    assert result["action"] == "block"
    assert all(result["signals"][signal] for signal in (
        "new_device",
        "new_location",
        "impossible_travel",
        "unusual_login_time",
        "multiple_failed_attempts",
        "credential_compromise",
        "suspicious_ip",
    ))

    _clean(email, tenant_id)


def test_invalid_risk_configuration_uses_bounded_logged_defaults(monkeypatch):
    monkeypatch.setenv(
        "PESAGUARD_AUTH_RISK_POLICY",
        json.dumps({
            "unusual_login_minimum_samples": "many",
            "unusual_login_hour_deviation": "invalid",
            "impossible_travel_minimum_speed_kmh": -1,
            "suspicious_ip_cidrs": "203.0.113.0/24",
            "compromised_ip_addresses": ["not-an-ip", "203.0.113.8"],
        }),
    )

    policy = _auth_risk_policy_for_tenant(None)

    assert policy["unusual_login_minimum_samples"] == 5
    assert policy["unusual_login_hour_deviation"] == 6
    assert policy["impossible_travel_minimum_speed_kmh"] == 1
    assert policy["suspicious_ip_cidrs"] == []
    assert policy["compromised_ip_addresses"] == ["203.0.113.8"]


def test_device_trust_requires_mfa_and_logout_all_ends_all_sessions(client, monkeypatch):
    clock = [real_time.time()]
    monkeypatch.setattr(advanced_features, "time", SimpleNamespace(time=lambda: clock[0]))
    tenant_id = "device-lifecycle-tenant"
    email = "device-lifecycle@example.com"
    _clean(email, tenant_id)
    _create_user(client, "device-lifecycle", email, tenant_id)

    first = _login(client, email, tenant_id, "device-one")
    second = _login(client, email, tenant_id, "device-two")
    assert first.status_code == second.status_code == 200
    first_token = first.get_json()["access_token"]
    first_headers = {"Authorization": f"Bearer {first_token}"}
    trust_url = "/auth/devices/device-one/trust"
    without_mfa = client.post(trust_url, headers=first_headers, json={})
    assert without_mfa.status_code == 401
    assert without_mfa.get_json()["error"]["code"] == "mfa_required"

    enrollment = client.post("/auth/mfa/enroll", headers=first_headers, json={})
    assert enrollment.status_code == 201
    secret = enrollment.get_json()["secret"]
    enabled = client.post(
        "/auth/mfa/enroll/verify",
        headers=first_headers,
        json={"code": _totp_code(secret)},
    )
    assert enabled.status_code == 200
    clock[0] += 30
    mfa_login = _login(
        client,
        email,
        tenant_id,
        "device-one",
        mfa_code=_totp_code(secret),
    )
    assert mfa_login.status_code == 200, mfa_login.get_data(as_text=True)
    first_token = mfa_login.get_json()["access_token"]
    first_headers = {"Authorization": f"Bearer {first_token}"}
    clock[0] += 30
    trusted = client.post(
        trust_url,
        headers=first_headers,
        json={"mfa_code": _totp_code(secret)},
    )
    assert trusted.status_code == 200
    assert trusted.get_json()["trusted"] is True
    with SessionLocal() as session:
        account_id = session.query(UserAccount.id).filter_by(email=email, tenant_id=tenant_id).scalar()
        active_session_count = session.query(UserSession).filter_by(
            user_id=account_id,
            tenant_id=tenant_id,
            active=True,
        ).count()

    logout = client.post("/auth/logout-all", headers=first_headers, json={})
    assert logout.status_code == 200
    assert active_session_count >= 3
    assert logout.get_json()["revoked_sessions"] == active_session_count
    for token in (first.get_json()["access_token"], second.get_json()["access_token"], first_token):
        assert client.get("/auth/verify", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    with SessionLocal() as session:
        assert session.query(UserSession).filter_by(
            user_id=account_id,
            tenant_id=tenant_id,
            active=True,
        ).count() == 0
        devices = session.query(DeviceIdentity).filter_by(user_id=account_id, tenant_id=tenant_id).all()
        assert {device.device_id for device in devices} == {"device-one", "device-two"}
        assert all(device.revoked_at is None for device in devices)
        assert next(device for device in devices if device.device_id == "device-one").trusted is True
    _clean(email, tenant_id)
