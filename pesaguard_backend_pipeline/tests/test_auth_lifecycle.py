import pytest
import uuid
from datetime import datetime, timedelta, timezone

import app_4_advanced_features as advanced_features
from app_4_advanced_features import app, SessionLocal, _totp_code
from auth_rbac import AuthRBAC, RefreshTokenRecord
from models import PasswordCredential, PasswordHistory, PasswordResetState, UserAccount, UserIdentity, UserSession


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def _clean_user_email(email: str, tenant_id: str = "test-tenant"):
    with SessionLocal() as session:
        session.query(UserIdentity).filter_by(email=email, tenant_id=tenant_id).delete(synchronize_session=False)
        session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).delete(synchronize_session=False)
        session.commit()


def test_webauthn_production_requires_explicit_https_origin(monkeypatch):
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", "production")
    monkeypatch.delenv("PESAGUARD_WEBAUTHN_ORIGIN", raising=False)

    with app.test_request_context(base_url="https://untrusted.example"):
        with pytest.raises(ValueError, match="must be configured in production"):
            advanced_features._webauthn_settings()


def test_webauthn_uses_configured_origin_and_rp_id(monkeypatch):
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", "production")
    monkeypatch.setenv("PESAGUARD_WEBAUTHN_ORIGIN", "https://developers.example.com")
    monkeypatch.setenv("PESAGUARD_WEBAUTHN_RP_ID", "example.com")
    monkeypatch.setenv("PESAGUARD_WEBAUTHN_RP_NAME", "PesaGuard Portal")

    with app.test_request_context(base_url="https://attacker.example"):
        assert advanced_features._webauthn_settings() == (
            "example.com",
            "PesaGuard Portal",
            "https://developers.example.com",
        )


def test_webauthn_rejects_http_origin_in_production(monkeypatch):
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", "production")
    monkeypatch.setenv("PESAGUARD_WEBAUTHN_ORIGIN", "http://developers.example.com")
    monkeypatch.setenv("PESAGUARD_WEBAUTHN_RP_ID", "example.com")

    with app.test_request_context(base_url="https://developers.example.com"):
        with pytest.raises(ValueError, match="must use HTTPS"):
            advanced_features._webauthn_settings()


def test_register_verify_and_login(client):
    email = "newuser@example.com"
    tenant_id = "test-tenant"
    _clean_user_email(email, tenant_id)
    response = client.post(
        "/auth/register",
        json={
            "username": "newuser",
            "email": email,
            "password": "StrongPass123!",
            "tenant_id": tenant_id,
            "first_name": "New",
            "last_name": "User",
            "display_name": "New User",
            "phone": "+254700000001",
        },
    )
    assert response.status_code == 201, response.get_data(as_text=True)
    payload = response.get_json()
    assert payload["user"]["username"] == "newuser"
    assert "verification_token" in payload
    verify_response = client.post(
        "/auth/verify-email",
        json={"email": email, "token": payload["verification_token"], "tenant_id": tenant_id},
    )
    assert verify_response.status_code == 200, verify_response.get_data(as_text=True)
    with SessionLocal() as session:
        identity = session.query(UserIdentity).filter_by(email=email, tenant_id=tenant_id).one()
        assert identity.external_id
        assert identity.email_verified is True
        assert identity.email_verified_at is not None
        assert identity.first_name == "New"
        assert identity.last_name == "User"
        assert identity.display_name == "New User"
        assert identity.phone == "+254700000001"
        assert identity.status == "ACTIVE"

    login_response = client.post(
        "/auth/login",
        json={"username": email, "password": "StrongPass123!", "tenant_id": tenant_id, "device_id": "device-verify"},
    )
    assert login_response.status_code == 200, login_response.get_data(as_text=True)
    body = login_response.get_json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["expires_in"] <= 15 * 60

    with SessionLocal() as session:
        session_record = session.query(UserSession).filter_by(user_id=body["user"]["id"], tenant_id=tenant_id).first()
        assert session_record is not None
        identity = session.query(UserIdentity).filter_by(user_id=body["user"]["id"], tenant_id=tenant_id).one()
        assert identity.last_login_at is not None
        assert identity.last_activity_at is not None

    _clean_user_email(email, tenant_id)


def test_refresh_rotation_and_reuse_revoke_the_entire_family(client):
    email = f"refresh-user-{uuid.uuid4().hex}@example.com"
    tenant_id = "refresh-tenant"
    registration = client.post(
        "/auth/register",
        json={"username": "refresh-user", "email": email, "password": "StrongPass123!", "tenant_id": tenant_id},
    )
    assert registration.status_code == 201
    assert client.post(
        "/auth/verify-email",
        json={"email": email, "token": registration.get_json()["verification_token"], "tenant_id": tenant_id},
    ).status_code == 200
    login = client.post(
        "/auth/login",
        json={
            "username": email,
            "password": "StrongPass123!",
            "tenant_id": tenant_id,
            "device_id": "refresh-device",
        },
    )
    assert login.status_code == 200
    original = login.get_json()["refresh_token"]

    rotation = AuthRBAC.rotate_refresh_token(original, device_id="refresh-device")
    assert rotation is not None
    _, replacement = rotation
    assert AuthRBAC.verify_refresh_token(original) is None
    assert AuthRBAC.verify_refresh_token(replacement) is not None

    assert AuthRBAC.rotate_refresh_token(original, device_id="refresh-device") is None
    assert AuthRBAC.verify_refresh_token(replacement) is None

    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        session.query(RefreshTokenRecord).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
        session.query(UserSession).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
        session.query(PasswordResetState).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
        session.query(PasswordHistory).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
        session.query(PasswordCredential).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
        session.query(UserIdentity).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
        session.delete(account)
        session.commit()


def test_password_reset_and_lockout(client, monkeypatch):
    email = "resetuser@example.com"
    tenant_id = "test-tenant"
    _clean_user_email(email, tenant_id)
    registration = client.post(
        "/auth/register",
        json={"username": "resetuser", "email": email, "password": "OriginalPass123!", "tenant_id": tenant_id},
    ).get_json()
    assert client.post(
        "/auth/verify-email",
        json={"email": email, "token": registration["verification_token"], "tenant_id": tenant_id},
    ).status_code == 200

    clock = [datetime.now(timezone.utc)]
    monkeypatch.setattr(advanced_features, "_now_utc", lambda: clock[0])
    failed_attempts = 0
    while failed_attempts < 5:
        response = client.post(
            "/auth/login",
            json={"username": email, "password": "WrongPass123!", "tenant_id": tenant_id},
        )
        assert response.status_code in {401, 423, 429}
        if response.status_code == 423:
            break
        if response.status_code == 429:
            clock[0] += timedelta(seconds=int(response.get_json()["retry_after"]) + 1)
            continue
        failed_attempts += 1
        clock[0] += timedelta(seconds=int(response.headers.get("Retry-After", "1")))
    assert response.status_code == 423
    assert client.post(
        "/auth/login",
        json={"username": email, "password": "OriginalPass123!", "tenant_id": tenant_id},
    ).status_code == 423

    reset_request = client.post("/auth/password-reset/request", json={"email": email, "tenant_id": tenant_id})
    reset_confirm = client.post(
        "/auth/password-reset/confirm",
        json={"email": email, "token": reset_request.get_json()["reset_token"], "new_password": "NewPass45678!", "tenant_id": tenant_id},
    )
    assert reset_confirm.status_code == 200
    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        assert account.status == "active"
        assert account.attributes["failed_login_count"] == 0
        assert "locked_until" not in account.attributes
    assert client.post(
        "/auth/login",
        json={"username": email, "password": "NewPass45678!", "tenant_id": tenant_id},
    ).status_code == 200
    _clean_user_email(email, tenant_id)


def test_expired_password_and_reset_revoke_existing_session(client):
    email = "expireduser@example.com"
    tenant_id = "test-tenant"
    _clean_user_email(email, tenant_id)
    registration = client.post(
        "/auth/register",
        json={"username": "expireduser", "email": email, "password": "OriginalPass123!", "tenant_id": tenant_id},
    ).get_json()
    assert client.post(
        "/auth/verify-email",
        json={"email": email, "token": registration["verification_token"], "tenant_id": tenant_id},
    ).status_code == 200
    login = client.post(
        "/auth/login",
        json={"username": email, "password": "OriginalPass123!", "tenant_id": tenant_id, "device_id": "reset-device"},
    )
    assert login.status_code == 200
    old_token = login.get_json()["access_token"]
    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        credential = session.query(PasswordCredential).filter_by(user_id=account.id, tenant_id=tenant_id, status="ACTIVE").one()
        credential.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        session.commit()
    expired = client.post("/auth/login", json={"username": email, "password": "OriginalPass123!", "tenant_id": tenant_id})
    assert expired.status_code == 403
    assert expired.get_json()["error"] == "password_expired"
    reset_request = client.post("/auth/password-reset/request", json={"email": email, "tenant_id": tenant_id})
    reset_confirm = client.post(
        "/auth/password-reset/confirm",
        json={"email": email, "token": reset_request.get_json()["reset_token"], "new_password": "NewPass45678!", "tenant_id": tenant_id},
    )
    assert reset_confirm.status_code == 200
    assert client.get("/auth/verify", headers={"Authorization": f"Bearer {old_token}"}).status_code == 401
    _clean_user_email(email, tenant_id)


def test_totp_recovery_email_and_reset_workflow(client, monkeypatch):
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", "development")
    email = f"mfauser-{uuid.uuid4().hex}@example.com"
    tenant_id = "test-tenant"
    _clean_user_email(email, tenant_id)

    registration_response = client.post(
        "/auth/register",
        json={"username": "mfauser", "email": email, "password": "OriginalPass123!", "tenant_id": tenant_id},
    )
    registration = registration_response.get_json()
    if "verification_token" not in registration:
        registration = client.post(
            "/auth/verify-email/resend",
            json={"email": email, "tenant_id": tenant_id},
        ).get_json()
    assert client.post(
        "/auth/verify-email",
        json={"email": email, "token": registration["verification_token"], "tenant_id": tenant_id},
    ).status_code == 200

    login = client.post(
        "/auth/login",
        json={"username": email, "password": "OriginalPass123!", "tenant_id": tenant_id},
    )
    token = login.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    enrollment = client.post("/auth/mfa/enroll", headers=headers, json={})
    assert enrollment.status_code == 201, enrollment.get_data(as_text=True)
    enrollment_body = enrollment.get_json()
    secret = enrollment_body["secret"]
    recovery_code = enrollment_body["recovery_codes"][0]

    enabled = client.post(
        "/auth/mfa/enroll/verify",
        headers=headers,
        json={"code": _totp_code(secret)},
    )
    assert enabled.status_code == 200, enabled.get_data(as_text=True)

    missing_mfa = client.post(
        "/auth/login",
        json={"username": email, "password": "OriginalPass123!", "tenant_id": tenant_id},
    )
    assert missing_mfa.status_code == 401
    assert missing_mfa.get_json()["error"] == "mfa_required"

    recovery_login = client.post(
        "/auth/login",
        json={"username": email, "password": "OriginalPass123!", "tenant_id": tenant_id, "recovery_code": recovery_code},
    )
    assert recovery_login.status_code == 200, recovery_login.get_data(as_text=True)
    headers = {"Authorization": f"Bearer {recovery_login.get_json()['access_token']}"}

    reused_recovery = client.post(
        "/auth/login",
        json={"username": email, "password": "OriginalPass123!", "tenant_id": tenant_id, "recovery_code": recovery_code},
    )
    assert reused_recovery.status_code == 401

    email_challenge = client.post("/auth/mfa/email/request", headers=headers, json={})
    assert email_challenge.status_code == 201, email_challenge.get_data(as_text=True)
    email_body = email_challenge.get_json()
    email_verified = client.post(
        "/auth/mfa/email/verify",
        headers=headers,
        json={"challenge_id": email_body["challenge_id"], "code": email_body["verification_code"]},
    )
    assert email_verified.status_code == 200
    assert email_verified.get_json()["verified"] is True

    reset_request = client.post("/auth/mfa/reset/request", headers=headers, json={})
    assert reset_request.status_code == 201
    reset_body = reset_request.get_json()
    reset_confirm = client.post(
        "/auth/mfa/reset/confirm",
        headers=headers,
        json={"challenge_id": reset_body["challenge_id"], "code": reset_body["verification_code"]},
    )
    assert reset_confirm.status_code == 200, reset_confirm.get_data(as_text=True)

    after_reset = client.post(
        "/auth/login",
        json={"username": email, "password": "OriginalPass123!", "tenant_id": tenant_id},
    )
    assert after_reset.status_code == 200

    _clean_user_email(email, tenant_id)
