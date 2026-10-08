import pytest

from test_config import configure_test_database

configure_test_database()

from app_4_advanced_features import SessionLocal, app
from models import UserAccount, UserIdentity, UserSession


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def _clean(email: str, tenant_id: str = "revoke-tenant"):
    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).first()
        if account is not None:
            session.query(UserSession).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
            session.query(UserIdentity).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
            session.query(UserAccount).filter_by(id=account.id).delete(synchronize_session=False)
        session.commit()


def test_revocation_levels_and_emergency_global_revoke(client, monkeypatch):
    email = "revocation-user@example.com"
    admin_email = "revocation-admin@example.com"
    tenant_id = "revoke-tenant"
    _clean(email, tenant_id)
    _clean(admin_email, tenant_id)
    monkeypatch.setenv("PESAGUARD_MFA_ADMIN_ENFORCED", "0")
    monkeypatch.setenv("PESAGUARD_AUTH_RISK_POLICY", '{"privileged_operation_requires_mfa": false}')
    registration = client.post(
        "/auth/register",
        json={"username": "revoke-user", "email": email, "password": "StrongPass123!", "tenant_id": tenant_id},
    )
    assert registration.status_code == 201
    admin_registration = client.post(
        "/auth/register",
        json={"username": "revoke-admin", "email": admin_email, "password": "StrongPass123!", "tenant_id": tenant_id},
    )
    assert admin_registration.status_code == 201
    admin_verification = client.post(
        "/auth/verify-email",
        json={"email": admin_email, "token": admin_registration.get_json()["verification_token"], "tenant_id": tenant_id},
    )
    assert admin_verification.status_code == 200
    with SessionLocal() as session:
        admin = session.query(UserAccount).filter_by(email=admin_email, tenant_id=tenant_id).one()
        admin.roles = ["admin"]
        session.commit()

    admin_login = client.post(
        "/auth/login",
        json={"username": admin_email, "password": "StrongPass123!", "tenant_id": tenant_id, "device_id": "admin-device"},
    )
    assert admin_login.status_code == 200
    admin_token = admin_login.get_json()["access_token"]

    verification = client.post(
        "/auth/verify-email",
        json={"email": email, "token": registration.get_json()["verification_token"], "tenant_id": tenant_id, "device_id": "device-alpha"},
    )
    assert verification.status_code == 200
    user_access = verification.get_json()
    user_headers = {"Authorization": f"Bearer {user_access['access_token']}"}

    login = client.post(
        "/auth/login",
        json={"username": email, "password": "StrongPass123!", "tenant_id": tenant_id, "device_id": "device-beta"},
    )
    assert login.status_code == 200
    login_data = login.get_json()
    login_headers = {"Authorization": f"Bearer {login_data['access_token']}"}

    device_revoked = client.post(
        "/auth/revoke/device",
        json={"device_id": "device-beta", "tenant_id": tenant_id, "reason": "lost device"},
        headers={"Authorization": f"Bearer {login_data['access_token']}"},
    )
    assert device_revoked.status_code == 200
    assert client.get("/auth/verify", headers=login_headers).status_code == 401

    refresh_revoked = client.post(
        "/auth/revoke/refresh",
        json={"refresh_token": login_data["refresh_token"], "reason": "compromise suspected"},
        headers=user_headers,
    )
    assert refresh_revoked.status_code == 200

    with SessionLocal() as session:
        user = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
    user_revoked = client.post(
        "/auth/revoke/user",
        json={"user_id": user.id, "tenant_id": tenant_id, "reason": "employee terminated"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert user_revoked.status_code == 200
    assert client.get("/auth/verify", headers=user_headers).status_code == 401

    emergency = client.post(
        "/auth/security/global-revoke",
        json={"reason": "critical platform incident"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert emergency.status_code == 200

    _clean(email, tenant_id)
    _clean(admin_email, tenant_id)
