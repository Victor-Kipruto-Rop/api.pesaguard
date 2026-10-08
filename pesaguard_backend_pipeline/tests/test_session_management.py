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


def _clean(email: str, tenant_id: str = "session-tenant"):
    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).first()
        if account is not None:
            session.query(UserSession).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
            session.query(UserIdentity).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
            session.query(UserAccount).filter_by(id=account.id).delete(synchronize_session=False)
        session.commit()


def test_session_creation_renewal_device_logout_and_global_logout(client):
    email = "session-user@example.com"
    tenant_id = "session-tenant"
    _clean(email, tenant_id)
    registration = client.post(
        "/auth/register",
        json={"username": "session-user", "email": email, "password": "StrongPass123!", "tenant_id": tenant_id},
    ).get_json()
    verified = client.post(
        "/auth/verify-email",
        json={"email": email, "token": registration["verification_token"], "tenant_id": tenant_id, "device_id": "device-a"},
    )
    assert verified.status_code == 200
    first = verified.get_json()
    first_headers = {"Authorization": f"Bearer {first['access_token']}"}

    with SessionLocal() as session:
        first_record = session.get(UserSession, first["session_id"])
        assert first_record.state == "ACTIVE"
        assert first_record.device_id == "device-a"
        assert first_record.authentication_method == "email_verification"
        assert first_record.absolute_expires_at is not None
        assert first_record.last_activity_at is not None

    renewed = client.post(f"/auth/sessions/{first['session_id']}/renew", headers=first_headers, json={})
    assert renewed.status_code == 200
    listed = client.get("/auth/sessions", headers=first_headers)
    assert listed.status_code == 200
    assert listed.get_json()["sessions"][0]["state"] == "ACTIVE"

    second = client.post(
        "/auth/login",
        json={"username": email, "password": "StrongPass123!", "tenant_id": tenant_id, "device_id": "device-b"},
    ).get_json()
    second_headers = {"Authorization": f"Bearer {second['access_token']}"}
    assert client.post(f"/auth/sessions/{second['session_id']}/revoke", headers=second_headers, json={}).status_code == 200
    assert client.get("/auth/verify", headers=second_headers).status_code == 401
    assert client.get("/auth/verify", headers=first_headers).status_code == 200

    third = client.post(
        "/auth/login",
        json={"username": email, "password": "StrongPass123!", "tenant_id": tenant_id, "device_id": "device-c"},
    ).get_json()
    third_headers = {"Authorization": f"Bearer {third['access_token']}"}
    assert client.post("/auth/logout-all", headers=first_headers, json={}).status_code == 200
    assert client.get("/auth/verify", headers=first_headers).status_code == 401
    assert client.get("/auth/verify", headers=third_headers).status_code == 401

    _clean(email, tenant_id)
