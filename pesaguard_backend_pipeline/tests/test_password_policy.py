import pytest

from test_config import configure_test_database

configure_test_database()

from app_4_advanced_features import SessionLocal, app
from auth_rbac import AuthRBAC
from models import PasswordCredential, UserAccount, UserIdentity, UserSession


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def _clean(email: str, tenant_id: str = "policy-tenant"):
    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).first()
        if account is not None:
            session.query(UserSession).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
            session.query(UserIdentity).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
            session.query(PasswordCredential).filter_by(user_id=account.id, tenant_id=tenant_id).delete(synchronize_session=False)
            session.query(UserAccount).filter_by(id=account.id).delete(synchronize_session=False)
        session.commit()


def test_passphrase_policy_change_and_admin_reset(client, monkeypatch):
    monkeypatch.setenv("PESAGUARD_AUTH_RISK_POLICY", '{"privileged_operation_requires_mfa": false}')
    email = "policy-user@example.com"
    tenant_id = "policy-tenant"
    _clean(email, tenant_id)
    registration = client.post(
        "/auth/register",
        json={"username": "policy-user", "email": email, "password": "Correct horse battery staple", "tenant_id": tenant_id},
    )
    assert registration.status_code == 201, registration.get_data(as_text=True)
    verification = client.post(
        "/auth/verify-email",
        json={"email": email, "token": registration.get_json()["verification_token"], "tenant_id": tenant_id},
    )
    assert verification.status_code == 200
    access_token = verification.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        admin_token = AuthRBAC.generate_token(account.id, account.username, tenant_id, ["admin"])
    policy_update = client.put(
        "/api/v1/iam/password-policy",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"max_age_days": 90, "privileged_max_age_days": 30, "notify_before_days": 7, "force_change": True},
    )
    assert policy_update.status_code == 200, policy_update.get_data(as_text=True)
    assert policy_update.get_json()["max_age_days"] == 90

    changed = client.post(
        "/auth/password/change",
        headers=headers,
        json={"current_password": "Correct horse battery staple", "new_password": "A longer secure passphrase 2026"},
    )
    assert changed.status_code == 200, changed.get_data(as_text=True)
    assert client.get("/auth/verify", headers=headers).status_code == 401
    assert client.post(
        "/auth/login",
        json={"username": email, "password": "A longer secure passphrase 2026", "tenant_id": tenant_id},
    ).status_code == 200

    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        admin_token = AuthRBAC.generate_token(account.id, account.username, tenant_id, ["admin"])
    reset = client.post(
        f"/auth/admin/users/{account.id}/password-reset",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"new_password": "Administrator reset passphrase 2026"},
    )
    assert reset.status_code == 200, reset.get_data(as_text=True)
    assert client.post(
        "/auth/login",
        json={"username": email, "password": "Administrator reset passphrase 2026", "tenant_id": tenant_id},
    ).status_code == 200
    assert client.post(
        "/auth/login",
        json={"username": email, "password": "Correct horse battery staple", "tenant_id": tenant_id},
    ).status_code == 401
    _clean(email, tenant_id)


def test_common_maximum_and_breached_passwords_are_rejected(client, monkeypatch):
    email = "weak-policy@example.com"
    tenant_id = "policy-tenant"
    _clean(email, tenant_id)

    common = client.post(
        "/auth/register",
        json={"username": "common", "email": email, "password": "password123", "tenant_id": tenant_id},
    )
    assert common.status_code == 400
    assert common.get_json()["error"] == "weak_password"

    too_long = client.post(
        "/auth/register",
        json={"username": "long", "email": email, "password": "x" * 129, "tenant_id": tenant_id},
    )
    assert too_long.status_code == 400

    class BreachResponse:
        status_code = 200
        text = "ABCDEF1234567890:42\n"

    monkeypatch.setenv("PESAGUARD_HIBP_ENABLED", "1")
    monkeypatch.setattr("app_4_advanced_features.requests.get", lambda *args, **kwargs: BreachResponse())
    breached_password = "Breach candidate passphrase 2026"
    import hashlib
    digest = hashlib.sha1(breached_password.encode()).hexdigest().upper()
    BreachResponse.text = f"{digest[5:]}:42\n"
    breached = client.post(
        "/auth/register",
        json={"username": "breached", "email": email, "password": breached_password, "tenant_id": tenant_id},
    )
    assert breached.status_code == 400
    assert breached.get_json()["error"] == "weak_password"
    _clean(email, tenant_id)
