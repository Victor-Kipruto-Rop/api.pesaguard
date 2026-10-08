import pytest

from app_4_advanced_features import SessionLocal, app
from models import PasswordCredential, PasswordHistory, PasswordResetState, UserAccount, UserIdentity


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def _clean(email: str, tenant_id: str = "credential-tenant"):
    with SessionLocal() as session:
        accounts = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).all()
        user_ids = [account.id for account in accounts]
        if user_ids:
            session.query(PasswordResetState).filter(PasswordResetState.user_id.in_(user_ids)).delete(synchronize_session=False)
            session.query(PasswordHistory).filter(PasswordHistory.user_id.in_(user_ids)).delete(synchronize_session=False)
            session.query(PasswordCredential).filter(PasswordCredential.user_id.in_(user_ids)).delete(synchronize_session=False)
        session.query(UserIdentity).filter_by(email=email, tenant_id=tenant_id).delete(synchronize_session=False)
        session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).delete(synchronize_session=False)
        session.commit()


def test_argon2id_credential_rotation_history_and_single_use_reset(client):
    email = "credential-user@example.com"
    tenant_id = "credential-tenant"
    _clean(email, tenant_id)

    registration = client.post(
        "/auth/register",
        json={"username": "credential-user", "email": email, "password": "OriginalPass123!", "tenant_id": tenant_id},
    )
    assert registration.status_code == 201, registration.get_data(as_text=True)
    verification_token = registration.get_json()["verification_token"]
    assert client.post(
        "/auth/verify-email",
        json={"email": email, "token": verification_token, "tenant_id": tenant_id},
    ).status_code == 200

    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        credential = session.query(PasswordCredential).filter_by(user_id=account.id, status="ACTIVE").one()
        assert credential.algorithm == "argon2id"
        assert credential.password_hash.startswith("$argon2id$")
        assert credential.parameters["memory_cost_kib"] == 65536
        assert credential.parameters["time_cost"] == 3
        assert "OriginalPass123!" not in credential.password_hash
        assert account.password_hash is None
        assert account.password_salt is None

    reset_request = client.post("/auth/password-reset/request", json={"email": email, "tenant_id": tenant_id})
    assert reset_request.status_code == 200
    reset_token = reset_request.get_json()["reset_token"]
    reset_confirm = client.post(
        "/auth/password-reset/confirm",
        json={"email": email, "token": reset_token, "new_password": "RotatedPass45678!", "tenant_id": tenant_id},
    )
    assert reset_confirm.status_code == 200, reset_confirm.get_data(as_text=True)

    reused = client.post(
        "/auth/password-reset/confirm",
        json={"email": email, "token": reset_token, "new_password": "AnotherPass78901!", "tenant_id": tenant_id},
    )
    assert reused.status_code == 400

    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).one()
        active = session.query(PasswordCredential).filter_by(user_id=account.id, status="ACTIVE").one()
        revoked = session.query(PasswordCredential).filter_by(user_id=account.id, status="REVOKED").all()
        history = session.query(PasswordHistory).filter_by(user_id=account.id).all()
        reset_state = session.query(PasswordResetState).filter_by(user_id=account.id).one()
        assert active.algorithm == "argon2id"
        assert revoked
        assert history
        assert reset_state.status == "USED"

    assert client.post(
        "/auth/login",
        json={"username": email, "password": "RotatedPass45678!", "tenant_id": tenant_id},
    ).status_code == 200
    assert client.post(
        "/auth/login",
        json={"username": email, "password": "OriginalPass123!", "tenant_id": tenant_id},
    ).status_code == 401

    _clean(email, tenant_id)
