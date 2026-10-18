"""Production session lifecycle checks must fail closed on schema/read errors."""

import pytest

import auth_rbac


class _BrokenSession:
    def __init__(self):
        self.execute_calls = 0
        self.rollback_calls = 0
        self.closed = False

    def execute(self, *_args, **_kwargs):
        self.execute_calls += 1
        raise RuntimeError("session lifecycle columns unavailable")

    def rollback(self):
        self.rollback_calls += 1

    def close(self):
        self.closed = True


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_session_lifecycle_read_error_fails_closed_without_legacy_fallback(
    monkeypatch, environment
):
    session = _BrokenSession()
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", environment)
    for name in ("PESAGUARD_ENV", "ENVIRONMENT", "FLASK_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(auth_rbac, "_ensure_revocation_store_ready", lambda: None)
    monkeypatch.setattr(auth_rbac, "_RevocationSession", lambda: session)

    with pytest.raises(auth_rbac.AuthenticationUnavailable):
        auth_rbac._session_is_active("session-1", "user-1", "tenant-1")

    # One call means the legacy SELECT active-only fallback was not attempted.
    assert session.execute_calls == 1
    assert session.rollback_calls >= 1
    assert session.closed is True


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_missing_session_id_is_rejected_in_production_like_environments(
    monkeypatch, environment
):
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", environment)
    for name in ("PESAGUARD_ENV", "ENVIRONMENT", "FLASK_ENV"):
        monkeypatch.delenv(name, raising=False)

    assert auth_rbac._session_is_active(None, "user-1", "tenant-1") is False


def test_missing_session_id_remains_tolerated_in_development(monkeypatch):
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", "development")
    for name in ("PESAGUARD_ENV", "ENVIRONMENT", "FLASK_ENV"):
        monkeypatch.delenv(name, raising=False)

    assert auth_rbac._session_is_active(None, "user-1", "tenant-1") is True


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_user_access_token_cannot_be_issued_without_session_id(
    monkeypatch, environment
):
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", environment)
    for name in ("PESAGUARD_ENV", "ENVIRONMENT", "FLASK_ENV"):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(ValueError, match="session_id is required"):
        auth_rbac.AuthRBAC.generate_token(
            user_id="user-1",
            username="user-1",
            tenant_id="tenant-1",
            roles=["operator"],
        )
