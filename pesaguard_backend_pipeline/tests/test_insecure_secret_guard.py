"""The insecure bootstrap JWT key is never permitted in staging or production."""

import pytest

import auth_rbac


@pytest.mark.parametrize("environment, expected", [
    ("development", True),
    ("test", True),
    ("staging", False),
    ("production", False),
])
def test_insecure_jwt_bootstrap_secret_is_limited_to_dev_and_test(
    monkeypatch, environment, expected
):
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", environment)
    monkeypatch.setenv("PESAGUARD_ALLOW_INSECURE_DEV_SECRET", "1")
    for name in ("PESAGUARD_ENV", "ENVIRONMENT", "FLASK_ENV"):
        monkeypatch.delenv(name, raising=False)

    assert auth_rbac._allow_insecure_development_secret() is expected
