"""Isolated checks for deployment configuration; no external services required."""
import os
from pathlib import Path

import pytest

import environment


@pytest.fixture
def env_file(monkeypatch, tmp_path):
    monkeypatch.delenv("PYTHON_DOTENV_DISABLED", raising=False)
    monkeypatch.delenv("PESAGUARD_ENV_FILE", raising=False)
    monkeypatch.delenv("ENV_LOADER_TEST", raising=False)
    path = tmp_path / ".env"
    path.write_text('ENV_LOADER_TEST="literal ${UNCHANGED} # value"\n', encoding="utf-8")
    return path


def test_loads_literal_values(env_file):
    assert environment.load_backend_env(env_file)
    assert os.environ["ENV_LOADER_TEST"] == "literal ${UNCHANGED} # value"


@pytest.mark.parametrize("value", ["runtime-value", ""])
def test_process_values_win(monkeypatch, env_file, value):
    monkeypatch.setenv("ENV_LOADER_TEST", value)
    environment.load_backend_env(env_file)
    assert os.environ["ENV_LOADER_TEST"] == value


def test_default_path_is_independent_of_cwd(monkeypatch, env_file, tmp_path):
    monkeypatch.setattr(environment, "DEFAULT_ENV_FILE", env_file)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / ".env").write_text("ENV_LOADER_TEST=wrong\n", encoding="utf-8")
    monkeypatch.chdir(elsewhere)
    environment.load_backend_env()
    assert os.environ["ENV_LOADER_TEST"].startswith("literal")


def test_explicit_file_override(monkeypatch, env_file):
    monkeypatch.setenv("PESAGUARD_ENV_FILE", str(env_file))
    assert environment.load_backend_env()


def test_disabled_loading(monkeypatch, env_file):
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    assert environment.load_backend_env(env_file) is False
    assert "ENV_LOADER_TEST" not in os.environ


def test_missing_default_is_optional(monkeypatch, env_file):
    monkeypatch.setattr(environment, "DEFAULT_ENV_FILE", env_file.parent / "missing")
    assert environment.load_backend_env() is False


@pytest.mark.parametrize("app_environment", ["production", "staging"])
def test_deployed_environments_do_not_load_implicit_dotenv(monkeypatch, env_file, app_environment):
    monkeypatch.setattr(environment, "DEFAULT_ENV_FILE", env_file)
    for name in environment._ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PESAGUARD_ENVIRONMENT", app_environment)

    assert environment.load_backend_env() is False
    assert "ENV_LOADER_TEST" not in os.environ


def test_missing_explicit_file_fails(env_file):
    with pytest.raises(RuntimeError, match="environment file is not available"):
        environment.load_backend_env(env_file.parent / "missing")


@pytest.mark.parametrize("value", [None, "", "   "])
def test_required_value_fails_safely(monkeypatch, value):
    monkeypatch.delenv("ENV_LOADER_TEST", raising=False)
    if value is not None:
        monkeypatch.setenv("ENV_LOADER_TEST", value)
    with pytest.raises(RuntimeError, match="^ENV_LOADER_TEST must be configured$"):
        environment.required_env("ENV_LOADER_TEST")


def test_required_value_unchanged(monkeypatch):
    monkeypatch.setenv("ENV_LOADER_TEST", "literal-value")
    assert environment.required_env("ENV_LOADER_TEST") == "literal-value"


def test_no_embedded_database_credentials():
    backend = Path(__file__).resolve().parents[1]
    forbidden = "postgresql://" + "pesaguard:pesaguard@"
    for path in backend.rglob("*.py"):
        if "tests" not in path.parts:
            assert forbidden not in path.read_text(encoding="utf-8"), str(path)
