import importlib
import os
from pathlib import Path


def test_init_sentry_handles_missing_dsn(monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    obs = importlib.import_module("pesaguard_backend_pipeline.observability")
    assert obs.init_sentry() is False


def test_init_sentry_handles_existing_sdk_path(monkeypatch):
    monkeypatch.setenv("SENTRY_DSN", "https://examplePublicKey@o0.ingest.sentry.io/0")
    obs = importlib.import_module("pesaguard_backend_pipeline.observability")
    if obs.sentry_sdk is not None:
        monkeypatch.setattr(obs.sentry_sdk, "init", lambda **kwargs: None)
        assert obs.init_sentry() is True
    else:
        assert obs.init_sentry() is False


def test_load_dotenv_file_populates_sentry_settings(monkeypatch, tmp_path):
    monkeypatch.delenv("PYTHON_DOTENV_DISABLED", raising=False)
    obs = importlib.import_module("pesaguard_backend_pipeline.observability")
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    monkeypatch.delenv("SENTRY_ENVIRONMENT", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(
        "SENTRY_DSN=https://examplePublicKey@o0.ingest.sentry.io/0\n"
        "SENTRY_ENVIRONMENT=development\n"
        "SENTRY_RELEASE=pesaguard@local\n"
        "SENTRY_TRACES_SAMPLE_RATE=0.1\n"
        "SENTRY_PROFILES_SAMPLE_RATE=0.0\n"
        "SENTRY_SEND_DEFAULT_PII=false\n",
        encoding="utf-8",
    )

    obs._load_dotenv_file(env_file)

    assert os.getenv("SENTRY_DSN") == "https://examplePublicKey@o0.ingest.sentry.io/0"
    assert os.getenv("SENTRY_ENVIRONMENT") == "development"
    assert os.getenv("SENTRY_RELEASE") == "pesaguard@local"



def test_init_sentry_skips_blank_or_malformed_dsn(monkeypatch):
    obs = importlib.import_module("pesaguard_backend_pipeline.observability")
    for dsn in ("", "   ", "not-a-valid-dsn", "ftp://example.com/project"):
        monkeypatch.setenv("SENTRY_DSN", dsn)
        if obs.sentry_sdk is not None:
            monkeypatch.setattr(
                obs.sentry_sdk,
                "init",
                lambda **kwargs: (_ for _ in ()).throw(AssertionError("Sentry must not initialize with an invalid DSN")),
            )
        assert obs.init_sentry() is False
