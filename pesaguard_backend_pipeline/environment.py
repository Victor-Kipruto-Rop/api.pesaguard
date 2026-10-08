"""Load backend environment settings without importing application services."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
_ENVIRONMENT_VARIABLES = (
    "PESAGUARD_ENVIRONMENT",
    "PESAGUARD_ENV",
    "ENVIRONMENT",
    "FLASK_ENV",
)


def runtime_environment() -> str:
    """Resolve one consistent application environment across legacy aliases."""
    configured = [
        (name, os.getenv(name, "").strip().lower())
        for name in _ENVIRONMENT_VARIABLES
        if os.getenv(name, "").strip()
    ]
    normalized = {
        "prod": "production",
        "dev": "development",
        "testing": "test",
    }
    values = [(name, normalized.get(value, value)) for name, value in configured]
    if len({value for _, value in values}) > 1:
        names = ", ".join(name for name, _ in values)
        raise RuntimeError(f"Conflicting application environment variables are set: {names}")
    if not values:
        return "development"
    value = values[0][1]
    if value not in {"development", "test", "production", "staging"}:
        raise RuntimeError("Application environment must be development, test, staging, or production")
    return value


def load_backend_env(env_path: str | os.PathLike[str] | None = None) -> bool:
    """Fill missing process variables; never search the current working directory.

    PESAGUARD_ENV_FILE selects an explicit deployment file. Set
    PYTHON_DOTENV_DISABLED=1 for environment-only deployments and isolated tests.
    Values are literal (no ${...} expansion), including secrets containing '$'.
    """
    if os.getenv("PYTHON_DOTENV_DISABLED", "").lower() in {"1", "true", "yes", "on"}:
        return False
    configured_path = env_path if env_path is not None else os.getenv("PESAGUARD_ENV_FILE")
    path = Path(configured_path) if configured_path is not None else DEFAULT_ENV_FILE
    if not path.is_file():
        if configured_path is not None:
            raise RuntimeError("Configured backend environment file is not available")
        return False
    return load_dotenv(path, override=False, interpolate=False, encoding="utf-8-sig")


def required_env(name: str) -> str:
    """Require an explicit value without including it in errors or logs."""
    value = os.getenv(name)
    if value is None or not value.strip():
        raise RuntimeError(f"{name} must be configured")
    return value


load_backend_env()
