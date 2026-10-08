"""Isolated infrastructure checks: no deployment secrets or service startup."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "infra/configure.py"
COMPOSE = ROOT / "infra/docker"


@pytest.fixture
def deployment(tmp_path):
    values = {
        "POSTGRES_USER": "config_test",
        "POSTGRES_DB": "config_test",
        "POSTGRES_PASSWORD": "isolated-config-test-only",
        "STAGING_POSTGRES_DB": "config_test_staging",
        "DATABASE_URL_DOCKER": "postgresql://config_test:isolated-test@postgres:5432/config_test",
        "JWT_SECRET_KEY": "isolated-configuration-test-only-not-production",
        "PESAGUARD_API_URL": "https://api.example.invalid",
        "KAFKA_BOOTSTRAP_SERVERS_DOCKER": "redpanda:9092",
        "REDIS_URL_DOCKER": "redis://redis:6379/0",
        "PESAGUARD_BIND_HOST_DOCKER": "0.0.0.0",
        "KAFKA_BOOTSTRAP_SERVERS_FULL": "kafka:29092",
        "KAFKA_ADVERTISED_LISTENERS_FULL": "PLAINTEXT://kafka:29092",
        "STAGING_KAFKA_ADVERTISED_LISTENERS": "PLAINTEXT://localhost:9092",
        "API_SERVER_NAME": "api.example.invalid",
        "CLOUDFLARE_TUNNEL_TOKEN": "isolated-config-test-only",
        "CONFIG_TEST_MARKER": "alternate-file-was-loaded",
    }
    path = tmp_path / ".env"
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    return path


def invoke(deployment, *args):
    # Explicit allowlist: never inherit database/provider credentials or Compose overrides.
    allowed = {
        "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "HOME",
        "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    return subprocess.run(
        [sys.executable, str(LAUNCHER), "--env-file", str(deployment), *args],
        env=env, cwd=deployment.parent, capture_output=True, text=True, timeout=60,
    )


@pytest.mark.skipif(not shutil.which("docker"), reason="Docker CLI unavailable")
@pytest.mark.parametrize("files,backend", [
    (["docker-compose.yml"], "webhook_receiver"),
    (["docker-compose.full.yml"], "backend"),
    (["docker-compose.staging.yml"], None),
    (["docker-compose.yml", "docker-compose.aws.yml"], "webhook_receiver"),
    (["docker-compose.yml", "docker-compose.tunnel.yml"], "webhook_receiver"),
])
def test_alternate_file_supplies_interpolation_and_service_env(deployment, files, backend):
    args = ["compose", "--"]
    for file in files:
        args += ["-f", str(COMPOSE / file)]
    result = invoke(deployment, *args, "config", "--format", "json")
    assert result.returncode == 0, result.stderr
    services = json.loads(result.stdout)["services"]
    postgres = services.get("postgres", services.get("postgres-staging"))
    assert postgres["environment"]["POSTGRES_USER"] == "config_test"
    assert "CONFIG_TEST_MARKER" not in postgres["environment"]
    if backend:
        for service in services.values():
            if "build" in service:
                assert service["environment"]["CONFIG_TEST_MARKER"] == "alternate-file-was-loaded"
                assert service["environment"]["DATABASE_URL"].endswith("/config_test")
            else:
                assert "CONFIG_TEST_MARKER" not in service.get("environment", {})
    if "nginx" in services:
        assert services["nginx"]["environment"]["NGINX_ENVSUBST_FILTER"] == r"^API_SERVER_NAME\b"


@pytest.mark.skipif(not shutil.which("docker"), reason="Docker CLI unavailable")
def test_missing_required_database_identity_fails(deployment):
    deployment.write_text(deployment.read_text().replace("POSTGRES_USER=config_test\n", ""))
    result = invoke(deployment, "compose", "--", "-f", str(COMPOSE / "docker-compose.full.yml"), "config", "--quiet")
    assert result.returncode != 0
    assert "POSTGRES_USER" in result.stderr


def test_host_nginx_preserves_runtime_variables(deployment):
    result = invoke(deployment, "render-nginx")
    assert result.returncode == 0, result.stderr
    assert "server_name api.example.invalid;" in result.stdout
    assert "${API_SERVER_NAME}" not in result.stdout
    for variable in ("$host", "$remote_addr", "$scheme", "$server_port"):
        assert variable in result.stdout
    assert "isolated-config-test-only" not in result.stdout


def test_invalid_hostname_rejected(deployment):
    deployment.write_text("API_SERVER_NAME=https://api.example.invalid\n")
    result = invoke(deployment, "render-nginx")
    assert result.returncode == 2
    assert result.stdout == ""


def test_missing_file_fails_without_values(tmp_path):
    result = invoke(tmp_path / "missing.env", "render-nginx")
    assert result.returncode == 2
    assert "Deployment environment file is missing" in result.stderr


def test_second_env_file_cannot_desynchronize_compose(deployment):
    result = invoke(deployment, "compose", "--", "--env-file=other.env", "config", "--quiet")
    assert result.returncode == 2
    assert "Select --env-file before" in result.stderr
