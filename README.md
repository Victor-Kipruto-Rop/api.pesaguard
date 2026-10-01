# PesaGuard

Real-time M-Pesa reconciliation and anomaly detection for SACCOs, e-commerce operators, and small fintechs.

## Current status

The repository contains the production application, migrations, Docker deployment, readiness checks, backup tooling, and CI/CD workflows. It must still pass the staging deployment gate before live payment traffic is enabled.

## Technology stack

- Python 3.12
- Flask API mounted behind a FastAPI control plane
- PostgreSQL 15+
- Redis 7+
- Redpanda/Kafka-compatible event streaming
- RQ background workers
- Docker and GitHub Actions
- Safaricom Daraja integrations

## Local verification

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r pesaguard_backend_pipeline/requirements-dev.txt
cp .env.example .env

export PYTHONPATH=.
pytest -v --tb=short --durations=10
python -m compileall -q pesaguard_backend_pipeline
```

## Local services

Use Docker Compose after setting real local values in `.env`:

```bash
python infra/configure.py compose -- -f infra/docker/docker-compose.yml config --quiet
python infra/configure.py compose -- -f infra/docker/docker-compose.yml up -d --build
```

The API exposes liveness at `/livez` and dependency readiness at `/health`. In production, PostgreSQL, Redis, Kafka/Redpanda, and configured Daraja credentials are required for a ready instance.

## Production release gates

A release must satisfy all of the following:

1. Full CI passes, including migrations and tests.
2. The production image builds and passes the vulnerability scan.
3. Staging deploys using the immutable image digest.
4. Staging `/health` reports `status: ok`.
5. Database backup and restore validation succeeds.
6. Production deployment is approved through the protected `production` environment.
7. Production `/health` reports `status: ok` after deployment.

Do not commit `.env` or production credentials. Generate secrets outside Git and provide them through the deployment environment.

## Documentation

Operational, security, database, testing, and recovery procedures are under `docs/` and `infra/README.md`.
