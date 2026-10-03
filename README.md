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

## Public status service and email subscriptions

The status website uses these public API routes:

- `GET /public/status` publishes API/dependency health and HTTP reachability
  for the public website, dashboard, docs, and status site.
- `POST /public/status/subscriptions` starts a double-opt-in subscription.
- `POST /public/status/subscriptions/confirm` confirms the email address.
- `POST /public/status/subscriptions/unsubscribe` removes a subscription using
  its signed link.
- `POST /public/status/monitor` sends change notifications to confirmed
  subscribers. The scheduled GitHub Actions workflow calls this endpoint with
  a bearer token.

### Production prerequisites

1. Push the backend change to `main` only after required review. The release
   workflow builds and deploys on `main`; its protected `production` GitHub
   environment requires `RENDER_PRODUCTION_DEPLOY_HOOK` and
   `PRODUCTION_HEALTH_URL`.
2. Back up the database, then run migrations from the backend checkout root
   with production `DATABASE_URL` configured:

   ```powershell
   python -m alembic upgrade head
   ```

   This creates `public_status_subscriptions` as well as any other pending
   schema changes. The release workflow validates migrations against CI but
   does not apply them to production.
3. Configure SMTP in the backend runtime: `SMTP_HOST`, `SMTP_PORT`,
   `SMTP_FROM_EMAIL`, TLS (`SMTP_USE_TLS` or `SMTP_USE_SSL`), and both
   `SMTP_USERNAME`/`SMTP_PASSWORD` when the provider requires authentication.
   The mail transport requires TLS.
4. Keep the existing production `JWT_SECRET_KEY` configured; it signs
   unsubscribe links. Do not rotate it solely for this feature.
5. Set `PESAGUARD_STATUS_MONITOR_TOKEN` to a newly generated random value of
   at least 32 characters in the backend runtime and set the same value as the
   GitHub Actions repository secret. Never commit the token or expose it in
   logs.
6. Set `PESAGUARD_CORS_ALLOWED_ORIGINS` to allow both
   `https://api.pesaguard.victorkipruto.com` and
   `https://status.pesaguard.victorkipruto.com`. An explicit value replaces
   defaults, so retain any other origins required by clients.
7. Ensure `.github/workflows/public-status-monitor.yml` is on the default
   branch and configure the Actions secret before enabling the workflow.
   It polls every five minutes and can also be manually dispatched.

### Production smoke checks

After deployment, verify:

1. `GET https://api.pesaguard.victorkipruto.com/public/status` returns a valid
   `verified` payload and the expected service IDs. HTTP 503 can carry a real
   degraded/outage payload; inspect the payload as well as the HTTP code.
2. A browser request from the status-site origin passes CORS preflight for the
   status GET and subscription POST.
3. A controlled test address receives the opt-in email, confirms successfully,
   and can unsubscribe. Avoid using real subscribers for the test.
4. A manual monitor workflow run succeeds. Its first run establishes a status
   baseline; it does not send a change notification.
5. Remove the test subscription and test data and review sanitized logs.

Email notifications are poll-based: a change can take up to five minutes to
trigger a message, and an incident that begins and recovers between polls may
not be observed. Production delivery is unverified until these checks pass
against the deployed service.
