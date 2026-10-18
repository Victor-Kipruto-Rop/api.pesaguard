# PesaGuard Deployment Architecture

## Runtime packaging

The repository includes Docker assets under `docker/` and infrastructure templates under `infra/`. The Python backend dependencies are pinned in `pesaguard_backend_pipeline/requirements.txt`, which the Docker images, the release workflow and CI all install. Test tooling lives in `requirements-dev.txt` and is not shipped in the images.

## Local development

Use the workspace virtual environment or install dependencies from the project requirements file before running the Flask routes or testing the pipeline.

## Container model

The production Compose stack includes a dedicated `workflow_scheduler` process. It requires the same migrated PostgreSQL database as the dashboard API and can be tuned with `PESAGUARD_WORKFLOW_SCHEDULER_INTERVAL_SECONDS` (minimum 5 seconds) and `PESAGUARD_WORKFLOW_SCHEDULER_BATCH` (maximum 500 records per cycle). Deploy it only after the tenant-workflow migration is applied, and monitor its container logs and scheduled-run backlog.

The scheduler atomically dispatches due reconciliation schedules, processes queued runs through the existing tenant-scoped reconciliation consumer in bounded batches, and creates scheduled persisted-data report summaries. A queued reconciliation run is **not** a completed reconciliation: it completes only after the pending scope is exhausted, and it fails visibly when the required ledger connector or source records are unavailable. Report summaries are JSON workflow records, not downloadable CSV/PDF artifacts. The scheduler does not execute settlements, refunds, reversals, or privacy deletion requests.

The repository ships:

- `docker/Dockerfile`
- `docker/Dockerfile.worker`
- `docker/docker-compose.yml`
- `docker/docker-compose.full.yml`

These files map mostly to the infrastructure and deployment model already observed in the repository. The code does not require a full rewrite of the current runtime packaging.

## Environment variables

Production and local runtime settings are driven through environment variables documented in `.env.example` and loaded by modules using `os.getenv(...)` patterns.

## Deployment posture

The project supports staged deployment flows and health checks through `health.py` and route conventions. Operationally, Sentry and Sourcery should remain environment-driven and optional rather than embedded in the code as runtime requirements.

## Release gates

Every staging or production release must follow this order:

1. Run the full CI test and compile gates.
2. Build the immutable container image and scan it for vulnerabilities.
3. Apply the reviewed Alembic migrations using a deployment identity before serving traffic.
4. Deploy the image and wait for `/health` to return JSON with `status: "ok"`.
5. Run authenticated smoke checks for webhook acceptance, tenant-scoped reads, outbox delivery, and metrics.
6. Monitor error rate, latency, database pool usage, consumer lag, retry rate, and dead-letter rate for the release window.
7. Promote only after the health and smoke checks pass.

The staging workflow requires `RENDER_STAGING_DEPLOY_HOOK` and
`STAGING_HEALTH_URL`. A deploy webhook response alone is not evidence that the
revision is healthy.

The staging release job applies Alembic migrations before deploying the image.
Configure the `staging` GitHub environment with `STAGING_DATABASE_URL`,
`STAGING_JWT_SECRET_KEY`, `PROVIDER_ENCRYPTION_KEY`,
`PESAGUARD_PAYLOAD_ENCRYPTION_KEY`, `RENDER_STAGING_DEPLOY_HOOK`, and
`STAGING_HEALTH_URL`. The database URL must be reachable from the workflow
runner. The encryption keys must be the same values configured for the staging
application, and a verified recoverable staging backup must exist before
migrations are applied. Configure required reviewers on the GitHub `staging`
environment so each deployment can be held while the target and backup are
reviewed.

The unified release workflow also publishes `ghcr.io/<owner>/<repository>@<digest>`. Staging deploys from the `staging` branch after verification. Production deploys from `main` behind the protected GitHub `production` environment, or through an explicitly approved manual dispatch. Configure deployment hooks to consume the digest supplied in the request payload rather than a mutable branch tag.

## Migration safety

Migrations must be backward-compatible with the currently running image during rolling deployment. Take or verify a database backup before destructive changes, separate expand/backfill/contract work, and never use application startup `create_all()` as a production migration mechanism.

## Rollback trigger

Rollback when health checks fail, error or latency SLOs regress, tenant isolation alarms fire, or transaction/outbox/DLQ counts move unexpectedly. Preserve the release SHA, health response, migration revision, metrics snapshot, and incident correlation ID before restoring the previous image.
