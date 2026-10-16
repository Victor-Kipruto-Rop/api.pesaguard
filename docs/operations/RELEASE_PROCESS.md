# Release Process

> Design and operating reference for **Operations / Release Process**.

## Purpose

This document defines the role of **Release Process** within PesaGuard. It provides a durable reference for production ownership, release safety, monitoring, incident response, and recovery, with enough detail for implementation, review, operations, and future change.

## Current position

PesaGuard currently runs a Flask and SQLAlchemy backend with PostgreSQL as the production store, Redis and RQ for asynchronous work, Kafka for event transport, and Alembic for schema migration. M-Pesa/Daraja is the active payment scope. Capabilities described here must be marked as implemented, in progress, or planned rather than implied.

## Design principles

- **Tenant isolation:** every query, mutation, export, cache key, event, audit record, and replay operation carries an authorized tenant and provider-account scope.
- **Durability first:** acknowledge work only after the required durable state or idempotency record is written.
- **Explicit contracts:** validate input, normalize provider data, return stable error shapes, and version public interfaces.
- **Safe failure:** retry transient failures with bounded backoff; dead-letter malformed or exhausted work; never silently discard financial events.
- **Evidence by default:** correlation IDs, structured logs, metrics, append-only audit events, and operator actions must explain what happened.
- **Migration discipline:** use Alembic revisions, backfill safely, and keep compatibility paths deliberate.

## Scope

### Included

- The responsibilities and interfaces implied by this document.
- PostgreSQL persistence and tenant-aware data access.
- Authentication, authorization, validation, observability, and recovery controls.
- Focused tests for normal paths, boundary conditions, isolation, retries, and failure recovery.

### Excluded

- Unscoped cross-tenant access or undocumented administrative bypasses.
- Production schema creation through `Base.metadata.create_all()`.
- Storing plaintext credentials, API keys, tokens, or provider secrets.
- Expanding payment rails beyond the approved product scope without a separate decision.

## Reference workflow

1. Authenticate the caller or verify the provider signature.
2. Resolve tenant and provider-account identity from trusted context.
3. Validate and normalize the request or event.
4. Enforce idempotency before performing a side effect.
5. Persist the durable record and audit event in a transaction.
6. Publish or enqueue work through the outbox or worker boundary.
7. Reconcile, notify, measure, and expose a traceable result.

## Interfaces and invariants

- Public API routes belong under `/api/v1` unless a documented compatibility alias exists.
- IDs are not globally trusted: detail lookups must include tenant and account predicates.
- A retry must be safe to run more than once.
- A successful response must not claim durable processing when the required persistence step failed.
- Audit entries are append-only and must not contain secret material.

## Security and privacy

Use least privilege, short-lived credentials, hashed API keys, explicit scopes, expiry, revocation, rotation, and last-used metadata. Redact sensitive fields at logging boundaries. Apply retention and archival policies by tenant, legal hold, and residency requirements.

## Operations

Monitor request success and latency, reconciliation health, database pool health, Kafka and outbox lag, retry and dead-letter rates, provider errors, audit delivery, and backup freshness. Every alert should identify an owner, a runbook, a severity, and a recovery target.

## Validation

At minimum, validate syntax and imports, focused unit behavior, cross-tenant isolation, migration compatibility, API contract behavior, and failure/retry paths. For integration changes, run the PostgreSQL, Redis, and Kafka checks when those services are available and record unavailable dependencies explicitly.

## Open work

- Replace this design baseline with implementation-specific diagrams, schemas, examples, and measured SLOs as the capability matures.
- Link the final implementation, migration revision, tests, dashboards, and runbook from this document.
- Review this document whenever the public contract, ownership boundary, or recovery behavior changes.

## Implemented CI/CD pipeline

`.github/workflows/release.yml` is the release path for `staging` and `main`:

1. Verify Python compilation and fatal/undefined-name lint, apply Alembic migrations to a disposable PostgreSQL service, and run the test suite.
2. Build and publish the backend image to GHCR with both the commit tag and immutable digest.
3. Scan the published digest with Trivy.
4. Pushes to `staging` and `main` deploy the immutable image digest to staging. The Render deploy hook receives the digest in the URL-encoded `imgURL` parameter. The workflow requires `status: "ok"` and the source commit in the health response's `release` field.
5. Production promotion runs only from a manual `workflow_dispatch` on `main` with `promote_production=true`, after staging succeeds. Configure required reviewers on the GitHub `production` environment. Production receives the same scanned digest and must report healthy status and the expected commit revision.

Configure these secrets in the GitHub environments:

- `staging`: `STAGING_DATABASE_URL`, `STAGING_JWT_SECRET_KEY`,
  `PROVIDER_ENCRYPTION_KEY`, `PESAGUARD_PAYLOAD_ENCRYPTION_KEY`,
  `RENDER_STAGING_DEPLOY_HOOK`, `STAGING_HEALTH_URL`
- `production`: `RENDER_PRODUCTION_DEPLOY_HOOK`, `PRODUCTION_HEALTH_URL`

The staging release job checks that these secrets exist, applies the reviewed
Alembic migrations to `STAGING_DATABASE_URL`, and only then deploys the scanned
image digest. The encryption keys must match the keys configured on the staging
application so data encrypted by a migration remains readable at runtime. Use a
staging-only database identity with migration privileges and a verified,
recoverable staging backup before applying migrations. Keep the database URL
reachable from GitHub-hosted runners, or use a controlled runner with access to
the staging database network. Configure required reviewers on the GitHub
`staging` environment; reviewers should confirm the backup and target database
before approving a release that may apply migrations.

The deployment target must consume the digest sent as `imgURL`. A hook that ignores it is not an immutable promotion and must be corrected before production use. Configure required reviewers on the GitHub `production` environment; naming an environment alone does not enforce approval. A health failure blocks workflow completion but does not automatically roll back the platform deployment; follow [ROLLBACK.md](ROLLBACK.md). This workflow does not authorize deployment or enable live payments by itself.
