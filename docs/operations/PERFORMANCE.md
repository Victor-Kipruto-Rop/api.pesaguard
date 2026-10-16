# Performance

> Design and operating reference for **Operations / Performance**.

## Purpose

This document defines the role of **Performance** within PesaGuard. It provides a durable reference for production ownership, release safety, monitoring, incident response, and recovery, with enough detail for implementation, review, operations, and future change.

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

## Load, stress, spike, and soak validation

`pesaguard_backend_pipeline/operations/run_endpoint_load_test.py` drives bounded
HTTP traffic from a JSON payload template and records a JSON report without
including request bodies or header values. It supports `load`, `stress`, `spike`,
and duration-based `soak` profiles. The runner requires explicit test-tenant
confirmation, rejects remote HTTP targets, caps concurrency, request counts,
timeouts, stress stages, and duration, and supports per-request HMAC signatures.
Remote staging targets require HTTPS and the explicit `--allow-nonlocal-target`
flag. Use only a dedicated non-production tenant and provider sandbox; never run
against real customer or payment traffic.

Example against a local test endpoint:

```powershell
python -m pesaguard_backend_pipeline.operations.run_endpoint_load_test `
  --target-url http://127.0.0.1:5000/test/load `
  --payload-template .\docs\operations\load-test-payload.example.json `
  --profile stress --requests-per-stage 100 --concurrency 20 --stress-steps 4 `
  --max-error-rate 0.01 --max-throttle-rate 0.05 --max-p95-ms 500 `
  --min-requests-per-second 10 --confirm-test-tenant `
  --json-path .\artifacts\load-test.json
```

Create the test endpoint only in an isolated environment. For HTTPS staging, add
`--allow-nonlocal-target` only after the service owner approves the tenant and
capacity. Supply sensitive headers through `PESAGUARD_LOAD_TEST_HEADERS_JSON`
and a signature key through an environment variable named by
`--hmac-secret-env`. Never pass secrets as command arguments or include personal
data in the template.

An acceptance report requires all four thresholds: maximum server/transport
error rate, maximum throttle rate, maximum p95 latency, and minimum throughput.
Set thresholds from approved service objectives before a run; the example values
above are illustrative and are not product SLOs. Preserve the report, revision,
test window, tenant, and staging resource profile with release evidence. A
diagnostic run without all thresholds is not an acceptance result.
