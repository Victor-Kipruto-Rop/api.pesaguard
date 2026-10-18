# End-to-end production integration verification

This is a release verification procedure, not a substitute for CI or staging
acceptance. A service returning HTTP 200 from its root URL does not prove that
database writes, queue execution, callback ingestion, reconciliation, or trace
export are working.

## 1. Run the read-only API smoke check

You can run this manually from GitHub Actions using **Production read-only integration smoke** (`.github/workflows/production-smoke.yml`). It performs GET-only checks and does not deploy or modify application data. Optional repository variables are `PESAGUARD_SMOKE_BASE_URL`, `PESAGUARD_AUTHENTICATED_READ_PATH`, and `PESAGUARD_REQUIRE_OTEL`; optional secrets are `PESAGUARD_SMOKE_BEARER_TOKEN`, `SENTRY_DSN`, and `OTEL_EXPORTER_OTLP_ENDPOINT`. Only use a short-lived, least-privilege read-only token.

From the repository root:

```bash
export PESAGUARD_BASE_URL=https://api.pesaguard.co.ke
python pesaguard_backend_pipeline/operations/production_integration_smoke.py
```

The check calls `/livez`, `/health`, and `/public/status`. It does not create
transactions, send provider callbacks, modify tenant records, or trigger refunds.
A degraded readiness/status payload fails the check even if the endpoint returns
HTTP 200. Use `PESAGUARD_LIVEZ_PATH`, `PESAGUARD_HEALTH_PATH`, or
`PESAGUARD_PUBLIC_STATUS_PATH` only if the deployed API intentionally mounts
these contracts at different paths.

For a protected read-only route, configure a short-lived, least-privilege token
and a known read-only path:

```bash
export PESAGUARD_SMOKE_BEARER_TOKEN='<short-lived read-only token>'
export PESAGUARD_AUTHENTICATED_READ_PATH='/api/v1/dashboard/overview'
python pesaguard_backend_pipeline/operations/production_integration_smoke.py
```

Never use a token with transaction-write, tenant-administration, refund, or
payment-operation permissions. The script never prints the token or Sentry DSN.

To require that a remote OpenTelemetry endpoint is configured:

```bash
export PESAGUARD_REQUIRE_OTEL=true
export OTEL_EXPORTER_OTLP_ENDPOINT='<provider endpoint>'
python pesaguard_backend_pipeline/operations/production_integration_smoke.py
```

This only validates configuration syntax. It does not claim that spans arrived
at the collector. Confirm delivery by generating a request and finding the
corresponding trace in the configured tracing backend.

## 2. Verify service dependencies in staging

- Confirm PostgreSQL is reachable and the deployed migration revision matches
  the repository head. Never run destructive migration experiments in production.
- Confirm Redis connectivity and worker queue health.
- If Kafka/Redpanda is enabled for the deployment, confirm broker metadata,
  produce/consume a disposable test event, and verify consumer lag is observable.
- Confirm background workers are running independently from the web process.
- Confirm backup creation and a restore into an isolated database both succeed.
- Verify readiness fails safely when a required dependency is unavailable.

## 3. Verify M-Pesa ingestion without real-money operations

Use Safaricom's sandbox and synthetic transactions only:

- Submit a valid, documented test callback and confirm durable receipt.
- Replay the same callback and confirm it is idempotent.
- Reuse the same scoped transaction identity with changed financial facts and
  confirm the event is quarantined/audited rather than inserted as a second
  transaction.
- Submit malformed and unauthenticated callbacks and confirm they are rejected
  or quarantined according to the documented contract.
- Confirm retries and dead-letter handling are observable and bounded.
- Verify every test transaction remains tenant/provider/account scoped.
- Run reconciliation and compare the persisted result with known ground truth.

Do not point this procedure at a live payment command, refund, reversal posting,
or settlement execution endpoint. Those capabilities require separately approved
contracts and safeguards.

## 4. Verify tenant workflow producers and consumers

For each workflow API, test both persistence and the worker that performs the
actual business operation. A stored workflow record is not evidence that the
work was executed.

- Reconciliation runs: create a sandbox run, observe worker pickup, and compare
  persisted results to known transaction fixtures.
- Matching rules: create/update a rule and prove the authoritative matcher uses
  its validated version; until this is proven, label rules as configuration
  records only.
- Data-quality findings: feed invalid synthetic records and verify findings are
  persisted with tenant scope, evidence, severity, and review status.
- Scheduled reconciliation: verify due schedules are claimed once, dispatched,
  retried safely, and not duplicated across concurrent scheduler instances.
- Report runs: verify bounded generation, durable status, artifact access control,
  expiry, and cleanup; do not expose internal storage paths.
- Fraud investigations: verify append-only evidence metadata and tenant-scoped
  access; do not store raw credentials or unnecessary payment payloads.
- Privacy requests: verify request tracking and authorization separately from
  actual export/deletion execution. Do not mark a request completed until the
  underlying operation and audit record succeed.
- Support cases: verify tenant scoping, assignment, state transitions, and
  attachment authorization.

## 5. Observability and error reporting

- Correct or remove a malformed `SENTRY_DSN` in the deployment environment.
  Sentry is optional; leaving it unset should disable Sentry without breaking API
  processing. A configured malformed DSN should be treated as a configuration
  failure, not as evidence that Sentry is working.
- Confirm the OTLP endpoint, protocol, TLS, authentication headers, and network
  egress match the provider's requirements.
- Generate a request and locate its trace by service name, release, and time.
- Verify HTTP, database, Redis, and downstream spans are present where expected.
- Verify trace context crosses the API/worker boundary.
- Confirm exporter errors are visible and bounded, and API processing remains
  available during a collector outage.
- Confirm logs and traces exclude tokens, secrets, raw callback bodies, and
  unnecessary personal or financial data.

## 6. Release decision

Do not call the release production-ready unless all are true:

1. Required CI and integration jobs pass on the exact candidate commit.
2. Staging deploys and its readiness check passes.
3. Migration upgrade and rollback/recovery procedures are rehearsed safely.
4. Database backup and isolated restore drill pass.
5. Sandbox callback, duplicate replay, conflict quarantine, and reconciliation
   acceptance tests pass.
6. Tenant-isolation and authorization tests pass for all changed endpoints.
7. A real trace is visible in the configured backend.
8. The deployment configuration warnings are resolved or explicitly documented
   as disabled optional integrations.
9. A post-deployment smoke test passes against the deployed revision.

The GitHub Actions runs and staging environment must be checked for the candidate
commit. Do not infer success from an image build or an HTTP 200 response alone.
