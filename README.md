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

Use Docker Compose after setting real local values in .env:

```bash
python infra/configure.py compose -- -f infra/docker/docker-compose.yml config --quiet
python infra/configure.py compose -- -f infra/docker/docker-compose.yml up -d --build
```

The API exposes liveness at /livez and dependency readiness at /health. In production, PostgreSQL, Redis, Kafka/Redpanda, and configured Daraja credentials are required for a ready instance.

## Production release gates

A release must satisfy all of the following:

1. Full CI passes, including migrations and tests.
2. The production image builds and passes the vulnerability scan.
3. Staging deploys using the immutable image digest.
4. Staging /health reports status: ok.
5. Database backup and restore validation succeeds.
6. Production deployment is approved through the protected production environment.
7. Production /health reports status: ok after deployment.

Do not commit .env or production credentials. Generate secrets outside Git and provide them through the deployment environment.

## Documentation

Operational, security, database, testing, and recovery procedures are under docs/ and infra/README.md.

## Public status service and email subscriptions

The status website uses these public API routes:

- GET /public/status publishes API/dependency health and HTTP reachability for the public website, dashboard, docs, and status site.
- POST /public/status/subscriptions starts a double-opt-in subscription.
- POST /public/status/subscriptions/confirm confirms the email address.
- POST /public/status/subscriptions/unsubscribe removes a subscription using its signed link.
- POST /public/status/monitor sends change notifications to confirmed subscribers. The scheduled GitHub Actions workflow calls this endpoint with a bearer token.

### Production prerequisites

1. Before merging the backend change, configure the production runtime: SMTP_HOST, SMTP_PORT, SMTP_FROM_EMAIL, TLS (SMTP_USE_TLS or SMTP_USE_SSL), and both SMTP_USERNAME/SMTP_PASSWORD when the provider requires authentication. The mail transport requires TLS.
2. Keep the existing production JWT_SECRET_KEY configured; it signs unsubscribe links. Do not rotate it solely for this feature.
3. Set PESAGUARD_STATUS_MONITOR_TOKEN to a newly generated random value of at least 32 characters in the backend runtime and set the same value as the GitHub Actions repository secret. Never commit the token or expose it in logs.
4. Set PESAGUARD_CORS_ALLOWED_ORIGINS to allow both https://api.pesaguard.co.ke and https://status.pesaguard.co.ke. An explicit value replaces defaults, so retain any other origins required by clients.
5. Back up the database, then run migrations from the backend checkout root with production DATABASE_URL configured, before deploying the code:

   ```powershell
   python -m alembic upgrade head
   ```

   This creates public_status_subscriptions as well as any other pending schema changes. The release workflow validates migrations against CI but does not apply them to production.
6. Confirm the protected production GitHub environment has RENDER_PRODUCTION_DEPLOY_HOOK and PRODUCTION_HEALTH_URL configured. Merge the reviewed change to main only after these prerequisites are ready; the release workflow builds and deploys on main.
7. The .github/workflows/public-status-monitor.yml workflow runs on the default branch every five minutes and can also be manually dispatched.

### Production smoke checks

After deployment, verify:

1. GET https://api.pesaguard.co.ke/public/status returns a valid verified payload and the expected service IDs. HTTP 503 can carry a real degraded/outage payload; inspect the payload as well as the HTTP code.
2. A browser request from the status-site origin passes CORS preflight for the status GET and subscription POST.
3. A controlled test address receives the opt-in email, confirms successfully, and can unsubscribe. Avoid using real subscribers for the test.
4. A manual monitor workflow run succeeds. Its first run establishes a status baseline; it does not send a change notification.
5. Remove the test subscription and test data and review sanitized logs.

Email notifications are poll-based: a change can take up to five minutes to trigger a message, and an incident that begins and recovers between polls may not be observed. Production delivery is unverified until these checks pass against the deployed service.

## Conflicting provider replay protection

The event store compares canonical transaction facts for an already-seen tenant/provider/account-scoped transaction ID. A semantically identical retry returns DUPLICATE; a reused transaction identity with changed or unverifiable facts returns CONFLICT and persists a deduplicated transaction event plus audit event marked QUARANTINED. The M-Pesa webhook acknowledges a quarantined conflict to avoid retry storms; authenticated API ingestion returns HTTP 409. The conflicting payload is not inserted as a second financial transaction. This guard is still subject to full CI and staging concurrency/tenant-isolation verification.

## Smart reconciliation algorithms

The additive, deterministic algorithm primitives and their safety/rollout contract are documented in docs/algorithms/SMART_RECONCILIATION_ALGORITHMS.md. They provide tenant-scoped duplicate fingerprints, explainable candidate ranking, ambiguity detection, robust amount outlier detection, rule-based risk triage, rolling-window velocity checks, and transaction-quality findings. They are not yet the authoritative production decision path; run shadow evaluation against approved ground truth before enabling decision-path changes.

## Reconciliation algorithm evaluation

The ground-truth evaluation helper reports automatic-match precision, recall, F1, false-positive rate, exact-decision accuracy, automatic-match coverage, review rate, and unmatched rate against reviewed labels. See docs/algorithms/RECONCILIATION_GROUND_TRUTH_EVALUATION.md. These metrics are a validation tool, not production certification; no policy is enabled by adding the evaluator.

The current implementation inventory and remaining production-integration gates are tracked in docs/algorithms/ALGORITHM_COVERAGE_AND_PRODUCTION_GAPS.md. It distinguishes existing helper functions from durable, tenant-safe production integration and calibration work.

### Reconciliation scope safety

The live reconciliation matcher has a fail-closed second-line guard for explicit tenant, provider, provider-account, and currency conflicts in candidate records. A conflict returns needs_review with a critical scope-conflict signal instead of auto-matching. This does not replace tenant-scoped database queries, database constraints, or authorization checks; missing scope metadata is not treated as proof of a conflict. Regression tests are in pesaguard_backend_pipeline/tests/test_reconciliation_scope_guard.py. This change is not a production-readiness certification: run the full suite and staging isolation tests before release.

## Live reconciliation quality gate

`ReconciliationEngine.reconcile` now applies the normalized transaction-quality algorithm before candidate selection. Missing/ambiguous timestamps and non-positive amounts fail closed as `EXCEPTION`, with structured quality findings in reconciliation evidence. This prevents these malformed records from being treated as ordinary matching candidates. The gate is covered by `pesaguard_backend_pipeline/tests/test_reconciliation_quality_gate.py`; alternate ingestion/legacy paths, persistence of findings, full CI, and staging behavior still require verification.

## Reversal lifecycle validation

The additive transaction lifecycle algorithm checks reversal/original linkage, tenant/provider/account/currency conflicts, timestamp ordering, duplicate reversal IDs, and cumulative confirmed reversal amounts. It is advisory-only and always returns `can_auto_post=false`; it is not connected to the authoritative posting path. See docs/algorithms/TRANSACTION_LIFECYCLE_ALGORITHMS.md. Live integration still requires transaction-scoped database locking, provider-confirmed states, idempotency, audit persistence, and concurrency tests.

## Advanced analytics primitives

The new advanced_reconciliation_algorithms.py module provides seasonal amount assessment and distribution-shift detection. These are advisory-only helpers, not enabled in the live matching/risk decision path. See docs/algorithms/ADVANCED_RECONCILIATION_ALGORITHMS.md for scope, safety boundaries, and test commands. Production activation requires tenant-scoped history, finance-reviewed holdout evaluation, false-positive analysis, monitoring, and an approved rollout.

## Cohort-level reconciliation evaluation

The offline `reconciliation_cohort_evaluation.py` helper evaluates match quality
separately by tenant, provider, currency, and transaction-size band. It prevents
overall metrics from hiding weak performance in a cohort and marks undersized
cohorts as insufficient rather than reporting misleading zero metrics. It is an
evaluation utility only; it does not tune or change live decisions. See
`docs/algorithms/COHORT_RECONCILIATION_EVALUATION.md` and
`pesaguard_backend_pipeline/tests/test_reconciliation_cohort_evaluation.py`.
