# Tenant Dashboard Core API Integration Matrix

This matrix is the source of truth for wiring `app.pesaguard.co.ke` to `api.pesaguard.co.ke`. A sidebar route is not considered integrated merely because a React page exists.

## Rules

- Authenticated tenant pages must use a bearer token from the current in-memory session.
- Never fall back to fixture/sample data when a live request fails or an endpoint is not implemented.
- Read endpoints are read-only. Mutations require a documented Core API route, explicit permission, server-side tenant enforcement, idempotency where appropriate, and audit logging.
- A page is `connected` only after endpoint contract tests and staging verification pass. A route found in the legacy route audit is a candidate endpoint, not proof of production readiness.
- The Core API currently has multiple legacy route families. Do not infer route availability from the limited published `docs/api/openapi.json` alone; reconcile the OpenAPI document with the mounted Flask routes before release.
- PesaGuard currently supports M-Pesa/Daraja ingestion and reconciliation against an internal ledger. Do not expose settlement execution, payment origination, refunds, or non-M-Pesa provider integrations as supported capabilities unless the backend contract explicitly implements them.

## Verified route candidates from `routes_audit.txt`

| Dashboard capability | Candidate route | Notes |
|---|---|---|
| Transactions | `GET /api/v1/transactions/search` | Tenant-scoped pagination, text search, sorting and validated comma-separated lifecycle-state filtering; tests cover status filters and tenant isolation. |
| Tenant dashboard overview | `GET /api/v1/dashboard/overview` | Newly implemented tenant-scoped persisted transaction/discrepancy KPIs; tests verify cross-tenant records are excluded. |
| Import history | `GET /api/v1/imports` | Newly implemented tenant-scoped paginated import-job listing with validated status filtering; regression test seeds two tenants. |
| Transaction detail | `GET /transactions/{transaction_id}` | Tenant-scoped transaction route; validate mounted prefix and identifier semantics. |
| Transaction status | `GET /transactions/{transaction_id}/status` | Tenant-scoped status route. |
| Reconciliation history/results | `GET /reconciliation/{transaction_id}` and `GET /api/v1/reconciliation/results` | Transaction-level history plus a tenant-scoped paginated collection of reconciliation outcomes. The collection supports validated status filters and exact transaction ID filtering. |
| Risk assessment | `GET /fraud/{transaction_id}` | Existing published route; transaction-level risk assessment only. |
| Reconciliation discrepancies/exceptions | `GET /discrepancies` | Existing route; verify filters, pagination, and tenant enforcement. |
| Operational activity | `GET /activity-feed` | Existing route; verify response shape and tenant filtering. |
| Reconciliation analytics | `GET /analytics/reconciliation-report` | Existing route; validate definitions and permissions. |
| Other analytics | `GET /analytics/incident-trends`, `/analytics/operator-stats`, `/analytics/resolution-times`, `/analytics/sla-metrics` | Do not reuse for unrelated business metrics. |
| Import history | `GET /api/v1/imports` | Newly implemented tenant-scoped, paginated import history with lifecycle status filtering; does not expose object storage keys or raw error payloads. |
| Import jobs | `POST /api/v1/imports`, `GET /api/v1/imports/{import_id}` | Verify upload format, async job contract and status lifecycle. |
| Data catalog | `GET /api/v1/catalog/datasets`, `GET /api/v1/catalog/datasets/{dataset_name}` | Dataset catalog is not a data-quality result API. |
| Transaction lineage | `GET /api/v1/lineage/transactions/{transaction_id}` | Requires a real transaction identifier. |
| Provider connections | `GET /providers`, `GET /providers/{provider_id}`, `POST /providers/{provider_id}/health` | Verify tenant scoping and ensure only supported providers are offered. |
| Webhooks | `GET /webhooks`, `POST /webhooks`, `PUT /webhooks/{webhook_id}`, `GET /webhooks/{webhook_id}/deliveries` | Do not reveal signing secrets. |
| Tenant settings | `GET /tenant/current`, `GET /v1/settings`, `POST /tenants/{tenant_id}/settings` | Validate settings ownership and supported schema. |
| Organization | `GET /api/v1/organizations`, `GET /api/v1/organizations/{organization_id}` | Organization IDs must be resolved from authenticated tenant membership. |
| Team / identity | `GET /auth/users`, `GET /api/v1/iam/external-identities`, `GET /api/v1/iam/service-identities` | Apply least-privilege permissions; do not expose secrets. |
| API clients | `GET /api/v1/iam/api-clients` | Secret rotation must be an explicit, audited mutation. |
| Communication events | `GET /api/v1/communications/messages`, `GET /api/v1/communications/incidents`, `GET /api/v1/communications/webhook-events` | These are communication resources, not automatically equivalent to PesaGuard financial alerts. |
| Public service status | `GET /public/status` | Public health status only; not tenant business data. |

## Sidebar coverage requirements

Every sidebar page must be assigned exactly one state:

1. **Connected** — calls a verified route and renders only server-returned data.
2. **Read-only connected** — reads server data but deliberately disables unsupported mutations.
3. **Unavailable** — no suitable Core API route exists yet; show an explicit message and never show synthetic records.
4. **Verification required** — a route exists, but response contract, tenant isolation, permissions, or staging behavior has not been verified.

Do not label a page production-ready solely because it has an endpoint mapping.

## Dedicated tenant workflow APIs

The Core API now mounts a shared tenant-scoped workflow API for the following persisted workflow resources. All routes require authentication and a tenant context, filter reads and updates by both tenant and domain, validate status transitions, and use optimistic version checks on updates.

| Capability | Collection endpoint | Detail / mutation | Contract boundary |
|---|---|---|---|
| Reconciliation runs | `/api/v1/reconciliation-runs` | GET/PATCH `/{record_id}` | Persists run requests; a worker must execute actual reconciliation. |
| Matching rules | `/api/v1/matching-rules` | GET/PATCH/DELETE `/{record_id}` | DELETE is a soft-disable. The authoritative matcher does not automatically consume these definitions yet. |
| Data-quality findings | `/api/v1/data-quality-findings` | GET/PATCH `/{record_id}` | Persisted review findings; ingestion/profiling producers must create findings. |
| Scheduled reconciliation | `/api/v1/reconciliation-schedules` | GET/PATCH `/{record_id}` | Validates cadence and stores schedule metadata; a scheduler/worker is required for execution. |
| Settlement reviews | `/api/v1/settlement-reviews` | GET/PATCH `/{record_id}` | Review records only; no settlement initiation, confirmation, or movement of funds. |
| Refund/reversal review | `/api/v1/refund-reversal-requests` | GET/PATCH `/{record_id}` | Review requests only; no provider refund/reversal command or ledger posting. |
| Report definitions | `/api/v1/report-definitions` | GET/PATCH `/{record_id}` | Supports transactions, discrepancies, and reconciliation summaries; scheduling metadata requires a worker for recurring delivery. |
| Report runs | `/api/v1/report-runs` | POST and GET/PATCH `/{record_id}` | Generates bounded persisted-data JSON summaries synchronously; not asynchronous job execution or CSV/PDF artifact generation. |
| Fraud investigations | `/api/v1/fraud-investigations` | GET/PATCH `/{record_id}`; POST `/{record_id}/evidence` | Append-only evidence metadata; sensitive payment payloads and credentials are rejected. |
| Privacy requests | `/api/v1/privacy-requests` | GET/PATCH `/{record_id}` | Registers access/export/correction/deletion requests; does not execute data deletion or claim an export exists. |
| Support cases | `/api/v1/support-cases` | GET/PATCH `/{record_id}` | Persisted case tracking; customer support delivery/notifications are separate integrations. |

Collection GET responses use `items`, `page`, `per_page`, and `total`. Supported filters are `status` and title search `q`. Creation uses a JSON object with `title`, optional `description`, and a validated domain-specific `payload`. Status changes are constrained by a domain transition map. Settlement/refund/privacy review transitions have an additional privileged-role gate.

Mutation audit records and their outbox messages are being added in API PR #97 so the audit row is committed atomically with each workflow mutation. Do not treat that audit enhancement as merged until its checks pass.

## Remaining gaps before full operational coverage

The persisted workflow APIs close the initial CRUD/API gap, but they do not by themselves deliver the end-to-end business workflows. Remaining work includes:

- A durable reconciliation worker that consumes run requests and writes reconciliation outcomes using the established tenant-scoped matching pipeline.
- A scheduler/worker that triggers enabled reconciliation schedules and recurring report definitions with lease/duplicate-run protection.
- Integration of matching-rule definitions with the authoritative reconciliation engine, versioned rule snapshots per run, and dry-run/rollback controls.
- Producers that create persisted data-quality findings from import validation, profiling, schema drift, and freshness checks.
- An approved, idempotent artifact pipeline for report exports and delivery; current report runs return bounded JSON summaries only.
- A separate privileged, auditable execution workflow for approved privacy export/deletion requests.
- Support notification/delivery integration and service-level monitoring.
- Production schema migration, permissions/role review, full CI, PostgreSQL tenant-isolation/concurrency testing, and staging smoke tests.

The workflow API deliberately does not claim that scheduled jobs ran, report files exist, data was deleted, fraud was proven, or funds moved.

## Release gate

- Generate and review a machine-readable page-to-route inventory for every `DashboardPage`.
- Every mapped route has a contract test and tenant-isolation test.
- Every mutation has permission, validation, idempotency where needed, and audit coverage.
- CI typecheck/build/API tests pass.
- Staging smoke tests verify loading, empty, permission-denied, timeout, and server-error states.
- No authenticated page uses preview fixtures as a fallback.


## Dashboard overview contract

`GET /api/v1/dashboard/overview` requires `read:analytics` and a verified authenticated tenant context. The endpoint aggregates persisted `transactions` and `discrepancies` using the current tenant ID, reports lifecycle counts, recorded transaction amount, open/resolved discrepancy counts, recent 30-day activity, and a generation timestamp. It deliberately does not infer match rates, fraud probabilities, revenue, settlement state, or other metrics not directly supported by persisted source records.

The route test `test_dashboard_overview_returns_persisted_metrics_for_current_tenant_only` seeds records for two tenants and asserts that only the active tenant's data contributes to the response.


## Reconciliation results collection

`GET /api/v1/reconciliation/results` requires `read:transactions` and authenticated tenant context. It supports `page`, `per_page` (1–100), comma-separated `status` values from `MATCHED`, `UNMATCHED`, `PARTIAL`, `MISMATCH`, `DUPLICATE`, `PENDING`, and `EXCEPTION`, plus an optional exact `transaction_id`. Results are filtered by tenant before counting and pagination. Response fields exclude the raw `matched_record` payload and expose only a boolean indicating whether a matched record exists. Regression tests cover tenant isolation, status validation, pagination, and payload minimization.

- Risk assessment collection: `GET /api/v1/fraud/assessments` requires `read:transactions`, filters to the authenticated tenant, validates risk-level filters (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and returns paginated persisted assessment summaries without raw feature payloads.
