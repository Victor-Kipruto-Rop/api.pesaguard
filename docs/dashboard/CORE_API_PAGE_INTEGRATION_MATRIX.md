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
| Reconciliation history/results | `GET /reconciliation/{transaction_id}` | Existing published route; transaction-level result, not a run collection. |
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

## Current gaps before full coverage

The current route audit does not prove the existence of complete CRUD/read APIs for reconciliation-run collections, matching-rule management, customer directory/profile records, persisted data-quality findings, scheduled reconciliation, settlements, risk investigations, report generation/export jobs, notification preferences, privacy requests, and support cases. These need dedicated schemas, tenant-scoped persistence, RBAC, audit events, OpenAPI contracts, migrations where needed, and tests before UI wiring can be called complete.

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
