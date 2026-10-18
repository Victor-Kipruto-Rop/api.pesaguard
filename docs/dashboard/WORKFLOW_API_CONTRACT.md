# Tenant workflow API contract

This contract describes the additive workflow endpoints introduced for the tenant dashboard. Every route is tenant-scoped using the authenticated principal; client-supplied tenant IDs are ignored. Collection responses use `{ items, page, per_page, total }`. Detail responses use `{ item }`. Mutations use JSON and return persisted records; the UI must never substitute fixtures when a request fails.

## Collections

| Capability | Collection | Permissions | Behavior |
|---|---|---|---|
| Reconciliation run requests | `/api/v1/reconciliation-runs` | `read:discrepancies`, `write:discrepancies` | Stores run requests and lifecycle status; does not execute settlement or ledger posting. |
| Matching rule definitions | `/api/v1/matching-rules` | `read:discrepancies`, `write:discrepancies` | Stores versioned configuration; the reconciliation consumer applies exactly one applicable tenant rule and records a rule snapshot. Ambiguous or unavailable rule configuration fails closed. |
| Data-quality findings | `/api/v1/data-quality-findings` | `read:discrepancies`, `write:discrepancies` | Persists findings and triage status; no synthetic quality scores. |
| Reconciliation schedules | `/api/v1/reconciliation-schedules` | `read:discrepancies`, `write:discrepancies` | Persists cadence/timezone/enabled state. The deployed scheduler creates queued runs and processes pending tenant transactions through the existing reconciliation path. Missing ledger connectors and invalid run configuration fail the run instead of fabricating matches. |
| Settlement review records | `/api/v1/settlement-reviews` | `read:discrepancies`, `write:discrepancies` | Review records only; never initiates, confirms, or executes settlements. |
| Refund/reversal review requests | `/api/v1/refund-reversal-requests` | `read:discrepancies`, `write:discrepancies` | Review queue only; provider commands, refunds, reversals and ledger writes are explicitly excluded. Status changes require a privileged reviewer role. |
| Report definitions | `/api/v1/report-definitions` | `read:analytics`, `write:settings` | Stores supported report definitions and schedule metadata. The workflow scheduler executes due definitions as bounded persisted-data JSON summaries; scheduled email delivery and downloadable artifacts are not implemented. |
| Report runs | `/api/v1/report-runs` | `read:analytics`, `write:settings` | Executes a bounded tenant-scoped summary for transactions, discrepancies or reconciliation summary; does not yet create downloadable CSV/PDF artifacts. |
| Fraud investigation cases | `/api/v1/fraud-investigations` | `read:discrepancies`, `write:discrepancies` | Persists investigation state and evidence metadata. It does not block payments or treat a risk flag as proof of fraud. |
| Privacy requests | `/api/v1/privacy-requests` | `read:settings`, `write:settings` | Registers access/export/correction/deletion requests. Deletion/export execution remains a separately authorized workflow; requests cannot be marked completed through the generic update route. |
| Support cases | `/api/v1/support-cases` | `read:settings`, `write:settings` | Persists tenant-scoped support cases and status. |

Each collection supports `GET` and `POST`; each `/<record_id>` route supports tenant-scoped `GET` and `PATCH`. Matching rules additionally support `DELETE`, implemented as an auditable soft-disable (`status=disabled`) rather than physical deletion. List parameters: `page` (minimum 1), `per_page` (1–100), `status` (comma-separated validated statuses), and `q` (title search). Updates accept optional `version`; mismatches return HTTP 409.

Fraud investigation evidence is append-only through `POST /api/v1/fraud-investigations/<record_id>/evidence` with `{ "evidence": { "type": "...", ... } }`. Evidence entries are tenant-scoped, stamped with actor/time, capped at 100 per case, and reject raw payment payloads and credential/phone fields.

## Common record shape

```json
{
  "title": "Review missing ledger reference",
  "description": "Optional reviewer context",
  "payload": { "finding_code": "LEDGER_REF_MISSING" }
}
```

Every record contains server-assigned `id`, `tenant_id`, `domain`, `status`, `created_by`, `updated_by`, `version`, `created_at`, and `updated_at`. The server never trusts a tenant ID from request JSON.

## Production gates and known limitations

- Apply Alembic revision `20261018_tenant_workflows` (`pesaguard_backend_pipeline/alembic/versions/20261018_tenant_workflow_records.py`) through the approved migration runner before deploying this code. The SQL file under `sql/migrations/` is a reference equivalent. Do not use `Base.metadata.create_all()` as a production migration strategy.
- Run the focused workflow tests and the full backend suite; validate tenant-isolation and permission behavior against PostgreSQL in staging.
- The workflow scheduler is deployed in the production Compose stack; it dispatches due schedules and executes queued reconciliation requests in bounded batches through the established tenant-scoped consumer. A report-delivery/artifact pipeline remains required.
- Report-run execution currently produces persisted-data summary JSON, not a downloadable artifact.
- Matching rules are consumed by the reconciliation pipeline when exactly one applicable tenant rule is active. Ambiguous or unavailable rule configuration blocks automatic matching; operator dry-run/rollback and full production evaluation remain release gates.
- Settlement/refund/reversal endpoints are review-only and cannot move funds.
- Privacy requests do not directly delete/export personal data; the execution workflow and audit evidence must be separately implemented and approved.
- Route registration does not imply production readiness. CI, migrations, staging smoke tests and the deployed OpenAPI snapshot must pass before release.
