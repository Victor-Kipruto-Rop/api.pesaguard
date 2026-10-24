# Tenant isolation release gate

This gate is mandatory before enabling live tenant traffic. Tenant isolation failures can expose transaction metadata across organizations; a passing unit test alone is not proof that production data access is isolated.

## Trust boundaries

- Derive `tenant_id` from authenticated server-side identity, a verified integration credential, or an explicitly bound tenant configuration.
- Never treat a callback body, query parameter, arbitrary header, or event payload as authoritative tenant identity by itself.
- If the authenticated tenant and the payload tenant disagree, reject the request and emit a sanitized security/audit event. Do not silently overwrite the conflicting value.
- Never route missing, blank, `default`, `unknown`, `none`, or `null` tenant values into a shared tenant namespace.
- Keep raw provider payloads, access tokens, signatures, phone numbers, and credentials out of logs and trace attributes. Log stable internal IDs and redacted failure reasons instead.
- Tenant identity must survive ingestion, validation, event publication, retry, dead-letter handling, lineage, quarantine, background jobs, report generation, and persistence.

## Required verification

Run from the repository root in a clean environment with the supported Python version and test dependencies installed:

```bash
export PYTHONPATH=.
python -m compileall -q pesaguard_backend_pipeline
ruff check --select E9,F821 .
pytest -v --tb=short --durations=10
```

Run the focused tenant/provenance/event contract tests first when iterating, then run the full suite. A focused pass does not replace the full CI suite.

The following cases must be covered by automated tests:

- Missing, empty, whitespace-only, and placeholder tenant identifiers are rejected.
- Conflicting tenant aliases are rejected rather than resolved by field precedence.
- Authenticated tenant context can supply tenant identity when the provider payload omits it.
- A payload tenant that conflicts with trusted context is rejected.
- Published events, retries, dead-letter records, quarantine records, and lineage preserve the same tenant scope.
- Batch processing rejects only invalid items, reports each item's result accurately, and does not publish unscoped events.
- Tenant A cannot read, mutate, export, or infer tenant B's records through API routes, background jobs, metrics, logs, or report artifacts.
- Database row-level security (where used) is tested with the actual production database role, not only a superuser or table owner.

## Production deployment checklist

- [ ] Identify every production entry point that calls provenance processing or event publishing.
- [ ] Pass the tenant resolved from authenticated server-side configuration into provenance processing; do not derive trust from callback JSON.
- [ ] Verify provider signature/authentication before accepting a callback, and make callback handling idempotent.
- [ ] Confirm database queries and mutations apply tenant scope at the repository/service boundary; use database-enforced isolation where supported.
- [ ] Confirm workers re-establish tenant context from a validated job envelope and do not rely on request-local context.
- [ ] Confirm retries and dead-letter replay retain tenant scope and cannot be replayed under another tenant.
- [ ] Confirm logs, traces, metrics labels, exports, and errors do not leak cross-tenant data or high-cardinality sensitive values.
- [ ] Run negative tests using at least two distinct tenants against staging with the same role and auth path used in production.
- [ ] Review CI results, migration status, rollback plan, and sanitized application logs.
- [ ] Keep live payment traffic disabled until all release gates pass and a reviewer signs off.

## Failure handling

Reject an unscoped or conflicting event before publishing or persisting tenant-owned records. Return a generic client-safe error; preserve a sanitized internal reason and correlation identifier for operators. Do not fall back to a shared tenant, infer a tenant from transaction identifiers, or retry an invalid payload indefinitely.

If a tenant-isolation incident is suspected, pause affected ingestion, preserve sanitized audit evidence, restrict access to affected exports, assess scope with the security owner, and follow the incident-response and applicable privacy-notification procedures.

## Evidence record

For each release, attach the commit SHA, CI run URL, migration result, staging smoke-test evidence, cross-tenant negative-test result, backup/restore result, and reviewer approval to the release record. Record any exception with an owner and expiry date; do not silently waive a failed isolation test.

This document describes a release gate, not a claim that the repository or a deployed environment has already passed it.
