# Reconciliation Scope Safety Guard

## Behavior

The live reconciliation matcher checks explicit candidate scope metadata before scoring or selecting a candidate. When both the incoming event and a candidate provide values for a scope dimension, these dimensions must agree:

- Tenant identifier
- Provider
- Provider account / business short code
- Currency

Provider and currency values are compared case-insensitively. Tenant and account identifiers are compared exactly. Missing metadata is not interpreted as a mismatch; callers must still use tenant-scoped retrieval and authoritative account/provider context.

If any candidate in the supplied candidate set explicitly conflicts, the matcher fails closed for that event and returns a `needs_review` result with `candidate_scope_conflict`. It does not select another apparently valid candidate from the same mixed set. This makes a wrongly scoped query visible instead of allowing an automatic match to mask a data-isolation defect.

## Security boundary

This is a second-line integrity check, not a substitute for:

1. Authorization and tenant scoping in the database query.
2. Database constraints that enforce tenant ownership and transaction identity.
3. Provider signature verification and callback authentication.
4. Transactional idempotency, audit persistence, and ledger invariants.

A candidate whose tenant/account/provider metadata is absent cannot be proven to belong to the correct scope by this helper alone. Do not use it to justify unscoped candidate queries.

## Rollout and validation

```bash
export PYTHONPATH=pesaguard_backend_pipeline
pytest -q pesaguard_backend_pipeline/tests/test_reconciliation_scope_guard.py
pytest -q
python -m compileall -q pesaguard_backend_pipeline
```

The focused tests cover cross-tenant, provider, account, and currency conflicts, plus a correctly scoped exact-match regression. Full CI, database-level tenant-isolation tests, staging verification, and review of all ingestion callers remain required before a production release.
