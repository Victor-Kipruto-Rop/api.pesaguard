# Reconciliation Decision Policy

## Status and scope

`reconciliation_decision_policy.py` is a deterministic, fail-closed arbitration layer for already-computed algorithm evidence. It standardizes precedence across quality checks, candidate scope conflicts, ambiguity, risk triage, and lifecycle validation.

**It is not wired into the authoritative posting path by this change.** Its `PROPOSE_MATCH` result is a recommendation only. Every result explicitly sets `may_post_to_ledger=false`. Existing tenant-scoped retrieval, database constraints, transactional idempotency, audit persistence, approval controls, and balanced ledger posting remain mandatory.

## Decision precedence

1. Invalid transaction-quality evidence -> `EXCEPTION`.
2. Explicit tenant/provider/account/currency conflict -> `REVIEW`.
3. Required but missing/unknown lifecycle evidence -> `EXCEPTION`.
4. High/critical risk or a review/block/escalate action -> `REVIEW`.
5. Ambiguous or tied candidates -> `REVIEW`.
6. No eligible candidate -> `UNMATCHED`.
7. One unambiguous eligible candidate -> `PROPOSE_MATCH` (never a posting authorization).
8. Unknown policy states or malformed evidence -> fail closed.

The algorithm preserves reason codes and a compact evidence record. Scores are never interpreted as probabilities. No fraud, refund, hold, settlement, or ledger-posting action is authorized by this module.

## Integration requirements before enabling

- Call only after authenticated tenant resolution and tenant/provider/account/currency-scoped candidate retrieval.
- Validate the exact schema of each algorithm output at the service boundary.
- Persist decision version and reason codes with the same transaction/outbox audit boundary as the reconciliation result.
- Do not let a policy exception suppress the underlying financial event; persist it for review using existing exception handling.
- Add integration tests for webhook, synchronous API, worker, retry, batch, and manual replay paths.
- Run PostgreSQL concurrency and tenant-isolation tests, then compare decisions against a finance-reviewed holdout dataset.
- Keep feature-flag rollout, metrics, alerting, and rollback separate from this pure function.

## Verification

```powershell
$env:PYTHONPATH = "."
pytest -q pesaguard_backend_pipeline/tests/test_reconciliation_decision_policy.py
pytest -q
python -m compileall -q pesaguard_backend_pipeline
```

A passing unit test suite demonstrates function behavior only. It does not certify end-to-end integration or production readiness.
