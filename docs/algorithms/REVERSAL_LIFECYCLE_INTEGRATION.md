# Reversal lifecycle validation integration

## Wiring status

The reconciliation worker now calls `reversal_lifecycle_integration.assess_persisted_reversal` for refund/reversal-shaped events. The adapter queries the original and bounded transaction history using the same tenant, provider account, and provider scope. Its output is attached to the reconciliation result and therefore to the existing audit/outbox payload.

If evidence is missing, contradictory, incomplete, or over the configured history limit, the worker changes the reconciliation result to `EXCEPTION` and records structured reason codes. This prevents the transaction from being represented as an ordinary successful match.

## Safety boundaries

- This is a **review-routing control**, not a posting authorization.
- The adapter always returns `can_auto_post: false`.
- It does not issue provider requests, create refunds, write ledger entries, or lock a posting period.
- It cannot prevent two concurrent reversals from passing a read-only check. Any real reversal writer must claim idempotency, lock/serialize the original transaction, re-check cumulative provider-confirmed reversals, and persist the state transition atomically in one database transaction.
- Only explicit provider confirmation is counted as a completed prior reversal. The database's internal `RECONCILED` status is not treated as provider confirmation.
- When a prior reversal row is present but its provider status cannot be established, the event requires review.
- History is bounded to 1,000 scoped rows. If more rows exist, the adapter fails closed to review rather than silently calculating against truncated history.

## Verification

Run from repository root:

```powershell
$env:PYTHONPATH = "."
pytest -q pesaguard_backend_pipeline/tests/test_reversal_lifecycle_integration.py
pytest -q pesaguard_backend_pipeline/tests/test_transaction_lifecycle_algorithms.py
pytest -q pesaguard_backend_pipeline/tests/test_phase3_reconciliation.py
python -m compileall -q pesaguard_backend_pipeline
```

These tests still need to run in CI. Staging must also verify the persisted raw payload shape for each provider, query plans/indexes for tenant/provider/account history, event replay behavior, and concurrent reversal attempts. Do not enable automatic financial posting on the strength of this review gate.
