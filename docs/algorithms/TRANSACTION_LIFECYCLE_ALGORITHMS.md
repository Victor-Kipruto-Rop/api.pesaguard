# Transaction Lifecycle Algorithms

## Purpose and status

The transaction_lifecycle_algorithms.py module implements a deterministic, pure-Python validation primitive for refunds and reversals. It checks linkage to the original transaction, tenant/provider/account/currency scope, event chronology, positive finite amounts, duplicate reversal IDs, and cumulative provider-confirmed reversal totals.

The helper is advisory and is **not wired into the authoritative posting path**. It never sends a provider request, changes a balance, authorizes a refund, or creates a ledger entry. A VALIDATION_PASS means only that the supplied evidence passed these checks; the result deliberately always sets can_auto_post=false.

## Required caller contract

- Resolve the original transaction and prior reversal rows using authenticated tenant, provider, and provider-account scope in the database query. Do not pass cross-tenant data and rely on this helper to repair the query.
- Supply explicit scope metadata on both the current reversal and original transaction. Missing scope is a review condition.
- Supply normalized, timezone-aware timestamps. Naive timestamps are ambiguous and fail closed.
- Include only provider-confirmed prior reversals for the same original in prior_reversals; the helper counts recognized confirmed states and reports invalid or cross-scope records for review.
- Run the check in the same transaction as the authoritative lifecycle transition and persist the result/version in audit evidence before considering any posting workflow.
- Keep provider confirmation, cumulative-reversal locking, idempotency, ledger balance checks, and database uniqueness constraints authoritative. The pure helper cannot protect against concurrent requests by itself.

## Result interpretation

- VALIDATION_PASS: no contradiction was found in the evidence supplied. This is not a fraud-free assertion or an authorization decision.
- REVIEW_REQUIRED: one or more reason codes describe missing or conflicting evidence; no automatic posting should follow.
- Amounts use Decimal, not binary floating-point arithmetic. Only confirmed prior reversals contribute to the cumulative total.
- Unknown or pending prior reversals do not count as completed financial reversals; callers must still prevent concurrent over-reversal through transactional database locking and constraints.

## Tests

Run from the repository root:

```powershell
$env:PYTHONPATH = "."
pytest -q pesaguard_backend_pipeline/tests/test_transaction_lifecycle_algorithms.py
pytest -q pesaguard_backend_pipeline/tests/test_phase3_reconciliation.py
python -m compileall -q pesaguard_backend_pipeline
```

Focused unit tests do not establish production certification. The helper must be integrated into the persisted lifecycle with tenant-isolation, concurrency, provider-confirmation, migration, and finance-reviewed acceptance tests before it can affect live financial state.
