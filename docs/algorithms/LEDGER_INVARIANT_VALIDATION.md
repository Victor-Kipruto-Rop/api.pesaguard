# Ledger Invariant Validation

## Purpose

`pesaguard_backend_pipeline/ledger_invariants.py` is a deterministic, fail-closed validation primitive for proposed double-entry journal batches. It verifies line identity, account/currency presence, valid debit/credit sides, finite positive decimal amounts, approved currency precision, and debit/credit equality **per journal and currency**.

The helper does not write entries, reserve an idempotency key, authorize an account, lock a posting period, or provide database concurrency guarantees. A successful result means only that the supplied proposal passed these local arithmetic/shape checks.

## Contract

Call `validate_journal_batch(entries, currency_exponents=...)` before posting. The result contains:

- `can_post`: false whenever any finding exists or a journal is unbalanced.
- `findings`: stable machine-readable codes with severity and a safe explanation.
- `journals`: per-journal/per-currency debit, credit, difference, line count, and balance result.
- `algorithm_version`: `ledger-invariants-v1`, suitable for audit evidence.

Unknown currency precision fails closed unless the caller supplies an explicitly approved integer exponent from 0 through 6. Cross-currency lines never offset each other. Malformed lines are excluded from arithmetic and still produce findings. Empty or incomplete batches are not postable.

## Required production integration

This is an additive safety primitive and is **not automatically the authoritative posting gate**. Before calling a system production-ready:

1. Invoke validation after canonical normalization and before ledger writes on every posting route, worker, retry, reversal, settlement, and manual replay path.
2. In one database transaction, enforce tenant authorization, claim idempotency, lock/serialize affected ledger accounts as required, validate the proposed batch, insert all lines, and persist audit evidence. Roll back the entire transaction on any failure.
3. Add database constraints for line identity, tenant scope, currency, and required references. Application validation alone cannot prevent concurrent duplicate posting.
4. Verify reversal and settlement posting use provider-confirmed states and are bounded by original transaction and cumulative confirmed reversal amounts.
5. Test real PostgreSQL concurrency, duplicate retries, process crashes, rollback, multi-currency journals, and tenant isolation.
6. Store the algorithm version and sanitized findings with the audit record; never log credentials or unnecessary payment personal data.

## Verification

Run:

```powershell
$env:PYTHONPATH = "."
pytest -q pesaguard_backend_pipeline/tests/test_ledger_invariants.py
pytest -q
python -m compileall -q pesaguard_backend_pipeline
```

Focused tests cover balanced and unbalanced journals, malformed money, precision, duplicate line identity, independent journal/currency balancing, unknown currency precision, and empty input. These tests are authored but must be executed in CI/local environment before release; no production certification is implied.
