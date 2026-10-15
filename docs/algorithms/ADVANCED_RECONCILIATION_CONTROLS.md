# Advanced reconciliation controls

## Algorithms added

- **Partial/batch payment allocation candidate search:** bounded subset-sum across open invoice balances. A unique combination is returned only when exactly one exact combination exists; multiple combinations require review.
- **Settlement amount/count variance:** compares expected and observed totals with Decimal arithmetic and optional transaction counts.
- **Reviewed match-quality metrics:** precision, recall, specificity, and accuracy from independently reviewed ground-truth labels. Undefined metrics are null, not fabricated zeroes.

## Safety and integration contract

- Inputs must already be scoped to one tenant, provider account, settlement window, and currency. Explicit tenant/currency conflicts are excluded as defense in depth.
- The invoice allocator is bounded to 20 invoices and a capped number of dynamic-programming states. Larger sets return REVIEW; use trusted database queries and approved grouping logic before retrying.
- Outstanding amount is preferred over invoice amount. Only open, unpaid, or partially paid rows qualify. Confirm current balances and lock invoice rows in a single database transaction before applying an allocation.
- Output is a candidate, not an accounting decision. Never apply an allocation solely from this result. Persist actor, input provenance, algorithm version, chosen allocation, and audit reason.
- Settlement totals must use provider settlement records and internal ledger totals from the same window, currency, and account. Variance is not necessarily fraud; fees, timing, reversals, and cut-off differences must be modelled explicitly.
- Metrics are valid only when outcomes are independently reviewed. Record evaluation window, tenant/provider segment, sample size, label policy, and reviewer. Do not tune and evaluate on the same holdout data.
- These helpers are not wired into payment approval, settlement posting, refunds, or API routes in this change. Integrate through a separately reviewed service layer and feature flag after staging replay, integration tests, and finance sign-off.

## Verification commands

    $env:PYTHONPATH = "."
    pytest -q pesaguard_backend_pipeline/tests/test_advanced_reconciliation_algorithms.py
    pytest -q pesaguard_backend_pipeline/tests/test_smart_reconciliation_algorithms.py
    pytest -q
    python -m compileall -q pesaguard_backend_pipeline

Passing tests do not by themselves establish production readiness. Certification still requires tenant-scoped data replay, transaction-level locking/idempotency tests, integration tests against database/provider adapters, security review, and observed CI results.
