# Advanced reconciliation controls

This document supplements the existing seasonal amount baseline and distribution-shift algorithms in advanced_reconciliation_algorithms.py.

## Additional primitives

- **Partial/batch payment allocation candidate search:** bounded subset-sum across open invoice balances. A unique combination is returned only when exactly one exact combination exists; multiple combinations require review.
- **Settlement amount/count variance:** compares expected and observed totals using Decimal and optional transaction counts.
- **Reviewed match-quality metrics:** precision, recall, specificity, and accuracy from independently reviewed labels. Undefined metrics are null, not fabricated zeroes.

## Safety and integration contract

- Inputs must already be scoped to one tenant, provider account, settlement window, and currency. Explicit tenant/currency conflicts are excluded as defense in depth.
- Invoice allocation is bounded to 20 invoices and a capped number of dynamic-programming states. Larger sets return REVIEW.
- Outstanding amount is preferred over invoice amount. Only open, unpaid, or partially paid rows qualify. Confirm balances and lock invoice rows in a single database transaction before applying an allocation.
- Output is a candidate, not an accounting decision. Never apply an allocation solely from this result. Persist actor, provenance, algorithm version, chosen allocation, and audit reason.
- Settlement totals must use provider and internal ledger records from the same window, currency, and account. Variance is not necessarily fraud; fees, timing, reversals, and cut-off differences must be modelled explicitly.
- Metrics are valid only when outcomes are independently reviewed. Record evaluation window, tenant/provider segment, sample size, label policy, and reviewer. Do not tune and evaluate on the same holdout data.
- Reversal assessment is surfaced only inside the existing opt-in shadow analysis; it does not alter the legacy decision. Invoice allocation, settlement comparison, and event-order analysis remain pure primitives, not live posting or approval paths. Broader integration requires a reviewed service layer and feature flag after staging replay, integration tests, and finance sign-off.

## Verification commands

    $env:PYTHONPATH = "."
    pytest -q pesaguard_backend_pipeline/tests/test_advanced_reconciliation_algorithms.py
    pytest -q
    python -m compileall -q pesaguard_backend_pipeline

Passing tests do not by themselves establish production readiness. Certification still requires tenant-scoped replay, transactional locking/idempotency tests, provider/database integration tests, security review, and observed CI results.


## Additional lifecycle safeguards

- Reversal assessment checks original-reference linkage, tenant/provider/account/currency scope, timezone-aware event ordering, and cumulative completed reversal amounts. Its only positive result is ELIGIBLE_FOR_REVIEW; it never authorizes posting.
- Event-order assessment classifies in-order, out-of-order-within-tolerance, late, and future-skew events. Late events are surfaced for controlled replay rather than silently discarded.
