# Advanced Reconciliation Algorithms

## Scope and status

The module pesaguard_backend_pipeline/advanced_reconciliation_algorithms.py adds two deterministic, explainable analytics helpers:

- **Seasonal amount assessment:** compares a transaction with observations from the same local weekday/hour and currency cohort. The timezone defaults to Africa/Nairobi; history must be supplied by the caller and restricted to the same tenant, provider/account, business context, and appropriate transaction type.
- **Distribution-shift detection:** compares the median of a reference window with a recent window and surfaces large changes for operational investigation.

These functions are advisory and are not wired into the authoritative reconciliation decision path. They do not mark payments as fraudulent, auto-match transactions, block payments, change balances, or create ledger entries.

## Safety and interpretation

- A baseline with too few comparable observations returns ready=false and a null decision; missing data is not treated as normality.
- Currency is explicitly matched. The caller is responsible for tenant/provider/account scoping and for excluding unconfirmed, reversed, or otherwise incomparable transactions.
- Amount outliers and distribution shifts are investigation signals, not causal explanations or calibrated fraud probabilities.
- A zero median absolute deviation does not produce an infinite z-score.
- Do not use these functions to automatically decline, refund, freeze, or post adjustments.
- Store algorithm/configuration version, cohort definition, sample counts, and decision evidence if results are persisted. Avoid storing unnecessary personal identifiers.
- Do not promote either helper into automatic financial decisions until finance-reviewed holdout evaluation, false-positive review, drift monitoring, feature-flag rollout, and rollback are complete.

## Verification

Run from the repository root:

```powershell
$env:PYTHONPATH = "."
pytest -q pesaguard_backend_pipeline/tests/test_advanced_reconciliation_algorithms.py
pytest -q
python -m compileall -q pesaguard_backend_pipeline
```

The focused tests are added in this change; actual CI and production behavior must be verified by running them. Passing unit tests alone is not production certification.
