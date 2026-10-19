# Cohort-level reconciliation evaluation

## Purpose

Aggregate reconciliation precision and recall can hide a failure in one provider,
currency, tenant, or transaction-size segment. The
`pesaguard_backend_pipeline/reconciliation_cohort_evaluation.py` helper runs the
existing reviewed-ground-truth scorecard separately for each configured cohort.
It is an offline evaluation utility; it does not affect live matching, posting,
risk decisions, or refunds.

## Input contract

Each sample must include:

- `tenant_id`: the tenant that owns the transaction and label.
- `provider`: e.g. `mpesa`; normalized to lowercase for grouping.
- `currency`: ISO-like currency label, normalized to uppercase.
- `amount`: finite, non-negative amount used only to select a broad size band.
- `expected_match_id`, `predicted_match_id`, and `decision`: same reviewed-label
  contract as `reconciliation_evaluation.py`.

Use a finance-reviewed dataset with tenant authorization, documented provenance,
and a separate holdout set. Do not place raw phone numbers, customer names,
transaction references, or other direct identifiers into cohort labels.

## Cohorts and minimum sample sizes

The default dimensions are tenant, provider, currency, and amount band. Tenant
must remain a dimension; cross-tenant pooling is deliberately rejected. Amount
bands are `lt_100`, `100_to_lt_1000`, `1000_to_lt_10000`, `gte_10000`, and
`unknown`. Since currency is a separate dimension, the bands are not interpreted
as equivalent purchasing power across currencies.

Cohorts below `minimum_cohort_size` return `INSUFFICIENT_SAMPLE` with
`metrics: null`. This means unknown, not zero performance. The default minimum
of 20 is a guardrail, not a universal statistical guarantee; teams must choose a
higher threshold where event rates are low or the impact is high.

## Run tests

From the repository root:

```bash
PYTHONPATH=. pytest -q pesaguard_backend_pipeline/tests/test_reconciliation_cohort_evaluation.py
```

## Interpretation and rollout

The output contains precision, recall, F1, false-positive rate, exact-decision
accuracy, automatic-match coverage, review rate, and unmatched rate from the
existing scorecard. Use it to find cohorts that need deeper review, not to
automatically tune thresholds. Before any live policy change, require dataset
versioning, time-based holdout evaluation, finance approval, false-positive
analysis, shadow evaluation, monitoring, feature-flag rollout, and rollback
instructions. A passing unit test or a strong score on one dataset is not
production certification.
