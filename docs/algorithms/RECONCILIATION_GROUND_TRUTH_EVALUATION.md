# Reconciliation Ground-Truth Evaluation

## Purpose

PesaGuard already has deterministic matching, ambiguity detection, anomaly signals, and settlement investigation primitives. These helpers are not enough to certify a decision policy: thresholds must be measured against a reviewed, representative set of known outcomes. This evaluation module adds a dependency-free scorecard for that process.

Implementation: `pesaguard_backend_pipeline/reconciliation_evaluation.py`.

## Metrics

- **Precision:** proportion of automatic matches that are correct.
- **Recall:** proportion of true matches that were automatically matched correctly.
- **F1:** harmonic mean of precision and recall when both are defined and their sum is non-zero.
- **False-positive rate:** incorrect automatic matches among all ground-truth non-matches.
- **Specificity:** ground-truth non-matches correctly left unmatched.
- **Exact-decision accuracy:** correct automatic matches plus correct unmatched decisions, divided by all evaluated examples.
- **Automatic-match coverage:** fraction of the dataset automatically matched.
- **Review rate:** fraction sent to review/exception/ambiguity states.
- **Unmatched rate:** fraction explicitly returned as unmatched.

A wrong automatic match is both a false positive and, when a valid match existed, a false negative. A review outcome is not counted as a correct match. Undefined metrics are returned as `null`, not zero, when their denominator is empty. An empty dataset returns `evaluated: false`.

## Input contract

Each sample must contain:

- `expected_match_id`: reviewed ledger record ID, or `None` if no valid match exists.
- `predicted_match_id`: ledger record ID the system actually auto-matched, or `None` when it did not auto-match. Do not put a suggested candidate in this field for a review decision.
- `decision`: one of `MATCHED`, `AUTO_MATCH`, `AUTO_MATCHED`, `REVIEW`, `NEEDS_REVIEW`, `AMBIGUOUS`, `EXCEPTION`, `UNMATCHED`, `MISSING_PAYMENT`, or `NO_MATCH`.

The evaluator rejects missing required fields, unknown decisions, and automatic-match decisions without a predicted record ID. It accepts IDs as strings or integers and normalizes surrounding whitespace.

## Example

Run from the repository root with the backend test environment installed:

```python
from reconciliation_evaluation import evaluate_reconciliation_predictions

scorecard = evaluate_reconciliation_predictions([
    {
        "expected_match_id": "ledger-123",
        "predicted_match_id": "ledger-123",
        "decision": "MATCHED",
    },
    {
        "expected_match_id": None,
        "predicted_match_id": None,
        "decision": "UNMATCHED",
    },
])
print(scorecard)
```

## Production acceptance process

1. Obtain finance-reviewed ground truth from a representative period, tenant, provider, transaction-value range, and lifecycle state.
2. Keep training/development examples separate from final holdout examples. Do not tune thresholds on the same holdout used to claim performance.
3. Include hard negatives: identical amounts, reused references, punctuation collisions, delayed ledger sync, duplicate callbacks, reversals, partial payments, and same-time candidate collisions.
4. Evaluate each tenant/provider cohort where sample size allows. Do not combine tenant data without an explicit privacy and measurement policy.
5. Review precision, recall, false-positive rate, coverage, and review rate together. High coverage is not a success if it increases incorrect financial matches.
6. Record the dataset version, time window, reviewer process, algorithm version, threshold configuration, sample counts, metrics, and approval decision outside this pure helper.
7. Run shadow evaluation and compare it with the existing decision path before enabling any new policy.
8. Re-run after material provider, schema, threshold, or algorithm changes and monitor for drift.

## Important limitations

- This scorecard measures labeled examples; it does not create ground truth or prove the dataset is representative.
- Match-ranking scores are not calibrated probabilities. Do not report them as fraud probabilities.
- The evaluator does not write to the ledger, persist audit evidence, approve refunds, or change production matching behavior.
- This is one release gate, not production certification. Database uniqueness, tenant authorization, atomic idempotency, operational monitoring, staging tests, and recovery validation remain mandatory.
