# Production Decision Algorithms

**Status:** implemented as deterministic, pure helper functions; not yet certified as end-to-end production controls.

Module: `pesaguard_backend_pipeline/production_decision_algorithms.py`

## Guarantees and limits

- Helpers return proposals, reason codes, and review signals. They do not write transactions, approve refunds, mutate balances, or post ledger entries.
- Callers must scope every history and candidate query to the authenticated tenant, provider, merchant account, and currency before invoking these helpers.
- Persist the input identifiers, output, algorithm version, policy/config version, and request/trace ID alongside the consuming business transaction.
- Scores are ranking signals, not probabilities. Do not advertise an algorithm as fraud detection accuracy without representative finance-reviewed labels and holdout evaluation.

## Included algorithms

### 1. Conservative reconciliation decision policy
Requires a unique candidate, explicit scope verification, confirmed provider state, passed quality gate, exact external identity, a transactional idempotency claim, and a configurable score threshold before returning `MATCH_PROPOSAL`. Ambiguous, weak, or insufficiently verified candidates remain in review. A match proposal is not a ledger posting.

### 2. Settlement variance decomposition
Classifies currency mismatch, within-tolerance variance, short/over settlement, and known fee/tax explanations. Any material unexplained variance remains `REVIEW`; the helper never creates an adjustment or balancing entry.

### 3. Transaction lifecycle transition validation
Checks legal state transitions, reversal linkage, original confirmation, scope agreement, and timezone-aware chronology. The caller must still validate cumulative reversal amount and enforce uniqueness/locking in the same database transaction that persists the reversal.

### 4. Velocity burst detection
Counts events and sums valid amounts in a caller-defined trailing window. It excludes naive/missing timestamps and returns explainable threshold reasons. It is an investigation signal, not proof of fraud. Caller must supply a single tenant/entity/account cohort and account for late-arriving events.

### 5. Algorithm promotion gate
Blocks promotion if holdout provenance, reviewer, sample size, or required metrics are missing or thresholds fail. A pass is `PASS_FOR_REVIEW`, not automatic deployment. Require shadow execution, finance approval, gradual rollout, monitoring, and rollback.

## Validation

Focused tests are in `tests/test_production_decision_algorithms.py`. Run from repository root:

```bash
python -m pytest pesaguard_backend_pipeline/tests/test_production_decision_algorithms.py -q
```

Run the full backend CI suite before merge. This execution environment has not run the repository test suite; CI evidence is required before claiming tests pass.

## Required follow-up integration gates

1. Verify webhook, batch, retry, worker, and manual replay paths share normalization, quality checks, and atomic idempotency.
2. Add database-level uniqueness and concurrent PostgreSQL tests for transaction identity and reversal callbacks.
3. Wire settlement classification into the exception/reporting path, with finance approval required for any adjustment.
4. Wire velocity signals to tenant-scoped history queries and persisted audit records; set cohort-specific thresholds using reviewed data.
5. Persist algorithm/config versions and reason codes in the reconciliation audit record.
6. Evaluate on time-separated finance-reviewed holdout data, segmented by provider, currency, amount band, and tenant where sample sizes permit.
7. Enable no automatic rule until shadow-run metrics, reviewer sign-off, monitoring, feature-flag rollout, and rollback are documented.
