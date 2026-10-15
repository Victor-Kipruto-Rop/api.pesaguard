# Global Batch Reconciliation Assignment

## Problem this addresses

Independent per-transaction matching can propose the same internal ledger row for
more than one incoming provider transaction. A strong local candidate score does
not guarantee a consistent batch-level assignment.

`pesaguard_backend_pipeline/batch_reconciliation_assignment.py` provides a bounded,
deterministic, exact one-to-one assignment proposal. It maximizes the sum of
eligible candidate ranking scores while allowing transactions to remain unmatched.
Each ledger candidate can be assigned at most once in a batch.

## Contract and safety boundary

- Input candidate scores must already be calculated by the existing matcher and
  must be ranking scores in the range 0–1, **not probabilities**.
- Callers must query candidates using authenticated tenant, provider, account,
  and currency scope before invoking this function. This helper cannot establish
  authorization or repair an unsafe query.
- A candidate may be marked `eligible: false` to exclude it.
- Scores below `minimum_score` are not considered.
- If removing a selected edge permits an alternative global assignment within
  `ambiguity_margin`, the result is `REVIEW` and `assignments` is empty. The
  optimum is returned only under `proposed_assignments` as diagnostic evidence.
- Inputs beyond the configured exact-search limits return `ready: false` and
  `REVIEW`; the algorithm never silently truncates a batch.
- Output explicitly reports `side_effects_performed: false`. No database writes,
  ledger postings, refunds, reversals, or payment decisions are made.

## Complexity and limits

This exact dynamic-programming search uses a bitmask over candidate ledger rows.
Default limits are 16 transactions and 16 distinct candidates. These are guardrails,
not throughput claims. Larger batches should be split only with a proven strategy
that preserves candidate-conflict boundaries, or handled by a separately tested
polynomial-time assignment solver. Arbitrarily chunking transactions can produce
a globally suboptimal result when candidates overlap across chunks.

## Example

```python
from pesaguard_backend_pipeline.batch_reconciliation_assignment import (
    propose_batch_assignment,
)

proposal = propose_batch_assignment([
    {"transaction_id": "provider-tx-1", "candidates": [
        {"candidate_id": "ledger-101", "score": 0.95},
        {"candidate_id": "ledger-102", "score": 0.82},
    ]},
    {"transaction_id": "provider-tx-2", "candidates": [
        {"candidate_id": "ledger-101", "score": 0.93},
    ]},
])
```

The result is a proposal for the caller to persist as auditable evidence and pass
through existing policy, idempotency, and approval controls. It must not be wired
directly to financial posting without integration tests, tenant-isolation tests,
concurrency-safe uniqueness constraints, ground-truth evaluation, shadow runs,
and an approved rollout plan.

## Verification

Run from the repository root:

```bash
PYTHONPATH=. pytest -q pesaguard_backend_pipeline/tests/test_batch_reconciliation_assignment.py
python -m compileall -q pesaguard_backend_pipeline/batch_reconciliation_assignment.py
```

Passing these focused tests does not certify the entire API or production deployment.
