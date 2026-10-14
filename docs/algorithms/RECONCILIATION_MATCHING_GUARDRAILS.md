# Reconciliation Matching Guardrails

## Purpose

The reconciliation matcher must prefer reviewable uncertainty over a confident-looking but incorrect ledger assignment. A false positive can make a missing payment appear reconciled, distort settlement reporting, and create an audit gap.

## Current implemented behavior

The legacy-compatible `evaluate_transaction` path now:

- ranks eligible candidates deterministically using score, match type, event-time distance, amount difference, and stable record identifiers;
- records `candidate_count`, `confidence_gap`, and `ambiguous` in selected-candidate evidence;
- returns `match_type: ambiguous` and routes the result to `needs_review` when the top two candidate scores differ by at most 0.03;
- includes up to five candidate references for operator review;
- preserves automatic matching for a single eligible candidate to avoid silently changing existing integration semantics.

The 0.03 margin is a heuristic, not a statistically calibrated probability. Match `score` values are ranking scores and must not be described as calibrated fraud or match probabilities.

## Operational interpretation

- `matched`: one eligible candidate passed the current match rules and the ambiguity guard did not trigger.
- `needs_review` with `match_type: ambiguous`: multiple candidates are similarly plausible. Do not settle, refund, or auto-approve solely from this result.
- `missing_payment`: no eligible internal candidate was found under the configured matching window and amount tolerance. Investigate delayed ledger synchronization before treating it as confirmed loss.
- `duplicate_ignored`: idempotency infrastructure identified a repeated provider transaction; do not emit a second financial posting.

## Required follow-up before production certification

1. Build approved, tenant-separated ground-truth fixtures covering true matches, non-matches, same-amount collisions, partial payments, reversals, late arrivals, and duplicate callbacks.
2. Measure precision, recall, false-positive rate, false-negative rate, and review rate per tenant and provider.
3. Calibrate the ambiguity margin against labeled data; keep the default conservative until evidence supports a change.
4. Ensure callers use tenant-scoped records and database uniqueness constraints. An in-memory matcher cannot replace transactional idempotency or tenant isolation.
5. Add shadow evaluation before enabling any future fuzzy or machine-learning model for financial decisions.
6. Treat ML anomaly scores as review signals only until validated training data, drift monitoring, explainability, and an explicit approval policy exist.

## Non-goals

This change does not certify fraud detection, guarantee complete reconciliation, enable automatic refunds, change ledger posting semantics, or prove production readiness. CI and staging tests must pass before merge.
