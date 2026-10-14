# Transaction Intelligence Algorithms

## Purpose

PesaGuard uses deterministic, explainable algorithms before any optional statistical or machine-learning model. These primitives help reconcile M-Pesa events safely and identify unusual amounts without silently correcting financial records.

Implementation lives in `pesaguard_backend_pipeline/algorithmic_intelligence.py`. The fraud risk engine uses robust amount deviation when at least five historical amount samples are available and retains its existing fallback for smaller samples.

## Implemented in this change

| Algorithm | Purpose | Guardrail |
|---|---|---|
| Decimal-to-minor-unit conversion | Compare money without binary floating-point equality errors | Decimal rounding is explicit; callers must use the correct currency precision |
| Canonical reference normalization | Produce a punctuation-insensitive candidate hint | Candidate hints cannot auto-match; partial-payment aggregation preserves punctuation to avoid collisions; missing references remain missing |
| Tenant/provider-scoped transaction identity | Build a stable deduplication key from tenant, provider and external transaction ID | Refuses missing identity fields; does not deduplicate by amount/time alone |
| Canonical payload fingerprint | Detect a conflicting replay where the same transaction ID carries changed facts | Separate from identity: changed amount/reference deliberately changes the fingerprint |
| Median/MAD modified z-score | Detect amount outliers despite a few extreme historical values | Requires at least five samples; not a fraud verdict |
| Same-reference partial-payment aggregation | Sum multiple identified payments against one expected amount | Requires explicit reference and transaction IDs; duplicate IDs count once; overpayment is surfaced |
| Trailing-window velocity detector | Count recent events for the same identity | Requires identity and timestamp; does not treat future-dated events as recent |
| Settlement variance decomposition | Explain expected gross vs actual net using known fees, reversals and adjustments | Uses explicit sign conventions; residual is surfaced, never posted automatically |
| Conservative candidate evidence score | Explain reference, amount, time and phone evidence | Missing phone data is neutral, conflicting phone data blocks auto-match, missing timestamps fail closed; callers must send ambiguous cases to review |
| Ambiguity-safe candidate ranking | Sort candidate evidence and detect a low score margin | Refuses automatic selection for near-ties or non-exact evidence |
| Window-change detection | Detect median shifts in numeric windows, such as volume or latency | Requires a minimum baseline; monitoring signal only, not fraud attribution |\n| Seasonality-aware robust baseline | Compare amount, count, or latency to weekday/hour cohorts using median/MAD with explicit fallback | Implemented as a separate pure helper; caller must provide scoped history; not wired to financial decisions or a persisted workflow |
| Robust fraud feature | Uses the robust amount deviation score when baseline history is sufficient | Keeps the previous small-sample fallback; risk thresholds remain uncalibrated until labelled data is reviewed |
| Replay classification | Distinguishes new events, identical replays and changed-payload replays within tenant/provider/account scope | Pure decision helper; database uniqueness and atomic writes remain authoritative |
| Reversal amount validation | Checks original-reference linkage and cumulative reversal amount | Caller must supply only confirmed reversals from a tenant/account-scoped query; no ledger posting is performed |
| Transaction batch quality profile | Counts missing fields, invalid amounts/timestamps, duplicate IDs, future/late events and unknown fields | Observability signal only; never silently drops or rewrites source rows |
| Bounded exact settlement subset search | Finds a unique set of scoped candidate transactions whose minor-unit sum equals a settlement target | Candidate count is capped; ambiguous/no-solution/invalid inputs go to review; even a unique result is not a confirmed match or ledger posting |

## Matching policy

1. Normalize and validate the source event.
2. Check tenant/provider-scoped external identity and replay fingerprints.
3. Prefer exact external reference (preserving punctuation) and exact amount evidence; normalized-only reference similarity is review evidence, not an automatic match.
4. Use time and phone consistency as corroborating signals. Missing time evidence is unknown, not a successful time-window check.
5. Never auto-match a candidate solely because amount and timestamp happen to be similar.
6. If multiple candidates are plausible, candidate ranking is ambiguous, required identity is missing, or source facts conflict, create an exception for review. The reconciliation engine returns an exception rather than selecting between top tolerant/amount-only candidates whose scores differ by less than 0.05.
7. Reconciliation detects discrepancies; it must not silently edit ledger balances or manufacture adjustment postings.

Partial-payment aggregation, velocity screening, settlement variance decomposition, replay classification, reversal validation and batch quality profiling are deterministic primitives. They do not by themselves provide end-to-end durable workflows. Before claiming a production capability, callers must wire them into tenant-scoped persistence, enforce database uniqueness/locking, add audit evidence and operational alerts, and test recovery from partial failure.

The candidate score is evidence, not a probability. A score of 1.0 does not mean a calibrated 100% probability of correctness.

## Statistical baseline

Daraja compact timestamps (YYYYMMDDHHMMSS) are interpreted as Africa/Nairobi local time and normalized to UTC for cross-format comparison across the primary reconciliation engine, transaction-intelligence helpers, risk features, and legacy timestamp utilities. Naive ISO timestamps continue to be treated as UTC; the legacy utility keeps a naive-UTC return type for compatibility. Risk time-of-day features use Africa/Nairobi local time; do not compare event-time and ingestion-time fields as if they were interchangeable. Risk feature scoring treats established customer history as context rather than a positive risk signal, and rapid amount-change screening is scoped to the same customer within a five-minute window. The rule model remains heuristic, not a calibrated fraud probability. Evaluation reports detection latency only when the caller supplies an event timestamp; decision age is not a latency metric.

The modified z-score is:

`z = (amount - median(history)) / (1.4826 * MAD(history))`

When MAD is zero, a conservative scale floor is used to avoid division by zero. The baseline is only considered when there are at least five valid historical observations. Production risk thresholds must be validated against labelled tenant data and reviewed for false positives before automatic actions are enabled.

## Next algorithms to add after data contracts and ground truth are verified

- One-to-many and many-to-one settlement matching using explicit batch/settlement identifiers and amount conservation.
- Integrate bounded exact subset results into the persisted settlement lifecycle with tenant-scoped retrieval, approvals, audit history, and safe retry semantics.
- Persistent reversal/refund lifecycle graph linked to the original external transaction. The current reversal validator is a pure helper; the provider-confirmed lifecycle and database transaction still need integration.
- Temporal/bi-temporal reconciliation using event time, settlement time and ingestion time separately.
- Persistence-level conflicting-replay handling backed by database uniqueness constraints, payload-fingerprint storage, and an audited operator workflow. The current replay classifier is a pure helper and must be wired into the durable ingestion transaction.
- Merchant/customer peer-group baselines, day-of-week and hour-of-day seasonality, and robust rolling windows.
- Change-point detection for sudden shifts in provider error rate, fees, transaction volume or settlement latency.
- Calibrated risk scoring with precision/recall, false-positive rate, PR-AUC, drift monitoring and human-reviewed labels.
- Persisted data-quality trend detection for schema drift, late-arriving events, null spikes, invalid currency/amount and provider-specific field changes. The current batch profiler reports a single batch and does not yet persist trends or emit alerts.
- Extend the existing settlement variance helper to classify timing gaps, missing records, duplicate records and amount mismatches using persisted, source-backed evidence.
- Graph-based related-entity analysis only where lawful, necessary data and validated labels exist.

The seasonality-aware helper is documented in [Seasonality-aware Transaction Intelligence](SEASONALITY_AWARE_TRANSACTION_INTELLIGENCE.md). It is an additive advisory primitive, not yet wired into persisted risk/monitoring workflows.\n\nThe bounded settlement subset search and ambiguity-safe selection guard are implemented as review-oriented primitives. Durable settlement workflow integration remains open. Do not enable unsupervised auto-blocking or auto-adjustments based on anomaly scores alone.

## Validation

Run from the repository root with the project virtual environment active:

```bash
export PYTHONPATH=pesaguard_backend_pipeline
pytest -q pesaguard_backend_pipeline/tests/test_algorithmic_intelligence.py
pytest -q pesaguard_backend_pipeline/tests/test_fraud_risk_engine.py
pytest -q pesaguard_backend_pipeline/tests/test_reconciliation_ambiguity.py
```

The full CI suite and staging validation remain required. Synthetic tests demonstrate deterministic behavior, not production accuracy.


## Cumulative below-threshold activity and duplicate-identity guard

The fraud rules include a conservative cumulative-activity signal. It evaluates
only tenant-scoped history with distinct transaction IDs, a matching customer
identity, valid event timestamps inside the configured trailing window, and
positive individual amounts below the configured threshold. A signal requires
the combined amount to reach that threshold and at least the configured minimum
number of transactions. Missing identity, time, or transaction IDs do not produce
a positive signal.

This is a screening feature, not a fraud verdict. It does not block payments,
reverse transactions, or change ledger balances. The caller must scope history
to the authenticated tenant and configure a threshold appropriate to the product
and applicable policy. Production deployment still requires labeled-data
validation, false-positive review, threshold governance, and monitoring before
the signal is used to change customer outcomes. Missing transaction IDs are no
longer treated as duplicates merely because both values normalize to the same
unknown sentinel.
