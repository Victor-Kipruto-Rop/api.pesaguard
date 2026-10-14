# Temporal and Seasonal Transaction Intelligence

## Scope

Implementation: `pesaguard_backend_pipeline/temporal_intelligence.py`.

This module adds deterministic helpers for (1) event/ingestion/settlement time ordering and lag classification, and (2) robust amount anomaly screening against a tenant/provider/account-scoped seasonal baseline. The helpers are advisory. They do not change reconciliation statuses, block transactions, issue refunds, or post ledger entries.

## Temporal evidence

`classify_temporal_evidence` distinguishes:

- `ON_TIME`: the provider event timestamp is not beyond the configured ingestion-lag threshold.
- `LATE_ARRIVAL`: ingestion occurred after the configured maximum lag.
- `CLOCK_SKEW_OR_FUTURE_EVENT`: event time is later than ingestion beyond allowed clock skew.
- `INVALID_TEMPORAL_ORDER`: a supplied settlement timestamp predates the payment event.
- `SETTLEMENT_OBSERVED`: event/ingestion timing is acceptable and a valid later settlement timestamp is present.
- `INSUFFICIENT_DATA`: event or ingestion time is absent or ambiguous.

A late callback can arrive after a provider's settlement timestamp; the helper preserves both lags and does not treat settlement-before-ingestion as invalid by itself. A settlement timestamp earlier than the payment event is an explicit temporal conflict. Missing or ambiguous timestamps are not silently converted into a healthy result.

Daraja compact timestamps (`YYYYMMDDHHMMSS`) are interpreted in `Africa/Nairobi`. ISO timestamps must include an explicit timezone. All output timestamps are normalized to UTC. Configure the source contract for each provider before using this helper in a production workflow.

## Seasonal amount screening

`seasonal_amount_anomaly` requires explicit tenant, provider, and account identifiers. It filters history to the exact same scope and to records strictly earlier than the current event. Its baseline hierarchy is:

1. Same weekday and local hour.
2. Same weekday.
3. All valid history within the same tenant/provider/account scope.

A cohort is used only if it meets the configured minimum sample count. Otherwise the result is `evaluated: false` with an insufficient-data reason. The detector uses median and median absolute deviation (MAD); a zero-MAD baseline never fabricates an infinite or calibrated z-score. It emits a review candidate with an explicit reason when the amount differs from a zero-MAD median.

The result is an anomaly candidate, not a probability of fraud. It must not be the sole basis for declining a payment, freezing funds, refunding, or changing a ledger balance.

## Data contract and isolation

- Callers must pass history retrieved using authenticated tenant/provider/account filters; this module additionally rechecks exact scope fields on every history row.
- Missing scope fields exclude a row from the baseline.
- Use provider event time rather than ingestion time for the seasonal bucket.
- Preserve event time, ingestion time, and settlement time as separate source facts; do not overwrite one with another.
- Algorithm outputs should be persisted with the algorithm version, input dataset/cohort version, decision timestamp, and reason codes if a downstream workflow consumes them.
- Do not log full phone numbers or raw provider payloads to algorithm telemetry.

## Tests

Run from the repository root:

```powershell
$env:PYTHONPATH = "pesaguard_backend_pipeline"
pytest -q pesaguard_backend_pipeline/tests/test_temporal_intelligence.py
```

These tests verify timezone handling, late-arriving events, invalid settlement order, missing evidence, seasonal outlier detection, tenant/account isolation, insufficient-data behavior, and invalid configuration. They demonstrate helper behavior only; they do not prove the helpers are wired into all ingestion routes or certify production accuracy.

## Production integration still required

1. Wire the temporal helper into a shared ingestion/evaluation service after source timestamp contracts are confirmed for each provider.
2. Persist source event, receipt, and settlement timestamps with provenance and immutable audit history.
3. Add tenant-scoped repository queries and database constraints for the settlement lifecycle.
4. Record shadow outputs and baseline cohort metadata without changing existing decisions.
5. Evaluate false-positive and false-negative rates on finance-reviewed, time-separated holdout data.
6. Monitor timestamp parse failures, ingestion-lag percentiles, baseline freshness, outlier rates, and tenant/provider cohort sizes.
7. Roll out with a feature flag, operator review, and rollback procedure only after full CI and staging tests pass.
