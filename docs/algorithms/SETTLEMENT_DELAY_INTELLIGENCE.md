# Settlement Delay Intelligence

## Purpose

`pesaguard_backend_pipeline/settlement_delay_algorithms.py` adds a deterministic,
explainable **advisory** check for unusually slow settlement. It compares the
current elapsed settlement duration with a historical peer cohort and emits
`INVESTIGATE_SETTLEMENT_DELAY` only when the baseline is sufficiently populated
and the current duration exceeds a robust upper threshold.

It does not mark a settlement failed, retry a transfer, initiate a refund, post a
ledger entry, or move funds.

## Algorithm

1. Validate a non-negative finite current duration and explicit tenant/provider/
   account/currency scope.
2. Discard invalid historical durations and report how many were discarded.
3. Return `ready=false` and `is_late=null` until at least the configured number
   of valid historical samples exists. Missing data is not interpreted as healthy.
4. Compute the historical median, median absolute deviation (MAD), and configured
   upper quantile.
5. Set the advisory threshold to the greater of the upper quantile and
   `median + multiplier * 1.4826 * MAD`, plus a minimum grace period.
6. Emit an investigation signal if the current duration is strictly greater than
   that threshold.

The default minimum history is 8 samples, quantile is 0.90, MAD multiplier is 3,
and grace period is 300 seconds. These are engineering defaults, not calibrated
business SLAs; review them against provider contracts and tenant settlement patterns.

## Integration contract

- Query history from confirmed settlement records only, using the same definition
  of start/end timestamps and the same tenant, provider, provider account, currency,
  settlement type, and relevant service cohort.
- Do not pass mixed-tenant history. The function requires scope identifiers to be
  declared, but cannot verify how the caller queried the database.
- Normalize event times upstream and compute elapsed seconds from authoritative
  timestamps. Account for provider cutoffs, weekends, Kenyan public holidays, and
  provider-specific calendars upstream where appropriate; raw elapsed seconds do
  not model business-day SLAs.
- Persist the algorithm version, threshold, sample count, cohort metadata, and
  signal in the existing audit/observability mechanism. Avoid logging customer
  phone numbers or raw provider payloads.
- Treat this as a monitoring/review signal. Never automatically freeze funds,
  declare a payment failed, retry, refund, or post a ledger adjustment from this
  result alone.
- Add a tenant-scoped feature flag, staging shadow run, finance-reviewed holdout
  evaluation, false-positive review, alert-deduplication, and rollback before
  connecting it to operational notifications.

## Verification

Run from the repository root:

```powershell
$env:PYTHONPATH = "."
pytest -q pesaguard_backend_pipeline/tests/test_settlement_delay_algorithms.py
pytest -q
python -m compileall -q pesaguard_backend_pipeline
```

Focused tests cover insufficient history, normal and extreme delays, invalid
history, scope/configuration validation, normalization, and non-finite inputs.
Tests authored in this change must be executed in CI; this document does not imply
that CI or production validation has passed.
