# Seasonality-aware transaction intelligence

## Status and purpose

The pure helper in `pesaguard_backend_pipeline/seasonality_aware_baseline.py` compares a numeric observation (for example transaction amount, hourly transaction count, or processing latency) with historical observations from a comparable seasonal cohort. It uses median and median absolute deviation (MAD), not mean/standard deviation, to reduce sensitivity to a few extreme historical values.

**This is an advisory signal only.** It is not a calibrated fraud probability and must not alone trigger payment rejection, account freezes, refunds, settlement adjustments, or ledger postings.

## Cohort fallback

The default cohort priority is:

1. Same weekday and hour.
2. Same hour across weekdays.
3. Same weekday across hours.
4. All observations in the lookback window.

The first cohort with the configured minimum sample count is used. The result records the selected cohort. If no cohort has sufficient data, `ready=false` and `anomalous=null`: missing evidence is not interpreted as normal activity.

## Robust score

For a non-zero MAD:

`modified_z = (observation - median(history)) / (1.4826 * MAD(history))`

The default absolute threshold is 3.5, a configurable investigation threshold rather than a fraud boundary. When MAD is zero, an exact baseline value is considered within baseline; any deviation is a review signal with no fabricated infinite score.

## Input contract and safeguards

- Supply only history already scoped to the same tenant, provider, merchant account, currency, and metric definition. The helper cannot prove caller authorization or tenant scope.
- Timestamps must be timezone-aware. Normalize provider-specific local timestamps at ingestion; do not mix event time with ingestion time.
- Only observations strictly before the target timestamp and within the lookback window are included, preventing future leakage.
- Invalid historical rows are ignored. Track input quality and history freshness separately at the caller.
- Minimum sample count defaults to 12 and cannot be set below 5.
- Output includes algorithm version, readiness, selected cohort, sample count, median, MAD, score, threshold, and reason code for auditability.
- Persist assessment metadata and a stable input/dataset version in the owning service if results must be reproducible.

## Safe integration plan

1. Invoke from a tenant-scoped monitoring/risk worker after normalization and authorization.
2. Start in shadow mode and store outputs alongside existing decisions; do not change legacy matching or transaction states.
3. Compare alerts against finance-reviewed labels and inspect false positives by provider, currency, transaction size, merchant category, and business cycle.
4. Monitor baseline sample count, freshness, cohort fallback, alert rate, and score distribution.
5. Version configuration and thresholds; require reviewer approval, offline holdout evaluation, gradual feature-flag rollout, and rollback before any decision-path change.
6. Never represent the score as probability or a definitive fraud classification.

## Verification

```powershell
$env:PYTHONPATH = "."
pytest -q pesaguard_backend_pipeline/tests/test_seasonality_aware_baseline.py
pytest -q
python -m compileall -q pesaguard_backend_pipeline
```

Focused tests should be run by CI. Full suite, production integration, persistent audit evidence, and cohort calibration remain separate release gates.
