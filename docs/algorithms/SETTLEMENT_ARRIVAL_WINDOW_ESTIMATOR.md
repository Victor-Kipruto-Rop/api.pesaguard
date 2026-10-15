# Settlement Arrival-Window Estimator

## Purpose

`pesaguard_backend_pipeline/settlement_arrival_algorithms.py` estimates an empirical settlement-duration window from prior provider-confirmed settlements. It returns the median and empirical 90th-percentile durations, plus timestamps derived from the transaction's `expected_at` value. It is a monitoring and prioritization signal for finance operators, not a promise about when funds will arrive.

## Scope and data contract

The caller must pass an explicit, authorized cohort scope containing all four non-empty fields: `tenant_id`, `provider`, `account_id`, and `currency`. Every historical observation must match all four values exactly. The estimator does not fetch history itself; callers must use tenant-authorized, provider/account-scoped queries and must not pass mixed-tenant data.

Each observation requires:

- `tenant_id`, `provider`, `account_id`, and `currency`
- `status`, using provider-confirmed settlement statuses only (default allowlist: `SETTLED`, `CONFIRMED`, `COMPLETED`)
- `initiated_at` and `settled_at`, both timezone-aware ISO-8601 strings or aware `datetime` values

`SUCCESS` is deliberately not accepted by default because payment success is not necessarily proof that settlement completed. Configure `confirmed_statuses` only after verifying the provider's authoritative settlement contract.

## Algorithm

1. Validate request times, required scope, and configuration.
2. Exclude missing or conflicting scope, unconfirmed statuses, naive/invalid timestamps, negative durations, future settlement timestamps, and observations older than the configured history horizon.
3. Require at least `minimum_samples` valid observations (default 20) and `history_complete=True`. An undersized or potentially truncated baseline returns `ready=false`, `status=UNAVAILABLE`, null ETAs, and explicit reason codes.
4. Compute linearly interpolated empirical p50 and p90 durations from `settled_at - initiated_at`.
5. Add those durations to the current transaction's `expected_at`. Report `WITHIN_TYPICAL_WINDOW`, `BEYOND_MEDIAN_WITHIN_P90`, or `PAST_HISTORICAL_P90_REVIEW` according to the observed clock time.

The p90 is a historical quantile, **not a 90% guarantee** and not a calibrated probability. It is sensitive to provider changes, weekends, holidays, pay cycles, and cohort composition. The current version does not model calendars or seasonality; compare like-for-like cohorts before relying on the estimate.

## Safety boundaries

- The result is `mode=advisory_only` and always sets `can_auto_settle=false` and `can_post_ledger=false`.
- The estimator never changes transaction status, settlement state, balances, or ledger entries.
- Do not auto-release funds, create settlement entries, charge fees, or notify customers of a guaranteed arrival time based on this result.
- A stale or incomplete baseline is unavailable, not normal.
- Caller-side tenant authorization, database scope filters, audit persistence, metrics, and retention controls remain required.
- This is not yet connected to a live settlement workflow. Integration requires an authorized history query, versioned evidence persistence, provider-calendar validation, operational telemetry, and staging/holdout evaluation.

## Verification

From the repository root:

```powershell
$env:PYTHONPATH = "."
pytest -q pesaguard_backend_pipeline/tests/test_settlement_arrival_algorithms.py
pytest -q
python -m compileall -q pesaguard_backend_pipeline
```

Focused tests cover cohort isolation, status semantics, incomplete/undersized history, timestamp quality, stale/future events, late-window classification, and the invariant that the algorithm cannot authorize posting. The focused test file is not evidence that the full suite or production deployment has passed.
