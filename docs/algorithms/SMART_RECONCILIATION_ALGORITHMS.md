# Smart Reconciliation Algorithms

## Scope and activation boundary

`pesaguard_backend_pipeline/smart_reconciliation_algorithms.py` provides deterministic, pure-Python algorithm primitives. The current change is additive: it does **not** replace the existing reconciliation engine's decision path, authorize refunds, block payments, or claim fraud probabilities. The engine has an opt-in shadow hook controlled by tenant settings at `reconciliation.smart_algorithms_shadow_enabled`; the default is disabled. Shadow output is attached to the internal evaluation result and does not change the legacy status or match. It is not persisted as a separate analytics record by this change.

## Scope-preservation hardening

The shadow adapter now carries the resolved tenant ID into the candidate ranker and
normalizes explicitly supplied provider, provider-account, and currency aliases from
the event and candidate records. Explicitly conflicting metadata is excluded from
ranking and yields a review signal. Missing metadata is not silently invented; the
connector/database query must still enforce tenant and provider-account scoping.

Regression coverage includes tenant, provider, account, and currency conflicts plus a
valid same-scope candidate. These checks exercise shadow analysis only and do not
change the established reconciliation result. They do not replace tenant-scoped SQL,
database constraints, authorization, or concurrency tests.

## Included algorithms

| Algorithm | Method | Output and safe use |
|---|---|---|
| Tenant-scoped transaction fingerprint | SHA-256 over provider + provider transaction ID; fallback requires finite amount, timezone-aware timestamp, and reference or phone | Weak/incomplete fallback payloads raise an error rather than collapsing into a shared fingerprint. A fallback fingerprint is not proof of duplication. |
| Candidate evidence scoring | Weighted reference, amount, timestamp, and phone evidence | Ranking signal with explicit conflicts. Score is not a probability. |
| Ambiguity detection | Deterministic ranking + configurable top-score margin | Emits `REVIEW` when top candidates are too close; never guesses between tied ledger rows. |
| Amount outlier detection | Median absolute deviation (MAD), modified z-score | Flags unusual amounts for review; requires a minimum sample count and reports insufficient-data state. |
| Explainable risk triage | Bounded weighted rules | Returns score, tier, active signals, and review action. It does not auto-decline a transaction. |
| Rolling-window velocity | Count events in a caller-selected window | Detects volume threshold breaches. Caller must scope input to a tenant and entity such as account/phone. |
| Transaction data-quality gate | Required ID, finite positive amount, timezone-aware timestamp, reference | Separates malformed/incomplete events from candidates for automatic matching. |

## Integration contract

1. Normalize provider callbacks at the integration boundary. Preserve the raw event and its provenance separately.
2. Require a non-empty `tenant_id` for fingerprinting. Never compare hashes across tenants.
3. Store the algorithm version and explainable evidence with any shadow result. Do not store full phone numbers in algorithm telemetry.
4. Enable `tenant_settings.reconciliation.smart_algorithms_shadow_enabled = true` only in a controlled non-production tenant first. Run the current engine and the new ranker side-by-side on the same tenant-scoped candidate set. The feature is disabled by default; do not let shadow results change transaction status.
   - The Kafka worker passes the resolved tenant ID separately from the settings document; the settings store does not need to duplicate that identity inside its JSON configuration.
   - When enabled, the worker stores shadow output in the existing reconciliation outbox payload and writes a compact summary into the audit record in the same transaction.
   - The audit summary contains the algorithm version, candidate decision/ambiguity, and risk tier/score; raw phone numbers are not copied into shadow telemetry.
   - A failed shadow calculation is recorded as unavailable and must not fail the established reconciliation decision.
   - This is not a separate queryable analytics table. Verify persistence and behavior in staging, and inspect alternate ingestion paths independently.
5. Compare proposed outcomes against approved, reviewed ground truth using the existing certification process. Report precision, recall, false positives, false negatives, ambiguous-match rate, and latency by tenant/provider/amount band.
6. Review false positives and false negatives with finance operators. Keep thresholds tenant-configurable only after approval and change audit.
7. Enable any decision-path change gradually behind a feature flag, with an immediate rollback to the existing engine.
8. Keep human approval for refund/reversal, settlement, and other irreversible financial actions.

## Operational constraints

- The score is a deterministic ranking heuristic, not a calibrated probability.
- Outlier detection is not ready until the minimum number of valid observations exists; do not treat an empty result as normality.
- Velocity detection is only correct when the caller supplies the correct tenant/entity history and uses consistent UTC timestamps.
- ISO timestamps without an explicit timezone are rejected as ambiguous. Normalize timestamps before calling.
- Exact provider transaction IDs should be the primary idempotency key. Fallback fingerprints require a finite amount, timezone-aware timestamp, and reference or phone; incomplete payloads are rejected. Fallback fingerprints can still collide and are investigative hints only.
- Do not use unsupervised anomaly results as sole evidence of fraud or as the sole reason to hold customer funds.
- Retain tenant isolation, audit records, idempotency, and existing authorization controls.

## Verification

Run from the repository root:

```powershell
$env:PYTHONPATH = "."
pytest -q pesaguard_backend_pipeline/tests/test_smart_reconciliation_algorithms.py
pytest -q
python -m compileall -q pesaguard_backend_pipeline
```

The focused tests cover deterministic/tenant-scoped fingerprints, normalized fallback fingerprints, explicit candidate conflicts, tie handling, MAD outliers and zero-MAD behavior, bounded risk scores, rolling windows, invalid timestamps, data-quality findings, and opt-in shadow integration that asserts the legacy decision is unchanged. Full-suite and production certification results must be recorded from an actual run; they are not implied by adding these tests.
