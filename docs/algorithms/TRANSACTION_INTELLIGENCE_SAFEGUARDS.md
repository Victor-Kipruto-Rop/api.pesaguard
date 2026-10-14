# Transaction intelligence safeguards

## Existing algorithm inventory

The repository already contains deterministic minor-unit money conversion, reference normalization, payload fingerprints, median/MAD amount outlier scoring, conservative match evidence, partial-payment aggregation, velocity screening, settlement variance decomposition, candidate ranking, and window-shift detection in algorithmic_intelligence.py.

## Added safeguards

- **Replay classification** separates new events, identical delivery retries, conflicting payloads reusing an external transaction ID, and insufficient evidence. It scopes comparisons by tenant/provider when present and never treats amount/time similarity as transaction identity.
- **Event-time quality** classifies invalid/missing, future-dated, stale, and current timestamps. Staleness is an operational/data-quality signal, not a fraud verdict.
- **Record-level data-quality profile** reports required-field completeness, amount validity, timestamp quality, and explicitly marks uniqueness as NOT_EVALUATED unless a population-level check is performed.

## Production integration contract

These safeguards are deterministic and dependency-light. They do not alter transactions, issue refunds, or automatically block a payment. Persist results with source event, tenant, algorithm version, and decision timestamp before exposing them to operators.

A CONFLICTING_REPLAY should be quarantined or escalated for review, not silently overwrite the original transaction. An IDENTICAL_REPLAY should be handled by the existing idempotency path. A FUTURE timestamp should fail data-quality validation or be held for review; STALE should be tagged as a late-arriving event. Neither timestamp classification alone proves fraud.

## Calibration and acceptance

- Keep monetary calculations in Decimal/integer minor units.
- Keep matching deterministic and require human review for ambiguous candidates.
- Calibrate risk thresholds against approved, tenant-scoped ground truth before using them for automated holds.
- Measure precision, recall, false-positive rate, false-negative rate, and detection latency on a time-separated validation set.
- Do not describe heuristic scores as fraud probabilities without calibration.
- Do not report a data-quality accuracy score from a single record; accuracy requires trusted ground truth.
