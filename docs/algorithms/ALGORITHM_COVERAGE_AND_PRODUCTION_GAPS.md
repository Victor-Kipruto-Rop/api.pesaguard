# Algorithm Coverage and Production Gaps

This inventory separates a helper's existence from end-to-end integration, persistence, calibration, and production certification.

## Existing algorithm families

| Algorithm | Current code evidence | Important boundary |
|---|---|---|
| Decimal/minor-unit money comparison | algorithmic_intelligence.py; tests | Currency precision must be explicit; reject invalid precision. |
| Reference normalization | Helper + tests | Candidate hint only; punctuation-insensitive similarity must not authorize a match. |
| Tenant/provider-scoped transaction identity | Helper + tests | Database uniqueness and atomic insertion are still required. |
| Payload fingerprint and replay classification | Canonical fingerprint helper plus EventStore duplicate/conflict classification and regression tests | Conflicts are audited/quarantined when an existing scoped transaction is found; verify live PostgreSQL concurrency, legacy rows with undecryptable payloads, and all ingestion paths before certification. |
| Candidate evidence scoring | Helper + tests | Ranking score is not a probability; missing time evidence is not positive evidence. |
| Ambiguity-safe selection | Algorithm helpers and reconciliation engine guardrails | Close/tied candidates go to review; thresholds need labeled evaluation. |
| Partial-payment aggregation | Helper + tests | Use confirmed tenant-scoped rows; aggregation does not post to the ledger. |
| Settlement subset investigation | Bounded exact subset search + tests | Unique subsets remain candidates requiring approval; ambiguity and size limits go to review. |
| Settlement variance decomposition | Helper + tests | Unknown residuals are exposed, never auto-adjusted. |
| Reversal lifecycle validation | Existing helper plus new transaction_lifecycle_algorithms.py and focused tests | New helper checks linkage, scope, chronology, duplicate IDs, and cumulative confirmed amounts; still advisory-only and not wired into the persisted lifecycle. |
| Robust amount anomaly detection | Median/MAD helper and risk-feature integration | Comparable baseline required; outlier is a review signal, not a fraud verdict. |
| Velocity screening | Trailing-window helper + tests | Caller must provide tenant/entity-scoped history and consistent timestamps. |
| Window-change detection | Helper + tests | Monitoring signal; seasonality and baseline size matter. |
| Batch data-quality profile | Helper + tests | Counts findings; does not itself quarantine, repair, or persist rows. |
| Transaction-quality gate | Helper + shadow hook + enforced in `ReconciliationEngine.reconcile` after normalization | Critical/high quality findings return `EXCEPTION` with structured evidence before candidate selection. Regression tests: `tests/test_reconciliation_quality_gate.py`. Still verify all alternate ingestion/legacy paths and persistence/audit behavior. |
| Missing ledger timestamp guard | Enforced in `ReconciliationEngine.reconcile` before exact matching | A candidate with matching reference, amount, and compatible phone but no ledger timestamp returns `EXCEPTION` with `ledger_timestamp_missing` and `manual_review_required`; absence of time evidence cannot authorize an automatic match. Regression tests: `tests/test_reconciliation_missing_ledger_timestamp.py`. Verify legacy entry points and persisted evidence before certification. |
| Risk scoring | Explainable weighted rules and existing fraud features | Not calibrated probability; never auto-decline or refund based on score alone. |
| Ground-truth evaluation | reconciliation_evaluation.py | Needs finance-reviewed representative labels; scorecard does not certify production. |
| Seasonal amount assessment | advanced_reconciliation_algorithms.py (new) | Same weekday/hour/currency cohort; tenant/account scoping remains caller responsibility. |
| Distribution-shift detection | advanced_reconciliation_algorithms.py (new) | Monitoring signal only; windows must be comparable and seasonally aligned. |
| Global one-to-one batch assignment | batch_reconciliation_assignment.py (new) | Bounded exact proposal; ambiguous/oversized batches fail closed; live-engine integration and tenant-safe candidate retrieval remain separate release gates. |
| Persisted reversal lifecycle review gate | reversal_lifecycle_integration.py + reconciliation_job.py | Tenant/provider/account-scoped history is attached to the reconciliation audit/outbox; missing, ambiguous, unknown-status, over-limit, or excessive reversal evidence routes to EXCEPTION. Review-only: no posting authority or concurrency protection. |\n| Settlement delay intelligence | settlement_delay_algorithms.py + focused tests | Robust median/MAD and upper-quantile threshold over confirmed peer-cohort settlement durations; insufficient history returns unknown. Advisory only; provider calendars and tenant-scoped history retrieval remain caller responsibilities. |

## Gaps to close before production certification

### P0 — correctness and financial safety

1. **Missing ledger-time evidence:** the class-based engine now fails closed when reference/amount evidence points to a ledger row whose timestamp is absent. Run the new regression tests and verify every alternate ingestion and persistence path follows the same policy.
2. **One ingestion contract:** the canonical `ReconciliationEngine.reconcile` now applies the normalized transaction-quality gate before candidate selection; verify webhook, retry, batch, worker, and manual replay paths all invoke an equivalent gate and share tenant resolution, normalization, and idempotency. The live matcher fails closed when candidate records explicitly disagree on tenant/provider/account/currency; database retrieval must still be tenant-scoped.
3. **Atomic idempotency:** enforce database uniqueness for tenant + provider/account + external transaction ID and claim it transactionally. In-memory ID sets are not concurrency controls.
4. **Conflicting replay quarantine:** the EventStore now compares canonical fingerprints against the protected original payload, records a deduplicated quarantine/audit event, and returns a distinct conflict result. Still verify all ingestion entry points and PostgreSQL concurrency behavior; do not treat the new unit coverage as certification.
5. **Tenant-safe inputs:** every candidate list, history window, reversal list, settlement batch, and labeled dataset must be scoped to the authenticated tenant and provider/account before the algorithm runs.
6. **Ledger invariants:** keep algorithms in the proposal/exception layer; posting must remain transactional, balanced, idempotent, and auditable.
7. **Reversal lifecycle:** validate original linkage, confirmed cumulative reversals, currency, provider status, and duplicate callbacks in the transaction that records the reversal.

The global batch-assignment helper is currently advisory and is not wired into the live financial posting path. Before integration, prove candidate-query tenant/provider/account/currency scoping, persist the proposal and algorithm version as audit evidence, add concurrency-safe one-to-one posting constraints, and compare it against finance-reviewed ground truth in shadow mode.

### P1 — evaluation and operations

7. Build a privacy-controlled, finance-reviewed ground-truth dataset with unresolved labels and a separate holdout set.
8. Wire the scorecard into a repeatable offline command/CI job; record dataset version, algorithm/config version, cohort counts, metrics, reviewer, and approval.
9. The Kafka reconciliation worker now persists opt-in shadow evidence in the existing outbox payload and a compact audit summary. Verify that persistence in staging and inspect alternate webhook, synchronous API, retry, batch, and manual-replay paths; the helper still does not create a separate analytics table.
10. Measure precision, recall, false-positive rate, coverage, ambiguity/review rate, latency, and missing-data rate by provider/tenant/currency/amount band when sample sizes permit.
11. Monitor baseline freshness, amount distribution, velocity, score distribution, event lag, schema changes, and outlier rates. Stale/undersized baseline means unavailable, not normal.
12. Version thresholds and require regression evaluation, shadow period, approval, gradual rollout, telemetry, and rollback.
13. Alert on conflicting replay spikes, ambiguous-match spikes, reconciliation backlog, unexplained settlement residuals, late events, and algorithm exceptions.

### P2 — advanced intelligence after P0/P1

14. Cross-channel entity graphs, only with reliable lawful identifiers; do not merge accounts based only on shared phone, amount, or location.
15. Seasonality-aware baselines for business hours, weekdays, pay cycles, merchant type, and currency.
16. Provider-specific lifecycle/state-transition anomaly rules, including invalid reversal/original ordering.
17. Settlement arrival-window prediction after provider calendars, merchant schedules, and holidays are configured.
18. Supervised fraud models only after reviewed time-split labels, leakage checks, calibration, explainability, cohort metrics, drift monitoring, and human governance.
19. Graph/unsupervised models as investigative signals only; never auto-freeze funds from uncalibrated anomaly scores.

## Release gates

Do not enable a new automatic decision rule merely because unit tests pass. Require focused tests and full backend CI, migration/concurrency/tenant-isolation tests, shadow runs on staging data, approved holdout metrics, finance review of false positives and negatives, feature-flag rollout, audit evidence, and rollback instructions.

This is a code/design inventory, not a claim that the gates have passed. See Smart Reconciliation Algorithms and Ground-Truth Evaluation.

## Offline algorithm release gate

The reconciliation_release_gate.py helper evaluates the scorecard from reconciliation_evaluation.py against explicit precision, recall, false-positive, review-rate, and minimum-sample thresholds. It blocks promotion when metrics are missing, the sample is too small, the evaluation is not declared a holdout, dataset provenance is missing, or a human reviewer is not named. Default thresholds are deliberately conservative and must be approved for the actual business cohort before use.

This gate is a policy evaluator, not a deployment switch. A PASS applies only to the supplied scorecard; it does not prove representativeness, guarantee future performance, automatically enable a model, or replace staging, shadow evaluation, finance approval, monitoring, and rollback.


## Reversal lifecycle worker wiring

The reconciliation worker now calls `reversal_lifecycle_integration.py` for refund/reversal-shaped events and attaches structured lifecycle evidence to the existing output. See `docs/algorithms/REVERSAL_LIFECYCLE_INTEGRATION.md`. This blocks ordinary successful-match presentation when required evidence is incomplete, but it does not replace transactional locking, idempotency, provider confirmation, or atomic ledger posting.
