# Algorithm Coverage and Production Gaps

This inventory separates a helper's existence from end-to-end integration, persistence, calibration, and production certification.

## Existing algorithm families

| Algorithm | Current code evidence | Important boundary |
|---|---|---|
| Decimal/minor-unit money comparison | `algorithmic_intelligence.py`; tests | Currency precision must be explicit; reject invalid precision. |
| Reference normalization | Helper + tests | Candidate hint only; punctuation-insensitive similarity must not authorize a match. |
| Tenant/provider-scoped transaction identity | Helper + tests | Database uniqueness and atomic insertion are still required. |
| Payload fingerprint and replay classification | Helper + tests | Requires persisted prior fingerprint scoped to tenant/provider/account. |
| Candidate evidence scoring | Helper + tests | Ranking score is not a probability; missing time evidence is not positive evidence. |
| Ambiguity-safe selection | Algorithm helpers and reconciliation engine guardrails | Close/tied candidates go to review; thresholds need labeled evaluation. |
| Partial-payment aggregation | Helper + tests | Use confirmed tenant-scoped rows; aggregation does not post to the ledger. |
| Settlement subset investigation | Bounded exact subset search + tests | Unique subsets remain candidates requiring approval; ambiguity and size limits go to review. |
| Settlement variance decomposition | Helper + tests | Unknown residuals are exposed, never auto-adjusted. |
| Reversal validation | Helper + tests | Must use confirmed reversals for the same account; helper does not issue refunds. |
| Robust amount anomaly detection | Median/MAD helper and risk-feature integration | Comparable baseline required; outlier is a review signal, not a fraud verdict. |
| Velocity screening | Trailing-window helper + tests | Caller must provide tenant/entity-scoped history and consistent timestamps. |
| Window-change detection | Helper + tests | Monitoring signal; seasonality and baseline size matter. |
| Batch data-quality profile | Helper + tests | Counts findings; does not itself quarantine, repair, or persist rows. |
| Transaction-quality gate | Helper + shadow hook | Confirm every actual ingestion route applies equivalent validation before financial state changes. |
| Risk scoring | Explainable weighted rules and existing fraud features | Not calibrated probability; never auto-decline or refund based on score alone. |
| Ground-truth evaluation | `reconciliation_evaluation.py` added in this change | Needs finance-reviewed representative labels; scorecard does not certify production. |

## Gaps to close before production certification

### Completed in the current safety branch

- Removed synthetic reference evidence: provider transaction IDs and local database row IDs are not merchant references.
- Missing references fail the automatic-match quality gate.
- Multiple ledger rows with the same reference are routed to review as ambiguous candidates rather than being counted as duplicate provider payments.
- Added focused regression tests for these false-match and status-semantics cases; execution remains pending CI/local test evidence.

### P0 — correctness and financial safety

1. **One ingestion contract:** verify webhook, retry, batch, worker, and manual replay paths share tenant resolution, validation, normalization, and idempotency.
2. **Atomic idempotency:** enforce database uniqueness for tenant + provider/account + external transaction ID and claim it transactionally. In-memory ID sets are not concurrency controls.
3. **Conflicting replay quarantine:** persist the original canonical payload fingerprint; distinguish identical retries from same-ID/different-payload conflicts before a second side effect.
4. **Tenant-safe inputs:** every candidate list, history window, reversal list, settlement batch, and labeled dataset must be scoped to the authenticated tenant and provider/account before the algorithm runs.
5. **Ledger invariants:** keep algorithms in the proposal/exception layer; posting must remain transactional, balanced, idempotent, and auditable.
6. **Reversal lifecycle:** validate original linkage, confirmed cumulative reversals, currency, provider status, and duplicate callbacks in the transaction that records the reversal.

### P1 — evaluation and operations

7. Build a privacy-controlled, finance-reviewed ground-truth dataset with unresolved labels and a separate holdout set.
8. Wire the scorecard into a repeatable offline command/CI job; record dataset version, algorithm/config version, cohort counts, metrics, reviewer, and approval.
9. Verify whether shadow analysis is durably persisted by every caller; returned output alone is not an audit record.
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

This is a code/design inventory, not a claim that the gates have passed. See [Smart Reconciliation Algorithms](SMART_RECONCILIATION_ALGORITHMS.md) and [Ground-Truth Evaluation](RECONCILIATION_GROUND_TRUTH_EVALUATION.md).


## Offline algorithm release gate

`pesaguard_backend_pipeline/reconciliation_release_gate.py` evaluates the scorecard
from `reconciliation_evaluation.py` against explicit precision, recall, false-positive,
review-rate, and minimum-sample thresholds. It blocks promotion when metrics are missing,
the sample is too small, the evaluation is not declared a holdout, dataset provenance is
missing, or a human reviewer is not named. Default thresholds are deliberately
conservative and must be approved for the actual business cohort before use.

This gate is a policy evaluator, not a deployment switch. A PASS applies only to the
supplied scorecard; it does not prove representativeness, guarantee future performance,
automatically enable a model, or replace staging, shadow evaluation, finance approval,
monitoring, and rollback.
