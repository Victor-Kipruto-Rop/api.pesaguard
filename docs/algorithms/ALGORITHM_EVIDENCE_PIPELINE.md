# Algorithm Evidence Pipeline

## Purpose

The algorithm_evidence_pipeline.py module composes existing deterministic algorithms
into one tenant-scoped, explainable evidence bundle. It is an advisory service, not
a ledger writer or fraud-decision authority.

## Scope requirements

The caller must derive scope from authenticated server context and database queries,
not trust scope claims in a webhook. Four fields are mandatory: tenant_id, provider,
provider_account_id, and currency. Candidate and history records must carry all four
fields; records with missing scope or any mismatch are excluded and candidate results
are escalated to review.

History queries must already be bounded and scoped by tenant/provider/account/currency.
Velocity history additionally requires a stable tenant-local entity_key; use a keyed
hash rather than returning phone numbers or direct identifiers. Never mix currencies
in amount baselines.

## Evidence returned

- Transaction quality findings from the existing validation primitive.
- Candidate ranking and explicit ambiguity/scope exclusions.
- Same-local-weekday/hour seasonal amount assessment, or an explicit unknown state
  when the baseline is insufficient.
- Rolling-window velocity assessment for one supplied entity key.
- Explainable bounded risk triage with active signals and algorithm version.
- Explicit indicators that the score is not a probability and no automatic financial
  action was taken.

The response deliberately excludes raw history records and does not return a phone
number. Risk levels are triage hints only; no funds are frozen, declined, refunded,
or posted by this module.

## Integration and rollout gates

This module is not automatically wired into authoritative posting. To integrate it:
1. Call it from an existing server-side shadow/advisory hook after tenant identity is
   authenticated and before the financial decision is committed.
2. Retrieve bounded history using database predicates for tenant, provider, account,
   currency, and (for velocity) the entity key.
3. Persist output with transaction ID, scope IDs, algorithm version, config version,
   timestamp, and request/correlation ID in an append-only audit record.
4. Keep legacy matching and posting authoritative during shadow mode.
5. Compare predictions with finance-reviewed, time-separated ground truth; measure
   precision, recall, false-positive rate, coverage, review rate, latency, and drift.
6. Require concurrency, tenant-isolation, replay, and reversal tests plus full CI and
   staging sign-off before considering any decision-path change.
7. Roll out with a feature flag, telemetry, approval record, and documented rollback.

## Limitations

A unit-tested algorithm bundle does not prove production readiness. Database
constraints, all ingestion paths, real data access scoping, durable audit writes,
runtime feature flags, provider integration, and deployment must be independently
verified. Insufficient or stale history is unknown, never evidence that a transaction
is safe.
