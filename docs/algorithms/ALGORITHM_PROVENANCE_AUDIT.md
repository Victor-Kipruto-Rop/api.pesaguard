# Durable Algorithm Provenance

## Purpose

The reconciliation worker now attaches a versioned algorithm-provenance-v1 envelope
to both the published reconciliation result and the durable audit details. It captures
only metadata already present in the evaluation; absent versions remain null rather
than being guessed.

## Captured fields

- Reconciliation engine version and resulting status.
- Stable, deduplicated matching reason codes.
- Whether evidence and shadow-analysis metadata were actually supplied.
- Shadow algorithm version, availability, and whether the legacy decision remained
  unchanged.
- Risk algorithm version and risk level when the upstream assessment supplies them.
- Explicit authority boundaries: shadow analysis is advisory, risk is triage-only,
  and this provenance envelope does not authorize movement of funds.

## Important boundaries

This is an auditability improvement, not a new matching algorithm and not a claim
that all upstream algorithms are wired into the live decision path. It does not
invent versions for legacy paths, persist new database columns, or change match
statuses. Existing database transaction handling persists the audit event and
outbox payload atomically.

Before production certification, run the focused tests and complete suite, then
verify on staging that persisted audit records and outbox events contain the
expected envelope for legacy, shadow-enabled, missing-evidence, and risk-assessment
cases. Also verify tenant isolation, idempotency under concurrent PostgreSQL
workers, replay quarantine, and rollback behavior.
