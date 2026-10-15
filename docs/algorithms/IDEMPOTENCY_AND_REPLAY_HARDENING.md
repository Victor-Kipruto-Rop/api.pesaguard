# Idempotency and replay hardening

## Change implemented

The fallback key builder in `pesaguard_backend_pipeline/idempotency.py` now:

- Uses `Decimal` and rejects invalid, non-finite, or missing amounts instead of converting malformed money to `0.00`.
- Canonicalizes timezone-aware ISO-8601 timestamps to UTC, and rejects ambiguous timezone-naive timestamps.
- Validates compact Daraja timestamps instead of accepting malformed 14-digit strings.
- Includes available provider-account, reference, phone, and currency facts in the fallback fingerprint.
- Accepts the canonical transaction ID aliases at the boundary and prefers a provider transaction ID when present.
- Has regression tests for large decimal values, equivalent timestamps, invalid payloads, and account/reference separation.

## Financial safety boundary

An idempotency key is not proof that two payloads are the same transaction. The durable ingestion path must continue to:

1. Resolve tenant and provider-account identity from trusted context, not from untrusted client claims alone.
2. Enforce database uniqueness and atomic insertion inside a transaction.
3. Compare canonical payload fingerprints when a scoped identity already exists.
4. Classify an identical replay as a no-op and a conflicting replay as a durable quarantine/audit event.
5. Publish side effects through the transactional outbox after durable state is committed.

The fallback key exists for compatibility with older events that lack a provider transaction ID. Similar-looking payments may be legitimate; therefore, fallback collisions must never authorize automatic ledger posting or be treated as conclusive duplicate evidence.

## Validation status

The tests in `tests/test_idempotency_hardening.py` are added but must run in the repository CI/runtime. No claim is made here that PostgreSQL concurrency, all provider callbacks, or production migrations have been certified by these unit tests.
