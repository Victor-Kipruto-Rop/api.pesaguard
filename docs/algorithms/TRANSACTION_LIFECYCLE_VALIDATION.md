# Transaction Lifecycle Validation

This helper is advisory only and must not post ledger entries, issue refunds, or mutate payment state. It validates confirmed reversal evidence against an original payment: transaction linkage, duplicate event IDs, currency, timestamps, positive amounts, and cumulative reversal totals. Missing or ambiguous evidence requires review.

## Production gates

- Query reversal history within the authenticated tenant, provider, provider account, and currency.
- Normalize provider-specific statuses before calling a validator.
- Persist sanitized evidence and algorithm version only after an approved integration.
- Compare against finance-reviewed examples including delayed events, duplicate callbacks, partial/full reversals, over-reversals, bad links, and cross-currency records.
- Run focused tests and the full suite. Unit tests do not certify production readiness.

Timestamps must be timezone-aware. Pending events are not counted as confirmed reversals. A valid result means only that the supplied records passed these checks; it does not prove the query was complete or the provider event authentic.
