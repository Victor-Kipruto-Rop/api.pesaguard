"""Tenant-scoped, review-only adapter for reversal lifecycle validation.

This adapter connects the pure lifecycle algorithm to persisted transaction evidence.
It never authorizes posting. Call it with a database session and only the authenticated
tenant's event; the query itself is scoped by tenant/provider account/provider.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

try:
    from .normalization import NormalizationError, normalize_timestamp
except ImportError:  # pragma: no cover - top-level service execution
    from normalization import NormalizationError, normalize_timestamp

try:
    from .models import Transaction
    from .transaction_lifecycle_algorithms import assess_reversal_lifecycle
except ImportError:  # pragma: no cover - top-level service execution
    from models import Transaction
    from transaction_lifecycle_algorithms import assess_reversal_lifecycle


_ORIGINAL_KEYS = (
    "OriginalTransID", "OriginalTransactionID", "original_transaction_id",
    "original_reference", "original_ref",
)
_REVERSAL_TYPES = frozenset({"reversal", "refund", "chargeback", "reversed", "refunded"})
_CONFIRMED = frozenset({"confirmed", "complete", "completed", "success", "succeeded"})
_FAILED = frozenset({"failed", "failure", "rejected", "cancelled", "canceled"})


def is_reversal_event(event: Mapping[str, Any]) -> bool:
    """Identify reversal/refund events without classifying ordinary payments."""
    kind = str(
        event.get("transaction_type") or event.get("TransactionType")
        or event.get("type") or event.get("event_type") or ""
    ).strip().casefold()
    return kind in _REVERSAL_TYPES or any(
        event.get(key) not in (None, "") for key in _ORIGINAL_KEYS
    )


def _first(record: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    return next((record.get(key) for key in keys if record.get(key) not in (None, "")), None)


def _normalize_provider_time(value: Any) -> Any:
    """Use the repository's canonical provider-time policy before lifecycle checks."""
    try:
        return normalize_timestamp(value)
    except (NormalizationError, TypeError, ValueError):
        # Preserve the original value so the lifecycle algorithm reports the
        # missing/ambiguous timestamp instead of silently guessing.
        return value


def _row_record(row: Transaction) -> dict[str, Any]:
    payload = row.raw_payload if isinstance(row.raw_payload, Mapping) else {}
    result = dict(payload)
    # Canonical database columns are the source of truth for scope and identity.
    result.update({
        "TransID": row.trans_id,
        "TransAmount": str(row.trans_amount),
        "TransTime": _normalize_provider_time(row.trans_time),
        "tenant_id": row.tenant_id,
        "provider": row.provider,
        "provider_account_id": row.provider_account_id,
        "currency": row.currency,
    })
    # Do not mistake an internal ingestion/reconciliation state for provider
    # confirmation of a financial reversal.
    provider_status = str(
        payload.get("status") or payload.get("reversal_status")
        or payload.get("result_description") or ""
    ).strip().casefold()
    result_code = payload.get("ResultCode", payload.get("result_code"))
    if provider_status in _CONFIRMED or (str(result_code).strip() == "0" and result_code is not None):
        result["status"] = "confirmed"
    elif provider_status in _FAILED or (result_code is not None and str(result_code).strip() not in {"", "0"}):
        result["status"] = "failed"
    elif provider_status in {"pending", "processing", "initiated"}:
        result["status"] = "pending"
    else:
        result["status"] = "unknown"
    return result


def assess_persisted_reversal(
    session: Session,
    event: Mapping[str, Any],
    *,
    tenant_id: str,
    transaction_id: str,
    history_limit: int = 1000,
) -> dict[str, Any] | None:
    """Validate a reversal against persisted same-scope evidence.

    Returns None for ordinary transactions. Incomplete or over-limit evidence
    becomes REVIEW_REQUIRED. This is a reconciliation review gate only: it does
    not provide locks for concurrent reversals, a posting transaction, or posting
    authorization. Any actual reversal/ledger writer must independently enforce
    provider confirmation, idempotency, and cumulative amount limits atomically.
    """
    if not isinstance(event, Mapping) or not is_reversal_event(event):
        return None
    if isinstance(history_limit, bool) or history_limit < 1:
        raise ValueError("history_limit must be a positive integer")

    original_ref = str(_first(event, _ORIGINAL_KEYS) or "").strip()
    account_id = str(
        event.get("provider_account_id") or event.get("BusinessShortCode")
        or event.get("business_short_code") or event.get("account_id") or ""
    ).strip()
    provider = str(event.get("provider") or event.get("provider_name") or "mpesa").strip().casefold()
    currency = str(event.get("currency") or event.get("Currency") or "KES").strip().upper()

    if not tenant_id.strip() or not account_id or not provider:
        return {
            "algorithm_version": "transaction-lifecycle-v1",
            "status": "REVIEW_REQUIRED",
            "review_required": True,
            "can_auto_post": False,
            "reason_codes": ["reversal_scope_context_missing"],
            "original_transaction_id": original_ref or None,
        }

    scoped = session.query(Transaction).filter(
        Transaction.tenant_id == tenant_id,
        Transaction.provider_account_id == account_id,
        Transaction.provider == provider,
    )
    if not original_ref:
        result = assess_reversal_lifecycle(dict(event), None, ())
        result["evidence_source"] = "tenant_scoped_transaction_store"
        result["prior_reversal_rows_considered"] = 0
        return result

    original_row = scoped.filter(Transaction.trans_id == original_ref).first()
    # Filter JSON payloads to the reversal's original reference before applying
    # the safety limit. Counting all account payments would make busy accounts
    # exceed the cap even when they have very few reversals.
    reversal_reference_filters = [
        Transaction.raw_payload[key].as_string() == original_ref
        for key in _ORIGINAL_KEYS
    ]
    rows = (
        scoped.filter(or_(*reversal_reference_filters))
        .order_by(Transaction.created_at.desc())
        .limit(history_limit + 1)
        .all()
    )
    if len(rows) > history_limit:
        return {
            "algorithm_version": "transaction-lifecycle-v1",
            "status": "REVIEW_REQUIRED",
            "review_required": True,
            "can_auto_post": False,
            "reason_codes": ["reversal_history_limit_exceeded"],
            "original_transaction_id": original_ref or None,
            "history_limit": history_limit,
        }

    current = dict(event)
    current.setdefault("TransID", transaction_id)
    current.setdefault("TransAmount", event.get("amount"))
    current.setdefault("tenant_id", tenant_id)
    current.setdefault("provider", provider)
    current.setdefault("provider_account_id", account_id)
    current.setdefault("currency", currency)
    current_time_key = next(
        (key for key in ("TransTime", "timestamp", "created_at", "event_time")
         if current.get(key) not in (None, "")),
        None,
    )
    if current_time_key is not None:
        current[current_time_key] = _normalize_provider_time(current[current_time_key])

    original = _row_record(original_row) if original_row is not None else None
    prior: list[dict[str, Any]] = []
    unknown_prior_status = False
    for row in rows:
        if row.trans_id == transaction_id:
            continue
        record = _row_record(row)
        if str(_first(record, _ORIGINAL_KEYS) or "").strip() != original_ref:
            continue
        if record.get("status") == "unknown":
            unknown_prior_status = True
        prior.append(record)

    result = assess_reversal_lifecycle(current, original, prior)
    if unknown_prior_status:
        result["reason_codes"] = list(dict.fromkeys(
            [*result["reason_codes"], "prior_reversal_provider_status_unknown"]
        ))
        result["status"] = "REVIEW_REQUIRED"
        result["review_required"] = True
    result["can_auto_post"] = False
    result["evidence_source"] = "tenant_scoped_transaction_store"
    result["prior_reversal_rows_considered"] = len(prior)
    return result
