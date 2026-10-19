"""Conservative transaction-lifecycle validation for reconciliation proposals.

This pure helper validates confirmed reversal/refund evidence against an original
payment. It is advisory: it never posts a ledger entry, issues a refund, mutates
transactions, or replaces database constraints and authorization.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation
import re
from typing import Any, Mapping, Sequence

ALGORITHM_VERSION = "transaction-lifecycle-v1"
_CONFIRMED = {"success", "successful", "completed", "confirmed", "settled", "paid"}
_PENDING = {"pending", "processing", "initiated", "queued"}
_REVERSAL_TYPES = {"reversal", "refund", "reversed", "refunded"}


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _money(value: Any) -> Decimal | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError):
        return None
    if not amount.is_finite():
        return None
    return amount


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    # Naive timestamps are not silently assigned a timezone in financial
    # lifecycle comparisons: callers must normalize provider-local times first.
    return parsed if parsed.tzinfo is not None else None


def validate_reversal_lifecycle(
    original: Mapping[str, Any],
    reversal_events: Sequence[Mapping[str, Any]],
    *,
    currency: str | None = None,
) -> dict[str, Any]:
    """Validate confirmed reversals against one original payment.

    Expected original keys: transaction_id (or TransID), amount (or
    TransAmount), currency, timestamp, status. Reversal rows require a stable
    transaction_id (or TransID), original_transaction_id (or OriginalTransID),
    amount (or TransAmount), currency, timestamp, status, and optionally type.

    Only confirmed reversal events contribute to the cumulative amount. Pending
    events are reported separately. Any malformed confirmed event, duplicate
    event ID, scope/link mismatch, event preceding the original, or cumulative
    over-reversal yields REVIEW_REQUIRED. Missing/unknown source data is never
    treated as proof that the lifecycle is valid.
    """
    reasons: list[str] = []
    original_id = _text(original.get("transaction_id") or original.get("TransID"))
    original_amount = _money(original.get("amount", original.get("TransAmount")))
    original_currency = _text(currency or original.get("currency") or original.get("Currency")).upper()
    original_time = _timestamp(original.get("timestamp") or original.get("TransTime"))
    original_status = _text(original.get("status") or original.get("ResultDesc")).casefold()

    if not original_id:
        reasons.append("original_transaction_id_missing")
    if original_amount is None or original_amount <= 0:
        reasons.append("original_amount_invalid")
    if not re.fullmatch(r"[A-Z]{3}", original_currency):
        reasons.append("original_currency_invalid")
    if original_time is None:
        reasons.append("original_timestamp_missing_or_invalid")
    if original_status not in _CONFIRMED:
        reasons.append("original_payment_not_confirmed")

    seen_ids: set[str] = set()
    confirmed_ids: list[str] = []
    pending_count = 0
    total = Decimal("0")
    evaluated_count = 0

    for index, event in enumerate(reversal_events):
        if not isinstance(event, Mapping):
            reasons.append(f"event_{index}_malformed")
            continue
        event_id = _text(event.get("transaction_id") or event.get("TransID"))
        linked_id = _text(
            event.get("original_transaction_id")
            or event.get("OriginalTransID")
            or event.get("OriginalTransactionID")
        )
        event_type = _text(event.get("type") or event.get("transaction_type") or event.get("TransactionType")).casefold()
        event_status = _text(event.get("status") or event.get("ResultDesc")).casefold()
        event_amount = _money(event.get("amount", event.get("TransAmount")))
        event_currency = _text(event.get("currency") or event.get("Currency") or original_currency).upper()
        event_time = _timestamp(event.get("timestamp") or event.get("TransTime"))

        if not event_id:
            reasons.append(f"event_{index}_transaction_id_missing")
            continue
        if event_id in seen_ids:
            reasons.append("duplicate_reversal_event_id")
            continue
        seen_ids.add(event_id)

        # If a type is supplied, it must describe a reversal/refund. Do not
        # infer a reversal from amount sign or free-form provider descriptions.
        if event_type and event_type not in _REVERSAL_TYPES:
            reasons.append(f"event_{event_id}_type_not_reversal")
            continue
        if linked_id != original_id:
            reasons.append(f"event_{event_id}_original_link_mismatch")
            continue
        if event_status in _PENDING:
            pending_count += 1
            continue
        if event_status not in _CONFIRMED:
            reasons.append(f"event_{event_id}_status_unrecognized")
            continue
        evaluated_count += 1
        if event_amount is None or event_amount <= 0:
            reasons.append(f"event_{event_id}_amount_invalid")
            continue
        if not re.fullmatch(r"[A-Z]{3}", event_currency):
            reasons.append(f"event_{event_id}_currency_invalid")
            continue
        if event_currency != original_currency:
            reasons.append(f"event_{event_id}_currency_mismatch")
            continue
        if event_time is None:
            reasons.append(f"event_{event_id}_timestamp_missing_or_invalid")
            continue
        if original_time is not None and event_time < original_time:
            reasons.append(f"event_{event_id}_precedes_original")
            continue
        total += event_amount
        confirmed_ids.append(event_id)

    if original_amount is not None and original_amount > 0 and total > original_amount:
        reasons.append("cumulative_reversal_exceeds_original_amount")

    # Stable ordering makes results reproducible and easy to diff in audit logs.
    reasons = sorted(set(reasons))
    valid = not reasons
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "status": "VALIDATED" if valid else "REVIEW_REQUIRED",
        "valid": valid,
        "original_transaction_id": original_id or None,
        "currency": original_currency or None,
        "original_amount": str(original_amount) if original_amount is not None else None,
        "confirmed_reversal_amount": str(total),
        "remaining_net_amount": (
            str(original_amount - total)
            if original_amount is not None and original_amount > 0 and total <= original_amount
            else None
        ),
        "confirmed_reversal_count": len(confirmed_ids),
        "confirmed_reversal_ids": sorted(confirmed_ids),
        "pending_reversal_count": pending_count,
        "evaluated_confirmed_event_count": evaluated_count,
        "reason_codes": reasons,
        "requires_ledger_transaction": True,
        "ledger_mutated": False,
        "human_or_policy_approval_required": True,
    }
