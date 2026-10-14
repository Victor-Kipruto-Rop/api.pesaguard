"""Production-safe reconciliation algorithms for settlement batches and reversals.

These pure functions produce auditable findings only. They do not post journal
entries, mutate balances, or infer identity from amount/time coincidences.
Callers must persist results with tenant-scoped uniqueness and authorization.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Mapping, Sequence


def _minor_units(value: Any, *, decimal_places: int = 2) -> int:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("amount must be a finite decimal number") from exc
    if not amount.is_finite():
        raise ValueError("amount must be a finite decimal number")
    if decimal_places < 0 or decimal_places > 6:
        raise ValueError("decimal_places must be between 0 and 6")
    quantum = Decimal(1).scaleb(-decimal_places)
    return int(amount.quantize(quantum, rounding=ROUND_HALF_UP).scaleb(decimal_places))


def _first(record: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = record.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _currency(record: Mapping[str, Any], default: str = "KES") -> str:
    return _first(record, "Currency", "currency").upper() or default


def reconcile_settlement_batch(
    expected_transactions: Sequence[Mapping[str, Any]],
    settlement_items: Sequence[Mapping[str, Any]],
    *,
    currency: str = "KES",
    decimal_places: int = 2,
) -> dict[str, Any]:
    """Reconcile a provider settlement against expected transactions by ID.

    Exact transaction identifiers are the join key. Duplicate IDs, unknown
    settlement rows, missing rows, currency mismatches and amount differences
    remain explicit exceptions. Totals use integer minor units. This function
    never creates a balancing adjustment or treats a batch total as proof that
    individual transactions match.
    """
    target_currency = str(currency or "KES").strip().upper()
    if not target_currency:
        raise ValueError("currency is required")

    expected: dict[str, dict[str, Any]] = {}
    duplicate_expected: set[str] = set()
    invalid_expected: list[dict[str, Any]] = []
    for index, row in enumerate(expected_transactions):
        txid = _first(row, "TransID", "transaction_id", "external_transaction_id")
        if not txid:
            invalid_expected.append({"index": index, "reason": "missing_transaction_id"})
            continue
        if txid in expected:
            duplicate_expected.add(txid)
            continue
        try:
            amount = _minor_units(row.get("TransAmount", row.get("amount")), decimal_places=decimal_places)
        except ValueError:
            invalid_expected.append({"index": index, "transaction_id": txid, "reason": "invalid_amount"})
            continue
        expected[txid] = {"amount_minor_units": amount, "currency": _currency(row, target_currency)}

    observed: dict[str, dict[str, Any]] = {}
    duplicate_observed: set[str] = set()
    invalid_observed: list[dict[str, Any]] = []
    for index, row in enumerate(settlement_items):
        txid = _first(row, "TransID", "transaction_id", "external_transaction_id")
        if not txid:
            invalid_observed.append({"index": index, "reason": "missing_transaction_id"})
            continue
        if txid in observed:
            duplicate_observed.add(txid)
            continue
        try:
            amount = _minor_units(row.get("TransAmount", row.get("amount")), decimal_places=decimal_places)
        except ValueError:
            invalid_observed.append({"index": index, "transaction_id": txid, "reason": "invalid_amount"})
            continue
        observed[txid] = {"amount_minor_units": amount, "currency": _currency(row, target_currency)}

    results: list[dict[str, Any]] = []
    for txid in sorted(set(expected) | set(observed) | duplicate_expected | duplicate_observed):
        left, right = expected.get(txid), observed.get(txid)
        if txid in duplicate_expected:
            status, reason = "EXCEPTION", "duplicate_expected_transaction_id"
        elif txid in duplicate_observed:
            status, reason = "EXCEPTION", "duplicate_settlement_transaction_id"
        elif left is None:
            status, reason = "UNEXPECTED", "settlement_transaction_not_in_expected_batch"
        elif right is None:
            status, reason = "MISSING", "expected_transaction_missing_from_settlement"
        elif left["currency"] != target_currency or right["currency"] != target_currency or left["currency"] != right["currency"]:
            status, reason = "CURRENCY_MISMATCH", "currency_mismatch"
        elif left["amount_minor_units"] != right["amount_minor_units"]:
            status, reason = "AMOUNT_MISMATCH", "amount_mismatch"
        else:
            status, reason = "MATCHED", None
        results.append({
            "transaction_id": txid,
            "status": status,
            "reason_code": reason,
            "expected_minor_units": left["amount_minor_units"] if left else None,
            "settled_minor_units": right["amount_minor_units"] if right else None,
            "expected_currency": left["currency"] if left else None,
            "settled_currency": right["currency"] if right else None,
        })

    expected_total = sum(row["amount_minor_units"] for row in expected.values())
    observed_total = sum(row["amount_minor_units"] for txid, row in observed.items() if txid not in duplicate_observed)
    counts: dict[str, int] = {}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    exception_count = len(invalid_expected) + len(invalid_observed) + len(duplicate_expected) + len(duplicate_observed)
    return {
        "status": "RECONCILED" if not exception_count and all(item["status"] == "MATCHED" for item in results) else "EXCEPTIONS",
        "currency": target_currency,
        "decimal_places": decimal_places,
        "expected_total_minor_units": expected_total,
        "settled_total_minor_units": observed_total,
        "total_variance_minor_units": observed_total - expected_total,
        "counts": counts,
        "items": results,
        "duplicate_expected_ids": sorted(duplicate_expected),
        "duplicate_settlement_ids": sorted(duplicate_observed),
        "invalid_expected_rows": invalid_expected,
        "invalid_settlement_rows": invalid_observed,
        "auto_adjustment_created": False,
    }


def assess_reversal_lifecycle(
    *,
    original_transaction_id: str,
    original_amount: Any,
    reversals: Sequence[Mapping[str, Any]],
    currency: str = "KES",
    decimal_places: int = 2,
) -> dict[str, Any]:
    """Assess cumulative refunds/reversals against one original transaction.

    Only rows explicitly linked to the original ID and in the same currency
    contribute to the accepted total. Duplicate reversal IDs are counted once
    and reported. Amounts above the original are flagged as OVER_REVERSED; no
    ledger posting or automatic refund decision is performed.
    """
    original_id = str(original_transaction_id or "").strip()
    if not original_id:
        raise ValueError("original_transaction_id is required")
    original_minor = _minor_units(original_amount, decimal_places=decimal_places)
    if original_minor <= 0:
        raise ValueError("original_amount must be positive")
    target_currency = str(currency or "KES").strip().upper()
    if not target_currency:
        raise ValueError("currency is required")

    seen: set[str] = set()
    accepted: list[dict[str, Any]] = []
    duplicate_ids: set[str] = set()
    rejected: list[dict[str, Any]] = []
    for index, row in enumerate(reversals):
        reversal_id = _first(row, "TransID", "transaction_id", "reversal_id")
        linked_original = _first(row, "OriginalTransID", "OriginalTransactionID", "original_transaction_id", "original_reference")
        if not reversal_id:
            rejected.append({"index": index, "reason": "missing_reversal_id"})
            continue
        if reversal_id in seen:
            duplicate_ids.add(reversal_id)
            continue
        seen.add(reversal_id)
        if linked_original != original_id:
            rejected.append({"index": index, "reversal_id": reversal_id, "reason": "original_reference_mismatch"})
            continue
        row_currency = _currency(row, target_currency)
        if row_currency != target_currency:
            rejected.append({"index": index, "reversal_id": reversal_id, "reason": "currency_mismatch"})
            continue
        try:
            amount = _minor_units(row.get("TransAmount", row.get("amount")), decimal_places=decimal_places)
        except ValueError:
            rejected.append({"index": index, "reversal_id": reversal_id, "reason": "invalid_amount"})
            continue
        if amount <= 0:
            rejected.append({"index": index, "reversal_id": reversal_id, "reason": "non_positive_amount"})
            continue
        accepted.append({"reversal_id": reversal_id, "amount_minor_units": amount})

    reversed_minor = sum(row["amount_minor_units"] for row in accepted)
    if reversed_minor == 0:
        status = "NO_VALID_REVERSALS"
    elif reversed_minor < original_minor:
        status = "PARTIALLY_REVERSED"
    elif reversed_minor == original_minor:
        status = "FULLY_REVERSED"
    else:
        status = "OVER_REVERSED"
    return {
        "status": status,
        "original_transaction_id": original_id,
        "currency": target_currency,
        "original_amount_minor_units": original_minor,
        "accepted_reversal_total_minor_units": reversed_minor,
        "remaining_amount_minor_units": original_minor - reversed_minor,
        "accepted_reversal_ids": sorted(row["reversal_id"] for row in accepted),
        "duplicate_reversal_ids": sorted(duplicate_ids),
        "rejected_rows": rejected,
        "over_reversal_minor_units": max(0, reversed_minor - original_minor),
        "auto_adjustment_created": False,
    }


def assess_event_timing(
    *,
    event_time: Any,
    ingested_at: Any,
    settled_at: Any = None,
    max_future_skew_seconds: int = 300,
    late_after_seconds: int = 3600,
) -> dict[str, Any]:
    """Surface future-dated, late-arriving and out-of-order transaction events.

    Naive timestamps are interpreted as UTC, consistent with existing PesaGuard
    timestamp helpers. Missing/unparseable timestamps are reported as unknown,
    not silently treated as healthy.
    """
    event = _parse_time(event_time)
    ingested = _parse_time(ingested_at)
    settled = _parse_time(settled_at) if settled_at not in (None, "") else None
    if event is None or ingested is None:
        return {
            "evaluated": False,
            "status": "UNKNOWN",
            "reason_codes": ["event_time_missing_or_invalid" if event is None else "ingestion_time_missing_or_invalid"],
            "event_to_ingestion_seconds": None,
            "event_to_settlement_seconds": None,
        }
    ingestion_lag = (ingested - event).total_seconds()
    settlement_lag = (settled - event).total_seconds() if settled is not None else None
    reasons: list[str] = []
    if ingestion_lag < -max(0, int(max_future_skew_seconds)):
        reasons.append("event_time_too_far_in_future")
    if ingestion_lag > max(0, int(late_after_seconds)):
        reasons.append("late_arriving_event")
    if settlement_lag is not None and settlement_lag < -max(0, int(max_future_skew_seconds)):
        reasons.append("settlement_precedes_event")
    return {
        "evaluated": True,
        "status": "REVIEW" if reasons else "CONSISTENT",
        "reason_codes": reasons,
        "event_to_ingestion_seconds": round(ingestion_lag, 3),
        "event_to_settlement_seconds": round(settlement_lag, 3) if settlement_lag is not None else None,
    }


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if len(text) == 14 and text.isdigit():
            return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None
