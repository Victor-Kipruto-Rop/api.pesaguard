"""Deterministic, explainable transaction-intelligence primitives.

These helpers are deliberately dependency-light and never make payment or ledger
corrections. They provide stable identity/fingerprints, money-safe normalization,
robust outlier scoring, and conservative candidate evidence for higher-level
reconciliation and risk workflows.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from statistics import median
from typing import Any, Mapping, Sequence

ROBUST_Z_THRESHOLD = 3.5
MIN_BASELINE_SAMPLES = 5
_MAD_NORMALIZER = 1.4826


def normalize_reference(value: Any) -> str:
    """Normalize a reference for comparison without inventing missing values."""
    if value is None:
        return ""
    normalized = unicodedata.normalize("NFKC", str(value)).casefold().strip()
    return re.sub(r"[^a-z0-9]", "", normalized)


def amount_to_minor_units(value: Any, *, decimal_places: int = 2) -> int:
    """Convert a decimal amount to integer minor units; floats are never used."""
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("amount must be a finite decimal number") from exc
    if not amount.is_finite():
        raise ValueError("amount must be a finite decimal number")
    quantum = Decimal(1).scaleb(-decimal_places)
    rounded = amount.quantize(quantum, rounding=ROUND_HALF_UP)
    return int(rounded.scaleb(decimal_places))


def transaction_identity_key(
    *,
    tenant_id: str,
    provider: str,
    transaction_id: str,
) -> str:
    """Return a tenant/provider-scoped stable identity for deduplication.

    External transaction IDs are required. Falling back to amount/time would
    incorrectly collapse legitimate payments that happen to look alike.
    """
    parts = [str(tenant_id or "").strip(), str(provider or "").strip().casefold(),
             str(transaction_id or "").strip()]
    if not all(parts):
        raise ValueError("tenant_id, provider, and transaction_id are required")
    raw = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def transaction_payload_fingerprint(payload: Mapping[str, Any]) -> str:
    """Hash canonical transaction facts to detect conflicting replays.

    This is not an identity key: the same transaction ID with altered amount or
    reference intentionally gets a different payload fingerprint.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a mapping")
    amount = payload.get("TransAmount", payload.get("amount"))
    facts = {
        "transaction_id": str(payload.get("TransID") or payload.get("trans_id")
                               or payload.get("transaction_id") or "").strip(),
        "reference": normalize_reference(payload.get("BillRefNumber") or payload.get("reference")),
        "amount_minor_units": amount_to_minor_units(amount) if amount is not None else None,
        "currency": str(payload.get("Currency") or payload.get("currency") or "KES").upper().strip(),
        "timestamp": _canonical_timestamp(payload.get("TransTime") or payload.get("timestamp") or payload.get("created_at")),
        "phone": _canonical_phone(payload.get("MSISDN") or payload.get("phone_number") or payload.get("msisdn")),
    }
    if not facts["transaction_id"]:
        raise ValueError("transaction_id is required to fingerprint a transaction")
    raw = json.dumps(facts, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def robust_amount_zscore(amount: Any, baseline_amounts: Sequence[Any]) -> float | None:
    """Return a robust modified z-score using median and MAD.

    Returns None when the baseline is too small or contains invalid values.
    A zero-MAD baseline uses a conservative scale floor to avoid division by
    zero; this is a screening signal, not a standalone fraud decision.
    """
    if len(baseline_amounts) < MIN_BASELINE_SAMPLES:
        return None
    try:
        current = float(Decimal(str(amount)))
        values = [float(Decimal(str(item))) for item in baseline_amounts]
    except (InvalidOperation, TypeError, ValueError, OverflowError):
        return None
    if not all(map(_is_finite, [current, *values])):
        return None
    center = median(values)
    mad = median([abs(value - center) for value in values])
    scale = _MAD_NORMALIZER * mad
    if scale <= 0:
        scale = max(abs(center) * 0.05, 1.0)
    return (current - center) / scale


def robust_amount_deviation(amount: Any, baseline_amounts: Sequence[Any]) -> float | None:
    """Map absolute robust z-score to [0, 1], saturating at |z| >= 5."""
    zscore = robust_amount_zscore(amount, baseline_amounts)
    if zscore is None:
        return None
    return min(abs(zscore), 5.0) / 5.0


def is_amount_outlier(
    amount: Any,
    baseline_amounts: Sequence[Any],
    *,
    threshold: float = ROBUST_Z_THRESHOLD,
) -> bool | None:
    """Return True/False when enough baseline data exists, otherwise None."""
    zscore = robust_amount_zscore(amount, baseline_amounts)
    if zscore is None:
        return None
    return abs(zscore) >= max(0.0, float(threshold))


def score_reconciliation_candidate(
    incoming: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    window_seconds: int = 900,
) -> dict[str, Any]:
    """Return explainable evidence; only conservative exact evidence auto-matches.

    This helper intentionally does not choose among multiple candidates. The
    caller must detect ambiguous top candidates and route them to review.
    """
    incoming_raw_ref = _canonical_reference(incoming.get("BillRefNumber") or incoming.get("reference"))
    candidate_raw_ref = _canonical_reference(candidate.get("reference") or candidate.get("internal_ref"))
    incoming_ref = normalize_reference(incoming.get("BillRefNumber") or incoming.get("reference"))
    candidate_ref = normalize_reference(candidate.get("reference") or candidate.get("internal_ref"))
    incoming_amount = incoming.get("TransAmount", incoming.get("amount"))
    candidate_amount = candidate.get("amount", candidate.get("TransAmount"))
    try:
        amount_equal = (incoming_amount is not None and candidate_amount is not None
                        and amount_to_minor_units(incoming_amount) == amount_to_minor_units(candidate_amount))
    except ValueError:
        amount_equal = False

    incoming_time = incoming.get("TransTime") or incoming.get("timestamp")
    candidate_time = candidate.get("timestamp") or candidate.get("created_at")
    delta_seconds = _timestamp_delta_seconds(incoming_time, candidate_time)
    # Missing timestamps are unknown evidence, not proof that the events are close.
    time_ok = delta_seconds is not None and delta_seconds <= max(0, int(window_seconds))
    incoming_phone = _canonical_phone(incoming.get("MSISDN") or incoming.get("phone_number"))
    candidate_phone = _canonical_phone(candidate.get("phone_number") or candidate.get("MSISDN"))
    phone_ok = not incoming_phone or not candidate_phone or incoming_phone == candidate_phone

    evidence = {
        "reference_exact": bool(incoming_raw_ref and candidate_raw_ref and incoming_raw_ref == candidate_raw_ref),
        "reference_normalized_only": bool(
            incoming_ref and candidate_ref and incoming_ref == candidate_ref
            and incoming_raw_ref != candidate_raw_ref
        ),
        "amount_exact": bool(amount_equal),
        "time_within_window": bool(time_ok),
        "phone_consistent": bool(phone_ok),
        "time_delta_seconds": delta_seconds,
    }
    score = (
        0.45 * evidence["reference_exact"]
        + 0.30 * evidence["amount_exact"]
        + 0.15 * evidence["time_within_window"]
        + 0.10 * evidence["phone_consistent"]
    )
    auto_matchable = all((
        evidence["reference_exact"], evidence["amount_exact"],
        evidence["time_within_window"], evidence["phone_consistent"],
    ))
    return {
        "score": round(float(score), 4),
        "auto_matchable": auto_matchable,
        "evidence": evidence,
        "reason_codes": [key for key, passed in evidence.items()
                         if key != "time_delta_seconds" and not passed],
    }


def _is_finite(value: float) -> bool:
    return value == value and value not in (float("inf"), float("-inf"))


def _timestamp_delta_seconds(left: Any, right: Any) -> float | None:
    from datetime import datetime, timezone

    def parse(value: Any):
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        text = str(value or "").strip()
        if len(text) == 14 and text.isdigit():
            try:
                return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=ZoneInfo("Africa/Nairobi"))
            except ValueError:
                return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    a, b = parse(left), parse(right)
    if a is None or b is None:
        return None
    return abs((a - b).total_seconds())



def aggregate_partial_payments(
    payments: Sequence[Mapping[str, Any]],
    expected_amount: Any,
    *,
    reference: str,
    currency: str = "KES",
) -> dict[str, Any]:
    """Aggregate only payments sharing an explicit normalized reference/currency.

    No combinatorial subset search is performed. An empty or ambiguous reference
    is rejected; overpayments are surfaced and never silently capped.
    """
    target_reference = _canonical_reference(reference)
    if not target_reference:
        raise ValueError("a non-empty reference is required for partial-payment aggregation")
    target_currency = str(currency or "KES").upper().strip()
    target_minor = amount_to_minor_units(expected_amount)
    selected: list[Mapping[str, Any]] = []
    seen_ids: set[str] = set()
    total_minor = 0
    for payment in payments:
        payment_reference = _canonical_reference(payment.get("BillRefNumber") or payment.get("reference"))
        payment_currency = str(payment.get("Currency") or payment.get("currency") or "KES").upper().strip()
        payment_id = str(payment.get("TransID") or payment.get("transaction_id") or "").strip()
        if payment_reference != target_reference or payment_currency != target_currency:
            continue
        if not payment_id:
            raise ValueError("every aggregated payment must have an external transaction ID")
        if payment_id in seen_ids:
            continue
        seen_ids.add(payment_id)
        total_minor += amount_to_minor_units(payment.get("TransAmount", payment.get("amount")))
        selected.append(payment)
    if total_minor == target_minor:
        status = "MATCHED"
    elif total_minor < target_minor:
        status = "PARTIAL"
    else:
        status = "OVERPAID"
    return {
        "status": status,
        "reference": target_reference,
        "currency": target_currency,
        "expected_minor_units": target_minor,
        "received_minor_units": total_minor,
        "variance_minor_units": total_minor - target_minor,
        "payment_ids": sorted(seen_ids),
        "payment_count": len(selected),
    }


def detect_velocity_spike(
    transaction: Mapping[str, Any],
    history: Sequence[Mapping[str, Any]],
    *,
    identity_fields: Sequence[str] = ("MSISDN", "phone_number", "customer_id"),
    window_seconds: int = 60,
    limit: int = 5,
) -> dict[str, Any]:
    """Count prior events for the same identity in a trailing time window."""
    current_identity = next(
        (str(transaction.get(key) or "").strip() for key in identity_fields
         if str(transaction.get(key) or "").strip()),
        "",
    )
    current_time = _parse_datetime(
        transaction.get("TransTime") or transaction.get("timestamp") or transaction.get("created_at")
    )
    if not current_identity or current_time is None:
        return {"evaluated": False, "triggered": False, "count": 0, "reason": "identity_or_timestamp_missing"}
    count = 0
    for item in history:
        identity = next(
            (str(item.get(key) or "").strip() for key in identity_fields
             if str(item.get(key) or "").strip()),
            "",
        )
        timestamp = _parse_datetime(item.get("TransTime") or item.get("timestamp") or item.get("created_at"))
        if identity != current_identity or timestamp is None:
            continue
        delta = (current_time - timestamp).total_seconds()
        if 0 <= delta <= max(0, int(window_seconds)):
            count += 1
    return {
        "evaluated": True,
        "triggered": count >= max(1, int(limit)),
        "count": count,
        "window_seconds": max(0, int(window_seconds)),
        "limit": max(1, int(limit)),
    }


def decompose_settlement_variance(
    *,
    expected_gross: Any,
    actual_net: Any,
    known_fees: Any = "0",
    known_reversals: Any = "0",
    known_adjustments: Any = "0",
) -> dict[str, Any]:
    """Explain net settlement variance using explicitly supplied components.

    Values use Decimal minor units. The unexplained residual is reported, not
    auto-adjusted; caller must define sign conventions consistently.
    """
    expected = amount_to_minor_units(expected_gross)
    actual = amount_to_minor_units(actual_net)
    fees = amount_to_minor_units(known_fees)
    reversals = amount_to_minor_units(known_reversals)
    adjustments = amount_to_minor_units(known_adjustments)
    explained_net = expected - fees - reversals + adjustments
    residual = actual - explained_net
    return {
        "expected_gross_minor_units": expected,
        "actual_net_minor_units": actual,
        "known_fees_minor_units": fees,
        "known_reversals_minor_units": reversals,
        "known_adjustments_minor_units": adjustments,
        "explained_net_minor_units": explained_net,
        "unexplained_variance_minor_units": residual,
        "status": "BALANCED" if residual == 0 else "VARIANCE",
    }


def _parse_datetime(value: Any):
    from datetime import datetime, timezone

    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value or "").strip()
    if len(text) == 14 and text.isdigit():
        try:
            return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None



def rank_reconciliation_candidates(
    incoming: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
    *,
    window_seconds: int = 900,
    minimum_margin: float = 0.15,
) -> dict[str, Any]:
    """Rank candidate evidence but refuse automatic selection when ambiguous."""
    scored = [
        {"candidate": candidate, **score_reconciliation_candidate(
            incoming, candidate, window_seconds=window_seconds
        )}
        for candidate in candidates
    ]
    scored.sort(key=lambda item: item["score"], reverse=True)
    if not scored:
        return {"status": "NO_CANDIDATE", "selected": None, "candidates": []}
    if len(scored) > 1 and (scored[0]["score"] - scored[1]["score"]) < max(0.0, minimum_margin):
        return {"status": "AMBIGUOUS", "selected": None, "candidates": scored}
    top = scored[0]
    if not top["auto_matchable"]:
        return {"status": "REVIEW", "selected": None, "candidates": scored}
    return {"status": "MATCH_CANDIDATE", "selected": top["candidate"], "candidates": scored}


def detect_window_change(
    baseline_values: Sequence[Any],
    recent_values: Sequence[Any],
    *,
    relative_change_threshold: float = 0.5,
    minimum_samples: int = 5,
) -> dict[str, Any]:
    """Detect a material shift between historical and recent numeric windows.

    This simple, transparent change detector is a monitoring signal. It is not
    a forecasting model and does not label a change as fraud or provider fault.
    """
    if len(baseline_values) < minimum_samples or len(recent_values) < 1:
        return {
            "evaluated": False, "changed": False, "reason": "insufficient_samples",
            "baseline_median": None, "recent_median": None, "relative_change": None,
        }
    try:
        baseline = [float(Decimal(str(value))) for value in baseline_values]
        recent = [float(Decimal(str(value))) for value in recent_values]
    except (InvalidOperation, TypeError, ValueError, OverflowError):
        return {
            "evaluated": False, "changed": False, "reason": "invalid_numeric_sample",
            "baseline_median": None, "recent_median": None, "relative_change": None,
        }
    if not all(map(_is_finite, [*baseline, *recent])):
        return {
            "evaluated": False, "changed": False, "reason": "invalid_numeric_sample",
            "baseline_median": None, "recent_median": None, "relative_change": None,
        }
    baseline_center = median(baseline)
    recent_center = median(recent)
    denominator = max(abs(baseline_center), 1.0)
    relative_change = (recent_center - baseline_center) / denominator
    return {
        "evaluated": True,
        "changed": abs(relative_change) >= max(0.0, float(relative_change_threshold)),
        "reason": None,
        "baseline_median": baseline_center,
        "recent_median": recent_center,
        "relative_change": round(relative_change, 6),
    }



def _canonical_reference(value: Any) -> str:
    """Normalize casing/Unicode/whitespace but preserve punctuation for exact matching."""
    if value is None:
        return ""
    normalized = unicodedata.normalize("NFKC", str(value)).casefold().strip()
    return re.sub(r"\s+", " ", normalized)


def classify_replay(existing: Mapping[str, Any] | None, incoming: Mapping[str, Any]) -> dict[str, Any]:
    """Classify a provider event as new, an identical replay, or a conflicting replay.

    This pure helper does not replace a database uniqueness constraint or lock.
    Provider account is part of the scope when available.
    """
    def identity_parts(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
        tenant = str(row.get("tenant_id") or "").strip()
        provider = str(row.get("provider") or row.get("provider_name") or "").strip().casefold()
        account = str(row.get("provider_account_id") or row.get("BusinessShortCode") or "").strip()
        transaction_id = str(row.get("TransID") or row.get("trans_id") or row.get("transaction_id") or "").strip()
        if not tenant or not provider or not transaction_id:
            raise ValueError("tenant_id, provider, and transaction_id are required for replay classification")
        return tenant, provider, account, transaction_id

    incoming_identity = identity_parts(incoming)
    if existing is None:
        return {"classification": "NEW_TRANSACTION", "same_identity": False, "same_payload": False,
                "reason_codes": ["no_existing_transaction"]}
    if identity_parts(existing) != incoming_identity:
        return {"classification": "NEW_TRANSACTION", "same_identity": False, "same_payload": False,
                "reason_codes": ["identity_scope_differs"]}
    same_payload = transaction_payload_fingerprint(existing) == transaction_payload_fingerprint(incoming)
    return {
        "classification": "IDENTICAL_REPLAY" if same_payload else "CONFLICTING_REPLAY",
        "same_identity": True,
        "same_payload": same_payload,
        "reason_codes": ["same_identity_same_payload" if same_payload else "same_identity_payload_changed"],
    }


def assess_reversal(
    original: Mapping[str, Any],
    reversal: Mapping[str, Any],
    prior_confirmed_reversals: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Validate reversal linkage and cumulative amount without posting ledger entries.

    The prior list must contain only provider-confirmed successful reversals for
    the same tenant/provider scope. The caller owns that scoped database query.
    """
    original_id = str(original.get("TransID") or original.get("trans_id") or original.get("transaction_id") or "").strip()
    reversal_id = str(reversal.get("TransID") or reversal.get("trans_id") or reversal.get("transaction_id") or "").strip()
    original_ref = str(reversal.get("OriginalTransID") or reversal.get("OriginalTransactionID")
                       or reversal.get("original_transaction_id") or reversal.get("original_reference") or "").strip()
    if not original_id or not reversal_id:
        return {"status": "INVALID", "valid": False, "reason_codes": ["missing_transaction_identity"]}
    if not original_ref or original_ref != original_id:
        return {"status": "INVALID", "valid": False, "reason_codes": ["original_reference_mismatch"]}

    original_currency = str(original.get("Currency") or original.get("currency") or "KES").strip().upper()
    reversal_currency = str(reversal.get("Currency") or reversal.get("currency") or "KES").strip().upper()
    if original_currency != reversal_currency:
        return {"status": "INVALID", "valid": False, "reason_codes": ["currency_mismatch"]}
    try:
        original_minor = amount_to_minor_units(original.get("TransAmount", original.get("amount")))
        reversal_minor = amount_to_minor_units(reversal.get("TransAmount", reversal.get("amount")))
        if original_minor <= 0 or reversal_minor <= 0:
            raise ValueError("amounts must be positive")
    except (ValueError, TypeError):
        return {"status": "INVALID", "valid": False, "reason_codes": ["invalid_amount"]}

    prior_minor = 0
    seen_ids: set[str] = set()
    for item in prior_confirmed_reversals:
        item_id = str(item.get("TransID") or item.get("trans_id") or item.get("transaction_id") or "").strip()
        item_ref = str(item.get("OriginalTransID") or item.get("OriginalTransactionID")
                       or item.get("original_transaction_id") or item.get("original_reference") or "").strip()
        item_currency = str(item.get("Currency") or item.get("currency") or "KES").strip().upper()
        if not item_id or item_id == reversal_id or item_id in seen_ids or item_ref != original_id:
            continue
        if item_currency != original_currency:
            return {"status": "INVALID", "valid": False, "reason_codes": ["prior_reversal_currency_mismatch"]}
        try:
            prior_amount = amount_to_minor_units(item.get("TransAmount", item.get("amount")))
        except (ValueError, TypeError):
            return {"status": "INVALID", "valid": False, "reason_codes": ["invalid_prior_reversal_amount"]}
        if prior_amount <= 0:
            return {"status": "INVALID", "valid": False, "reason_codes": ["invalid_prior_reversal_amount"]}
        seen_ids.add(item_id)
        prior_minor += prior_amount

    remaining = original_minor - prior_minor
    cumulative = prior_minor + reversal_minor
    if remaining < 0:
        return {"status": "OVER_REVERSED_ALREADY", "valid": False,
                "reason_codes": ["prior_reversals_exceed_original"], "original_minor_units": original_minor,
                "previously_reversed_minor_units": prior_minor, "requested_reversal_minor_units": reversal_minor,
                "remaining_reversible_minor_units": 0}
    if reversal_minor > remaining:
        return {"status": "OVER_REVERSAL", "valid": False,
                "reason_codes": ["cumulative_reversal_exceeds_original"], "original_minor_units": original_minor,
                "previously_reversed_minor_units": prior_minor, "requested_reversal_minor_units": reversal_minor,
                "remaining_reversible_minor_units": remaining}
    return {
        "status": "FULL_REVERSAL" if cumulative == original_minor else "PARTIAL_REVERSAL",
        "valid": True, "reason_codes": ["reversal_amount_within_original"],
        "original_minor_units": original_minor, "previously_reversed_minor_units": prior_minor,
        "requested_reversal_minor_units": reversal_minor, "cumulative_reversed_minor_units": cumulative,
        "remaining_reversible_minor_units": original_minor - cumulative,
    }


def profile_transaction_batch(
    records: Sequence[Mapping[str, Any]],
    *,
    required_fields: Sequence[str] = ("transaction_id", "amount", "timestamp"),
    known_fields: Sequence[str] | None = None,
    now: datetime | None = None,
    late_after_seconds: int | None = None,
) -> dict[str, Any]:
    """Profile batch quality without mutating or discarding source rows.

    Required fields use canonical names: transaction_id, amount, timestamp,
    phone, currency, or reference. Lateness is computed only when explicitly
    configured; event time is not assumed to equal ingestion time.
    """
    aliases = {
        "transaction_id": ("TransID", "trans_id", "transaction_id", "TransactionID"),
        "amount": ("TransAmount", "amount", "Amount"),
        "timestamp": ("TransTime", "timestamp", "created_at", "trans_time"),
        "phone": ("MSISDN", "msisdn", "phone_number", "PhoneNumber"),
        "currency": ("Currency", "currency"),
        "reference": ("BillRefNumber", "reference", "internal_ref", "merchant_ref"),
    }
    for field in required_fields:
        if field not in aliases:
            raise ValueError(f"unsupported required field: {field}")
    total = len(records)
    missing = {field: 0 for field in required_fields}
    invalid_amount = invalid_timestamp = future_timestamp = late_events = invalid_rows = 0
    duplicate_ids: set[str] = set()
    seen_ids: set[str] = set()
    currencies: dict[str, int] = {}
    observed_fields: set[str] = set()
    reference_missing = 0
    clock = now or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)

    for row in records:
        if not isinstance(row, Mapping):
            invalid_rows += 1
            continue
        observed_fields.update(str(key) for key in row.keys())
        values = {field: next((row[key] for key in keys if row.get(key) not in (None, "")), None)
                  for field, keys in aliases.items()}
        for field in required_fields:
            if values[field] is None:
                missing[field] += 1
        transaction_id = str(values["transaction_id"] or "").strip()
        if transaction_id:
            if transaction_id in seen_ids:
                duplicate_ids.add(transaction_id)
            seen_ids.add(transaction_id)
        if values["reference"] is None:
            reference_missing += 1
        amount = values["amount"]
        if amount is not None:
            try:
                parsed_amount = Decimal(str(amount))
                if not parsed_amount.is_finite() or parsed_amount <= 0:
                    invalid_amount += 1
            except (InvalidOperation, TypeError, ValueError):
                invalid_amount += 1
        timestamp = _parse_datetime(values["timestamp"])
        if values["timestamp"] is not None and timestamp is None:
            invalid_timestamp += 1
        if timestamp is not None and late_after_seconds is not None:
            age = (clock - timestamp).total_seconds()
            if age < 0:
                future_timestamp += 1
            elif age >= max(0, int(late_after_seconds)):
                late_events += 1
        currency = str(values["currency"] or "KES").strip().upper()
        currencies[currency] = currencies.get(currency, 0) + 1

    rates = {field: round(count / total, 4) if total else 0.0 for field, count in missing.items()}
    unknown_fields = sorted(observed_fields - set(known_fields)) if known_fields is not None else []
    return {
        "record_count": total, "invalid_row_count": invalid_rows,
        "missing_field_counts": missing, "missing_field_rates": rates,
        "invalid_amount_count": invalid_amount, "invalid_timestamp_count": invalid_timestamp,
        "future_timestamp_count": future_timestamp, "late_event_count": late_events,
        "duplicate_transaction_ids": sorted(duplicate_ids),
        "duplicate_transaction_id_count": len(duplicate_ids),
        "missing_reference_count": reference_missing, "currency_counts": dict(sorted(currencies.items())),
        "schema_drift_fields": unknown_fields, "late_event_threshold_seconds": late_after_seconds,
    }


def _canonical_timestamp(value: Any) -> str:
    """Normalize recognized timestamps to UTC; Daraja's compact timestamp is EAT."""
    parsed = _parse_datetime(value)
    if parsed is None:
        return str(value or "").strip()
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical_phone(value: Any) -> str:
    digits = re.sub(r"[^0-9]", "", str(value or ""))
    if digits.startswith("00"):
        digits = digits[2:]
    if len(digits) == 10 and digits.startswith("0"):
        digits = "254" + digits[1:]
    return digits
