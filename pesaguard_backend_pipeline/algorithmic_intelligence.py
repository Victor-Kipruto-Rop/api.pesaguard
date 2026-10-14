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
        "timestamp": str(payload.get("TransTime") or payload.get("timestamp") or "").strip(),
        "phone": re.sub(r"[^0-9]", "", str(payload.get("MSISDN") or payload.get("phone_number") or "")),
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
    """Return explainable candidate evidence without rewarding missing data.

    Exact reference and amount are necessary but not sufficient for an automatic
    match: both timestamps must parse and fall inside the configured window.
    Phone evidence is corroborating when both sides provide it; absent phone data
    is neutral, while conflicting phone data blocks automatic matching.
    """
    incoming_raw_ref = _canonical_reference(incoming.get("BillRefNumber") or incoming.get("reference"))
    candidate_raw_ref = _canonical_reference(candidate.get("reference") or candidate.get("internal_ref"))
    incoming_ref = normalize_reference(incoming.get("BillRefNumber") or incoming.get("reference"))
    candidate_ref = normalize_reference(candidate.get("reference") or candidate.get("internal_ref"))
    incoming_amount = incoming.get("TransAmount", incoming.get("amount"))
    candidate_amount = candidate.get("amount", candidate.get("TransAmount"))
    try:
        amount_equal = (
            incoming_amount is not None and candidate_amount is not None
            and amount_to_minor_units(incoming_amount) == amount_to_minor_units(candidate_amount)
        )
    except (ValueError, TypeError, InvalidOperation):
        amount_equal = False

    incoming_time = incoming.get("TransTime") or incoming.get("timestamp")
    candidate_time = candidate.get("timestamp") or candidate.get("created_at")
    delta_seconds = _timestamp_delta_seconds(incoming_time, candidate_time)
    time_available = delta_seconds is not None
    time_ok = time_available and delta_seconds <= max(0, int(window_seconds))

    incoming_phone = re.sub(r"[^0-9]", "", str(incoming.get("MSISDN") or incoming.get("phone_number") or ""))
    candidate_phone = re.sub(r"[^0-9]", "", str(candidate.get("phone_number") or candidate.get("MSISDN") or ""))
    phone_available = bool(incoming_phone and candidate_phone)
    phone_ok = not phone_available or incoming_phone == candidate_phone

    reference_exact = bool(incoming_raw_ref and candidate_raw_ref and incoming_raw_ref == candidate_raw_ref)
    reference_normalized_only = bool(
        incoming_ref and candidate_ref and incoming_ref == candidate_ref
        and incoming_raw_ref != candidate_raw_ref
    )
    evidence = {
        "reference_exact": reference_exact,
        "reference_normalized_only": reference_normalized_only,
        "amount_exact": bool(amount_equal),
        "time_evidence_available": time_available,
        "time_within_window": bool(time_ok),
        "phone_evidence_available": phone_available,
        "phone_consistent": bool(phone_ok),
        "time_delta_seconds": delta_seconds,
    }

    # Missing optional evidence contributes neither a positive nor a negative
    # score. Renormalize weights over observed evidence to avoid rewarding gaps.
    weighted_evidence = [
        (0.45, reference_exact, True),
        (0.30, bool(amount_equal), incoming_amount is not None and candidate_amount is not None),
        (0.15, bool(time_ok), time_available),
        (0.10, bool(phone_ok), phone_available),
    ]
    available_weight = sum(weight for weight, _, available in weighted_evidence if available)
    score = (
        sum(weight * float(passed) for weight, passed, available in weighted_evidence if available)
        / available_weight
        if available_weight else 0.0
    )
    auto_matchable = bool(
        reference_exact and amount_equal and time_available and time_ok
        and phone_ok
    )
    reason_codes = []
    if not reference_exact:
        reason_codes.append("reference_not_exact")
    if not amount_equal:
        reason_codes.append("amount_not_exact")
    if not time_available:
        reason_codes.append("timestamp_evidence_missing")
    elif not time_ok:
        reason_codes.append("timestamp_outside_window")
    if phone_available and not phone_ok:
        reason_codes.append("phone_conflict")
    return {
        "score": round(float(score), 4),
        "auto_matchable": auto_matchable,
        "evidence": evidence,
        "reason_codes": reason_codes,
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
                return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
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
