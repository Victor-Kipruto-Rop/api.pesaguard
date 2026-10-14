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
    """Return explainable evidence; only conservative exact evidence auto-matches.

    This helper intentionally does not choose among multiple candidates. The
    caller must detect ambiguous top candidates and route them to review.
    """
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
    time_ok = delta_seconds is None or delta_seconds <= max(0, int(window_seconds))
    incoming_phone = re.sub(r"[^0-9]", "", str(incoming.get("MSISDN") or incoming.get("phone_number") or ""))
    candidate_phone = re.sub(r"[^0-9]", "", str(candidate.get("phone_number") or candidate.get("MSISDN") or ""))
    phone_ok = not incoming_phone or not candidate_phone or incoming_phone == candidate_phone

    evidence = {
        "reference_exact": bool(incoming_ref and candidate_ref and incoming_ref == candidate_ref),
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
