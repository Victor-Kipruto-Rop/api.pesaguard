from __future__ import annotations

"""Production-safe deterministic safeguards for payment event pipelines.

These algorithms emit evidence and advisory classifications only. They never
rewrite ledger values, reverse payments, or declare fraud without policy review.
"""
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

try:
    from .algorithmic_intelligence import transaction_payload_fingerprint
except ImportError:  # pragma: no cover - top-level service execution
    from algorithmic_intelligence import transaction_payload_fingerprint


def classify_replay(transaction: Mapping[str, Any], history: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Distinguish new events, identical delivery retries, and conflicting replays.

    Matching is tenant/provider aware when those fields are available. If the
    source omits an external transaction ID, the result is explicitly unknown;
    amount/time similarity is never used as an identity substitute.
    """
    transaction_id = str(transaction.get("TransID") or transaction.get("trans_id") or transaction.get("transaction_id") or "").strip()
    if not transaction_id:
        return {"classification": "INSUFFICIENT_IDENTITY", "matched_history": 0, "reason_codes": ["missing_external_transaction_id"]}
    provider = str(transaction.get("provider") or transaction.get("provider_name") or "mpesa").strip().casefold()
    tenant = str(transaction.get("tenant_id") or transaction.get("TenantID") or "").strip()
    matches = []
    for item in history:
        item_id = str(item.get("TransID") or item.get("trans_id") or item.get("transaction_id") or "").strip()
        item_provider = str(item.get("provider") or item.get("provider_name") or "mpesa").strip().casefold()
        item_tenant = str(item.get("tenant_id") or item.get("TenantID") or "").strip()
        if item_id != transaction_id or item_provider != provider:
            continue
        if tenant and item_tenant and tenant != item_tenant:
            continue
        matches.append(item)
    if not matches:
        return {"classification": "NEW", "matched_history": 0, "reason_codes": []}
    try:
        current_fingerprint = transaction_payload_fingerprint(transaction)
    except (TypeError, ValueError):
        return {"classification": "INSUFFICIENT_PAYLOAD", "matched_history": len(matches), "reason_codes": ["payload_not_fingerprintable"]}
    fingerprints = set()
    for item in matches:
        try:
            fingerprints.add(transaction_payload_fingerprint(item))
        except (TypeError, ValueError):
            continue
    if not fingerprints:
        return {"classification": "INSUFFICIENT_PAYLOAD", "matched_history": len(matches), "reason_codes": ["history_payload_not_fingerprintable"]}
    if current_fingerprint in fingerprints:
        return {"classification": "IDENTICAL_REPLAY", "matched_history": len(matches), "reason_codes": ["duplicate_delivery_same_payload"]}
    return {"classification": "CONFLICTING_REPLAY", "matched_history": len(matches), "reason_codes": ["same_external_id_different_payload"]}


def assess_event_time(value: Any, *, now: datetime | None = None, max_future_skew_seconds: int = 300, stale_after_seconds: int = 86400) -> dict[str, Any]:
    """Classify timestamp quality separately from fraud risk."""
    parsed = _parse_datetime(value)
    if parsed is None:
        return {"evaluated": False, "classification": "MISSING_OR_INVALID", "reason_codes": ["timestamp_missing_or_invalid"], "age_seconds": None}
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    age = (current.astimezone(timezone.utc) - parsed).total_seconds()
    if age < -max(0, int(max_future_skew_seconds)):
        classification, reasons = "FUTURE", ["timestamp_in_future"]
    elif age > max(0, int(stale_after_seconds)):
        classification, reasons = "STALE", ["late_arriving_event"]
    else:
        classification, reasons = "CURRENT", []
    return {"evaluated": True, "classification": classification, "reason_codes": reasons, "age_seconds": round(age, 3)}


def profile_data_quality(transaction: Mapping[str, Any], *, now: datetime | None = None, stale_after_seconds: int = 86400) -> dict[str, Any]:
    """Return transparent per-record completeness, validity and timeliness evidence."""
    required = {
        "transaction_id": ("TransID", "trans_id", "transaction_id"),
        "amount": ("TransAmount", "amount"),
        "timestamp": ("TransTime", "timestamp", "created_at"),
        "reference": ("BillRefNumber", "reference"),
    }
    present = {name: any(transaction.get(key) not in (None, "") for key in aliases) for name, aliases in required.items()}
    amount_value = transaction.get("TransAmount", transaction.get("amount"))
    amount_valid = False
    if amount_value not in (None, ""):
        try:
            from decimal import Decimal
            parsed_amount = Decimal(str(amount_value))
            amount_valid = parsed_amount.is_finite() and parsed_amount > 0
        except Exception:
            amount_valid = False
    timestamp_value = next((transaction.get(key) for key in required["timestamp"] if transaction.get(key) not in (None, "")), None)
    time_quality = assess_event_time(timestamp_value, now=now, stale_after_seconds=stale_after_seconds)
    checks = {
        "transaction_id_present": present["transaction_id"],
        "amount_present": present["amount"],
        "amount_positive_finite": amount_valid,
        "timestamp_present": present["timestamp"],
        "reference_present": present["reference"],
    }
    failures = [name for name, value in checks.items() if not value]
    validity_checks = (present["transaction_id"], amount_valid, time_quality["classification"] != "FUTURE")
    return {
        "completeness": round(sum(present.values()) / len(present), 4),
        "validity": round(sum(bool(value) for value in validity_checks) / len(validity_checks), 4),
        "timeliness": time_quality,
        "uniqueness": "NOT_EVALUATED",
        "checks": checks,
        "failure_count": len(failures),
        "failures": failures,
        "passed_checks": sum(bool(value) for value in checks.values()),
        "total_checks": len(checks),
        "profile_version": "dq-profile-v1",
    }


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value or "").strip()
    if len(text) == 14 and text.isdigit():
        try:
            return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
