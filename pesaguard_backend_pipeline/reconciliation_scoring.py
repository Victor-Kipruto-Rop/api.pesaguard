from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Any, Dict, Tuple

try:
    from rapidfuzz.distance import Levenshtein
except Exception:  # pragma: no cover - optional dependency
    Levenshtein = None


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _norm_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _parse_time(value: Any):
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    text = str(value).strip()
    if len(text) == 14 and text.isdigit():
        try:
            return datetime.strptime(text, "%Y%m%d%H%M%S").replace(
                tzinfo=ZoneInfo("Africa/Nairobi")
            ).astimezone(timezone.utc)
        except ValueError:
            return None

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0

    if Levenshtein is None:
        return 1.0 if left == right else 0.0

    max_len = max(len(left), len(right), 1)
    distance = Levenshtein.distance(left, right)
    return max(0.0, min(1.0, 1.0 - (distance / max_len)))


def score_match(event: Dict[str, Any], record: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    # Provider IDs and local row IDs are not merchant references. Treat absent
    # business references as missing evidence, never as an exact reference match.
    event_ref = _norm_text(
        event.get("BillRefNumber") or event.get("reference")
        or event.get("transaction_reference") or event.get("tx_ref")
    )
    record_ref = _norm_text(
        record.get("BillRefNumber") or record.get("reference")
        or record.get("merchant_ref") or record.get("transaction_reference")
    )

    ref_exact = 1.0 if event_ref and record_ref and event_ref == record_ref else 0.0
    ref_similarity = _similarity(event_ref, record_ref)

    event_amount = _to_float(event.get("TransAmount") or event.get("amount"))
    record_amount = _to_float(record.get("amount"))
    max_amount = max(abs(event_amount), abs(record_amount), 1.0)
    amount_diff_normalized = max(0.0, 1.0 - (abs(event_amount - record_amount) / max_amount))

    event_time = _parse_time(event.get("TransTime") or event.get("trans_time") or event.get("timestamp"))
    record_time = _parse_time(record.get("timestamp") or record.get("synced_at") or record.get("created_at"))
    if event_time and record_time:
        time_delta_seconds = abs((event_time - record_time).total_seconds())
        time_delta_normalized = max(0.0, 1.0 - min(time_delta_seconds / 3600.0, 1.0))
    else:
        time_delta_seconds = None
        time_delta_normalized = 0.0

    event_phone = _norm_text(event.get("MSISDN") or event.get("msisdn") or event.get("phone_number"))
    record_phone = _norm_text(record.get("phone_number") or record.get("msisdn"))
    phone_match = bool(event_phone and record_phone and event_phone == record_phone)

    weights = {
        "ref_exact": 0.35,
        "ref_similarity": 0.20,
        "amount_diff_normalized": 0.20,
        "time_delta_normalized": 0.15,
        "phone_match": 0.10,
    }

    components = {
        "ref_exact": ref_exact,
        "ref_similarity": ref_similarity,
        "amount_diff_normalized": amount_diff_normalized,
        "time_delta_normalized": time_delta_normalized,
        "phone_match": 1.0 if phone_match else 0.0,
    }

    score = 0.0
    for name, weight in weights.items():
        score += components[name] * weight
    score = max(0.0, min(1.0, score))

    matched_features = [name for name, value in components.items() if value > 0]
    anomaly_features = [name for name, value in components.items() if value == 0]

    reasons = {
        "components": components,
        "weights": weights,
        "time_delta_seconds": time_delta_seconds,
        "matched_features": matched_features,
        "anomaly_features": anomaly_features,
    }
    return score, reasons
