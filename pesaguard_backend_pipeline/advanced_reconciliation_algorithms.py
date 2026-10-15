"""Advanced, explainable baseline algorithms for PesaGuard.

These helpers are advisory analytics only. They require caller-supplied, tenant-
and currency-scoped history; they never change transaction or ledger state.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation
import math
import statistics
from typing import Any, Iterable, Mapping, Sequence
from zoneinfo import ZoneInfo

ALGORITHM_VERSION = "advanced-reconciliation-v1"
DEFAULT_TIMEZONE = "Africa/Nairobi"


def _finite_decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError):
        return None
    return parsed if parsed.is_finite() else None


def _aware_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        raw = value.strip()
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo is not None else None


def seasonal_amount_assessment(
    current_amount: Any,
    history: Sequence[Mapping[str, Any]],
    *,
    event_time: Any,
    timezone_name: str = DEFAULT_TIMEZONE,
    minimum_samples: int = 8,
    modified_z_threshold: float = 3.5,
    currency: str = "KES",
) -> dict[str, Any]:
    """Compare an amount to same-local-weekday/hour observations.

    Each history item must contain amount, timestamp, and currency. Only matching
    currency and matching weekday/hour in the supplied timezone are considered.
    Insufficient history returns ready=False, never evidence the amount is normal.
    """
    if isinstance(minimum_samples, bool) or minimum_samples < 5:
        raise ValueError("minimum_samples must be at least 5")
    if not math.isfinite(modified_z_threshold) or modified_z_threshold <= 0:
        raise ValueError("modified_z_threshold must be finite and positive")
    if not str(currency).strip():
        raise ValueError("currency is required")

    current = _finite_decimal(current_amount)
    timestamp = _aware_datetime(event_time)
    if current is None or current <= 0:
        raise ValueError("current_amount must be a finite positive decimal")
    if timestamp is None:
        raise ValueError("event_time must be timezone-aware")
    try:
        zone = ZoneInfo(timezone_name)
        local_current = timestamp.astimezone(zone)
    except Exception as exc:
        raise ValueError("timezone_name must be a valid IANA timezone") from exc

    values: list[float] = []
    invalid = 0
    for item in history:
        if not isinstance(item, Mapping):
            invalid += 1
            continue
        if str(item.get("currency") or "").strip().upper() != str(currency).strip().upper():
            continue
        historic_time = _aware_datetime(item.get("timestamp"))
        amount = _finite_decimal(item.get("amount"))
        if historic_time is None or amount is None or amount <= 0:
            invalid += 1
            continue
        local_history = historic_time.astimezone(zone)
        if (local_history.weekday(), local_history.hour) == (local_current.weekday(), local_current.hour):
            values.append(float(amount))

    if len(values) < minimum_samples:
        return {
            "algorithm_version": ALGORITHM_VERSION,
            "ready": False,
            "reason": "insufficient_matching_seasonal_samples",
            "sample_count": len(values),
            "minimum_samples": minimum_samples,
            "currency": str(currency).strip().upper(),
            "timezone": timezone_name,
            "is_outlier": None,
            "modified_z": None,
            "baseline_median": None,
            "baseline_mad": None,
            "invalid_history_rows": invalid,
        }

    median = statistics.median(values)
    deviations = [abs(value - median) for value in values]
    mad = statistics.median(deviations)
    current_float = float(current)
    modified_z = None
    if mad > 0:
        modified_z = 0.6745 * (current_float - median) / mad
        is_outlier = abs(modified_z) > modified_z_threshold
    else:
        is_outlier = current_float != median
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "ready": True,
        "sample_count": len(values),
        "minimum_samples": minimum_samples,
        "currency": str(currency).strip().upper(),
        "timezone": timezone_name,
        "cohort": {"weekday": local_current.weekday(), "hour": local_current.hour},
        "baseline_median": str(Decimal(str(median))),
        "baseline_mad": str(Decimal(str(mad))),
        "modified_z": round(modified_z, 4) if modified_z is not None else None,
        "is_outlier": bool(is_outlier),
        "invalid_history_rows": invalid,
        "action": "REVIEW_SIGNAL" if is_outlier else "NO_SEASONAL_OUTLIER_SIGNAL",
    }


def detect_distribution_shift(
    reference_values: Iterable[Any],
    recent_values: Iterable[Any],
    *,
    minimum_samples_per_window: int = 10,
    relative_change_threshold: float = 0.5,
) -> dict[str, Any]:
    """Detect a median shift between windows without claiming causation.

    Intended for operational monitoring, not individual transaction decisions.
    Windows must contain comparable units and cohorts. Small windows are unknown,
    not normal.
    """
    if isinstance(minimum_samples_per_window, bool) or minimum_samples_per_window < 3:
        raise ValueError("minimum_samples_per_window must be at least 3")
    if not math.isfinite(relative_change_threshold) or relative_change_threshold <= 0:
        raise ValueError("relative_change_threshold must be finite and positive")

    def parse(values: Iterable[Any]) -> tuple[list[float], int]:
        parsed: list[float] = []
        invalid = 0
        for value in values:
            number = _finite_decimal(value)
            if number is None:
                invalid += 1
            else:
                parsed.append(float(number))
        return parsed, invalid

    reference, invalid_reference = parse(reference_values)
    recent, invalid_recent = parse(recent_values)
    base = {
        "algorithm_version": ALGORITHM_VERSION,
        "reference_sample_count": len(reference),
        "recent_sample_count": len(recent),
        "invalid_reference_values": invalid_reference,
        "invalid_recent_values": invalid_recent,
        "relative_change_threshold": relative_change_threshold,
    }
    if len(reference) < minimum_samples_per_window or len(recent) < minimum_samples_per_window:
        return {
            **base,
            "ready": False,
            "reason": "insufficient_window_samples",
            "shift_detected": None,
            "reference_median": None,
            "recent_median": None,
            "relative_change": None,
        }

    reference_median = statistics.median(reference)
    recent_median = statistics.median(recent)
    if reference_median == 0:
        relative_change = 0.0 if recent_median == 0 else None
        shift_detected = recent_median != 0
    else:
        relative_change = (recent_median - reference_median) / abs(reference_median)
        shift_detected = abs(relative_change) >= relative_change_threshold
    return {
        **base,
        "ready": True,
        "reference_median": reference_median,
        "recent_median": recent_median,
        "relative_change": round(relative_change, 6) if relative_change is not None else None,
        "shift_detected": bool(shift_detected),
        "action": "INVESTIGATE_DISTRIBUTION_SHIFT" if shift_detected else "NO_SHIFT_SIGNAL",
    }
