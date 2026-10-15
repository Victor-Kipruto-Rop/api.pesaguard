"""Advisory settlement-delay intelligence for tenant-scoped reconciliation history.

This module never changes settlement state, retries payments, or moves funds.
The caller must supply confirmed, comparable historical settlement durations from
the same tenant/provider/account/currency and settlement class.
"""
from __future__ import annotations

import math
import statistics
from typing import Any, Iterable, Mapping

ALGORITHM_VERSION = "settlement-delay-v1"


def _finite_seconds(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(parsed) or parsed < 0:
        return None
    return parsed


def _finite_config_number(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a finite number")
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{name} must be a finite number") from exc
    if not math.isfinite(parsed):
        raise ValueError(f"{name} must be a finite number")
    return parsed


def _quantile(values: list[float], q: float) -> float:
    """Linearly interpolated quantile, independent of optional numeric packages."""
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def assess_settlement_delay(
    current_delay_seconds: Any,
    historical_delays_seconds: Iterable[Any],
    *,
    tenant_id: str,
    provider: str,
    account_id: str,
    currency: str,
    minimum_samples: int = 8,
    upper_quantile: float = 0.90,
    minimum_grace_seconds: float = 300.0,
    robust_mad_multiplier: float = 3.0,
) -> dict[str, Any]:
    """Assess whether a settlement is unusually delayed for its peer cohort.

    The result is a monitoring/review signal only. Insufficient history returns
    ready=False and late=None (not a healthy result). Scope identifiers are required
    so callers cannot accidentally invoke the algorithm without declaring the
    intended tenant/provider/account/currency cohort.

    Historical durations must be produced from confirmed settlement events and
    normalized to a consistent definition (for example, provider acceptance to
    settlement confirmation). Business calendars, provider cutoffs, and holidays
    must be applied upstream if they matter for the integration.
    """
    scope = {
        "tenant_id": str(tenant_id or "").strip(),
        "provider": str(provider or "").strip().casefold(),
        "account_id": str(account_id or "").strip(),
        "currency": str(currency or "").strip().upper(),
    }
    if any(not value for value in scope.values()):
        raise ValueError("tenant_id, provider, account_id, and currency are required")
    if isinstance(minimum_samples, bool) or not isinstance(minimum_samples, int) or minimum_samples < 5:
        raise ValueError("minimum_samples must be an integer of at least 5")
    upper_quantile = _finite_config_number(upper_quantile, "upper_quantile")
    minimum_grace_seconds = _finite_config_number(minimum_grace_seconds, "minimum_grace_seconds")
    robust_mad_multiplier = _finite_config_number(robust_mad_multiplier, "robust_mad_multiplier")
    if not 0.5 < upper_quantile < 1:
        raise ValueError("upper_quantile must be between 0.5 and 1")
    if minimum_grace_seconds < 0:
        raise ValueError("minimum_grace_seconds must be finite and non-negative")
    if robust_mad_multiplier <= 0:
        raise ValueError("robust_mad_multiplier must be finite and positive")

    current = _finite_seconds(current_delay_seconds)
    if current is None:
        raise ValueError("current_delay_seconds must be finite and non-negative")

    history: list[float] = []
    invalid_count = 0
    for value in historical_delays_seconds:
        parsed = _finite_seconds(value)
        if parsed is None:
            invalid_count += 1
        else:
            history.append(parsed)

    base = {
        "algorithm_version": ALGORITHM_VERSION,
        "scope": scope,
        "current_delay_seconds": current,
        "sample_count": len(history),
        "invalid_history_count": invalid_count,
        "minimum_samples": minimum_samples,
        "upper_quantile": upper_quantile,
        "minimum_grace_seconds": minimum_grace_seconds,
        "is_late": None,
        "threshold_seconds": None,
        "median_seconds": None,
        "upper_quantile_seconds": None,
        "mad_seconds": None,
    }
    if len(history) < minimum_samples:
        return {
            **base,
            "ready": False,
            "reason": "insufficient_confirmed_history",
            "action": "INSUFFICIENT_DATA",
        }

    median = statistics.median(history)
    mad = statistics.median(abs(value - median) for value in history)
    quantile_bound = _quantile(history, upper_quantile)
    robust_bound = median + robust_mad_multiplier * 1.4826 * mad
    threshold = max(quantile_bound, robust_bound) + minimum_grace_seconds
    is_late = current > threshold
    return {
        **base,
        "ready": True,
        "median_seconds": round(median, 3),
        "upper_quantile_seconds": round(quantile_bound, 3),
        "mad_seconds": round(mad, 3),
        "robust_bound_seconds": round(robust_bound, 3),
        "threshold_seconds": round(threshold, 3),
        "is_late": is_late,
        "action": "INVESTIGATE_SETTLEMENT_DELAY" if is_late else "NO_DELAY_SIGNAL",
        "interpretation": (
            "Settlement age exceeds the historical peer threshold."
            if is_late
            else "Settlement age does not exceed the current historical peer threshold."
        ),
    }
