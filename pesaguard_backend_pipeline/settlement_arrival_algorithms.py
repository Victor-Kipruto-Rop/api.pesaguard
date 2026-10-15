"""Tenant-scoped, review-only settlement arrival-window estimation.

This module estimates empirical settlement duration windows from provider-confirmed
history. It is intentionally advisory: it never mutates transactions, balances, or
ledger state and does not claim that quantiles are probabilities.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import math
from typing import Any, Iterable, Mapping

ALGORITHM_VERSION = "settlement-arrival-window-v1"
_REQUIRED_SCOPE = ("tenant_id", "provider", "account_id", "currency")
_CONFIRMED_STATUSES = frozenset({"SETTLED", "CONFIRMED", "COMPLETED"})


def _aware_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _quantile(values: list[float], q: float) -> float:
    """Linear-interpolated quantile on sorted, finite observations."""
    ordered = sorted(values)
    if not ordered:
        raise ValueError("values must not be empty")
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def estimate_settlement_arrival_window(
    observations: Iterable[Mapping[str, Any]],
    *,
    expected_at: datetime | str,
    now: datetime | str,
    scope: Mapping[str, Any],
    minimum_samples: int = 20,
    max_observation_age_days: int = 180,
    confirmed_statuses: Iterable[str] = _CONFIRMED_STATUSES,
    history_complete: bool = True,
) -> dict[str, Any]:
    """Estimate p50/p90 settlement windows from exact-scope confirmed history.

    ``scope`` must explicitly contain tenant_id, provider, account_id and currency.
    Observations outside that exact scope, with unknown status, invalid timestamps,
    negative duration, or too-old/future settlement timestamps are excluded. A
    truncated/unknown history or undersized baseline is never treated as normal.
    """
    if not isinstance(scope, Mapping) or any(
        not isinstance(scope.get(key), str) or not scope[key].strip()
        for key in _REQUIRED_SCOPE
    ):
        raise ValueError("scope must provide non-empty tenant_id, provider, account_id and currency")
    if isinstance(minimum_samples, bool) or not isinstance(minimum_samples, int) or minimum_samples < 3:
        raise ValueError("minimum_samples must be an integer >= 3")
    if isinstance(max_observation_age_days, bool) or not isinstance(max_observation_age_days, int) or max_observation_age_days < 1:
        raise ValueError("max_observation_age_days must be an integer >= 1")

    reference = _aware_datetime(expected_at)
    current = _aware_datetime(now)
    if reference is None or current is None:
        raise ValueError("expected_at and now must be timezone-aware datetimes or ISO timestamps")
    if reference > current:
        raise ValueError("expected_at must not be in the future")

    allowed_statuses = {str(status).strip().upper() for status in confirmed_statuses if str(status).strip()}
    if not allowed_statuses:
        raise ValueError("confirmed_statuses must not be empty")

    cutoff = current - timedelta(days=max_observation_age_days)
    durations: list[float] = []
    excluded: dict[str, int] = {}
    for item in observations:
        if not isinstance(item, Mapping):
            excluded["invalid_observation"] = excluded.get("invalid_observation", 0) + 1
            continue
        if any(item.get(key) != scope[key] for key in _REQUIRED_SCOPE):
            excluded["scope_mismatch_or_missing"] = excluded.get("scope_mismatch_or_missing", 0) + 1
            continue
        status = str(item.get("status", "")).strip().upper()
        if status not in allowed_statuses:
            excluded["not_provider_confirmed"] = excluded.get("not_provider_confirmed", 0) + 1
            continue
        initiated = _aware_datetime(item.get("initiated_at"))
        settled = _aware_datetime(item.get("settled_at"))
        if initiated is None or settled is None:
            excluded["invalid_or_naive_timestamp"] = excluded.get("invalid_or_naive_timestamp", 0) + 1
            continue
        if settled > current:
            excluded["future_settlement_timestamp"] = excluded.get("future_settlement_timestamp", 0) + 1
            continue
        if settled < cutoff:
            excluded["stale_observation"] = excluded.get("stale_observation", 0) + 1
            continue
        seconds = (settled - initiated).total_seconds()
        if seconds < 0:
            excluded["negative_duration"] = excluded.get("negative_duration", 0) + 1
            continue
        durations.append(seconds)

    base: dict[str, Any] = {
        "algorithm_version": ALGORITHM_VERSION,
        "mode": "advisory_only",
        "ready": False,
        "status": "UNAVAILABLE",
        "sample_count": len(durations),
        "excluded_count": sum(excluded.values()),
        "excluded_reasons": excluded,
        "minimum_samples": minimum_samples,
        "history_complete": bool(history_complete),
        "scope": {key: scope[key] for key in _REQUIRED_SCOPE},
        "median_duration_seconds": None,
        "p90_duration_seconds": None,
        "predicted_median_arrival_at": None,
        "predicted_likely_by_at": None,
        "is_late_vs_p90": None,
        "reason_codes": [],
        "can_auto_settle": False,
        "can_post_ledger": False,
    }
    if not history_complete:
        base["reason_codes"].append("HISTORY_INCOMPLETE")
    if len(durations) < minimum_samples:
        base["reason_codes"].append("BASELINE_TOO_SMALL")
    if base["reason_codes"]:
        return base

    median_seconds = _quantile(durations, 0.50)
    p90_seconds = _quantile(durations, 0.90)
    median_eta = reference + timedelta(seconds=median_seconds)
    p90_eta = reference + timedelta(seconds=p90_seconds)
    if current <= median_eta:
        status = "WITHIN_TYPICAL_WINDOW"
    elif current <= p90_eta:
        status = "BEYOND_MEDIAN_WITHIN_P90"
    else:
        status = "PAST_HISTORICAL_P90_REVIEW"

    base.update({
        "ready": True,
        "status": status,
        "median_duration_seconds": round(median_seconds, 3),
        "p90_duration_seconds": round(p90_seconds, 3),
        "predicted_median_arrival_at": median_eta.isoformat().replace("+00:00", "Z"),
        "predicted_likely_by_at": p90_eta.isoformat().replace("+00:00", "Z"),
        "is_late_vs_p90": current > p90_eta,
        "reason_codes": ["HISTORICAL_WINDOW_ESTIMATE_ONLY"],
    })
    return base
