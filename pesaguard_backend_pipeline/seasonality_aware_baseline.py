"""Seasonality-aware robust baselines for transaction monitoring.

This module is intentionally pure and advisory. It does not authorize matching,
blocking, refunds, or ledger postings. Callers must supply tenant/provider/account
scoped history and persist the result with the caller's audit record.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from statistics import median
from typing import Any, Iterable, Mapping, Sequence

ALGORITHM_VERSION = "seasonal-robust-baseline-v1"


@dataclass(frozen=True)
class BaselineAssessment:
    algorithm_version: str
    ready: bool
    anomalous: bool | None
    reason: str
    cohort: str
    sample_count: int
    baseline_median: float | None
    baseline_mad: float | None
    modified_z_score: float | None
    threshold: float
    observation: float | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _aware_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            raise ValueError("timestamp is required")
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _finite_decimal(value: Any) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("observation must be a valid decimal") from exc
    if not parsed.is_finite():
        raise ValueError("observation must be finite")
    return parsed


def _cohort_key(timestamp: datetime, cohort: str) -> tuple[int, ...]:
    if cohort == "weekday_hour":
        return (timestamp.weekday(), timestamp.hour)
    if cohort == "hour":
        return (timestamp.hour,)
    if cohort == "weekday":
        return (timestamp.weekday(),)
    if cohort == "global":
        return ()
    raise ValueError("unsupported cohort")


def assess_seasonal_outlier(
    observation: Any,
    timestamp: Any,
    history: Iterable[Mapping[str, Any]],
    *,
    minimum_samples: int = 12,
    lookback_days: int = 90,
    modified_z_threshold: float = 3.5,
    allowed_cohorts: Sequence[str] = ("weekday_hour", "hour", "weekday", "global"),
) -> dict[str, Any]:
    """Assess an observation against a robust, seasonality-aware history.

    Candidate cohorts are attempted in order. The first cohort with enough valid
    prior samples is selected. Only strictly earlier observations within lookback
    are considered. Missing/invalid history is ignored but counted nowhere; if
    no cohort has enough valid points, the result is explicitly unavailable.
    Timestamps must be timezone-aware; callers should normalize to UTC at ingestion.
    """
    if minimum_samples < 5:
        raise ValueError("minimum_samples must be at least 5")
    if lookback_days < 1:
        raise ValueError("lookback_days must be positive")
    if modified_z_threshold <= 0:
        raise ValueError("modified_z_threshold must be positive")
    if not allowed_cohorts or any(
        cohort not in {"weekday_hour", "hour", "weekday", "global"}
        for cohort in allowed_cohorts
    ):
        raise ValueError("allowed_cohorts contains an unsupported cohort")

    target_time = _aware_datetime(timestamp)
    try:
        target_value = _finite_decimal(observation)
    except ValueError:
        return BaselineAssessment(
            ALGORITHM_VERSION, False, None, "invalid_observation", "none", 0,
            None, None, None, float(modified_z_threshold), None,
        ).to_dict()

    cutoff = target_time - timedelta(days=lookback_days)
    parsed_history: list[tuple[datetime, Decimal]] = []
    for item in history:
        if not isinstance(item, Mapping):
            continue
        try:
            point_time = _aware_datetime(item.get("timestamp"))
            point_value = _finite_decimal(item.get("value"))
        except ValueError:
            continue
        if cutoff <= point_time < target_time:
            parsed_history.append((point_time, point_value))

    selected: tuple[str, list[Decimal]] | None = None
    for cohort in allowed_cohorts:
        target_key = _cohort_key(target_time, cohort)
        values = [
            value for point_time, value in parsed_history
            if _cohort_key(point_time, cohort) == target_key
        ]
        if len(values) >= minimum_samples:
            selected = (cohort, values)
            break

    if selected is None:
        best_cohort = "none"
        best_count = 0
        for cohort in allowed_cohorts:
            count = sum(
                _cohort_key(point_time, cohort) == _cohort_key(target_time, cohort)
                for point_time, _ in parsed_history
            )
            if count > best_count:
                best_cohort, best_count = cohort, count
        return BaselineAssessment(
            ALGORITHM_VERSION, False, None, "insufficient_history", best_cohort,
            best_count, None, None, None, float(modified_z_threshold),
            float(target_value),
        ).to_dict()

    cohort, values = selected
    numbers = [float(value) for value in values]
    center = median(numbers)
    deviations = [abs(value - center) for value in numbers]
    mad = median(deviations)
    current = float(target_value)

    # With MAD=0, do not divide by zero or claim the sample is normal.
    # A value equal to the baseline is normal; any deviation is a review signal.
    if mad == 0:
        z_score = None
        anomalous = current != center
        reason = "zero_mad_deviation" if anomalous else "within_baseline"
    else:
        z_score = (current - center) / (1.4826 * mad)
        anomalous = abs(z_score) >= modified_z_threshold
        reason = "robust_outlier" if anomalous else "within_baseline"

    return BaselineAssessment(
        ALGORITHM_VERSION, True, anomalous, reason, cohort, len(numbers),
        center, mad, z_score, float(modified_z_threshold), current,
    ).to_dict()


def assess_seasonal_volume(
    observation_count: Any,
    timestamp: Any,
    historical_counts: Iterable[Mapping[str, Any]],
    **kwargs: Any,
) -> dict[str, Any]:
    """Convenience wrapper for count/volume monitoring; zero is a valid count."""
    try:
        count = _finite_decimal(observation_count)
        if count < 0 or count != count.to_integral_value():
            raise ValueError("count must be a non-negative integer")
    except ValueError:
        return BaselineAssessment(
            ALGORITHM_VERSION, False, None, "invalid_observation", "none", 0,
            None, None, None, float(kwargs.get("modified_z_threshold", 3.5)), None,
        ).to_dict()
    return assess_seasonal_outlier(count, timestamp, historical_counts, **kwargs)
