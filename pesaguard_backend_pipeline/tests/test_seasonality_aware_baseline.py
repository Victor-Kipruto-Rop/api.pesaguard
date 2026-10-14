from datetime import datetime, timedelta, timezone

import pytest

from pesaguard_backend_pipeline.seasonality_aware_baseline import (
    ALGORITHM_VERSION,
    assess_seasonal_outlier,
    assess_seasonal_volume,
)


TARGET = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)


def history(values, *, target=TARGET, step_days=7, hour=10):
    return [
        {
            "timestamp": (target - timedelta(days=step_days * (len(values) - i), hours=target.hour-hour)).isoformat(),
            "value": value,
        }
        for i, value in enumerate(values)
    ]


def test_insufficient_baseline_is_unavailable_not_normal():
    result = assess_seasonal_outlier(100, TARGET, history([10, 11, 10, 12]))
    assert result["ready"] is False
    assert result["anomalous"] is None
    assert result["reason"] == "insufficient_history"


def test_weekday_hour_cohort_detects_an_outlier_and_explains_baseline():
    result = assess_seasonal_outlier(100, TARGET, history([10, 11, 10, 12, 9, 10, 11, 10, 12, 9, 10, 11]))
    assert result["ready"] is True
    assert result["cohort"] == "weekday_hour"
    assert result["anomalous"] is True
    assert result["reason"] in {"robust_outlier", "zero_mad_deviation"}
    assert result["algorithm_version"] == ALGORITHM_VERSION
    assert result["sample_count"] == 12


def test_matching_baseline_value_is_not_flagged_when_mad_is_zero():
    result = assess_seasonal_outlier(10, TARGET, history([10] * 12))
    assert result["ready"] is True
    assert result["anomalous"] is False
    assert result["modified_z_score"] is None
    assert result["reason"] == "within_baseline"


def test_zero_mad_deviation_is_review_signal_not_fraud_verdict():
    result = assess_seasonal_outlier(50, TARGET, history([10] * 12))
    assert result["ready"] is True
    assert result["anomalous"] is True
    assert result["reason"] == "zero_mad_deviation"


def test_future_and_out_of_lookback_samples_are_excluded():
    points = history([10] * 12)
    points.extend([
        {"timestamp": (TARGET + timedelta(minutes=1)).isoformat(), "value": 100000},
        {"timestamp": (TARGET - timedelta(days=120)).isoformat(), "value": 100000},
    ])
    result = assess_seasonal_outlier(10, TARGET, points, lookback_days=90)
    assert result["ready"] is True
    assert result["sample_count"] == 12
    assert result["anomalous"] is False


def test_naive_timestamp_fails_closed():
    with pytest.raises(ValueError, match="timezone"):
        assess_seasonal_outlier(10, "2026-10-15T10:00:00", history([10] * 12))


def test_invalid_observation_returns_unavailable_result():
    result = assess_seasonal_outlier("NaN", TARGET, history([10] * 12))
    assert result["ready"] is False
    assert result["anomalous"] is None
    assert result["reason"] == "invalid_observation"


def test_parameters_are_validated():
    with pytest.raises(ValueError):
        assess_seasonal_outlier(10, TARGET, [], minimum_samples=4)
    with pytest.raises(ValueError):
        assess_seasonal_outlier(10, TARGET, [], lookback_days=0)
    with pytest.raises(ValueError):
        assess_seasonal_outlier(10, TARGET, [], modified_z_threshold=0)


def test_volume_allows_zero_but_rejects_negative_and_fractional_counts():
    valid = assess_seasonal_volume(0, TARGET, history([0] * 12))
    assert valid["ready"] is True
    invalid = assess_seasonal_volume(-1, TARGET, history([0] * 12))
    assert invalid["ready"] is False
    assert invalid["reason"] == "invalid_observation"
    fractional = assess_seasonal_volume(1.5, TARGET, history([0] * 12))
    assert fractional["ready"] is False
