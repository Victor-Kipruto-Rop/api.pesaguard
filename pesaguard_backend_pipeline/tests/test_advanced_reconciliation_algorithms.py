from datetime import datetime, timedelta, timezone

import pytest

from pesaguard_backend_pipeline.advanced_reconciliation_algorithms import (
    ALGORITHM_VERSION,
    detect_distribution_shift,
    seasonal_amount_assessment,
)


def _history_for(dt, amounts, currency="KES"):
    return [
        {"amount": amount, "currency": currency,
         "timestamp": (dt - timedelta(days=7 * (index + 1))).isoformat()}
        for index, amount in enumerate(amounts)
    ]


def test_seasonal_amount_assessment_uses_same_weekday_hour_and_currency():
    event_time = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)
    history = _history_for(event_time, [100, 101, 99, 100, 102, 98, 100, 101])
    history.append({"amount": "99999", "currency": "USD", "timestamp": event_time.isoformat()})
    result = seasonal_amount_assessment(
        "100", history, event_time=event_time, timezone_name="UTC", currency="KES"
    )
    assert result["algorithm_version"] == ALGORITHM_VERSION
    assert result["ready"] is True
    assert result["sample_count"] == 8
    assert result["is_outlier"] is False


def test_seasonal_amount_assessment_flags_extreme_value_as_review_signal():
    event_time = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)
    history = _history_for(event_time, [100, 101, 99, 100, 102, 98, 100, 101])
    result = seasonal_amount_assessment(
        "10000", history, event_time=event_time, timezone_name="UTC"
    )
    assert result["ready"] is True
    assert result["is_outlier"] is True
    assert result["action"] == "REVIEW_SIGNAL"


def test_seasonal_baseline_is_unavailable_when_history_is_small():
    event_time = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)
    result = seasonal_amount_assessment(
        "100", _history_for(event_time, [100, 101, 99, 100, 102]),
        event_time=event_time, timezone_name="UTC"
    )
    assert result["ready"] is False
    assert result["is_outlier"] is None


@pytest.mark.parametrize("kwargs", [
    {"minimum_samples": 4},
    {"modified_z_threshold": float("nan")},
])
def test_seasonal_algorithm_rejects_invalid_parameters(kwargs):
    with pytest.raises(ValueError):
        seasonal_amount_assessment(
            "100", [], event_time=datetime.now(timezone.utc), **kwargs
        )


def test_seasonal_algorithm_rejects_naive_timestamp():
    with pytest.raises(ValueError, match="timezone-aware"):
        seasonal_amount_assessment(
            "100", [], event_time="2026-10-15T10:00:00"
        )


def test_distribution_shift_detects_median_change():
    result = detect_distribution_shift(
        [100] * 12, [180] * 12,
        minimum_samples_per_window=10, relative_change_threshold=0.5,
    )
    assert result["ready"] is True
    assert result["shift_detected"] is True
    assert result["relative_change"] == 0.8


def test_distribution_shift_reports_insufficient_data_as_unavailable():
    result = detect_distribution_shift([100, 101], [180, 181])
    assert result["ready"] is False
    assert result["shift_detected"] is None


def test_distribution_shift_handles_zero_reference_median():
    result = detect_distribution_shift(
        [0] * 10, [1] * 10, minimum_samples_per_window=10
    )
    assert result["ready"] is True
    assert result["shift_detected"] is True
    assert result["relative_change"] is None


def test_distribution_shift_ignores_invalid_values_but_reports_them():
    result = detect_distribution_shift(
        [100] * 10 + ["NaN"], [100] * 10 + ["bad"],
        minimum_samples_per_window=10,
    )
    assert result["ready"] is True
    assert result["invalid_reference_values"] == 1
    assert result["invalid_recent_values"] == 1
    assert result["shift_detected"] is False



def test_seasonal_zero_mad_flags_deviation_without_infinite_score():
    event_time = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)
    history = _history_for(event_time, [100] * 8)
    result = seasonal_amount_assessment(
        "1000", history, event_time=event_time, timezone_name="UTC"
    )
    assert result["ready"] is True
    assert result["is_outlier"] is True
    assert result["modified_z"] is None
