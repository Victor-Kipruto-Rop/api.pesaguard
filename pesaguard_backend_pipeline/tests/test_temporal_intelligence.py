from datetime import datetime, timedelta, timezone

import pytest

from temporal_intelligence import (
    classify_temporal_evidence,
    parse_event_time,
    seasonal_amount_anomaly,
)


def test_daraja_compact_timestamp_is_interpreted_in_nairobi():
    parsed = parse_event_time("20261014120000")
    assert parsed == datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)


def test_naive_iso_timestamp_is_rejected_as_ambiguous():
    assert parse_event_time("2026-10-14T12:00:00") is None


def test_temporal_evidence_flags_late_arrival_and_keeps_settlement_lag():
    result = classify_temporal_evidence({
        "TransTime": "20261014120000",
        "ingested_at": "2026-10-14T09:10:00Z",
        "settlement_time": "2026-10-14T09:05:00Z",
    })
    assert result["classification"] == "LATE_ARRIVAL"
    assert result["ingestion_lag_seconds"] == 600
    assert result["settlement_lag_seconds"] == 300
    assert "ingestion_lag_exceeded_threshold" in result["reason_codes"]


def test_temporal_evidence_rejects_settlement_before_payment():
    result = classify_temporal_evidence({
        "event_time": "2026-10-14T09:00:00Z",
        "ingested_at": "2026-10-14T09:01:00Z",
        "settlement_time": "2026-10-14T08:59:00Z",
    })
    assert result["classification"] == "INVALID_TEMPORAL_ORDER"
    assert "settlement_precedes_payment_event" in result["reason_codes"]


def test_missing_temporal_evidence_is_not_reported_as_healthy():
    result = classify_temporal_evidence({
        "event_time": "2026-10-14T09:00:00Z",
    })
    assert result["evaluated"] is False
    assert result["classification"] == "INSUFFICIENT_DATA"


def _history_for_wednesdays():
    event = datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc)
    amounts = ["100", "101", "99", "100", "102"]
    rows = []
    for weeks, amount in enumerate(amounts, start=1):
        stamp = event - timedelta(days=7 * weeks)
        rows.append({
            "tenant_id": "tenant-a",
            "provider": "mpesa",
            "account_id": "paybill-a",
            "event_time": stamp.isoformat(),
            "amount": amount,
        })
    return event, rows


def test_seasonal_baseline_uses_weekday_hour_and_detects_outlier():
    event, history = _history_for_wednesdays()
    result = seasonal_amount_anomaly({
        "tenant_id": "tenant-a",
        "provider": "MPESA",
        "account_id": "paybill-a",
        "event_time": event.isoformat(),
        "amount": "10000",
    }, history)
    assert result["evaluated"] is True
    assert result["baseline_level"] == "weekday_hour"
    assert result["sample_count"] == 5
    assert result["outlier_candidate"] is True
    assert "seasonal_amount_outlier" in result["reason_codes"]


def test_seasonal_baseline_never_mixes_tenants_or_accounts():
    event, history = _history_for_wednesdays()
    contaminated = history + [
        {
            "tenant_id": "tenant-b",
            "provider": "mpesa",
            "account_id": "paybill-a",
            "event_time": (event - timedelta(days=7)).isoformat(),
            "amount": "1000000",
        },
        {
            "tenant_id": "tenant-a",
            "provider": "mpesa",
            "account_id": "other-account",
            "event_time": (event - timedelta(days=7)).isoformat(),
            "amount": "1000000",
        },
    ]
    result = seasonal_amount_anomaly({
        "tenant_id": "tenant-a",
        "provider": "mpesa",
        "account_id": "paybill-a",
        "event_time": event.isoformat(),
        "amount": "100",
    }, contaminated)
    assert result["evaluated"] is True
    assert result["sample_count"] == 5
    assert result["median_amount"] == "100"


def test_seasonal_baseline_reports_insufficient_history_instead_of_normal():
    event, history = _history_for_wednesdays()
    result = seasonal_amount_anomaly({
        "tenant_id": "tenant-a",
        "provider": "mpesa",
        "account_id": "paybill-a",
        "event_time": event.isoformat(),
        "amount": "100",
    }, history[:2])
    assert result["evaluated"] is False
    assert result["outlier_candidate"] is False
    assert "insufficient_scoped_baseline_samples" in result["reason_codes"]


def test_seasonal_baseline_requires_explicit_scope():
    result = seasonal_amount_anomaly(
        {"event_time": "2026-10-14T10:00:00Z", "amount": "100"},
        [],
    )
    assert result["evaluated"] is False
    assert "tenant_provider_account_scope_required" in result["reason_codes"]


def test_invalid_algorithm_thresholds_are_rejected():
    with pytest.raises(ValueError):
        seasonal_amount_anomaly({}, [], minimum_samples=2)
    with pytest.raises(ValueError):
        classify_temporal_evidence({}, max_ingestion_lag_seconds=-1)
    with pytest.raises(ValueError):
        seasonal_amount_anomaly({}, [], modified_z_threshold=float("nan"))


def test_seasonal_baseline_rejects_non_positive_current_amount():
    event, history = _history_for_wednesdays()
    result = seasonal_amount_anomaly({
        "tenant_id": "tenant-a",
        "provider": "mpesa",
        "account_id": "paybill-a",
        "event_time": event.isoformat(),
        "amount": "0",
    }, history)
    assert result["evaluated"] is False
    assert "positive_amount_and_timezone_aware_event_time_required" in result["reason_codes"]
