from datetime import datetime, timedelta, timezone

import pytest

from settlement_arrival_algorithms import estimate_settlement_arrival_window

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
SCOPE = {
    "tenant_id": "tenant-a",
    "provider": "mpesa",
    "account_id": "paybill-001",
    "currency": "KES",
}


def observations(count=25, seconds=3600, **overrides):
    rows = []
    for index in range(count):
        initiated = NOW - timedelta(days=index + 1)
        rows.append({
            **SCOPE,
            "status": "SETTLED",
            "initiated_at": initiated.isoformat(),
            "settled_at": (initiated + timedelta(seconds=seconds + index * 60)).isoformat(),
            **overrides,
        })
    return rows


def test_estimator_returns_scoped_empirical_window_and_never_authorizes_posting():
    result = estimate_settlement_arrival_window(
        observations(), expected_at=NOW - timedelta(hours=2), now=NOW, scope=SCOPE,
    )
    assert result["ready"] is True
    assert result["sample_count"] == 25
    assert result["median_duration_seconds"] > 3600
    assert result["p90_duration_seconds"] >= result["median_duration_seconds"]
    assert result["can_auto_settle"] is False
    assert result["can_post_ledger"] is False
    assert result["mode"] == "advisory_only"


def test_small_baseline_is_unavailable_not_normal():
    result = estimate_settlement_arrival_window(
        observations(5), expected_at=NOW - timedelta(hours=2), now=NOW,
        scope=SCOPE, minimum_samples=20,
    )
    assert result["ready"] is False
    assert result["status"] == "UNAVAILABLE"
    assert "BASELINE_TOO_SMALL" in result["reason_codes"]
    assert result["is_late_vs_p90"] is None


def test_incomplete_history_fails_closed_even_with_enough_samples():
    result = estimate_settlement_arrival_window(
        observations(), expected_at=NOW - timedelta(hours=2), now=NOW,
        scope=SCOPE, history_complete=False,
    )
    assert result["ready"] is False
    assert "HISTORY_INCOMPLETE" in result["reason_codes"]


def test_cross_tenant_provider_account_and_currency_history_is_excluded():
    rows = observations()
    rows[0]["tenant_id"] = "tenant-b"
    rows[1]["provider"] = "other-provider"
    rows[2]["account_id"] = "other-account"
    rows[3]["currency"] = "USD"
    result = estimate_settlement_arrival_window(
        rows, expected_at=NOW - timedelta(hours=2), now=NOW, scope=SCOPE,
    )
    assert result["sample_count"] == 21
    assert result["excluded_reasons"]["scope_mismatch_or_missing"] == 4


def test_pending_or_unknown_provider_states_do_not_train_baseline():
    rows = observations()
    rows[0]["status"] = "PENDING"
    rows[1]["status"] = "SUCCESS"  # Payment success is not assumed to mean settlement.
    result = estimate_settlement_arrival_window(
        rows, expected_at=NOW - timedelta(hours=2), now=NOW, scope=SCOPE,
    )
    assert result["sample_count"] == 23
    assert result["excluded_reasons"]["not_provider_confirmed"] == 2


def test_invalid_naive_and_negative_timestamps_are_excluded():
    rows = observations()
    rows[0]["initiated_at"] = "2026-10-14T12:00:00"  # Naive time is ambiguous.
    rows[1]["settled_at"] = (NOW - timedelta(days=2)).isoformat()
    rows[1]["initiated_at"] = (NOW - timedelta(days=1)).isoformat()  # Negative duration.
    result = estimate_settlement_arrival_window(
        rows, expected_at=NOW - timedelta(hours=2), now=NOW, scope=SCOPE,
    )
    assert result["excluded_reasons"]["invalid_or_naive_timestamp"] == 1
    assert result["excluded_reasons"]["negative_duration"] == 1


def test_stale_and_future_settlement_events_are_excluded():
    rows = observations()
    rows[0]["settled_at"] = (NOW - timedelta(days=250)).isoformat()
    rows[1]["settled_at"] = (NOW + timedelta(minutes=1)).isoformat()
    result = estimate_settlement_arrival_window(
        rows, expected_at=NOW - timedelta(hours=2), now=NOW, scope=SCOPE,
        max_observation_age_days=180,
    )
    assert result["excluded_reasons"]["stale_observation"] == 1
    assert result["excluded_reasons"]["future_settlement_timestamp"] == 1


def test_late_status_only_after_p90_window():
    rows = observations(seconds=3600)
    expected_at = NOW - timedelta(hours=4)
    result = estimate_settlement_arrival_window(
        rows, expected_at=expected_at, now=NOW, scope=SCOPE,
    )
    assert result["ready"] is True
    assert result["status"] == "PAST_HISTORICAL_P90_REVIEW"
    assert result["is_late_vs_p90"] is True


def test_invalid_scope_and_naive_request_times_raise():
    with pytest.raises(ValueError, match="scope"):
        estimate_settlement_arrival_window(
            observations(), expected_at=NOW, now=NOW, scope={"tenant_id": "tenant-a"},
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        estimate_settlement_arrival_window(
            observations(), expected_at="2026-10-15T10:00:00", now=NOW, scope=SCOPE,
        )


def test_invalid_configuration_fails_closed():
    with pytest.raises(ValueError, match="minimum_samples"):
        estimate_settlement_arrival_window(
            observations(), expected_at=NOW, now=NOW, scope=SCOPE, minimum_samples=2,
        )
    with pytest.raises(ValueError, match="future"):
        estimate_settlement_arrival_window(
            observations(), expected_at=NOW + timedelta(minutes=1), now=NOW, scope=SCOPE,
        )
