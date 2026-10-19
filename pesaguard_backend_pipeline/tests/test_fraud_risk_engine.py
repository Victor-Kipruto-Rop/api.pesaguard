from datetime import datetime, timedelta, timezone

from fraud_risk_engine import (
    assess_transaction, calculate_features, detect_cumulative_subthreshold_activity, evaluate_predictions,
)


def tx(identifier, *, amount="1000", customer="254700000001", merchant="600000", when="20260914100000"):
    return {
        "TransID": identifier,
        "TransAmount": amount,
        "MSISDN": customer,
        "BusinessShortCode": merchant,
        "TransTime": when,
    }


def test_normal_transaction_is_low_and_processed():
    decision = assess_transaction(tx("normal-1"), [tx("old-1", when="20260913090000")])
    assert decision.risk_level == "LOW"
    assert decision.action == "process"
    assert decision.reason_codes == ()


def test_synthetic_fraud_triggers_velocity_duplicate_and_odd_hour():
    current = tx("fraud-2", amount="300000", when="20260914030000")
    history = [
        tx("fraud-1", amount="299000", when="20260914025959"),
        tx("fraud-0", amount="298000", when="20260914025950"),
        tx("fraud-2", amount="297000", when="20260914025940"),
        tx("fraud-3", amount="296000", when="20260914025930"),
        tx("fraud-4", amount="295000", when="20260914025920"),
    ]
    decision = assess_transaction(current, history)
    assert decision.risk_level in {"HIGH", "CRITICAL"}
    assert {"velocity", "amount_threshold", "unusual_time"}.issubset(decision.rules_triggered)
    assert decision.action in {"review", "escalate"}


def test_high_value_legitimate_transaction_can_use_tenant_baseline():
    decision = assess_transaction(
        tx("legitimate-high", amount="200000", merchant="trusted-merchant"),
        [tx(f"history-{index}", amount="195000", merchant="trusted-merchant", when=f"202609{index + 1:02d}100000") for index in range(10)],
        {"mean_amount": 195000, "std_amount": 5000, "customer_mean_amount": 190000},
    )
    assert decision.risk_level in {"LOW", "MEDIUM"}
    assert "amount_threshold" in decision.rules_triggered


def test_high_frequency_merchant_is_not_automatically_fraud():
    history = [tx(f"merchant-{index}", customer=f"254700{index:06d}", merchant="busy") for index in range(20)]
    decision = assess_transaction(tx("merchant-current", merchant="busy"), history)
    assert decision.action in {"process", "monitor"}
    assert "velocity" not in decision.rules_triggered


def test_duplicate_activity_and_rapid_changes_are_explainable():
    history = [
        tx("same-id", amount="100"),
        tx("other-1", amount="200"),
        tx("other-2", amount="400"),
        tx("other-3", amount="800"),
    ]
    decision = assess_transaction(tx("same-id", amount="1600"), history)
    assert "duplicate_activity" in decision.rules_triggered
    assert "rapid_transaction_changes" in decision.rules_triggered
    assert decision.model_version
    assert decision.features.as_dict()["amount"] == 1600.0


def test_evaluation_reports_precision_recall_false_positives_and_latency():
    normal = assess_transaction(tx("eval-normal"))
    suspicious = assess_transaction(tx("eval-fraud", amount="400000", when="20260914020000"))
    metrics = evaluate_predictions([(normal, False), (suspicious, True), (normal, True)])
    assert metrics["precision"] >= 0
    assert metrics["recall"] >= 0
    assert metrics["false_positives"] >= 0
    assert metrics["false_negatives"] >= 0
    assert metrics["detection_latency_ms"] is None
    assert metrics["latency_sample_count"] == 0



def test_daraja_compact_timestamp_uses_kenya_local_hour_for_time_risk():
    daraja = assess_transaction(tx("night-local", when="20261014020000"))
    iso_utc = assess_transaction({
        "TransID": "night-iso", "TransAmount": "1000", "MSISDN": "254700000001",
        "BusinessShortCode": "600000", "timestamp": "2026-10-13T23:00:00Z",
    })
    assert daraja.features.time_pattern == 1.0
    assert iso_utc.features.time_pattern == 1.0


def test_established_customer_history_does_not_increase_risk_score():
    baseline = {"mean_amount": 1000, "std_amount": 250, "customer_mean_amount": 1000}
    current = tx("history-current", amount="1000", when="20261014100000")
    new_customer = assess_transaction(current, [], baseline)
    history = [
        tx(f"known-{index}", amount="1000", when="20261013100000")
        for index in range(20)
    ]
    established_customer = assess_transaction(current, history, baseline)
    assert established_customer.features.customer_history == 1.0
    assert new_customer.features.customer_history == 0.0
    assert established_customer.risk_score <= new_customer.risk_score


def test_risk_configuration_rejects_invalid_thresholds():
    import pytest

    with pytest.raises(ValueError):
        assess_transaction(tx("bad-threshold"), amount_threshold=float("nan"))
    with pytest.raises(ValueError):
        assess_transaction(tx("bad-velocity"), velocity_limit=0)


def test_detection_latency_uses_event_time_not_decision_age():
    event_time = datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc)
    decision = assess_transaction(tx("latency-test", when="20261014130000"))
    metrics = evaluate_predictions([(decision, False, event_time)])
    expected_ms = max(0.0, (decision.detected_at - event_time).total_seconds() * 1000)
    assert metrics["latency_sample_count"] == 1
    assert metrics["detection_latency_ms"] == expected_ms



def test_cumulative_activity_counts_distinct_customer_events():
    current = tx("current", amount="40000", when="20261014120000")
    history = [
        tx("prior-1", amount="35000", when="20261014115000"),
        tx("prior-2", amount="30000", when="20261014115500"),
        tx("prior-2", amount="30000", when="20261014115500"),
        tx("other-customer", amount="90000", customer="254700000099", when="20261014115900"),
        tx("stale", amount="90000", when="20261014090000"),
    ]
    result = detect_cumulative_subthreshold_activity(
        current, history, threshold=100000, window_seconds=3600, min_transactions=3
    )
    assert result["evaluated"] is True
    assert result["triggered"] is True
    assert result["transaction_count"] == 3
    assert result["total_amount"] == 105000.0
    assert result["reason_codes"] == ["cumulative_subthreshold_activity"]


def test_cumulative_activity_requires_valid_identity_and_subthreshold_amount():
    large = detect_cumulative_subthreshold_activity(tx("large", amount="100000"), [], threshold=100000)
    missing_identity = detect_cumulative_subthreshold_activity(
        {"TransID": "no-customer", "TransAmount": "100", "TransTime": "20261014120000"},
        [], threshold=100000
    )
    assert large["triggered"] is False
    assert missing_identity["evaluated"] is False
    assert missing_identity["triggered"] is False


def test_cumulative_activity_signal_is_explainable_and_non_blocking():
    current = tx("current", amount="40000", when="20261014120000")
    history = [
        tx("prior-1", amount="35000", when="20261014115000"),
        tx("prior-2", amount="30000", when="20261014115500"),
    ]
    decision = assess_transaction(current, history, amount_threshold=100000)
    assert "cumulative_subthreshold_activity" in decision.rules_triggered
    assert decision.model_version
    assert decision.action in {"process", "monitor", "review", "escalate"}


def test_missing_transaction_ids_do_not_create_false_duplicate_risk():
    decision = assess_transaction(
        {"TransAmount": "1000", "MSISDN": "254700000001"},
        [{"TransAmount": "1000", "MSISDN": "254700000001"}],
    )
    assert "duplicate_activity" not in decision.rules_triggered


def test_risk_history_rejects_cross_tenant_and_cross_account_rows():
    current = {
        **tx("current-scope", amount="1000"),
        "tenant_id": "tenant-a",
        "provider_account_id": "account-1",
    }
    foreign = {
        **tx("current-scope", amount="1000"),
        "tenant_id": "tenant-b",
        "provider_account_id": "account-1",
    }
    decision = assess_transaction(current, [foreign])
    assert "duplicate_activity" not in decision.rules_triggered
    assert decision.features.customer_history == 0.0

    same_tenant_wrong_account = {
        **tx("current-scope", amount="1000"),
        "tenant_id": "tenant-a",
        "provider_account_id": "account-2",
    }
    decision = assess_transaction(current, [same_tenant_wrong_account])
    assert "duplicate_activity" not in decision.rules_triggered


def test_scoped_risk_history_fails_closed_when_scope_metadata_is_missing():
    current = {
        **tx("current-scope", amount="1000"),
        "tenant_id": "tenant-a",
        "provider_account_id": "account-1",
    }
    unscoped_history = tx("current-scope", amount="1000")
    decision = assess_transaction(current, [unscoped_history])
    assert "duplicate_activity" not in decision.rules_triggered
    assert decision.features.customer_history == 0.0


def test_scoped_risk_history_retains_rows_from_the_same_scope():
    current = {
        **tx("current-scope", amount="1000"),
        "tenant_id": "tenant-a",
        "provider_account_id": "account-1",
    }
    same_scope = {
        **tx("current-scope", amount="1000"),
        "tenant_id": "tenant-a",
        "provider_account_id": "account-1",
    }
    decision = assess_transaction(current, [same_scope])
    assert "duplicate_activity" in decision.rules_triggered
    assert decision.features.customer_history == 0.05
