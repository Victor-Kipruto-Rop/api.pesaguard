"""
Basic tests for anomaly detection rules.
Run with: pytest tests/
"""
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "streaming", "flink_jobs"))

from anomaly_rules import check_for_anomalies  # noqa: E402


def test_clean_transaction_has_no_anomalies():
    event = {"TransID": "ABC123", "TransAmount": "500"}
    result = check_for_anomalies(event, seen_trans_ids=set())
    assert result == []


def test_duplicate_transaction_flagged():
    event = {"TransID": "ABC123", "TransAmount": "500"}
    result = check_for_anomalies(event, seen_trans_ids={"ABC123"})
    assert "duplicate_transaction_id" in result


def test_large_amount_flagged():
    event = {"TransID": "XYZ999", "TransAmount": "200000"}
    result = check_for_anomalies(event, seen_trans_ids=set())
    assert any("amount_exceeds_threshold" in a for a in result)


def test_zero_amount_flagged():
    event = {"TransID": "ZERO1", "TransAmount": "0"}
    result = check_for_anomalies(event, seen_trans_ids=set())
    assert "invalid_or_zero_amount" in result


def test_invalid_amount_type_flagged():
    event = {"TransID": "BAD1", "TransAmount": "not_a_number"}
    result = check_for_anomalies(event, seen_trans_ids=set())
    assert "invalid_or_zero_amount" in result



def test_robust_historical_amount_outlier_is_explained():
    from anomaly_rules import robust_amount_modified_zscore

    baseline = [100] * 25
    score = robust_amount_modified_zscore(500, baseline)
    assert score is not None and score >= 3.5

    result = check_for_anomalies(
        {"TransID": "OUTLIER1", "TransAmount": "500"},
        seen_trans_ids=set(),
        tenant_settings={"historical_amounts": baseline},
    )
    assert "historical_amount_outlier_robust_zscore" in result


def test_robust_baseline_is_ignored_when_sample_is_too_small():
    from anomaly_rules import robust_amount_modified_zscore

    assert robust_amount_modified_zscore(500, [100] * 10) is None


def test_robust_baseline_does_not_flag_typical_amount():
    from anomaly_rules import robust_amount_modified_zscore

    baseline = list(range(90, 111)) + [100, 101, 99, 100]
    score = robust_amount_modified_zscore(102, baseline)
    assert score is not None and score < 3.5
