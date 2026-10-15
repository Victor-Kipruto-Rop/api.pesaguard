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



def test_invoice_allocation_returns_unique_candidate_not_posted_state():
    from pesaguard_backend_pipeline.advanced_reconciliation_algorithms import find_invoice_allocation_candidates
    result = find_invoice_allocation_candidates(
        "150.00",
        [{"id": "a", "outstanding_amount": "100.00", "tenant_id": "t", "currency": "KES"},
         {"id": "b", "outstanding_amount": "50.00", "tenant_id": "t", "currency": "KES"},
         {"id": "c", "outstanding_amount": "70.00", "tenant_id": "t", "currency": "KES"}],
        tenant_id="t",
    )
    assert result["decision"] == "UNIQUE_CANDIDATE"
    assert result["allocations"] == [{"invoice_ids": ["a", "b"], "amount": "150.00"}]


def test_invoice_allocation_detects_ambiguity_and_scope_conflicts():
    from pesaguard_backend_pipeline.advanced_reconciliation_algorithms import find_invoice_allocation_candidates
    ambiguous = find_invoice_allocation_candidates(
        "100", [{"id": "a", "amount": "40"}, {"id": "b", "amount": "60"},
                {"id": "c", "amount": "30"}, {"id": "d", "amount": "70"}], tenant_id="t")
    assert ambiguous["decision"] == "REVIEW"
    assert len(ambiguous["allocations"]) == 2
    scoped = find_invoice_allocation_candidates(
        "100", [{"id": "other", "amount": "100", "tenant_id": "elsewhere"},
                {"id": "usd", "amount": "100", "currency": "USD"}], tenant_id="t")
    assert scoped["decision"] == "UNMATCHED"
    assert {row["reason"] for row in scoped["excluded_candidates"]} == {"tenant_scope_conflict", "currency_scope_conflict"}


def test_invoice_allocation_fails_closed_on_limits_precision_and_duplicate_ids():
    from decimal import Decimal
    from pesaguard_backend_pipeline.advanced_reconciliation_algorithms import find_invoice_allocation_candidates
    too_many = find_invoice_allocation_candidates("100", [{"id": str(i), "amount": "1"} for i in range(21)], tenant_id="t")
    assert too_many["decision"] == "REVIEW"
    assert too_many["reason_codes"] == ["candidate_set_too_large"]
    assert find_invoice_allocation_candidates("NaN", [], tenant_id="t")["decision"] == "REVIEW"
    assert find_invoice_allocation_candidates("100", [{"id": "a", "amount": "50"}, {"id": "a", "amount": "50"}], tenant_id="t")["decision"] == "UNMATCHED"
    with pytest.raises(ValueError):
        find_invoice_allocation_candidates("100", [], tenant_id=" ", quantum=Decimal("0.01"))
    supported_quantum = find_invoice_allocation_candidates(
        "100.00", [{"id": "a", "amount": "100.00"}], tenant_id="t", quantum=Decimal("0.05")
    )
    assert supported_quantum["decision"] == "UNIQUE_CANDIDATE"


def test_settlement_comparison_checks_amount_and_count_variances():
    from pesaguard_backend_pipeline.advanced_reconciliation_algorithms import compare_settlement_totals
    same = compare_settlement_totals(expected_amount="100.00", actual_amount="100.01", expected_count=4, actual_count=4)
    assert same["status"] == "MATCHED"
    different = compare_settlement_totals(expected_amount="100", actual_amount="101", expected_count=4, actual_count=5)
    assert different["status"] == "REVIEW"
    assert different["reason_codes"] == ["settlement_amount_variance", "settlement_count_variance"]
    with pytest.raises(ValueError):
        compare_settlement_totals(expected_amount="1", actual_amount="1", expected_count=1)


def test_match_quality_metrics_report_undefined_denominators():
    from pesaguard_backend_pipeline.advanced_reconciliation_algorithms import calculate_match_quality_metrics
    result = calculate_match_quality_metrics([
        {"predicted_match": True, "actual_match": True},
        {"predicted_match": True, "actual_match": False},
        {"predicted_match": False, "actual_match": False},
        {"predicted_match": False, "actual_match": True},
    ])
    assert result["true_positive"] == result["false_positive"] == 1
    assert result["true_negative"] == result["false_negative"] == 1
    assert result["precision"] == result["recall"] == 0.5
    assert result["specificity"] == result["accuracy"] == 0.5
    empty = calculate_match_quality_metrics([])
    assert empty["precision"] is None
    with pytest.raises(ValueError):
        calculate_match_quality_metrics([{"predicted_match": 1, "actual_match": False}])



def test_reversal_candidate_checks_linkage_and_cumulative_amount():
    from pesaguard_backend_pipeline.advanced_reconciliation_algorithms import assess_reversal_candidate
    original = {"transaction_id": "TX-1", "tenant_id": "t", "provider": "mpesa",
                "account_id": "paybill-1", "currency": "KES", "amount": "100",
                "timestamp": "2026-10-14T10:00:00Z"}
    reversal = {"original_reference": "TX-1", "tenant_id": "t", "provider": "mpesa",
                "account_id": "paybill-1", "currency": "KES", "amount": "40",
                "timestamp": "2026-10-14T11:00:00Z"}
    result = assess_reversal_candidate(reversal, original, [{"amount": "30", "status": "completed"}])
    assert result["decision"] == "ELIGIBLE_FOR_REVIEW"
    assert result["remaining_reversible_amount"] == "70"
    assert result["posting_authorized"] is False


def test_reversal_over_amount_or_wrong_tenant_requires_review():
    from pesaguard_backend_pipeline.advanced_reconciliation_algorithms import assess_reversal_candidate
    original = {"transaction_id": "TX-1", "tenant_id": "t", "provider": "mpesa",
                "account_id": "a", "currency": "KES", "amount": "100",
                "timestamp": "2026-10-14T10:00:00Z"}
    reversal = {"original_reference": "TX-1", "tenant_id": "other", "provider": "mpesa",
                "account_id": "a", "currency": "KES", "amount": "80",
                "timestamp": "2026-10-14T11:00:00Z"}
    result = assess_reversal_candidate(reversal, original, [{"amount": "30", "status": "successful"}])
    assert result["decision"] == "REVIEW"
    assert "tenant_scope_conflict" in result["reason_codes"]
    assert "reversal_exceeds_remaining_amount" in result["reason_codes"]


def test_reversal_without_original_or_with_bad_time_is_reviewed():
    from pesaguard_backend_pipeline.advanced_reconciliation_algorithms import assess_reversal_candidate
    assert assess_reversal_candidate({"amount": "5"}, None)["decision"] == "REVIEW"
    result = assess_reversal_candidate(
        {"original_reference": "TX-1", "tenant_id": "t", "provider": "mpesa",
         "account_id": "a", "currency": "KES", "amount": "5", "timestamp": "2026-10-14T09:00:00Z"},
        {"transaction_id": "TX-1", "tenant_id": "t", "provider": "mpesa",
         "account_id": "a", "currency": "KES", "amount": "10", "timestamp": "2026-10-14T10:00:00Z"})
    assert "reversal_precedes_original" in result["reason_codes"]


def test_event_order_flags_late_and_future_events_without_discarding_them():
    from datetime import datetime, timezone
    from pesaguard_backend_pipeline.advanced_reconciliation_algorithms import assess_event_order
    latest = datetime(2026, 10, 15, 10, 10, tzinfo=timezone.utc)
    now = datetime(2026, 10, 15, 10, 11, tzinfo=timezone.utc)
    assert assess_event_order("2026-10-15T10:00:00Z", latest, now=now)["classification"] == "LATE"
    assert assess_event_order("2026-10-15T10:20:00Z", latest, now=now)["classification"] == "FUTURE_SKEW"
    assert assess_event_order("2026-10-15T10:10:00Z", latest, now=now)["classification"] == "IN_ORDER"
