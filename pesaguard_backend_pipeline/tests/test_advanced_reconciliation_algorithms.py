from decimal import Decimal
import pytest

from pesaguard_backend_pipeline.advanced_reconciliation_algorithms import (
    ALGORITHM_VERSION, calculate_match_quality_metrics, compare_settlement_totals,
    find_invoice_allocation_candidates,
)


def test_unique_subset_is_only_a_candidate():
    result = find_invoice_allocation_candidates(
        "150.00",
        [{"id": "a", "outstanding_amount": "100.00", "tenant_id": "t", "currency": "KES"},
         {"id": "b", "outstanding_amount": "50.00", "tenant_id": "t", "currency": "KES"},
         {"id": "c", "outstanding_amount": "70.00", "tenant_id": "t", "currency": "KES"}],
        tenant_id="t",
    )
    assert result["algorithm_version"] == ALGORITHM_VERSION
    assert result["decision"] == "UNIQUE_CANDIDATE"
    assert result["allocations"] == [{"invoice_ids": ["a", "b"], "amount": "150.00"}]


def test_multiple_subsets_require_review():
    result = find_invoice_allocation_candidates(
        "100", [{"id": "a", "amount": "40"}, {"id": "b", "amount": "60"},
                {"id": "c", "amount": "30"}, {"id": "d", "amount": "70"}],
        tenant_id="t",
    )
    assert result["decision"] == "REVIEW"
    assert result["reason_codes"] == ["ambiguous_exact_allocations"]
    assert len(result["allocations"]) == 2


def test_explicit_scope_conflicts_are_excluded():
    result = find_invoice_allocation_candidates(
        "100", [{"id": "wrong-tenant", "amount": "100", "tenant_id": "other"},
                {"id": "wrong-currency", "amount": "100", "currency": "USD"}],
        tenant_id="t",
    )
    assert result["decision"] == "UNMATCHED"
    assert {item["reason"] for item in result["excluded_candidates"]} == {
        "tenant_scope_conflict", "currency_scope_conflict"
    }


def test_bounded_search_and_bad_inputs_fail_closed():
    result = find_invoice_allocation_candidates(
        "100", [{"id": str(i), "amount": "1"} for i in range(21)], tenant_id="t"
    )
    assert result["decision"] == "REVIEW"
    assert result["reason_codes"] == ["candidate_set_too_large"]
    assert find_invoice_allocation_candidates("NaN", [], tenant_id="t")["decision"] == "REVIEW"
    with pytest.raises(ValueError):
        find_invoice_allocation_candidates("100", [], tenant_id=" ", quantum=Decimal("0.01"))


def test_duplicate_ids_cannot_be_double_counted():
    result = find_invoice_allocation_candidates(
        "100", [{"id": "same", "amount": "50"}, {"id": "same", "amount": "50"}], tenant_id="t"
    )
    assert result["decision"] == "UNMATCHED"
    assert result["excluded_candidates"][0]["reason"] == "duplicate_invoice_id"


def test_settlement_amount_and_count_variances_are_reported():
    matched = compare_settlement_totals(
        expected_amount="100.00", actual_amount="100.01",
        expected_count=4, actual_count=4, amount_tolerance="0.01",
    )
    assert matched["status"] == "MATCHED"
    changed = compare_settlement_totals(
        expected_amount="100", actual_amount="101", expected_count=4, actual_count=5,
    )
    assert changed["status"] == "REVIEW"
    assert changed["reason_codes"] == ["settlement_amount_variance", "settlement_count_variance"]
    with pytest.raises(ValueError):
        compare_settlement_totals(expected_amount="1", actual_amount="1", expected_count=1)


def test_quality_metrics_report_undefined_denominators():
    metrics = calculate_match_quality_metrics([
        {"predicted_match": True, "actual_match": True},
        {"predicted_match": True, "actual_match": False},
        {"predicted_match": False, "actual_match": False},
        {"predicted_match": False, "actual_match": True},
    ])
    assert metrics["true_positive"] == metrics["false_positive"] == 1
    assert metrics["true_negative"] == metrics["false_negative"] == 1
    assert metrics["precision"] == metrics["recall"] == 0.5
    assert metrics["specificity"] == metrics["accuracy"] == 0.5
    empty = calculate_match_quality_metrics([])
    assert empty["precision"] is None
    assert "precision" in empty["undefined_metrics"]
    with pytest.raises(ValueError):
        calculate_match_quality_metrics([{"predicted_match": 1, "actual_match": False}])
