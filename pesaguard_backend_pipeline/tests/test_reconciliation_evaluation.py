import pytest

from reconciliation_evaluation import evaluate_reconciliation_predictions


def test_evaluation_reports_precision_recall_review_rate_and_coverage():
    result = evaluate_reconciliation_predictions([
        {"expected_match_id": "ledger-1", "predicted_match_id": "ledger-1", "decision": "MATCHED"},
        {"expected_match_id": "ledger-2", "predicted_match_id": "wrong-ledger", "decision": "AUTO_MATCHED"},
        {"expected_match_id": "ledger-3", "predicted_match_id": None, "decision": "NEEDS_REVIEW"},
        {"expected_match_id": None, "predicted_match_id": None, "decision": "UNMATCHED"},
    ])

    assert result["evaluated"] is True
    assert result["sample_count"] == 4
    assert result["true_positives"] == 1
    assert result["false_positives"] == 1
    assert result["false_negatives"] == 2
    assert result["true_negatives"] == 1
    assert result["precision"] == 0.5
    assert result["recall"] == round(1 / 3, 6)
    assert result["f1"] == 0.4
    assert result["false_positive_rate"] == 0.5
    assert result["automatic_match_coverage"] == 0.5
    assert result["review_rate"] == 0.25
    assert result["unmatched_rate"] == 0.25


def test_wrong_automatic_match_when_no_match_exists_is_false_positive():
    result = evaluate_reconciliation_predictions([
        {"expected_match_id": None, "predicted_match_id": "ledger-9", "decision": "MATCHED"},
    ])
    assert result["false_positives"] == 1
    assert result["true_negatives"] == 0
    assert result["precision"] == 0.0
    assert result["false_positive_rate"] == 1.0


def test_review_candidate_is_not_counted_as_an_automatic_prediction():
    result = evaluate_reconciliation_predictions([
        {"expected_match_id": "ledger-1", "predicted_match_id": None, "decision": "AMBIGUOUS"},
    ])
    assert result["true_positives"] == 0
    assert result["false_positives"] == 0
    assert result["false_negatives"] == 1
    assert result["review_rate"] == 1.0
    assert result["automatic_match_coverage"] == 0.0


def test_empty_ground_truth_is_unavailable_not_zero_performance():
    result = evaluate_reconciliation_predictions([])
    assert result["evaluated"] is False
    assert result["sample_count"] == 0
    assert result["precision"] is None
    assert result["recall"] is None
    assert result["exact_decision_accuracy"] is None


@pytest.mark.parametrize("sample", [
    {"predicted_match_id": None, "decision": "UNMATCHED"},
    {"expected_match_id": None, "decision": "UNMATCHED"},
    {"expected_match_id": None, "predicted_match_id": None},
])
def test_missing_required_fields_are_rejected(sample):
    with pytest.raises(ValueError, match="missing required field"):
        evaluate_reconciliation_predictions([sample])


def test_automatic_match_requires_a_predicted_ledger_id():
    with pytest.raises(ValueError, match="requires predicted_match_id"):
        evaluate_reconciliation_predictions([
            {"expected_match_id": "ledger-1", "predicted_match_id": None, "decision": "MATCHED"},
        ])


def test_unknown_decision_is_rejected_instead_of_silently_counted():
    with pytest.raises(ValueError, match="unsupported decision"):
        evaluate_reconciliation_predictions([
            {"expected_match_id": None, "predicted_match_id": None, "decision": "PROBABLY_OK"},
        ])


def test_identifiers_are_normalized_but_invalid_types_are_rejected():
    result = evaluate_reconciliation_predictions([
        {"expected_match_id": 123, "predicted_match_id": "123", "decision": "AUTO_MATCH"},
    ])
    assert result["true_positives"] == 1
    with pytest.raises(ValueError, match="must be a string, integer, or None"):
        evaluate_reconciliation_predictions([
            {"expected_match_id": {"id": 1}, "predicted_match_id": None, "decision": "REVIEW"},
        ])


def test_review_of_a_true_non_match_is_an_abstention_not_a_true_negative():
    result = evaluate_reconciliation_predictions([
        {"expected_match_id": None, "predicted_match_id": None, "decision": "REVIEW"},
    ])
    assert result["true_negatives"] == 0
    assert result["exact_decision_accuracy"] == 0.0
    assert result["review_rate"] == 1.0
