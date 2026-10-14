import pytest

from reconciliation_release_gate import (
    GATE_VERSION,
    ReleaseGatePolicy,
    evaluate_reconciliation_release_gate,
)


GOOD = {
    "evaluated": True,
    "sample_count": 500,
    "precision": 0.999,
    "recall": 0.95,
    "false_positive_rate": 0.001,
    "review_rate": 0.20,
}


def test_release_gate_passes_only_with_holdout_provenance_and_review():
    result = evaluate_reconciliation_release_gate(
        GOOD, dataset_version="finance-reviewed-v3", is_holdout=True, reviewed_by="finance-owner"
    )
    assert result["status"] == "PASS"
    assert result["promotion_eligible"] is True
    assert result["gate_version"] == GATE_VERSION
    assert result["reason_codes"] == []


def test_release_gate_blocks_empty_or_small_datasets():
    result = evaluate_reconciliation_release_gate(
        {**GOOD, "sample_count": 20},
        policy=ReleaseGatePolicy(minimum_sample_count=100),
        dataset_version="small-v1",
        is_holdout=True,
        reviewed_by="reviewer",
    )
    assert result["status"] == "BLOCKED"
    assert "insufficient_holdout_samples" in result["reason_codes"]


def test_release_gate_blocks_unavailable_metrics_instead_of_treating_them_as_zero():
    metrics = {**GOOD, "false_positive_rate": None}
    result = evaluate_reconciliation_release_gate(
        metrics, dataset_version="v1", is_holdout=True, reviewed_by="reviewer"
    )
    assert result["status"] == "BLOCKED"
    assert "metric_unavailable:false_positive_rate" in result["reason_codes"]


def test_release_gate_blocks_non_holdout_or_missing_provenance():
    result = evaluate_reconciliation_release_gate(GOOD)
    assert result["status"] == "BLOCKED"
    assert {"holdout_dataset_required", "dataset_version_required", "human_reviewer_required"} <= set(result["reason_codes"])


def test_release_gate_blocks_metrics_that_fail_policy():
    result = evaluate_reconciliation_release_gate(
        {**GOOD, "precision": 0.90, "false_positive_rate": 0.10, "review_rate": 0.80},
        dataset_version="v2", is_holdout=True, reviewed_by="reviewer",
    )
    assert result["status"] == "BLOCKED"
    assert "threshold_failed:precision" in result["reason_codes"]
    assert "threshold_failed:false_positive_rate" in result["reason_codes"]
    assert "threshold_failed:review_rate" in result["reason_codes"]


def test_release_gate_rejects_invalid_metric_shapes():
    with pytest.raises(ValueError, match="metrics must be a mapping"):
        evaluate_reconciliation_release_gate([])  # type: ignore[arg-type]
    result = evaluate_reconciliation_release_gate(
        {**GOOD, "recall": float("nan")},
        dataset_version="v1", is_holdout=True, reviewed_by="reviewer",
    )
    assert result["status"] == "BLOCKED"
    assert "metric_invalid:recall" in result["reason_codes"]


@pytest.mark.parametrize("kwargs", [
    {"minimum_sample_count": 0},
    {"minimum_precision": 1.1},
    {"minimum_recall": float("nan")},
    {"maximum_false_positive_rate": -0.1},
    {"maximum_review_rate": True},
])
def test_release_gate_policy_rejects_invalid_thresholds(kwargs):
    with pytest.raises(ValueError):
        ReleaseGatePolicy(**kwargs)
