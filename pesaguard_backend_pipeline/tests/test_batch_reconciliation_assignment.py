import pytest

from pesaguard_backend_pipeline.batch_reconciliation_assignment import (
    ALGORITHM_VERSION,
    propose_batch_assignment,
)


def test_global_assignment_never_reuses_a_ledger_candidate():
    result = propose_batch_assignment([
        {"transaction_id": "tx-1", "candidates": [
            {"candidate_id": "ledger-a", "score": 0.95},
            {"candidate_id": "ledger-b", "score": 0.80},
        ]},
        {"transaction_id": "tx-2", "candidates": [
            {"candidate_id": "ledger-a", "score": 0.94},
        ]},
    ])

    assert result["ready"] is True
    assert result["decision"] == "PROPOSAL"
    assert result["algorithm_version"] == ALGORITHM_VERSION
    assert {item["candidate_id"] for item in result["assignments"]} == {"ledger-a", "ledger-b"}
    assert len({item["candidate_id"] for item in result["assignments"]}) == 2
    assert result["side_effects_performed"] is False


def test_global_assignment_prefers_higher_total_not_independent_greedy_choice():
    result = propose_batch_assignment([
        {"transaction_id": "tx-1", "candidates": [
            {"candidate_id": "a", "score": 0.90},
            {"candidate_id": "b", "score": 0.89},
        ]},
        {"transaction_id": "tx-2", "candidates": [
            {"candidate_id": "a", "score": 0.88},
            {"candidate_id": "b", "score": 0.10},
        ]},
    ])

    assert result["decision"] == "PROPOSAL"
    assert [(x["transaction_id"], x["candidate_id"]) for x in result["assignments"]] == [
        ("tx-1", "b"), ("tx-2", "a")
    ]


def test_near_equivalent_global_assignments_fail_closed_for_review():
    result = propose_batch_assignment([
        {"transaction_id": "tx-1", "candidates": [
            {"candidate_id": "a", "score": 0.91},
            {"candidate_id": "b", "score": 0.90},
        ]},
        {"transaction_id": "tx-2", "candidates": [
            {"candidate_id": "a", "score": 0.90},
            {"candidate_id": "b", "score": 0.91},
        ]},
    ], ambiguity_margin=0.05)

    assert result["decision"] == "REVIEW"
    assert result["is_ambiguous"] is True
    assert result["assignments"] == []
    assert len(result["proposed_assignments"]) == 2
    assert result["reason_codes"] == ["near_equivalent_global_assignment"]


def test_below_threshold_and_ineligible_candidates_are_not_assigned():
    result = propose_batch_assignment([
        {"transaction_id": "tx-1", "candidates": [
            {"candidate_id": "low", "score": 0.59},
            {"candidate_id": "ineligible", "score": 0.99, "eligible": False},
        ]},
    ])

    assert result["assignments"] == []
    assert result["unmatched_transaction_ids"] == ["tx-1"]


def test_search_limit_returns_review_not_partial_result():
    result = propose_batch_assignment([
        {"transaction_id": f"tx-{i}", "candidates": []} for i in range(3)
    ], max_transactions=2)

    assert result["ready"] is False
    assert result["decision"] == "REVIEW"
    assert result["assignments"] == []
    assert result["reason_codes"] == ["batch_exceeds_exact_search_limit"]


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -0.1, 1.1, True, "bad"])
def test_invalid_scores_are_rejected(score):
    with pytest.raises(ValueError):
        propose_batch_assignment([
            {"transaction_id": "tx-1", "candidates": [{"candidate_id": "a", "score": score}]}
        ])


def test_duplicate_transaction_ids_are_rejected():
    with pytest.raises(ValueError, match="duplicate transaction_id"):
        propose_batch_assignment([
            {"transaction_id": "same", "candidates": []},
            {"transaction_id": "same", "candidates": []},
        ])


def test_no_candidate_is_forced_and_empty_batch_is_valid():
    empty = propose_batch_assignment([])
    unmatched = propose_batch_assignment([{"transaction_id": "tx-1", "candidates": []}])

    assert empty["ready"] is True
    assert empty["assignments"] == []
    assert unmatched["unmatched_transaction_ids"] == ["tx-1"]
