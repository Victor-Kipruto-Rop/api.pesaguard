from datetime import datetime, timezone, timedelta

import pytest

from pesaguard_backend_pipeline.production_decision_algorithms import (
    classify_settlement_variance,
    conservative_reconciliation_decision,
    detect_velocity_burst,
    evaluate_algorithm_release,
    validate_transaction_transition,
)


def test_settlement_variance_is_explained_but_never_auto_adjusted():
    result = classify_settlement_variance("100", "97", currency="KES", known_fee="2", known_tax="1")
    assert result["classification"] == "KNOWN_DEDUCTIONS_EXPLAIN_VARIANCE"
    assert result["action"] == "REVIEW"
    assert result["unexplained_variance"] == "0"


def test_settlement_currency_mismatch_fails_closed():
    result = classify_settlement_variance(
        "100", "100", currency="KES", expected_currency="KES", settled_currency="USD"
    )
    assert result["classification"] == "CURRENCY_MISMATCH"
    assert result["action"] == "REVIEW"


def test_reversal_requires_linkage_and_valid_chronology():
    now = datetime.now(timezone.utc)
    invalid = validate_transaction_transition(
        "CONFIRMED", "REVERSED", original_confirmed=True, same_scope=True,
        original_transaction_id="tx-1", reversal_transaction_id="rev-1",
        original_time=now.isoformat(), event_time=(now - timedelta(seconds=1)).isoformat(),
    )
    assert not invalid["allowed"]
    assert "reversal_precedes_original" in invalid["reason_codes"]


def test_valid_transition_does_not_claim_to_persist_state():
    result = validate_transaction_transition("PENDING", "CONFIRMED")
    assert result["allowed"]
    assert result["action"] == "PROCEED_TO_TRANSACTIONAL_VALIDATION"


def test_match_proposal_requires_every_guard():
    blocked = conservative_reconciliation_decision(
        candidate_count=1, top_score=1, scope_verified=True, provider_confirmed=True,
        quality_passed=True, exact_external_id=True, idempotency_claimed=False,
    )
    assert blocked["decision"] == "REVIEW"
    approved = conservative_reconciliation_decision(
        candidate_count=1, top_score=1, scope_verified=True, provider_confirmed=True,
        quality_passed=True, exact_external_id=True, idempotency_claimed=True,
    )
    assert approved["decision"] == "MATCH_PROPOSAL"
    assert approved["posts_ledger"] is False


def test_ambiguous_match_is_review_even_with_high_score():
    result = conservative_reconciliation_decision(
        candidate_count=2, top_score=0.99, second_score=0.98, ambiguity_margin=0.05,
        scope_verified=True, provider_confirmed=True, quality_passed=True,
        exact_external_id=True, idempotency_claimed=True,
    )
    assert result["decision"] == "REVIEW"
    assert "ambiguous_candidates" in result["reason_codes"]


def test_velocity_uses_only_events_inside_window_and_timezone_aware():
    now = datetime(2026, 10, 15, 1, 0, tzinfo=timezone.utc)
    events = [
        {"timestamp": (now - timedelta(seconds=30)).isoformat(), "amount": "5"},
        {"timestamp": (now - timedelta(seconds=60)).isoformat(), "amount": "7"},
        {"timestamp": (now - timedelta(seconds=500)).isoformat(), "amount": "99"},
        {"timestamp": "2026-10-15T00:59:00", "amount": "100"},
    ]
    result = detect_velocity_burst(events, now=now, window_seconds=120, count_threshold=2, amount_threshold="10")
    assert result["event_count"] == 2
    assert result["amount_total"] == "12"
    assert result["burst_detected"]
    assert result["invalid_or_untimed_events"] == 1


def test_release_gate_blocks_missing_metrics_and_unreviewed_dataset():
    result = evaluate_algorithm_release(
        {"sample_count": 100, "precision": 0.99, "recall": 0.95},
        minimum_samples=50, minimum_precision=0.95, minimum_recall=0.90,
        maximum_false_positive_rate=0.02, maximum_review_rate=0.20,
        is_holdout=False, dataset_version=None, algorithm_version="candidate-v2", reviewer=None,
    )
    assert result["decision"] == "BLOCK"
    assert "evaluation_must_use_holdout" in result["blockers"]
    assert "metric_missing_or_invalid:false_positive_rate" in result["blockers"]


def test_release_gate_only_passes_explicit_holdout_metrics_and_still_needs_approval():
    result = evaluate_algorithm_release(
        {"sample_count": 100, "precision": 0.99, "recall": 0.95,
         "false_positive_rate": 0.01, "review_rate": 0.10},
        minimum_samples=50, minimum_precision=0.95, minimum_recall=0.90,
        maximum_false_positive_rate=0.02, maximum_review_rate=0.20,
        is_holdout=True, dataset_version="finance-reviewed-v1",
        algorithm_version="candidate-v2", reviewer="finance-reviewer",
    )
    assert result["decision"] == "PASS_FOR_REVIEW"
    assert result["automatic_deployment"] is False


@pytest.mark.parametrize(("previous", "next_state"), [
    ("FAILED", "CONFIRMED"), ("REVERSED", "PARTIALLY_REVERSED"), ("PENDING", "REVERSED")
])
def test_invalid_lifecycle_transitions_are_rejected(previous, next_state):
    assert not validate_transaction_transition(previous, next_state)["allowed"]
