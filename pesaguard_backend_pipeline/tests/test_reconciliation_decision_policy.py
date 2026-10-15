import pytest

from pesaguard_backend_pipeline.reconciliation_decision_policy import (
    ALGORITHM_VERSION,
    arbitrate_reconciliation_evidence,
)


_MISSING = object()


def quality(valid=True, findings=None):
    return {"valid_for_automatic_matching": valid, "findings": findings or []}


def ranking(decision="CANDIDATE", candidate=_MISSING, ambiguous=False, reasons=None, excluded=None):
    if candidate is _MISSING:
        candidate = {"candidate_id": "ledger-1", "score": 0.98, "evidence": ["amount_exact"]}
    return {
        "decision": decision,
        "top_candidate": candidate,
        "ambiguous": ambiguous,
        "reason_codes": reasons or [],
        "excluded_candidates": excluded or [],
    }


def test_proposes_only_and_never_authorizes_posting():
    result = arbitrate_reconciliation_evidence(
        tenant_id="tenant-a", transaction_quality=quality(),
        candidate_ranking=ranking(),
    )
    assert result["decision"] == "PROPOSE_MATCH"
    assert result["may_post_to_ledger"] is False
    assert result["evidence"]["decision_is_posting_authority"] is False
    assert result["algorithm_version"] == ALGORITHM_VERSION


def test_missing_quality_evidence_fails_closed():
    result = arbitrate_reconciliation_evidence(
        tenant_id="tenant-a", transaction_quality=None, candidate_ranking=ranking()
    )
    assert result["decision"] == "EXCEPTION"
    assert result["reason_codes"] == ["transaction_quality_block"]


def test_missing_candidate_decision_fails_closed():
    result = arbitrate_reconciliation_evidence(
        tenant_id="tenant-a", transaction_quality=quality(), candidate_ranking={}
    )
    assert result["decision"] == "EXCEPTION"
    assert result["reason_codes"] == ["candidate_decision_missing"]


def test_invalid_transaction_quality_fails_closed_before_candidate_selection():
    result = arbitrate_reconciliation_evidence(
        tenant_id="tenant-a",
        transaction_quality=quality(False, [{"code": "INVALID_AMOUNT"}]),
        candidate_ranking=ranking(),
    )
    assert result["decision"] == "EXCEPTION"
    assert result["reason_codes"] == ["transaction_quality_block"]


def test_critical_scope_conflict_goes_to_review_even_with_candidate():
    result = arbitrate_reconciliation_evidence(
        tenant_id="tenant-a", transaction_quality=quality(),
        candidate_ranking=ranking(
            reasons=["candidate_scope_conflict"],
            excluded=[{"reason_codes": ["tenant_scope_conflict"]}],
        ),
    )
    assert result["decision"] == "REVIEW"
    assert "candidate_scope_conflict" in result["reason_codes"]


def test_ambiguous_candidate_never_proposes_match():
    result = arbitrate_reconciliation_evidence(
        tenant_id="tenant-a", transaction_quality=quality(),
        candidate_ranking=ranking(ambiguous=True),
    )
    assert result["decision"] == "REVIEW"


def test_high_risk_requires_review():
    result = arbitrate_reconciliation_evidence(
        tenant_id="tenant-a", transaction_quality=quality(),
        candidate_ranking=ranking(),
        risk_assessment={"level": "HIGH", "action": "REVIEW", "signals": ["velocity_breach"]},
    )
    assert result["decision"] == "REVIEW"
    assert result["evidence"]["risk_signals"] == ["velocity_breach"]


def test_required_lifecycle_with_missing_evidence_fails_closed():
    result = arbitrate_reconciliation_evidence(
        tenant_id="tenant-a", transaction_quality=quality(),
        candidate_ranking=ranking(),
        lifecycle_assessment={"required": True, "status": "UNKNOWN", "can_auto_post": False},
    )
    assert result["decision"] == "EXCEPTION"
    assert result["reason_codes"] == ["lifecycle_evidence_incomplete"]


def test_no_candidate_is_unmatched_not_a_match():
    result = arbitrate_reconciliation_evidence(
        tenant_id="tenant-a", transaction_quality=quality(),
        candidate_ranking=ranking(decision="UNMATCHED", candidate=None),
    )
    assert result["decision"] == "UNMATCHED"


@pytest.mark.parametrize("tenant", ["", " ", None])
def test_tenant_scope_is_mandatory(tenant):
    with pytest.raises(ValueError, match="tenant_id"):
        arbitrate_reconciliation_evidence(
            tenant_id=tenant, transaction_quality=quality(), candidate_ranking=ranking()
        )


def test_malformed_policy_input_fails_loudly():
    with pytest.raises(ValueError, match="findings"):
        arbitrate_reconciliation_evidence(
            tenant_id="tenant-a",
            transaction_quality={"findings": "not-a-list"},
            candidate_ranking=ranking(),
        )
