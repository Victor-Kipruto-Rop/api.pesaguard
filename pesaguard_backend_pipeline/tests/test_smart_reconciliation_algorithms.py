from datetime import datetime, timezone, timedelta

import pytest

from pesaguard_backend_pipeline.smart_reconciliation_algorithms import (
    ALGORITHM_VERSION,
    assess_rule_based_risk,
    detect_velocity_breach,
    rank_reconciliation_candidates,
    robust_amount_outliers,
    score_reconciliation_candidate,
    transaction_fingerprint,
    validate_transaction_quality,
)


NOW = datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc)


def test_fingerprint_is_stable_and_tenant_scoped():
    tx = {"TransID": " QW123 ", "TransAmount": "100.00"}
    assert transaction_fingerprint(tx, tenant_id="tenant-a") == transaction_fingerprint(
        {"TransID": "qw123"}, tenant_id="tenant-a"
    )
    assert transaction_fingerprint(tx, tenant_id="tenant-a") != transaction_fingerprint(tx, tenant_id="tenant-b")


def test_fallback_fingerprint_uses_normalized_fields():
    first = {"reference": " Invoice-9 ", "amount": "100", "timestamp": "2026-10-14T10:00:00Z", "phone": "+254 712 345 678"}
    second = {"reference": "invoice-9", "amount": "100.00", "timestamp": "2026-10-14T13:00:00+03:00", "phone": "254712345678"}
    assert transaction_fingerprint(first, tenant_id="t") == transaction_fingerprint(second, tenant_id="t")


def test_fingerprint_requires_tenant():
    with pytest.raises(ValueError):
        transaction_fingerprint({"TransID": "x"}, tenant_id=" ")


def test_candidate_score_exposes_evidence_and_conflicts():
    tx = {"reference": "INV-1", "amount": "125.00", "timestamp": "2026-10-14T10:00:00Z", "phone": "2547123"}
    candidate = {"internal_ref": "ledger-1", "reference": "INV-1", "amount": "125", "created_at": "2026-10-14T10:02:00Z", "phone_number": "2547123"}
    result = score_reconciliation_candidate(tx, candidate, window_seconds=300)
    assert result.score == 1.0
    assert set(result.evidence) == {"reference_exact", "amount_exact", "timestamp_within_window", "phone_exact"}
    assert not result.conflicts


def test_candidate_score_does_not_hide_reference_or_phone_conflicts():
    result = score_reconciliation_candidate(
        {"reference": "A", "amount": "10", "timestamp": "2026-10-14T10:00:00Z", "phone": "2541"},
        {"internal_ref": "r2", "reference": "B", "amount": "10", "timestamp": "2026-10-14T10:00:00Z", "phone": "2542"},
    )
    assert "reference_conflict" in result.conflicts
    assert "phone_conflict" in result.conflicts


def test_ranker_flags_near_ties_for_review():
    tx = {"reference": "A", "amount": "10", "timestamp": "2026-10-14T10:00:00Z"}
    candidates = [
        {"internal_ref": "one", "reference": "A", "amount": "10", "timestamp": "2026-10-14T10:00:00Z"},
        {"internal_ref": "two", "reference": "A", "amount": "10", "timestamp": "2026-10-14T10:00:01Z"},
    ]
    result = rank_reconciliation_candidates(tx, candidates)
    assert result["decision"] == "REVIEW"
    assert result["ambiguous"] is True


def test_ranker_handles_empty_candidates():
    result = rank_reconciliation_candidates({"reference": "A"}, [])
    assert result["decision"] == "UNMATCHED"
    assert result["top_candidate"] is None


def test_mad_outlier_detection_and_insufficient_samples():
    assert robust_amount_outliers([10, 11, 10, 12])["ready"] is False
    result = robust_amount_outliers([10, 10, 11, 10, 10, 100])
    assert result["ready"] is True
    assert [item["index"] for item in result["outliers"]] == [2, 5]


def test_mad_zero_does_not_return_infinite_z_score():
    result = robust_amount_outliers([10, 10, 10, 10, 100])
    assert result["ready"] is True
    assert result["outliers"][0]["index"] == 4
    assert result["outliers"][0]["modified_z"] is None


def test_risk_assessment_is_bounded_explainable_and_review_only():
    result = assess_rule_based_risk(duplicate=True, reference_conflict=True, phone_conflict=True)
    assert result.score == 80
    assert result.level == "HIGH"
    assert result.action == "REVIEW"
    assert "reference_conflict" in result.signals
    assert result.algorithm_version == ALGORITHM_VERSION


def test_low_risk_does_not_claim_fraud_free():
    result = assess_rule_based_risk()
    assert result.score == 0
    assert result.action == "CONTINUE_STANDARD_CONTROLS"
    assert result.level == "LOW"


def test_velocity_counts_only_events_in_window_not_future_events():
    events = [
        NOW - timedelta(seconds=30),
        NOW - timedelta(seconds=100),
        NOW - timedelta(seconds=400),
        NOW + timedelta(seconds=1),
        "not-a-time",
    ]
    result = detect_velocity_breach(events, now=NOW, window_seconds=300, max_events=1)
    assert result["count"] == 2
    assert result["breach"] is True
    assert result["invalid_or_future_timestamps"] == 2


def test_velocity_threshold_is_strictly_greater_than_limit():
    result = detect_velocity_breach([NOW.isoformat()] * 3, now=NOW, max_events=3)
    assert result["breach"] is False


def test_quality_gate_rejects_invalid_money_and_ambiguous_time():
    result = validate_transaction_quality({"TransID": "x", "TransAmount": "NaN", "TransTime": "2026-10-14T10:00:00"})
    assert result["valid_for_automatic_matching"] is False
    assert {item["code"] for item in result["findings"]} == {"INVALID_AMOUNT", "MISSING_OR_AMBIGUOUS_TIMESTAMP", "MISSING_REFERENCE"}


def test_quality_gate_flags_non_positive_amount():
    result = validate_transaction_quality({"TransID": "x", "amount": "0", "timestamp": NOW.isoformat(), "reference": "r"})
    assert result["valid_for_automatic_matching"] is False
    assert result["findings"][0]["code"] == "NON_POSITIVE_AMOUNT"


def test_bad_algorithm_parameters_fail_closed():
    with pytest.raises(ValueError):
        rank_reconciliation_candidates({}, [], ambiguity_margin=2)
    with pytest.raises(ValueError):
        robust_amount_outliers([1, 2, 3], minimum_samples=2)
    with pytest.raises(ValueError):
        detect_velocity_breach([], window_seconds=0)



def test_engine_shadow_mode_is_opt_in_and_does_not_change_legacy_decision():
    from reconciliation_engine import evaluate_transaction

    event = {
        "TransID": "SHADOW-1",
        "TransAmount": "100",
        "MSISDN": "254700000000",
        "TransTime": "20261014130000",
        "BillRefNumber": "INV-1",
    }
    record = {
        "internal_ref": "ledger-1",
        "reference": "INV-1",
        "amount": "100",
        "phone_number": "254700000000",
        "timestamp": "2026-10-14T13:00:00+03:00",
    }
    baseline = evaluate_transaction(event, [record], seen_trans_ids=set())
    assert baseline["status"] == "matched"
    assert "smart_analysis" not in baseline

    shadow = evaluate_transaction(
        event,
        [record],
        seen_trans_ids=set(),
        tenant_settings={"tenant_id": "tenant-a", "reconciliation": {"smart_algorithms_shadow_enabled": True}},
    )
    assert shadow["status"] == baseline["status"]
    assert shadow["match"] == baseline["match"]
    assert shadow["smart_analysis"]["mode"] == "shadow"
    assert shadow["smart_analysis"]["legacy_decision_unchanged"] is True
    assert shadow["smart_analysis"]["candidate_ranking"]["top_candidate"]["candidate_id"] == "ledger-1"


def test_shadow_mode_does_not_break_legacy_decision_when_disabled():
    from reconciliation_engine import evaluate_transaction

    event = {
        "TransID": "SHADOW-2",
        "TransAmount": "100",
        "MSISDN": "254700000000",
        "TransTime": "20261014130000",
        "BillRefNumber": "INV-2",
    }
    record = {
        "internal_ref": "ledger-2",
        "reference": "INV-2",
        "amount": "100",
        "phone_number": "254700000000",
        "timestamp": "2026-10-14T13:00:00+03:00",
    }
    result = evaluate_transaction(
        event,
        [record],
        seen_trans_ids=set(),
        tenant_settings={"tenant_id": "tenant-a", "reconciliation": {"smart_algorithms_shadow_enabled": False}},
    )
    assert result["status"] == "matched"
    assert "smart_analysis" not in result



def test_internal_ledger_id_is_not_mistaken_for_payment_reference():
    result = score_reconciliation_candidate(
        {"reference": "INV-1", "amount": "10"},
        {"internal_ref": "INV-1", "amount": "10"},
    )
    assert "reference_exact" not in result.evidence
    assert "reference_missing" in result.conflicts


def test_ranker_excludes_explicit_cross_tenant_candidates():
    tx = {
        "tenant_id": "tenant-a", "provider": "mpesa", "account_id": "paybill-1",
        "currency": "KES", "reference": "INV-1", "amount": "10",
        "timestamp": "2026-10-14T10:00:00Z",
    }
    wrong = {
        "tenant_id": "tenant-b", "provider": "mpesa", "account_id": "paybill-1",
        "currency": "KES", "internal_ref": "wrong-tenant", "reference": "INV-1",
        "amount": "10", "timestamp": "2026-10-14T10:00:00Z",
    }
    result = rank_reconciliation_candidates(tx, [wrong])
    assert result["decision"] == "REVIEW"
    assert result["top_candidate"] is None
    assert result["excluded_candidate_count"] == 1
    assert result["excluded_candidates"][0]["reason_codes"] == ["tenant_scope_conflict"]
    assert result["reason_codes"] == ["candidate_scope_conflict"]


@pytest.mark.parametrize(
    ("scope", "expected_reason"),
    [
        ({"provider": "airtel_money"}, "provider_scope_conflict"),
        ({"account_id": "paybill-2"}, "account_scope_conflict"),
        ({"currency": "USD"}, "currency_scope_conflict"),
    ],
)
def test_ranker_excludes_provider_account_and_currency_conflicts(scope, expected_reason):
    tx = {
        "tenant_id": "tenant-a", "provider": "mpesa", "account_id": "paybill-1",
        "currency": "KES", "reference": "INV-1", "amount": "10",
        "timestamp": "2026-10-14T10:00:00Z",
    }
    candidate = {
        **tx, **scope, "internal_ref": "ledger-1",
        "timestamp": "2026-10-14T10:00:00Z",
    }
    result = rank_reconciliation_candidates(tx, [candidate])
    assert result["decision"] == "REVIEW"
    assert result["top_candidate"] is None
    assert result["excluded_candidates"][0]["reason_codes"] == [expected_reason]


def test_ranker_preserves_pre_scoped_legacy_candidates_without_scope_metadata():
    tx = {"tenant_id": "tenant-a", "reference": "INV-1", "amount": "10",
          "timestamp": "2026-10-14T10:00:00Z"}
    candidate = {"internal_ref": "ledger-1", "reference": "INV-1", "amount": "10",
                 "timestamp": "2026-10-14T10:00:00Z"}
    result = rank_reconciliation_candidates(tx, [candidate])
    assert result["decision"] == "CANDIDATE"
    assert result["eligible_candidate_count"] == 1
    assert result["excluded_candidate_count"] == 0
