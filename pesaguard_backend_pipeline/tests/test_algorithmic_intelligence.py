import pytest

from fraud_risk_engine import calculate_features
from algorithmic_intelligence import (
    aggregate_partial_payments,
    assess_reversal,
    classify_replay,
    amount_to_minor_units,
    decompose_settlement_variance,
    detect_velocity_spike,
    is_amount_outlier,
    normalize_reference,
    rank_reconciliation_candidates,
    detect_window_change,
    robust_amount_deviation,
    robust_amount_zscore,
    profile_transaction_batch,
    score_reconciliation_candidate,
    transaction_identity_key,
    transaction_payload_fingerprint,
)


def test_money_uses_decimal_minor_units_not_binary_float():
    assert amount_to_minor_units("100.10") == 10010
    assert amount_to_minor_units("100.105") == 10011
    with pytest.raises(ValueError):
        amount_to_minor_units("NaN")


def test_reference_normalization_is_case_and_punctuation_insensitive():
    assert normalize_reference(" INV- 001/ABC ") == "inv001abc"
    assert normalize_reference(None) == ""


def test_identity_is_tenant_and_provider_scoped_and_requires_provider_id():
    one = transaction_identity_key(tenant_id="tenant-a", provider="MPESA", transaction_id="QWE123")
    assert one == transaction_identity_key(tenant_id="tenant-a", provider="mpesa", transaction_id="QWE123")
    assert one != transaction_identity_key(tenant_id="tenant-b", provider="mpesa", transaction_id="QWE123")
    with pytest.raises(ValueError):
        transaction_identity_key(tenant_id="tenant-a", provider="mpesa", transaction_id="")


def test_payload_fingerprint_is_stable_but_detects_conflicting_replay():
    original = {"TransID": "QWE123", "TransAmount": "100.00", "BillRefNumber": "inv-001", "Currency": "KES"}
    assert transaction_payload_fingerprint(original) == transaction_payload_fingerprint(dict(original))
    changed = {**original, "TransAmount": "101.00"}
    assert transaction_payload_fingerprint(original) != transaction_payload_fingerprint(changed)



def test_payload_fingerprint_preserves_reference_punctuation_and_rejects_invalid_precision():
    base = {"TransID": "QWE123", "TransAmount": "100.00", "BillRefNumber": "INV-001"}
    assert transaction_payload_fingerprint(base) != transaction_payload_fingerprint(
        {**base, "BillRefNumber": "INV001"}
    )
    with pytest.raises(ValueError):
        transaction_payload_fingerprint({**base, "TransAmount": "100.001"})


def test_robust_outlier_detection_resists_one_extreme_historical_value():
    baseline = [100, 101, 99, 100, 102, 1000]
    assert robust_amount_zscore(100, baseline) is not None
    assert robust_amount_deviation(100, baseline) == 0
    assert is_amount_outlier(10000, baseline) is True
    assert is_amount_outlier(100, [100, 101, 99]) is None


def test_candidate_scoring_only_auto_matches_complete_exact_evidence():
    incoming = {
        "BillRefNumber": "INV-001",
        "TransAmount": "125.00",
        "TransTime": "20261014120000",
        "MSISDN": "254700000001",
    }
    exact = {
        "reference": "inv-001",
        "amount": "125.00",
        "timestamp": "2026-10-14T09:05:00Z",
        "phone_number": "+254 700 000 001",
    }
    result = score_reconciliation_candidate(incoming, exact, window_seconds=900)
    assert result["auto_matchable"] is True
    assert result["score"] == 1.0

    ambiguous_or_partial = score_reconciliation_candidate(
        incoming, {**exact, "reference": "different-ref"}, window_seconds=900
    )
    assert ambiguous_or_partial["auto_matchable"] is False
    assert "reference_exact" in ambiguous_or_partial["reason_codes"]


def test_candidate_scoring_fails_closed_when_time_evidence_is_missing():
    result = score_reconciliation_candidate(
        {"reference": "A", "amount": "10.00"},
        {"reference": "A", "amount": "10.00"},
    )
    assert result["auto_matchable"] is False
    assert result["evidence"]["time_delta_seconds"] is None
    assert result["evidence"]["time_within_window"] is False


def test_fraud_features_use_robust_baseline_when_history_is_sufficient():
    history = [
        {"TransID": f"h-{index}", "TransAmount": amount, "MSISDN": f"25470000000{index}",
         "TransTime": f"2026100{index + 1}120000"}
        for index, amount in enumerate([100, 101, 99, 100, 102, 10000])
    ]
    features = calculate_features(
        {"TransID": "current", "TransAmount": "150", "MSISDN": "254799999999",
         "TransTime": "20261014120000"},
        history,
    )
    # The historical outlier should not inflate the mean and hide a meaningful
    # deviation from the normal 100-KES cluster.
    assert features.amount_deviation > 0.5



def test_partial_payment_aggregation_is_reference_scoped_and_idempotent():
    payments = [
        {"TransID": "P1", "BillRefNumber": "INV-7", "TransAmount": "40.00"},
        {"TransID": "P2", "BillRefNumber": "inv-7", "TransAmount": "60.00"},
        {"TransID": "P2", "BillRefNumber": "INV-7", "TransAmount": "60.00"},
        {"TransID": "P3", "BillRefNumber": "OTHER", "TransAmount": "999.00"},
    ]
    result = aggregate_partial_payments(payments, "100.00", reference="INV-7")
    assert result["status"] == "MATCHED"
    assert result["payment_count"] == 2
    assert result["received_minor_units"] == 10000


def test_partial_payment_aggregation_surfaces_overpayment_and_rejects_missing_ids():
    result = aggregate_partial_payments(
        [{"TransID": "P1", "reference": "A", "amount": "11.00"}],
        "10.00",
        reference="A",
    )
    assert result["status"] == "OVERPAID"
    with pytest.raises(ValueError):
        aggregate_partial_payments([{"reference": "A", "amount": "10.00"}], "10.00", reference="A")


def test_velocity_detection_uses_trailing_window_and_same_identity_only():
    result = detect_velocity_spike(
        {"MSISDN": "254700000001", "TransTime": "20261014120030"},
        [
            {"MSISDN": "254700000001", "TransTime": "20261014120000"},
            {"MSISDN": "254700000001", "TransTime": "20261014120010"},
            {"MSISDN": "254700000002", "TransTime": "20261014120020"},
            {"MSISDN": "254700000001", "TransTime": "20261014115900"},
        ],
        limit=2,
    )
    assert result["evaluated"] is True
    assert result["triggered"] is True
    assert result["count"] == 2


def test_settlement_variance_is_decomposed_without_silent_adjustment():
    balanced = decompose_settlement_variance(
        expected_gross="1000.00", actual_net="970.00", known_fees="20.00",
        known_reversals="10.00",
    )
    assert balanced["status"] == "BALANCED"
    assert balanced["unexplained_variance_minor_units"] == 0
    unbalanced = decompose_settlement_variance(expected_gross="1000", actual_net="960", known_fees="20")
    assert unbalanced["status"] == "VARIANCE"
    assert unbalanced["unexplained_variance_minor_units"] == -2000



def test_candidate_ranking_refuses_equal_scoring_ambiguous_matches():
    incoming = {"reference": "INV-1", "amount": "10.00"}
    candidates = [
        {"reference": "INV-1", "amount": "10.00", "id": "A"},
        {"reference": "INV-1", "amount": "10.00", "id": "B"},
    ]
    result = rank_reconciliation_candidates(incoming, candidates)
    assert result["status"] == "AMBIGUOUS"
    assert result["selected"] is None


def test_candidate_ranking_selects_only_unambiguous_exact_evidence():
    incoming = {
        "reference": "INV-1", "amount": "10.00",
        "timestamp": "2026-10-14T12:00:00Z", "phone_number": "254700000001",
    }
    candidates = [
        {"reference": "INV-1", "amount": "10.00",
         "timestamp": "2026-10-14T12:00:01Z", "phone_number": "254700000001", "id": "A"},
        {"reference": "OTHER", "amount": "11.00",
         "timestamp": "2026-10-14T12:00:01Z", "phone_number": "254700000002", "id": "B"},
    ]
    result = rank_reconciliation_candidates(incoming, candidates)
    assert result["status"] == "MATCH_CANDIDATE"
    assert result["selected"]["id"] == "A"


def test_window_change_detection_requires_enough_baseline_and_finds_spike():
    assert detect_window_change([10, 11], [20])["evaluated"] is False
    result = detect_window_change([10, 11, 10, 9, 10, 10], [20, 21])
    assert result["evaluated"] is True
    assert result["changed"] is True
    assert result["relative_change"] >= 1.0



def test_punctuation_only_reference_similarity_is_not_auto_match_evidence():
    result = score_reconciliation_candidate(
        {"reference": "INV-001", "amount": "20.00"},
        {"reference": "INV 001", "amount": "20.00"},
    )
    assert result["evidence"]["reference_normalized_only"] is True
    assert result["auto_matchable"] is False



def test_partial_payment_aggregation_does_not_merge_punctuation_collisions():
    result = aggregate_partial_payments(
        [
            {"TransID": "P1", "reference": "INV-7", "amount": "40.00"},
            {"TransID": "P2", "reference": "INV 7", "amount": "60.00"},
        ],
        "100.00",
        reference="INV-7",
    )
    assert result["status"] == "PARTIAL"
    assert result["received_minor_units"] == 4000



def test_replay_classification_distinguishes_duplicate_and_conflicting_payload():
    original = {
        "tenant_id": "tenant-1", "provider": "MPESA", "provider_account_id": "600001",
        "TransID": "QWE123", "TransAmount": "100.00", "BillRefNumber": "INV-1",
        "TransTime": "20261014120000", "MSISDN": "0700000001", "Currency": "KES",
    }
    equivalent = {
        **original, "provider": "mpesa", "TransTime": "2026-10-14T09:00:00Z",
        "MSISDN": "+254 700 000 001",
    }
    assert classify_replay(None, original)["classification"] == "NEW_TRANSACTION"
    assert classify_replay(original, equivalent)["classification"] == "IDENTICAL_REPLAY"
    changed = {**equivalent, "TransAmount": "101.00"}
    assert classify_replay(original, changed)["classification"] == "CONFLICTING_REPLAY"
    other_account = {**equivalent, "provider_account_id": "600002"}
    assert classify_replay(original, other_account)["classification"] == "NEW_TRANSACTION"


def test_reversal_assessment_prevents_cumulative_over_reversal():
    original = {"TransID": "ORIGINAL-1", "TransAmount": "100.00", "Currency": "KES"}
    prior = [{"TransID": "REV-1", "OriginalTransID": "ORIGINAL-1", "TransAmount": "40.00", "Currency": "KES"}]
    partial = assess_reversal(
        original,
        {"TransID": "REV-2", "OriginalTransID": "ORIGINAL-1", "TransAmount": "60.00", "Currency": "KES"},
        prior,
    )
    assert partial["status"] == "FULL_REVERSAL"
    assert partial["remaining_reversible_minor_units"] == 0
    over = assess_reversal(
        original,
        {"TransID": "REV-3", "OriginalTransID": "ORIGINAL-1", "TransAmount": "60.01", "Currency": "KES"},
        prior,
    )
    assert over["status"] == "OVER_REVERSAL"
    assert over["valid"] is False


def test_reversal_assessment_rejects_wrong_original_and_currency():
    original = {"TransID": "ORIGINAL-1", "TransAmount": "100.00", "Currency": "KES"}
    wrong_reference = assess_reversal(
        original, {"TransID": "REV-1", "OriginalTransID": "OTHER", "TransAmount": "10.00"}
    )
    assert wrong_reference["status"] == "INVALID"
    assert "original_reference_mismatch" in wrong_reference["reason_codes"]
    wrong_currency = assess_reversal(
        original, {"TransID": "REV-2", "OriginalTransID": "ORIGINAL-1", "TransAmount": "10.00", "Currency": "USD"}
    )
    assert "currency_mismatch" in wrong_currency["reason_codes"]


def test_batch_quality_profile_reports_missing_invalid_duplicate_late_and_schema_drift():
    from datetime import datetime, timezone

    result = profile_transaction_batch(
        [
            {"TransID": "A", "TransAmount": "10.00", "TransTime": "20261014090000", "BillRefNumber": "INV-A"},
            {"TransID": "A", "TransAmount": "NaN", "TransTime": "not-a-time", "NewProviderField": "x"},
            {"TransAmount": "0", "Currency": "KES"},
        ],
        known_fields=("TransID", "TransAmount", "TransTime", "BillRefNumber", "Currency"),
        now=datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc),
        late_after_seconds=1800,
    )
    assert result["record_count"] == 3
    assert result["duplicate_transaction_ids"] == ["A"]
    assert result["invalid_amount_count"] == 2
    assert result["invalid_timestamp_count"] == 1
    assert result["missing_field_counts"]["transaction_id"] == 1
    assert result["late_event_count"] == 1
    assert result["schema_drift_fields"] == ["NewProviderField"]
