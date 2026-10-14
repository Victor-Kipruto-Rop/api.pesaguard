import pytest

from fraud_risk_engine import calculate_features\nfrom algorithmic_intelligence import (
    aggregate_partial_payments,\n    amount_to_minor_units,\n    decompose_settlement_variance,\n    detect_velocity_spike,
    is_amount_outlier,
    normalize_reference,
    robust_amount_deviation,
    robust_amount_zscore,
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
        "reference": "inv 001",
        "amount": "125.00",
        "timestamp": "2026-10-14T12:05:00Z",
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


def test_candidate_scoring_does_not_assume_missing_time_is_proof_of_match():
    result = score_reconciliation_candidate(
        {"reference": "A", "amount": "10.00"},
        {"reference": "A", "amount": "10.00"},
    )
    assert result["auto_matchable"] is True
    assert result["evidence"]["time_delta_seconds"] is None


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
        {"TransID": "P2", "BillRefNumber": "inv 7", "TransAmount": "60.00"},
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
