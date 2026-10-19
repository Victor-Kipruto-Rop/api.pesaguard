from pesaguard_backend_pipeline.transaction_lifecycle_validation import (
    ALGORITHM_VERSION,
    validate_reversal_lifecycle,
)

ORIGINAL = {
    "transaction_id": "MPESA-ORIGINAL-1",
    "amount": "1000.00",
    "currency": "KES",
    "timestamp": "2026-10-01T10:00:00+03:00",
    "status": "confirmed",
}


def reversal(event_id, amount, **overrides):
    row = {
        "transaction_id": event_id,
        "original_transaction_id": ORIGINAL["transaction_id"],
        "amount": amount,
        "currency": "KES",
        "timestamp": "2026-10-01T11:00:00+03:00",
        "status": "confirmed",
        "type": "reversal",
    }
    row.update(overrides)
    return row


def test_valid_partial_reversals_are_summed_without_ledger_mutation():
    result = validate_reversal_lifecycle(ORIGINAL, [reversal("REV-1", "200"), reversal("REV-2", "300")])
    assert result["algorithm_version"] == ALGORITHM_VERSION
    assert result["status"] == "VALIDATED"
    assert result["confirmed_reversal_amount"] == "500"
    assert result["remaining_net_amount"] == "500.00"
    assert result["ledger_mutated"] is False
    assert result["human_or_policy_approval_required"] is True


def test_full_reversal_is_valid():
    result = validate_reversal_lifecycle(ORIGINAL, [reversal("REV-1", "1000")])
    assert result["valid"] is True
    assert result["remaining_net_amount"] == "0.00"


def test_cumulative_over_reversal_requires_review():
    result = validate_reversal_lifecycle(ORIGINAL, [reversal("REV-1", "700"), reversal("REV-2", "400")])
    assert result["status"] == "REVIEW_REQUIRED"
    assert "cumulative_reversal_exceeds_original_amount" in result["reason_codes"]
    assert result["remaining_net_amount"] is None


def test_duplicate_callback_is_not_counted_twice():
    result = validate_reversal_lifecycle(ORIGINAL, [reversal("REV-1", "200"), reversal("REV-1", "200")])
    assert result["status"] == "REVIEW_REQUIRED"
    assert result["confirmed_reversal_amount"] == "200"
    assert "duplicate_reversal_event_id" in result["reason_codes"]


def test_original_link_and_currency_conflicts_require_review():
    result = validate_reversal_lifecycle(
        ORIGINAL,
        [reversal("REV-1", "200", original_transaction_id="OTHER"),
         reversal("REV-2", "100", currency="USD")],
    )
    assert result["status"] == "REVIEW_REQUIRED"
    assert "event_REV-1_original_link_mismatch" in result["reason_codes"]
    assert "event_REV-2_currency_mismatch" in result["reason_codes"]


def test_pending_reversal_is_reported_but_not_counted():
    result = validate_reversal_lifecycle(ORIGINAL, [reversal("REV-PENDING", "100", status="pending")])
    assert result["valid"] is True
    assert result["pending_reversal_count"] == 1
    assert result["confirmed_reversal_amount"] == "0"


def test_pre_original_and_naive_timestamps_require_review():
    result = validate_reversal_lifecycle(
        ORIGINAL,
        [reversal("REV-EARLY", "100", timestamp="2026-10-01T09:00:00+03:00"),
         reversal("REV-NAIVE", "100", timestamp="2026-10-01T12:00:00")],
    )
    assert result["status"] == "REVIEW_REQUIRED"
    assert "event_REV-EARLY_precedes_original" in result["reason_codes"]
    assert "event_REV-NAIVE_timestamp_missing_or_invalid" in result["reason_codes"]


def test_unconfirmed_original_requires_review():
    result = validate_reversal_lifecycle({**ORIGINAL, "status": "pending"}, [reversal("REV-1", "100")])
    assert result["status"] == "REVIEW_REQUIRED"
    assert "original_payment_not_confirmed" in result["reason_codes"]


def test_empty_reversal_history_is_not_an_error_for_confirmed_original():
    result = validate_reversal_lifecycle(ORIGINAL, [])
    assert result["valid"] is True
    assert result["confirmed_reversal_count"] == 0
    assert result["confirmed_reversal_amount"] == "0"


def test_invalid_amount_fails_closed():
    result = validate_reversal_lifecycle(ORIGINAL, [reversal("REV-1", "NaN")])
    assert result["status"] == "REVIEW_REQUIRED"
    assert "event_REV-1_amount_invalid" in result["reason_codes"]
