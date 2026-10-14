import pytest

from advanced_transaction_algorithms import (
    assess_event_timing,
    assess_reversal_lifecycle,
    reconcile_settlement_batch,
)


def test_settlement_batch_matches_by_external_id_and_money_minor_units():
    result = reconcile_settlement_batch(
        [
            {"TransID": "A", "TransAmount": "100.00"},
            {"TransID": "B", "TransAmount": "25.50"},
        ],
        [
            {"transaction_id": "B", "amount": "25.50", "currency": "KES"},
            {"transaction_id": "A", "amount": "100.00", "currency": "KES"},
        ],
    )
    assert result["status"] == "RECONCILED"
    assert result["expected_total_minor_units"] == 12550
    assert result["settled_total_minor_units"] == 12550
    assert result["total_variance_minor_units"] == 0
    assert result["counts"] == {"MATCHED": 2}
    assert result["auto_adjustment_created"] is False


def test_settlement_batch_surfaces_missing_unexpected_mismatched_and_duplicate_rows():
    result = reconcile_settlement_batch(
        [{"TransID": "A", "amount": "100.00"}, {"TransID": "B", "amount": "10.00"}],
        [
            {"TransID": "A", "amount": "99.00"},
            {"TransID": "A", "amount": "99.00"},
            {"TransID": "X", "amount": "4.00"},
        ],
    )
    by_id = {item["transaction_id"]: item for item in result["items"]}
    assert by_id["A"]["status"] == "EXCEPTION"
    assert by_id["B"]["status"] == "MISSING"
    assert by_id["X"]["status"] == "UNEXPECTED"
    assert result["duplicate_settlement_ids"] == ["A"]
    assert result["status"] == "EXCEPTIONS"


def test_settlement_batch_does_not_treat_matching_totals_as_item_matches():
    result = reconcile_settlement_batch(
        [{"TransID": "A", "amount": "10"}, {"TransID": "B", "amount": "20"}],
        [{"TransID": "A", "amount": "20"}, {"TransID": "B", "amount": "10"}],
    )
    assert result["total_variance_minor_units"] == 0
    assert result["status"] == "EXCEPTIONS"
    assert result["counts"] == {"AMOUNT_MISMATCH": 2}


def test_settlement_batch_reports_currency_mismatch_and_invalid_rows():
    result = reconcile_settlement_batch(
        [{"TransID": "A", "amount": "10.00", "currency": "KES"}],
        [{"TransID": "A", "amount": "10.00", "currency": "USD"}, {"amount": "3"}],
    )
    assert result["items"][0]["status"] == "CURRENCY_MISMATCH"
    assert result["invalid_settlement_rows"] == [{"index": 1, "reason": "missing_transaction_id"}]


def test_reversal_lifecycle_deduplicates_and_detects_partial_full_and_over_reversal():
    partial = assess_reversal_lifecycle(
        original_transaction_id="ORIG", original_amount="100.00",
        reversals=[
            {"TransID": "R1", "OriginalTransID": "ORIG", "TransAmount": "30.00"},
            {"TransID": "R1", "OriginalTransID": "ORIG", "TransAmount": "30.00"},
            {"TransID": "R2", "OriginalTransID": "ORIG", "TransAmount": "20.00"},
        ],
    )
    assert partial["status"] == "PARTIALLY_REVERSED"
    assert partial["accepted_reversal_total_minor_units"] == 5000
    assert partial["duplicate_reversal_ids"] == ["R1"]

    full = assess_reversal_lifecycle(
        original_transaction_id="ORIG", original_amount="100.00",
        reversals=[{"TransID": "R1", "OriginalTransID": "ORIG", "TransAmount": "100.00"}],
    )
    assert full["status"] == "FULLY_REVERSED"

    over = assess_reversal_lifecycle(
        original_transaction_id="ORIG", original_amount="100.00",
        reversals=[
            {"TransID": "R1", "OriginalTransID": "ORIG", "TransAmount": "70.00"},
            {"TransID": "R2", "OriginalTransID": "ORIG", "TransAmount": "50.00"},
        ],
    )
    assert over["status"] == "OVER_REVERSED"
    assert over["over_reversal_minor_units"] == 2000
    assert over["auto_adjustment_created"] is False


def test_reversal_lifecycle_rejects_unlinked_and_wrong_currency_reversals():
    result = assess_reversal_lifecycle(
        original_transaction_id="ORIG", original_amount="100.00",
        reversals=[
            {"TransID": "R1", "OriginalTransID": "OTHER", "TransAmount": "30.00"},
            {"TransID": "R2", "OriginalTransID": "ORIG", "TransAmount": "30.00", "Currency": "USD"},
        ],
    )
    assert result["status"] == "NO_VALID_REVERSALS"
    assert {row["reason"] for row in result["rejected_rows"]} == {
        "original_reference_mismatch", "currency_mismatch"
    }


def test_event_timing_reports_late_future_and_unknown_events():
    late = assess_event_timing(
        event_time="2026-10-14T10:00:00Z",
        ingested_at="2026-10-14T12:00:00Z",
        settled_at="2026-10-14T10:30:00Z",
    )
    assert late["status"] == "REVIEW"
    assert "late_arriving_event" in late["reason_codes"]
    assert late["event_to_ingestion_seconds"] == 7200

    future = assess_event_timing(
        event_time="2026-10-14T12:00:00Z",
        ingested_at="2026-10-14T11:00:00Z",
    )
    assert "event_time_too_far_in_future" in future["reason_codes"]

    unknown = assess_event_timing(event_time="not-a-time", ingested_at="2026-10-14T12:00:00Z")
    assert unknown["evaluated"] is False
    assert unknown["status"] == "UNKNOWN"


def test_money_algorithms_reject_non_finite_values_and_invalid_originals():
    with pytest.raises(ValueError):
        reconcile_settlement_batch([{"TransID": "A", "amount": "NaN"}], [])
    with pytest.raises(ValueError):
        assess_reversal_lifecycle(original_transaction_id="", original_amount="10", reversals=[])
    with pytest.raises(ValueError):
        assess_reversal_lifecycle(original_transaction_id="A", original_amount="0", reversals=[])
