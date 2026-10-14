"""Regression tests for financial-safety boundaries in the phase-3 engine."""

from reconciliation_engine import ReconciliationEngine


def _event(*, reference="INV-100", trans_id="MPESA-100"):
    event = {
        "TransID": trans_id,
        "TransAmount": "100.00",
        "TransTime": "20261014120000",
        "BusinessShortCode": "123456",
    }
    if reference is not None:
        event["BillRefNumber"] = reference
    return event


def _ledger(*, reference="INV-100", internal_ref="ledger-100"):
    row = {
        "internal_ref": internal_ref,
        "amount": "100.00",
        "timestamp": "2026-10-14T12:00:00+03:00",
        "status": "pending",
    }
    if reference is not None:
        row["reference"] = reference
    return row


def test_missing_provider_reference_never_becomes_an_exact_match_from_trans_id():
    result = ReconciliationEngine().reconcile(
        _event(reference=None, trans_id="MPESA-100"),
        [_ledger(reference="MPESA-100")],
    )

    assert result["status"] != "MATCHED"
    assert result["status"] == "PARTIAL"
    assert "reference_exact" not in result["evidence"]["matching_rules"]


def test_internal_database_id_is_not_used_as_a_payment_reference():
    result = ReconciliationEngine().reconcile(
        _event(reference="ledger-100"),
        [_ledger(reference=None, internal_ref="ledger-100")],
    )

    assert result["status"] != "MATCHED"
    assert result["status"] == "PARTIAL"
    assert "reference_exact" not in result["evidence"]["matching_rules"]


def test_multiple_ledger_rows_for_same_reference_are_ambiguous_not_duplicate_payment():
    result = ReconciliationEngine().reconcile(
        _event(),
        [
            _ledger(internal_ref="ledger-a"),
            _ledger(internal_ref="ledger-b"),
        ],
    )

    assert result["status"] == "EXCEPTION"
    assert result["evidence"]["matching_rules"] == ["ambiguous_internal_reference"]
    assert "multiple internal records" in result["reason"]
