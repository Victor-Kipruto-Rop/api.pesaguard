"""Regression tests for fail-closed matching when ledger timestamps are absent."""

from reconciliation_engine import ReconciliationEngine


ENGINE = ReconciliationEngine()


def test_exact_reference_and_amount_without_ledger_timestamp_requires_review():
    transaction = {
        "TransID": "NO-LEDGER-TIME-1",
        "TransAmount": "250.00",
        "TransTime": "20261014120000",
        "MSISDN": "254700000000",
        "BillRefNumber": "ORDER-NO-TIME",
        "tenant_id": "tenant-a",
        "provider": "mpesa",
        "currency": "KES",
    }
    ledger = {
        "internal_ref": "ledger-no-time-1",
        "reference": "ORDER-NO-TIME",
        "amount": "250.00",
        "timestamp": None,
        "phone_number": "254700000000",
        "tenant_id": "tenant-a",
        "provider": "mpesa",
        "currency": "KES",
    }

    result = ENGINE.reconcile(transaction, [ledger])

    assert result["status"] == "EXCEPTION"
    assert result["evidence"]["matched_record"] is None
    assert "ledger_timestamp_missing" in result["evidence"]["matching_rules"]
    assert "manual_review_required" in result["evidence"]["matching_rules"]
    assert "no trustworthy timestamp" in result["reason"]


def test_missing_timestamp_does_not_trigger_guard_for_unrelated_reference():
    transaction = {
        "TransID": "NO-LEDGER-TIME-2",
        "TransAmount": "250.00",
        "TransTime": "20261014120000",
        "MSISDN": "254700000000",
        "BillRefNumber": "ORDER-A",
    }
    ledger = {
        "internal_ref": "ledger-no-time-2",
        "reference": "ORDER-B",
        "amount": "250.00",
        "timestamp": None,
        "phone_number": "254700000000",
    }

    result = ENGINE.reconcile(transaction, [ledger])

    assert result["status"] == "UNMATCHED"
    assert "ledger_timestamp_missing" not in result["evidence"]["matching_rules"]
