from datetime import datetime, timezone

from reconciliation_engine import ReconciliationEngine


def test_reconciliation_refuses_tied_non_reference_candidates():
    engine = ReconciliationEngine(window_seconds=900)
    incoming = {
        "TransID": "MPESA-1",
        "TransAmount": "100.00",
        "TransTime": "20261014120000",
        "BillRefNumber": "ORDER-UNKNOWN",
        "MSISDN": "254700000001",
    }
    records = [
        {
            "internal_ref": "ORDER-A",
            "reference": "ORDER-A",
            "amount": "100.00",
            "timestamp": datetime(2026, 10, 14, 9, 0, 1, tzinfo=timezone.utc),
            "phone_number": "254700000001",
            "status": "pending",
        },
        {
            "internal_ref": "ORDER-B",
            "reference": "ORDER-B",
            "amount": "100.00",
            "timestamp": datetime(2026, 10, 14, 9, 0, 1, tzinfo=timezone.utc),
            "phone_number": "254700000001",
            "status": "pending",
        },
    ]

    result = engine.reconcile(incoming, records)

    assert result["status"] == "EXCEPTION"
    assert result["evidence"]["matched_record"] is None
    assert "ambiguous_candidate_match" in result["evidence"]["matching_rules"]


def test_reconciliation_still_selects_a_single_clear_candidate():
    engine = ReconciliationEngine(window_seconds=900)
    incoming = {
        "TransID": "MPESA-2",
        "TransAmount": "100.00",
        "TransTime": "20261014120000",
        "BillRefNumber": "ORDER-UNKNOWN",
        "MSISDN": "254700000001",
    }
    records = [
        {
            "internal_ref": "ORDER-A",
            "reference": "ORDER-A",
            "amount": "100.00",
            "timestamp": datetime(2026, 10, 14, 9, 0, 1, tzinfo=timezone.utc),
            "phone_number": "254700000001",
            "status": "pending",
        },
        {
            "internal_ref": "ORDER-B",
            "reference": "ORDER-B",
            "amount": "120.00",
            "timestamp": datetime(2026, 10, 14, 9, 0, 1, tzinfo=timezone.utc),
            "phone_number": "254700000002",
            "status": "pending",
        },
    ]

    result = engine.reconcile(incoming, records)

    assert result["status"] == "PARTIAL"
    assert result["evidence"]["matched_record"]["internal_ref"] == "ORDER-A"
