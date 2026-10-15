"""Regression tests for the normalized transaction-quality gate in the live engine."""

from reconciliation_engine import ReconciliationEngine


ENGINE = ReconciliationEngine()


def event(**overrides):
    value = {
        "TransID": "QUALITY-1",
        "TransAmount": "100.00",
        "TransTime": "20261014120000",
        "MSISDN": "254700000000",
        "BillRefNumber": "ORDER-1",
    }
    value.update(overrides)
    return value


def ledger(**overrides):
    value = {
        "internal_ref": "ledger-1",
        "reference": "ORDER-1",
        "amount": "100.00",
        "timestamp": "2026-10-14T09:00:00Z",
        "phone_number": "254700000000",
    }
    value.update(overrides)
    return value


def test_valid_normalized_transaction_can_continue_to_matching():
    result = ENGINE.reconcile(event(), [ledger()])
    assert result["status"] == "MATCHED"
    assert "transaction_quality_findings" not in result["evidence"]


def test_non_positive_amount_fails_closed_before_matching():
    result = ENGINE.reconcile(event(TransAmount="0.00"), [ledger()])
    assert result["status"] == "EXCEPTION"
    assert result["evidence"]["matched_record"] is None
    assert "transaction_quality_gate" in result["evidence"]["matching_rules"]
    findings = result["evidence"]["transaction_quality_findings"]
    assert {"code": "NON_POSITIVE_AMOUNT", "severity": "high"} in findings


def test_missing_or_ambiguous_event_timestamp_fails_closed():
    result = ENGINE.reconcile(event(TransTime="not-a-timestamp"), [ledger()])
    assert result["status"] == "EXCEPTION"
    assert result["evidence"]["matched_record"] is None
    assert "transaction_quality_gate" in result["evidence"]["matching_rules"]
    assert any(
        finding["code"] == "MISSING_OR_AMBIGUOUS_TIMESTAMP"
        for finding in result["evidence"]["transaction_quality_findings"]
    )


def test_missing_transaction_id_fails_closed_before_candidate_selection():
    result = ENGINE.reconcile(event(TransID=""), [ledger()])
    assert result["status"] == "EXCEPTION"
    assert result["evidence"]["matched_record"] is None
