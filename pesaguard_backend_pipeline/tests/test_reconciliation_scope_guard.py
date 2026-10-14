"""Regression tests for fail-closed reconciliation candidate scoping."""
from reconciliation_engine import ReconciliationEngine, evaluate_transaction


EVENT = {
    "TransID": "SCOPE-TEST-1",
    "TransAmount": "100.00",
    "MSISDN": "254700000001",
    "TransTime": "20261014130000",
    "BillRefNumber": "INV-SCOPE-1",
    "BusinessShortCode": "123456",
    "provider": "mpesa",
    "currency": "KES",
}
RECORD = {
    "id": "ledger-scope-1",
    "internal_ref": "ledger-scope-1",
    "reference": "INV-SCOPE-1",
    "amount": "100.00",
    "phone_number": "254700000001",
    "timestamp": "2026-10-14T13:00:00+03:00",
    "provider_account_id": "123456",
    "provider": "mpesa",
    "currency": "KES",
}


def evaluate(record, tenant="tenant-a"):
    return evaluate_transaction(
        EVENT,
        [record],
        seen_trans_ids=set(),
        tenant_settings={"tenant_id": tenant},
    )


def test_explicit_cross_tenant_candidate_never_auto_matches():
    result = evaluate({**RECORD, "tenant_id": "tenant-b"})
    assert result["status"] == "needs_review"
    assert result["severity"] == "critical"
    assert "candidate_scope_conflict" in result["anomalies"]
    assert result["match"]["match_type"] == "scope_conflict"
    assert "tenant_scope_conflict" in result["match"]["reason_codes"]


def test_explicit_provider_account_and_currency_conflicts_fail_closed():
    cases = [
        ({"provider": "airtel_money"}, "provider_scope_conflict"),
        ({"provider_account_id": "654321"}, "account_scope_conflict"),
        ({"currency": "USD"}, "currency_scope_conflict"),
    ]
    for change, reason in cases:
        result = evaluate({**RECORD, "tenant_id": "tenant-a", **change})
        assert result["status"] == "needs_review"
        assert result["match"]["match_type"] == "scope_conflict"
        assert reason in result["match"]["reason_codes"]


def test_matching_scoped_candidate_keeps_existing_exact_match_behavior():
    result = evaluate({**RECORD, "tenant_id": "tenant-a"})
    assert result["status"] == "matched"
    assert result["match"]["match_type"] == "exact"



def test_class_engine_rejects_explicit_scope_conflict_before_matching():
    transaction = {
        "TransID": "CLASS-SCOPE-1",
        "TransAmount": "100.00",
        "TransTime": "20261014130000",
        "BillRefNumber": "INV-SCOPE-1",
        "tenant_id": "tenant-a",
        "provider": "mpesa",
        "BusinessShortCode": "123456",
        "currency": "KES",
    }
    record = {
        "internal_ref": "ledger-cross-tenant",
        "reference": "INV-SCOPE-1",
        "amount": "100.00",
        "timestamp": "2026-10-14T13:00:00+03:00",
        "tenant_id": "tenant-b",
        "provider": "mpesa",
        "provider_account_id": "123456",
        "currency": "KES",
    }
    result = ReconciliationEngine().reconcile(transaction, [record])
    assert result["status"] == "EXCEPTION"
    assert "candidate_scope_conflict" in result["rules"]
    assert "tenant_scope_conflict" in result["rules"]
