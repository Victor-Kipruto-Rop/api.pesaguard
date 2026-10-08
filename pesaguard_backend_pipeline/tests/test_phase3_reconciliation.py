import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from reconciliation_engine import ENGINE_VERSION, ReconciliationEngine, evaluate_transaction, measure_reconciliation
from models import Base, ReconciliationGroundTruth
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


ENGINE = ReconciliationEngine(tolerance_percent="0.5", window_seconds=900)


def transaction(transaction_id, amount="100.00", timestamp="20260913120000", **extra):
    value = {
        "TransID": transaction_id,
        "TransAmount": amount,
        "MSISDN": "254700000000",
        "TransTime": timestamp,
        "BillRefNumber": f"order-{transaction_id}",
    }
    value.update(extra)
    return value


def record(transaction_id, amount="100.00", timestamp="2026-09-13T12:00:00Z", **extra):
    value = {
        "internal_ref": f"order-{transaction_id}",
        "amount": amount,
        "phone_number": "254700000000",
        "timestamp": timestamp,
    }
    value.update(extra)
    return value


def test_golden_dataset_is_100_percent_correct():
    fixture_path = Path(__file__).parent / "fixtures" / "phase3_golden_dataset.json"
    cases = json.loads(fixture_path.read_text(encoding="utf-8"))
    base_time = datetime(2026, 9, 13, 12, 0, tzinfo=timezone.utc)

    prepared = []
    for case in cases:
        event_time = base_time
        record_time = base_time + timedelta(seconds=case.get("time_offset_seconds") or 0)
        event_kwargs = {"TransactionType": case.get("transaction_type", "payment")}
        if case.get("original_transaction_id"):
            event_kwargs["OriginalTransID"] = case["original_transaction_id"]
        record_kwargs = {}
        if case.get("original_transaction_id"):
            record_kwargs["original_transaction_id"] = case["original_transaction_id"]
        raw = transaction(case["transaction_id"], amount=case["amount"], timestamp=event_time.strftime("%Y%m%d%H%M%S"), **event_kwargs)
        records = [] if case["record_amount"] is None else [record(case["transaction_id"], amount=case["record_amount"], timestamp=record_time.isoformat().replace("+00:00", "Z"), **record_kwargs)]
        prepared.append((case["name"], raw, records, case["expected_status"]))
    results = [
        ENGINE.reconcile(raw, records, seen_transaction_ids={"duplicate"} if name == "duplicate transaction" else set())
        for name, raw, records, _ in prepared
    ]
    expected = [expected_status for _, _, _, expected_status in prepared]

    assert [result["status"] for result in results] == expected
    assert all(result["evidence"]["engine_version"] == ENGINE_VERSION for result in results)
    assert all("matched_record" in result["evidence"] for result in results)
    assert all("matching_rules" in result["evidence"] for result in results)
    assert all("match_score" in result["evidence"] for result in results)
    assert all("match_timestamp" in result["evidence"] for result in results)

    metrics = measure_reconciliation(results, expected)
    assert metrics["known_cases"] == len(cases)
    assert metrics["correct_cases"] == len(cases)
    assert metrics["false_positives"] == 0
    assert metrics["false_negatives"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["processing_latency_ms"] >= 0
    assert metrics["throughput_per_second"] > 0


def test_invalid_input_is_exception_and_pending_candidate_is_not_silent():
    invalid = ENGINE.reconcile({"TransID": "bad", "TransAmount": "not-money"}, [])
    assert invalid["status"] == "EXCEPTION"

    pending = ENGINE.reconcile(
        transaction("pending", amount="100.00"),
        [{"internal_ref": "order-pending", "amount": "100.00", "timestamp": "2026-09-13T12:00:00Z"}],
    )
    assert pending["status"] == "MATCHED"
    assert pending["evidence"]["matched_record"]["internal_ref"] == "order-pending"


@pytest.mark.parametrize("amount", ["1.005", "1.001"])
def test_reconciliation_rejects_amounts_below_minor_unit_precision(amount):
    result = ENGINE.reconcile(transaction("sub-cent", amount=amount), [record("sub-cent", amount="1.00")])

    assert result["status"] == "EXCEPTION"
    assert "minor unit" in result["reason"]


def test_reconciliation_rejects_sub_minor_internal_amounts():
    result = ENGINE.reconcile(transaction("bad-record"), [record("bad-record", amount="100.001")])

    assert result["status"] == "EXCEPTION"
    assert "minor unit" in result["reason"]


def test_legacy_reconciliation_does_not_round_sub_cent_amount_into_a_match():
    event = transaction("legacy-sub-cent", amount="1.005")
    internal_record = record("legacy-sub-cent", amount="1.00")

    result = evaluate_transaction(event, [internal_record], seen_trans_ids=set())

    assert result["status"] != "matched"
    assert "invalid_or_zero_amount" in result["anomalies"]


def test_tolerance_match_records_rule_and_confidence():
    result = ENGINE.reconcile(
        transaction("tolerance", amount="100.00"),
        [record("different-reference", amount="100.40")],
    )
    assert result["status"] == "PARTIAL"
    assert "amount_within_tolerance" in result["evidence"]["matching_rules"]
    assert 0 < result["evidence"]["match_score"] < 1


def test_pending_internal_record_has_explicit_pending_status():
    result = ENGINE.reconcile(
        transaction("pending-status"),
        [record("pending-status", status="pending")],
    )
    assert result["status"] == "PENDING"


def test_refund_and_reversal_require_original_transaction_reference():
    for transaction_type in ("Refund", "Reversal"):
        result = ENGINE.reconcile(
            transaction(f"missing-{transaction_type.lower()}", TransactionType=transaction_type),
            [record("missing")],
        )
        assert result["status"] == "EXCEPTION"
        assert f"{transaction_type.lower()}_requires_original_reference" in result["evidence"]["matching_rules"]


def test_ground_truth_capture_is_immutable_and_measureable(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'ground-truth.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        from reconciliation_engine import record_ground_truth

        record_ground_truth(session, tenant_id="tenant-a", transaction_id="truth-1", expected_status="MATCHED", approved_by="approver", approval_reference="case-1")
        record_ground_truth(session, tenant_id="tenant-a", transaction_id="truth-1", expected_status="MATCHED", approved_by="approver", approval_reference="case-1", actual_status="MATCHED", validated_by="test")
        session.commit()
        row = session.query(ReconciliationGroundTruth).one()
        assert row.actual_status == "MATCHED"
        assert row.validated_at is not None
    finally:
        session.close()