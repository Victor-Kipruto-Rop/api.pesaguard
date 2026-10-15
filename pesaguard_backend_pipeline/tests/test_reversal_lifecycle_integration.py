from decimal import Decimal

from pesaguard_backend_pipeline.models import Transaction
from pesaguard_backend_pipeline.reversal_lifecycle_integration import (
    _row_record,
    is_reversal_event,
)


def _row(payload, *, status="RECONCILED"):
    return Transaction(
        trans_id="REV-1",
        tenant_id="tenant-a",
        provider_account_id="paybill-1",
        provider="mpesa",
        trans_amount=Decimal("25.00"),
        currency="KES",
        msisdn="254700000000",
        business_short_code="paybill-1",
        trans_time="2026-10-14T10:05:00+00:00",
        raw_payload=payload,
        status=status,
    )


def test_reversal_event_detection_does_not_classify_normal_payment():
    assert not is_reversal_event({"TransID": "PAY-1", "TransAmount": "25"})
    assert is_reversal_event({"transaction_type": "refund", "TransID": "REF-1"})
    assert is_reversal_event({"OriginalTransID": "PAY-1", "TransID": "REV-1"})


def test_database_reconciliation_status_is_not_provider_confirmation():
    row = _row({"TransID": "REV-1", "OriginalTransID": "PAY-1"})
    result = _row_record(row)
    assert result["status"] == "unknown"


def test_provider_success_result_code_is_normalized_to_confirmed():
    row = _row({"TransID": "REV-1", "OriginalTransID": "PAY-1", "ResultCode": 0})
    result = _row_record(row)
    assert result["status"] == "confirmed"


def test_provider_failure_result_code_is_not_counted_as_confirmed():
    row = _row({"TransID": "REV-1", "OriginalTransID": "PAY-1", "ResultCode": 17})
    result = _row_record(row)
    assert result["status"] == "failed"


def test_adapter_uses_database_columns_for_scope_and_identity():
    row = _row({"TransID": "spoofed", "tenant_id": "tenant-other", "ResultCode": 0})
    result = _row_record(row)
    assert result["TransID"] == "REV-1"
    assert result["tenant_id"] == "tenant-a"
    assert result["provider_account_id"] == "paybill-1"
    assert result["currency"] == "KES"


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pesaguard_backend_pipeline.reversal_lifecycle_integration import assess_persisted_reversal


def _stored_row(trans_id, amount, payload, timestamp):
    return Transaction(
        trans_id=trans_id,
        tenant_id="tenant-a",
        provider_account_id="paybill-1",
        provider="mpesa",
        trans_amount=Decimal(amount),
        currency="KES",
        msisdn="254700000000",
        business_short_code="paybill-1",
        trans_time=timestamp,
        raw_payload=payload,
        status="RECONCILED",
    )


def _session_with_rows(*rows):
    engine = create_engine("sqlite:///:memory:")
    Transaction.__table__.create(engine)
    factory = sessionmaker(bind=engine)
    session = factory()
    session.add_all(rows)
    session.commit()
    return session, engine


def _reversal_event(amount="25.00"):
    return {
        "TransID": "REV-NEW",
        "OriginalTransID": "ORIG-1",
        "TransAmount": amount,
        "TransTime": "2026-10-14T10:10:00+00:00",
        "tenant_id": "tenant-a",
        "provider": "mpesa",
        "provider_account_id": "paybill-1",
        "currency": "KES",
    }


def test_persisted_gate_routes_cumulative_over_reversal_to_review():
    session, engine = _session_with_rows(
        _stored_row("ORIG-1", "100.00", {}, "2026-10-14T10:00:00+00:00"),
        _stored_row(
            "REV-OLD", "80.00",
            {"OriginalTransID": "ORIG-1", "ResultCode": 0},
            "2026-10-14T10:05:00+00:00",
        ),
    )
    try:
        result = assess_persisted_reversal(
            session, _reversal_event("25.00"),
            tenant_id="tenant-a", transaction_id="REV-NEW",
        )
        assert result["status"] == "REVIEW_REQUIRED"
        assert "cumulative_reversal_exceeds_original_amount" in result["reason_codes"]
        assert result["can_auto_post"] is False
    finally:
        session.close()
        engine.dispose()


def test_persisted_gate_requires_review_when_prior_provider_status_is_unknown():
    session, engine = _session_with_rows(
        _stored_row("ORIG-1", "100.00", {}, "2026-10-14T10:00:00+00:00"),
        _stored_row(
            "REV-OLD", "20.00", {"OriginalTransID": "ORIG-1"},
            "2026-10-14T10:05:00+00:00",
        ),
    )
    try:
        result = assess_persisted_reversal(
            session, _reversal_event("25.00"),
            tenant_id="tenant-a", transaction_id="REV-NEW",
        )
        assert result["status"] == "REVIEW_REQUIRED"
        assert "prior_reversal_provider_status_unknown" in result["reason_codes"]
        assert result["can_auto_post"] is False
    finally:
        session.close()
        engine.dispose()


def test_persisted_gate_pass_is_not_posting_authority():
    session, engine = _session_with_rows(
        _stored_row("ORIG-1", "100.00", {}, "2026-10-14T10:00:00+00:00"),
        _stored_row(
            "REV-OLD", "20.00",
            {"OriginalTransID": "ORIG-1", "ResultCode": 0},
            "2026-10-14T10:05:00+00:00",
        ),
    )
    try:
        result = assess_persisted_reversal(
            session, _reversal_event("25.00"),
            tenant_id="tenant-a", transaction_id="REV-NEW",
        )
        assert result["status"] == "VALIDATION_PASS"
        assert result["can_auto_post"] is False
    finally:
        session.close()
        engine.dispose()


def test_persisted_gate_normalizes_compact_daraja_timestamps():
    session, engine = _session_with_rows(
        _stored_row("ORIG-1", "100.00", {}, "20261014100000"),
    )
    try:
        event = _reversal_event("25.00")
        event["TransTime"] = "20261014101000"
        result = assess_persisted_reversal(
            session, event, tenant_id="tenant-a", transaction_id="REV-NEW",
        )
        assert result["status"] == "VALIDATION_PASS"
        assert result["can_auto_post"] is False
    finally:
        session.close()
        engine.dispose()
