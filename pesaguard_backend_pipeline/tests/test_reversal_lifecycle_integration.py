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
