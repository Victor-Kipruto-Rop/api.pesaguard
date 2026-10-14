import sys
import os
import importlib
from datetime import datetime, timedelta

# Ensure repo root is on sys.path so we can import sibling modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from reconciliation_utils import normalize_daraja_event, exact_match, time_window_match
validator = importlib.import_module('shared.daraja.validator')
compute_hmac = validator.compute_hmac
validate_signature = validator.validate_signature


def test_normalize_daraja_flat_c2b():
    payload = {
        "TransID": "ABC123",
        "TransAmount": "150.00",
        "TransTime": "20240101123045",
        "MSISDN": "254700000001",
    }
    n = normalize_daraja_event(payload)
    assert n["TransID"] == "ABC123"
    assert n["TransAmount"] == 150.0
    assert n["TransTime"] == "2024-01-01T09:30:45"
    assert n["timestamp"] == datetime(2024, 1, 1, 9, 30, 45)
    assert "reference" not in n


def test_normalize_daraja_uses_bill_reference_not_provider_transaction_id():
    payload = {
        "TransID": "PROVIDER-123",
        "BillRefNumber": "ORDER-456",
        "TransAmount": "150.00",
        "TransTime": "20240101123045",
    }

    normalized = normalize_daraja_event(payload)

    assert normalized["TransID"] == "PROVIDER-123"
    assert normalized["reference"] == "ORDER-456"


def test_exact_match_requires_explicit_business_reference_and_amount():
    tx = {"BillRefNumber": "REF-1", "TransID": "PROVIDER-1", "TransAmount": "100.00"}
    s = {"reference": "REF-1", "amount": 100}
    assert exact_match(tx, s)


def test_provider_transaction_id_is_not_a_business_reference():
    tx = {"TransID": "PROVIDER-1", "TransAmount": "100.00"}
    s = {"reference": "PROVIDER-1", "amount": 100}
    assert not exact_match(tx, s)


def test_time_window_match_by_ref_and_time():
    now = datetime.utcnow()
    tx = {"BillRefNumber": "R1", "TransID": "PROVIDER-1", "TransTime": now.strftime("%Y%m%d%H%M%S"), "TransAmount": "10"}
    settlements = [
        {"reference": "R1", "TransTime": (now + timedelta(seconds=10)).strftime("%Y%m%d%H%M%S"), "TransAmount": 10},
        {"reference": "R2", "TransTime": now.strftime("%Y%m%d%H%M%S"), "TransAmount": 5},
    ]
    matched = time_window_match(tx, settlements, window_seconds=60)
    assert matched is not None and matched.get("reference") == "R1"


def test_validate_signature_hex():
    payload = b'{"key":"value"}'
    secret = "s3cr3t"
    digest = compute_hmac(payload, secret, algo="sha256").hex()
    assert validate_signature(digest, payload, secret, algo="sha256", signature_encoding="hex")


def test_daraja_and_iso_timestamps_compare_in_utc():
    compact = {"BillRefNumber": "R-UTC", "TransID": "PROVIDER-UTC", "TransTime": "20240101123045", "TransAmount": "10"}
    utc_record = {
        "reference": "R-UTC", "timestamp": "2024-01-01T09:30:55Z", "TransAmount": "10"
    }
    matched = time_window_match(compact, [utc_record], window_seconds=60)
    assert matched is utc_record
