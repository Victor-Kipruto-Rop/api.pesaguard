from datetime import datetime, timezone

import pytest

from idempotency import derive_idempotency_key


def test_provider_transaction_id_is_preferred_and_stable():
    assert derive_idempotency_key({"TransID": " abc123 "}) == "transid:ABC123"
    assert derive_idempotency_key({"transaction_id": "abc123"}) == "transid:ABC123"


def test_fallback_money_uses_decimal_not_binary_float():
    base = {
        "MSISDN": "254 712 345 678",
        "TransAmount": "90071992547409.93",
        "TransTime": "20261014120000",
        "BillRefNumber": "Invoice-9",
        "BusinessShortCode": "123456",
    }
    assert derive_idempotency_key(base) == derive_idempotency_key({
        **base,
        "MSISDN": "+254712345678",
        "TransAmount": "90071992547409.9300",
        "BillRefNumber": " invoice-9 ",
    })


def test_iso_timestamps_with_different_offsets_canonicalize_to_same_instant():
    first = {
        "amount": "12.50",
        "reference": "INV-2",
        "timestamp": "2026-10-14T10:00:00Z",
        "phone_number": "254700000000",
    }
    second = {
        **first,
        "timestamp": "2026-10-14T13:00:00+03:00",
    }
    assert derive_idempotency_key(first) == derive_idempotency_key(second)


def test_fallback_requires_a_valid_amount_timestamp_and_identity():
    base = {"amount": "10.00", "timestamp": "2026-10-14T10:00:00Z", "reference": "INV-1"}
    for bad_amount in ("NaN", "Infinity", "not-money", "0", "-1", None, True):
        with pytest.raises(ValueError):
            derive_idempotency_key({**base, "amount": bad_amount})
    with pytest.raises(ValueError, match="timezone"):
        derive_idempotency_key({**base, "timestamp": "2026-10-14T10:00:00"})
    with pytest.raises(ValueError, match="phone number or reference"):
        derive_idempotency_key({**base, "reference": "", "phone_number": ""})


def test_fallback_scope_facts_prevent_easy_cross_account_or_reference_collisions():
    base = {
        "amount": "10.00",
        "timestamp": "20261014100000",
        "reference": "INV-1",
        "phone_number": "254700000000",
        "provider_account_id": "till-1",
    }
    original = derive_idempotency_key(base)
    assert original != derive_idempotency_key({**base, "provider_account_id": "till-2"})
    assert original != derive_idempotency_key({**base, "reference": "INV-2"})


def test_datetime_object_requires_timezone_for_fallback():
    with pytest.raises(ValueError, match="timezone"):
        derive_idempotency_key({
            "amount": "1.00",
            "timestamp": datetime(2026, 10, 14, 10, 0),
            "reference": "INV-1",
        })
    assert derive_idempotency_key({
        "amount": "1.00",
        "timestamp": datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc),
        "reference": "INV-1",
    }).startswith("hash:")
