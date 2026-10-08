import pytest

from event_store import _money
from validators import extract_canonical_event, validate_daraja_payload


def _flat_payload(amount="10.00"):
    return {
        "TransactionType": "Pay Bill",
        "TransID": "R-1",
        "TransTime": "20260923120000",
        "TransAmount": amount,
        "BusinessShortCode": "123456",
        "MSISDN": "254700000000",
    }


def test_flat_callback_preserves_amount_as_exact_decimal_text():
    payload = _flat_payload("90071992547409.93")

    assert validate_daraja_payload(payload) == (True, "")
    assert extract_canonical_event(payload)["TransAmount"] == "90071992547409.93"


def test_malformed_nested_callbacks_return_validation_errors_not_exceptions():
    for payload in (
        {"Body": {"stkCallback": None}},
        {"Body": {"stkCallback": {"ResultCode": "not-an-integer"}}},
        {"Result": None},
        {"Result": {"ResultCode": "not-an-integer"}},
    ):
        is_valid, error = validate_daraja_payload(payload)
        assert not is_valid
        assert error


def test_flat_callback_rejects_nonfinite_and_subcent_amounts():
    for amount in ("NaN", "Infinity", "1.005"):
        is_valid, error = validate_daraja_payload(_flat_payload(amount))
        assert not is_valid
        assert error == "TransAmount must be a valid numeric value"


def test_event_store_does_not_round_subcent_amounts():
    with pytest.raises(ValueError, match="minor unit"):
        _money("1.005")
