import pytest

from normalization import (
    NormalizationError,
    normalize_amount,
    normalize_currency,
    normalize_phone,
    normalize_provider,
    normalize_status,
    normalize_timestamp,
    normalize_transaction_type,
)


def test_normalizes_financial_values_and_eat_timestamp():
    assert normalize_amount("1,500") == "1500.00"
    assert normalize_currency("Kenyan Shilling") == "KES"
    assert normalize_phone("0712 345 678") == "+254712345678"
    assert normalize_timestamp("2026-09-22 10:00 EAT") == "2026-09-22T07:00:00Z"


def test_normalizes_provider_type_and_status_aliases():
    assert normalize_provider("M-PESA") == "mpesa"
    assert normalize_provider("Mpesa") == "mpesa"
    assert normalize_transaction_type("STK Push") == "PAYMENT"
    assert normalize_status("successful") == "COMPLETED"


def test_amount_normalization_rejects_rounding_and_unsupported_precision():
    with pytest.raises(NormalizationError, match="minor unit"):
        normalize_amount("1.005")
    with pytest.raises(NormalizationError, match="precision"):
        normalize_amount("10000000000000000.00")