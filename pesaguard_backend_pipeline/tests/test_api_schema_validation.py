from api_validation import ApiContractError, validate_transaction_create, validate_transaction_response


def _request():
    return {
        "provider_transaction_id": "tx-1",
        "provider_account_id": "123456",
        "provider": "mpesa",
        "TransAmount": "10.50",
        "Currency": "KES",
        "MSISDN": "254700000000",
        "TransTime": "20260923120000",
    }


def test_transaction_request_schema_accepts_valid_payload():
    validate_transaction_create(_request())


def test_transaction_request_schema_rejects_bad_currency_and_body():
    invalid = _request()
    invalid["Currency"] = "kes"
    try:
        validate_transaction_create(invalid)
    except ApiContractError as exc:
        assert "Currency" in str(exc)
    else:
        raise AssertionError("invalid currency must be rejected")

    try:
        validate_transaction_create(None)
    except ApiContractError as exc:
        assert "JSON object" in str(exc)
    else:
        raise AssertionError("non-object body must be rejected")


def test_transaction_response_schema_is_checked():
    validate_transaction_response({"status": "accepted", "duplicate": False, "idempotency_key": "key-1"})


def test_transaction_request_rejects_nonpositive_and_subcent_amounts():
    for amount in ("0.00", "1.005"):
        payload = _request()
        payload["TransAmount"] = amount
        try:
            validate_transaction_create(payload)
        except ApiContractError:
            pass
        else:
            raise AssertionError(f"invalid amount {amount!r} must be rejected")