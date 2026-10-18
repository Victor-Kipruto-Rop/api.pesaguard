from data_protection import protect_payload, tokenize_identifier, unprotect_payload


def test_sensitive_payload_values_are_encrypted_and_round_trip():
    payload = {"TransID": "tx-1", "MSISDN": "254700000000", "nested": {"account_number": "1234"}}
    protected = protect_payload(payload)

    assert protected["MSISDN"].startswith("enc:v1:")
    assert protected["nested"]["account_number"].startswith("enc:v1:")
    assert "254700000000" not in str(protected)
    assert unprotect_payload(protected) == payload


def test_identifier_tokens_are_deterministic_without_revealing_plaintext():
    first = tokenize_identifier("254700000000")
    second = tokenize_identifier("254700000000")

    assert first == second
    assert first.startswith("tok:v1:")
    assert "254700000000" not in first

def test_protect_payload_is_idempotent_for_already_encrypted_values():
    payload = {"msisdn": "254700000000"}
    protected = protect_payload(payload)

    assert protect_payload(protected) == protected
    assert unprotect_payload(protected) == payload
