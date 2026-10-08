from ingestion import IngestionError, IngestionService, ProcessResult
from connectors.registry import get_connector


def mpesa_payload(reference="R-1"):
    return {
        "TransactionType": "Pay Bill",
        "TransID": reference,
        "TransTime": "20260923120000",
        "TransAmount": "10.50",
        "BusinessShortCode": "123456",
        "MSISDN": "254700000000",
    }


class FakeEventStore:
    def __init__(self):
        self.calls = []
        self.seen = set()

    def mark_processed(self, payload, *, tenant_id, idempotency_key_override):
        self.calls.append((payload, tenant_id, idempotency_key_override))
        if idempotency_key_override in self.seen:
            return ProcessResult.DUPLICATE
        self.seen.add(idempotency_key_override)
        return ProcessResult.STORED


def test_all_source_adapters_share_one_envelope_contract():
    service = IngestionService(FakeEventStore())
    records = {
        "mpesa": mpesa_payload(),
        "airtel-money": {"transaction_id": "airtel-1", "amount": "4.25", "account_id": "airtel-acct"},
        "bank": {"transaction_id": "bank-1", "amount": "8.00", "account_id": "bank-acct"},
        "pos": {"transaction_id": "pos-1", "amount": "2.00", "account_id": "pos-acct", "merchant_id": "merchant-1", "terminal_id": "terminal-1"},
        "csv": {"transaction_id": "csv-1", "amount": "3.00", "account_id": "file-1"},
        "external-api": {"transaction_id": "api-1", "amount": "5.00", "account_id": "api-1"},
        "webhook": {"transaction_id": "hook-1", "amount": "6.00", "account_id": "hook-1"},
    }
    for provider, payload in records.items():
        result = service.ingest(provider, payload, tenant_id="tenant-a")
        assert result.envelope.provider == provider
        assert result.envelope.tenant_id == "tenant-a"
        assert result.envelope.external_reference
        assert result.envelope.schema_version == 1


def test_ingestion_service_uses_store_for_idempotency_without_direct_table_access():
    store = FakeEventStore()
    service = IngestionService(store)
    first = service.ingest("mpesa", mpesa_payload(), tenant_id="tenant-a")
    second = service.ingest("mpesa", mpesa_payload(), tenant_id="tenant-a")
    assert first.result is ProcessResult.STORED
    assert second.result is ProcessResult.DUPLICATE
    assert len(store.calls) == 2
    assert all(call[1] == "tenant-a" for call in store.calls)


def test_unknown_provider_and_invalid_payload_are_rejected():
    service = IngestionService(FakeEventStore())
    try:
        service.ingest("unknown", {}, tenant_id="tenant-a")
    except IngestionError as error:
        assert "unsupported" in str(error)
    else:
        raise AssertionError("unknown providers must not bypass the adapter registry")

    try:
        service.ingest("bank", {"transaction_id": "bank-2"}, tenant_id="tenant-a")
    except IngestionError as error:
        assert "amount" in str(error)
    else:
        raise AssertionError("invalid records must be rejected before persistence")


def test_safaricom_api_adapter_maps_provider_fields_at_boundary():
    service = IngestionService(FakeEventStore())
    result = service.ingest(
        "safaricom-api",
        {
            "data": {
                "transactionId": "QWE123",
                "amount": 2500,
                "currency": "KES",
                "accountId": "acc-123",
                "phoneNumber": "254700000000",
                "transactionTime": "2026-09-23T18:29:54Z",
            }
        },
        tenant_id="tenant-a",
    )
    assert result.envelope.canonical.transaction_id.startswith("txn_")
    assert result.envelope.canonical.provider_transaction_id == "QWE123"
    assert result.envelope.canonical.amount == "2500.00"
    assert result.envelope.canonical.provider == "safaricom"
    assert "transactionId" not in result.envelope.canonical.__dict__
    assert result.envelope.payload["TransID"] == "QWE123"


def test_mpesa_canonical_amount_preserves_large_decimal_digits():
    payload = mpesa_payload("large-decimal")
    payload["TransAmount"] = "90071992547409.93"

    result = IngestionService(FakeEventStore()).ingest("mpesa", payload, tenant_id="tenant-a")

    assert result.envelope.canonical.amount == "90071992547409.93"
    assert result.envelope.payload["TransAmount"] == "90071992547409.93"


def test_successful_b2c_callback_is_rejected_without_account_mapping():
    store = FakeEventStore()
    service = IngestionService(store)

    try:
        service.ingest("mpesa", {"Result": {"ResultCode": 0}}, tenant_id="tenant-a")
    except IngestionError as error:
        assert "provider account mapping" in str(error)
    else:
        raise AssertionError("B2C result callbacks must not be persisted without account mapping")
    assert store.calls == []


def test_connector_enforces_source_contract_before_persistence():
    store = FakeEventStore()
    service = IngestionService(store)
    connector = get_connector("mpesa", service)
    payload = mpesa_payload()
    payload["schema_version"] = "99.0"

    try:
        connector.ingest(payload, tenant_id="tenant-a")
    except IngestionError as error:
        assert "unsupported mpesa contract version" in str(error)
    else:
        raise AssertionError("unsupported source schema versions must be rejected")
    assert store.calls == []


def test_connector_emit_rejects_envelope_payload_tampering():
    from dataclasses import replace

    store = FakeEventStore()
    service = IngestionService(store)
    connector = get_connector("mpesa", service)
    envelope = connector.transform(mpesa_payload(), tenant_id="tenant-a")
    tampered_payload = {**envelope.payload, "TransAmount": "11.00"}

    try:
        service.emit(replace(envelope, payload=tampered_payload))
    except IngestionError as error:
        assert "does not match" in str(error)
    else:
        raise AssertionError("tampered connector envelopes must not be persisted")
    assert store.calls == []


def test_connector_emit_accepts_sources_without_transaction_timestamp():
    store = FakeEventStore()
    service = IngestionService(store)
    connector = get_connector("bank", service)
    payload = {"transaction_id": "bank-no-time", "amount": "8.00", "account_id": "bank-acct"}
    envelope = connector.transform(payload, tenant_id="tenant-a")

    result = connector.emit(envelope)

    assert result.envelope is envelope
    assert envelope.observed_at == envelope.canonical.transaction_time
    assert envelope.payload["TransTime"] == envelope.observed_at
    assert len(store.calls) == 1


def test_safaricom_connector_emit_accepts_response_without_transaction_timestamp():
    store = FakeEventStore()
    service = IngestionService(store)
    connector = get_connector("safaricom-api", service)
    payloads = (
        {
            "data": {
                "transactionId": "QWE-no-time",
                "amount": "10.00",
                "accountId": "safaricom-account",
            }
        },
        {
            "data": {
                "transactionId": "QWE-with-time",
                "amount": "11.00",
                "accountId": "safaricom-account",
                "transactionTime": "2026-09-23T18:29:54Z",
            }
        },
    )

    envelopes = [connector.transform(payload, tenant_id="tenant-a") for payload in payloads]
    results = [connector.emit(envelope) for envelope in envelopes]

    assert all(result.envelope is envelope for result, envelope in zip(results, envelopes))
    assert envelopes[0].observed_at == envelopes[0].canonical.transaction_time
    assert envelopes[0].payload["TransTime"] == envelopes[0].observed_at
    assert envelopes[1].observed_at == "2026-09-23T18:29:54Z"
    assert envelopes[1].payload["TransTime"] == envelopes[1].observed_at
    assert len(store.calls) == 2


def test_generic_adapter_uses_transaction_time_alias_and_emit_preserves_it():
    store = FakeEventStore()
    service = IngestionService(store)
    payload = {
        "transaction_id": "api-tx-with-time",
        "amount": "5.00",
        "account_id": "api-account",
        "transaction_time": "2026-09-23T18:29:54Z",
    }
    envelope = service.adapters["external-api"].normalize(payload, tenant_id="tenant-a")

    result = service.emit(envelope)

    assert result.envelope.canonical.transaction_time == "2026-09-23T18:29:54Z"
    assert result.envelope.observed_at == "2026-09-23T18:29:54Z"
    assert len(store.calls) == 1


def test_connector_emit_rejects_inconsistent_generated_timestamp():
    from dataclasses import replace

    store = FakeEventStore()
    service = IngestionService(store)
    connector = get_connector("bank", service)
    envelope = connector.transform(
        {"transaction_id": "bank-timestamp-tamper", "amount": "8.00", "account_id": "bank-acct"},
        tenant_id="tenant-a",
    )
    tampered_payload = {**envelope.payload, "TransTime": "2026-09-23T18:29:54Z"}

    try:
        service.emit(replace(envelope, payload=tampered_payload))
    except IngestionError as error:
        assert "does not match" in str(error)
    else:
        raise AssertionError("inconsistent envelope timestamps must not be persisted")
    assert store.calls == []