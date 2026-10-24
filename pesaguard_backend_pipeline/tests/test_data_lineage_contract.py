"""Contract tests for transaction-level data lineage.

These tests protect the immutable lineage contract used by ingestion,
normalization, reconciliation, and reporting. They intentionally avoid
external services and credentials.
"""

from data_lineage import LineageEntry, build_lineage


def test_build_lineage_preserves_transaction_and_tenant_identity():
    lineage = build_lineage(
        event_id="event-001",
        transaction_id="tx-001",
        tenant_id="tenant-001",
        provider_id="mpesa",
    )

    payload = lineage.to_dict()
    assert payload["event_id"] == "event-001"
    assert payload["transaction_id"] == "tx-001"
    assert payload["tenant_id"] == "tenant-001"
    assert payload["provider_id"] == "mpesa"
    assert payload["lineage_id"]
    assert payload["stages"] == []


def test_lineage_ids_are_unique_for_independent_events():
    first = build_lineage(
        event_id="event-001",
        transaction_id="tx-001",
        tenant_id="tenant-001",
        provider_id="mpesa",
    )
    second = build_lineage(
        event_id="event-001",
        transaction_id="tx-001",
        tenant_id="tenant-001",
        provider_id="mpesa",
    )

    assert first.lineage_id != second.lineage_id


def test_snapshot_appends_stage_without_mutating_original():
    original = build_lineage(
        event_id="event-002",
        transaction_id="tx-002",
        tenant_id="tenant-002",
        provider_id="mpesa",
    )

    enriched = original.snapshot(
        stage="normalized",
        service="ingestion",
        action="normalize",
        schema_version="1.0",
        metadata={"field_count": 8},
    )

    assert original.entries == []
    assert len(enriched.entries) == 1
    assert enriched.has_stage("normalized") is True
    assert original.has_stage("normalized") is False
    assert enriched.entries[0].to_dict() == {
        "stage": "normalized",
        "service": "ingestion",
        "action": "normalize",
        "occurred_at": enriched.entries[0].occurred_at,
        "schema_version": "1.0",
        "metadata": {"field_count": 8},
    }


def test_finalize_preserves_lineage_and_records_decision_immutably():
    original = build_lineage(
        event_id="event-003",
        transaction_id="tx-003",
        tenant_id="tenant-003",
        provider_id="mpesa",
    ).snapshot("raw_event", "webhook", "accepted")

    finalized = original.finalize("accepted")

    assert original.final_decision is None
    assert finalized.final_decision == "accepted"
    assert finalized.lineage_id == original.lineage_id
    assert finalized.tenant_id == original.tenant_id
    assert finalized.transaction_id == original.transaction_id
    assert finalized.to_dict()["stages"][0]["stage"] == "raw_event"


def test_lineage_entry_omits_optional_fields_when_not_set():
    entry = LineageEntry(
        stage="provider",
        service="daraja",
        action="callback_received",
    )

    payload = entry.to_dict()
    assert payload["stage"] == "provider"
    assert payload["service"] == "daraja"
    assert payload["action"] == "callback_received"
    assert "schema_version" not in payload
    assert "metadata" not in payload
