from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine

from event_bus import EVENT_TYPES, EventContractError, build_event, validate_event
from event_consumer import ConsumerGroup, EventConsumer
from event_store import EventStore, ProcessResult
from models import Base, Transaction
from producer import publish_versioned_event
from topics import ALL_TOPICS, EVENT_TYPE_TOPICS, TOPIC_SPECIFICATIONS

_TOPIC_INVENTORY_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "pesaguard_backend_pipeline"
    / "infra"
    / "redpanda"
    / "topics.yaml"
)


def _load_topic_inventory():
    import yaml

    return yaml.safe_load(_TOPIC_INVENTORY_PATH.read_text(encoding="utf-8"))


def _transaction_payload():
    return {
        "TransID": "contract-tx-1",
        "TransAmount": "10.00",
        "MSISDN": "254700000000",
        "BusinessShortCode": "123456",
        "TransTime": "20260923120000",
        "provider": "mpesa",
        "tenant_id": "tenant-a",
    }


class CapturingProducer:
    def __init__(self):
        self.messages = []

    def send(self, topic, **kwargs):
        self.messages.append((topic, kwargs))
        return SimpleNamespace(get=lambda timeout: SimpleNamespace(topic=topic, partition=0, offset=0))


def test_producer_generates_valid_versioned_event_envelope():
    event = build_event("transaction.received", "tenant-a", "contract-tx-1", _transaction_payload(), event_id="contract-event-1")
    producer = CapturingProducer()

    publish_versioned_event(event, producer=producer)
    topic, message = producer.messages[0]
    received = validate_event(message["value"])

    assert topic == "pesaguard.transactions.raw"
    assert received.event_id == "contract-event-1"
    assert received.event_version == 1
    assert received.schema_version == "1.0"
    assert received.tenant_id == "tenant-a"
    assert received.payload["TransID"] == "contract-tx-1"


def test_consumer_accepts_optional_and_unknown_metadata_fields():
    event = build_event(
        "transaction.received",
        "tenant-a",
        "contract-tx-2",
        _transaction_payload(),
        metadata={"new_optional_field": "accepted"},
    ).to_dict()
    event["future_field"] = "ignored"
    consumer = EventConsumer(ConsumerGroup("audit", frozenset({"transaction.received"})))
    seen = []
    consumer.register("transaction.received", lambda received: seen.append(received.metadata["new_optional_field"]))

    assert consumer.consume(event).status == "processed"
    assert seen == ["accepted"]


def test_consumer_rejects_invalid_event_contract():
    consumer = EventConsumer(ConsumerGroup("audit", frozenset({"transaction.received"})))
    result = consumer.consume({"event_id": "invalid", "event_type": "transaction.received"})

    assert result.status == "dead_lettered"
    assert "schema_validation_failed" in result.reason


def test_consumer_to_postgres_contract_is_idempotent(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'contract.db'}"
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    store = EventStore(database_url=database_url)
    consumer = EventConsumer(ConsumerGroup("transaction", frozenset({"transaction.received"})))
    consumer.register(
        "transaction.received",
        lambda event: store.mark_processed(event.payload, tenant_id=event.tenant_id),
    )
    event = build_event("transaction.received", "tenant-a", "contract-tx-3", _transaction_payload(), event_id="contract-event-3")

    assert consumer.consume(event).status == "processed"
    assert store.mark_processed(event.payload, tenant_id=event.tenant_id) is ProcessResult.DUPLICATE
    from sqlalchemy.orm import sessionmaker
    with sessionmaker(bind=engine)() as session:
        assert session.query(Transaction).count() == 1


# ---------------------------------------------------------------------------
# Event routing coverage. Regression guard for the gap where an event type could
# be registered in EVENT_TYPES (and therefore validate) while having no entry in
# EVENT_TYPE_TOPICS, making producer.publish_versioned_event() raise KeyError.
# ---------------------------------------------------------------------------


def test_every_registered_event_type_has_a_topic_route():
    unrouted = sorted(EVENT_TYPES - set(EVENT_TYPE_TOPICS))

    assert unrouted == [], f"event types registered but not routed: {unrouted}"


def test_every_event_route_targets_a_provisioned_topic():
    targets = set(EVENT_TYPE_TOPICS.values())

    assert targets <= set(TOPIC_SPECIFICATIONS), (
        f"routes target unprovisioned topics: {sorted(targets - set(TOPIC_SPECIFICATIONS))}"
    )
    assert targets <= set(ALL_TOPICS), (
        f"routes target topics absent from ALL_TOPICS: {sorted(targets - set(ALL_TOPICS))}"
    )


def test_publish_versioned_event_routes_every_registered_event_type():
    """Every registered contract must be publishable without a KeyError."""
    producer = CapturingProducer()

    for event_type in sorted(EVENT_TYPES):
        event = build_event(
            event_type,
            "tenant-a",
            f"aggregate-{event_type}",
            {"probe": True},
            event_id=f"probe-{event_type}",
        )
        publish_versioned_event(event, producer=producer)

    published_topics = [topic for topic, _ in producer.messages]
    assert len(published_topics) == len(EVENT_TYPES)
    assert set(published_topics) <= set(ALL_TOPICS)


def test_terminal_transaction_outcomes_use_dedicated_topics():
    """Stage-topic consumers must never receive a terminal outcome event."""
    stage_events = {
        "transaction.created",
        "transaction.received",
        "transaction.validated",
        "transaction.normalized",
        "transaction.enriched",
        "transaction.processed",
    }
    terminal_events = {
        "transaction.completed",
        "transaction.failed",
        "transaction.rejected",
    }

    assert EVENT_TYPE_TOPICS["transaction.completed"] == "pesaguard.transactions.completed"
    assert EVENT_TYPE_TOPICS["transaction.failed"] == "pesaguard.transactions.failed"
    assert EVENT_TYPE_TOPICS["transaction.rejected"] == "pesaguard.transactions.rejected"

    stage_topics = {EVENT_TYPE_TOPICS[event_type] for event_type in stage_events}
    terminal_topics = {EVENT_TYPE_TOPICS[event_type] for event_type in terminal_events}
    assert stage_topics.isdisjoint(terminal_topics)


def test_reconciliation_run_lifecycle_shares_the_requested_topic():
    """requested/started/failed describe one run; results use their own topics."""
    run_topics = {
        EVENT_TYPE_TOPICS["reconciliation.requested"],
        EVENT_TYPE_TOPICS["reconciliation.started"],
        EVENT_TYPE_TOPICS["reconciliation.failed"],
    }

    assert run_topics == {"pesaguard.reconciliation.requested"}


def test_notification_delivery_problems_share_the_failed_topic():
    failure_topics = {
        EVENT_TYPE_TOPICS["notification.failed"],
        EVENT_TYPE_TOPICS["notification.retry"],
        EVENT_TYPE_TOPICS["notification.exhausted"],
    }

    assert failure_topics == {"pesaguard.notifications.failed"}
    assert EVENT_TYPE_TOPICS["notification.sent"] == "pesaguard.notifications.sent"


def _write_topic_inventory(path, entries):
    lines = ["topics:"]
    for name, partitions, retention_ms in entries:
        lines += [
            f"  - name: {name}",
            f"    partitions: {partitions}",
            f"    retention_ms: {retention_ms}",
        ]
    return Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _inventory_entries():
    return [
        (name, TOPIC_SPECIFICATIONS[name]["num_partitions"], TOPIC_SPECIFICATIONS[name]["configs"]["retention.ms"])
        for name in TOPIC_SPECIFICATIONS
    ]


def test_declared_redpanda_inventory_matches_kafka_provisioning_specs(tmp_path):
    """Keep infra/redpanda/topics.yaml drift-free from provision_topics() specs."""
    pytest.importorskip("yaml")
    inventory = _load_topic_inventory()["topics"]
    declared = {
        entry["name"]: (entry["partitions"], entry["retention_ms"])
        for entry in inventory
    }

    code_topics = set(TOPIC_SPECIFICATIONS)
    missing_from_inventory = sorted(code_topics - set(declared))
    missing_from_code = sorted(set(declared) - code_topics)
    mismatched = sorted(
        name
        for name in code_topics & set(declared)
        if (
            declared[name][0],
            str(declared[name][1]),
        )
        != (
            TOPIC_SPECIFICATIONS[name]["num_partitions"],
            TOPIC_SPECIFICATIONS[name]["configs"]["retention.ms"],
        )
    )

    assert missing_from_inventory == [], (
        f"topics in code but absent from topics.yaml: {missing_from_inventory}"
    )
    assert missing_from_code == [], (
        f"topics in topics.yaml but absent from code: {missing_from_code}"
    )
    assert mismatched == [], (
        f"topics.yaml/code partition-or-retention drift: {mismatched}"
    )


def test_topic_inventory_guard_detects_partition_or_retention_drift(tmp_path):
    """The inventory guard must reject a topics.yaml missing names or values."""
    drifted = [entry for entry in _inventory_entries() if entry[0] != "pesaguard.dlq"]
    drifted[0] = (drifted[0][0], drifted[0][1] + 3, drifted[0][2])
    inventory_path = tmp_path / "topics.yaml"
    _write_topic_inventory(inventory_path, drifted)
    import yaml

    declared = {
        entry["name"]: (entry["partitions"], entry["retention_ms"])
        for entry in yaml.safe_load(inventory_path.read_text(encoding="utf-8"))["topics"]
    }
    code_topics = set(TOPIC_SPECIFICATIONS)
    missing_from_inventory = sorted(code_topics - set(declared))
    mismatched = sorted(
        name
        for name in code_topics & set(declared)
        if (
            declared[name][0],
            str(declared[name][1]),
        )
        != (
            TOPIC_SPECIFICATIONS[name]["num_partitions"],
            TOPIC_SPECIFICATIONS[name]["configs"]["retention.ms"],
        )
    )

    assert missing_from_inventory == ["pesaguard.dlq"]
    assert mismatched, "the drift check must fail on changed partitions"