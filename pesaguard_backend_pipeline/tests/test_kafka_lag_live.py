"""Broker-derived Kafka lag semantics and disposable broker integration checks."""

from __future__ import annotations

import json
import os
import uuid

import pytest


def _live_broker_enabled() -> bool:
    return os.getenv("PESAGUARD_RUN_KAFKA_INTEGRATION") == "1"


def _bootstrap_servers() -> str:
    return os.environ["PESAGUARD_LIVE_KAFKA_BOOTSTRAP"]


def _create_topic(bootstrap: str, topic: str) -> None:
    from kafka.admin import KafkaAdminClient, NewTopic

    admin = KafkaAdminClient(bootstrap_servers=bootstrap.split(","), client_id="pesaguard-lag-test")
    try:
        admin.create_topics([NewTopic(topic, num_partitions=1, replication_factor=1)])
    finally:
        admin.close()


def test_broker_consumer_lag_is_empty_when_kafka_is_not_configured(monkeypatch):
    from event_bus import broker_consumer_lag

    for name in ("KAFKA_BOOTSTRAP_SERVERS", "KAFKA_LAG_TOPICS", "KAFKA_LAG_GROUPS"):
        monkeypatch.delenv(name, raising=False)
    assert broker_consumer_lag() == {}


def test_consumer_lag_registry_is_an_isolated_process_local_snapshot():
    from event_bus import ConsumerLagRegistry

    registry = ConsumerLagRegistry()
    lag = {0: 7, 1: 2}
    registry.update("reconciliation", lag)
    lag[0] = 99

    snapshot = registry.snapshot()
    assert snapshot == {"reconciliation": {0: 7, 1: 2}}
    snapshot["reconciliation"][1] = 99
    assert registry.snapshot() == {"reconciliation": {0: 7, 1: 2}}


@pytest.mark.integration
@pytest.mark.skipif(not _live_broker_enabled(), reason="set PESAGUARD_RUN_KAFKA_INTEGRATION=1 to use a disposable broker")
def test_broker_derived_lag_and_queue_depth_match_published_messages():
    from event_bus import admin_client_lag, query_broker_lag, queue_depth
    from kafka import KafkaConsumer, KafkaProducer

    bootstrap = _bootstrap_servers()
    topic = f"pesaguard.lag.{uuid.uuid4().hex}"
    group = f"pesaguard-lag-test-{uuid.uuid4().hex[:8]}"
    total_messages = 10
    _create_topic(bootstrap, topic)

    producer = KafkaProducer(
        bootstrap_servers=bootstrap.split(","),
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )
    try:
        for index in range(total_messages):
            producer.send(topic, {"index": index})
        producer.flush()
    finally:
        producer.close()

    consumer = KafkaConsumer(
        bootstrap_servers=bootstrap.split(","),
        group_id=group,
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        consumer_timeout_ms=10_000,
    )
    consumed = 0
    try:
        consumer.subscribe([topic])
        for _message in consumer:
            consumed += 1
            consumer.commit()
            if consumed == 4:
                break
    finally:
        consumer.close()

    assert consumed == 4
    assert query_broker_lag(bootstrap, [topic], [group])[group][f"{topic}:0"] == total_messages - consumed
    assert queue_depth(bootstrap, [topic])[topic] == total_messages
    admin_lag = admin_client_lag(bootstrap, [topic], [group])
    if admin_lag is not None:
        assert admin_lag[group][f"{topic}:0"] == total_messages - consumed


@pytest.mark.integration
@pytest.mark.skipif(not _live_broker_enabled(), reason="set PESAGUARD_RUN_KAFKA_INTEGRATION=1 to use a disposable broker")
def test_broker_consumer_lag_reads_env_configured_topics(monkeypatch):
    from event_bus import broker_consumer_lag
    from kafka import KafkaProducer

    bootstrap = _bootstrap_servers()
    topic = f"pesaguard.envlag.{uuid.uuid4().hex}"
    group = f"pesaguard-envlag-{uuid.uuid4().hex[:8]}"
    _create_topic(bootstrap, topic)

    producer = KafkaProducer(
        bootstrap_servers=bootstrap.split(","),
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )
    try:
        producer.send(topic, {"probe": 1})
        producer.flush()
    finally:
        producer.close()

    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", bootstrap)
    monkeypatch.setenv("KAFKA_LAG_TOPICS", topic)
    monkeypatch.setenv("KAFKA_LAG_GROUPS", group)
    monkeypatch.setenv("KAFKA_LAG_REQUEST_TIMEOUT_MS", "5000")
    assert broker_consumer_lag()[group][f"{topic}:0"] == 1
