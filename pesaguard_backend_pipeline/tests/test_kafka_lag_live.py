"""Broker-derived Kafka lag semantics (unit + opt-in live).

Local tests verify the dual-source design: the consumer lag registry is the
process-local snapshot, while ``broker_consumer_lag`` is the broker-derived
authoritative source that is only populated when env-configured Kafka is present.
Live tests verify the same behavior against a real broker.

Run with PESAGUARD_LIVE_E2E=1 against a reachable Kafka broker.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("PESAGUARD_LIVE_E2E") != "1",
    reason="set PESAGUARD_LIVE_E2E=1 to run against the integration stack",
)


@pytest.mark.integration
def test_broker_derived_lag_and_queue_depth_match_published_messages():
    from kafka import KafkaConsumer, KafkaProducer, TopicPartition

def test_broker_consumer_lag_is_empty_when_env_unconfigured():
    """Broker-derived lag must not block startup or scrape when Kafka is absent."""
    for name in ("KAFKA_BOOTSTRAP_SERVERS", "KAFKA_LAG_TOPICS", "KAFKA_LAG_GROUPS"):
        assert os.getenv(name) != "pesaguard-test-value"
    result = broker_consumer_lag()
    assert result == {}


def test_consumer_lag_registry_is_process_local_snapshot():
    consumer_lag_registry.update("reconciliation", {0: 7, 1: 2})
    snapshot = consumer_lag_registry.snapshot()
    assert snapshot["reconciliation"] == {0: 7, 1: 2}
    # Registry reflects the last consumer snapshot, not broker offsets.

    from event_bus import admin_client_lag, query_broker_lag, queue_depth

    bootstrap = os.environ["PESAGUARD_LIVE_KAFKA_BOOTSTRAP"]
    topic = f"pesaguard.lag.{uuid.uuid4().hex}"
    group = f"pesaguard-lag-test-{uuid.uuid4().hex[:8]}"
    total_messages = 10

    from kafka.admin import KafkaAdminClient, NewTopic
    admin = KafkaAdminClient(bootstrap_servers=bootstrap.split(","), client_id="pesaguard-lag-test")
    admin.create_topics([NewTopic(topic, num_partitions=1, replication_factor=1)])
    admin.close()

    producer = KafkaProducer(
        bootstrap_servers=bootstrap.split(","),
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )
    for index in range(total_messages):
        producer.send(topic, {"index": index})
    producer.flush()
    producer.close()

    consumer = KafkaConsumer(
        bootstrap_servers=bootstrap.split(","),
        group_id=group,
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        consumer_timeout_ms=10_000,
    )
    consumer.subscribe([topic])
    consumed = 0
    for message in consumer:
        consumed += 1
        consumer.commit()
        if consumed == 4:
            break
    consumer.close()
    assert consumed == 4

    # Broker-derived lag: 10 produced - 4 committed = 6.
    lag = query_broker_lag(bootstrap, [topic], [group])
    assert lag[group][f"{topic}:0"] == 6

    depth = queue_depth(bootstrap, [topic])
    assert depth[topic] == total_messages

    admin_result = admin_client_lag(bootstrap, [topic], [group])
    if admin_result is not None:
        assert admin_result[group][f"{topic}:0"] == 6


@pytest.mark.integration
def test_broker_consumer_lag_reads_env_configured_topics(monkeypatch):
    from event_bus import broker_consumer_lag

    bootstrap = os.environ["PESAGUARD_LIVE_KAFKA_BOOTSTRAP"]
    topic = f"pesaguard.envlag.{uuid.uuid4().hex}"
    group = f"pesaguard-envlag-{uuid.uuid4().hex[:8]}"

    from kafka import KafkaProducer
    from kafka.admin import KafkaAdminClient, NewTopic

    admin = KafkaAdminClient(bootstrap_servers=bootstrap.split(","), client_id="pesaguard-envlag")
    admin.create_topics([NewTopic(topic, num_partitions=1, replication_factor=1)])
    admin.close()

    producer = KafkaProducer(
        bootstrap_servers=bootstrap.split(","),
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )
    producer.send(topic, {"probe": 1})
    producer.flush()
    producer.close()

    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", bootstrap)
    monkeypatch.setenv("KAFKA_LAG_TOPICS", topic)
    monkeypatch.setenv("KAFKA_LAG_GROUPS", group)
    monkeypatch.setenv("KAFKA_LAG_REQUEST_TIMEOUT_MS", "5000")

    result = broker_consumer_lag()
    assert result[group][f"{topic}:0"] == 1
