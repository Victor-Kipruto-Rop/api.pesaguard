"""Kafka/Redpanda worker for the staged real-time transaction pipeline."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Callable, Dict

from event_bus import EventEnvelope
from producer import publish_versioned_event  # noqa: F401
from realtime_pipeline import RealtimeTransactionPipeline
from topics import TOPIC_TRANSACTIONS_ENRICHED, TOPIC_TRANSACTIONS_NORMALIZED, TOPIC_TRANSACTIONS_RAW, TOPIC_TRANSACTIONS_VALIDATED

logger = logging.getLogger("pesaguard.realtime_worker")


@dataclass(frozen=True)
class Stage:
    name: str
    input_topic: str
    consumer_group: str
    handler_name: str


STAGES: Dict[str, Stage] = {
    "validation": Stage("validation", TOPIC_TRANSACTIONS_RAW, "transaction-validation", "validate"),
    "normalization": Stage("normalization", TOPIC_TRANSACTIONS_VALIDATED, "transaction-normalization", "normalize"),
    "enrichment": Stage("enrichment", TOPIC_TRANSACTIONS_NORMALIZED, "transaction-enrichment", "enrich"),
    "processing": Stage("processing", TOPIC_TRANSACTIONS_ENRICHED, "transaction-processors", "process"),
}


def run_stage(stage_name: str, *, bootstrap_servers: str | None = None) -> None:
    """Run one independently scalable stage until shutdown."""
    try:
        from kafka import KafkaConsumer, KafkaProducer
    except ImportError as exc:
        raise RuntimeError("realtime worker requires kafka-python-ng") from exc
    stage = STAGES.get(stage_name)
    if stage is None:
        raise ValueError(f"unknown real-time stage: {stage_name}")
    servers = bootstrap_servers or os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    consumer = KafkaConsumer(
        stage.input_topic,
        bootstrap_servers=servers,
        group_id=stage.consumer_group,
        enable_auto_commit=False,
        value_deserializer=lambda value: json.loads(value.decode("utf-8")),
        max_poll_records=int(os.getenv("PESAGUARD_STAGE_MAX_POLL_RECORDS", "100")),
    )
    producer = KafkaProducer(
        bootstrap_servers=servers,
        acks="all",
        enable_idempotence=True,
        value_serializer=lambda value: json.dumps(value, ensure_ascii=False).encode("utf-8"),
    )
    pipeline = RealtimeTransactionPipeline(publisher=lambda event: publish_versioned_event(event, producer=producer))
    handler: Callable[[EventEnvelope], EventEnvelope] = getattr(pipeline, stage.handler_name)
    logger.info("Starting real-time stage=%s topic=%s group=%s", stage.name, stage.input_topic, stage.consumer_group)
    try:
        for message in consumer:
            event = EventEnvelope.from_dict(message.value)
            handler(event)
            producer.flush(timeout=10)
            consumer.commit()
    finally:
        consumer.close()
        producer.close()


if __name__ == "__main__":
    run_stage(os.getenv("PESAGUARD_REALTIME_STAGE", "validation"))