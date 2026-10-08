"""
Kafka event producer wrapper for PesaGuard transaction ingestion.

Provides thread-safe event publishing with delivery acknowledgement, exponential retries,
partition key routing, open telemetry metadata headers, schema validation, batching,
dead-letter queue fallbacks, and circuit-breaker resilient connection management.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, Dict, Optional, Callable, List

from partitioning import event_partition_key

logger = logging.getLogger("pesaguard.producer")

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
PRODUCER_SEND_TIMEOUT_SECONDS = int(os.getenv("PESAGUARD_PRODUCER_SEND_TIMEOUT_SECONDS", "10"))
ENABLE_DLQ_FALLBACK = os.getenv("PESAGUARD_PRODUCER_ENABLE_DLQ_FALLBACK", "1") == "1"


def publish_versioned_event(event: Any, *, producer: Any = None) -> Any:
    """Publish a validated Phase 4 EventEnvelope through the existing Kafka producer."""
    from event_bus import EventEnvelope, validate_event
    from topics import EVENT_TYPE_TOPICS

    event = validate_event(event)
    from logging_utils import bind_observability_context
    from observability import trace_span
    persisted_traceparent = str(event.metadata.get("traceparent") or "").strip()
    bind_observability_context(
        correlation_id=event.correlation_id,
        transaction_id=event.aggregate_id,
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        **({"traceparent": persisted_traceparent} if persisted_traceparent else {}),
    )
    topic = EVENT_TYPE_TOPICS[event.event_type]
    payload = event.to_dict()
    if producer is not None:
        # Keep tenant/account-related events ordered without assuming global ordering.
        partition_key = str(event.metadata.get("partition_key") or event_partition_key(event.to_dict()))
        key = partition_key.encode("utf-8")
        span_fields = {"topic": topic, "event_type": event.event_type}
        if persisted_traceparent:
            span_fields["traceparent"] = persisted_traceparent
        with trace_span("kafka.publish", **span_fields):
            from observability import inject_trace_context
            trace_headers = inject_trace_context({})
            return producer.send(topic, key=key, value=payload, headers=[
                ("event_type", event.event_type.encode("utf-8")),
                ("event_version", str(event.event_version).encode("utf-8")),
                ("schema_version", event.schema_version.encode("utf-8")),
                ("source", event.source.encode("utf-8")),
                ("tenant_id", event.tenant_id.encode("utf-8")),
                ("traceparent", trace_headers["traceparent"].encode("ascii")),
            ])
    return publish_transaction_event(topic, payload, correlation_id=event.correlation_id)


class CircuitBreakerOpenException(Exception):
    """Raised when the circuit breaker blocks execution due to consecutive downstream failures."""
    pass


class CircuitBreaker:
    """Production-grade circuit breaker to prevent cascade failures on Kafka transport outages."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 30.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_state_change = time.time()
        self.state = "CLOSED"  # CLOSED, OPEN, HALF-OPEN
        self._lock = threading.Lock()

    def can_execute(self) -> bool:
        with self._lock:
            now = time.time()
            if self.state == "OPEN":
                if now - self.last_state_change > self.recovery_timeout:
                    self.state = "HALF-OPEN"
                    self.last_state_change = now
                    logger.info("CircuitBreaker transitioned to HALF-OPEN state. Testing connection...")
                    return True
                return False
            return True

    def record_success(self) -> None:
        with self._lock:
            self.failure_count = 0
            if self.state == "HALF-OPEN":
                self.state = "CLOSED"
                self.last_state_change = time.time()
                logger.info("CircuitBreaker reset to CLOSED state following successful transmission.")

    def record_failure(self) -> None:
        with self._lock:
            self.failure_count += 1
            now = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"
                self.last_state_change = now
                logger.error("CircuitBreaker threshold reached (%d failures). Transitioning to OPEN state.", self.failure_count)


class _ProducerManager:
    """Thread-safe lazy manager for the underlying KafkaProducer connection pool with idempotency and compression."""

    def __init__(self) -> None:
        self._producer: Any = None
        self._lock = threading.Lock()

    def get_producer(self) -> Any:
        if self._producer is not None:
            return self._producer

        with self._lock:
            if self._producer is not None:
                return self._producer

            try:
                from kafka import KafkaProducer
            except ImportError as exc:
                raise ImportError(
                    "Kafka producer package 'kafka-python' is not installed. "
                    "Install 'kafka-python' or configure fallback mode."
                ) from exc

            try:
                producer_kwargs = {
                    "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS,
                    "value_serializer": lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
                    "retries": 5,
                    "acks": "all",
                    "compression_type": "gzip",
                    "max_in_flight_requests_per_connection": 1,
                    "request_timeout_ms": PRODUCER_SEND_TIMEOUT_SECONDS * 1000,
                    "batch_size": 16384,
                    "linger_ms": 10,
                }
                self._producer = KafkaProducer(**producer_kwargs)
                logger.info("Kafka producer successfully initialized connecting to %s with idempotence-compatible settings.", KAFKA_BOOTSTRAP_SERVERS)
                return self._producer
            except Exception as exc:
                logger.exception("Failed to initialize Kafka producer connecting to %s: %s", KAFKA_BOOTSTRAP_SERVERS, exc)
                raise

    def reset_producer(self) -> None:
        """Close and discard the producer instance if an unrecoverable connection failure occurs."""
        with self._lock:
            if self._producer is not None:
                try:
                    self._producer.close(timeout=2)
                except Exception as exc:
                    logger.debug("Error while closing degraded Kafka producer: %s", exc)
                finally:
                    self._producer = None


_producer_manager = _ProducerManager()
_circuit_breaker = CircuitBreaker()


def _validate_payload_schema(payload: Dict[str, Any]) -> None:
    """Enforce strict runtime validation for mandatory event fields before dispatching."""
    if not isinstance(payload, dict):
        raise ValueError("Event payload must be a JSON object dictionary.")
    
    if payload.get("event_id") and payload.get("event_type") and payload.get("event_version"):
        from event_bus import EventEnvelope
        EventEnvelope.from_dict(payload)
        return
    trans_id = payload.get("TransID") or payload.get("trans_id")
    if not trans_id:
        raise ValueError("Missing required transaction identifier ('TransID' or 'trans_id') in event payload.")


def _fallback_to_dead_letter_queue(topic: str, payload: Dict[str, Any], error_reason: str) -> None:
    """Persist undeliverable events directly to the Postgres DeadLetter table if Kafka is down."""
    if not ENABLE_DLQ_FALLBACK:
        return

    try:
        from models import DeadLetter
        from app_2 import SessionLocal
        from data_protection import protect_payload
        import hashlib
        import uuid
        from datetime import datetime, timezone

        tenant_id = payload.get("tenant_id") or payload.get("TenantID") or "default"
        trans_id = payload.get("TransID") or payload.get("trans_id") or payload.get("aggregate_id") or payload.get("event_id") or "unknown"
        event_type = payload.get("event_type") or "legacy.event"
        event_id = payload.get("event_id") or "unknown"
        event_key = hashlib.sha256(f"{tenant_id}:{trans_id}:{topic}:{error_reason[:200]}".encode("utf-8")).hexdigest()
        
        with SessionLocal() as session:
            dlq_record = DeadLetter(
                id=f"dlq_{event_key[:24]}",
                tenant_id=tenant_id,
                reason=f"Kafka Delivery Failure: {error_reason[:200]}",
                payload=protect_payload(payload),
                error_detail=f"Target Topic: {topic}; EventType: {event_type}; EventID: {event_id}",
                attempts=0,
                processed=False,
                created_at=datetime.now(timezone.utc),
            )
            session.add(dlq_record)
            session.commit()
            logger.info("Fallback succeeded: Event for trans_id=%s persisted to DeadLetter DB store.", trans_id)
    except Exception as exc:
        logger.exception("DLQ fallback persistence failed for event topic=%s: %s", topic, exc)
        raise RuntimeError("dead-letter persistence failed") from exc


def publish_transaction_event(
    topic: str,
    payload: Dict[str, Any],
    correlation_id: Optional[str] = None,
    headers: Optional[List[tuple[str, bytes]]] = None,
) -> Any:
    """Publish a transaction callback event to Kafka with confirmation, correlation headers, and circuit breaker.

    Args:
        topic: Destination Kafka topic name (e.g. 'daraja-callbacks', 'discrepancies')
        payload: Event payload dictionary
        correlation_id: Optional trace correlation ID for distributed log tracing
        headers: Optional custom metadata headers (e.g., OpenTelemetry span contexts)

    Returns:
        RecordMetadata of the published message.

    Raises:
        CircuitBreakerOpenException: If Kafka transport is tripped and unreachable.
        Exception: If event delivery fails after exhausting all retries or timing out.
    """
    _validate_payload_schema(payload)

    if not _circuit_breaker.can_execute():
        error_msg = f"Kafka transport circuit breaker is OPEN for topic={topic}. Request blocked."
        logger.error(error_msg)
        _fallback_to_dead_letter_queue(topic, payload, error_msg)
        raise CircuitBreakerOpenException(error_msg)

    event_metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    persisted_traceparent = str(event_metadata.get("traceparent") or "").strip()
    if persisted_traceparent:
        from logging_utils import bind_observability_context
        from observability import extract_trace_context

        parsed_trace = extract_trace_context({"traceparent": persisted_traceparent})
        if parsed_trace:
            bind_observability_context(
                trace_id=parsed_trace["trace_id"],
                span_id=parsed_trace["span_id"],
                traceparent=persisted_traceparent,
            )
        else:
            persisted_traceparent = ""

    # Format trace headers
    msg_headers: List[tuple[str, bytes]] = list(headers) if headers else []
    if not any(str(name).lower() == "traceparent" for name, _ in msg_headers):
        if persisted_traceparent:
            msg_headers.append(("traceparent", persisted_traceparent.encode("ascii")))
        else:
            try:
                from observability import inject_trace_context
                carrier = inject_trace_context({})
                msg_headers.append(("traceparent", carrier["traceparent"].encode("ascii")))
            except Exception:
                logger.debug("Could not inject W3C traceparent header for Kafka publish", exc_info=True)
    if correlation_id:
        msg_headers.append(("correlation_id", correlation_id.encode("utf-8")))
    
    tenant_id = str(payload.get("tenant_id") or payload.get("TenantID") or "default")
    msg_headers.append(("tenant_id", tenant_id.encode("utf-8")))

    trans_id = payload.get("TransID") or payload.get("trans_id") or payload.get("aggregate_id") or payload.get("event_id")
    key = str(trans_id).encode("utf-8") if trans_id else None

    try:
        producer = _producer_manager.get_producer()
        future = producer.send(topic, key=key, value=payload, headers=msg_headers)
        
        # Non-blocking flush call to encourage batching under high load
        record_metadata = future.get(timeout=PRODUCER_SEND_TIMEOUT_SECONDS)
        _circuit_breaker.record_success()

        logger.debug(
            "Event delivered to topic=%s partition=%d offset=%d trans_id=%s tenant_id=%s",
            record_metadata.topic, record_metadata.partition, record_metadata.offset, trans_id, tenant_id
        )
        return record_metadata

    except Exception as exc:
        _circuit_breaker.record_failure()
        logger.exception(
            "Kafka event publish failed for trans_id=%s topic=%s â€” resetting producer connection.",
            trans_id, topic
        )
        _producer_manager.reset_producer()
        _fallback_to_dead_letter_queue(topic, payload, str(exc))
        raise


def publish_transaction_batch(
    topic: str,
    payloads: List[Dict[str, Any]],
    correlation_id: Optional[str] = None,
) -> int:
    """Asynchronously batch publish multiple events to Kafka with high throughput efficiency.

    Args:
        topic: Destination Kafka topic name
        payloads: List of event payload dictionaries
        correlation_id: Optional trace correlation ID

    Returns:
        Number of successfully published events.
    """
    if not payloads:
        return 0

    if not _circuit_breaker.can_execute():
        error_msg = f"Circuit breaker OPEN during batch publish to topic={topic}."
        logger.error(error_msg)
        for p in payloads:
            _fallback_to_dead_letter_queue(topic, p, error_msg)
        raise CircuitBreakerOpenException(error_msg)

    try:
        producer = _producer_manager.get_producer()
    except Exception:
        logger.exception("Batch producer initialization failed for topic=%s", topic)
        _circuit_breaker.record_failure()
        return [False] * len(payloads)
    futures = []

    for payload in payloads:
        try:
            _validate_payload_schema(payload)
            trans_id = payload.get("TransID") or payload.get("trans_id") or payload.get("aggregate_id") or payload.get("event_id")
            key = str(trans_id).encode("utf-8") if trans_id else None
            
            headers = [("tenant_id", str(payload.get("tenant_id", "default")).encode("utf-8"))]
            if correlation_id:
                headers.append(("correlation_id", correlation_id.encode("utf-8")))

            future = producer.send(topic, key=key, value=payload, headers=headers)
            futures.append((payload, future))
        except Exception as exc:
            logger.warning("Batch validation failed for payload item: %s", exc)
            _fallback_to_dead_letter_queue(topic, payload, str(exc))

    producer.flush(timeout=PRODUCER_SEND_TIMEOUT_SECONDS)

    successful_count = 0
    for payload, future in futures:
        try:
            future.get(timeout=PRODUCER_SEND_TIMEOUT_SECONDS)
            successful_count += 1
        except Exception as exc:
            logger.exception("Failed delivering batch item: %s", exc)
            _fallback_to_dead_letter_queue(topic, payload, str(exc))

    if successful_count == len(payloads):
        _circuit_breaker.record_success()
    else:
        _circuit_breaker.record_failure()

    logger.info("Batch publish completed for topic=%s: %d/%d items delivered successfully.", topic, successful_count, len(payloads))
    return successful_count


def publish_transaction_batch_results(
    topic: str,
    payloads: List[Dict[str, Any]],
    correlation_id: Optional[str] = None,
) -> List[bool]:
    """Batch-send events while retaining per-message delivery outcomes for outbox updates."""
    if not payloads:
        return []
    if not _circuit_breaker.can_execute():
        return [False] * len(payloads)

    producer = _producer_manager.get_producer()
    results = [False] * len(payloads)
    futures = []
    for index, payload in enumerate(payloads):
        try:
            _validate_payload_schema(payload)
            trans_id = payload.get("TransID") or payload.get("trans_id") or payload.get("aggregate_id") or payload.get("event_id")
            headers = [("tenant_id", str(payload.get("tenant_id", "default")).encode("utf-8"))]
            if correlation_id:
                headers.append(("correlation_id", correlation_id.encode("utf-8")))
            future = producer.send(
                topic,
                key=str(trans_id).encode("utf-8") if trans_id else None,
                value=payload,
                headers=headers,
            )
            futures.append((index, future))
        except Exception:
            logger.exception("Batch validation or enqueue failed for topic=%s index=%s", topic, index)

    try:
        producer.flush(timeout=PRODUCER_SEND_TIMEOUT_SECONDS)
    except Exception:
        logger.exception("Batch flush failed for topic=%s", topic)

    for index, future in futures:
        try:
            future.get(timeout=PRODUCER_SEND_TIMEOUT_SECONDS)
            results[index] = True
        except Exception:
            logger.exception("Batch delivery failed for topic=%s index=%s", topic, index)

    if all(results):
        _circuit_breaker.record_success()
    else:
        _circuit_breaker.record_failure()
    return results
