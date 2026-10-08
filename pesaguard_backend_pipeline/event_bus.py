"""Versioned event contracts and delivery controls for Phase 4 processing."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Optional

from contract_versioning import validate_contract_version

EVENT_TYPES = frozenset({
    "transaction.created",
    "transaction.received",
    "transaction.validated",
    "transaction.normalized",
    "transaction.enriched",
    "transaction.processed",
    "transaction.reconciled",
    "transaction.exception_created",
    "transaction.fraud_detected",
    "reconciliation.requested",
    "reconciliation.completed",
    "reconciliation.exception",
    "fraud.analysis_requested",
    "fraud.anomaly_detected",
    "fraud.decision_created",
    "notification.requested",
    "notification.sent",
    "notification.failed",
    "webhook.received",
    "batch_import.received",
    "batch_import.completed",
    "batch_import.failed",
    "event.retry_scheduled",
    "system.event",
    "data_processing.event",
    "transaction.rejected",
    "transaction.completed",
    "transaction.failed",
    "reconciliation.requested",
    "reconciliation.started",
    "reconciliation.failed",
    "reconciliation.exception.detected",
    "reconciliation.exception.resolved",
    "fraud.analysis.requested",
    "fraud.analysis.started",
    "fraud.analysis.completed",
    "fraud.anomaly.detected",
    "fraud.anomaly.reviewed",
    "notification.retry",
    "notification.exhausted",
    "batch.import.started",
    "batch.import.completed",
    "batch.import.failed",
    "batch.record.rejected",
    "audit.event.created",
})
EVENT_VERSION = 1
logger = logging.getLogger("pesaguard.event_bus")


class ConsumerLagRegistry:
    """Process-local lag registry used by consumers and Prometheus scraping."""

    def __init__(self) -> None:
        self._values: Dict[str, Dict[int, int]] = {}
        self._lock = threading.Lock()

    def update(self, group: str, partition_lags: Dict[int, int]) -> None:
        with self._lock:
            self._values[group] = dict(partition_lags)

    def snapshot(self) -> Dict[str, Dict[int, int]]:
        with self._lock:
            return {group: dict(values) for group, values in self._values.items()}


consumer_lag_registry = ConsumerLagRegistry()


def _partition_lag_key(topic: str, partition: int) -> str:
    """Composite partition identity so lag from multiple topics never collides."""
    return f"{topic}:{partition}"


def query_broker_lag(
    bootstrap_servers: str,
    topics: Iterable[str],
    groups: Iterable[str],
    *,
    timeout_ms: int = 2000,
) -> Dict[str, Dict[str, int]]:
    """Read consumer-group lag exclusively from Kafka broker offsets.

    For every ``group x topic`` pair the committed offset is read through
    ``KafkaConsumer.committed`` and subtracted from ``end_offsets`` so lag is
    broker-derived rather than approximated from in-process snapshots.
    """
    from kafka import KafkaConsumer, TopicPartition

    consumer = KafkaConsumer(
        bootstrap_servers=str(bootstrap_servers).split(","),
        enable_auto_commit=False,
        request_timeout_ms=int(timeout_ms),
        consumer_timeout_ms=int(timeout_ms),
    )
    result: Dict[str, Dict[str, int]] = {}
    try:
        for group in groups:
            group_lags: Dict[str, int] = {}
            for topic in topics:
                partitions = consumer.partitions_for_topic(topic) or set()
                topic_partitions = [TopicPartition(topic, partition) for partition in partitions]
                if not topic_partitions:
                    continue
                end_offsets = consumer.end_offsets(topic_partitions)
                for partition in topic_partitions:
                    committed = consumer.committed(partition)
                    group_lags[_partition_lag_key(topic, partition.partition)] = max(
                        0, int(end_offsets.get(partition, 0)) - int(committed or 0)
                    )
            if group_lags:
                result[group] = group_lags
        return result
    finally:
        consumer.close()


def admin_client_lag(
    bootstrap_servers: str,
    topics: Iterable[str],
    groups: Iterable[str],
    *,
    timeout_ms: int = 2000,
) -> Optional[Dict[str, Dict[str, int]]]:
    """Read committed consumer-group offsets through KafkaAdminClient.

    Returns ``None`` when the broker does not support the administrative
    offset-reporting call so callers can fall back to :func:`query_broker_lag`.
    """
    try:
        from kafka import KafkaConsumer, TopicPartition
        from kafka.admin import KafkaAdminClient
        from kafka.structs import OffsetAndMetadata
    except ImportError:
        return None

    consumer = KafkaConsumer(
        bootstrap_servers=str(bootstrap_servers).split(","),
        enable_auto_commit=False,
        request_timeout_ms=int(timeout_ms),
        consumer_timeout_ms=int(timeout_ms),
    )
    result: Dict[str, Dict[str, int]] = {}
    try:
        admin = KafkaAdminClient(
            bootstrap_servers=str(bootstrap_servers).split(","),
            client_id="pesaguard-lag-poll",
            request_timeout_ms=int(timeout_ms),
        )
        try:
            for group in groups:
                committed_map = admin.list_consumer_group_offsets(group_id=group) or {}
                group_lags: Dict[str, int] = {}
                for topic in topics:
                    partitions = consumer.partitions_for_topic(topic) or set()
                    topic_partitions = [TopicPartition(topic, partition) for partition in partitions]
                    if not topic_partitions:
                        continue
                    end_offsets = consumer.end_offsets(topic_partitions)
                    for partition in topic_partitions:
                        offset_meta = committed_map.get(partition)
                        if isinstance(offset_meta, OffsetAndMetadata):
                            committed = int(offset_meta.offset or 0)
                        elif isinstance(offset_meta, dict):
                            committed = int(offset_meta.get("offset", 0) or 0)
                        elif offset_meta is None:
                            committed = consumer.committed(partition) or 0
                        else:
                            committed = 0
                        group_lags[_partition_lag_key(topic, partition.partition)] = max(
                            0, int(end_offsets.get(partition, 0)) - committed
                        )
                if group_lags:
                    result[group] = group_lags
        finally:
            admin.close()
        return result
    except Exception:
        logger.debug("AdminClient consumer-group lag query failed; caller may fall back.", exc_info=True)
        return None
    finally:
        consumer.close()


def queue_depth(
    bootstrap_servers: str,
    topics: Iterable[str],
    *,
    timeout_ms: int = 2000,
) -> Dict[str, int]:
    """Return the broker-side queue depth (sum of end offsets) per topic.

    Queue depth measures how many messages are present on a topic regardless of
    consumer progress: ``sum(end_offsets - start_offsets)``.
    """
    from kafka import KafkaConsumer, TopicPartition

    consumer = KafkaConsumer(
        bootstrap_servers=str(bootstrap_servers).split(","),
        enable_auto_commit=False,
        request_timeout_ms=int(timeout_ms),
        consumer_timeout_ms=int(timeout_ms),
    )
    result: Dict[str, int] = {}
    try:
        for topic in topics:
            partitions = consumer.partitions_for_topic(topic) or set()
            topic_partitions = [TopicPartition(topic, partition) for partition in partitions]
            if not topic_partitions:
                continue
            end_offsets = consumer.end_offsets(topic_partitions)
            start_offsets = consumer.start_offsets(topic_partitions)
            depth = 0
            for partition in topic_partitions:
                start = int(start_offsets.get(partition, 0))
                end = int(end_offsets.get(partition, 0))
                depth += max(0, end - start)
            result[topic] = depth
        return result
    finally:
        consumer.close()
def broker_consumer_lag() -> Dict[str, Dict[str, int]]:
    """Read consumer-group lag from Kafka committed and end offsets.

    Broker collection is opt-in so a metrics scrape cannot make local or test
    deployments fail when Kafka is intentionally absent. The AdminClient path is
    preferred because committed offsets are authoritative; the consumer path is
    the fallback that works on every kafka-python-ng deployment.

    When no Kafka environment is configured, the registry snapshot in
    ``consumer_lag_registry`` is the only available lag source and it reflects
    the last consumer snapshot, not broker offsets.
    """
    import os

    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS")
    topics = [topic.strip() for topic in os.getenv("KAFKA_LAG_TOPICS", "").split(",") if topic.strip()]
    groups = [group.strip() for group in os.getenv("KAFKA_LAG_GROUPS", "").split(",") if group.strip()]
    if not bootstrap_servers or not topics or not groups:
        return {}
    timeout_ms = int(os.getenv("KAFKA_LAG_REQUEST_TIMEOUT_MS", "2000"))
    try:
        admin_result = admin_client_lag(bootstrap_servers, topics, groups, timeout_ms=timeout_ms)
        if admin_result:
            return admin_result
    except Exception:
        logger.debug("Kafka AdminClient lag query unavailable; falling back to KafkaConsumer.", exc_info=True)
    try:
        return query_broker_lag(bootstrap_servers, topics, groups, timeout_ms=timeout_ms)
    except Exception:
        return {}


class EventContractError(ValueError):
    """Raised when an event violates the versioned contract."""


@dataclass(frozen=True)
class EventEnvelope:
    event_id: str
    event_type: str
    event_version: int
    occurred_at: str
    tenant_id: str
    aggregate_id: str
    payload: Dict[str, Any]
    correlation_id: str
    request_id: str = ""
    attempt: int = 1
    max_attempts: int = 3
    schema_version: str = "1.0"
    source: str = "pesaguard"
    source_event_id: str = ""
    causation_id: str = ""
    producer: str = "pesaguard"
    producer_version: str = "1"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def timestamp(self) -> str:
        """Canonical timestamp name exposed to external event consumers."""
        return self.occurred_at

    def __post_init__(self) -> None:
        if not self.event_id or not self.event_type or self.event_type not in EVENT_TYPES:
            raise EventContractError("event_id and a supported event_type are required")
        if self.event_version != EVENT_VERSION:
            raise EventContractError(f"unsupported event version: {self.event_version}")
        if not self.tenant_id or not self.aggregate_id or not self.correlation_id:
            raise EventContractError("tenant_id, aggregate_id, and correlation_id are required")
        if not self.schema_version or not self.source or not self.producer:
            raise EventContractError("schema_version, source, and producer are required")
        try:
            validate_contract_version("event", self.schema_version)
        except ValueError as exc:
            raise EventContractError(str(exc)) from exc
        if not isinstance(self.payload, dict):
            raise EventContractError("payload must be an object")
        if not isinstance(self.metadata, dict):
            raise EventContractError("metadata must be an object")
        if not 1 <= self.attempt <= self.max_attempts:
            raise EventContractError("attempt must be within max_attempts")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "event_version": self.event_version,
            "occurred_at": self.occurred_at,
            "timestamp": self.occurred_at,
            "tenant_id": self.tenant_id,
            "aggregate_id": self.aggregate_id,
            "payload": self.payload,
            "correlation_id": self.correlation_id,
            "request_id": self.request_id,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "schema_version": self.schema_version,
            "source": self.source,
            "source_event_id": self.source_event_id,
            "causation_id": self.causation_id,
            "producer": self.producer,
            "producer_version": self.producer_version,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "EventEnvelope":
        try:
            fields = {
                "event_id", "event_type", "event_version", "occurred_at", "tenant_id", "aggregate_id",
                "payload", "correlation_id", "request_id", "attempt", "max_attempts", "schema_version",
                "source", "source_event_id", "causation_id", "producer", "producer_version", "metadata",
            }
            event_data = {key: value[key] for key in fields if key in value}
            if "occurred_at" not in event_data and value.get("timestamp"):
                event_data["occurred_at"] = value["timestamp"]
            return cls(**event_data)
        except TypeError as exc:
            raise EventContractError(f"invalid event envelope: {exc}") from exc

    def retry(self) -> "EventEnvelope":
        if self.attempt >= self.max_attempts:
            raise EventContractError("event has exhausted retry attempts")
        return EventEnvelope.from_dict({**self.to_dict(), "attempt": self.attempt + 1})


def validate_event(value: EventEnvelope | Dict[str, Any]) -> EventEnvelope:
    """Validate and materialize one first-class event contract."""
    if isinstance(value, EventEnvelope):
        return value
    if not isinstance(value, dict):
        raise EventContractError("event must be an envelope or object")
    try:
        from schema_validation import validate_event_envelope
        schema_value = dict(value)
        if "occurred_at" not in schema_value and schema_value.get("timestamp"):
            schema_value["occurred_at"] = schema_value["timestamp"]
        validate_event_envelope(schema_value)
        return EventEnvelope.from_dict(value)
    except ValueError as exc:
        raise EventContractError(str(exc)) from exc


def build_event(
    event_type: str,
    tenant_id: str,
    aggregate_id: str,
    payload: Dict[str, Any],
    *,
    correlation_id: Optional[str] = None,
    event_id: Optional[str] = None,
    source: str = "pesaguard",
    source_event_id: str = "",
    causation_id: str = "",
    producer: str = "pesaguard",
    producer_version: str = "1",
    schema_version: str = "1.0",
    metadata: Optional[Dict[str, Any]] = None,
) -> EventEnvelope:
    """Build a deterministic-contract event with a unique delivery identity."""
    from logging_utils import get_observability_context
    return EventEnvelope(
        event_id=event_id or f"evt_{uuid.uuid4().hex}",
        event_type=event_type,
        event_version=EVENT_VERSION,
        occurred_at=datetime.now(timezone.utc).isoformat(),
        tenant_id=tenant_id,
        aggregate_id=aggregate_id,
        payload=payload,
        correlation_id=correlation_id or uuid.uuid4().hex,
        request_id=get_observability_context().get("request_id", ""),
        schema_version=schema_version,
        source=source,
        source_event_id=source_event_id,
        causation_id=causation_id,
        producer=producer,
        producer_version=producer_version,
        metadata=dict(metadata or {}),
    )


@dataclass(frozen=True)
class RetryTask:
    event: EventEnvelope
    available_at: float
    reason: str


@dataclass(frozen=True)
class DeadLetterEvent:
    event: EventEnvelope
    reason: str
    failed_at: str


@dataclass(frozen=True)
class DeliveryResult:
    status: str
    event_id: str
    attempt: int
    retry_at: Optional[float] = None
    reason: Optional[str] = None


class RetryPolicy:
    """Bounded exponential backoff: Attempt 1 -> Attempt 2 -> Attempt 3 -> DLQ."""

    def __init__(self, max_attempts: int = 3, base_delay_seconds: float = 1.0, max_delay_seconds: float = 60.0):
        self.max_attempts = max(1, max_attempts)
        self.base_delay_seconds = max(0.001, base_delay_seconds)
        self.max_delay_seconds = max(self.base_delay_seconds, max_delay_seconds)

    def delay(self, attempt: int) -> float:
        return min(self.max_delay_seconds, self.base_delay_seconds * (2 ** max(0, attempt - 1)))


class BackpressureGate:
    """Bound in-flight work and reject polling when consumer lag exceeds a limit."""

    def __init__(self, max_in_flight: int = 100, max_lag: int = 10_000):
        self.max_in_flight = max(1, max_in_flight)
        self.max_lag = max(1, max_lag)
        self._semaphore = threading.BoundedSemaphore(self.max_in_flight)

    def acquire(self, lag: int = 0, timeout: float = 0.0) -> bool:
        if lag > self.max_lag:
            return False
        return self._semaphore.acquire(timeout=timeout)

    def release(self) -> None:
        self._semaphore.release()


class EventDeliveryController:
    """Idempotent consumer delivery with retry, DLQ, replay, and backpressure."""

    def __init__(self, *, retry_policy: Optional[RetryPolicy] = None, max_in_flight: int = 100, max_lag: int = 10_000):
        self.retry_policy = retry_policy or RetryPolicy()
        self.backpressure = BackpressureGate(max_in_flight=max_in_flight, max_lag=max_lag)
        self.retry_queue: list[RetryTask] = []
        self.dlq: list[DeadLetterEvent] = []
        self._completed: set[str] = set()
        self._lock = threading.Lock()
        self._state_client = None
        state_url = os.getenv("PESAGUARD_EVENT_STATE_REDIS_URL", "").strip()
        environment = os.getenv("PESAGUARD_ENVIRONMENT", "development").lower()
        if state_url:
            try:
                import redis
                self._state_client = redis.from_url(state_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
                self._state_client.ping()
                self._load_durable_state()
            except Exception as exc:
                if environment in {"production", "prod"}:
                    raise RuntimeError("PESAGUARD_EVENT_STATE_REDIS_URL is unavailable") from exc
                logger.warning("Event delivery state is using process-local fallback: %s", exc)
                self._state_client = None
        elif environment in {"production", "prod"}:
            raise RuntimeError("PESAGUARD_EVENT_STATE_REDIS_URL is required in production")

    @property
    def _state_prefix(self) -> str:
        return os.getenv("PESAGUARD_EVENT_STATE_PREFIX", "pesaguard:event-delivery")

    def _load_durable_state(self) -> None:
        if self._state_client is None:
            return
        self._completed.update(self._state_client.smembers(f"{self._state_prefix}:completed"))
        for encoded in self._state_client.lrange(f"{self._state_prefix}:retries", 0, -1):
            value = json.loads(encoded)
            self.retry_queue.append(RetryTask(EventEnvelope.from_dict(value["event"]), value["available_at"], value["reason"]))
        for encoded in self._state_client.lrange(f"{self._state_prefix}:dlq", 0, -1):
            value = json.loads(encoded)
            self.dlq.append(DeadLetterEvent(EventEnvelope.from_dict(value["event"]), value["reason"], value["failed_at"]))

    def _persist_retry(self, task: RetryTask) -> None:
        if self._state_client is not None:
            self._state_client.rpush(f"{self._state_prefix}:retries", json.dumps({"event": task.event.to_dict(), "available_at": task.available_at, "reason": task.reason}))

    def _persist_dead_letter(self, entry: DeadLetterEvent) -> None:
        if self._state_client is not None:
            self._state_client.rpush(f"{self._state_prefix}:dlq", json.dumps({"event": entry.event.to_dict(), "reason": entry.reason, "failed_at": entry.failed_at}))

    def deliver(self, event: EventEnvelope, handler: Callable[[EventEnvelope], Any], *, lag: int = 0, now: Optional[float] = None, traceparent: Optional[str] = None) -> DeliveryResult:
        from logging_utils import bind_observability_context
        from observability import trace_span
        bind_observability_context(
            correlation_id=event.correlation_id,
            transaction_id=event.aggregate_id,
            event_id=event.event_id,
            request_id=event.request_id,
            tenant_id=event.tenant_id,
        )
        if not self.backpressure.acquire(lag=lag):
            return DeliveryResult("backpressured", event.event_id, event.attempt, reason="consumer_lag_or_inflight_limit")
        try:
            with self._lock:
                if event.event_id in self._completed:
                    return DeliveryResult("duplicate", event.event_id, event.attempt)
            try:
                span_kwargs = {"event_type": event.event_type, "attempt": event.attempt}
                if traceparent:
                    span_kwargs["traceparent"] = traceparent
                with trace_span("event.consume", **span_kwargs):
                    handler(event)
            except Exception as exc:
                reason = str(exc)[:1000]
                from metrics import record_business_metric
                if event.event_type.startswith("transaction.fraud"):
                    record_business_metric("fraud_engine_failures")
                if event.event_type.startswith("transaction.recon") or event.event_type == "transaction.exception_created":
                    record_business_metric("reconciliation_failures")
                if event.attempt >= self.retry_policy.max_attempts:
                    from metrics import record_business_metric
                    record_business_metric("dlq_events")
                    dead_letter = DeadLetterEvent(event, reason, datetime.now(timezone.utc).isoformat())
                    with self._lock:
                        self.dlq.append(dead_letter)
                        self._persist_dead_letter(dead_letter)
                    return DeliveryResult("dead_lettered", event.event_id, event.attempt, reason=reason)
                retry_event = event.retry()
                from metrics import record_event_retry
                record_event_retry()
                retry_at = (now if now is not None else time.time()) + self.retry_policy.delay(event.attempt)
                with self._lock:
                    retry_task = RetryTask(retry_event, retry_at, reason)
                    self.retry_queue.append(retry_task)
                    self._persist_retry(retry_task)
                return DeliveryResult("retry_scheduled", event.event_id, event.attempt, retry_at=retry_at, reason=reason)
            with self._lock:
                self._completed.add(event.event_id)
                if self._state_client is not None:
                    self._state_client.sadd(f"{self._state_prefix}:completed", event.event_id)
            return DeliveryResult("processed", event.event_id, event.attempt)
        finally:
            self.backpressure.release()

    def replay(self, dead_letter: DeadLetterEvent, handler: Callable[[EventEnvelope], Any], *, lag: int = 0) -> DeliveryResult:
        """Replay a DLQ event from attempt one without changing its event identity."""
        replay_event = EventEnvelope.from_dict({**dead_letter.event.to_dict(), "attempt": 1})
        result = self.deliver(replay_event, handler, lag=lag)
        if result.status == "backpressured":
            return result

        with self._lock:
            self.dlq = [entry for entry in self.dlq if entry is not dead_letter]
            if self._state_client is not None:
                key = f"{self._state_prefix}:dlq"
                self._state_client.delete(key)
                for entry in self.dlq:
                    self._persist_dead_letter(entry)
        return result

    def due_retries(self, now: Optional[float] = None) -> list[RetryTask]:
        current = time.time() if now is None else now
        with self._lock:
            due = [task for task in self.retry_queue if task.available_at <= current]
            self.retry_queue = [task for task in self.retry_queue if task.available_at > current]
            if self._state_client is not None:
                key = f"{self._state_prefix}:retries"
                self._state_client.delete(key)
                for task in self.retry_queue:
                    self._persist_retry(task)
        return due

    def lag_snapshot(self, *, partition_lags: Dict[int, int]) -> Dict[str, Any]:
        values = list(partition_lags.values())
        return {
            "partitions": len(values),
            "total_lag": sum(values),
            "max_partition_lag": max(values, default=0),
            "backpressured": sum(values) > self.backpressure.max_lag,
        }


def event_fingerprint(event: EventEnvelope) -> str:
    """Stable hash for audit, replay, and duplicate diagnostics."""
    encoded = json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
