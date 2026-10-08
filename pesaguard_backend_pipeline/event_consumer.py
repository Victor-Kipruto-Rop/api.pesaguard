"""Consumer-group dispatch controls for versioned PesaGuard events."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional

from event_bus import DeliveryResult, EventContractError, EventDeliveryController, EventEnvelope, validate_event


@dataclass(frozen=True)
class ConsumerGroup:
    name: str
    event_types: frozenset[str]


class EventConsumer:
    """Dispatch versioned events to a named consumer group."""

    def __init__(self, group: ConsumerGroup, *, controller: Optional[EventDeliveryController] = None):
        self.group = group
        self.controller = controller or EventDeliveryController()
        self.handlers: Dict[str, Callable[[EventEnvelope], Any]] = {}
        self.processed_by_type: Dict[str, int] = defaultdict(int)

    def register(self, event_type: str, handler: Callable[[EventEnvelope], Any]) -> None:
        if event_type not in self.group.event_types:
            raise ValueError(f"event type {event_type!r} is not assigned to group {self.group.name!r}")
        self.handlers[event_type] = handler

    def consume(self, event: EventEnvelope | Dict[str, Any], *, lag: int = 0, traceparent: Optional[str] = None) -> DeliveryResult:
        try:
            event = validate_event(event)
        except EventContractError as exc:
            event_id = str(event.get("event_id") or "invalid-event") if isinstance(event, dict) else "invalid-event"
            return DeliveryResult("dead_lettered", event_id, 1, reason=f"schema_validation_failed: {exc}")
        if event.event_type not in self.group.event_types:
            return DeliveryResult("ignored", event.event_id, event.attempt, reason="event_not_assigned_to_group")
        handler = self.handlers.get(event.event_type)
        if handler is None:
            return DeliveryResult("dead_lettered", event.event_id, event.attempt, reason="no_handler_registered")
        result = self.controller.deliver(event, handler, lag=lag, traceparent=traceparent)
        if result.status == "processed":
            self.processed_by_type[event.event_type] += 1
            from metrics import record_business_metric
            metric_name = event.event_type.replace(".", "_")
            record_business_metric(metric_name)
        return result

    def replay_dead_letters(self, *, limit: int = 100) -> list[DeliveryResult]:
        results = []
        for dead_letter in list(self.controller.dlq)[:max(0, limit)]:
            handler = self.handlers.get(dead_letter.event.event_type)
            if handler is None:
                results.append(DeliveryResult(
                    "dead_lettered",
                    dead_letter.event.event_id,
                    dead_letter.event.attempt,
                    reason="no_handler_registered",
                ))
                continue
            results.append(self.controller.replay(dead_letter, handler))
        return results

    def lag_snapshot(self, partition_lags: Dict[int, int]) -> Dict[str, Any]:
        from event_bus import consumer_lag_registry
        consumer_lag_registry.update(self.group.name, partition_lags)
        snapshot = self.controller.lag_snapshot(partition_lags=partition_lags)
        snapshot["consumer_group"] = self.group.name
        return snapshot


def validate_no_consumer_conflicts(
    groups: Iterable[ConsumerGroup],
    *,
    event_type_topics: Optional[Dict[str, str]] = None,
) -> None:
    """Raise ValueError when two consumer groups collide on a topic or handler.

    Confusions that are illegal:
      * Two groups subscribing to the same Kafka topic (same group_id-like semantics
        for the same physical topic) — this produces duplicated processing unless
        the topic is partitioned and groups are intentionally distinct, which we do
        not permit implicitly.
      * Two groups claiming the same event_type with the same handler signature
        (evil-twin handlers) — the same logical work would be performed by two
        unrelated groups.
    """
    event_type_topics = event_type_topics or {}
    topic_to_groups: Dict[str, list[str]] = defaultdict(list)
    type_to_handlers: Dict[str, list[tuple[str, str]]] = defaultdict(list)

    for group in groups:
        topic = event_type_topics.get(group.name)
        if topic is None:
            continue
        topic_to_groups[topic].append(group.name)
        # In the generic case handlers are registered individually; conflicts
        # are asserted at registration time instead. We only detect structural
        # duplicates here:
        for event_type in group.event_types:
            type_to_handlers[event_type].append((group.name, event_type))

    # Structural topic collisions
    collisions: list[tuple[str, list[str]]] = [
        (topic, names) for topic, names in topic_to_groups.items() if len(names) > 1
    ]
    if collisions:
        raise ValueError(
            "consumer groups share Kafka topics: " +
            "; ".join(f"{topic} -> {names}" for topic, names in collisions)
        )

    # Structural event-type overlaps between groups
    overlaps: list[tuple[str, list[str]]] = [
        (et, names) for et, names in type_to_handlers.items() if len(names) > 1
    ]
    if overlaps:
        raise ValueError(
            "event types are claimed by multiple consumer groups: " +
            "; ".join(f"{et} -> {names}" for et, names in overlaps)
        )


def default_consumer_groups() -> tuple[ConsumerGroup, ...]:
    return (
        ConsumerGroup("transaction-validation", frozenset({"transaction.received"})),
        ConsumerGroup("transaction-normalization", frozenset({"transaction.validated"})),
        ConsumerGroup("transaction-processors", frozenset({"transaction.normalized"})),
        ConsumerGroup(
            "fraud",
            frozenset(
                {
                    "transaction.received",
                    "transaction.validated",
                    "transaction.fraud_detected",
                    "fraud.analysis.completed",
                    "fraud.anomaly_detected",
                    "fraud.decision_created",
                    "fraud.anomaly.reviewed",
                }
            ),
        ),
        ConsumerGroup("audit", frozenset({"transaction.received", "transaction.validated", "transaction.normalized", "transaction.processed", "transaction.reconciled", "transaction.exception_created", "transaction.fraud_detected", "notification.requested", "audit.event.created"})),
        ConsumerGroup("alerts", frozenset({"transaction.exception_created", "transaction.fraud_detected", "notification.requested"})),
    )
