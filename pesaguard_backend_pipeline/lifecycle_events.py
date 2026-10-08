"""Durable lifecycle-event emission for transaction state changes.

The authoritative transaction lifecycle lives in PostgreSQL
(``EventStore.transition_transaction``). These helpers wrap that transition so a
versioned Kafka lifecycle event is emitted only after the database transition
commits. Emission itself stays best-effort and outbox-backed: if the broker is
unavailable, callers receive a pending publication record and can drain it later
through ``drain_lifecycle_events``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Optional

from lifecycle import TRANSACTION_TRANSITIONS

STATE_TO_EVENT = {
    "FAILED": "transaction.failed",
    "REJECTED": "transaction.rejected",
}

STATE_TO_TOPIC_ENV = {
    "FAILED": ("PESAGUARD_TOPIC_TRANSACTIONS_FAILED", "pesaguard.transactions.failed"),
    "REJECTED": ("PESAGUARD_TOPIC_TRANSACTIONS_REJECTED", "pesaguard.transactions.rejected"),
}


@dataclass(frozen=True)
class LifecyclePublication:
    """Durable-but-undelivered lifecycle event awaiting Kafka emission."""

    event_type: str
    tenant_id: str
    transaction_id: str
    event: Any
    topic: str


def pending_lifecycle_event(
    target: str,
    tenant_id: str,
    transaction_id: str,
    *,
    correlation_id: str | None = None,
) -> LifecyclePublication:
    """Build the lifecycle event for a transaction state target.

    Only terminal states that own dedicated Kafka topics are emitted here.
    ``transaction.completed`` is intentionally not emitted: the completed
    contract is published by the reconciliation path once a match is durable.
    """
    from event_bus import build_event

    if target not in STATE_TO_EVENT:
        raise ValueError(f"no lifecycle event is defined for transaction state {target!r}")
    if target not in TRANSACTION_TRANSITIONS or target in {"RECONCILED"}:
        raise ValueError(f"unsupported transaction lifecycle target: {target!r}")
    event_type = STATE_TO_EVENT[target]
    env_name, default_topic = STATE_TO_TOPIC_ENV[target]
    topic = os.getenv(env_name, default_topic)
    event = build_event(
        event_type,
        tenant_id,
        transaction_id,
        {"transaction_id": transaction_id, "state": target},
        correlation_id=correlation_id,
        producer="pesaguard.lifecycle_emitter",
        producer_version="1",
    )
    return LifecyclePublication(
        event_type=event_type,
        tenant_id=tenant_id,
        transaction_id=transaction_id,
        event=event,
        topic=topic,
    )


def transition_and_stage_lifecycle_event(
    store: Any,
    trans_id: str,
    target: str,
    tenant_id: str,
    expected_version: int,
    *,
    actor: str = "system",
    reason: Optional[str] = None,
    correlation_id: str | None = None,
) -> tuple[bool, LifecyclePublication | None]:
    """Advance PostgreSQL first, then return a staged event only on commit.

    Returns ``(transitioned, publication)`` where ``publication`` is None when no
    Kafka lifecycle event exists for ``target``. Kafka emission is callers'
    responsibility so that retries use ``drain_lifecycle_events`` rather than
    repeating the financial state change.
    """
    from event_store import ProcessResult  # noqa: F401  (documented side effect only)

    transitioned = store.transition_transaction(
        trans_id, target, tenant_id, expected_version, actor=actor, reason=reason
    )
    if not transitioned:
        return False, None
    if target not in STATE_TO_EVENT:
        return True, None
    return True, pending_lifecycle_event(
        target, tenant_id, trans_id, correlation_id=correlation_id
    )


def drain_lifecycle_events(publications: list[LifecyclePublication], publisher: Callable[..., Any]) -> dict[str, int]:
    """Publish staged lifecycle events. Pure delivery; never mutates finance state."""
    published = 0
    failed = 0
    for publication in list(publications):
        try:
            from producer import publish_versioned_event

            publish_versioned_event(publication.event, producer=publisher)
            published += 1
        except Exception:
            failed += 1
    return {"published": published, "failed": failed, "total": len(publications)}
