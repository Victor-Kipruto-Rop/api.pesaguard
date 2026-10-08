"""Versioned audit publication reusing the existing durable audit boundary.

``persist_audit_event`` already stages an append-only ``ActionAuditEntry`` plus a
durable ``AuditOutboxEntry`` atomically. `deliver_audit_outbox` already drains
those entries with leases, retries, and dead-letter handling. This module only
adds a Kafka dispatcher for that existing drain, mapping each claimed outbox row
to the registered `audit.event.created` contract.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Mapping

logger = logging.getLogger("pesaguard.audit_events")


def kafka_audit_dispatcher(publisher: Callable[..., Any]) -> Callable[[Mapping[str, Any]], Any]:
    """Return a `deliver_audit_outbox`-compatible dispatcher for Kafka."""
    from event_bus import build_event
    from producer import publish_versioned_event

    def dispatch(entry_payload: Mapping[str, Any]) -> Any:
        payload = dict(entry_payload or {})
        event_type = str(payload.pop("event_type", "") or "audit.event.created")
        tenant_id = str(payload.get("tenant_id") or payload.pop("tenant_id", "") or "")
        aggregate_id = str(
            payload.get("audit_id")
            or payload.get("id")
            or payload.get("idempotency_key")
            or "audit"
        )
        event = build_event(
            event_type,
            tenant_id,
            aggregate_id,
            payload,
            correlation_id=payload.get("correlation_id"),
            producer="pesaguard.audit_events",
            producer_version="1",
        )
        return publish_versioned_event(event, producer=publisher)

    return dispatch


def deliver_audit_events_to_kafka(
    session: Any,
    publisher: Callable[..., Any],
    *,
    batch_size: int = 100,
    tenant_id: str | None = None,
    worker_id: str = "audit-worker",
) -> dict[str, int]:
    """Drain claimed audit outbox rows onto Kafka through the existing lease flow."""
    from action_audit import deliver_audit_outbox

    return deliver_audit_outbox(
        session,
        kafka_audit_dispatcher(publisher),
        batch_size=batch_size,
        tenant_id=tenant_id,
        worker_id=worker_id,
    )
