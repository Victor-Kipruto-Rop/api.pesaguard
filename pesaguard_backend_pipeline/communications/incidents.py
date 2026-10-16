"""Communication incident management.

Incidents are created automatically from real signals (provider degradation,
SLA breaches, anomalies) and deduplicated by fingerprint so that hundreds of
identical failures aggregate into one incident with an occurrence counter.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from sqlalchemy.orm import Session

from .models import CommunicationIncident, CommunicationOutboxEntry

SEVERITIES = frozenset({"low", "medium", "high", "critical"})
INCIDENT_STATUSES = ("open", "investigating", "mitigated", "resolved")
_STATUS_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"investigating", "mitigated", "resolved"}),
    "investigating": frozenset({"mitigated", "resolved", "open"}),
    "mitigated": frozenset({"resolved", "open"}),
    "resolved": frozenset({"open"}),
}


class InvalidIncidentTransition(ValueError):
    pass


def _cooldown_minutes() -> int:
    try:
        return max(1, int(os.getenv("PESAGUARD_COMMUNICATION_ALERT_COOLDOWN_MINUTES", "30")))
    except ValueError:
        return 30


def _next_reference() -> str:
    return f"PG-INC-{uuid.uuid4().int % 100000:05d}"


def report_incident(
    session: Session,
    *,
    category: str,
    title: str,
    fingerprint: str,
    severity: str = "medium",
    tenant_id: str | None = None,
    metrics: Mapping[str, Any] | None = None,
    summary: str | None = None,
    affected_count: int = 0,
    now: datetime | None = None,
) -> CommunicationIncident:
    """Create an incident or aggregate into an existing open one.

    Deduplication: an incident with the same fingerprint that is still open and
    was last seen within the cooldown window absorbs the new occurrence.
    """
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {sorted(SEVERITIES)}")
    now = now or datetime.now(timezone.utc)
    cooldown_start = now - timedelta(minutes=_cooldown_minutes())
    existing = (
        session.query(CommunicationIncident)
        .filter(
            CommunicationIncident.fingerprint == fingerprint,
            CommunicationIncident.status.in_(("open", "investigating", "mitigated")),
            CommunicationIncident.last_seen_at >= cooldown_start,
        )
        .one_or_none()
    )
    if existing is not None:
        existing.occurrence_count = (existing.occurrence_count or 1) + 1
        existing.affected_count = max(existing.affected_count or 0, affected_count)
        existing.last_seen_at = now
        existing.metrics = {**(existing.metrics or {}), **dict(metrics or {})}
        if summary:
            existing.summary = summary
        session.flush()
        return existing

    incident = CommunicationIncident(
        id=f"incident_{uuid.uuid4().hex}",
        reference=_next_reference(),
        tenant_id=tenant_id,
        title=title[:255],
        category=category,
        severity=severity,
        status="open",
        fingerprint=fingerprint[:128],
        occurrence_count=1,
        affected_count=affected_count,
        metrics=dict(metrics or {}),
        summary=summary,
        opened_at=now,
        last_seen_at=now,
    )
    session.add(incident)
    session.flush()
    return incident


def transition_incident(session: Session, incident: CommunicationIncident, target_status: str, *, actor: str | None = None) -> CommunicationIncident:
    if target_status not in INCIDENT_STATUSES:
        raise ValueError(f"invalid incident status {target_status!r}")
    current = incident.status
    if current == target_status:
        return incident
    if target_status not in _STATUS_TRANSITIONS.get(current, frozenset()):
        raise InvalidIncidentTransition(f"incident cannot transition from {current} to {target_status}")
    incident.status = target_status
    now = datetime.now(timezone.utc)
    if target_status == "investigating":
        incident.acknowledged_at = now
    elif target_status == "mitigated":
        incident.mitigated_at = now
    elif target_status == "resolved":
        incident.resolved_at = now
    session.flush()
    return incident


def incident_payload(incident: CommunicationIncident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "reference": incident.reference,
        "tenant_id": incident.tenant_id,
        "title": incident.title,
        "category": incident.category,
        "severity": incident.severity,
        "status": incident.status,
        "occurrence_count": incident.occurrence_count,
        "affected_count": incident.affected_count,
        "metrics": incident.metrics,
        "summary": incident.summary,
        "opened_at": incident.opened_at.isoformat() if incident.opened_at else None,
        "last_seen_at": incident.last_seen_at.isoformat() if incident.last_seen_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
    }


# --- SLA monitoring ----------------------------------------------------------

# Queue latency targets in seconds per notification priority.
_DEFAULT_SLA_TARGETS = {"critical": 5, "high": 30, "normal": 120, "low": 600}


def sla_targets() -> dict[str, int]:
    raw = os.getenv("PESAGUARD_COMMUNICATION_SLA_TARGETS", "")
    if raw:
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                merged = dict(_DEFAULT_SLA_TARGETS)
                merged.update({key: int(value) for key, value in loaded.items()})
                return merged
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    return dict(_DEFAULT_SLA_TARGETS)


def queue_latency_seconds(created_at: datetime, *, now: datetime | None = None) -> float:
    now = now or datetime.now(timezone.utc)
    created = created_at if created_at.tzinfo else created_at.replace(tzinfo=timezone.utc)
    return max(0.0, (now - created).total_seconds())


def sla_breach(created_at: datetime, priority: str, *, now: datetime | None = None) -> dict[str, Any] | None:
    """Return breach details when an entry exceeds its priority SLA target."""
    latency = queue_latency_seconds(created_at, now=now)
    target = sla_targets().get(priority, 600)
    if latency < target:
        return None
    return {
        "priority": priority,
        "target_seconds": target,
        "actual_seconds": round(latency, 2),
    }
