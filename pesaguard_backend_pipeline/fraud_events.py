"""Versioned fraud event publication on top of the existing risk-scoring pipeline.

The fraud risk engine and reconciliation job already compute and persist
decisions.  These helpers expose the same results as versioned Kafka events
without changing the durable scoring/assessment boundary: callers persist first
(``persist_assessment``), then publish the corresponding event.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Mapping, Optional

from fraud_risk_engine import MODEL_VERSION, RiskDecision

logger = logging.getLogger("pesaguard.fraud_events")


def _publish(event_type: str, tenant_id: str, aggregate_id: str, payload: Mapping[str, Any], publisher: Callable[..., Any], *, correlation_id: str | None = None) -> Any:
    from event_bus import build_event
    from producer import publish_versioned_event

    event = build_event(
        event_type,
        tenant_id,
        aggregate_id,
        dict(payload),
        correlation_id=correlation_id,
        producer="pesaguard.fraud_events",
        producer_version="1",
    )
    return publish_versioned_event(event, producer=publisher)


def publish_fraud_analysis(
    *,
    tenant_id: str,
    transaction_id: str,
    decision: RiskDecision,
    model_version: str = MODEL_VERSION,
    publisher: Callable[..., Any],
    correlation_id: str | None = None,
) -> Any:
    """Publish one self-describing fraud-analysis completion/result event."""
    action = str(getattr(decision, "action", "") or "").lower()
    payload = {
        "transaction_id": transaction_id,
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "action": decision.action,
        "model_version": model_version,
        "features": dict(decision.features.as_dict()),
        "reason_codes": list(decision.reason_codes),
        "rules_triggered": list(decision.rules_triggered),
    }
    event_type = "fraud.analysis.completed"
    if action == "review":
        event_type = "fraud.anomaly_detected"
    elif action == "escalate":
        event_type = "fraud.decision_created"
    return _publish(event_type, tenant_id, transaction_id, payload, publisher, correlation_id=correlation_id)


def publish_fraud_analysis_started(
    *,
    tenant_id: str,
    transaction_id: str,
    model_version: str = MODEL_VERSION,
    publisher: Callable[..., Any],
    correlation_id: str | None = None,
) -> Any:
    """Publish the auditable start of a fraud-analysis run."""
    return _publish(
        "fraud.analysis.started",
        tenant_id,
        transaction_id,
        {"transaction_id": transaction_id, "model_version": model_version},
        publisher,
        correlation_id=correlation_id,
    )


def publish_fraud_review_decision(
    *,
    tenant_id: str,
    transaction_id: str,
    reviewer: str,
    decision: RiskDecision,
    verdict: str,
    note: str | None = None,
    publisher: Callable[..., Any],
    correlation_id: str | None = None,
) -> Any:
    """Publish an analyst-attributed fraud review decision."""
    payload = {
        "transaction_id": transaction_id,
        "reviewer": reviewer,
        "verdict": verdict,
        "note": note or "",
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "model_version": decision.model_version,
        "reason_codes": list(decision.reason_codes),
        "rules_triggered": list(decision.rules_triggered),
    }
    return _publish("fraud.anomaly.reviewed", tenant_id, transaction_id, payload, publisher, correlation_id=correlation_id)
