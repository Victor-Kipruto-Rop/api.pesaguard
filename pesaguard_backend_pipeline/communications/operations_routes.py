"""Operational communication APIs: timelines, search, costs, health, incidents.

All endpoints are tenant-scoped by the authenticated principal. Dangerous
operations (replay, incident transitions, quota changes) require the
`manage:communications` permission.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request

from .cost import cost_by_channel, cost_summary, wallet_health
from .core.state_machine import InvalidNotificationTransition
from .flags import snapshot as flags_snapshot
from .incidents import InvalidIncidentTransition, incident_payload, transition_incident
from .models import (
    CommunicationAttempt,
    CommunicationCampaign,
    CommunicationDeliveryReport,
    CommunicationIncident,
    CommunicationNotification,
    CommunicationOutboxEntry,
    CommunicationSavedFilter,
    CommunicationTenantQuota,
    CommunicationWebhookEvent,
)
from .outbox import replay_dead_letter
from .policy import NotificationPolicyEngine
from .providers.email import EmailProviderAnalytics
from .providers.health import all_provider_health
from .webhooks import ignore_webhook_event, replay_webhook_event


def create_operations_blueprint(session_factory, require_auth_fn, current_user_fn, provider_router=None):
    blueprint = Blueprint("communications_operations", __name__, url_prefix="/api/v1/communications")

    def tenant_id():
        return getattr(current_user_fn(), "tenant_id", None)

    def _error(message: str, status: int = 400, code: str = "INVALID_REQUEST"):
        return jsonify({"error": {"code": code, "message": message}}), status

    @blueprint.get("/messages")
    @require_auth_fn("read:communications")
    def messages_route():
        session = session_factory()
        try:
            query = session.query(CommunicationNotification).filter_by(tenant_id=tenant_id())
            filters = request.args
            for field in ("status", "channel", "provider", "template_id", "recipient", "correlation_id", "trace_id", "provider_message_id", "idempotency_key"):
                value = filters.get(field)
                if value:
                    query = query.filter(getattr(CommunicationNotification, field) == value)
            if filters.get("created_after"):
                query = query.filter(CommunicationNotification.created_at >= _parse_dt(filters["created_after"]))
            if filters.get("created_before"):
                query = query.filter(CommunicationNotification.created_at <= _parse_dt(filters["created_before"]))
            cursor = filters.get("cursor")
            if cursor:
                query = query.filter(CommunicationNotification.created_at < _parse_dt(cursor))
            limit = min(200, max(1, int(filters.get("limit", 50))))
            rows = query.order_by(CommunicationNotification.created_at.desc()).limit(limit + 1).all()
            next_cursor = None
            if len(rows) > limit:
                rows = rows[:limit]
                next_cursor = rows[-1].created_at.isoformat()
            return jsonify({"messages": [_message_summary(row) for row in rows], "next_cursor": next_cursor, "count": len(rows)})
        except ValueError as exc:
            return _error(str(exc))
        finally:
            session.close()

    @blueprint.get("/messages/<message_id>")
    @require_auth_fn("read:communications")
    def message_detail_route(message_id: str):
        session = session_factory()
        try:
            notification = session.query(CommunicationNotification).filter_by(id=message_id, tenant_id=tenant_id()).one_or_none()
            if notification is None:
                return _error("message not found", 404, "NOT_FOUND")
            attempts = session.query(CommunicationAttempt).filter_by(notification_id=notification.id).order_by(CommunicationAttempt.attempt_number.asc()).all()
            reports = session.query(CommunicationDeliveryReport).filter_by(notification_id=notification.id).order_by(CommunicationDeliveryReport.received_at.asc()).all()
            return jsonify({
                **_message_summary(notification),
                "message": notification.message,
                "failure_code": notification.failure_code,
                "failure_reason": notification.failure_reason,
                "latency": _latencies(notification, attempts),
                "attempts": [_attempt_payload(a) for a in attempts],
                "delivery_reports": [_report_payload(r) for r in reports],
                "timeline": _timeline(notification, attempts, reports),
            })
        finally:
            session.close()

    # --- saved filters -----------------------------------------------------------

    @blueprint.get("/saved-filters")
    @require_auth_fn("read:communications")
    def saved_filters_route():
        session = session_factory()
        try:
            rows = session.query(CommunicationSavedFilter).filter_by(tenant_id=tenant_id()).order_by(CommunicationSavedFilter.name.asc()).all()
            return jsonify([{"id": row.id, "name": row.name, "query": row.query, "created_at": row.created_at.isoformat()} for row in rows])
        finally:
            session.close()

    @blueprint.post("/saved-filters")
    @require_auth_fn("read:communications")
    def create_saved_filter_route():
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name") or "").strip()
        query = payload.get("query")
        if not name or not isinstance(query, dict):
            return _error("name and query object are required")
        session = session_factory()
        try:
            existing = session.query(CommunicationSavedFilter).filter_by(tenant_id=tenant_id(), name=name).one_or_none()
            if existing is not None:
                existing.query = query
                row = existing
            else:
                row = CommunicationSavedFilter(id=f"savedfilter_{uuid.uuid4().hex}", tenant_id=tenant_id(), owner_user_id=str(getattr(current_user_fn(), "user_id", "") or "") or None, name=name, query=query)
                session.add(row)
            session.commit()
            return jsonify({"id": row.id, "name": row.name, "query": row.query}), 201
        finally:
            session.close()

    @blueprint.delete("/saved-filters/<filter_id>")
    @require_auth_fn("read:communications")
    def delete_saved_filter_route(filter_id: str):
        session = session_factory()
        try:
            row = session.query(CommunicationSavedFilter).filter_by(id=filter_id, tenant_id=tenant_id()).one_or_none()
            if row is None:
                return _error("saved filter not found", 404, "NOT_FOUND")
            session.delete(row)
            session.commit()
            return jsonify({"deleted": True})
        finally:
            session.close()

    # --- cost intelligence ---------------------------------------------------------

    @blueprint.get("/analytics/costs")
    @require_auth_fn("read:communications")
    def costs_route():
        session = session_factory()
        try:
            return jsonify({
                "summary": cost_summary(session, tenant_id=tenant_id()),
                "by_channel": cost_by_channel(session, tenant_id=tenant_id()),
                "wallet_health": wallet_health(session),
            })
        finally:
            session.close()

    # --- provider health ------------------------------------------------------------

    @blueprint.get("/providers/health")
    @require_auth_fn("read:communications")
    def provider_health_route():
        session = session_factory()
        try:
            analytics = EmailProviderAnalytics(session=session)
            payload = {
                "providers": all_provider_health(session),
                "feature_flags": flags_snapshot(),
                "analytics": analytics.snapshot(session=session),
            }
            if provider_router is not None and hasattr(provider_router, "snapshot"):
                payload["circuits"] = provider_router.snapshot()
            return jsonify(payload)
        finally:
            session.close()

    # --- incidents -----------------------------------------------------------------

    @blueprint.get("/incidents")
    @require_auth_fn("read:communications")
    def incidents_route():
        session = session_factory()
        try:
            query = session.query(CommunicationIncident).filter(
                (CommunicationIncident.tenant_id == tenant_id()) | (CommunicationIncident.tenant_id.is_(None))
            )
            status = request.args.get("status")
            if status:
                query = query.filter(CommunicationIncident.status == status)
            rows = query.order_by(CommunicationIncident.last_seen_at.desc()).limit(200).all()
            return jsonify([incident_payload(row) for row in rows])
        finally:
            session.close()

    @blueprint.post("/incidents/<incident_id>/status")
    @require_auth_fn("manage:communications")
    def incident_status_route(incident_id: str):
        payload = request.get_json(silent=True) or {}
        target = str(payload.get("status") or "")
        session = session_factory()
        try:
            incident = session.query(CommunicationIncident).filter_by(id=incident_id).filter(
                (CommunicationIncident.tenant_id == tenant_id()) | (CommunicationIncident.tenant_id.is_(None))
            ).one_or_none()
            if incident is None:
                return _error("incident not found", 404, "NOT_FOUND")
            transition_incident(session, incident, target, actor=str(getattr(current_user_fn(), "user_id", "system")))
            session.commit()
            return jsonify(incident_payload(incident))
        except InvalidIncidentTransition as exc:
            session.rollback()
            return _error(str(exc), 409, "INVALID_TRANSITION")
        except ValueError as exc:
            session.rollback()
            return _error(str(exc))
        finally:
            session.close()

    # --- tenant quotas ---------------------------------------------------------------

    @blueprint.get("/quotas")
    @require_auth_fn("read:communications")
    def quotas_route():
        session = session_factory()
        try:
            rows = session.query(CommunicationTenantQuota).filter_by(tenant_id=tenant_id()).all()
            day_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            utilization = {}
            for row in rows:
                if row.scope.endswith("_daily") or row.window == "daily":
                    used = session.query(CommunicationNotification).filter(
                        CommunicationNotification.tenant_id == tenant_id(),
                        CommunicationNotification.created_at >= day_start,
                    ).count()
                else:
                    used = session.query(CommunicationNotification).filter(
                        CommunicationNotification.tenant_id == tenant_id(),
                        CommunicationNotification.created_at >= day_start - timedelta(days=30),
                    ).count()
                utilization[row.scope] = {
                    "limit": row.limit_value,
                    "window": row.window,
                    "used": used,
                    "utilization_percent": round((used / row.limit_value) * 100, 1) if row.limit_value else None,
                }
            return jsonify({"quotas": utilization})
        finally:
            session.close()

    @blueprint.put("/quotas/<scope>")
    @require_auth_fn("manage:communications")
    def set_quota_route(scope: str):
        payload = request.get_json(silent=True) or {}
        try:
            limit_value = int(payload["limit_value"])
        except (KeyError, TypeError, ValueError):
            return _error("limit_value (integer) is required")
        session = session_factory()
        try:
            row = session.query(CommunicationTenantQuota).filter_by(tenant_id=tenant_id(), scope=scope).one_or_none()
            if row is None:
                row = CommunicationTenantQuota(id=f"quota_{uuid.uuid4().hex}", tenant_id=tenant_id(), scope=scope, limit_value=limit_value, window=str(payload.get("window", "daily")))
                session.add(row)
            else:
                row.limit_value = limit_value
                row.window = str(payload.get("window", row.window))
                row.updated_at = datetime.now(timezone.utc)
            session.commit()
            return jsonify({"scope": row.scope, "limit_value": row.limit_value, "window": row.window})
        finally:
            session.close()

    # --- webhook inbox administration -------------------------------------------------

    @blueprint.get("/webhook-events")
    @require_auth_fn("read:communications")
    def webhook_events_route():
        session = session_factory()
        try:
            query = session.query(CommunicationWebhookEvent).filter(
                (CommunicationWebhookEvent.tenant_id == tenant_id()) | (CommunicationWebhookEvent.tenant_id.is_(None))
            )
            processing_status = request.args.get("processing_status")
            if processing_status:
                query = query.filter(CommunicationWebhookEvent.processing_status == processing_status)
            rows = query.order_by(CommunicationWebhookEvent.received_at.desc()).limit(200).all()
            return jsonify([{
                "id": row.id,
                "provider": row.provider,
                "provider_event_id": row.provider_event_id,
                "event_type": row.event_type,
                "processing_status": row.processing_status,
                "attempt_count": row.attempt_count,
                "received_at": row.received_at.isoformat() if row.received_at else None,
                "processed_at": row.processed_at.isoformat() if row.processed_at else None,
                "last_error": row.last_error,
                "payload_hash": row.payload_hash,
            } for row in rows])
        finally:
            session.close()

    @blueprint.post("/webhook-events/<event_id>/replay")
    @require_auth_fn("manage:communications")
    def webhook_replay_route(event_id: str):
        session = session_factory()
        try:
            event = session.query(CommunicationWebhookEvent).filter_by(id=event_id).filter(
                (CommunicationWebhookEvent.tenant_id == tenant_id()) | (CommunicationWebhookEvent.tenant_id.is_(None))
            ).one_or_none()
            if event is None:
                return _error("webhook event not found", 404, "NOT_FOUND")
            result = replay_webhook_event(session, event_id)
            session.commit()
            return jsonify(result)
        except ValueError as exc:
            session.rollback()
            return _error(str(exc))
        finally:
            session.close()

    @blueprint.post("/webhook-events/<event_id>/ignore")
    @require_auth_fn("manage:communications")
    def webhook_ignore_route(event_id: str):
        session = session_factory()
        try:
            event = session.query(CommunicationWebhookEvent).filter_by(id=event_id).filter(
                (CommunicationWebhookEvent.tenant_id == tenant_id()) | (CommunicationWebhookEvent.tenant_id.is_(None))
            ).one_or_none()
            if event is None:
                return _error("webhook event not found", 404, "NOT_FOUND")
            result = ignore_webhook_event(session, event_id)
            session.commit()
            return jsonify(result)
        except ValueError as exc:
            session.rollback()
            return _error(str(exc))
        finally:
            session.close()

    # --- dead letter administration ---------------------------------------------------

    @blueprint.get("/dead-letters")
    @require_auth_fn("read:communications")
    def dead_letters_route():
        session = session_factory()
        try:
            rows = session.query(CommunicationOutboxEntry, CommunicationNotification).join(
                CommunicationNotification, CommunicationNotification.id == CommunicationOutboxEntry.notification_id
            ).filter(
                CommunicationOutboxEntry.status == "dead_letter",
                CommunicationOutboxEntry.tenant_id == tenant_id(),
            ).order_by(CommunicationOutboxEntry.created_at.desc()).limit(200).all()
            return jsonify([{
                "entry_id": entry.id,
                "notification_id": notification.id,
                "channel": notification.channel,
                "recipient": notification.recipient,
                "attempt_count": entry.attempt_count,
                "max_attempts": entry.max_attempts,
                "last_error": entry.last_error,
                "failure_code": notification.failure_code,
                "created_at": entry.created_at.isoformat() if entry.created_at else None,
            } for entry, notification in rows])
        finally:
            session.close()

    @blueprint.post("/dead-letters/<entry_id>/replay")
    @require_auth_fn("manage:communications")
    def dead_letter_replay_route(entry_id: str):
        session = session_factory()
        try:
            entry = session.query(CommunicationOutboxEntry).filter_by(id=entry_id, tenant_id=tenant_id(), status="dead_letter").one_or_none()
            if entry is None:
                return _error("dead letter entry not found", 404, "NOT_FOUND")
            replay_dead_letter(session, entry_id)
            session.commit()
            return jsonify({"status": "requeued", "entry_id": entry_id})
        except (ValueError, InvalidNotificationTransition) as exc:
            session.rollback()
            return _error(str(exc))
        finally:
            session.close()

    # --- campaign control ---------------------------------------------------------------

    @blueprint.post("/campaigns/<campaign_id>/estimate")
    @require_auth_fn("send:communications")
    def campaign_estimate_route(campaign_id: str):
        from .campaigns import estimate_campaign

        session = session_factory()
        try:
            campaign = session.query(CommunicationCampaign).filter_by(id=campaign_id, tenant_id=tenant_id()).one_or_none()
            if campaign is None:
                return _error("campaign not found", 404, "NOT_FOUND")
            return jsonify(estimate_campaign(session, campaign))
        finally:
            session.close()

    @blueprint.post("/campaigns/<campaign_id>/pause")
    @require_auth_fn("manage:communications")
    def campaign_pause_route(campaign_id: str):
        from .campaigns import pause_campaign

        return _campaign_state_action(session_factory, tenant_id(), campaign_id, pause_campaign)

    @blueprint.post("/campaigns/<campaign_id>/resume")
    @require_auth_fn("manage:communications")
    def campaign_resume_route(campaign_id: str):
        from .campaigns import resume_campaign

        return _campaign_state_action(session_factory, tenant_id(), campaign_id, resume_campaign)

    @blueprint.post("/campaigns/<campaign_id>/cancel")
    @require_auth_fn("manage:communications")
    def campaign_cancel_route(campaign_id: str):
        from .campaigns import cancel_campaign

        return _campaign_state_action(session_factory, tenant_id(), campaign_id, cancel_campaign)

    # --- flags + policy preview -----------------------------------------------------------

    @blueprint.get("/flags")
    @require_auth_fn("read:communications")
    def flags_route():
        return jsonify(flags_snapshot())

    @blueprint.post("/policy/preview")
    @require_auth_fn("read:communications")
    def policy_preview_route():
        payload = request.get_json(silent=True) or {}
        event = str(payload.get("event") or "")
        if not event:
            return _error("event is required")
        engine = NotificationPolicyEngine()
        decision = engine.decide(event, tenant_id=tenant_id(), context=payload.get("context") or {})
        return jsonify({"event": event, "decision": decision.to_dict()})

    return blueprint


def _campaign_state_action(session_factory, tenant, campaign_id, action):
    session = session_factory()
    try:
        campaign = session.query(CommunicationCampaign).filter_by(id=campaign_id, tenant_id=tenant).one_or_none()
        if campaign is None:
            return jsonify({"error": {"code": "NOT_FOUND", "message": "campaign not found"}}), 404
        action(session, campaign)
        session.commit()
        return jsonify({"id": campaign.id, "status": campaign.status})
    except ValueError as exc:
        session.rollback()
        return jsonify({"error": {"code": "INVALID_TRANSITION", "message": str(exc)}}), 409
    finally:
        session.close()


def _parse_dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _message_summary(notification: CommunicationNotification) -> dict:
    return {
        "id": notification.id,
        "tenant_id": notification.tenant_id,
        "channel": notification.channel,
        "recipient": notification.recipient,
        "status": notification.status,
        "priority": notification.priority,
        "provider": notification.provider,
        "provider_message_id": notification.provider_message_id,
        "template_id": notification.template_id,
        "correlation_id": notification.correlation_id,
        "trace_id": notification.trace_id,
        "failure_code": notification.failure_code,
        "created_at": notification.created_at.isoformat() if notification.created_at else None,
        "queued_at": notification.queued_at.isoformat() if notification.queued_at else None,
        "submitted_at": notification.submitted_at.isoformat() if notification.submitted_at else None,
        "delivered_at": notification.delivered_at.isoformat() if notification.delivered_at else None,
        "failed_at": notification.failed_at.isoformat() if notification.failed_at else None,
    }


def _latencies(notification: CommunicationNotification, attempts: list) -> dict:
    def _seconds(later, earlier):
        if not later or not earlier:
            return None
        start = earlier if earlier.tzinfo else earlier.replace(tzinfo=timezone.utc)
        end = later if later.tzinfo else later.replace(tzinfo=timezone.utc)
        return round((end - start).total_seconds(), 3)

    provider_response_ms = next((a.latency_ms for a in attempts if a.latency_ms is not None), None)
    return {
        "queue_time_seconds": _seconds(notification.queued_at, notification.created_at),
        "provider_response_time_ms": provider_response_ms,
        "delivery_time_seconds": _seconds(notification.delivered_at, notification.submitted_at),
        "total_latency_seconds": _seconds(notification.delivered_at, notification.created_at),
    }


def _attempt_payload(attempt: CommunicationAttempt) -> dict:
    return {
        "id": attempt.id,
        "attempt_number": attempt.attempt_number,
        "provider": attempt.provider,
        "status": attempt.status,
        "error_code": attempt.error_code,
        "error_category": attempt.error_category,
        "error_detail": attempt.error_detail,
        "latency_ms": attempt.latency_ms,
        "cost": attempt.cost,
        "started_at": attempt.started_at.isoformat() if attempt.started_at else None,
        "completed_at": attempt.completed_at.isoformat() if attempt.completed_at else None,
    }


def _report_payload(report: CommunicationDeliveryReport) -> dict:
    return {
        "id": report.id,
        "provider": report.provider,
        "provider_event_id": report.provider_event_id,
        "status": report.status,
        "received_at": report.received_at.isoformat() if report.received_at else None,
        "delivered_at": report.delivered_at.isoformat() if report.delivered_at else None,
    }


def _timeline(notification: CommunicationNotification, attempts: list, reports: list) -> list:
    events = []
    if notification.created_at:
        events.append({"at": notification.created_at, "event": "created", "detail": None})
    if notification.queued_at:
        events.append({"at": notification.queued_at, "event": "queued", "detail": None})
    for attempt in attempts:
        if attempt.started_at:
            events.append({"at": attempt.started_at, "event": f"attempt_{attempt.attempt_number}_started", "detail": attempt.provider})
        if attempt.completed_at:
            events.append({"at": attempt.completed_at, "event": f"attempt_{attempt.attempt_number}_{attempt.status}", "detail": attempt.error_category or attempt.provider_message_id})
    for report in reports:
        events.append({"at": report.received_at, "event": f"delivery_report_{report.status}", "detail": report.provider_event_id})
    if notification.delivered_at:
        events.append({"at": notification.delivered_at, "event": "delivered", "detail": None})
    if notification.failed_at:
        events.append({"at": notification.failed_at, "event": "failed", "detail": notification.failure_code})
    ordered = sorted(events, key=lambda item: item["at"] if item["at"].tzinfo else item["at"].replace(tzinfo=timezone.utc))
    return [{"at": item["at"].isoformat(), "event": item["event"], "detail": item["detail"]} for item in ordered]
