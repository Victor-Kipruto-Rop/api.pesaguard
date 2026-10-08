from __future__ import annotations

import os

from flask import Blueprint, current_app, jsonify, request

from .application.email_service import EmailService
from .application.notification_service import NotificationService
from .core.enums import CommunicationChannel, CommunicationPriority
from .core.interfaces import NotificationRequest
from .providers.email import EmailProviderConfig
from .providers.factory import build_africas_talking_provider
from .webhooks import process_delivery_webhook


def create_webhook_blueprint(
    session_factory,
    provider_factory=build_africas_talking_provider,
    require_auth_fn=None,
    current_user_fn=None,
    email_provider_factory=None,
):
    if require_auth_fn is None or current_user_fn is None:
        from auth_rbac import get_current_user as current_user_fn, require_auth as require_auth_fn

    blueprint = Blueprint("communications_webhooks", __name__)

    @blueprint.post("/api/v1/communications/sms")
    @require_auth_fn("send:communications")
    def send_sms():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": {"code": "INVALID_REQUEST", "message": "A JSON object is required."}}), 400
        user = current_user_fn()
        tenant_id = getattr(user, "tenant_id", None)
        recipient = payload.get("recipient")
        message = payload.get("message")
        idempotency_key = payload.get("idempotency_key") or request.headers.get("Idempotency-Key")
        if not tenant_id or not isinstance(recipient, str) or not isinstance(message, str) or not isinstance(idempotency_key, str):
            return jsonify({"error": {"code": "INVALID_REQUEST", "message": "recipient, message, and idempotency_key are required."}}), 400
        session = session_factory()
        try:
            priority = CommunicationPriority(str(payload.get("priority", "normal")).lower())
            notification = NotificationService(
                session,
                provider_factory(),
            ).enqueue(
                NotificationRequest(
                    tenant_id=tenant_id,
                    recipient=recipient,
                    message=message,
                    channel=CommunicationChannel.SMS,
                    priority=priority,
                    idempotency_key=idempotency_key,
                    template_id=payload.get("template_id"),
                    variables=payload.get("variables") or {},
                    correlation_id=request.headers.get("X-Correlation-ID"),
                    trace_id=request.headers.get("X-Trace-ID"),
                )
            )
            session.commit()
            return jsonify({"id": notification.id, "status": notification.status, "tenant_id": tenant_id}), 202
        except (TypeError, ValueError) as exc:
            session.rollback()
            return jsonify({"error": {"code": "INVALID_REQUEST", "message": str(exc)}}), 400
        except Exception:
            session.rollback()
            current_app.logger.exception("Communication send failed")
            return jsonify({"error": {"code": "COMMUNICATION_SEND_FAILED", "message": "Communication could not be submitted."}}), 502
        finally:
            session.close()

    @blueprint.post("/api/v1/communications/email")
    @require_auth_fn("send:communications")
    def send_email():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": {"code": "INVALID_REQUEST", "message": "A JSON object is required."}}), 400
        user = current_user_fn()
        tenant_id = getattr(user, "tenant_id", None)
        recipient = payload.get("recipient")
        message = payload.get("message")
        idempotency_key = payload.get("idempotency_key") or request.headers.get("Idempotency-Key")
        if not tenant_id or not isinstance(recipient, str) or not isinstance(message, str) or not isinstance(idempotency_key, str):
            return jsonify({"error": {"code": "INVALID_REQUEST", "message": "recipient, message, and idempotency_key are required."}}), 400

        session = session_factory()
        try:
            priority = CommunicationPriority(str(payload.get("priority", "normal")).lower())
            provider = email_provider_factory() if email_provider_factory is not None else None
            config = EmailProviderConfig(
                provider=str(payload.get("provider", "smtp_email")).lower(),
                from_email=str(payload.get("from_email") or "no-reply@pesaguard.co.ke"),
            )
            email_service = EmailService(
                session,
                gateway_client=None,
                config=config,
                provider=provider,
            )
            notification = email_service.enqueue(
                NotificationRequest(
                    tenant_id=tenant_id,
                    recipient=recipient,
                    message=message,
                    channel=CommunicationChannel.EMAIL,
                    priority=priority,
                    idempotency_key=idempotency_key,
                    template_id=payload.get("template_id"),
                    variables=payload.get("variables") or {},
                    correlation_id=request.headers.get("X-Correlation-ID"),
                    trace_id=request.headers.get("X-Trace-ID"),
                )
            )
            session.commit()
            return jsonify({"id": notification.id, "status": notification.status, "tenant_id": tenant_id}), 202
        except (TypeError, ValueError) as exc:
            session.rollback()
            return jsonify({"error": {"code": "INVALID_REQUEST", "message": str(exc)}}), 400
        except Exception:
            session.rollback()
            current_app.logger.exception("Email communication send failed")
            return jsonify({"error": {"code": "COMMUNICATION_SEND_FAILED", "message": "Communication could not be submitted."}}), 502
        finally:
            session.close()

    @blueprint.post("/api/v1/webhooks/africastalking/delivery")
    def africastalking_delivery():
        secret = os.getenv("AFRICASTALKING_WEBHOOK_SECRET") or os.getenv("AFRICAS_TALKING_WEBHOOK_SECRET", "")
        if not secret:
            return jsonify({"error": {"code": "WEBHOOK_NOT_CONFIGURED", "message": "Webhook authentication is not configured."}}), 503

        raw_body = request.get_data(cache=False)
        max_body_bytes = current_app.config.get("PESAGUARD_WEBHOOK_MAX_BODY_BYTES")
        if max_body_bytes and len(raw_body) > max_body_bytes:
            return jsonify({"error": {"code": "PAYLOAD_TOO_LARGE", "message": "Webhook payload exceeds the configured limit."}}), 413

        session = session_factory()
        try:
            result = process_delivery_webhook(
                session,
                raw_body,
                signature=request.headers.get("X-Africa-Talking-Signature")
                or request.headers.get("X-Webhook-Signature"),
                secret=secret,
            )
            session.commit()
            return jsonify(result), 200
        except ValueError as exc:
            session.rollback()
            message = str(exc)
            status = 401 if "signature" in message else 400
            return jsonify({"error": {"code": "INVALID_WEBHOOK", "message": message}}), status
        except Exception:
            session.rollback()
            current_app.logger.exception("Africa's Talking delivery webhook processing failed")
            return jsonify({"error": {"code": "WEBHOOK_PROCESSING_FAILED", "message": "Webhook processing failed."}}), 500
        finally:
            session.close()

    return blueprint
