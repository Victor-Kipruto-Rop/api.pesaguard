"""
Webhook delivery manager for event-driven notifications in PesaGuard.

Provides secure webhook registration, SSRF defense, HMAC SHA-256 payload signing,
and exponential backoff retries.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from sqlalchemy.orm import Session

from models import WebhookConfig, WebhookDelivery

logger = logging.getLogger("pesaguard.webhooks")


def _is_private_or_reserved(ip_str: str) -> bool:
    """Check if an IP string belongs to private, loopback, or reserved network space."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # Treat unparseable IP as unsafe
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _validate_webhook_url(url: str) -> Optional[str]:
    """Validate a webhook URL against SSRF threats and reserved IP ranges.

    Returns:
        None if valid, or a error string reason if rejected.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return "url_could_not_be_parsed"

    if parsed.scheme != "https":
        return "url_must_use_https"

    if not parsed.hostname:
        return "url_missing_hostname"

    if parsed.hostname.lower() in {"localhost", "metadata.google.internal", "169.254.169.254"}:
        return "url_targets_reserved_hostname"

    try:
        resolved_ips = {info[4][0] for info in socket.getaddrinfo(parsed.hostname, None)}
    except socket.gaierror:
        return "url_hostname_cannot_be_resolved"

    for ip_str in resolved_ips:
        if _is_private_or_reserved(ip_str):
            return f"url_resolves_to_disallowed_address:{ip_str}"

    return None


class WebhookManager:
    """Manages webhook registrations, authorization checks, and payload deliveries."""

    def __init__(self, session: Session):
        self.session = session
        self.default_timeout = 10
        self.default_max_retries = 3

    def register_webhook(
        self,
        tenant_id: str,
        url: str,
        event_types: List[str],
        retry_attempts: int = 3,
        timeout_seconds: int = 10,
    ) -> Dict[str, Any]:
        """Register a new webhook endpoint for a tenant."""
        rejection_reason = _validate_webhook_url(url)
        if rejection_reason:
            logger.warning("Rejected webhook registration for tenant=%s: %s (url=%s)", tenant_id, rejection_reason, url)
            return {"error": "invalid_webhook_url", "reason": rejection_reason}

        webhook_id = f"webhook_{uuid.uuid4().hex[:12]}"
        signing_secret = f"whsec_{secrets.token_hex(24)}"

        webhook = WebhookConfig(
            id=webhook_id,
            tenant_id=tenant_id,
            url=url,
            event_types=event_types,
            retry_attempts=min(retry_attempts, 5),
            timeout_seconds=min(timeout_seconds, 30),
            active=True,
            signing_secret=signing_secret,
        )
        self.session.add(webhook)
        self.session.commit()
        logger.info("Registered webhook_id=%s for tenant_id=%s", webhook_id, tenant_id)

        return {
            "id": webhook_id,
            "tenant_id": tenant_id,
            "url": url,
            "event_types": event_types,
            "active": True,
            "signing_secret": signing_secret,
        }

    def get_webhooks(self, tenant_id: str, event_type: Optional[str] = None) -> List[WebhookConfig]:
        """Retrieve active webhooks for a tenant, optionally filtered by event_type."""
        query = self.session.query(WebhookConfig).filter(
            WebhookConfig.tenant_id == tenant_id,
            WebhookConfig.active == True,
        )
        webhooks = query.all()
        if event_type:
            webhooks = [w for w in webhooks if event_type in (w.event_types or [])]
        return webhooks

    def trigger_event(
        self,
        tenant_id: str,
        event_type: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Trigger an event and dispatch to subscribed webhooks."""
        webhooks = self.get_webhooks(tenant_id, event_type)
        results = []

        for webhook in webhooks:
            delivery = self._deliver_webhook(webhook, event_type, payload)
            results.append(delivery)

        return {
            "event_type": event_type,
            "webhooks_triggered": len(webhooks),
            "deliveries": results,
        }

    def _deliver_webhook(
        self,
        webhook: WebhookConfig,
        event_type: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Deliver payload to endpoint with exponential backoff retries."""
        # Re-verify URL before delivery to defend against Dynamic DNS SSRF changes
        rejection_reason = _validate_webhook_url(webhook.url)
        if rejection_reason:
            logger.error("Webhook delivery aborted for webhook_id=%s: URL validation failed (%s)", webhook.id, rejection_reason)
            return {"id": webhook.id, "status": "failed", "reason": rejection_reason}

        delivery_id = f"delivery_{uuid.uuid4().hex[:12]}"
        delivery = WebhookDelivery(
            id=delivery_id,
            tenant_id=webhook.tenant_id,
            webhook_id=webhook.id,
            event_type=event_type,
            payload=payload,
            status="pending",
            attempt_count=0,
        )

        timestamp_str = str(int(datetime.now(timezone.utc).timestamp()))
        signature_header = self._generate_signature(webhook, payload, timestamp_str)

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "PesaGuard-Webhook-Dispatcher/2.0",
            "X-Webhook-Event": event_type,
            "X-Webhook-Timestamp": timestamp_str,
            "X-Webhook-Signature": signature_header,
        }

        max_attempts = webhook.retry_attempts or self.default_max_retries
        timeout = webhook.timeout_seconds or self.default_timeout

        for attempt in range(max_attempts):
            delivery.attempt_count = attempt + 1
            try:
                response = requests.post(
                    webhook.url,
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                )
                delivery.response_status = response.status_code
                delivery.response_body = response.text[:500] if response.text else ""

                if 200 <= response.status_code < 300:
                    delivery.status = "success"
                    delivery.delivered_at = datetime.now(timezone.utc)
                    self.session.add(delivery)
                    self.session.commit()
                    logger.info("Webhook delivery_id=%s succeeded on attempt %d", delivery_id, attempt + 1)
                    return {
                        "id": delivery_id,
                        "status": "success",
                        "attempt": attempt + 1,
                        "response_code": response.status_code,
                    }

                if response.is_redirect:
                    logger.warning("Webhook delivery_id=%s returned redirect (%d). Aborting for security.", delivery_id, response.status_code)
                    break

            except requests.Timeout:
                logger.warning("Webhook delivery_id=%s timed out on attempt %d", delivery_id, attempt + 1)
            except Exception as exc:
                logger.error("Webhook delivery_id=%s failed on attempt %d: %s", delivery_id, attempt + 1, exc)

            if attempt < max_attempts - 1:
                wait_seconds = 2 ** attempt
                time.sleep(wait_seconds)

        delivery.status = "failed"
        self.session.add(delivery)
        self.session.commit()
        logger.error("Webhook delivery_id=%s permanently failed after %d attempts", delivery_id, max_attempts)

        return {
            "id": delivery_id,
            "status": "failed",
            "attempts": max_attempts,
        }

    def _generate_signature(self, webhook: WebhookConfig, payload: Dict[str, Any], timestamp: str) -> str:
        """Generate HMAC SHA-256 signature using the webhook signing secret."""
        secret = getattr(webhook, "signing_secret", None) or webhook.id
        raw_body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        signed_payload = f"{timestamp}.{raw_body}".encode("utf-8")

        digest = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
        return f"t={timestamp},v1={digest}"

    def update_webhook(self, webhook_id: str, tenant_id: str, **kwargs: Any) -> Dict[str, Any]:
        """Update active configuration parameters for a tenant's webhook."""
        webhook = (
            self.session.query(WebhookConfig)
            .filter(WebhookConfig.id == webhook_id, WebhookConfig.tenant_id == tenant_id)
            .first()
        )
        if not webhook:
            return {"error": "webhook_not_found"}

        if "url" in kwargs:
            rejection_reason = _validate_webhook_url(kwargs["url"])
            if rejection_reason:
                return {"error": "invalid_webhook_url", "reason": rejection_reason}

        for key, value in kwargs.items():
            if hasattr(webhook, key) and key not in {"id", "tenant_id", "signing_secret"}:
                setattr(webhook, key, value)

        self.session.commit()
        return {
            "id": webhook_id,
            "url": webhook.url,
            "active": webhook.active,
            "event_types": webhook.event_types,
        }

    def delete_webhook(self, webhook_id: str, tenant_id: str) -> Dict[str, Any]:
        """Delete a registered webhook for a tenant."""
        webhook = (
            self.session.query(WebhookConfig)
            .filter(WebhookConfig.id == webhook_id, WebhookConfig.tenant_id == tenant_id)
            .first()
        )
        if not webhook:
            return {"error": "webhook_not_found"}

        self.session.delete(webhook)
        self.session.commit()
        return {"status": "deleted", "id": webhook_id}

    def get_delivery_history(self, webhook_id: str, tenant_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent delivery logs for a tenant's webhook."""
        owner_check = (
            self.session.query(WebhookConfig)
            .filter(WebhookConfig.id == webhook_id, WebhookConfig.tenant_id == tenant_id)
            .first()
        )
        if not owner_check:
            return []

        deliveries = (
            self.session.query(WebhookDelivery)
            .filter(
                WebhookDelivery.webhook_id == webhook_id,
                WebhookDelivery.tenant_id == tenant_id,
            )
            .order_by(WebhookDelivery.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": d.id,
                "event_type": d.event_type,
                "status": d.status,
                "attempt_count": d.attempt_count,
                "response_status": d.response_status,
                "created_at": d.created_at.isoformat() if d.created_at else None,
                "delivered_at": d.delivered_at.isoformat() if d.delivered_at else None,
            }
            for d in deliveries
        ]
