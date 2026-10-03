"""Public status feed and opt-in email change notifications."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from threading import Lock
from time import monotonic
from typing import Any, Callable

from flask import Blueprint, current_app, jsonify, request
import requests
from sqlalchemy.exc import IntegrityError

from email_service import EmailService
from models import PublicStatusSubscription

STATUS_SITE_URL = "https://status.pesaguard.victorkipruto.com/"
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TOKEN_TTL = timedelta(hours=24)
SITE_PROBES = (
    ("public-website", "Public website", "https://pesaguard.victorkipruto.com/"),
    ("dashboard-site", "Dashboard", "https://dashboard.pesaguard.victorkipruto.com/"),
    ("documentation-site", "Documentation", "https://docs.pesaguard.victorkipruto.com/"),
    ("status-site", "Status website", STATUS_SITE_URL),
)
_SITE_CACHE_SECONDS = 30
_site_cache_lock = Lock()
_site_cache: dict[str, Any] = {"checked_at": 0.0, "services": []}
_site_probe_pool = ThreadPoolExecutor(max_workers=len(SITE_PROBES), thread_name_prefix="status-site-probe")


def _probe_site(service_id: str, name: str, url: str) -> dict[str, str]:
    try:
        response = requests.get(url, timeout=(1, 2), allow_redirects=False, stream=True)
        try:
            status = "operational" if response.status_code < 500 else "outage"
        finally:
            response.close()
    except requests.RequestException:
        status = "unknown"
    return {
        "id": service_id,
        "name": name,
        "status": status,
        "description": "Public HTTP reachability check from the PesaGuard API.",
    }


def _site_services() -> list[dict[str, str]]:
    now = monotonic()
    with _site_cache_lock:
        if now - _site_cache["checked_at"] < _SITE_CACHE_SECONDS:
            return list(_site_cache["services"])
    futures = [
        _site_probe_pool.submit(_probe_site, service_id, name, url)
        for service_id, name, url in SITE_PROBES
    ]
    services = []
    deadline = monotonic() + 4
    for (service_id, name, _), future in zip(SITE_PROBES, futures):
        try:
            services.append(future.result(timeout=max(0, deadline - monotonic())))
        except FutureTimeoutError:
            current_app.logger.warning("Public status HTTP probe timed out for %s.", service_id)
            services.append({
                "id": service_id,
                "name": name,
                "status": "unknown",
                "description": "The public HTTP reachability check timed out.",
            })
        except Exception:
            current_app.logger.exception("Public status HTTP probe failed for %s.", service_id)
            services.append({
                "id": service_id,
                "name": name,
                "status": "unknown",
                "description": "The public HTTP reachability check failed.",
            })
    with _site_cache_lock:
        _site_cache["checked_at"] = monotonic()
        _site_cache["services"] = services
    return list(services)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _status_secret() -> bytes:
    secret = os.getenv("JWT_SECRET_KEY", "").encode("utf-8")
    if len(secret) < 32:
        raise RuntimeError("JWT_SECRET_KEY must be configured to sign status unsubscribe links.")
    return hmac.new(secret, b"pesaguard-public-status-unsubscribe-v1", hashlib.sha256).digest()


def _unsubscribe_token(subscription_id: str) -> str:
    signature = hmac.new(
        _status_secret(),
        subscription_id.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{subscription_id}.{signature}"


def _valid_unsubscribe_token(token: str) -> str | None:
    try:
        subscription_id, signature = token.split(".", 1)
    except ValueError:
        return None
    if not re.fullmatch(r"[a-f0-9]{32}", subscription_id):
        return None
    expected = _unsubscribe_token(subscription_id).split(".", 1)[1]
    return subscription_id if hmac.compare_digest(signature, expected) else None


def build_public_status_payload(health: dict[str, Any]) -> dict[str, Any]:
    """Map internal dependency details to a small, safe public health contract."""
    status_map = {"ok": "operational", "degraded": "degraded", "failed": "outage"}
    raw_status = health.get("status")
    overall = status_map.get(raw_status, "unknown")
    checked_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    check_names = {
        "database": ("Database", "Relational database connectivity."),
        "kafka": ("Event processing", "Kafka broker connectivity."),
        "redis": ("Cache", "Redis connectivity."),
        "daraja": ("Payment provider", "Daraja provider connectivity."),
    }
    checks = health.get("checks")
    checks = checks if isinstance(checks, dict) else {}
    services = [{
        "id": "api",
        "name": "PesaGuard API",
        "status": overall,
        "description": "Overall status reported by the API health checks.",
    }]
    for check_id, (name, description) in check_names.items():
        check = checks.get(check_id)
        check_status = check.get("status") if isinstance(check, dict) else None
        services.append({
            "id": check_id,
            "name": name,
            "status": status_map.get(check_status, "unknown"),
            "description": description,
        })
    services.extend(_site_services())
    service_statuses = {service["status"] for service in services}
    if "outage" in service_statuses:
        overall = "outage"
    elif "degraded" in service_statuses:
        overall = "degraded"

    descriptions = {
        "operational": "All measured API dependencies and reachable public sites report operational.",
        "degraded": "One or more measured API dependencies or public sites report reduced health.",
        "outage": "One or more measured API dependencies or public sites report a failure.",
        "unknown": "The API returned an unrecognized health state; service health cannot be confirmed.",
    }
    labels = {
        "operational": "Covered services operational",
        "degraded": "Degraded performance",
        "outage": "Service disruption detected",
        "unknown": "Status unavailable",
    }
    return {
        "version": "1.0.0",
        "generatedAt": checked_at,
        "lastUpdated": checked_at,
        "dataSource": "PesaGuard API health checks",
        "verified": overall != "unknown",
        "note": (
            "This live feed covers the API and its reported dependencies only. "
            "The public website, dashboard, documentation, and status site are "
            "checked for HTTP reachability. Incident, maintenance, and historical "
            "uptime feeds are not connected."
        ),
        "overall": {
            "status": overall,
            "label": labels[overall],
            "description": descriptions[overall],
        },
        "services": services,
    }


def _deliver_email(recipient: str, subject: str, text: str, html: str) -> tuple[bool, str | None]:
    """Send one email using the existing TLS-configured SMTP service."""
    try:
        mailer = EmailService(max_workers=1)
        configuration_error = mailer.configuration_error()
        if configuration_error:
            return False, configuration_error
        sent, error = mailer.send_email(recipient, subject, html, text)
        return sent, error
    except Exception:
        current_app.logger.exception("Public status email delivery failed.")
        return False, "email delivery failed"


def _fingerprint(payload: dict[str, Any]) -> str:
    stable = {
        "overall": (payload.get("overall") or {}).get("status"),
        "services": sorted(
            (service.get("id"), service.get("status"))
            for service in payload.get("services", [])
            if isinstance(service, dict)
        ),
    }
    serialized = json.dumps(stable, sort_keys=True, separators=(",", ":"))
    return _digest(serialized)


def create_public_status_blueprint(
    session_factory: Callable[[], Any],
    health_payload_provider: Callable[[], dict[str, Any]],
    email_sender: Callable[[str, str, str, str], tuple[bool, str | None]] | None = None,
) -> Blueprint:
    blueprint = Blueprint("public_status", __name__)
    send_email = email_sender or _deliver_email

    @blueprint.get("/public/status")
    def public_status():
        health = health_payload_provider()
        payload = build_public_status_payload(health)
        code = 200 if payload["overall"]["status"] == "operational" else 503
        return jsonify(payload), code

    @blueprint.post("/public/status/subscriptions")
    def subscribe():
        payload = request.get_json(silent=True)
        address = payload.get("email") if isinstance(payload, dict) else None
        if not isinstance(address, str) or len(address) > 254 or not EMAIL_PATTERN.fullmatch(address.strip()):
            return jsonify({"error": "invalid_email", "message": "Enter a valid email address."}), 400
        address = address.strip().lower()

        mailer = EmailService(max_workers=1) if email_sender is None else None
        if mailer is not None and mailer.configuration_error():
            current_app.logger.error("Status subscriptions are disabled because SMTP is not configured.")
            return jsonify({
                "error": "email_delivery_unavailable",
                "message": "Email updates are temporarily unavailable. Please try again later.",
            }), 503

        token = secrets.token_urlsafe(32)
        session = session_factory()
        try:
            email_hash = _digest(address)
            subscription = session.query(PublicStatusSubscription).filter_by(email_hash=email_hash).one_or_none()
            if subscription is not None and subscription.confirmed:
                return jsonify({
                    "message": "If this address can receive status updates, a confirmation email has been sent.",
                }), 202
            if subscription is None:
                subscription = PublicStatusSubscription(
                    id=uuid.uuid4().hex,
                    email=address,
                    email_hash=email_hash,
                )
                session.add(subscription)
            subscription.confirmation_token_hash = _digest(token)
            subscription.confirmation_expires_at = datetime.now(timezone.utc) + TOKEN_TTL
            subscription.email = address
            session.commit()
            confirm_url = f"{STATUS_SITE_URL}?confirm={token}"
            unsubscribe_url = f"{STATUS_SITE_URL}?unsubscribe={_unsubscribe_token(subscription.id)}"
            text = (
                "Confirm your PesaGuard status email subscription by opening:\n"
                f"{confirm_url}\n\n"
                "If you did not request this, ignore this email. To remove this pending request:\n"
                f"{unsubscribe_url}"
            )
            html = (
                '<p>Confirm your PesaGuard status email subscription:</p>'
                f'<p><a href="{confirm_url}">Review and confirm subscription</a></p>'
                '<p>If you did not request this, ignore this email. You can also '
                f'<a href="{unsubscribe_url}">remove this request</a>.</p>'
            )
            sent, error = send_email(address, "Confirm PesaGuard status updates", text, html)
            if not sent:
                current_app.logger.error("Status subscription confirmation email was not delivered: %s", error)
                return jsonify({
                    "error": "confirmation_delivery_failed",
                    "message": "The confirmation email could not be sent. Please try again later.",
                }), 502
            return jsonify({
                "message": "Check your email for a link to confirm your status subscription.",
            }), 202
        except IntegrityError:
            session.rollback()
            return jsonify({
                "message": "If this address can receive status updates, a confirmation email has been sent.",
            }), 202
        except Exception:
            session.rollback()
            current_app.logger.exception("Unable to create a public status subscription.")
            return jsonify({
                "error": "subscription_unavailable",
                "message": "The subscription could not be created. Please try again later.",
            }), 503
        finally:
            session.close()

    @blueprint.post("/public/status/subscriptions/confirm")
    def confirm_subscription():
        payload = request.get_json(silent=True)
        token = payload.get("token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or len(token) > 128:
            return jsonify({"error": "invalid_confirmation", "message": "This confirmation link is invalid or expired."}), 400
        session = session_factory()
        try:
            subscription = session.query(PublicStatusSubscription).filter_by(
                confirmation_token_hash=_digest(token),
                confirmed=False,
            ).one_or_none()
            now = datetime.now(timezone.utc)
            if (subscription is None or subscription.confirmation_expires_at is None or
                    subscription.confirmation_expires_at.replace(tzinfo=timezone.utc) < now):
                return jsonify({"error": "invalid_confirmation", "message": "This confirmation link is invalid or expired."}), 400
            subscription.confirmed = True
            subscription.confirmed_at = now
            subscription.confirmation_token_hash = None
            subscription.confirmation_expires_at = None
            session.commit()
            return jsonify({"message": "Your PesaGuard status email subscription is confirmed."}), 200
        except Exception:
            session.rollback()
            current_app.logger.exception("Unable to confirm a public status subscription.")
            return jsonify({"error": "confirmation_unavailable", "message": "The subscription could not be confirmed."}), 503
        finally:
            session.close()

    @blueprint.post("/public/status/subscriptions/unsubscribe")
    def unsubscribe():
        payload = request.get_json(silent=True)
        token = payload.get("token") if isinstance(payload, dict) else None
        subscription_id = _valid_unsubscribe_token(token) if isinstance(token, str) and len(token) <= 128 else None
        if subscription_id is None:
            return jsonify({"error": "invalid_unsubscribe", "message": "This unsubscribe link is invalid."}), 400
        session = session_factory()
        try:
            subscription = session.get(PublicStatusSubscription, subscription_id)
            if subscription is not None:
                session.delete(subscription)
                session.commit()
            return jsonify({"message": "This email address has been unsubscribed from status updates."}), 200
        except Exception:
            session.rollback()
            current_app.logger.exception("Unable to remove a public status subscription.")
            return jsonify({"error": "unsubscribe_unavailable", "message": "The subscription could not be removed."}), 503
        finally:
            session.close()

    @blueprint.post("/public/status/monitor")
    def monitor_status():
        expected_token = os.getenv("PESAGUARD_STATUS_MONITOR_TOKEN", "")
        supplied = request.headers.get("Authorization", "")
        if len(expected_token) < 32:
            return jsonify({"error": "monitor_not_configured"}), 503
        if not supplied.startswith("Bearer ") or not hmac.compare_digest(
                supplied[7:].strip(), expected_token):
            return jsonify({"error": "unauthorized"}), 401

        try:
            payload = build_public_status_payload(health_payload_provider())
            fingerprint = _fingerprint(payload)
            session = session_factory()
            sent_count = 0
            failed_count = 0
            try:
                subscribers = session.query(PublicStatusSubscription).filter_by(confirmed=True).all()
                for subscriber in subscribers:
                    if subscriber.last_status_fingerprint is None:
                        subscriber.last_status_fingerprint = fingerprint
                        continue
                    if subscriber.last_status_fingerprint == fingerprint:
                        continue

                    unsubscribe_url = (
                        f"{STATUS_SITE_URL}?unsubscribe={_unsubscribe_token(subscriber.id)}"
                    )
                    lines = [
                        f"Status: {payload['overall']['label']}",
                        f"Updated: {payload['lastUpdated']}",
                        "",
                        "Covered services:",
                    ]
                    lines.extend(
                        f"- {service['name']}: {service['status']}"
                        for service in payload["services"]
                    )
                    lines.extend(["", f"Manage this subscription: {unsubscribe_url}"])
                    text = "\n".join(lines)
                    html_services = "".join(
                        f"<li>{service['name']}: {service['status']}</li>"
                        for service in payload["services"]
                    )
                    html = (
                        f"<p>PesaGuard service status changed: <strong>{payload['overall']['label']}</strong></p>"
                        f"<p>Updated: {payload['lastUpdated']}</p>"
                        f"<ul>{html_services}</ul>"
                        f'<p><a href="{unsubscribe_url}">Unsubscribe from status emails</a></p>'
                    )
                    sent, error = send_email(
                        subscriber.email,
                        f"PesaGuard status update: {payload['overall']['label']}",
                        text,
                        html,
                    )
                    if sent:
                        subscriber.last_status_fingerprint = fingerprint
                        sent_count += 1
                    else:
                        failed_count += 1
                        current_app.logger.error(
                            "Public status change email delivery failed for subscription id=%s: %s",
                            subscriber.id,
                            error,
                        )
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()
            if failed_count:
                return jsonify({
                    "status": "partial_failure",
                    "emails_sent": sent_count,
                    "emails_failed": failed_count,
                }), 502
            return jsonify({"status": "ok", "emails_sent": sent_count}), 200
        except Exception:
            current_app.logger.exception("Public status monitoring job failed.")
            return jsonify({"error": "status_monitor_failed"}), 503

    return blueprint
