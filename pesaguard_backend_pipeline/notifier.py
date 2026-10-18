"""
Multi-channel alerting engine for PesaGuard discrepancy notifications.

Supports Slack webhooks, Africa's Talking SMS, and SMTP Email dispatch with configurable
exponential backoff retries, localized templates (English/Swahili), and structured logs.
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from email.message import EmailMessage
from typing import Any, Dict, Optional

try:
    from africas_talking import AfricasTalkingClient
    HAS_AFRICAS_TALKING = True
except ImportError:
    HAS_AFRICAS_TALKING = False

from alert_template_loader import load_alert_fields, render_message_template
from email_branding import escape_email_value, render_branded_email
from localization_utils import format_ke_currency, format_ke_datetime, normalise_locale

logger = logging.getLogger("pesaguard.alerting")

# Environment configurations
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
SMS_RECIPIENT = os.getenv("SMS_ALERT_RECIPIENT", "")
EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", "no-reply@pesaguard.co.ke")
SMTP_HOST = os.getenv("ALERT_SMTP_HOST")
SMTP_PORT = int(os.getenv("ALERT_SMTP_PORT", "25"))
SMTP_USER = os.getenv("ALERT_SMTP_USER")
SMTP_PASS = os.getenv("ALERT_SMTP_PASS")

# Retry configuration defaults
SLACK_RETRIES = int(os.getenv("ALERT_SLACK_RETRIES", "2"))
SMS_RETRIES = int(os.getenv("ALERT_SMS_RETRIES", "2"))
EMAIL_RETRIES = int(os.getenv("ALERT_EMAIL_RETRIES", "3"))
RETRY_BACKOFF_SECONDS = float(os.getenv("ALERT_RETRY_BACKOFF_SECONDS", "1.0"))

sms_client = AfricasTalkingClient() if HAS_AFRICAS_TALKING else None


def send_slack_alert(discrepancy: Dict[str, Any], locale: str = "en", max_retries: int = SLACK_RETRIES) -> bool:
    """Send alert payload to Slack via webhook with exponential retries.

    Args:
        discrepancy: Discrepancy anomaly dictionary
        locale: Message locale code ('en' or 'sw')
        max_retries: Maximum retry attempts on network error

    Returns:
        True if delivered successfully, False otherwise
    """
    if not SLACK_WEBHOOK_URL:
        logger.warning("SLACK_WEBHOOK_URL is not set; skipping Slack alert dispatch for trans_id=%s", discrepancy.get("trans_id"))
        return False
    try:
        webhook_url = urlsplit(SLACK_WEBHOOK_URL)
        webhook_port = webhook_url.port
    except ValueError:
        logger.error("Slack webhook URL is malformed.")
        return False
    if (
        webhook_url.scheme != "https"
        or webhook_url.hostname != "hooks.slack.com"
        or webhook_port not in (None, 443)
        or webhook_url.username
        or webhook_url.password
        or webhook_url.query
        or webhook_url.fragment
    ):
        logger.error("Slack webhook URL must target hooks.slack.com over HTTPS without credentials.")
        return False

    trans_id = discrepancy.get("trans_id", "unknown")
    tenant_id = discrepancy.get("tenant_id", "default")

    text = _format_slack_alert_text(discrepancy, locale=locale)
    body = json.dumps({"text": text}).encode("utf-8")

    for attempt in range(max_retries + 1):
        try:
            req = urllib.request.Request(
                SLACK_WEBHOOK_URL,
                data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310: HTTPS Slack hostname and port are allowlisted above.
                if resp.status == 200:
                    logger.info("Slack alert sent successfully trans_id=%s tenant_id=%s", trans_id, tenant_id)
                    return True
                
                logger.error("Slack alert failed with status %d (attempt %d/%d)", resp.status, attempt + 1, max_retries + 1)
        except urllib.error.URLError as e:
            if attempt < max_retries:
                backoff = RETRY_BACKOFF_SECONDS * (2 ** attempt)
                logger.warning(
                    "Slack alert delivery failed (attempt %d/%d): %s. Retrying in %.1fs...",
                    attempt + 1, max_retries + 1, e, backoff
                )
                time.sleep(backoff)
            else:
                logger.error("Slack alert delivery failed after %d attempts: %s", max_retries + 1, e)
                return False
        except Exception as e:
            logger.exception("Unexpected error dispatching Slack alert for trans_id=%s: %s", trans_id, e)
            return False

    return False


def send_sms_alert(discrepancy: Dict[str, Any], locale: str = "en", max_retries: int = SMS_RETRIES) -> bool:
    """Send alert via Africa's Talking SMS API with exponential retries.

    Args:
        discrepancy: Discrepancy anomaly dictionary
        locale: Message locale
        max_retries: Maximum retry attempts

    Returns:
        True if delivered successfully, False otherwise
    """
    recipient = os.getenv("SMS_ALERT_RECIPIENT", SMS_RECIPIENT)
    trans_id = discrepancy.get("trans_id", "unknown")
    tenant_id = discrepancy.get("tenant_id", "default")

    if not recipient:
        logger.debug("SMS_ALERT_RECIPIENT not configured; skipping SMS dispatch.")
        return False

    if not sms_client:
        logger.error("Africa's Talking client unavailable (package not installed or uninitialized).")
        return False

    message = _format_sms_alert_text(discrepancy, locale=locale)

    for attempt in range(max_retries + 1):
        try:
            sms_client.send_sms(recipient, message)
            logger.info("SMS alert sent successfully trans_id=%s recipient=%s", trans_id, recipient)
            return True
        except Exception as e:
            if attempt < max_retries:
                backoff = RETRY_BACKOFF_SECONDS * (2 ** attempt)
                logger.warning(
                    "SMS alert delivery failed (attempt %d/%d): %s. Retrying in %.1fs...",
                    attempt + 1, max_retries + 1, e, backoff
                )
                time.sleep(backoff)
            else:
                logger.error("SMS alert delivery failed after %d attempts: %s", max_retries + 1, e)
                return False

    return False


def send_email_alert(discrepancy: Dict[str, Any], locale: str = "en", max_retries: int = EMAIL_RETRIES) -> bool:
    """Send alert via SMTP with retries on network failures.

    Args:
        discrepancy: Discrepancy anomaly dictionary
        locale: Message locale
        max_retries: Maximum retry attempts

    Returns:
        True if delivered successfully, False otherwise
    """
    recipients = os.getenv("ALERT_EMAIL_RECIPIENTS")
    trans_id = discrepancy.get("trans_id", "unknown")
    tenant_id = discrepancy.get("tenant_id", "default")

    if not recipients or not SMTP_HOST:
        logger.debug("Email SMTP host or recipient configuration missing; skipping email dispatch.")
        return False

    message_text = _format_alert_text(discrepancy, locale=locale)
    msg = EmailMessage()
    msg["Subject"] = f"PesaGuard Alert: {str(discrepancy.get('severity', 'alert')).upper()} - {trans_id}"
    msg["From"] = EMAIL_FROM
    msg["To"] = recipients
    msg.set_content(message_text)
    msg.add_alternative(_format_alert_html(discrepancy, locale=locale), subtype="html")

    for attempt in range(max_retries + 1):
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as s:
                if SMTP_USER and SMTP_PASS:
                    s.starttls()
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
            logger.info("Email alert sent successfully trans_id=%s recipients=%s", trans_id, recipients)
            return True
        except smtplib.SMTPException as e:
            if attempt < max_retries:
                backoff = RETRY_BACKOFF_SECONDS * (2 ** attempt)
                logger.warning(
                    "Email alert delivery failed (attempt %d/%d): %s. Retrying in %.1fs...",
                    attempt + 1, max_retries + 1, e, backoff
                )
                time.sleep(backoff)
            else:
                logger.error("Email alert delivery failed after %d attempts: %s", max_retries + 1, e)
                return False
        except Exception as e:
            logger.exception("Unexpected error sending email alert trans_id=%s: %s", trans_id, e)
            return False

    return False


def _template_context(discrepancy: Dict[str, Any]) -> Dict[str, Any]:
    anomalies = discrepancy.get("anomalies", [])
    anomaly_type = (
        ", ".join(anomalies)
        if isinstance(anomalies, list) and anomalies
        else discrepancy.get("anomaly_type") or "discrepancy"
    )
    amount = discrepancy.get("amount") or discrepancy.get("amount_value")
    return {
        "tenant_name": discrepancy.get("tenant_name") or discrepancy.get("tenant_id") or "default",
        "anomaly_type": anomaly_type,
        "amount": format_ke_currency(amount) if amount is not None else "N/A",
        "summary": ", ".join(anomalies) if isinstance(anomalies, list) else discrepancy.get("status") or "needs_review",
        "trans_id": discrepancy.get("trans_id", discrepancy.get("TransID", "unknown")),
        "severity": discrepancy.get("severity", "warning"),
        "status": discrepancy.get("status", "needs_review"),
    }


def _format_sms_alert_text(discrepancy: Dict[str, Any], locale: str = "en") -> str:
    locale_code = normalise_locale(locale)
    template_name = f"sms_template_{locale_code}.md"
    rendered = render_message_template(template_name, _template_context(discrepancy))
    if rendered:
        return rendered
    return _format_alert_text(discrepancy, locale=locale)


def _format_slack_alert_text(discrepancy: Dict[str, Any], locale: str = "en") -> str:
    locale_code = normalise_locale(locale)
    template_name = f"slack_template_{locale_code}.md"
    rendered = render_message_template(template_name, _template_context(discrepancy))
    if rendered:
        return rendered
    return _format_alert_text(discrepancy, locale=locale)


def _format_alert_text(discrepancy: Dict[str, Any], locale: str = "en") -> str:
    trans_id = discrepancy.get("trans_id", discrepancy.get("TransID", "unknown"))
    anomalies = discrepancy.get("anomalies", [])
    severity = discrepancy.get("severity", "warning")
    status = discrepancy.get("status", "needs_review")
    locale_code = normalise_locale(locale)
    template = load_alert_fields(locale_code)
    
    issues = ", ".join(anomalies) if isinstance(anomalies, list) and anomalies else (discrepancy.get("anomaly_type") or template.get("no_issues", "None"))
    detected_at = discrepancy.get("checked_at") or discrepancy.get("detected_at") or discrepancy.get("timestamp") or discrepancy.get("created_at") or "unknown"
    detected_at_display = format_ke_datetime(detected_at) or str(detected_at)
    
    amount = discrepancy.get("amount") or discrepancy.get("amount_value")
    amount_line = ""
    if amount is not None:
        amount_line = f"\n{template.get('amount', 'Amount')}: {format_ke_currency(amount)}"

    return (
        f":rotating_light: {template.get('title', 'PesaGuard Alert')}\n"
        f"{template.get('transaction', 'Transaction')}: `{trans_id}`\n"
        f"{template.get('severity', 'Severity')}: `{severity}`\n"
        f"{template.get('status', 'Status')}: `{status}`\n"
        f"{template.get('issues', 'Issues')}: {issues}\n"
        f"{template.get('detected_at', 'Detected At')}: {detected_at_display}"
        f"{amount_line}"
    )


def _format_alert_html(discrepancy: Dict[str, Any], locale: str = "en") -> str:
    """Render discrepancy alerts with the shared premium PesaGuard email styling."""
    locale_code = normalise_locale(locale)
    fields = load_alert_fields(locale_code)
    context = _template_context(discrepancy)
    detected_at = (
        discrepancy.get("checked_at")
        or discrepancy.get("detected_at")
        or discrepancy.get("timestamp")
        or discrepancy.get("created_at")
        or "unknown"
    )
    detected_at_display = format_ke_datetime(detected_at) or str(detected_at)
    severity_key = str(context["severity"]).strip().lower()
    severity_color, severity_background = {
        "critical": ("#a72d2d", "#fff0ef"),
        "high": ("#a72d2d", "#fff0ef"),
        "medium": ("#80561c", "#fff7e9"),
        "low": ("#23623f", "#eff7f1"),
    }.get(severity_key, ("#526158", "#f2f5f3"))
    details = [
        (fields.get("transaction", "Transaction"), context["trans_id"]),
        (fields.get("status", "Status"), context["status"]),
        (fields.get("issues", "Issues"), context["anomaly_type"]),
        (fields.get("detected_at", "Detected at"), detected_at_display),
    ]
    amount = discrepancy.get("amount")
    if amount is None:
        amount = discrepancy.get("amount_value")
    if amount is not None:
        details.append((fields.get("amount", "Amount"), format_ke_currency(amount)))

    rows = "".join(
        f"""<tr>
            <td style="padding:13px 0;color:#65736a;font-size:13px;border-bottom:1px solid #e8ede9;">{escape_email_value(label)}</td>
            <td align="right" style="padding:13px 0;color:#26352c;font-size:13px;font-weight:700;border-bottom:1px solid #e8ede9;">{escape_email_value(value)}</td>
        </tr>"""
        for label, value in details
    )
    title = fields.get("title", "PesaGuard discrepancy detected")
    subtitle = (
        "Tukio hili linahitaji ukaguzi wako."
        if locale_code == "sw"
        else "This item needs your review."
    )
    content = f"""
        <p style="margin:0 0 18px;color:#58675e;font-size:15px;line-height:1.65;">{escape_email_value(subtitle)}</p>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;padding:18px 20px;background-color:#fbfcfb;border:1px solid #e4ebe6;border-radius:12px;">
            <tr>
                <td style="padding:0 0 13px;color:#65736a;font-size:13px;">{escape_email_value(fields.get("severity", "Severity"))}</td>
                <td align="right" style="padding:0 0 13px;"><span style="display:inline-block;padding:6px 10px;background-color:{severity_background};border-radius:20px;color:{severity_color};font-size:11px;font-weight:700;letter-spacing:.6px;">{escape_email_value(str(context["severity"]).upper())}</span></td>
            </tr>
            {rows}
        </table>"""
    return render_branded_email(
        str(title),
        subtitle,
        content,
        locale_code,
        eyebrow="PESAGUARD ALERT",
    )
