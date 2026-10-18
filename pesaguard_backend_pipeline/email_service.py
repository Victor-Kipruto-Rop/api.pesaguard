"""
Enterprise-grade Email Notification and Reconciliation Reporting Service for PesaGuard.
Supports asynchronous thread-pool SMTP delivery, localized multipart HTML/plain-text templates,
and delivery audit logging.
"""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

from email_branding import escape_email_value, render_branded_email
from environment import load_backend_env
from localization_utils import format_ke_currency, format_ke_datetime, normalise_locale
from models import EmailNotification
from sqlalchemy.orm import Session

logger = logging.getLogger("pesaguard.email")


class EmailService:
    """Handles async email dispatch for reconciliation reports, alerts, and summaries."""

    def __init__(
        self,
        smtp_server: Optional[str] = None,
        smtp_port: Optional[int] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: Optional[bool] = None,
        use_ssl: Optional[bool] = None,
        timeout: int = 10,
        max_workers: int = 5,
    ):
        load_backend_env()

        def env_value(*names: str, default: str = "") -> str:
            # Presence, not truthiness: an explicitly empty value must not fall back.
            return next((os.environ[name] for name in names if name in os.environ), default)

        def env_bool(name: str, legacy_name: str, default: bool) -> bool:
            value = env_value(name, legacy_name, default=str(default)).strip().lower()
            if value not in {"true", "false", "1", "0"}:
                raise ValueError(f"{name} must be true or false")
            return value in {"true", "1"}

        self.smtp_server = smtp_server if smtp_server is not None else env_value("SMTP_HOST", "EMAIL_HOST", "SMTP_SERVER")
        self.use_ssl = use_ssl if use_ssl is not None else env_bool("SMTP_USE_SSL", "EMAIL_USE_SSL", False)
        self.use_tls = use_tls if use_tls is not None else env_bool("SMTP_USE_TLS", "EMAIL_USE_TLS", not self.use_ssl)
        try:
            self.smtp_port = int(smtp_port if smtp_port is not None else env_value(
                "SMTP_PORT", "EMAIL_PORT", default="465" if self.use_ssl else "587",
            ))
        except (TypeError, ValueError):
            raise ValueError("SMTP_PORT must be an integer") from None
        if not 1 <= self.smtp_port <= 65535:
            raise ValueError("SMTP_PORT must be between 1 and 65535")
        if self.use_ssl and self.use_tls:
            raise ValueError("Select either SMTP_USE_SSL or SMTP_USE_TLS, not both")
        self.from_email = from_email if from_email is not None else env_value("SMTP_FROM_EMAIL", "EMAIL_FROM")
        self.from_name = from_name if from_name is not None else env_value("SMTP_FROM_NAME", default="PesaGuard")
        self.username = username if username is not None else env_value("SMTP_USERNAME", "EMAIL_USERNAME")
        self.password = password if password is not None else env_value("SMTP_PASSWORD", "EMAIL_PASSWORD")
        self.timeout = timeout
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="pesaguard_email_worker")

    def send_reconciliation_report(
        self,
        session: Session,
        tenant_id: str,
        recipient_email: str,
        report_data: Dict[str, Any],
        locale: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate and dispatch a reconciliation report email."""
        locale_code = normalise_locale(locale)
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if locale_code == "sw":
            subject = f"Ripoti ya Upatanishi ya PesaGuard - {date_str}"
        else:
            subject = f"PesaGuard Reconciliation Report - {date_str}"

        html_content = self._build_reconciliation_html(report_data, locale=locale_code)
        text_content = self._build_reconciliation_text(report_data, locale=locale_code)

        email_record = EmailNotification(
            id=f"email_{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            recipient_email=recipient_email,
            report_type="reconciliation",
            subject=subject,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )

        success, error_msg = self._send_email(
            recipient_email,
            subject,
            html_content,
            text_content,
        )

        if success:
            email_record.status = "sent"
            email_record.sent_at = datetime.now(timezone.utc)
            logger.info("Sent reconciliation report to recipient=%s tenant_id=%s", recipient_email, tenant_id)
        else:
            email_record.status = "failed"
            email_record.error_message = error_msg or "SMTP delivery failed"
            logger.error("Failed sending reconciliation report to recipient=%s: %s", recipient_email, error_msg)

        session.add(email_record)
        session.commit()

        return {
            "id": email_record.id,
            "status": email_record.status,
            "recipient": recipient_email,
            "report_type": "reconciliation",
            "sent_at": email_record.sent_at.isoformat() if email_record.sent_at else None,
            "error": email_record.error_message,
        }

    def send_escalation_notification(
        self,
        session: Session,
        tenant_id: str,
        recipient_email: str,
        incident_data: Dict[str, Any],
        locale: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dispatch a high-priority incident escalation alert."""
        locale_code = normalise_locale(locale)
        anomaly = incident_data.get("anomaly_type", "Unknown")

        if locale_code == "sw":
            subject = f"Tahadhari ya PesaGuard: Kipindi Kilichopandishwa - {anomaly}"
        else:
            subject = f"PesaGuard Alert: Incident Escalated - {anomaly}"

        html_content = self._build_escalation_html(incident_data, locale=locale_code)
        text_content = self._build_escalation_text(incident_data, locale=locale_code)

        email_record = EmailNotification(
            id=f"email_{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            recipient_email=recipient_email,
            report_type="escalation",
            subject=subject,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )

        success, error_msg = self._send_email(
            recipient_email,
            subject,
            html_content,
            text_content,
        )

        if success:
            email_record.status = "sent"
            email_record.sent_at = datetime.now(timezone.utc)
            logger.info("Sent escalation alert to recipient=%s tenant_id=%s", recipient_email, tenant_id)
        else:
            email_record.status = "failed"
            email_record.error_message = error_msg or "SMTP delivery failed"
            logger.error("Failed sending escalation alert to recipient=%s: %s", recipient_email, error_msg)

        session.add(email_record)
        session.commit()

        return {
            "id": email_record.id,
            "status": email_record.status,
            "recipient": recipient_email,
            "error": email_record.error_message,
        }

    def send_daily_summary(
        self,
        session: Session,
        tenant_id: str,
        recipient_email: str,
        summary_data: Dict[str, Any],
        locale: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dispatch a daily operations telemetry summary."""
        locale_code = normalise_locale(locale)
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if locale_code == "sw":
            subject = f"Muhtasari wa Kila Siku wa PesaGuard - {date_str}"
        else:
            subject = f"PesaGuard Daily Summary - {date_str}"

        html_content = self._build_summary_html(summary_data, locale=locale_code)
        text_content = self._build_summary_text(summary_data, locale=locale_code)

        email_record = EmailNotification(
            id=f"email_{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            recipient_email=recipient_email,
            report_type="daily_summary",
            subject=subject,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )

        success, error_msg = self._send_email(
            recipient_email,
            subject,
            html_content,
            text_content,
        )

        if success:
            email_record.status = "sent"
            email_record.sent_at = datetime.now(timezone.utc)
        else:
            email_record.status = "failed"
            email_record.error_message = error_msg or "SMTP delivery failed"

        session.add(email_record)
        session.commit()

        return {
            "id": email_record.id,
            "status": email_record.status,
            "recipient": recipient_email,
            "error": email_record.error_message,
        }

    def configuration_error(self) -> Optional[str]:
        """Validate delivery configuration without opening a connection."""
        if not self.smtp_server.strip() or not self.from_email.strip():
            return "SMTP configuration missing: SMTP_HOST and SMTP_FROM_EMAIL are required"
        if bool(self.username) != bool(self.password):
            return "SMTP credentials must include both username and password"
        if not (self.use_tls or self.use_ssl):
            return "SMTP delivery requires TLS"
        return None

    def send_email(
        self,
        recipient_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        """Send a general transactional email through the configured SMTP transport."""
        if 'data-pesaguard-email-shell="1"' not in html_content:
            html_content = self._branded_email(
                subject,
                "A PesaGuard account update.",
                html_content,
                "en",
            )
        return self._send_email(recipient_email, subject, html_content, text_content)

    @staticmethod
    def _email_text(value: Any) -> str:
        return escape_email_value(value)

    def build_notice_html(self, title: str, message: str) -> str:
        """Render a short account notice in the shared email design."""
        content = (
            '<p style="margin:0;color:#44534a;font-size:15px;line-height:1.7;">'
            f"{self._email_text(message)}</p>"
        )
        return self._branded_email(
            title,
            "A secure update for your PesaGuard account.",
            content,
            "en",
        )

    def _branded_email(self, title: str, preheader: str, content: str, locale: str) -> str:
        return render_branded_email(title, preheader, content, locale)

    def _send_email(
        self,
        recipient_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        """Synchronous SMTP transport helper; never expose provider responses."""
        error = self.configuration_error()
        if error:
            logger.error("%s", error)
            return False, error
        phase = "message_build"
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = recipient_email

            if text_content:
                msg.attach(MIMEText(text_content, "plain", "utf-8"))
            msg.attach(MIMEText(html_content, "html", "utf-8"))

            phase = "connection"
            if self.use_ssl:
                server = smtplib.SMTP_SSL(
                    self.smtp_server, self.smtp_port, timeout=self.timeout,
                    context=ssl.create_default_context(),
                )
            else:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=self.timeout)

            with server:
                if self.use_tls and not self.use_ssl:
                    phase = "starttls"
                    server.starttls(context=ssl.create_default_context())
                if self.username and self.password:
                    phase = "authentication"
                    server.login(self.username, self.password)
                phase = "submission"
                if server.send_message(msg):
                    logger.error("SMTP recipients refused")
                    return False, "SMTP recipients refused"

            return True, None
        except Exception as exc:
            code = getattr(exc, "smtp_code", None)
            logger.error(
                "SMTP delivery failed phase=%s error_type=%s smtp_code=%s",
                phase, type(exc).__name__, code if isinstance(code, int) else "unavailable",
            )
            return False, "SMTP delivery failed"

    def _build_reconciliation_html(self, data: Dict[str, Any], locale: str) -> str:
        if locale == "sw":
            title = "Ripoti ya Upatanishi"
            total_label = "Tofauti zote"
            resolved_label = "Zilizotatuliwa"
            pending_label = "Zinazosubiri"
            sla_label = "Utekelezaji wa SLA"
            avg_label = "Wakati wa Wastani wa Utatuzi"
            preheader = "Muhtasari wa upatanishi na hatua zinazohitaji uangalizi."
            minutes_suffix = "dakika"
        else:
            title = "Reconciliation Report"
            total_label = "Total discrepancies"
            resolved_label = "Resolved"
            pending_label = "Pending"
            sla_label = "SLA performance"
            avg_label = "Average resolution time"
            preheader = "A concise view of reconciliation progress and outstanding work."
            minutes_suffix = "minutes"

        total = self._email_text(data.get("total_discrepancies", 0))
        resolved = self._email_text(data.get("resolved", 0))
        pending = self._email_text(data.get("pending", 0))
        sla = self._email_text(data.get("sla_compliance", "N/A"))
        average = self._email_text(data.get("avg_resolution_time", "N/A"))
        content = f"""
            <p style="margin:0 0 20px;color:#58675e;font-size:15px;line-height:1.65;">{"Huu hapa muhtasari wa hivi karibuni wa upatanishi wako." if locale == "sw" else "Here is your latest reconciliation overview."}</p>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:separate;border-spacing:0;">
                <tr>
                    <td width="50%" style="padding:16px;background-color:#f5f8f6;border:1px solid #e4ebe6;border-radius:12px;">
                        <p style="margin:0;color:#69776e;font-size:12px;">{total_label}</p>
                        <p style="margin:8px 0 0;color:#17231d;font-size:26px;font-weight:700;line-height:1.1;">{total}</p>
                    </td>
                    <td width="12"></td>
                    <td width="50%" style="padding:16px;background-color:#f1f7f3;border:1px solid #dce9e0;border-radius:12px;">
                        <p style="margin:0;color:#4f705c;font-size:12px;">{resolved_label}</p>
                        <p style="margin:8px 0 0;color:#23623f;font-size:26px;font-weight:700;line-height:1.1;">{resolved}</p>
                    </td>
                </tr>
                <tr><td colspan="3" height="12" style="height:12px;"></td></tr>
                <tr>
                    <td width="50%" style="padding:16px;background-color:#fff8ee;border:1px solid #f1e5d2;border-radius:12px;">
                        <p style="margin:0;color:#836b4c;font-size:12px;">{pending_label}</p>
                        <p style="margin:8px 0 0;color:#80561c;font-size:26px;font-weight:700;line-height:1.1;">{pending}</p>
                    </td>
                    <td width="12"></td>
                    <td width="50%" style="padding:16px;background-color:#f5f8f6;border:1px solid #e4ebe6;border-radius:12px;">
                        <p style="margin:0;color:#69776e;font-size:12px;">{sla_label}</p>
                        <p style="margin:8px 0 0;color:#17231d;font-size:26px;font-weight:700;line-height:1.1;">{sla}<span style="font-size:15px;font-weight:400;">%</span></p>
                    </td>
                </tr>
            </table>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;margin-top:22px;border-top:1px solid #e8ede9;">
                <tr>
                    <td style="padding:16px 0;color:#65736a;font-size:13px;">{avg_label}</td>
                    <td align="right" style="padding:16px 0;color:#26352c;font-size:13px;font-weight:700;">{average} {minutes_suffix}</td>
                </tr>
            </table>
            <p style="margin:12px 0 0;color:#849087;font-size:11px;line-height:1.5;">{"Imetayarishwa" if locale == "sw" else "Prepared"} {datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")}</p>"""
        return self._branded_email(title, preheader, content, locale)

    def _build_reconciliation_text(self, data: Dict[str, Any], locale: str) -> str:
        if locale == "sw":
            return f"RIPOTI YA UPATANISHI\nTofauti Zote: {data.get('total_discrepancies', 0)}\nZilizotatuliwa: {data.get('resolved', 0)}\nZinazosubiri: {data.get('pending', 0)}"
        return f"RECONCILIATION REPORT\nTotal Discrepancies: {data.get('total_discrepancies', 0)}\nResolved: {data.get('resolved', 0)}\nPending: {data.get('pending', 0)}"

    def _build_escalation_html(self, incident_data: Dict[str, Any], locale: str) -> str:
        if locale == "sw":
            title = "Kipindi kilichopandishwa"
            anomaly_label = "Aina ya Usumbufu"
            severity_label = "Ukali"
            amount_label = "Kiasi"
            trans_label = "Kitambulisho cha Muamala"
            detected_label = "Iligunduliwa Saa"
            action_text = "Msaada wa utendaji: Tafadhali kagua tukio hili na uchukue hatua inayofaa."
            preheader = "Tukio limeongezwa kipaumbele na linahitaji ukaguzi wako."
        else:
            title = "Incident Escalated"
            anomaly_label = "Anomaly Type"
            severity_label = "Severity"
            amount_label = "Amount"
            trans_label = "Transaction reference"
            detected_label = "Detected At"
            action_text = "Please review and take appropriate action immediately."
            preheader = "An escalated incident needs your attention."

        raw_amount = incident_data.get("amount")
        amount_value = format_ke_currency(raw_amount) if raw_amount is not None else "N/A"

        detected_raw = incident_data.get("detected_at", "N/A")
        detected_value = format_ke_datetime(detected_raw) if detected_raw != "N/A" else "N/A"
        raw_severity = str(incident_data.get("severity", "Unknown"))
        severity = self._email_text(raw_severity.upper())
        severity_key = raw_severity.strip().lower()
        severity_color, severity_background = {
            "critical": ("#a72d2d", "#fff0ef"),
            "high": ("#a72d2d", "#fff0ef"),
            "medium": ("#80561c", "#fff7e9"),
            "low": ("#23623f", "#eff7f1"),
        }.get(severity_key, ("#526158", "#f2f5f3"))
        details = (
            (anomaly_label, incident_data.get("anomaly_type", "Unknown")),
            (amount_label, amount_value),
            (trans_label, incident_data.get("trans_id", "N/A")),
            (detected_label, detected_value or "N/A"),
        )
        detail_rows = "".join(
            f"""<tr>
                <td style="padding:13px 0;color:#65736a;font-size:13px;border-bottom:1px solid #e8ede9;">{self._email_text(label)}</td>
                <td align="right" style="padding:13px 0;color:#26352c;font-size:13px;font-weight:700;border-bottom:1px solid #e8ede9;">{self._email_text(value)}</td>
            </tr>"""
            for label, value in details
        )
        content = f"""
            <p style="margin:0 0 18px;color:#58675e;font-size:15px;line-height:1.65;">{self._email_text(action_text)}</p>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;padding:18px 20px;background-color:#fbfcfb;border:1px solid #e4ebe6;border-radius:12px;">
                <tr>
                    <td style="padding:0 0 13px;color:#65736a;font-size:13px;">{severity_label}</td>
                    <td align="right" style="padding:0 0 13px;"><span style="display:inline-block;padding:6px 10px;background-color:{severity_background};border-radius:20px;color:{severity_color};font-size:11px;font-weight:700;letter-spacing:.6px;">{severity}</span></td>
                </tr>
                {detail_rows}
            </table>"""
        return self._branded_email(title, preheader, content, locale)

    def _build_escalation_text(self, incident_data: Dict[str, Any], locale: str) -> str:
        return f"INCIDENT ESCALATED\nType: {incident_data.get('anomaly_type')}\nSeverity: {incident_data.get('severity')}\nTransID: {incident_data.get('trans_id')}"

    def _build_summary_html(self, summary_data: Dict[str, Any], locale: str) -> str:
        if locale == "sw":
            title = "Muhtasari wa Kila Siku"
            total_label = "Matukio Yote"
            resolved_label = "Zilizotatuliwa Leo"
            pending_label = "Zinazosubiri"
        else:
            title = "Daily Summary"
            total_label = "Total Incidents"
            resolved_label = "Resolved Today"
            pending_label = "Pending"

        preheader = (
            "Muhtasari wa shughuli za leo na matukio yanayosubiri."
            if locale == "sw"
            else "A clear daily snapshot of activity and outstanding incidents."
        )
        metrics = (
            (total_label, self._email_text(summary_data.get("total_incidents", 0)), "#17231d", "#f5f8f6"),
            (resolved_label, self._email_text(summary_data.get("resolved_today", 0)), "#23623f", "#f1f7f3"),
            (pending_label, self._email_text(summary_data.get("pending", 0)), "#80561c", "#fff8ee"),
        )
        metric_cards = "".join(
            f"""<td width="33.33%" valign="top" style="padding:16px 12px;background-color:{background};border:1px solid #e4ebe6;border-radius:12px;">
                <p style="margin:0;color:#69776e;font-size:12px;line-height:1.45;">{self._email_text(label)}</p>
                <p style="margin:10px 0 0;color:{color};font-size:26px;font-weight:700;line-height:1;">{value}</p>
            </td>"""
            for label, value, color, background in metrics
        )
        content = f"""
            <p style="margin:0 0 20px;color:#58675e;font-size:15px;line-height:1.65;">{"Huu hapa muhtasari wa shughuli zako za kila siku." if locale == "sw" else "Here is your daily operations snapshot."}</p>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:separate;border-spacing:8px 0;">
                <tr>{metric_cards}</tr>
            </table>
            <p style="margin:22px 0 0;color:#849087;font-size:11px;line-height:1.5;">{"Tarehe" if locale == "sw" else "Report date"}: {datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")}</p>"""
        return self._branded_email(title, preheader, content, locale)

    def _build_summary_text(self, summary_data: Dict[str, Any], locale: str) -> str:
        return f"DAILY SUMMARY\nTotal: {summary_data.get('total_incidents', 0)}\nResolved Today: {summary_data.get('resolved_today', 0)}\nPending: {summary_data.get('pending', 0)}"

    def get_email_history(
        self,
        session: Session,
        tenant_id: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Retrieve historical email notification delivery records for a given tenant."""
        emails = (
            session.query(EmailNotification)
            .filter(EmailNotification.tenant_id == tenant_id)
            .order_by(EmailNotification.created_at.desc())
            .limit(min(limit, 200))
            .all()
        )
        return [
            {
                "id": e.id,
                "recipient": e.recipient_email,
                "report_type": e.report_type,
                "status": e.status,
                "error_message": e.error_message,
                "created_at": e.created_at.isoformat() if e.created_at else None,
                "sent_at": e.sent_at.isoformat() if e.sent_at else None,
            }
            for e in emails
        ]
