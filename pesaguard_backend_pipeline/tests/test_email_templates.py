from email_service import EmailService


def _service() -> EmailService:
    return EmailService(
        smtp_server="smtp.example.invalid",
        from_email="no-reply@pesaguard.co.ke",
        use_tls=True,
    )


def test_reconciliation_email_uses_branded_responsive_layout():
    html = _service()._build_reconciliation_html(
        {
            "total_discrepancies": 18,
            "resolved": 12,
            "pending": 6,
            "sla_compliance": 92,
            "avg_resolution_time": 14,
        },
        locale="en",
    )

    assert "<!doctype html>" in html
    assert 'lang="en"' in html
    assert 'name="viewport"' in html
    assert "PesaGuard" in html
    assert "background-color:#12372b" in html
    assert "Total discrepancies" in html
    assert ">92<span" in html
    assert "14 minutes" in html
    assert "role=\"presentation\"" in html


def test_escalation_email_escapes_untrusted_values_and_formats_decimal_amount():
    html = _service()._build_escalation_html(
        {
            "anomaly_type": "<script>alert(1)</script>",
            "severity": "high",
            "amount": "9007199254740992.01",
            "trans_id": 'txn-" onmouseover="alert(1)',
            "detected_at": "2026-07-04T00:00:00Z",
        },
        locale="en",
    )

    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "txn-&quot; onmouseover=&quot;alert(1)" in html
    assert "KES 9,007,199,254,740,992.01" in html
    assert 'background-color:#fff0ef' in html
    assert "04 Jul 2026, 03:00 EAT" in html


def test_summary_email_renders_swahili_labels_and_escapes_values():
    html = _service()._build_summary_html(
        {
            "total_incidents": '<img src=x onerror="alert(1)">',
            "resolved_today": 3,
            "pending": 2,
        },
        locale="sw",
    )

    assert 'lang="sw"' in html
    assert "Muhtasari wa Kila Siku" in html
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in html
    assert "<img src=x" not in html
    assert "Zilizotatuliwa Leo" in html


def test_account_notice_and_generic_email_use_branded_shell(monkeypatch):
    service = _service()
    sent = {}

    def capture(recipient, subject, html_content, text_content=None):
        sent.update(
            recipient=recipient,
            subject=subject,
            html=html_content,
            text=text_content,
        )
        return True, None

    monkeypatch.setattr(service, "_send_email", capture)
    message = 'Your verification code is <123456>.'

    assert service.send_email("user@example.test", "Account verification", "<p>Confirm your email.</p>", "Confirm your email.") == (True, None)
    assert 'data-pesaguard-email-shell="1"' in sent["html"]
    assert "<p>Confirm your email.</p>" in sent["html"]
    assert sent["text"] == "Confirm your email."
    assert message not in service.build_notice_html("Verify account", message)
    assert "&lt;123456&gt;" in service.build_notice_html("Verify account", message)


def test_discrepancy_alert_email_is_branded_and_escapes_provider_values():
    from notifier import _format_alert_html

    html = _format_alert_html(
        {
            "trans_id": 'transaction<svg onload="alert(1)">',
            "severity": "critical",
            "anomaly_type": "<script>alert(1)</script>",
            "amount": "1200.25",
            "detected_at": "2026-07-04T00:00:00Z",
        },
    )

    assert 'data-pesaguard-email-shell="1"' in html
    assert "PESAGUARD ALERT" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;svg onload=&quot;alert(1)&quot;&gt;" in html
    assert "<script>" not in html
