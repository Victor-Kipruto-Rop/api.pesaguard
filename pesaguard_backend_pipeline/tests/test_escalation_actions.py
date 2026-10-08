import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, "pesaguard_backend_pipeline")

from escalation_engine import EscalationEngine
from models import Base, Discrepancy


def build_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    return Session()


def test_webhook_action_triggers_http_post(monkeypatch):
    # _trigger_webhook now refuses to send unless it can HMAC-sign the payload.
    monkeypatch.setenv("WEBHOOK_SECRET_KEY", "test-webhook-secret-key")
    # _validate_webhook_url does a real DNS lookup as part of its SSRF check, and
    # example.test (RFC 2606) is guaranteed never to resolve -- by design, not a
    # bug. This test is about the signed POST the action makes, not the SSRF
    # guard (which has no dedicated test coverage of its own yet), so stub the
    # guard out rather than depend on live DNS resolution succeeding in CI.
    monkeypatch.setattr("escalation_engine._validate_webhook_url", lambda url: None)
    session = build_session()
    incident = Discrepancy(
        id="inc-1",
        trans_id="txn-1",
        tenant_id="tenant-a",
        anomaly_type="double_charge",
        severity="critical",
        details="Possible duplicate transfer",
        status="needs_review",
    )
    session.add(incident)
    session.commit()

    engine = EscalationEngine(session)
    engine.create_rule(
        tenant_id="tenant-a",
        name="Critical webhook",
        description="Notify external system",
        condition_field="severity",
        condition_operator="equals",
        condition_value="critical",
        action="webhook",
        webhook_url="https://example.test/hook",
        priority=10,
    )

    calls = []

    class DummyResponse:
        status_code = 200
        text = "ok"

    def fake_post(url, json=None, headers=None, timeout=None, allow_redirects=True):
        calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout, "allow_redirects": allow_redirects})
        return DummyResponse()

    # The URL validator is covered separately. This unit isolates the action's
    # request construction and successful HTTP response handling.
    monkeypatch.setenv("WEBHOOK_SECRET_KEY", "test-webhook-signing-secret")
    monkeypatch.setattr("escalation_engine._validate_webhook_url", lambda url: None)
    monkeypatch.setattr("escalation_engine.requests.post", fake_post)

    result = engine.evaluate_and_escalate("tenant-a", incident)

    assert result["details"][0]["status"] == "webhook_triggered"
    assert calls[0]["url"] == "https://example.test/hook"
    # Redirects must stay disabled: a redirect could otherwise steer the signed
    # payload at a host the SSRF check above never got to see.
    assert calls[0]["allow_redirects"] is False


def test_notify_action_sends_email(monkeypatch, tmp_path):
    session = build_session()
    incident = Discrepancy(
        id="inc-2",
        trans_id="txn-2",
        tenant_id="tenant-a",
        anomaly_type="suspicious_amount",
        severity="critical",
        details="Large transfer above threshold",
        status="needs_review",
    )
    session.add(incident)
    session.commit()

    settings_path = tmp_path / "tenant_settings.json"
    settings_path.write_text(
        '{"default": {"preferred_locale": "en"}, "tenant-a": {"preferred_locale": "sw"}}',
        encoding="utf-8",
    )
    monkeypatch.setenv("TENANT_SETTINGS_FILE", str(settings_path))

    engine = EscalationEngine(session)
    engine.create_rule(
        tenant_id="tenant-a",
        name="High severity email",
        description="Email on-call operator",
        condition_field="severity",
        condition_operator="equals",
        condition_value="critical",
        action="notify",
        target="ops@example.com",
        priority=5,
    )

    calls = []

    class DummyEmailService:
        def __init__(self, *args, **kwargs):
            pass

        def send_escalation_notification(self, session_obj, tenant_id, recipient_email, incident_data, locale=None):
            calls.append({
                "tenant_id": tenant_id,
                "recipient_email": recipient_email,
                "incident_data": incident_data,
                "locale": locale,
            })
            return {"status": "sent"}

    monkeypatch.setattr("escalation_engine.EmailService", DummyEmailService)

    result = engine.evaluate_and_escalate("tenant-a", incident)

    assert result["details"][0]["status"] == "notification_sent"
    assert calls[0]["recipient_email"] == "ops@example.com"
    assert calls[0]["locale"] == "sw"
