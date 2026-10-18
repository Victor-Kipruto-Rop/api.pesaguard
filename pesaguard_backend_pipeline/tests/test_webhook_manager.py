from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import webhook_manager
from models import Base, WebhookConfig, WebhookDelivery


def test_webhook_delivery_history_retains_owner_tenant(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    monkeypatch.setattr(webhook_manager, "_validate_webhook_url", lambda url: None)
    monkeypatch.setattr(
        webhook_manager.requests,
        "post",
        lambda *args, **kwargs: SimpleNamespace(status_code=204, text="", is_redirect=False),
    )

    manager = webhook_manager.WebhookManager(session)
    registration = manager.register_webhook(
        tenant_id="tenant-a",
        url="https://hooks.example.test/events",
        event_types=["payment.reconciled"],
        retry_attempts=1,
        timeout_seconds=2,
    )
    result = manager.trigger_event(
        "tenant-a",
        "payment.reconciled",
        {"transaction_id": "tx-1"},
    )

    assert result["deliveries"][0]["status"] == "success"
    assert registration["signing_secret"].startswith("whsec_")
    stored_webhook = session.query(WebhookConfig).filter_by(id=registration["id"]).one()
    assert stored_webhook.signing_secret.startswith("enc:v1:")
    delivery = session.query(WebhookDelivery).one()
    assert delivery.tenant_id == "tenant-a"
    assert len(manager.get_delivery_history(registration["id"], "tenant-a")) == 1
    assert manager.get_delivery_history(registration["id"], "tenant-b") == []

    session.close()
    engine.dispose()



def test_webhook_url_rejects_userinfo_fragments_and_nonstandard_ports():
    assert webhook_manager._validate_webhook_url(
        "https://user:password@example.com/hooks"
    ) == "url_userinfo_not_allowed"
    assert webhook_manager._validate_webhook_url(
        "https://example.com/hooks#token"
    ) == "url_fragment_not_allowed"
    assert webhook_manager._validate_webhook_url(
        "https://example.com:8443/hooks"
    ) == "url_port_not_allowed"
