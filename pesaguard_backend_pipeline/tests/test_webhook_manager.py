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
        webhook_manager,
        "post_json_pinned",
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
        {"transaction_id": "tx-1", "msisdn": "254700000000"},
    )

    assert result["deliveries"][0]["status"] == "success"
    assert registration["signing_secret"].startswith("whsec_")
    stored_webhook = session.query(WebhookConfig).filter_by(id=registration["id"]).one()
    assert stored_webhook.signing_secret.startswith("enc:v1:")
    delivery = session.query(WebhookDelivery).one()
    assert delivery.tenant_id == "tenant-a"
    assert delivery.response_body == ""
    assert delivery.payload["msisdn"].startswith("enc:v1:")
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



def test_webhook_url_rejects_private_dns_answers(monkeypatch):
    monkeypatch.setattr(
        webhook_manager.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (None, None, None, None, ("127.0.0.1", 443))
        ],
    )
    assert webhook_manager._validate_webhook_url(
        "https://public-looking.example/events"
    ) == "url_resolves_to_disallowed_address:127.0.0.1"


def test_webhook_url_rejects_malformed_port():
    assert webhook_manager._validate_webhook_url(
        "https://example.com:notaport/events"
    ) == "url_invalid_port"



def test_pinned_transport_connects_to_resolved_ip_and_preserves_tls_hostname(monkeypatch):
    import webhook_transport

    captured = {}

    class FakeResponse:
        status = 204
        headers = {}

        def release_conn(self):
            pass

    class FakePool:
        def __init__(self, **kwargs):
            captured["pool"] = kwargs

        def request(self, method, path, **kwargs):
            captured["request"] = (method, path, kwargs)
            return FakeResponse()

        def close(self):
            captured["closed"] = True

    monkeypatch.setattr(
        webhook_transport.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("93.184.216.34", 443))
        ],
    )
    monkeypatch.setattr(webhook_transport, "HTTPSConnectionPool", FakePool)

    result = webhook_transport.post_json_pinned(
        "https://hooks.example.test/events?kind=ok",
        payload={"ok": True},
        headers={"Content-Type": "application/json"},
        timeout=3,
    )

    assert result.status_code == 204
    assert captured["pool"]["host"] == "93.184.216.34"
    assert captured["pool"]["server_hostname"] == "hooks.example.test"
    assert captured["pool"]["assert_hostname"] == "hooks.example.test"
    assert captured["pool"]["cert_reqs"] == "CERT_REQUIRED"
    method, path, request = captured["request"]
    assert method == "POST"
    assert path == "/events?kind=ok"
    assert request["headers"]["Host"] == "hooks.example.test"
    assert captured["closed"] is True


def test_pinned_transport_rejects_private_dns_answers(monkeypatch):
    import pytest
    import webhook_transport

    monkeypatch.setattr(
        webhook_transport.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("10.0.0.7", 443))],
    )
    with pytest.raises(ValueError, match="disallowed"):
        webhook_transport.post_json_pinned(
            "https://hooks.example.test/events",
            payload={"ok": True},
            headers={},
            timeout=3,
        )
