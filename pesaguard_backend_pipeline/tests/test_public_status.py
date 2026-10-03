from __future__ import annotations

import re
from concurrent.futures import TimeoutError as FutureTimeoutError

import pytest
from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from models import Base, PublicStatusSubscription
import public_status


@pytest.fixture()
def public_status_client(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test-status-signing-secret-with-32-bytes")
    monkeypatch.setenv("PESAGUARD_STATUS_MONITOR_TOKEN", "monitor-token-that-is-long-enough")
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine, tables=[PublicStatusSubscription.__table__])
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    health = {
        "status": "ok",
        "checks": {
            "database": {"status": "ok"},
            "kafka": {"status": "ok"},
            "redis": {"status": "ok"},
            "daraja": {"status": "ok"},
        },
    }
    monkeypatch.setattr(public_status, "_site_services", lambda: [
        {"id": "public-website", "name": "Public website", "status": "operational"},
        {"id": "dashboard-site", "name": "Dashboard", "status": "operational"},
        {"id": "documentation-site", "name": "Documentation", "status": "operational"},
        {"id": "status-site", "name": "Status website", "status": "operational"},
    ])
    deliveries = []

    def send_email(recipient, subject, text, html):
        deliveries.append({"recipient": recipient, "subject": subject, "text": text, "html": html})
        return True, None

    app = Flask(__name__)
    app.register_blueprint(public_status.create_public_status_blueprint(
        session_factory,
        lambda: health,
        email_sender=send_email,
    ))
    with app.test_client() as client:
        yield client, health, deliveries, session_factory
    engine.dispose()


def test_public_status_lists_each_backend_check_and_deployed_site(public_status_client):
    client, _, _, _ = public_status_client
    response = client.get("/public/status")

    assert response.status_code == 200
    payload = response.get_json()
    ids = {service["id"] for service in payload["services"]}
    assert ids == {
        "api", "database", "kafka", "redis", "daraja",
        "public-website", "dashboard-site", "documentation-site", "status-site",
    }
    assert all(service["status"] == "operational" for service in payload["services"])
    assert payload["verified"] is True


def test_public_site_outage_degrades_the_overall_status(public_status_client, monkeypatch):
    client, _, _, _ = public_status_client
    monkeypatch.setattr(public_status, "_site_services", lambda: [
        {"id": "public-website", "name": "Public website", "status": "outage"},
    ])

    response = client.get("/public/status")

    assert response.status_code == 503
    assert response.get_json()["overall"]["status"] == "outage"


def test_email_subscribe_confirm_monitor_change_and_unsubscribe(public_status_client):
    client, health, deliveries, session_factory = public_status_client
    response = client.post("/public/status/subscriptions", json={"email": "Updates@Example.com"})

    assert response.status_code == 202
    assert response.get_json()["message"].startswith("Check your email")
    assert len(deliveries) == 1
    assert deliveries[0]["recipient"] == "updates@example.com"
    confirmation_token = re.search(r"\?confirm=([A-Za-z0-9_-]+)", deliveries[0]["text"]).group(1)

    confirmed = client.post(
        "/public/status/subscriptions/confirm",
        json={"token": confirmation_token},
    )
    assert confirmed.status_code == 200
    with session_factory() as session:
        subscription = session.query(PublicStatusSubscription).one()
        assert subscription.confirmed is True
        assert subscription.email_hash

    monitor_headers = {"Authorization": "Bearer monitor-token-that-is-long-enough"}
    initial = client.post("/public/status/monitor", headers=monitor_headers)
    assert initial.status_code == 200
    assert initial.get_json()["emails_sent"] == 0
    assert len(deliveries) == 1

    health["status"] = "degraded"
    health["checks"]["kafka"]["status"] = "failed"
    changed = client.post("/public/status/monitor", headers=monitor_headers)
    assert changed.status_code == 200
    assert changed.get_json()["emails_sent"] == 1
    assert len(deliveries) == 2
    assert "Event processing: outage" in deliveries[-1]["text"]
    assert "unsubscribe=" in deliveries[-1]["text"]

    unchanged = client.post("/public/status/monitor", headers=monitor_headers)
    assert unchanged.status_code == 200
    assert unchanged.get_json()["emails_sent"] == 0
    assert len(deliveries) == 2

    unsubscribe_token = re.search(r"\?unsubscribe=([A-Fa-f0-9.]+)", deliveries[-1]["text"]).group(1)
    removed = client.post(
        "/public/status/subscriptions/unsubscribe",
        json={"token": unsubscribe_token},
    )
    assert removed.status_code == 200
    with session_factory() as session:
        assert session.query(PublicStatusSubscription).count() == 0


def test_subscription_rejects_invalid_addresses_and_monitor_requires_secret(public_status_client):
    client, _, _, _ = public_status_client
    assert client.post("/public/status/subscriptions", json={"email": "not-an-email"}).status_code == 400
    assert client.post("/public/status/monitor").status_code == 401
    assert client.post(
        "/public/status/monitor",
        headers={"Authorization": "Bearer incorrect"},
    ).status_code == 401


def test_site_probe_timeout_is_reported_as_unknown_not_raised(monkeypatch):
    class TimedOutProbe:
        def result(self, timeout):
            raise FutureTimeoutError()

    monkeypatch.setattr(public_status, "SITE_PROBES", (
        ("public-website", "Public website", "https://pesaguard.victorkipruto.com/"),
    ))
    monkeypatch.setattr(public_status, "_site_cache", {"checked_at": 0.0, "services": []})
    monkeypatch.setattr(public_status._site_probe_pool, "submit", lambda *args: TimedOutProbe())
    app = Flask(__name__)

    with app.app_context():
        services = public_status._site_services()

    assert services == [{
        "id": "public-website",
        "name": "Public website",
        "status": "unknown",
        "description": "The public HTTP reachability check timed out.",
    }]
