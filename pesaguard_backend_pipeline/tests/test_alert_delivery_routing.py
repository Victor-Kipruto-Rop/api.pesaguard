"""Alert delivery routing and accounting (hermetic).

Verifies that the Prometheus rule file, the Alertmanager routing file, and the
Prometheus scrape configuration stay aligned, and that AlertingService deliveries
are recorded in the shared alert-delivery telemetry.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import metrics
from alerting_service import AlertingService
from models import Base

BACKEND_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def alerts_yaml() -> dict:
    import yaml

    content = (BACKEND_ROOT / "monitoring" / "alerts.yml").read_text(encoding="utf-8")
    return yaml.safe_load(content)


@pytest.fixture(scope="module")
def alertmanager_yaml() -> dict:
    import yaml

    content = (BACKEND_ROOT / "monitoring" / "alertmanager.yml").read_text(encoding="utf-8")
    return yaml.safe_load(content)


def test_every_prometheus_alert_has_severity_and_service_labels(alerts_yaml):
    for group in alerts_yaml["groups"]:
        for rule in group["rules"]:
            labels = rule.get("labels", {})
            assert labels.get("severity") in {"critical", "warning", "info"}, rule["alert"]
            assert labels.get("service"), rule["alert"]


def test_alertmanager_routes_cover_both_severities_and_receivers_exist(alertmanager_yaml):
    receivers = {receiver["name"] for receiver in alertmanager_yaml["receivers"]}
    assert "pesaguard-default" in receivers

    severity_matchers = set()
    for route in alertmanager_yaml["route"]["routes"]:
        for matcher in route.get("matchers", []):
            key, _, value = matcher.partition("=")
            if key.strip() == "severity":
                severity_matchers.add(value.strip().strip('"'))
        assert route["receiver"] in receivers
    assert {"critical", "warning"}.issubset(severity_matchers)


def test_prometheus_points_at_alertmanager():
    import yaml

    content = (BACKEND_ROOT / "monitoring" / "prometheus.yml").read_text(encoding="utf-8")
    config = yaml.safe_load(content)
    managers = config.get("alerting", {}).get("alertmanagers", [])
    assert any("alertmanager" in str(manager) for manager in managers)


def test_alertmanager_webhook_receivers_target_the_pesa_guard_gateway(alertmanager_yaml):
    urls = []
    for receiver in alertmanager_yaml["receivers"]:
        for config in receiver.get("webhook_configs", []):
            urls.append(config["url"])
    assert urls, "alertmanager has no webhook receivers"
    assert all(url.endswith("/ops/alerts") for url in urls)


def test_alerting_service_records_delivery_metrics_per_channel(monkeypatch):
    calls = []

    def fake_send(channel):
        def _send(discrepancy, locale="en", **kwargs):
            calls.append(channel)
            return True

        return _send

    monkeypatch.setattr("alerting_service.send_slack_alert", fake_send("slack"))
    monkeypatch.setattr("alerting_service.send_sms_alert", fake_send("sms"))

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    service = AlertingService(session=session, tenant_settings={"alert_channels": ["slack", "sms"]})

    result = service.handle_discrepancy({
        "id": "disc-metrics-1",
        "tenant_id": "tenant-a",
        "trans_id": "TX-METRICS",
        "severity": "critical",
        "status": "missing_payment",
        "anomalies": ["missing_payment"],
        "checked_at": "2026-09-14T00:00:00Z",
    })

    assert {entry["channel"] for entry in result["deliveries"]} == {"slack", "sms"}
    assert calls == ["slack", "sms"]
    snapshot = metrics.telemetry_snapshot()
    assert snapshot["alert_deliveries"].get("slack", 0) >= 1
    assert snapshot["alert_deliveries"].get("sms", 0) >= 1


def test_alerting_service_counts_delivery_failures(monkeypatch):
    def failing_slack(discrepancy, locale="en", **kwargs):
        raise RuntimeError("slack unavailable")

    monkeypatch.setattr("alerting_service.send_slack_alert", failing_slack)

    service = AlertingService(session=None, tenant_settings={"alert_channels": ["slack"]})
    result = service.handle_discrepancy({
        "id": "disc-metrics-2",
        "tenant_id": "tenant-a",
        "trans_id": "TX-FAIL",
        "severity": "critical",
        "status": "missing_payment",
        "anomalies": ["missing_payment"],
        "checked_at": "2026-09-14T00:00:00Z",
    })

    assert result["deliveries"][0]["status"] == "failed"
    snapshot = metrics.telemetry_snapshot()
    assert snapshot["alert_delivery_failures"] >= 1