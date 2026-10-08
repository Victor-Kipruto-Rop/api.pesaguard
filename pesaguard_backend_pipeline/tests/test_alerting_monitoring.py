import os
import sys
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import reconciliation_job
from models import Base
from alerting_consumer import AlertingConsumer
from alerting_service import AlertingService
from metrics import build_metrics_payload


def test_alerting_service_routes_critical_to_sms_and_slack_and_dedupes():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    session = Session()
    service = AlertingService(session=session, tenant_settings={"alert_channels": ["slack", "sms"]})

    discrepancy = {
        "id": "disc-1",
        "tenant_id": "tenant-a",
        "trans_id": "TX-1",
        "severity": "critical",
        "status": "missing_payment",
        "anomalies": ["missing_payment"],
        "checked_at": "2026-07-04T00:00:00Z",
    }

    first = service.handle_discrepancy(discrepancy)
    second = service.handle_discrepancy(discrepancy)

    assert first["status"] == "queued"
    assert second["status"] == "deduped"
    assert {entry["channel"] for entry in first["deliveries"]} == {"slack", "sms"}
    assert len(first["deliveries"]) == 2


def test_alerting_service_routes_info_to_digest():
    service = AlertingService(session=None, tenant_settings={"alert_channels": ["slack", "sms", "email"]})

    result = service.handle_discrepancy({
        "id": "disc-info",
        "tenant_id": "tenant-a",
        "trans_id": "TX-2",
        "severity": "info",
        "status": "resolved",
        "anomalies": ["auto_resolved"],
        "checked_at": "2026-07-04T00:00:00Z",
    })

    assert result["status"] == "queued"
    assert result["delivery_mode"] == "digest"
    assert result["deliveries"] == []


def test_metrics_payload_exposes_prometheus_text():
    payload = build_metrics_payload()

    assert "# HELP pesaguard_transactions_total" in payload
    assert "pesaguard_alerts_total" in payload
    assert "pesaguard_open_discrepancies" in payload
    assert "pesaguard_alert_delivery_failures_total" in payload
    assert "pesaguard_discrepancies_open" in payload


def test_metrics_payload_exposes_channel_and_connector_metrics():
    payload = build_metrics_payload()

    assert "pesaguard_alert_deliveries_total" in payload
    assert 'channel="slack"' in payload
    assert "pesaguard_connector_last_success_timestamp_seconds" in payload
    assert "pesaguard_connector_errors_total" in payload
    assert "pesaguard_kafka_consumer_lag" in payload


def test_alerting_consumer_processes_discrepancy_messages():
    calls = []

    class DummyService:
        def handle_discrepancy(self, discrepancy):
            calls.append(discrepancy["trans_id"])
            return {"status": "queued", "alert_id": discrepancy["id"], "deliveries": [], "delivery_mode": "realtime"}

    consumer = AlertingConsumer(alert_service=DummyService(), tenant_settings_provider=lambda tenant_id: {"alert_channels": ["slack"]})
    results = consumer.process_messages([
        {
            "id": "disc-100",
            "tenant_id": "tenant-a",
            "trans_id": "TX-100",
            "severity": "critical",
            "status": "missing_payment",
            "anomalies": ["missing_payment"],
        }
    ])

    assert calls == ["TX-100"]
    assert results[0]["status"] == "queued"


def test_reconciliation_job_publishes_discrepancies_to_topic(monkeypatch):
    published = []

    class DummyProducer:
        def send(self, topic, key=None, value=None):
            published.append((topic, value))

            class Future:
                def get(self, timeout=None):
                    return None

            return Future()

        def flush(self, timeout=None):
            return None

        def close(self, timeout=None):
            return None

    class DummyConsumer:
        """Poll-shaped consumer (kafka-python-ng contract) that yields one batch."""

        def __init__(self):
            self._polls = 0

        def poll(self, timeout_ms=1000):
            self._polls += 1
            if self._polls == 1:
                message = SimpleNamespace(
                    value={"TransID": "TX-100", "TransAmount": "100.00", "MSISDN": "254700000000", "TransTime": "20260704120000"},
                    topic="mpesa.transactions.raw",
                    partition=0,
                    offset=0,
                    headers=[],
                )
                return {("mpesa.transactions.raw", 0): [message]}
            # Stop the run loop on the second poll, after the batch was processed.
            reconciliation_job._RUNNING = False
            return {}

        def commit(self, offsets=None):
            return None

        def close(self):
            return None

    monkeypatch.setattr(reconciliation_job, "KafkaConsumer", lambda *args, **kwargs: DummyConsumer())
    monkeypatch.setattr(reconciliation_job, "KafkaProducer", lambda *args, **kwargs: DummyProducer())
    monkeypatch.setattr(reconciliation_job, "ConnectorRegistry", type("DummyRegistry", (), {"from_env": staticmethod(lambda: type("Dummy", (), {"get_connector": lambda self, tenant_id: None})())}))
    monkeypatch.setattr(reconciliation_job, "check_for_anomalies", lambda event, seen, tenant_settings=None: ["missing_payment"])
    monkeypatch.setattr(reconciliation_job, "_RUNNING", True)

    # Persist reconciliation outcomes into an isolated database so the audit
    # tables always exist regardless of test collection order.
    import tempfile
    import uuid as uuid_module

    from action_audit import Base as AuditBase
    from models import Base as ModelsBase
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(
        f"sqlite:///{os.path.join(tempfile.gettempdir(), f'alerting-recon-{uuid_module.uuid4().hex}.db')}"
    )
    ModelsBase.metadata.create_all(engine)
    AuditBase.metadata.create_all(engine)
    monkeypatch.setattr(reconciliation_job, "AuditSession", sessionmaker(bind=engine, expire_on_commit=False))

    reconciliation_job.run()

    assert any(topic == reconciliation_job.TOPIC_DISCREPANCIES for topic, _ in published)
    engine.dispose()
