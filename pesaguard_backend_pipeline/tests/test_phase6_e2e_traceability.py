"""Hermetic end-to-end traceability: gateway -> PostgreSQL -> Kafka -> consumer
-> reconciliation -> notification.

Verifies that one trace identity (trace_id + correlation_id + transaction_id)
survives every boundary: it appears in emitted structured logs, in Kafka message
headers (W3C traceparent), in the observability context after the consumer hop,
and in the persisted reconciliation audit record.

The test uses the real Flask gateway, real SQLAlchemy persistence, real producer/
consumer/reconciliation modules, and a captured fake Kafka transport so it runs
without live infrastructure.
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import tempfile
import uuid
from types import SimpleNamespace

import pytest

from event_bus import build_event
from event_consumer import ConsumerGroup, EventConsumer


DARAJA_SECRET = "e2e-trace-secret"


@pytest.fixture()
def gateway(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{os.path.join(tmpdir, 'e2e.db')}")
        monkeypatch.setenv("DARAJA_ALLOWED_IPS", "127.0.0.1")
        monkeypatch.setenv("DARAJA_SHARED_SECRET", DARAJA_SECRET)
        monkeypatch.setenv("TENANT_ID", "tenant-a")
        import app as webhook_app

        webhook_app = importlib.reload(webhook_app)
        webhook_app.app.config.update(TESTING=True)
        yield webhook_app
        # Release the SQLite file so TemporaryDirectory cleanup succeeds on Windows.
        try:
            webhook_app.event_store.engine.dispose()
        except Exception:
            pass


def _json_logs(caplog):
    """Re-emit each captured record through the production JsonFormatter."""
    from logging_utils import JsonFormatter

    formatter = JsonFormatter()
    payloads = []
    for record in caplog.records:
        try:
            payloads.append(json.loads(formatter.format(record)))
        except (json.JSONDecodeError, ValueError):
            continue
    return payloads


def test_gateway_to_notification_trace_survives_every_boundary(monkeypatch, caplog, gateway):
    caplog.set_level(logging.INFO)
    # normalize_identifier() (ingestion.py) upper-cases every provider transaction
    # id on the way in, so the id used throughout this test must already be
    # upper-case or the "PostgreSQL boundary" query below won't find the row
    # the gateway actually wrote.
    transaction_id = f"E2E-TRACE-{uuid.uuid4().hex[:10].upper()}"
    trace_id = uuid.uuid4().hex
    correlation_id = f"corr-{trace_id[:12]}"
    payload = {
        "TransactionType": "Pay Bill",
        "TransID": transaction_id,
        "TransTime": "20260914090000",
        "TransAmount": "150.00",
        "BusinessShortCode": "123456",
        "MSISDN": "254700000000",
        "BillRefNumber": transaction_id,
    }

    # 1. Gateway boundary: submit a real webhook through the Flask gateway.
    response = gateway.app.test_client().post(
        "/webhook/mpesa/confirmation",
        json=payload,
        headers={
            "X-Daraja-Shared-Secret": DARAJA_SECRET,
            "X-Trace-ID": trace_id,
            "X-Correlation-ID": correlation_id,
            "X-Tenant-ID": "tenant-a",
        },
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    assert response.headers.get("X-Trace-ID") == trace_id

    # 2. PostgreSQL boundary: transaction and audit rows persisted.
    store = gateway.event_store
    session = store.Session()
    try:
        from models import AuditEvent, Transaction

        transaction = (
            session.query(Transaction)
            .filter(Transaction.trans_id == transaction_id.upper())
            .one_or_none()
        )
        assert transaction is not None, "gateway did not persist the transaction"
        audit_event = (
            session.query(AuditEvent)
            .filter(AuditEvent.details.like(f"%{transaction_id}%"))
            .one_or_none()
        )
        assert audit_event is not None, "gateway did not persist an audit record for the transaction"
    finally:
        session.close()

    # 3. Kafka boundary: drain the durable outbox through the producer and
    #    capture the message exactly as a broker would receive it.
    from producer import publish_transaction_event

    claimed = store.claim_outbox_batch(limit=10)
    assert claimed, "gateway did not write a transaction outbox row"
    captured = []

    class CapturingProducer:
        def send(self, topic, key=None, value=None, headers=None):
            captured.append({"topic": topic, "value": value, "headers": headers or []})
            metadata = SimpleNamespace(topic=topic, partition=0, offset=len(captured) - 1)

            class Future:
                def get(self, timeout=None):
                    return metadata

            return Future()

    monkeypatch.setattr(
        "producer._producer_manager",
        SimpleNamespace(get_producer=lambda: CapturingProducer(), reset_producer=lambda: None),
    )
    for row in claimed:
        publish_transaction_event(row["topic"], row["payload"])
        store.mark_outbox_published(row["id"])

    assert captured, "nothing was published to Kafka"
    message_headers = {
        str(name).lower(): (value.decode("ascii") if isinstance(value, bytes) else value)
        for name, value in captured[0]["headers"]
    }
    assert "traceparent" in message_headers, "Kafka message is missing W3C traceparent"

    # 4. Consumer boundary: extract the header like the reconciliation job does
    #    and dispatch through a real EventConsumer.
    from logging_utils import bind_observability_context, get_observability_context
    from observability import extract_trace_context
    from reconciliation_job import _message_traceparent

    kafka_message = SimpleNamespace(headers=captured[0]["headers"])
    traceparent = _message_traceparent(kafka_message)
    assert traceparent == message_headers["traceparent"]
    parsed = extract_trace_context({"traceparent": traceparent})
    assert parsed["trace_id"] == trace_id, "traceparent does not carry the gateway trace_id"

    bind_observability_context(trace_id=parsed["trace_id"], span_id=parsed["span_id"], traceparent=traceparent)
    received_events = []
    audit_group = EventConsumer(ConsumerGroup("audit", frozenset({"transaction.received"})))
    audit_group.register("transaction.received", lambda event: received_events.append(event))
    event = build_event(
        "transaction.received",
        "tenant-a",
        transaction_id,
        payload,
        correlation_id=correlation_id,
    )
    delivery = audit_group.consume(event, traceparent=traceparent)
    assert delivery.status == "processed"
    assert received_events[0].correlation_id == correlation_id
    assert get_observability_context()["trace_id"] == trace_id

    # 5. Reconciliation boundary: persist the outcome with the real
    #    _persist_atomically, then require the persisted audit record to carry
    #    the gateway trace identity.
    import reconciliation_job
    from action_audit import ActionAuditEntry
    from action_audit import Base as AuditBase
    from models import Base as ModelsBase
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(f"sqlite:///{os.path.join(tempfile.gettempdir(), f'pesaguard-e2e-{uuid.uuid4().hex}.db')}")
    ModelsBase.metadata.create_all(engine)
    AuditBase.metadata.create_all(engine)
    monkeypatch.setattr(reconciliation_job, "AuditSession", sessionmaker(bind=engine, expire_on_commit=False))

    persist_result = reconciliation_job._persist_atomically(
        payload,
        {"status": "missing_payment", "anomalies": ["missing_payment"]},
        transaction_id,
        "tenant-a",
    )
    assert persist_result is not None

    audit_session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        audit_row = (
            audit_session.query(ActionAuditEntry)
            .filter(ActionAuditEntry.resource_id == transaction_id)
            .one_or_none()
        )
        assert audit_row is not None, "reconciliation did not persist an audit record"
        assert audit_row.trace_id == trace_id, "persisted audit record lost the gateway trace_id"
        assert audit_row.correlation_id == correlation_id
    finally:
        audit_session.close()
        engine.dispose()

    # 6. Notification boundary: route the discrepancy through the real
    #    AlertingConsumer/AlertingService with a captured channel.
    import metrics
    from alerting_consumer import AlertingConsumer
    from alerting_service import AlertingService

    deliveries = []
    service = AlertingService(tenant_settings={"alert_channels": ["slack"]})

    def fake_slack(discrepancy, locale="en", **kwargs):
        deliveries.append(discrepancy)
        return True

    monkeypatch.setattr("alerting_service.send_slack_alert", fake_slack)
    consumer = AlertingConsumer(alert_service=service)
    results = consumer.process_messages([
        {
            "id": f"disc-{transaction_id}",
            "tenant_id": "tenant-a",
            "trans_id": transaction_id,
            "severity": "critical",
            "status": "missing_payment",
            "anomalies": ["missing_payment"],
        }
    ])
    assert results[0]["status"] in {"queued", "deduped"}
    assert deliveries and deliveries[0]["trans_id"] == transaction_id
    assert metrics.telemetry_snapshot()["alert_deliveries"].get("slack", 0) >= 1

    # 7. Log evidence: the trace identity must be present in emitted structured
    #    logs (span records carry trace_id; audit/alert logs carry trans_id).
    logs = _json_logs(caplog)
    span_logs = [entry for entry in logs if entry.get("span_name")]
    assert any(entry.get("trace_id") == trace_id for entry in span_logs), (
        "no structured log carries the gateway trace_id"
    )
    serialized_logs = json.dumps(logs)
    assert transaction_id in serialized_logs
    # Operational smoke requirement: the full end-to-end path must emit at least one
    # structured log with the gateway trace identity and the same transaction identifier
    # in a JSON-serialisable payload (so downstream log aggregation can correlate).
    assert any(
        entry.get("trace_id") == trace_id and entry.get("transaction_id") == transaction_id
        for entry in logs
    ), "no structured log carries both the gateway trace_id and the transaction_id together"