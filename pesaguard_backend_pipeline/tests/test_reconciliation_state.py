from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from action_audit import ActionAuditEntry
from event_store import EventStore, ProcessResult
from models import Base, Discrepancy, FraudRiskAssessment, ProcessedTransaction, ReconciliationOutbox
from reconciliation_job import _persist_atomically


def _event():
    return {
        "TransID": "TX-STATE-1",
        "TransAmount": "10.00",
        "MSISDN": "254700000000",
        "BusinessShortCode": "123456",
        "TransTime": "20260912120000",
    }


def test_reconciliation_is_separate_from_ingestion_and_replay_safe(tmp_path, monkeypatch):
    database_url = f"sqlite:///{tmp_path / 'reconciliation.db'}"
    engine = create_engine(database_url)

    import reconciliation_job
    from action_audit import Base as AuditBase

    Base.metadata.create_all(engine)
    AuditBase.metadata.create_all(engine)
    monkeypatch.setattr(reconciliation_job, "AuditSession", sessionmaker(bind=engine, expire_on_commit=False))
    store = EventStore(database_url=database_url)
    event = _event()
    assert store.mark_processed(event, tenant_id="tenant-a") is ProcessResult.STORED

    evaluation = {
        "status": "missing_payment",
        "severity": "critical",
        "match": {"match_type": "none"},
        "anomalies": ["missing_payment"],
        "event": event,
        "tenant_id": "tenant-a",
    }
    assert _persist_atomically(event, evaluation, event["TransID"], "tenant-a") is ProcessResult.STORED
    assert _persist_atomically(event, evaluation, event["TransID"], "tenant-a") is ProcessResult.DUPLICATE

    with sessionmaker(bind=engine)() as session:
        assert session.query(ProcessedTransaction).one().reconciliation_status == "completed"
        assert session.query(Discrepancy).count() == 1
        assert session.query(ActionAuditEntry).count() == 1
        assert session.query(ReconciliationOutbox).count() == 1
        assessment = session.query(FraudRiskAssessment).one()
        assert "duplicate_activity" not in assessment.rules_triggered


def test_reconciliation_uses_tenant_anomaly_settings(monkeypatch):
    import reconciliation_job

    captured = {}
    tenant_settings = {"anomaly_large_amount_kes": 250}
    monkeypatch.setattr(reconciliation_job.settings_store, "get", lambda tenant_id: tenant_settings)
    monkeypatch.setattr(
        reconciliation_job,
        "check_for_anomalies",
        lambda event, seen, settings: captured.update(settings=settings) or [],
    )
    monkeypatch.setattr(
        reconciliation_job,
        "reconciliation_engine",
        type(
            "FakeEngine",
            (),
            {
                "reconcile": staticmethod(
                    lambda event, records, seen_transaction_ids: {
                        "status": "MATCHED",
                        "evidence": {
                            "matched_record": None,
                            "matching_rules": ["reference_exact"],
                            "match_score": 1.0,
                            "match_timestamp": "2026-09-12T12:00:00+00:00",
                            "engine_version": "test",
                        },
                        "processing_latency_ms": 0,
                    }
                )
            },
        )(),
    )
    monkeypatch.setattr(reconciliation_job, "_persist_atomically", lambda *args: ProcessResult.STORED)
    monkeypatch.setattr(reconciliation_job, "_publish_downstream", lambda *args: None)
    registry = type("Registry", (), {"get_connector": lambda self, tenant_id: None})()

    assert reconciliation_job._process_message_unbounded(
        {**_event(), "tenant_id": "tenant-a"},
        None,
        None,
        registry,
    )
    assert captured["settings"] == tenant_settings


def test_high_risk_match_is_persisted_and_published_as_a_discrepancy(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace

    import reconciliation_job
    from action_audit import Base as AuditBase

    database_url = f"sqlite:///{tmp_path / 'high-risk.db'}"
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    AuditBase.metadata.create_all(engine)
    monkeypatch.setattr(reconciliation_job, "AuditSession", sessionmaker(bind=engine, expire_on_commit=False))
    monkeypatch.setattr(
        reconciliation_job,
        "assess_transaction",
        lambda event, history: SimpleNamespace(
            risk_level="CRITICAL",
            reason_codes=("amount_threshold",),
            as_dict=lambda: {"risk_level": "CRITICAL", "reason_codes": ["amount_threshold"]},
        ),
    )
    monkeypatch.setattr(reconciliation_job, "persist_assessment", lambda *args: None)

    event = _event()
    assert EventStore(database_url=database_url).mark_processed(event, tenant_id="tenant-a") is ProcessResult.STORED
    evaluation = {
        "trans_id": event["TransID"],
        "tenant_id": "tenant-a",
        "status": "matched",
        "phase3_status": "MATCHED",
        "severity": "info",
        "anomalies": [],
        "evidence": {"match_timestamp": "2026-09-12T12:00:00+00:00"},
        "event": event,
    }
    assert reconciliation_job._persist_atomically(event, evaluation, event["TransID"], "tenant-a") is ProcessResult.STORED

    with sessionmaker(bind=engine)() as session:
        discrepancy = session.query(Discrepancy).one()
        outbox = session.query(ReconciliationOutbox).one()
        assert discrepancy.anomaly_type == "fraud_risk"
        assert discrepancy.severity == "critical"
        assert outbox.topic == reconciliation_job.TOPIC_DISCREPANCIES
        assert outbox.payload["fraud_risk"]["risk_level"] == "CRITICAL"

    published = []
    alerts = []

    class Future:
        def get(self, timeout=None):
            return None

    class Producer:
        def send(self, topic, key=None, value=None):
            published.append((topic, json.loads(value)))
            return Future()

        def flush(self, timeout=None):
            return None

    monkeypatch.setattr(
        reconciliation_job,
        "dispatch_discrepancy_alert",
        lambda payload, tenant_id: alerts.append((payload, tenant_id)) or {"status": "queued"},
    )
    reconciliation_job._publish_downstream(evaluation, event["TransID"], Producer(), "tenant-a")

    assert published[0][0] == reconciliation_job.TOPIC_DISCREPANCIES
    assert published[0][1]["fraud_risk"]["risk_level"] == "CRITICAL"
    assert alerts[0][0]["severity"] == "critical"
    assert alerts[0][0]["anomalies"] == ["amount_threshold"]
    engine.dispose()
