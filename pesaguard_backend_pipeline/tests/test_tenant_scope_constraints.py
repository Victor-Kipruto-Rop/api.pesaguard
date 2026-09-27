import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from pesaguard_backend_pipeline . models import (
    Base,
    DeadLetter,
    Discrepancy,
    DiscrepancyEvent,
    Organization,
    ProcessedTransaction,
    ReconciliationOutbox,
    Transaction,
    TransactionEvent,
    TransactionOutbox,
)
# Bare, not "pesaguard_backend_pipeline.communications.models": that module
# already unifies onto pesaguard_backend_pipeline.models.Base itself (see the
# try/except at the top of communications/models.py), so importing it under a
# second dotted name here doesn't change which Base its classes attach to --
# it just makes Python execute the file's class bodies a second time. Each of
# those classes uses __table_args__ = {"extend_existing": True} so the second
# execution reuses the same Table rather than raising, but the bare Index(...)
# objects inside __table_args__ aren't deduplicated the same way, so
# Base.metadata.create_all() below tried to CREATE INDEX the same index twice.
from communications.models import (
    CommunicationConsent,
    CommunicationNotification,
    CommunicationOutboxEntry,
    CommunicationPreference,
    CommunicationTemplate,
)


@pytest.fixture
def engine():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return engine


def test_database_rejects_empty_tenant_ids(engine):
    Session = sessionmaker(bind=engine)
    session = Session()

    with pytest.raises(Exception):
        session.add(Transaction(
            trans_id="trans-empty-tenant",
            tenant_id="",
            trans_amount=10,
            currency="KES",
            msisdn="254700000001",
            business_short_code="174379",
            trans_time="2026-09-13T00:00:00Z",
            raw_payload={"transaction": {"amount": 10}},
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(ProcessedTransaction(
            daraja_trans_id="trans-empty-tenant-2",
            tenant_id="",
            provider_account_id="legacy-default",
            status="received",
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(TransactionOutbox(
            tenant_id="",
            event_key="evt-1",
            topic="mpesa.transactions.matched",
            payload={"status": "matched"},
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(ReconciliationOutbox(
            tenant_id="",
            event_key="evt-2",
            topic="mpesa.transactions.matched",
            payload={"status": "matched"},
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(Discrepancy(
            id="d-1",
            trans_id="trans-empty-tenant-3",
            tenant_id="",
            anomaly_type="amount_mismatch",
            status="needs_review",
            severity="warning",
            details="mismatch",
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(TransactionEvent(
            id="te-1",
            tenant_id="",
            transaction_id="txn-1",
            trans_id="trans-empty-tenant-4",
            event_key="event-1",
            event_type="received",
            to_state="received",
            actor="system",
            details={},
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(DiscrepancyEvent(
            id="de-1",
            tenant_id="",
            discrepancy_id="d-2",
            event_key="disc-event-1",
            to_state="needs_review",
            actor="system",
            details={},
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(DeadLetter(
            id="dl-1",
            tenant_id="",
            reason="malformed_webhook",
            payload={"bad": True},
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(Organization(
            id="org-1",
            tenant_id="",
            name="Empty Tenant Org",
            slug="empty-tenant-org",
            settings={},
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(Organization(
            id="org-2",
            tenant_id="",
            name="User Session Scope",
            slug="user-session-scope",
            settings={},
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(CommunicationNotification(
            id="notif-1",
            tenant_id="",
            channel="sms",
            recipient="254700000001",
            message="hello",
            template_id="tpl-1",
            idempotency_key="idemp-1",
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(CommunicationOutboxEntry(
            id="outbox-1",
            notification_id="notif-1",
            tenant_id="",
            status="pending",
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(CommunicationTemplate(
            id="tpl-1",
            tenant_id="",
            slug="welcome",
            version=1,
            channel="sms",
            body="hello",
            variables=[],
            status="draft",
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(CommunicationPreference(
            id="pref-1",
            tenant_id="",
            recipient="254700000001",
            channels=["sms"],
            timezone="Africa/Nairobi",
        ))
        session.commit()

    with pytest.raises(Exception):
        session.add(CommunicationConsent(
            id="consent-1",
            tenant_id="",
            recipient="254700000001",
            channel="sms",
            purpose="marketing",
            granted=1,
            source="api",
        ))
        session.commit()

    session.close()
