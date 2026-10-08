import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from event_store import EventStore, ProcessResult
from models import Base, DeadLetter, ProcessedTransaction, ReconciliationOutbox, Transaction, TransactionOutbox


def _payload(trans_id="tx-1"):
    return {
        "TransID": trans_id,
        "TransAmount": "10.50",
        "MSISDN": "254700000000",
        "BusinessShortCode": "123456",
        "TransTime": "20240101120000",
    }


def test_accepted_transaction_and_outbox_are_committed_together(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'outbox.db'}"
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)

    store = EventStore(database_url=database_url)
    assert store.mark_processed(_payload(), tenant_id="tenant-a") is ProcessResult.STORED

    Session = sessionmaker(bind=engine)
    with Session() as session:
        assert session.query(ProcessedTransaction).count() == 1
        assert session.query(Transaction).count() == 1
        outbox = session.query(TransactionOutbox).one()
        assert outbox.tenant_id == "tenant-a"
        assert outbox.event_key
        assert outbox.status == "pending"
        assert outbox.payload["TransID"] == "tx-1"
        assert outbox.payload["event_id"] == outbox.event_key


def test_duplicate_transaction_does_not_create_second_outbox_row(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'duplicate.db'}"
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)

    store = EventStore(database_url=database_url)
    assert store.mark_processed(_payload(), tenant_id="tenant-a") is ProcessResult.STORED
    assert store.mark_processed(_payload(), tenant_id="tenant-a") is ProcessResult.DUPLICATE

    Session = sessionmaker(bind=engine)
    with Session() as session:
        assert session.query(TransactionOutbox).count() == 1


def test_outbox_claim_and_failure_release_are_replayable(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'retry.db'}"
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)

    store = EventStore(database_url=database_url)
    assert store.mark_processed(_payload(), tenant_id="tenant-a") is ProcessResult.STORED

    claimed = store.claim_outbox_batch(limit=10, lease_seconds=30)
    assert len(claimed) == 1
    assert claimed[0]["attempts"] == 1

    store.mark_outbox_failed(claimed[0]["id"], "kafka unavailable", retry_seconds=1)
    with sessionmaker(bind=engine)() as session:
        row = session.query(TransactionOutbox).one()
        assert row.status == "failed"
        assert row.attempts == 1
        assert row.last_error == "kafka unavailable"


def test_exhausted_outbox_is_atomically_dead_lettered(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'dead_letter.db'}"
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)

    store = EventStore(database_url=database_url)
    assert store.mark_processed(_payload(), tenant_id="tenant-a") is ProcessResult.STORED
    claimed = store.claim_outbox_batch(limit=1)

    store.mark_outbox_dead_lettered(claimed[0]["id"], "payload is corrupted")

    with sessionmaker(bind=engine)() as session:
        outbox = session.query(TransactionOutbox).one()
        dead_letter = session.query(DeadLetter).one()
        assert outbox.status == "dead_lettered"
        assert outbox.locked_until is None
        assert dead_letter.id == f"dl_outbox_{outbox.id}"
        assert dead_letter.tenant_id == "tenant-a"
        assert dead_letter.reason == "transaction_outbox_publish_exhausted"
        assert dead_letter.attempts == 1


def test_reconciliation_outbox_claim_publish_and_retry_are_durable(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'reconciliation_retry.db'}"
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        session.add(ReconciliationOutbox(
            id="recon-outbox-1", tenant_id="tenant-a", event_key="event-1",
            topic="matched", payload={"TransID": "tx-1"}, status="pending",
        ))
        session.commit()

    store = EventStore(database_url=database_url)
    claimed = store.claim_reconciliation_outbox_batch(limit=10, lease_seconds=30)
    assert claimed[0]["attempts"] == 1
    store.mark_reconciliation_outbox_failed(claimed[0]["id"], "kafka unavailable", retry_seconds=1)
    with Session() as session:
        row = session.get(ReconciliationOutbox, "recon-outbox-1")
        assert row.status == "failed"
        assert row.locked_until is None
        row.available_at = row.available_at.replace(year=2020)
        session.commit()

    claimed_again = store.claim_reconciliation_outbox_batch(limit=10, lease_seconds=30)
    assert claimed_again[0]["attempts"] == 2
    store.mark_reconciliation_outbox_published("recon-outbox-1")
    with Session() as session:
        assert session.get(ReconciliationOutbox, "recon-outbox-1").status == "published"


def test_outbox_drain_releases_claims_when_producer_initialization_fails(tmp_path, monkeypatch):
    database_url = f"sqlite:///{tmp_path / 'producer_failure.db'}"
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    store = EventStore(database_url=database_url)
    assert store.mark_processed(_payload(), tenant_id="tenant-a") is ProcessResult.STORED

    import background_tasks
    import producer

    monkeypatch.setattr(background_tasks, "DATABASE_URL", database_url)
    monkeypatch.setattr(
        producer,
        "publish_transaction_batch_results",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("producer unavailable")),
    )

    result = background_tasks.drain_transaction_outbox()

    assert result == {"status": "partial_failure", "claimed": 1, "published": 0, "failed": 1}
    with sessionmaker(bind=engine)() as session:
        row = session.query(TransactionOutbox).one()
        assert row.status == "failed"
        assert row.locked_until is None
        assert row.last_error == "producer unavailable"
