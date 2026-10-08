"""
Reconciliation Job (Production Kafka Consumer Service)

Processes canonical transaction events from `pesaguard.transactions.raw`, executes multi-tenant
reconciliation checks against connector internal records, atomically records idempotency marks
and audit entries in Postgres, and commits consumer offsets safely.
"""

from __future__ import annotations

from environment import required_env

import json
import hashlib
from decimal import Decimal
import logging
import os
import signal
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

try:
    from kafka import KafkaConsumer, KafkaProducer
    HAS_KAFKA = True
except ImportError:
    KafkaConsumer = None  # type: ignore[assignment]
    KafkaProducer = None  # type: ignore[assignment]
    HAS_KAFKA = False

from action_audit import ActionAuditRecord, persist_audit_event
from anomaly_rules import check_for_anomalies
from base_connector import ConnectorRegistry
from event_store import EventStore, ProcessResult, provider_account_id
from fraud_risk_engine import assess_transaction, persist_assessment
from logging_utils import configure_logging
from models import Base, Discrepancy, ProcessedTransaction, ReconciliationMatch, ReconciliationOutbox, Transaction
from reconciliation_engine import ReconciliationEngine
from tenant_settings import TenantSettingsStore
from communications.events import discrepancy_notification_event
from background_tasks import enqueue_notification_event
from lifecycle import transition_reconciliation

configure_logging()
logger = logging.getLogger("pesaguard.reconciliation")

# Kafka & Service Settings
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC_RAW = os.getenv("KAFKA_TOPIC_TRANSACTIONS", "pesaguard.transactions.raw")
TOPIC_MATCHED = os.getenv("KAFKA_TOPIC_MATCHED", "pesaguard.reconciliation.completed")
TOPIC_DISCREPANCIES = os.getenv("KAFKA_TOPIC_DISCREPANCIES", "pesaguard.reconciliation.exceptions")
DEFAULT_TENANT_ID = os.getenv("TENANT_ID", "default")
WINDOW_MINUTES = int(os.getenv("RECONCILIATION_WINDOW_MINUTES", "15"))
BATCH_SIZE = max(1, int(os.getenv("PESAGUARD_RECONCILIATION_BATCH_SIZE", "100")))
MAX_TENANT_IN_FLIGHT = max(1, int(os.getenv("PESAGUARD_MAX_TENANT_IN_FLIGHT", "4")))

DB_URL = required_env("DATABASE_URL")

# Database Engine & Event Store Setup
if DB_URL.startswith("sqlite"):
    engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DB_URL, pool_pre_ping=True, pool_size=5, max_overflow=10)
from metrics import instrument_engine_query_timing
instrument_engine_query_timing(engine)
engine_for_audit = engine
AuditSession = sessionmaker(bind=engine, expire_on_commit=False)
event_store = EventStore(database_url=DB_URL)
settings_store = TenantSettingsStore()
reconciliation_engine = ReconciliationEngine(window_seconds=WINDOW_MINUTES * 60)

_RUNNING = True


class TenantConcurrencyLimiter:
    """Bound reconciliation work per tenant to protect shared resources."""

    def __init__(self, limit: int):
        self.limit = limit
        self._lock = threading.Lock()
        self._semaphores: Dict[str, threading.BoundedSemaphore] = {}

    @contextmanager
    def acquire(self, tenant_id: str):
        with self._lock:
            semaphore = self._semaphores.setdefault(tenant_id, threading.BoundedSemaphore(self.limit))
        semaphore.acquire()
        try:
            yield
        finally:
            semaphore.release()


tenant_limiter = TenantConcurrencyLimiter(MAX_TENANT_IN_FLIGHT)


def _signal_handler(signum, frame):
    """Graceful shutdown signal listener for containerized deployments."""
    global _RUNNING
    logger.info("Received termination signal (%s). Initiating graceful shutdown...", signum)
    _RUNNING = False


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


def dispatch_discrepancy_alert(evaluation: Dict[str, Any], tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """Queue multi-channel alerts without calling communication providers in reconciliation."""
    if evaluation.get("status") not in {"needs_review", "missing_payment"} and not evaluation.get("anomalies"):
        return {"status": "skipped", "trans_id": evaluation.get("trans_id")}

    tid = tenant_id or evaluation.get("tenant_id") or DEFAULT_TENANT_ID
    return enqueue_notification_event(discrepancy_notification_event(evaluation, str(tid)))


def _persist_atomically(event: Dict[str, Any], evaluation: Dict[str, Any], trans_id: str, tenant_id: str) -> ProcessResult:
    """
    Atomically commit the idempotency ledger entry and audit log record
    within a SINGLE database transaction.
    """
    session = AuditSession()
    try:
        provider_id = provider_account_id(event)
        event_key = hashlib.sha256(f"{tenant_id}:{provider_id}:{trans_id}".encode("utf-8")).hexdigest()
        processed = session.query(ProcessedTransaction).filter(
            ProcessedTransaction.daraja_trans_id == trans_id,
            ProcessedTransaction.tenant_id == tenant_id,
            ProcessedTransaction.provider_account_id == provider_id,
        ).with_for_update().first()
        if processed is None:
            processed = ProcessedTransaction(
                id=f"pt_{hashlib.sha256(event_key.encode()).hexdigest()[:12]}",
                daraja_trans_id=trans_id,
                tenant_id=tenant_id,
                provider_account_id=provider_id,
                status="received",
                received_at=datetime.now(timezone.utc),
            )
            session.add(processed)
        elif processed.reconciliation_status == "completed":
            session.rollback()
            return ProcessResult.DUPLICATE

        transition_reconciliation(processed.reconciliation_status or "pending", "processing")
        processed.reconciliation_status = "processing"
        processed.reconciliation_attempts = (processed.reconciliation_attempts or 0) + 1
        processed.reconciliation_started_at = datetime.now(timezone.utc)
        processed.reconciliation_error = None
        result_payload = json.loads(json.dumps(evaluation, ensure_ascii=False, default=str))

        recent_transactions = session.query(Transaction).filter(
            Transaction.tenant_id == tenant_id,
            Transaction.provider_account_id == provider_id,
            Transaction.trans_id != trans_id,
        ).order_by(Transaction.created_at.desc()).limit(100).all()
        risk_history = [
            {
                "TransID": item.trans_id,
                "TransAmount": item.trans_amount,
                "MSISDN": item.msisdn,
                "BusinessShortCode": item.business_short_code,
                "TransTime": item.trans_time,
            }
            for item in recent_transactions
        ]
        risk_decision = assess_transaction(event, risk_history)
        persist_assessment(session, tenant_id, trans_id, risk_decision)
        result_payload["fraud_risk"] = risk_decision.as_dict()

        phase3_status = evaluation.get("phase3_status")
        is_discrepancy = (
            phase3_status not in {None, "MATCHED", "DUPLICATE"}
            if phase3_status
            else evaluation.get("status") in {"needs_review", "missing_payment"} or bool(evaluation.get("anomalies"))
        )
        if risk_decision.risk_level in {"HIGH", "CRITICAL"}:
            is_discrepancy = True
            result_payload["anomalies"] = list(result_payload.get("anomalies") or []) + list(risk_decision.reason_codes)
            result_payload["severity"] = (
                "critical"
                if risk_decision.risk_level == "CRITICAL" or result_payload.get("severity") == "critical"
                else "warning"
            )
        if is_discrepancy:
            discrepancy_id = f"{tenant_id}:{trans_id}:reconciliation"
            discrepancy = session.get(Discrepancy, discrepancy_id)
            if discrepancy is None:
                discrepancy_status = evaluation.get("status")
                if discrepancy_status not in {"needs_review", "reviewed", "resolved", "escalated"}:
                    discrepancy_status = "needs_review"
                discrepancy = Discrepancy(
                    id=discrepancy_id,
                    trans_id=trans_id,
                    tenant_id=tenant_id,
                    anomaly_type=(
                        "fraud_risk"
                        if risk_decision.risk_level in {"HIGH", "CRITICAL"}
                        and phase3_status in {"MATCHED", "DUPLICATE"}
                        else evaluation.get("status", "reconciliation_anomaly")
                    ),
                    status=discrepancy_status,
                    severity=result_payload.get("severity", "warning"),
                    details=json.dumps(result_payload, ensure_ascii=False),
                    detected_at=datetime.now(timezone.utc),
                )
                session.add(discrepancy)

        audit_details = {
            "trans_id": trans_id,
            "status": evaluation.get("status"),
            "match": evaluation.get("match"),
            "anomalies": evaluation.get("anomalies", []),
        }
        trace_context = {}
        try:
            from logging_utils import get_observability_context
            trace_context = get_observability_context()
        except Exception:
            logger.debug("Could not read trace identifiers for reconciliation audit", exc_info=True)
        persist_audit_event(session, ActionAuditRecord(
            tenant_id=tenant_id,
            actor="reconciliation_job",
            action="discrepancy_flagged" if is_discrepancy else "matched",
            category="operations",
            outcome="success",
            severity=result_payload.get("severity", "info"),
            resource_type="transaction",
            resource_id=trans_id,
            idempotency_key=f"reconciliation:{event_key}",
            details=audit_details,
            trace_id=trace_context.get("trace_id") or None,
            correlation_id=trace_context.get("correlation_id") or None,
            request_id=trace_context.get("request_id") or None,
        ))
        evidence = evaluation.get("evidence") or {}
        match_timestamp = evidence.get("match_timestamp")
        if match_timestamp:
            session.add(ReconciliationMatch(
                id=f"recon_match_{event_key[:24]}",
                tenant_id=tenant_id,
                transaction_id=trans_id,
                matched_record=evidence.get("matched_record"),
                matching_rules=evidence.get("matching_rules", []),
                match_score=evidence.get("match_score", 0),
                match_timestamp=datetime.fromisoformat(match_timestamp),
                engine_version=evidence.get("engine_version", "unknown"),
                status=phase3_status or "EXCEPTION",
                processing_latency_ms=evaluation.get("processing_latency_ms", 0),
                created_at=datetime.now(timezone.utc),
            ))
        result_topic = TOPIC_DISCREPANCIES if is_discrepancy else TOPIC_MATCHED
        session.add(ReconciliationOutbox(
            id=f"recon_outbox_{event_key[:12]}",
            tenant_id=tenant_id,
            event_key=event_key,
            topic=result_topic,
            payload=result_payload,
            status="pending",
            created_at=datetime.now(timezone.utc),
            available_at=datetime.now(timezone.utc),
        ))
        transition_reconciliation(processed.reconciliation_status, "completed")
        processed.reconciliation_status = "completed"
        processed.reconciliation_completed_at = datetime.now(timezone.utc)
        session.commit()
        return ProcessResult.STORED

    except Exception as exc:
        logger.exception("Atomic persist transaction failed for trans_id=%s — rolling back: %s", trans_id, exc)
        session.rollback()
        return ProcessResult.ERROR
    finally:
        session.close()


def _publish_downstream(evaluation: Dict[str, Any], trans_id: str, producer: Any, tenant_id: str) -> None:
    """Best-effort publish of reconciliation results to downstream Kafka topics."""
    provider_id = provider_account_id(evaluation.get("event", {}))
    event_key = hashlib.sha256(f"{tenant_id}:{provider_id}:{trans_id}".encode("utf-8")).hexdigest()
    session = None
    outbox = None

    try:
        session = AuditSession()
        outbox = session.query(ReconciliationOutbox).filter_by(tenant_id=tenant_id, event_key=event_key).first()
        if outbox is None or outbox.status == "published":
            session.close()
            return
        topic = outbox.topic
        is_discrepancy = topic == TOPIC_DISCREPANCIES
        outbox.status = "processing"
        outbox.attempts = (outbox.attempts or 0) + 1
        session.commit()
        key_bytes = str(trans_id).encode("utf-8")
        val_bytes = json.dumps(outbox.payload, ensure_ascii=False).encode("utf-8")

        try:
            future = producer.send(topic, key=key_bytes, value=val_bytes)
        except TypeError:
            future = producer.send(topic, val_bytes)

        if hasattr(producer, "flush"):
            producer.flush(timeout=5)
        if hasattr(future, "get"):
            future.get(timeout=5)

        if is_discrepancy:
            logger.warning("Discrepancy event published for trans_id=%s to topic=%s", trans_id, topic)
            dispatch_discrepancy_alert({**evaluation, **outbox.payload}, tenant_id=tenant_id)
        else:
            logger.info("Transaction %s cleanly reconciled and published to %s", trans_id, topic)
        outbox.status = "published"
        outbox.published_at = datetime.now(timezone.utc)
        outbox.locked_until = None
        session.commit()
        session.close()

    except Exception as exc:
        try:
            if outbox is None or session is None:
                raise RuntimeError("reconciliation outbox state was not initialized")
            outbox.status = "failed"
            outbox.last_error = str(exc)[:1000]
            outbox.available_at = datetime.now(timezone.utc)
            outbox.locked_until = None
            session.commit()
            session.close()
        except Exception:
            logger.exception("Failed recording reconciliation outbox failure for trans_id=%s", trans_id)
        logger.exception(
            "Failed publishing trans_id=%s to downstream topic=%s. DB record remains authoritative.",
            trans_id, topic
        )


def publish_reconciliation_outbox_batch(producer: Any, limit: int = 100) -> Dict[str, int]:
    """Publish leased reconciliation outbox rows and persist retryable outcomes."""
    published = 0
    failed = 0
    for row in event_store.claim_reconciliation_outbox_batch(limit=limit):
        try:
            try:
                future = producer.send(row["topic"], key=row["event_key"].encode("utf-8"),
                                       value=json.dumps(row["payload"], ensure_ascii=False).encode("utf-8"))
            except TypeError:
                future = producer.send(row["topic"], json.dumps(row["payload"], ensure_ascii=False).encode("utf-8"))
            if hasattr(producer, "flush"):
                producer.flush(timeout=5)
            if hasattr(future, "get"):
                future.get(timeout=5)
            event_store.mark_reconciliation_outbox_published(row["id"])
            published += 1
        except Exception as exc:
            event_store.mark_reconciliation_outbox_failed(row["id"], str(exc))
            failed += 1
            logger.exception("Failed publishing reconciliation outbox id=%s", row["id"])
    return {"published": published, "failed": failed}


def _process_message(event: Dict[str, Any], consumer: Any, producer: Any, connector_registry: Any) -> bool:
    tenant_id = str(event.get("tenant_id") or event.get("TenantID") or DEFAULT_TENANT_ID)
    with tenant_limiter.acquire(tenant_id):
        return _process_message_unbounded(event, consumer, producer, connector_registry)


def _process_message_unbounded(event: Dict[str, Any], consumer: Any, producer: Any, connector_registry: Any) -> bool:
    """Process a single reconciliation event for a transaction payload."""
    trans_id = str(event.get("TransID") or event.get("trans_id") or "unknown").strip()
    tenant_id = str(event.get("tenant_id") or event.get("TenantID") or DEFAULT_TENANT_ID)

    try:
        seen_trans_ids: Set[str] = set()
        tenant_settings = settings_store.get(tenant_id)
        anomalies = check_for_anomalies(event, seen_trans_ids, tenant_settings)

        connector = connector_registry.get_connector(tenant_id)
        if connector and hasattr(connector, "fetch_candidate_records"):
            raw_amount = event.get("TransAmount") or event.get("amount")
            try:
                amount = Decimal(str(raw_amount)) if raw_amount is not None else None
            except Exception:
                amount = None
            tolerance = (amount * Decimal("0.005")) if amount is not None else None
            internal_records = connector.fetch_candidate_records(
                since_minutes=WINDOW_MINUTES,
                amount=amount,
                phone_number=str(event.get("MSISDN") or event.get("phone_number") or "").strip() or None,
                tolerance=tolerance,
                limit=500,
            )
        else:
            internal_records = connector.fetch_recent_records(since_minutes=WINDOW_MINUTES) if connector else []

        phase3_result = reconciliation_engine.reconcile(
            event,
            internal_records,
            seen_transaction_ids=seen_trans_ids,
        )
        phase3_status = phase3_result["status"]
        compatibility = {
            "MATCHED": ("matched", "info"),
            "UNMATCHED": ("missing_payment", "critical"),
            "PARTIAL": ("needs_review", "warning"),
            "MISMATCH": ("needs_review", "warning"),
            "DUPLICATE": ("duplicate_ignored", "info"),
            "PENDING": ("pending", "warning"),
            "EXCEPTION": ("needs_review", "critical"),
        }
        legacy_status, severity = compatibility[phase3_status]
        evaluation = {
            "trans_id": trans_id,
            "status": legacy_status,
            "severity": severity,
            "phase3_status": phase3_status,
            "match": {"match_type": phase3_status.lower(), "evidence": phase3_result["evidence"]},
            "evidence": phase3_result["evidence"],
            "processing_latency_ms": phase3_result["processing_latency_ms"],
            "anomalies": list(phase3_result["evidence"].get("matching_rules", [])) if phase3_status != "MATCHED" else [],
        }

        evaluation["tenant_id"] = tenant_id
        evaluation["event"] = event
        evaluation["checked_at"] = datetime.now(timezone.utc).isoformat()
        evaluation["anomalies"] = list(set(anomalies + evaluation.get("anomalies", [])))

        logger.info(
            "Reconciled trans_id=%s tenant_id=%s status=%s severity=%s",
            trans_id, tenant_id, evaluation["status"], evaluation["severity"]
        )

        persist_result = _persist_atomically(event, evaluation, trans_id, tenant_id)

        if persist_result == ProcessResult.DUPLICATE:
            logger.info("Duplicate trans_id=%s caught during flush, advancing offset.", trans_id)
            return True

        if persist_result == ProcessResult.ERROR:
            logger.error("Persistence failed for trans_id=%s. Offset NOT committed for retry.", trans_id)
            return False

        if producer is not None:
            _publish_downstream(evaluation, trans_id, producer, tenant_id)
        return True

    except Exception as exc:
        logger.exception("Unexpected error processing trans_id=%s in reconciliation loop: %s", trans_id, exc)
        return False


def _commit_message(consumer: Any, message: Any) -> None:
    """Commit exactly this message, including its partition and next offset."""
    if not hasattr(consumer, "commit"):
        return
    try:
        from kafka import TopicPartition
        from kafka.structs import OffsetAndMetadata
        consumer.commit({TopicPartition(message.topic, message.partition): OffsetAndMetadata(message.offset + 1, None)})
    except (ImportError, AttributeError):
        consumer.commit()


def _message_traceparent(message: Any) -> Optional[str]:
    """Extract a W3C traceparent header from a kafka-python message if the producer injected one."""
    headers = getattr(message, "headers", None) or []
    for key, value in headers:
        if str(key).lower() == "traceparent" and value:
            try:
                return value.decode("ascii")
            except Exception:
                continue
    return None


def process_polled_batch(message_batch: Dict[Any, Any], consumer: Any, producer: Any, connector_registry: Any) -> Dict[str, int]:
    """Process a bounded poll while preserving message order within each partition."""
    processed = 0
    failed = 0
    for _partition, messages in message_batch.items():
        for message in list(messages)[:BATCH_SIZE]:
            if not _RUNNING:
                break
            traceparent = _message_traceparent(message)
            if traceparent:
                try:
                    from logging_utils import bind_observability_context
                    from observability import extract_trace_context
                    parsed = extract_trace_context({"traceparent": traceparent})
                    if parsed:
                        bind_observability_context(trace_id=parsed["trace_id"], span_id=parsed["span_id"], traceparent=traceparent)
                except Exception:
                    logger.debug("Could not bind incoming W3C trace context from message headers", exc_info=True)
            if _process_message(message.value, consumer, producer, connector_registry) is not False:
                _commit_message(consumer, message)
                processed += 1
            else:
                failed += 1
    return {"processed": processed, "failed": failed}


def run():
    """Main execution loop for the reconciliation Kafka consumer service."""
    if not HAS_KAFKA or KafkaConsumer is None or KafkaProducer is None:
        logger.error("Kafka client dependencies unavailable. Reconciliation job exiting.")
        sys.exit(1)

    logger.info("Initializing Reconciliation Job consumer on topic='%s'...", TOPIC_RAW)

    consumer = KafkaConsumer(
        TOPIC_RAW,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        group_id="pesaguard-reconciliation-v2",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        max_poll_records=BATCH_SIZE,
    )

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
        retries=3,
        acks="all",
    )

    connector_registry = ConnectorRegistry.from_env()
    logger.info("Reconciliation worker active and listening for M-Pesa callbacks...")
    last_outbox_publish = 0.0

    while _RUNNING:
        now = time.monotonic()
        if now - last_outbox_publish >= 5:
            try:
                publish_reconciliation_outbox_batch(producer, limit=BATCH_SIZE)
            except Exception:
                logger.exception("Reconciliation outbox recovery pass failed; continuing Kafka consumption")
            last_outbox_publish = now
        if hasattr(consumer, "poll"):
            message_batch = consumer.poll(timeout_ms=1000)
            if not message_batch:
                continue
            process_polled_batch(message_batch, consumer, producer, connector_registry)
        else:
            for message in consumer:
                if not _RUNNING:
                    break
                if _process_message(message.value, consumer, producer, connector_registry) is not False:
                    _commit_message(consumer, message)

    logger.info("Cleaning up Kafka consumer resources...")
    try:
        if hasattr(consumer, "close"):
            consumer.close()
        if hasattr(producer, "close"):
            producer.close(timeout=5)
    except Exception as exc:
        logger.debug("Error during consumer shutdown: %s", exc)
    logger.info("Reconciliation Job stopped cleanly.")


if __name__ == "__main__":
    run()
