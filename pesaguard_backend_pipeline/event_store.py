"""A lightweight durable event store for idempotency and replay.

Uses ProcessedTransaction table as the idempotency source of truth.
Each webhook callback from Daraja is recorded exactly once via unique constraint.
"""

from __future__ import annotations

from environment import required_env

import logging
import os
import threading
import uuid
import hashlib
import json
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Optional

from sqlalchemy import create_engine, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from lifecycle import transition_data_lifecycle, transition_transaction
from event_bus import build_event
from idempotency import derive_idempotency_key
from normalization import normalize_amount
from models import AuditEvent, Base, IdempotencyRecord, ProcessedTransaction, ReconciliationOutbox, Transaction, TransactionEvent, TransactionOutbox
from transformation_store import record_transformation_stage
from lineage import record_lineage
from data_protection import protect_payload, tokenize_identifier

logger = logging.getLogger("pesaguard.event_store")

# Providers recognised by the ingestion layer. A provider that is NOT in this
# set is rejected as an "invalid provider reference" so garbled or forged
# provider values can never bypass idempotency scoping.
VALID_PROVIDERS = frozenset(
    {
        "mpesa",
        "airtel-money",
        "equitel",
        "t-kash",
        "safaricom",
        "bank",
        "pos",
        "csv",
        "external-api",
        "webhook",
    }
)


def _money(value: Any) -> Decimal:
    """Normalize provider amounts without binary floating-point conversion."""
    amount = Decimal(normalize_amount(value))
    if amount <= 0:
        raise ValueError("transaction amount must be greater than zero")
    return amount


def _currency(value: Any) -> str:
    """Validate an explicitly provided currency code.

    Missing keys are resolved to the provider default (KES) by callers; an
    explicit empty or non-ISO string is a hard validation error.
    """
    raw = str(value).strip()
    if not raw:
        raise ValueError("transaction currency is required and must be a three-letter ISO code")
    currency = raw.upper()
    if len(currency) != 3 or not currency.isalpha():
        raise ValueError("transaction currency must be a three-letter ISO code")
    return currency


def _resolve_currency(payload: Dict[str, Any]) -> str:
    """Resolve the currency from a payload, defaulting to KES when absent."""
    if "Currency" in payload:
        return _currency(payload["Currency"])
    if "currency" in payload:
        return _currency(payload["currency"])
    return "KES"


def _provider(value: Any) -> str:
    """Normalise and validate the provider reference on an inbound payload.

    A payload that explicitly declares a provider must use one of the known
    provider identifiers; an explicit unknown/empty/garbled provider is an
    invalid provider reference and is rejected.
    """
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("provider reference is required")
    provider = raw.lower()
    if provider not in VALID_PROVIDERS:
        raise ValueError(f"provider '{raw}' is not a recognised provider reference")
    return provider


def _payload_hash(payload: Dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def provider_account_id(payload: Dict[str, Any]) -> str:
    """Resolve the stable Daraja account identity used for idempotency scope."""
    return str(
        payload.get("provider_account_id")
        or payload.get("BusinessShortCode")
        or payload.get("business_short_code")
        or "legacy-default"
    ).strip()


class ProcessResult(str, Enum):
    """Outcome of attempting to record a webhook callback.

    The webhook handler MUST branch on this, not treat it as a plain boolean â€”
    STORED and DUPLICATE both mean "return 200 to Daraja, no retry needed".
    ERROR means "return 5xx so Daraja retries" â€” a genuine failure must never
    be indistinguishable from a benign duplicate, or real transactions can be
    silently dropped.
    """

    STORED = "stored"        # new transaction, successfully recorded
    DUPLICATE = "duplicate"  # already processed before â€” safe no-op
    ERROR = "error"          # genuine failure â€” caller should signal retry


class EventStore:
    """Persist processed transactions so duplicate callbacks can be ignored safely.

    Uses ProcessedTransaction table as explicit idempotency ledger. This table tracks
    which webhook callbacks (identified by Daraja TransID) have been received and processed.
    The unique constraint on daraja_trans_id is the hard guarantee against race conditions â€”
    the already_processed() check is just an optimization to skip needless work, not the
    actual safety mechanism.
    """

    def __init__(self, database_url: Optional[str] = None, isolation_level: str = "serializable"):
        self.database_url = database_url or required_env("DATABASE_URL")
        self.isolation_level = isolation_level
        self.engine = None
        self.Session = None
        self._initialized = False
        self._init_lock = threading.Lock()

    def _ensure_ready(self) -> None:
        """Thread-safe lazy initialization of the database engine and session factory."""
        if self._initialized:
            return

        with self._init_lock:
            if self._initialized:
                return

            connect_args = {}
            if "postgresql" in self.database_url:
                connect_args["connect_timeout"] = int(os.getenv("DB_CONNECT_TIMEOUT", "5"))

            if self.database_url.startswith("sqlite"):
                self.engine = create_engine(
                    self.database_url,
                    connect_args={"check_same_thread": False},
                    isolation_level=self.isolation_level if "postgresql" in self.database_url else None,
                )
            else:
                self.engine = create_engine(
                    self.database_url,
                    pool_pre_ping=True,
                    pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
                    max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
                    isolation_level=self.isolation_level if "postgresql" in self.database_url else None,
                    connect_args=connect_args,
                )
            # Production PostgreSQL schemas are owned by Alembic. SQLite is
            # retained as an explicit test/development convenience only.
            from observability import instrument_sqlalchemy_engine
            instrument_sqlalchemy_engine(self.engine)

            if self.database_url.startswith("sqlite"):
                Base.metadata.create_all(self.engine)
            self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
            self._initialized = True

    def already_processed(
        self,
        trans_id: str,
        tenant_id: Optional[str] = None,
        provider_account: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> bool:
        """Check if a webhook callback has already been processed (idempotency gate).

        This is an optimization only â€” the real guarantee is the unique constraint
        enforced in mark_processed(). Conservative: returns True on DB errors, so a
        transient read failure doesn't cause reprocessing.

        Args:
            trans_id: Daraja M-Pesa TransID
            source_ip: Optional IP address of callback source (for audit)

        Returns:
            True if this callback has been seen before, or if the check itself
            failed (conservative fallback). False only on a confirmed "not seen".
        """
        if not trans_id:
            return False
        try:
            self._ensure_ready()
            with self.Session() as session:
                existing = session.query(ProcessedTransaction).filter(
                    ProcessedTransaction.daraja_trans_id == str(trans_id),
                    ProcessedTransaction.tenant_id == (tenant_id or "default"),
                    ProcessedTransaction.provider_account_id == (provider_account or "legacy-default"),
                ).first()
                return existing is not None
        except SQLAlchemyError:
            logger.exception(
                "already_processed() check failed for trans_id=%s â€” assuming processed "
                "(conservative fallback); mark_processed's unique constraint remains the "
                "real safety net.",
                trans_id,
            )
            return True

    def mark_processed(
        self,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        signature_verified: bool = False,
        idempotency_key_override: Optional[str] = None,
    ) -> ProcessResult:
        """Atomically record that a webhook callback has been processed.

        Creates a ProcessedTransaction record with a unique constraint on
        daraja_trans_id. Distinguishes an expected duplicate (unique constraint
        violation) from a genuine error (connection failure, etc.) â€” callers must
        NOT treat these the same way.

        Args:
            payload: Daraja webhook payload dict
            tenant_id: Optional tenant identifier
            source_ip: Optional IP address of callback source
            signature_verified: Whether HMAC signature was valid

        Returns:
            ProcessResult.STORED    â€” new transaction, recorded successfully
            ProcessResult.DUPLICATE â€” already recorded, safe no-op
            ProcessResult.ERROR     â€” genuine failure, caller should signal retry
        """
        trans_id = str(payload.get("TransID", "")).strip()
        tenant_id = str(tenant_id or "").strip()
        if not tenant_id:
            logger.error("mark_processed() rejected missing tenant for trans_id=%s", trans_id)
            return ProcessResult.ERROR
        account_id = provider_account_id(payload)
        idempotency_key = (idempotency_key_override or derive_idempotency_key(payload)).strip()
        if not idempotency_key or len(idempotency_key) > 255:
            logger.error("mark_processed() rejected invalid idempotency key for trans_id=%s", trans_id)
            return ProcessResult.ERROR
        try:
            currency = _resolve_currency(payload)
            amount = _money(payload.get("TransAmount", 0))
            raw_provider = str(payload.get("provider") or "").strip()
            provider = _provider(raw_provider) if raw_provider else "mpesa"
        except ValueError as exc:
            logger.error("mark_processed() rejected trans_id=%s: %s", trans_id, exc)
            return ProcessResult.ERROR
        if not trans_id or not provider or provider == "unknown" or not account_id:
            logger.error("mark_processed() called with missing TransID in payload")
            return ProcessResult.ERROR
        from logging_utils import get_observability_context
        from observability import extract_trace_context

        event_context = get_observability_context()
        candidate_traceparent = str(event_context.get("traceparent") or "").strip()
        event_metadata = {}
        if extract_trace_context({"traceparent": candidate_traceparent}):
            event_metadata["traceparent"] = candidate_traceparent
        event_correlation_id = str(
            payload.get("correlation_id")
            or event_context.get("correlation_id")
            or idempotency_key
        )
        event_payload = build_event(
            "transaction.received",
            tenant_id,
            trans_id,
            payload,
            event_id=idempotency_key,
            correlation_id=event_correlation_id,
            metadata=event_metadata,
        ).to_dict()
        event_payload["TransID"] = trans_id
        from logging_utils import bind_observability_context
        bind_observability_context(
            transaction_id=trans_id,
            event_id=event_payload["event_id"],
            correlation_id=event_payload["correlation_id"],
            tenant_id=tenant_id,
        )

        try:
            self._ensure_ready()
        except SQLAlchemyError:
            logger.exception("EventStore failed to initialize DB engine")
            return ProcessResult.ERROR

        try:
            with self.Session() as session:
                existing_identity = session.query(IdempotencyRecord).filter(
                    IdempotencyRecord.tenant_id == tenant_id,
                    IdempotencyRecord.provider == provider,
                    IdempotencyRecord.idempotency_key == idempotency_key,
                ).one_or_none()
                if existing_identity is not None:
                    return ProcessResult.DUPLICATE
                pt_record = ProcessedTransaction(
                    id=f"pt_{uuid.uuid4().hex[:12]}",
                    daraja_trans_id=trans_id,
                    tenant_id=tenant_id,
                    provider_account_id=account_id,
                    status="received",
                    source_ip=source_ip,
                    signature_verified=signature_verified,
                    webhook_attempt_number=int(payload.get("retry_count", 1)),
                    received_at=datetime.now(timezone.utc),
                )
                session.add(pt_record)

                t_record = Transaction(
                    trans_id=trans_id,
                    tenant_id=tenant_id,
                    provider_account_id=account_id,
                    provider=provider,
                    idempotency_key=idempotency_key,
                    external_reference=str(payload.get("BillRefNumber") or payload.get("external_reference") or "").strip() or None,
                    provider_transaction_id=trans_id,
                    trans_amount=amount,
                    currency=currency,
                    msisdn=tokenize_identifier(payload.get("MSISDN", "")),
                    business_short_code=str(payload.get("BusinessShortCode", "")),
                    trans_time=str(payload.get("TransTime", "")),
                    raw_payload=protect_payload(payload),
                    lifecycle_stage="STORED",
                    created_at=datetime.now(timezone.utc),
                )
                session.add(t_record)
                session.flush()
                session.add(TransactionEvent(
                    id=f"te_{idempotency_key[:24]}",
                    tenant_id=tenant_id,
                    transaction_id=t_record.id,
                    trans_id=trans_id,
                    event_key=f"{idempotency_key}:received",
                    event_type="transaction.received",
                    to_state="RECEIVED",
                    actor="event_store",
                    payload_hash=_payload_hash(payload),
                    correlation_id=str(payload.get("correlation_id") or "") or None,
                    details={"provider_account_id": account_id},
                    created_at=datetime.now(timezone.utc),
                ))
                record_transformation_stage(
                    session,
                    tenant_id=tenant_id,
                    transaction_id=t_record.id,
                    event_id=event_payload["event_id"],
                    source_event_id=str(event_payload.get("source_event_id") or ""),
                    stage="RAW",
                    payload=payload.get("raw_payload") if isinstance(payload.get("raw_payload"), dict) else payload,
                )
                record_lineage(
                    session,
                    tenant_id=tenant_id,
                    transaction_id=trans_id,
                    event_id=event_payload["event_id"],
                    stage="RAW",
                    source=str(payload.get("source") or payload.get("provider") or "unknown"),
                    source_event_id=str(payload.get("source_event_id") or trans_id),
                    pipeline_version=os.getenv("PESAGUARD_PIPELINE_VERSION", "1"),
                    transformation_version="raw-1",
                    job_id=str(payload.get("job_id") or "") or None,
                    correlation_id=str(event_payload.get("correlation_id") or "") or None,
                )

                session.add(TransactionOutbox(
                    id=f"outbox_{uuid.uuid4().hex[:12]}",
                    tenant_id=tenant_id,
                    event_key=idempotency_key,
                    topic=os.getenv("KAFKA_TOPIC_TRANSACTIONS", "pesaguard.transactions.raw"),
                    payload=protect_payload(event_payload),
                    status="pending",
                    available_at=datetime.now(timezone.utc),
                    created_at=datetime.now(timezone.utc),
                ))
                session.add(IdempotencyRecord(
                    id=f"idem_{uuid.uuid4().hex[:12]}",
                    tenant_id=tenant_id,
                    provider=provider,
                    idempotency_key=idempotency_key,
                    external_reference=str(payload.get("BillRefNumber") or payload.get("external_reference") or "").strip() or None,
                    provider_transaction_id=trans_id,
                    request_hash=_payload_hash(payload),
                ))
                session.add(AuditEvent(
                    id=f"audit_{uuid.uuid4().hex[:12]}",
                    tenant_id=tenant_id,
                    event_key=f"{idempotency_key}:accepted",
                    event_type="transaction.accepted",
                    aggregate_type="transaction",
                    aggregate_id=t_record.id,
                    actor="event_store",
                    payload_hash=_payload_hash(payload),
                    details={"provider": provider, "provider_transaction_id": trans_id},
                ))

                from observability import trace_span
                with trace_span("db.transaction.persist", transaction_id=trans_id, tenant_id=tenant_id):
                    session.commit()
                from metrics import record_business_metric
                record_business_metric("transactions_received")
                return ProcessResult.STORED

        except IntegrityError:
            if self.already_processed(trans_id, tenant_id=tenant_id, provider_account=account_id):
                logger.info(
                    "Duplicate webhook callback ignored for trans_id=%s idempotency_key=%s",
                    trans_id,
                    idempotency_key,
                )
                return ProcessResult.DUPLICATE
            logger.exception(
                "mark_processed() hit a non-duplicate integrity constraint for trans_id=%s idempotency_key=%s",
                trans_id,
                idempotency_key,
            )
            return ProcessResult.ERROR

        except SQLAlchemyError:
            logger.exception(
                "mark_processed() failed for trans_id=%s idempotency_key=%s due to a DB error, not a "
                "duplicate â€” this transaction was NOT stored and needs retry/investigation.",
                trans_id,
                idempotency_key,
            )
            return ProcessResult.ERROR

    def mark_processed_in_session(
        self,
        session: Session,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        signature_verified: bool = False,
    ) -> ProcessResult:
        
        trans_id = str(payload.get("TransID", "")).strip()
        tenant_id = str(tenant_id or "").strip()
        if not tenant_id:
            logger.error("mark_processed_in_session() rejected missing tenant for trans_id=%s", trans_id)
            return ProcessResult.ERROR
        account_id = provider_account_id(payload)
        idempotency_key = derive_idempotency_key(payload)
        try:
            currency = _resolve_currency(payload)
            amount = _money(payload.get("TransAmount", 0))
            raw_provider = str(payload.get("provider") or "").strip()
            provider = _provider(raw_provider) if raw_provider else "mpesa"
        except ValueError as exc:
            logger.error("mark_processed_in_session() rejected trans_id=%s: %s", trans_id, exc)
            return ProcessResult.ERROR
        if not trans_id or not provider or provider == "unknown" or not account_id:
            logger.error("mark_processed_in_session() called with missing TransID in payload")
            return ProcessResult.ERROR
        from logging_utils import get_observability_context
        from observability import extract_trace_context

        event_context = get_observability_context()
        candidate_traceparent = str(event_context.get("traceparent") or "").strip()
        event_metadata = {}
        if extract_trace_context({"traceparent": candidate_traceparent}):
            event_metadata["traceparent"] = candidate_traceparent
        event_correlation_id = str(
            payload.get("correlation_id")
            or event_context.get("correlation_id")
            or idempotency_key
        )
        event_payload = build_event(
            "transaction.received",
            tenant_id,
            trans_id,
            payload,
            event_id=idempotency_key,
            correlation_id=event_correlation_id,
            metadata=event_metadata,
        ).to_dict()
        event_payload["TransID"] = trans_id

        existing = session.query(ProcessedTransaction).filter(
            ProcessedTransaction.daraja_trans_id == trans_id,
            ProcessedTransaction.tenant_id == tenant_id,
            ProcessedTransaction.provider_account_id == account_id,
        ).first()
        if existing is not None:
            logger.info("Duplicate trans_id=%s detected in pre-flight session check", trans_id)
            return ProcessResult.DUPLICATE

        try:
            # Create a savepoint to catch duplicate constraints without breaking the parent transaction
            savepoint = session.begin_nested()

            pt_record = ProcessedTransaction(
                id=f"pt_{uuid.uuid4().hex[:12]}",
                daraja_trans_id=trans_id,
                tenant_id=tenant_id,
                provider_account_id=account_id,
                status="received",
                source_ip=source_ip,
                signature_verified=signature_verified,
                webhook_attempt_number=int(payload.get("retry_count", 1)),
                received_at=datetime.now(timezone.utc),
            )
            session.add(pt_record)

            t_record = Transaction(
                trans_id=trans_id,
                tenant_id=tenant_id,
                provider_account_id=account_id,
                provider=provider,
                idempotency_key=idempotency_key,
                external_reference=str(payload.get("BillRefNumber") or payload.get("external_reference") or "").strip() or None,
                provider_transaction_id=trans_id,
                trans_amount=amount,
                currency=currency,
                msisdn=tokenize_identifier(payload.get("MSISDN", "")),
                business_short_code=str(payload.get("BusinessShortCode", "")),
                trans_time=str(payload.get("TransTime", "")),
                raw_payload=protect_payload(payload),
                lifecycle_stage="STORED",
                created_at=datetime.now(timezone.utc),
            )
            session.add(t_record)
            session.flush()
            session.add(TransactionEvent(
                id=f"te_{idempotency_key[:24]}",
                tenant_id=tenant_id,
                transaction_id=t_record.id,
                trans_id=trans_id,
                event_key=f"{idempotency_key}:received",
                event_type="transaction.received",
                to_state="RECEIVED",
                actor="event_store",
                payload_hash=_payload_hash(payload),
                correlation_id=str(payload.get("correlation_id") or "") or None,
                details={"provider_account_id": account_id},
                created_at=datetime.now(timezone.utc),
            ))

            session.add(TransactionOutbox(
                id=f"outbox_{uuid.uuid4().hex[:12]}",
                tenant_id=tenant_id,
                event_key=idempotency_key,
                topic=os.getenv("KAFKA_TOPIC_TRANSACTIONS", "pesaguard.transactions.raw"),
                payload=protect_payload(event_payload),
                status="pending",
                available_at=datetime.now(timezone.utc),
                created_at=datetime.now(timezone.utc),
            ))
            session.add(IdempotencyRecord(
                id=f"idem_{uuid.uuid4().hex[:12]}",
                tenant_id=tenant_id,
                provider=provider,
                idempotency_key=idempotency_key,
                external_reference=str(payload.get("BillRefNumber") or payload.get("external_reference") or "").strip() or None,
                provider_transaction_id=trans_id,
                request_hash=_payload_hash(payload),
            ))
            session.add(AuditEvent(
                id=f"audit_{uuid.uuid4().hex[:12]}",
                tenant_id=tenant_id,
                event_key=f"{idempotency_key}:accepted",
                event_type="transaction.accepted",
                aggregate_type="transaction",
                aggregate_id=t_record.id,
                actor="event_store",
                payload_hash=_payload_hash(payload),
                details={"provider": provider, "provider_transaction_id": trans_id},
            ))

            session.flush()
            return ProcessResult.STORED

        except IntegrityError:
            savepoint.rollback()
            existing = session.query(ProcessedTransaction).filter(
                ProcessedTransaction.daraja_trans_id == trans_id,
                ProcessedTransaction.tenant_id == tenant_id,
                ProcessedTransaction.provider_account_id == account_id,
            ).first()
            if existing is not None:
                logger.info(
                    "Duplicate trans_id=%s idempotency_key=%s caught at flush time (race window closed by unique constraint)",
                    trans_id,
                    idempotency_key,
                )
                return ProcessResult.DUPLICATE
            logger.exception(
                "mark_processed_in_session() hit a non-duplicate integrity constraint for trans_id=%s idempotency_key=%s",
                trans_id,
                idempotency_key,
            )
            return ProcessResult.ERROR
        except SQLAlchemyError:
            savepoint.rollback()
            logger.exception(
                "mark_processed_in_session() encountered database error for trans_id=%s idempotency_key=%s",
                trans_id,
                idempotency_key,
            )
            return ProcessResult.ERROR

    def update_processing_status(
        self,
        trans_id: str,
        status: str,
        tenant_id: Optional[str] = None,
        provider_account: Optional[str] = None,
        error_reason: Optional[str] = None,
        processing_time_ms: Optional[int] = None,
    ) -> None:
        """Update the processing status of a webhook callback."""
        if not trans_id:
            return

        try:
            self._ensure_ready()
            with self.Session() as session:
                pt_record = session.query(ProcessedTransaction).filter(
                    ProcessedTransaction.daraja_trans_id == str(trans_id),
                    ProcessedTransaction.tenant_id == (tenant_id or "default"),
                    ProcessedTransaction.provider_account_id == (provider_account or "legacy-default"),
                ).first()
                if pt_record:
                    pt_record.status = status
                    if error_reason:
                        pt_record.error_reason = error_reason
                    if processing_time_ms is not None:
                        pt_record.processing_time_ms = processing_time_ms
                    session.commit()
                else:
                    logger.warning("update_processing_status() found no ProcessedTransaction for trans_id=%s", trans_id)
        except SQLAlchemyError:
            logger.exception("update_processing_status() failed for trans_id=%s", trans_id)

    def transition_transaction(
        self,
        trans_id: str,
        target: str,
        tenant_id: str,
        expected_version: int,
        actor: str = "system",
        reason: Optional[str] = None,
    ) -> bool:
        """Advance a transaction only when its state and version are current."""
        self._ensure_ready()
        with self.Session() as session:
            row = session.query(Transaction).filter(
                Transaction.trans_id == str(trans_id),
                Transaction.tenant_id == tenant_id,
                Transaction.version == expected_version,
            ).one_or_none()
            if row is None:
                return False
            try:
                new_state = transition_transaction(row.status, target)
            except ValueError:
                return False
            old_state = row.status
            row.status = new_state
            row.version += 1
            session.add(TransactionEvent(
                id=f"te_{uuid.uuid4().hex[:12]}",
                tenant_id=tenant_id,
                transaction_id=row.id,
                trans_id=str(trans_id),
                event_key=f"{row.id}:state:{row.version}",
                event_type="transaction.state_changed",
                from_state=old_state,
                to_state=new_state,
                actor=actor,
                reason=reason,
                details={"version": row.version},
            ))
            try:
                session.commit()
            except SQLAlchemyError:
                session.rollback()
                return False
            return True

    def mark_transaction_archived(self, transaction_id: str, tenant_id: str, object_key: str) -> bool:
        """Mark a transaction archived only after its immutable archive is written."""
        self._ensure_ready()
        with self.Session() as session:
            row = session.query(Transaction).filter(
                Transaction.id == transaction_id,
                Transaction.tenant_id == tenant_id,
            ).one_or_none()
            if row is None:
                return False
            try:
                transition_data_lifecycle(row.lifecycle_stage, "ARCHIVED")
            except ValueError:
                session.rollback()
                return False
            row.lifecycle_stage = "ARCHIVED"
            row.archive_object_key = object_key
            row.archived_at = datetime.now(timezone.utc)
            session.commit()
            return True

    def write_dead_letter(
        self,
        payload: Optional[Dict[str, Any]],
        reason: str,
        error_detail: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> None:
        """Persist a malformed or rejected webhook payload for later inspection and replay."""
        try:
            from models import DeadLetter

            self._ensure_ready()
            with self.Session() as session:
                scoped_tenant = tenant_id or "default"
                account_id = provider_account_id(payload or {})
                trans_id = str((payload or {}).get("TransID") or (payload or {}).get("trans_id") or "unknown")
                event_key = hashlib.sha256(f"{scoped_tenant}:{account_id}:{trans_id}:{reason}".encode("utf-8")).hexdigest()
                dl = DeadLetter(
                    id=f"dl_{event_key[:24]}",
                    tenant_id=scoped_tenant,
                    reason=reason,
                    payload=protect_payload(payload or {}),
                    error_detail=str(error_detail) if error_detail else None,
                    attempts=0,
                    processed=False,
                    processed_at=None,
                    replay_status="idle",
                    provider_account_id=account_id,
                    event_key=event_key,
                    created_at=datetime.now(timezone.utc),
                )
                session.add(dl)
                session.commit()
                logger.info("Recorded dead-letter entry id=%s reason=%s", dl.id, reason)
        except SQLAlchemyError:
            logger.exception(
                "write_dead_letter() failed for reason=%s â€” payload could not be persisted.",
                reason,
            )

    def claim_outbox_batch(self, limit: int = 100, lease_seconds: int = 60):
        """Claim a bounded batch of pending outbox rows for one worker lease."""
        self._ensure_ready()
        now = datetime.now(timezone.utc)
        lease_until = now + timedelta(seconds=lease_seconds)
        with self.Session() as session:
            rows = (
                session.query(TransactionOutbox)
                .filter(
                    TransactionOutbox.status.in_(["pending", "failed"]),
                    TransactionOutbox.available_at <= now,
                    or_(TransactionOutbox.locked_until.is_(None), TransactionOutbox.locked_until < now),
                )
                .order_by(TransactionOutbox.created_at.asc())
                .with_for_update(skip_locked=True)
                .limit(max(1, min(limit, 1000)))
                .all()
            )
            for row in rows:
                row.status = "processing"
                row.attempts += 1
                row.locked_until = lease_until
            session.commit()
            return [
                {
                    "id": row.id,
                    "tenant_id": row.tenant_id,
                    "topic": row.topic,
                    "payload": row.payload,
                    "attempts": row.attempts,
                }
                for row in rows
            ]

    def mark_outbox_published(self, outbox_id: str) -> None:
        """Mark a successfully published outbox row."""
        self._ensure_ready()
        with self.Session() as session:
            row = session.get(TransactionOutbox, outbox_id)
            if row is None:
                return
            row.status = "published"
            row.published_at = datetime.now(timezone.utc)
            row.locked_until = None
            session.commit()

    def mark_outbox_failed(self, outbox_id: str, error: str, retry_seconds: int = 30) -> None:
        """Release a failed outbox row with bounded retry backoff."""
        self._ensure_ready()
        with self.Session() as session:
            row = session.get(TransactionOutbox, outbox_id)
            if row is None:
                return
            row.status = "failed"
            row.last_error = str(error)[:1000]
            row.available_at = datetime.now(timezone.utc) + timedelta(seconds=min(max(retry_seconds, 1), 3600))
            row.locked_until = None
            session.commit()

    def mark_outbox_dead_lettered(self, outbox_id: str, error: str) -> None:
        """Atomically stop retrying an exhausted outbox row and record it for replay."""
        from models import DeadLetter

        self._ensure_ready()
        with self.Session() as session:
            row = session.get(TransactionOutbox, outbox_id)
            if row is None or row.status == "dead_lettered":
                return

            dead_letter_id = f"dl_outbox_{outbox_id}"
            dead_letter = session.get(DeadLetter, dead_letter_id)
            if dead_letter is None:
                dead_letter = DeadLetter(
                    id=dead_letter_id,
                    tenant_id=row.tenant_id,
                    reason="transaction_outbox_publish_exhausted",
                    payload=row.payload,
                    error_detail=str(error)[:2000],
                    attempts=row.attempts,
                    processed=False,
                    replay_status="idle",
                    event_key=row.event_key,
                    created_at=datetime.now(timezone.utc),
                )
                session.add(dead_letter)

            row.status = "dead_lettered"
            row.last_error = str(error)[:1000]
            row.locked_until = None
            session.commit()

    def claim_reconciliation_outbox_batch(self, limit: int = 100, lease_seconds: int = 60):
        """Claim due reconciliation publications with an expiring lease."""
        self._ensure_ready()
        now = datetime.now(timezone.utc)
        lease_until = now + timedelta(seconds=lease_seconds)
        with self.Session() as session:
            rows = (
                session.query(ReconciliationOutbox)
                .filter(
                    ReconciliationOutbox.status.in_(["pending", "failed"]),
                    ReconciliationOutbox.available_at <= now,
                    or_(ReconciliationOutbox.locked_until.is_(None), ReconciliationOutbox.locked_until < now),
                )
                .order_by(ReconciliationOutbox.created_at.asc())
                .with_for_update(skip_locked=True)
                .limit(max(1, min(limit, 1000)))
                .all()
            )
            for row in rows:
                row.status = "processing"
                row.attempts += 1
                row.locked_until = lease_until
            session.commit()
            return [
                {"id": row.id, "tenant_id": row.tenant_id, "event_key": row.event_key,
                 "topic": row.topic, "payload": row.payload, "attempts": row.attempts}
                for row in rows
            ]

    def mark_reconciliation_outbox_published(self, outbox_id: str) -> None:
        """Mark a successfully published reconciliation row."""
        self._ensure_ready()
        with self.Session() as session:
            row = session.get(ReconciliationOutbox, outbox_id)
            if row is None:
                return
            row.status = "published"
            row.published_at = datetime.now(timezone.utc)
            row.locked_until = None
            session.commit()

    def mark_reconciliation_outbox_failed(self, outbox_id: str, error: str, retry_seconds: int = 30) -> None:
        """Release a failed reconciliation row for a later retry."""
        self._ensure_ready()
        with self.Session() as session:
            row = session.get(ReconciliationOutbox, outbox_id)
            if row is None:
                return
            row.status = "failed"
            row.last_error = str(error)[:1000]
            row.available_at = datetime.now(timezone.utc) + timedelta(seconds=min(max(retry_seconds, 1), 3600))
            row.locked_until = None
            session.commit()


# Default singleton instance
event_store = EventStore()
