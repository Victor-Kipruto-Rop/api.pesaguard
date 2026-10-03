"""
SQLAlchemy ORM Data Models for PesaGuard's Postgres Store.

Defines schemas for Daraja transactions, idempotency tracking, discrepancy logging,
webhooks, escalation rules, on-call schedules, email audits, and dead-letter queues.
"""

from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


def _transaction_id_default(context):
    trans_id = str(context.get_current_parameters().get("trans_id") or "").strip()
    return trans_id


def _transaction_key_default(context):
    trans_id = _transaction_id_default(context)
    return f"transid:{trans_id.upper()}"


class Transaction(Base):
    """Raw M-Pesa transaction events received from Daraja webhooks."""

    __tablename__ = "transactions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "provider_account_id", "trans_id", name="uq_transaction_scope_trans_id"),
        Index("ix_transaction_scope_trans_id", "tenant_id", "provider_account_id", "trans_id"),
        Index("ix_transaction_trans_id", "trans_id"),
        Index("ix_transaction_created_at", "created_at"),
        Index("ix_transaction_msisdn", "msisdn"),
        UniqueConstraint("tenant_id", "id", name="uq_transaction_tenant_id"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_transactions_tenant_id_nonempty"),
        CheckConstraint("trans_amount > 0", name="ck_transactions_trans_amount_positive"),
        CheckConstraint("length(currency) = 3 AND currency = upper(currency)", name="ck_transactions_currency_iso"),
        CheckConstraint("status IN ('RECEIVED', 'VALIDATED', 'PROCESSING', 'RECONCILING', 'RECONCILED', 'FAILED', 'REJECTED')", name="ck_transactions_status"),
        CheckConstraint("lifecycle_stage IN ('CREATED', 'INGESTED', 'VALIDATED', 'PROCESSED', 'STORED', 'CONSUMED', 'ARCHIVED', 'DELETED', 'QUARANTINED')", name="ck_transactions_lifecycle_stage"),
        CheckConstraint("version >= 1", name="ck_transactions_version_positive"),
        UniqueConstraint("tenant_id", "provider", "provider_transaction_id", name="uq_transaction_provider_reference"),
        UniqueConstraint("tenant_id", "provider", "external_reference", name="uq_transaction_external_reference"),
    )

    id = Column(String, primary_key=True, default=lambda: f"txn_{uuid.uuid4().hex}")
    trans_id = Column(String, nullable=False)
    tenant_id = Column(String, nullable=False)
    provider_account_id = Column(String, nullable=False, default="legacy-default", server_default="legacy-default")
    provider = Column(String(64), nullable=False, default="mpesa", server_default="mpesa")
    idempotency_key = Column(String(255), nullable=False, default=_transaction_key_default)
    external_reference = Column(String(255), nullable=True)
    provider_transaction_id = Column(String(255), nullable=False, default=_transaction_id_default)
    trans_amount = Column(Numeric(18, 2), nullable=False)
    currency = Column(String(3), nullable=False, default="KES", server_default="KES")
    msisdn = Column(String, nullable=False)
    business_short_code = Column(String, nullable=False)
    trans_time = Column(String, nullable=False)  # Raw string timestamp format from Daraja
    raw_payload = Column(JSON, nullable=False)
    status = Column(String(32), nullable=False, default="RECEIVED", server_default="RECEIVED")
    lifecycle_stage = Column(String(16), nullable=False, default="STORED", server_default="STORED")
    archived_at = Column(DateTime(timezone=True), nullable=True)
    archive_object_key = Column(String(1024), nullable=True)
    version = Column(Integer, nullable=False, default=1, server_default="1")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    __mapper_args__ = {"version_id_col": version}


class TransformationRecord(Base):
    """Append-only evidence for each immutable transaction data stage."""

    __tablename__ = "transformation_records"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_id", "stage", name="uq_transformation_stage_event"),
        Index("ix_transformation_tenant_transaction", "tenant_id", "transaction_id", "created_at"),
        Index("ix_transformation_tenant_stage", "tenant_id", "stage", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_transformation_tenant_nonempty"),
        CheckConstraint("stage IN ('RAW', 'VALIDATED', 'NORMALIZED', 'ENRICHED', 'PROCESSED')", name="ck_transformation_stage"),
    )

    id = Column(String, primary_key=True, default=lambda: f"stage_{uuid.uuid4().hex}")
    tenant_id = Column(String, nullable=False)
    transaction_id = Column(String, nullable=False)
    event_id = Column(String, nullable=False)
    source_event_id = Column(String, nullable=True)
    stage = Column(String(16), nullable=False)
    payload = Column(JSON, nullable=False)
    payload_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class MerchantMetric(Base):
    """Persisted derived merchant metrics for dashboard and reporting reads."""

    __tablename__ = "merchant_metrics"
    __table_args__ = (
        UniqueConstraint("tenant_id", "merchant_id", "granularity", "bucket_start", name="uq_merchant_metric_bucket"),
        Index("ix_merchant_metrics_tenant_bucket", "tenant_id", "granularity", "bucket_start"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_merchant_metrics_tenant_nonempty"),
        CheckConstraint("granularity IN ('hour', 'day', 'week')", name="ck_merchant_metrics_granularity"),
        CheckConstraint("transaction_count >= 0", name="ck_merchant_metrics_count_nonnegative"),
        CheckConstraint("failed_transactions >= 0", name="ck_merchant_metrics_failed_nonnegative"),
        CheckConstraint("reconciled_transactions >= 0", name="ck_merchant_metrics_reconciled_nonnegative"),
        CheckConstraint("anomaly_count >= 0", name="ck_merchant_metrics_anomaly_nonnegative"),
    )

    id = Column(String, primary_key=True, default=lambda: f"metric_{uuid.uuid4().hex}")
    tenant_id = Column(String, nullable=False)
    merchant_id = Column(String, nullable=False)
    granularity = Column(String(8), nullable=False)
    bucket_start = Column(DateTime(timezone=True), nullable=False)
    transaction_count = Column(Integer, nullable=False, default=0, server_default="0")
    total_volume = Column(Numeric(20, 2), nullable=False, default=0, server_default="0")
    average_transaction = Column(Numeric(20, 2), nullable=False, default=0, server_default="0")
    failed_transactions = Column(Integer, nullable=False, default=0, server_default="0")
    reconciled_transactions = Column(Integer, nullable=False, default=0, server_default="0")
    anomaly_count = Column(Integer, nullable=False, default=0, server_default="0")
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class DeletionRequest(Base):
    """Durable approval and execution state for controlled data deletion."""

    __tablename__ = "deletion_requests"
    __table_args__ = (
        Index("ix_deletion_requests_tenant_status", "tenant_id", "status", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_deletion_request_tenant_nonempty"),
        CheckConstraint("status IN ('pending', 'approved', 'anonymized', 'deleted', 'rejected', 'failed')", name="ck_deletion_request_status"),
    )

    id = Column(String, primary_key=True, default=lambda: f"del_{uuid.uuid4().hex}")
    tenant_id = Column(String, nullable=False)
    transaction_id = Column(String, nullable=False)
    requested_by = Column(String, nullable=False)
    reason = Column(Text, nullable=False)
    status = Column(String(16), nullable=False, default="pending", server_default="pending")
    decision = Column(String(32), nullable=True)
    dependency_report = Column(JSON, nullable=False, default=dict, server_default="{}")
    authorization_reference = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class LineageRecord(Base):
    """Append-only record connecting a served result to its source event."""

    __tablename__ = "lineage_records"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_id", "stage", name="uq_lineage_event_stage"),
        Index("ix_lineage_tenant_transaction", "tenant_id", "transaction_id", "created_at"),
        Index("ix_lineage_tenant_source_event", "tenant_id", "source_event_id"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_lineage_tenant_nonempty"),
    )

    id = Column(String, primary_key=True, default=lambda: f"lineage_{uuid.uuid4().hex}")
    tenant_id = Column(String, nullable=False)
    transaction_id = Column(String, nullable=False)
    event_id = Column(String, nullable=False)
    stage = Column(String(32), nullable=False)
    source = Column(String(64), nullable=False)
    source_event_id = Column(String(255), nullable=True)
    upstream_event_id = Column(String(255), nullable=True)
    ingestion_time = Column(DateTime(timezone=True), nullable=False)
    pipeline_version = Column(String(64), nullable=False)
    transformation_version = Column(String(64), nullable=False)
    job_id = Column(String(255), nullable=True)
    correlation_id = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class IdempotencyRecord(Base):
    """Durable request identity ledger shared by API and provider ingestion."""

    __tablename__ = "idempotency_records"
    __table_args__ = (
        UniqueConstraint("tenant_id", "provider", "idempotency_key", name="uq_idempotency_request"),
        UniqueConstraint("tenant_id", "provider", "provider_transaction_id", name="uq_idempotency_provider_reference"),
        Index("ix_idempotency_tenant_key", "tenant_id", "idempotency_key"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_idempotency_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    provider = Column(String(64), nullable=False)
    idempotency_key = Column(String(255), nullable=False)
    external_reference = Column(String(255), nullable=True)
    provider_transaction_id = Column(String(255), nullable=False)
    request_hash = Column(String(64), nullable=False)
    response = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class AuditEvent(Base):
    """Append-only business audit event ledger."""

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_key", name="uq_audit_events_tenant_key"),
        Index("ix_audit_events_tenant_created", "tenant_id", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_audit_events_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    event_key = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    aggregate_type = Column(String, nullable=False)
    aggregate_id = Column(String, nullable=False)
    actor = Column(String, nullable=False)
    payload_hash = Column(String(64), nullable=False)
    details = Column(JSON, nullable=False, default=dict, server_default="{}")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class ReconciliationMatch(Base):
    """Durable, queryable evidence for one reconciliation decision."""

    __tablename__ = "reconciliation_matches"
    __table_args__ = (
        UniqueConstraint("tenant_id", "transaction_id", name="uq_reconciliation_matches_transaction"),
        Index("ix_reconciliation_matches_tenant_status", "tenant_id", "status", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_reconciliation_matches_tenant_nonempty"),
        CheckConstraint("status IN ('MATCHED', 'UNMATCHED', 'PARTIAL', 'MISMATCH', 'DUPLICATE', 'PENDING', 'EXCEPTION')", name="ck_reconciliation_matches_status"),
        CheckConstraint("match_score >= 0 AND match_score <= 1", name="ck_reconciliation_matches_score"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    transaction_id = Column(String, nullable=False)
    matched_record = Column(JSON, nullable=True)
    matching_rules = Column(JSON, nullable=False, default=list, server_default="[]")
    match_score = Column(Numeric(5, 4), nullable=False)
    match_timestamp = Column(DateTime(timezone=True), nullable=False)
    engine_version = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False)
    processing_latency_ms = Column(Numeric(12, 3), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class ReconciliationGroundTruth(Base):
    """Validated expected outcomes used to calculate certification metrics."""

    __tablename__ = "reconciliation_ground_truth"
    __table_args__ = (
        UniqueConstraint("tenant_id", "transaction_id", name="uq_reconciliation_ground_truth_transaction"),
        Index("ix_reconciliation_ground_truth_validation", "tenant_id", "validated_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_reconciliation_ground_truth_tenant_nonempty"),
        CheckConstraint("expected_status IN ('MATCHED', 'UNMATCHED', 'PARTIAL', 'MISMATCH', 'DUPLICATE', 'PENDING', 'EXCEPTION')", name="ck_ground_truth_expected_status"),
        CheckConstraint("actual_status IS NULL OR actual_status IN ('MATCHED', 'UNMATCHED', 'PARTIAL', 'MISMATCH', 'DUPLICATE', 'PENDING', 'EXCEPTION')", name="ck_ground_truth_actual_status"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    transaction_id = Column(String, nullable=False)
    expected_status = Column(String(32), nullable=False)
    actual_status = Column(String(32), nullable=True)
    source = Column(String(64), nullable=False, default="certification", server_default="certification")
    approved_by = Column(String(128), nullable=False)
    approval_reference = Column(String(255), nullable=False)
    approved_at = Column(DateTime(timezone=True), nullable=False)
    validated_by = Column(String(128), nullable=True)
    validated_at = Column(DateTime(timezone=True), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class TransactionEvent(Base):
    """Append-only source and lifecycle history for a financial transaction."""

    __tablename__ = "transaction_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_key", name="uq_transaction_events_tenant_key"),
        Index("ix_transaction_events_transaction", "tenant_id", "transaction_id", "created_at"),
        Index("ix_transaction_events_correlation", "tenant_id", "correlation_id"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_transaction_events_tenant_id_nonempty"),
        ForeignKeyConstraint(
            ["tenant_id", "transaction_id"],
            ["transactions.tenant_id", "transactions.id"],
            name="fk_transaction_events_transaction_id",
        ),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    transaction_id = Column(String, nullable=True)
    trans_id = Column(String, nullable=False)
    event_key = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    from_state = Column(String, nullable=True)
    to_state = Column(String, nullable=False)
    actor = Column(String, nullable=False)
    reason = Column(Text, nullable=True)
    payload_hash = Column(String(64), nullable=True)
    correlation_id = Column(String, nullable=True)
    details = Column(JSON, nullable=False, default=dict, server_default="{}")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class ProcessedTransaction(Base):
    """
    Explicit Idempotency Ledger: Tracks which webhook callbacks have been received.
    
    Prevents race conditions and duplicate transaction handling using a unique constraint
    on daraja_trans_id.
    """

    __tablename__ = "processed_transactions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "provider_account_id", "daraja_trans_id", name="uq_processed_scope_trans_id"),
        Index("ix_processed_daraja_id", "daraja_trans_id"),
        Index("ix_processed_scope", "tenant_id", "provider_account_id"),
        Index("ix_processed_received_at", "received_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_processed_tenant_id_nonempty"),
        CheckConstraint("status IN ('received', 'validated', 'stored', 'failed')", name="ck_processed_status"),
        CheckConstraint("reconciliation_status IN ('pending', 'processing', 'completed', 'failed')", name="ck_processed_reconciliation_status"),
    )

    id = Column(String, primary_key=True)
    daraja_trans_id = Column(String, nullable=False)
    tenant_id = Column(String, nullable=False)
    provider_account_id = Column(String, nullable=False, default="legacy-default", server_default="legacy-default")
    status = Column(String, nullable=False, default="received")  # received, validated, stored, failed
    processing_time_ms = Column(Integer, nullable=True)
    received_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    webhook_attempt_number = Column(Integer, default=1)
    source_ip = Column(String, nullable=True)
    signature_verified = Column(Boolean, default=False)
    error_reason = Column(String, nullable=True)
    reconciliation_status = Column(String, nullable=False, default="pending", server_default="pending")
    reconciliation_attempts = Column(Integer, nullable=False, default=0, server_default="0")
    reconciliation_started_at = Column(DateTime(timezone=True), nullable=True)
    reconciliation_completed_at = Column(DateTime(timezone=True), nullable=True)
    reconciliation_error = Column(Text, nullable=True)


class FraudRiskAssessment(Base):
    """Explainable fraud decision persisted independently from reconciliation state."""

    __tablename__ = "fraud_risk_assessments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "transaction_id", name="uq_fraud_risk_tenant_transaction"),
        Index("ix_fraud_risk_tenant_level", "tenant_id", "risk_level", "created_at"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="ck_fraud_risk_score_range"),
        CheckConstraint("risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="ck_fraud_risk_level"),
    )

    id = Column(String, primary_key=True, default=lambda: f"fraud_{uuid.uuid4().hex}")
    tenant_id = Column(String, nullable=False)
    transaction_id = Column(String, nullable=False)
    risk_score = Column(Numeric(6, 4), nullable=False)
    risk_level = Column(String(16), nullable=False)
    action = Column(String(16), nullable=False)
    reason_codes = Column(JSON, nullable=False, default=list, server_default="[]")
    model_version = Column(String(64), nullable=False)
    rules_triggered = Column(JSON, nullable=False, default=list, server_default="[]")
    features = Column(JSON, nullable=False, default=dict, server_default="{}")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class TransactionOutbox(Base):
    """Durable downstream publication intent for an accepted transaction."""

    __tablename__ = "transaction_outbox"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_key", name="uq_transaction_outbox_tenant_event"),
        Index("ix_transaction_outbox_pending", "status", "available_at", "created_at"),
        Index("ix_transaction_outbox_tenant_created", "tenant_id", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_transaction_outbox_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default", server_default="default")
    event_key = Column(String, nullable=False)
    topic = Column(String, nullable=False)
    payload = Column(JSON, nullable=False)
    status = Column(String, nullable=False, default="pending", server_default="pending")
    attempts = Column(Integer, nullable=False, default=0, server_default="0")
    available_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    published_at = Column(DateTime(timezone=True), nullable=True)


class ImportJob(Base):
    """Durable lifecycle and counters for one tenant-scoped file import."""

    __tablename__ = "import_jobs"
    __table_args__ = (
        Index("ix_import_jobs_tenant_status", "tenant_id", "status", "created_at"),
        Index("ix_import_jobs_status_created", "status", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_import_jobs_tenant_id_nonempty"),
        CheckConstraint("status IN ('queued', 'running', 'completed', 'failed')", name="ck_import_jobs_status"),
        CheckConstraint("records_received >= 0", name="ck_import_jobs_received_nonnegative"),
        CheckConstraint("records_valid >= 0", name="ck_import_jobs_valid_nonnegative"),
        CheckConstraint("records_failed >= 0", name="ck_import_jobs_failed_nonnegative"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    source = Column(String(64), nullable=False)
    filename = Column(String(255), nullable=False)
    file_format = Column(String(16), nullable=False)
    object_key = Column(String(512), nullable=False, unique=True)
    records_received = Column(Integer, nullable=False, default=0, server_default="0")
    records_valid = Column(Integer, nullable=False, default=0, server_default="0")
    records_failed = Column(Integer, nullable=False, default=0, server_default="0")
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(16), nullable=False, default="queued", server_default="queued")
    error_summary = Column(JSON, nullable=False, default=list, server_default="[]")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class ReconciliationOutbox(Base):
    """Durable publication intent for matched/discrepancy outcomes."""

    __tablename__ = "reconciliation_outbox"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_key", name="uq_reconciliation_outbox_tenant_event"),
        Index("ix_reconciliation_outbox_pending", "status", "available_at", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_reconciliation_outbox_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default", server_default="default")
    event_key = Column(String, nullable=False)
    topic = Column(String, nullable=False)
    payload = Column(JSON, nullable=False)
    status = Column(String, nullable=False, default="pending", server_default="pending")
    attempts = Column(Integer, nullable=False, default=0, server_default="0")
    available_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    published_at = Column(DateTime(timezone=True), nullable=True)


class Discrepancy(Base):
    """Reconciliation anomaly records flagged during transaction checks."""

    __tablename__ = "discrepancies"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_discrepancy_tenant_id"),
        Index("ix_discrepancy_trans_id", "trans_id"),
        Index("ix_discrepancy_tenant_id", "tenant_id"),
        Index("ix_discrepancy_detected_at", "detected_at"),
        Index("ix_discrepancy_status_resolved", "status", "resolved"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_discrepancy_tenant_id_nonempty"),
        CheckConstraint("status IN ('needs_review', 'reviewed', 'resolved', 'escalated')", name="ck_discrepancy_status"),
        CheckConstraint("severity IN ('info', 'warning', 'critical')", name="ck_discrepancy_severity"),
    )

    id = Column(String, primary_key=True)  # Format: f"{trans_id}-{anomaly_type}"
    trans_id = Column(String, nullable=False)
    tenant_id = Column(String, nullable=False, default="default", server_default="default")
    anomaly_type = Column(String, nullable=False)
    status = Column(String, nullable=False, default="needs_review")
    severity = Column(String, nullable=False, default="warning")
    details = Column(Text, nullable=True)
    resolved = Column(Boolean, default=False)
    detected_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_note = Column(Text, nullable=True)
    latency_seconds = Column(Integer, nullable=True)
    assignee = Column(String, nullable=True)
    notes = Column(Text, nullable=True)
    timeline = Column(JSON, nullable=True, default=list)


class DiscrepancyEvent(Base):
    """Append-only discrepancy lifecycle event history."""

    __tablename__ = "discrepancy_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_key", name="uq_discrepancy_events_tenant_key"),
        Index("ix_discrepancy_events_scope", "tenant_id", "discrepancy_id", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_discrepancy_events_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    discrepancy_id = Column(String, nullable=False)
    event_key = Column(String, nullable=False)
    from_state = Column(String, nullable=True)
    to_state = Column(String, nullable=False)
    actor = Column(String, nullable=False)
    reason = Column(Text, nullable=True)
    correlation_id = Column(String, nullable=True)
    details = Column(JSON, nullable=False, default=dict, server_default="{}")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class DiscrepancyFilterPreset(Base):
    """A tenant's saved discrepancy/incident search filter.

    Mirrors CommunicationSavedFilter (communications/models.py) -- same shape,
    separate table, because discrepancy filters and communications filters are
    different resources with different tenants' data in their JSON payload.
    """

    __tablename__ = "discrepancy_filter_presets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_discrepancy_filter_preset_name"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_discrepancy_filter_preset_tenant_id_nonempty"),
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    owner_user_id = Column(String(128), nullable=True)
    name = Column(String(128), nullable=False)
    filters = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), server_default="now()")


class InternalRecord(Base):
    """Customer internal ledger or order system record baseline for comparison."""

    __tablename__ = "internal_records"
    __table_args__ = (
        Index("ix_internal_records_tenant_phone", "tenant_id", "phone_number"),
        Index("ix_internal_records_phone", "phone_number"),
        Index("ix_internal_records_synced", "synced_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_internal_records_tenant_id_nonempty"),
    )

    internal_ref = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default", server_default="default")
    amount = Column(Numeric(18, 2), nullable=False)
    phone_number = Column(String, nullable=False)
    status = Column(String, nullable=False)
    synced_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class WebhookConfig(Base):
    """Registered customer outbound webhook endpoint configurations."""

    __tablename__ = "webhook_configs"
    __table_args__ = (
        Index("ix_webhook_configs_tenant", "tenant_id"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_webhook_configs_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    url = Column(String, nullable=False)
    event_types = Column(JSON, nullable=False)  # e.g., ["escalation", "resolution"]
    active = Column(Boolean, default=True)
    retry_attempts = Column(Integer, default=3)
    timeout_seconds = Column(Integer, default=10)
    signing_secret = Column(String, nullable=True)  # Dynamic HMAC signing key
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class WebhookDelivery(Base):
    """Outbound webhook delivery execution and response audit logs."""

    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        Index("ix_webhook_deliveries_webhook_id", "webhook_id"),
        Index("ix_webhook_deliveries_tenant_webhook", "tenant_id", "webhook_id"),
        Index("ix_webhook_deliveries_created_at", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_webhook_deliveries_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default", server_default="default")
    webhook_id = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    payload = Column(JSON, nullable=False)
    status = Column(String, nullable=False)  # success, failed, pending
    response_status = Column(Integer, nullable=True)
    response_body = Column(Text, nullable=True)
    attempt_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    delivered_at = Column(DateTime(timezone=True), nullable=True)


class EscalationRule(Base):
    """Per-tenant automated escalation criteria and notification triggers."""

    __tablename__ = "escalation_rules"
    __table_args__ = (
        Index("ix_escalation_rules_tenant", "tenant_id", "priority"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_escalation_rules_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    condition_field = Column(String, nullable=False)  # e.g., "severity", "anomaly_type"
    condition_operator = Column(String, nullable=False)  # e.g., "equals", "greater_than"
    condition_value = Column(String, nullable=False)
    action = Column(String, nullable=False)  # "escalate", "notify", "webhook"
    target = Column(String, nullable=True)
    webhook_url = Column(String, nullable=True)
    active = Column(Boolean, default=True)
    priority = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class OnCallRotation(Base):
    """On-call operational shift rotation schedules."""

    __tablename__ = "on_call_rotations"
    __table_args__ = (
        Index("ix_on_call_tenant_shift", "tenant_id", "shift_start", "shift_end"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_on_call_rotations_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    operator_id = Column(String, nullable=False)
    operator_name = Column(String, nullable=True)
    operator_email = Column(String, nullable=True)
    operator_phone = Column(String, nullable=True)
    shift_start = Column(DateTime(timezone=True), nullable=False)
    shift_end = Column(DateTime(timezone=True), nullable=False)
    is_active = Column(Boolean, default=False)
    escalation_level = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class EmailNotification(Base):
    """Audit log for outgoing email alerts and reconciliation reports."""

    __tablename__ = "email_notifications"
    __table_args__ = (
        Index("ix_email_tenant_created", "tenant_id", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_email_notifications_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    recipient_email = Column(String, nullable=False)
    report_type = Column(String, nullable=False)  # "reconciliation", "daily_summary", "escalation"
    subject = Column(String, nullable=False)
    status = Column(String, nullable=False)  # "pending", "sent", "failed"
    content_hash = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class PublicStatusSubscription(Base):
    """Double-opt-in email subscriptions for public service-status changes."""

    __tablename__ = "public_status_subscriptions"
    __table_args__ = (
        UniqueConstraint("email_hash", name="uq_public_status_subscription_email_hash"),
        Index("ix_public_status_subscription_confirmed", "confirmed"),
    )

    id = Column(String(32), primary_key=True)
    email = Column(String(254), nullable=False)
    email_hash = Column(String(64), nullable=False)
    confirmation_token_hash = Column(String(64), nullable=True)
    confirmation_expires_at = Column(DateTime(timezone=True), nullable=True)
    confirmed = Column(Boolean, nullable=False, default=False, server_default="false")
    last_status_fingerprint = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)


class DeadLetter(Base):
    """Failed, malformed, or unprocessable webhook payload repository."""

    __tablename__ = "dead_letters"
    __table_args__ = (
        Index("ix_dead_letters_tenant", "tenant_id"),
        Index("ix_dead_letters_created", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_dead_letters_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default", server_default="default")
    reason = Column(String, nullable=False)
    payload = Column(JSON, nullable=True)
    error_detail = Column(Text, nullable=True)
    attempts = Column(Integer, default=0)
    processed = Column(Boolean, default=False)
    processed_at = Column(DateTime(timezone=True), nullable=True)
    replay_status = Column(String, nullable=False, default="idle", server_default="idle")
    replayed_by = Column(String, nullable=True)
    replayed_at = Column(DateTime(timezone=True), nullable=True)
    replay_reason = Column(Text, nullable=True)
    provider_account_id = Column(String, nullable=True)
    event_key = Column(String, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    received_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class Report(Base):
    """Persisted daily, weekly, or ad-hoc reconciliation reports."""

    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_tenant_type", "tenant_id", "report_type"),
        Index("ix_reports_created", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_reports_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    report_type = Column(String, nullable=False)  # "daily", "weekly", "monthly"
    period_start = Column(DateTime(timezone=True), nullable=False)
    period_end = Column(DateTime(timezone=True), nullable=False)
    content = Column(JSON, nullable=True)
    status = Column(String, nullable=False, default="generated")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    delivered_at = Column(DateTime(timezone=True), nullable=True)


class UserAccount(Base):
    """Local account record provisioned from an external IdP or internal directory."""

    __tablename__ = "user_accounts"
    __table_args__ = (
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_user_accounts_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default")
    username = Column(String, nullable=False)
    email = Column(String, nullable=True)
    password_hash = Column(String, nullable=True)
    password_salt = Column(String, nullable=True)
    roles = Column(JSON, nullable=False, default=list)
    permissions = Column(JSON, nullable=False, default=list)
    attributes = Column(JSON, nullable=True, default=dict)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    status = Column(String, nullable=False, default="active")
    authorization_version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class Organization(Base):
    """Top-level SaaS organization or customer tenant container."""

    __tablename__ = "organizations"
    __table_args__ = (
        Index("ix_organizations_tenant_slug", "tenant_id", "slug", unique=True),
        Index("ix_organizations_tenant_id", "tenant_id"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_organizations_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default")
    name = Column(String, nullable=False)
    slug = Column(String, nullable=False)
    owner_user_id = Column(String, nullable=True)
    status = Column(String, nullable=False, default="active")
    settings = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class Team(Base):
    """Functional team within an organization."""

    __tablename__ = "teams"
    __table_args__ = (
        Index("ix_teams_organization_tenant", "organization_id", "tenant_id"),
        Index("ix_teams_slug", "tenant_id", "slug", unique=False),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_teams_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default")
    organization_id = Column(String, nullable=False)
    name = Column(String, nullable=False)
    slug = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class Department(Base):
    """Department or sub-unit under a team or organization."""

    __tablename__ = "departments"
    __table_args__ = (
        Index("ix_departments_organization_tenant", "organization_id", "tenant_id"),
        Index("ix_departments_team", "team_id"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_departments_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default")
    organization_id = Column(String, nullable=False)
    team_id = Column(String, nullable=True)
    name = Column(String, nullable=False)
    slug = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class OrganizationMembership(Base):
    """Associates users with organizations, teams, and departments."""

    __tablename__ = "organization_memberships"
    __table_args__ = (
        Index("ix_org_membership_user_tenant", "tenant_id", "user_id"),
        Index("ix_org_membership_org", "organization_id"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_organization_memberships_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default")
    user_id = Column(String, nullable=False)
    organization_id = Column(String, nullable=False)
    team_id = Column(String, nullable=True)
    department_id = Column(String, nullable=True)
    role = Column(String, nullable=False, default="member")
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class OrganizationApproval(Base):
    """Approval workflow records for SaaS org onboarding and lifecycle changes."""

    __tablename__ = "organization_approvals"
    __table_args__ = (
        Index("ix_org_approval_tenant", "tenant_id", "status"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_organization_approvals_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default")
    organization_id = Column(String, nullable=True)
    request_type = Column(String, nullable=False, default="create")
    requested_by = Column(String, nullable=False)
    approver_id = Column(String, nullable=True)
    status = Column(String, nullable=False, default="pending")
    reason = Column(Text, nullable=True)
    approval_metadata = Column(JSON, nullable=True, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)


class TenantConfiguration(Base):
    """Tenant-wide configuration and feature flags."""

    __tablename__ = "tenant_configurations"
    __table_args__ = (
        Index("ix_tenant_config_unique", "tenant_id", unique=True),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_tenant_configurations_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default")
    organization_id = Column(String, nullable=True)
    config = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class TenantLimit(Base):
    """Enforced limit for a tenant or organization metric."""

    __tablename__ = "tenant_limits"
    __table_args__ = (
        Index("ix_tenant_limits_tenant_metric", "tenant_id", "organization_id", "metric_name", "period", unique=True),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_tenant_limits_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default")
    organization_id = Column(String, nullable=False)
    metric_name = Column(String, nullable=False)
    limit_value = Column(Float, nullable=False, default=0.0)
    period = Column(String, nullable=False, default="monthly")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class TransactionProvenance(Base):
    """Provenance + data-quality snapshot for one transaction lifecycle.

    This is the Phase 9 exit-gate anchor: it answers where data originated,
    what changed it, which service processed it, which version processed it,
    and what the final decision was. The table is append-only once finalized.
    """

    __tablename__ = "transaction_provenances"
    __table_args__ = (
        Index("ix_prov_tenant_final", "tenant_id", "final_decision"),
        Index("ix_prov_tenant_created", "tenant_id", "created_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_prov_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True, default=lambda: f"prov_{uuid.uuid4().hex}")
    tenant_id = Column(String, nullable=False)
    transaction_id = Column(String, nullable=False)
    provider_id = Column(String, nullable=False)
    lineage_id = Column(String, nullable=False)
    event_id = Column(String, nullable=False)
    schema_version = Column(String(64), nullable=False, default="1.0")
    pipeline_version = Column(String(64), nullable=False, default="1.0")
    raw_payload_sha256 = Column(String(64), nullable=False)
    provider_payload_sha256 = Column(String(64), nullable=True)
    provider_source_ip = Column(String, nullable=True)
    provider_signature_verified = Column(Boolean, nullable=False, default=False)
    normalized_payload_sha256 = Column(String(64), nullable=True)
    normalized_at = Column(DateTime(timezone=True), nullable=True)
    fraud_decision = Column(String, nullable=True)
    fraud_checked_at = Column(DateTime(timezone=True), nullable=True)
    reconciliation_decision = Column(String, nullable=True)
    reconciliation_checked_at = Column(DateTime(timezone=True), nullable=True)
    final_decision = Column(String, nullable=True)
    dq_status = Column(String(16), nullable=False, default="pass")
    dq_completeness = Column(Numeric(5, 4), nullable=False, default=1.0)
    dq_validity = Column(Numeric(5, 4), nullable=False, default=1.0)
    dq_accuracy = Column(Numeric(5, 4), nullable=False, default=1.0)
    dq_timeliness = Column(Numeric(5, 4), nullable=False, default=1.0)
    dq_consistency = Column(Numeric(5, 4), nullable=False, default=1.0)
    dq_uniqueness = Column(Numeric(5, 4), nullable=False, default=1.0)
    dq_failures = Column(JSON, nullable=False, default=list)
    dq_warnings = Column(JSON, nullable=False, default=list)
    dq_checked_at = Column(DateTime(timezone=True), nullable=False)
    lineage_snapshot = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    finalized_at = Column(DateTime(timezone=True), nullable=True)


class QuarantineRecord(Base):
    """Quarantined payload that failed one or more data-quality checks.

    Quarantine is the safe destination for bad records. Nothing from quarantine
    automatically contaminates production transaction datasets.
    """

    __tablename__ = "quarantine_records"
    __table_args__ = (
        Index("ix_quarantine_tenant_reason", "tenant_id", "reason"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_quarantine_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True, default=lambda: f"q_{uuid.uuid4().hex}")
    tenant_id = Column(String, nullable=False)
    transaction_id = Column(String, nullable=True)
    provider_id = Column(String, nullable=False)
    lineage_id = Column(String, nullable=True)
    reason = Column(String, nullable=False)
    failure_rule = Column(String, nullable=True)
    payload = Column(JSON, nullable=False)
    payload_sha256 = Column(String(64), nullable=False)
    rejection_context = Column(JSON, nullable=True)
    source_ip = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class TenantUsage(Base):
    """Usage tracking for tenant and organization resource consumption."""

    __tablename__ = "tenant_usage"
    __table_args__ = (
        Index("ix_tenant_usage_tenant_metric", "tenant_id", "organization_id", "metric_name", "period", unique=True),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_tenant_usage_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default")
    organization_id = Column(String, nullable=False)
    metric_name = Column(String, nullable=False)
    current_usage = Column(Float, nullable=False, default=0.0)
    period = Column(String, nullable=False, default="monthly")
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class UserSession(Base):
    """Authenticated session record for device and session risk evaluation."""

    __tablename__ = "user_sessions"
    __table_args__ = (
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_user_sessions_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default")
    user_id = Column(String, nullable=True)
    device_id = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    active = Column(Boolean, nullable=False, default=True)
    issued_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    session_metadata = Column(JSON, nullable=True, default=dict)


class OIDCProvider(Base):
    """Tenant-managed external OIDC identity provider configuration."""

    __tablename__ = "oidc_providers"
    __table_args__ = (
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_oidc_providers_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default")
    provider_name = Column(String, nullable=False)
    issuer = Column(String, nullable=False)
    client_id = Column(String, nullable=True)
    client_secret = Column(String, nullable=True)
    authorization_endpoint = Column(String, nullable=True)
    token_endpoint = Column(String, nullable=True)
    userinfo_endpoint = Column(String, nullable=True)
    jwks_uri = Column(String, nullable=True)
    scopes = Column(JSON, nullable=False, default=list)
    allowed_roles = Column(JSON, nullable=False, default=list)
    auto_provision = Column(Boolean, nullable=False, default=False)
    claim_mapping = Column(JSON, nullable=True, default=dict)
    provider_metadata = Column("provider_metadata", JSON, nullable=True, default=dict)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class PaymentProvider(Base):
    """Tenant-scoped payment provider registration and operational configuration."""

    __tablename__ = "payment_providers"
    __table_args__ = (
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_payment_providers_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default", index=True)
    name = Column(String, nullable=False)
    provider_type = Column(String, nullable=False, default="payment")
    status = Column(String, nullable=False, default="active")
    credentials = Column(JSON, nullable=False, default=dict)
    api_configuration = Column(JSON, nullable=False, default=dict)
    account_configuration = Column(JSON, nullable=False, default=dict)
    provider_metadata = Column("metadata", JSON, nullable=False, default=dict)
    supported_currencies = Column(JSON, nullable=False, default=list)
    capabilities = Column(JSON, nullable=False, default=list)
    webhook_configuration = Column(JSON, nullable=False, default=dict)
    connection_status = Column(String, nullable=False, default="unknown")
    connection_checked_at = Column(DateTime(timezone=True), nullable=True)
    health_status = Column(String, nullable=False, default="unknown")
    health_details = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class ApiKeyRecord(Base):
    """Tenant-scoped API keys issued for machine access."""

    __tablename__ = "api_key_records"
    __table_args__ = (
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_api_key_records_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, default="default")
    key_hash = Column(String(128), nullable=False, unique=True, index=True)
    key_prefix = Column(String(32), nullable=False)
    role = Column(String, nullable=False, default="read-only")
    scopes = Column(JSON, nullable=False, default=list, server_default="[]")
    expires_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    rotated_from_id = Column(String, nullable=True)
    api_metadata = Column("api_metadata", JSON, nullable=True, default=dict)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class MFAChallenge(Base):
    """MFA challenge state for end-user verification flows."""

    __tablename__ = "mfa_challenges"
    __table_args__ = (
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_mfa_challenges_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    tenant_id = Column(String, nullable=False)
    code_hash = Column(String(128), nullable=False)
    status = Column(String, nullable=False, default="pending")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    attempts = Column(Integer, nullable=False, default=0)


class PasswordlessChallenge(Base):
    """Passwordless challenge state for email or magic-link verification."""

    __tablename__ = "passwordless_challenges"
    __table_args__ = (
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_passwordless_challenges_tenant_id_nonempty"),
    )

    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    tenant_id = Column(String, nullable=False)
    token_hash = Column(String(128), nullable=False)
    status = Column(String, nullable=False, default="pending")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
