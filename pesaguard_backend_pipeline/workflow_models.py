"""Durable tenant-scoped workflow records for dashboard workflow APIs.

The records model stores workflow metadata only. It never initiates payments,
posts ledger entries, executes refunds, or performs destructive privacy actions.
Domain-specific payloads are validated by workflow_api.py.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, Column, DateTime, Index, Integer, JSON, String, Text
from models import Base


class TenantWorkflowRecord(Base):
    __tablename__ = "tenant_workflow_records"
    __table_args__ = (
        Index("ix_workflow_tenant_domain_status_created", "tenant_id", "domain", "status", "created_at"),
        Index("ix_workflow_tenant_domain_updated", "tenant_id", "domain", "updated_at"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_workflow_tenant_nonempty"),
        CheckConstraint("domain IN ('reconciliation_run','matching_rule','data_quality_finding','scheduled_reconciliation','settlement_review','refund_reversal_request','report_definition','report_run','fraud_investigation','privacy_request','support_case')", name="ck_workflow_domain"),
        CheckConstraint("status IN ('draft','requested','queued','running','completed','failed','open','triage','in_progress','pending_review','approved','rejected','resolved','closed','disabled','scheduled','cancelled','needs_information')", name="ck_workflow_status"),
        CheckConstraint("version >= 1", name="ck_workflow_version_positive"),
    )

    id = Column(String(64), primary_key=True, default=lambda: "wf_" + uuid.uuid4().hex)
    tenant_id = Column(String(128), nullable=False)
    domain = Column(String(40), nullable=False)
    status = Column(String(32), nullable=False, default="open", server_default="open")
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    payload = Column(JSON, nullable=False, default=dict, server_default="{}")
    created_by = Column(String(128), nullable=False)
    updated_by = Column(String(128), nullable=False)
    version = Column(Integer, nullable=False, default=1, server_default="1")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
