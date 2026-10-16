from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import declarative_base

try:
    from models import Base as _LocalBase
except Exception:
    _LocalBase = None

try:
    from pesaguard_backend_pipeline.models import Base
except Exception:
    Base = _LocalBase

if Base is None:
    Base = declarative_base()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CommunicationNotification(Base):
    __tablename__ = "communication_notifications"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_communication_notification_idempotency"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_communication_notification_tenant_id_nonempty"),
        CheckConstraint("status IN ('created', 'queued', 'processing', 'accepted', 'submitted', 'sent', 'delivered', 'opened', 'clicked', 'bounced', 'complained', 'failed', 'rejected', 'expired', 'cancelled', 'retrying', 'dead_letter')", name="ck_communication_notification_status"),
        CheckConstraint("priority IN ('critical', 'high', 'normal', 'low', 'bulk')", name="ck_communication_notification_priority"),
        Index("ix_communication_notification_tenant_status_created", "tenant_id", "status", "created_at"),
        Index("ix_communication_notification_tenant_correlation", "tenant_id", "correlation_id"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    channel = Column(String(32), nullable=False)
    recipient = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    template_id = Column(String(128), nullable=True)
    priority = Column(String(16), nullable=False, default="normal", server_default="normal")
    status = Column(String(32), nullable=False, default="created", server_default="created")
    idempotency_key = Column(String(255), nullable=False)
    provider = Column(String(64), nullable=True)
    provider_message_id = Column(String(255), nullable=True)
    correlation_id = Column(String(128), nullable=True)
    trace_id = Column(String(128), nullable=True)
    metadata_json = Column("metadata", JSON, nullable=False, default=dict, server_default="{}")
    failure_code = Column(String(64), nullable=True)
    failure_reason = Column(Text, nullable=True)
    queued_at = Column(DateTime(timezone=True), nullable=True)
    submitted_at = Column(DateTime(timezone=True), nullable=True)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    failed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")


class CommunicationOutboxEntry(Base):
    __tablename__ = "communication_outbox_entries"
    __table_args__ = (
        UniqueConstraint("notification_id", name="uq_communication_outbox_notification"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_communication_outbox_entry_tenant_id_nonempty"),
        CheckConstraint("status IN ('pending', 'leased', 'retrying', 'completed', 'dead_letter')", name="ck_communication_outbox_status"),
        CheckConstraint("attempt_count >= 0 AND max_attempts > 0", name="ck_communication_outbox_attempt_counts"),
        Index("ix_communication_outbox_due", "status", "available_at"),
        Index("ix_communication_outbox_lease", "lease_expires_at"),
        Index("ix_communication_outbox_tenant_status", "tenant_id", "status", "created_at"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    notification_id = Column(String(64), ForeignKey("communication_notifications.id"), nullable=False)
    tenant_id = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False, default="pending", server_default="pending")
    attempt_count = Column(Integer, nullable=False, default=0, server_default="0")
    max_attempts = Column(Integer, nullable=False, default=5, server_default="5")
    available_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    leased_by = Column(String(128), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")
    completed_at = Column(DateTime(timezone=True), nullable=True)


class CommunicationAttempt(Base):
    __tablename__ = "communication_attempts"
    __table_args__ = (
        UniqueConstraint("notification_id", "attempt_number", name="uq_communication_attempt_number"),
        Index("ix_communication_attempt_notification_started", "notification_id", "started_at"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    notification_id = Column(String(64), ForeignKey("communication_notifications.id"), nullable=False)
    attempt_number = Column(Integer, nullable=False)
    provider = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False)
    provider_message_id = Column(String(255), nullable=True)
    error_code = Column(String(64), nullable=True)
    error_category = Column(String(64), nullable=True)
    error_detail = Column(Text, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    cost = Column(JSON, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")
    completed_at = Column(DateTime(timezone=True), nullable=True)


class CommunicationDeliveryReport(Base):
    __tablename__ = "communication_delivery_reports"
    __table_args__ = (
        UniqueConstraint("provider", "provider_event_id", name="uq_communication_delivery_provider_event"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_communication_delivery_report_tenant_id_nonempty"),
        Index("ix_communication_delivery_notification_received", "notification_id", "received_at"),
        Index("ix_communication_delivery_tenant_status_received", "tenant_id", "status", "received_at"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    notification_id = Column(String(64), ForeignKey("communication_notifications.id"), nullable=True)
    tenant_id = Column(String(128), nullable=False)
    provider = Column(String(64), nullable=False)
    provider_event_id = Column(String(255), nullable=False)
    status = Column(String(32), nullable=False)
    raw_payload = Column(JSON, nullable=False)
    received_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")
    delivered_at = Column(DateTime(timezone=True), nullable=True)


class CommunicationWebhookEvent(Base):
    __tablename__ = "communication_webhook_events"
    __table_args__ = (
        UniqueConstraint("provider", "provider_event_id", "event_type", name="uq_communication_webhook_event"),
        CheckConstraint("processing_status IN ('pending', 'processed', 'unprocessed', 'ignored')", name="ck_communication_webhook_processing_status"),
        Index("ix_communication_webhook_tenant_received", "tenant_id", "received_at"),
        Index("ix_communication_webhook_processing_status", "processing_status", "received_at"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=True)
    provider = Column(String(64), nullable=False)
    provider_event_id = Column(String(255), nullable=False)
    event_type = Column(String(64), nullable=False)
    payload = Column(JSON, nullable=False)
    payload_hash = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default="received", server_default="received")
    processing_status = Column(String(32), nullable=False, default="pending", server_default="pending")
    signature_valid = Column(Integer, nullable=True, server_default="1")
    attempt_count = Column(Integer, nullable=False, default=0, server_default="0")
    received_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")
    processed_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)


class CommunicationTemplate(Base):
    __tablename__ = "communication_templates"
    __table_args__ = (
        UniqueConstraint("tenant_id", "slug", "version", name="uq_communication_template_version"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_communication_template_tenant_id_nonempty"),
        Index("ix_communication_template_tenant_slug", "tenant_id", "slug", "status"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    slug = Column(String(128), nullable=False)
    version = Column(Integer, nullable=False, default=1, server_default="1")
    channel = Column(String(32), nullable=False)
    body = Column(Text, nullable=False)
    variables = Column(JSON, nullable=False, default=list, server_default="[]")
    status = Column(String(32), nullable=False, default="draft", server_default="draft")
    approved_by = Column(String(128), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")


class CommunicationPreference(Base):
    __tablename__ = "communication_preferences"
    __table_args__ = (
        UniqueConstraint("tenant_id", "recipient", name="uq_communication_preference_recipient"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_communication_preference_tenant_id_nonempty"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    recipient = Column(String(255), nullable=False)
    channels = Column(JSON, nullable=False, default=list, server_default="[]")
    quiet_hours_start = Column(String(5), nullable=True)
    quiet_hours_end = Column(String(5), nullable=True)
    timezone = Column(String(64), nullable=False, default="Africa/Nairobi", server_default="Africa/Nairobi")
    marketing_opt_in = Column(Integer, nullable=False, default=0, server_default="0")
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")


class CommunicationConsent(Base):
    __tablename__ = "communication_consents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "recipient", "channel", name="uq_communication_consent"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_communication_consent_tenant_id_nonempty"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    recipient = Column(String(255), nullable=False)
    channel = Column(String(32), nullable=False)
    purpose = Column(String(64), nullable=False)
    granted = Column(Integer, nullable=False, default=0, server_default="0")
    source = Column(String(64), nullable=False, default="api", server_default="api")
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")


class CommunicationOtpChallenge(Base):
    __tablename__ = "communication_otp_challenges"
    __table_args__ = (
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_communication_otp_challenge_tenant_id_nonempty"),
        Index("ix_communication_otp_recipient_active", "tenant_id", "recipient", "expires_at"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    recipient = Column(String(255), nullable=False)
    purpose = Column(String(64), nullable=False)
    code_hash = Column(String(128), nullable=False)
    attempts = Column(Integer, nullable=False, default=0, server_default="0")
    max_attempts = Column(Integer, nullable=False, default=5, server_default="5")
    ip_address = Column(String(64), nullable=True)
    context_json = Column("context", JSON, nullable=False, default=dict, server_default="{}")
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")


class CommunicationCampaign(Base):
    __tablename__ = "communication_campaigns"
    __table_args__ = (
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_communication_campaign_tenant_id_nonempty"),
        CheckConstraint("status IN ('draft', 'queued', 'scheduled', 'running', 'paused', 'completed', 'cancelled')", name="ck_communication_campaign_status"),
        Index("ix_communication_campaign_tenant_schedule", "tenant_id", "status", "scheduled_at"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    name = Column(String(255), nullable=False)
    template_id = Column(String(64), ForeignKey("communication_templates.id"), nullable=False)
    channel = Column(String(32), nullable=False)
    audience = Column(JSON, nullable=False)
    status = Column(String(32), nullable=False, default="draft", server_default="draft")
    scheduled_at = Column(DateTime(timezone=True), nullable=True)
    rate_per_minute = Column(Integer, nullable=True)
    processed_count = Column(Integer, nullable=False, default=0, server_default="0")
    failed_count = Column(Integer, nullable=False, default=0, server_default="0")
    paused_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")


class CommunicationCampaignRecipient(Base):
    __tablename__ = "communication_campaign_recipients"
    __table_args__ = (
        UniqueConstraint("campaign_id", "recipient", name="uq_communication_campaign_recipient"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    campaign_id = Column(String(64), ForeignKey("communication_campaigns.id"), nullable=False)
    recipient = Column(String(255), nullable=False)
    status = Column(String(32), nullable=False, default="pending", server_default="pending")
    notification_id = Column(String(64), nullable=True)
    error = Column(Text, nullable=True)


class CommunicationProviderRoute(Base):
    __tablename__ = "communication_provider_routes"
    __table_args__ = (
        UniqueConstraint("tenant_id", "channel", "provider", name="uq_communication_provider_route"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_communication_provider_route_tenant_id_nonempty"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    channel = Column(String(32), nullable=False)
    provider = Column(String(64), nullable=False)
    priority = Column(Integer, nullable=False, default=100, server_default="100")
    enabled = Column(Integer, nullable=False, default=1, server_default="1")
    max_daily_cost = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")


class CommunicationIncident(Base):
    """Operational communication incident with fingerprint-based deduplication."""

    __tablename__ = "communication_incidents"
    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_communication_incident_fingerprint"),
        Index("ix_communication_incident_status_opened", "status", "opened_at"),
        Index("ix_communication_incident_tenant_opened", "tenant_id", "opened_at"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    reference = Column(String(32), nullable=False, unique=True)
    tenant_id = Column(String(128), nullable=True)
    title = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False, default="medium", server_default="medium")
    status = Column(String(16), nullable=False, default="open", server_default="open")
    fingerprint = Column(String(128), nullable=False)
    occurrence_count = Column(Integer, nullable=False, default=1, server_default="1")
    affected_count = Column(Integer, nullable=False, default=0, server_default="0")
    metrics = Column(JSON, nullable=False, default=dict, server_default="{}")
    summary = Column(Text, nullable=True)
    opened_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    mitigated_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)


class CommunicationSavedFilter(Base):
    __tablename__ = "communication_saved_filters"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_communication_saved_filter_name"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_communication_saved_filter_tenant_id_nonempty"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    owner_user_id = Column(String(128), nullable=True)
    name = Column(String(128), nullable=False)
    query = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")


class CommunicationTenantQuota(Base):
    __tablename__ = "communication_tenant_quotas"
    __table_args__ = (
        UniqueConstraint("tenant_id", "scope", name="uq_communication_tenant_quota_scope"),
        CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_communication_tenant_quota_tenant_id_nonempty"),
        {"extend_existing": True},
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    scope = Column(String(64), nullable=False)
    limit_value = Column(Integer, nullable=False)
    window = Column(String(32), nullable=False, default="daily", server_default="daily")
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default="now()")
