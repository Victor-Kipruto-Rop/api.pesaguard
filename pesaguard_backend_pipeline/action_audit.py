from __future__ import annotations

from copy import deepcopy
import base64
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from enum import StrEnum
from typing import Any, Callable, Iterable, Mapping, Optional

from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, DDL, ForeignKeyConstraint, Index, Integer, JSON, String, Text, UniqueConstraint, event, func, text
from sqlalchemy import inspect
from sqlalchemy.orm import declarative_base, validates
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

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


MAX_TENANT_ID_LENGTH = 128
MAX_ACTOR_LENGTH = 255
MAX_ACTION_LENGTH = 128
MAX_CATEGORY_LENGTH = 64
MAX_OUTCOME_LENGTH = 32
MAX_SEVERITY_LENGTH = 32
MAX_RESOURCE_TYPE_LENGTH = 128
MAX_RESOURCE_ID_LENGTH = 255
MAX_REQUEST_ID_LENGTH = 128
MAX_TRACE_ID_LENGTH = 128
MAX_CORRELATION_ID_LENGTH = 128
MAX_IDEMPOTENCY_KEY_LENGTH = 255
MAX_DETAIL_KEY_LENGTH = 128
MAX_HASH_LENGTH = 64
MAX_SIGNATURE_LENGTH = 256
MAX_SIGNATURE_KEY_ID_LENGTH = 128
MAX_DETAILS_BYTES = 64 * 1024
MAX_DETAILS_DEPTH = 8
MAX_DETAILS_KEYS = 200
MAX_LIST_ITEMS = 200
MAX_STRING_LENGTH = 4096
MAX_TOTAL_NODES = 2000
AUDIT_SCHEMA_VERSION = 1
AUDIT_HASH_VERSION = 1
AUDIT_ID_PREFIX = "audit_"
AUDIT_ID_LENGTH = len(AUDIT_ID_PREFIX) + 32
SENSITIVE_DETAIL_KEYS = {
    "api_key",
    "authorization",
    "client_secret",
    "cookie",
    "csrf_token",
    "database_url",
    "encryption_key",
    "mpesa_pin",
    "otp",
    "password",
    "pin",
    "private_key",
    "refresh_token",
    "secret",
    "secret_key",
    "token",
    "access_token",
    "bearer_token",
    "client_id",
    "credit_card",
    "card_number",
    "cvv",
    "cvv2",
    "database_password",
    "email_password",
    "jwt",
    "mpesa_password",
    "phone",
    "security_code",
    "session_token",
    "smtp_password",
    "webhook_secret",
}
SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"(?i)^bearer\s+\S+$"),
    re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
    re.compile(r"(?i)^[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"),
)

ACTION_DISCREPANCY_FLAGGED = "discrepancy.flagged"
ACTION_DISCREPANCY_RESOLVED = "discrepancy.resolved"
ACTION_SETTINGS_UPDATED = "settings.updated"
ACTION_EXPORT_CREATED = "export.created"
ACTION_AUDIT_LOG_ACCESSED = "audit.log.accessed"
ACTION_AUDIT_LOG_SEARCHED = "audit.log.searched"
ACTION_AUDIT_LOG_EXPORTED = "audit.log.exported"
ACTION_AUDIT_INTEGRITY_VERIFIED = "audit.integrity.verified"
ACTION_AUDIT_LOG_REPLAYED = "audit.log.replayed"
ACTION_AUDIT_RETENTION_CHANGED = "audit.retention.changed"
ACTION_AUDIT_LEGAL_HOLD_CREATED = "audit.legal_hold.created"
ACTION_AUDIT_LEGAL_HOLD_RELEASED = "audit.legal_hold.released"

AUDIT_CATEGORIES = frozenset({
    "access",
    "authentication",
    "compliance",
    "configuration",
    "data",
    "operations",
    "security",
    "system",
})
AUDIT_OUTCOMES = frozenset({"success", "failure", "denied", "partial"})
AUDIT_SEVERITIES = frozenset({"debug", "info", "notice", "warning", "critical"})
AUDIT_PRIVACY_MODES = frozenset({"strict", "standard", "internal", "regulated"})
CANONICAL_ACTIONS = frozenset({
    ACTION_DISCREPANCY_FLAGGED,
    ACTION_DISCREPANCY_RESOLVED,
    ACTION_EXPORT_CREATED,
    ACTION_SETTINGS_UPDATED,
    ACTION_AUDIT_LOG_ACCESSED,
    ACTION_AUDIT_LOG_SEARCHED,
    ACTION_AUDIT_LOG_EXPORTED,
    ACTION_AUDIT_INTEGRITY_VERIFIED,
    ACTION_AUDIT_LOG_REPLAYED,
    ACTION_AUDIT_RETENTION_CHANGED,
    ACTION_AUDIT_LEGAL_HOLD_CREATED,
    ACTION_AUDIT_LEGAL_HOLD_RELEASED,
    "authentication.login",
    "authentication.logout",
    "configuration.created",
    "configuration.updated",
    "data.exported",
    "reconciliation.matched",
    "retention.cleanup",
    "security.access_denied",
    "webhook.created",
    "webhook.updated",
})
LEGACY_ACTION_ALIASES = {
    "discrepancy_flagged": ACTION_DISCREPANCY_FLAGGED,
    "resolve_discrepancy": ACTION_DISCREPANCY_RESOLVED,
    "created": "configuration.created",
    "cleanup": "retention.cleanup",
    "matched": "reconciliation.matched",
    "create_webhook": "webhook.created",
    "update_webhook": "webhook.updated",
}
DEFAULT_DELIVERY_MAX_ATTEMPTS = 5
DEFAULT_DELIVERY_BACKOFF_SECONDS = 5
MAX_DELIVERY_BATCH_SIZE = 500
AUDIT_SIGNATURE_ALGORITHM = "Ed25519"


def generate_audit_id() -> str:
    return f"{AUDIT_ID_PREFIX}{uuid.uuid4().hex}"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_text(value: str, field_name: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    if len(normalized) > max_length:
        raise ValueError(f"{field_name} must be at most {max_length} characters")
    return normalized


def _validate_optional_text(value: Optional[str], field_name: str, max_length: int) -> Optional[str]:
    return None if value is None else _validate_text(value, field_name, max_length)


def canonicalize_action(value: str, *, strict: bool = False) -> str:
    action = _validate_text(value, "action", MAX_ACTION_LENGTH)
    canonical = LEGACY_ACTION_ALIASES.get(action, action)
    if strict and canonical not in CANONICAL_ACTIONS:
        raise ValueError(f"unknown canonical audit action: {canonical}")
    return canonical


def derive_audit_idempotency_key(
    tenant_id: str,
    action: str,
    *,
    request_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
) -> str:
    """Derive a stable key from the event identity, excluding mutable detail data."""
    canonical = "|".join([
        _validate_text(tenant_id, "tenant_id", MAX_TENANT_ID_LENGTH),
        canonicalize_action(action),
        request_id or "",
        correlation_id or "",
        resource_type or "",
        resource_id or "",
    ])
    return f"audit-key:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _validate_idempotency_key(value: str) -> str:
    return _validate_text(value, "idempotency_key", MAX_IDEMPOTENCY_KEY_LENGTH)


def _validate_hash(value: Optional[str], field_name: str) -> Optional[str]:
    if value is None:
        return None
    normalized = _validate_text(value, field_name, MAX_HASH_LENGTH)
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return normalized


def _validate_choice(value: str, field_name: str, choices: Iterable[str]) -> str:
    normalized = _validate_text(value, field_name, MAX_CATEGORY_LENGTH)
    if normalized not in choices:
        raise ValueError(f"{field_name} must be one of: {', '.join(sorted(choices))}")
    return normalized


def validate_audit_id(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("id must be a string")
    if not re.fullmatch(r"audit_[0-9a-f]{32}", value):
        raise ValueError("id must be a generated audit ID")
    return value


def _sanitize_details(
    value: Any,
    depth: int = 0,
    state: Optional[dict[str, int]] = None,
    active: Optional[set[int]] = None,
) -> Any:
    state = state or {"nodes": 0}
    active = active or set()
    state["nodes"] += 1
    if state["nodes"] > MAX_TOTAL_NODES:
        raise ValueError(f"details must contain at most {MAX_TOTAL_NODES} values")
    if depth > MAX_DETAILS_DEPTH:
        raise ValueError(f"details nesting must not exceed {MAX_DETAILS_DEPTH} levels")
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise ValueError(f"detail strings must be at most {MAX_STRING_LENGTH} characters")
        if any(pattern.search(value) for pattern in SENSITIVE_VALUE_PATTERNS):
            return "[REDACTED]"
        return value
    if isinstance(value, Mapping):
        if len(value) > MAX_DETAILS_KEYS:
            raise ValueError(f"each details object must contain at most {MAX_DETAILS_KEYS} keys")
        marker = id(value)
        if marker in active:
            raise ValueError("details must not contain cyclic references")
        active.add(marker)
        sanitized: dict[str, Any] = {}
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError("details keys must be strings")
                if len(key) > MAX_DETAIL_KEY_LENGTH:
                    raise ValueError(f"detail keys must be at most {MAX_DETAIL_KEY_LENGTH} characters")
                normalized_key = re.sub(r"[-\s]", "_", key).casefold()
                sanitized[key] = (
                    "[REDACTED]"
                    if normalized_key in SENSITIVE_DETAIL_KEYS
                    else _sanitize_details(item, depth + 1, state, active)
                )
        finally:
            active.remove(marker)
        return sanitized
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_LIST_ITEMS:
            raise ValueError(f"detail lists must contain at most {MAX_LIST_ITEMS} values")
        marker = id(value)
        if marker in active:
            raise ValueError("details must not contain cyclic references")
        active.add(marker)
        try:
            return [_sanitize_details(item, depth + 1, state, active) for item in value]
        finally:
            active.remove(marker)
    return value


def sanitize_details(details: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    if details is None:
        return {}
    if not isinstance(details, Mapping):
        raise ValueError("details must be a mapping")
    sanitized = _sanitize_details(details)
    try:
        serialized = json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("details must contain JSON-serializable values") from exc
    if len(serialized.encode("utf-8")) > MAX_DETAILS_BYTES:
        raise ValueError(f"details must be at most {MAX_DETAILS_BYTES} bytes")
    return sanitized


class ActionAuditEntry(Base):
    __tablename__ = "action_audit_entries"
    __table_args__ = (
        CheckConstraint("length(trim(tenant_id)) > 0", name="ck_audit_tenant_id_not_empty"),
        CheckConstraint("length(trim(actor)) > 0", name="ck_audit_actor_not_empty"),
        CheckConstraint("length(trim(action)) > 0", name="ck_audit_action_not_empty"),
        CheckConstraint("category IN ('access', 'authentication', 'compliance', 'configuration', 'data', 'operations', 'security', 'system')", name="ck_audit_category"),
        CheckConstraint("outcome IN ('success', 'failure', 'denied', 'partial')", name="ck_audit_outcome"),
        CheckConstraint("severity IN ('debug', 'info', 'notice', 'warning', 'critical')", name="ck_audit_severity"),
        CheckConstraint("signature IS NULL OR (event_hash IS NOT NULL AND signature_algorithm = 'Ed25519' AND signature_key_id IS NOT NULL)", name="ck_audit_signature_requirements"),
        CheckConstraint("tenant_sequence IS NULL OR tenant_sequence > 0", name="ck_audit_tenant_sequence_positive"),
        UniqueConstraint("tenant_id", "tenant_sequence", name="uq_audit_tenant_sequence"),
        UniqueConstraint("id", "tenant_id", name="uq_audit_id_tenant"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_audit_tenant_idempotency_key"),
        Index("ix_audit_tenant_created_at", "tenant_id", "created_at"),
        Index("ix_audit_tenant_action_created_at", "tenant_id", "action", "created_at"),
        Index("ix_audit_tenant_actor_created_at", "tenant_id", "actor", "created_at"),
        Index("ix_audit_tenant_category_created_at", "tenant_id", "category", "created_at"),
        Index("ix_audit_tenant_outcome_severity_created_at", "tenant_id", "outcome", "severity", "created_at"),
        Index("ix_audit_tenant_resource_created_at", "tenant_id", "resource_type", "resource_id", "created_at"),
        Index("ix_audit_tenant_trace_created_at", "tenant_id", "trace_id", "created_at"),
        Index("ix_audit_tenant_correlation_created_at", "tenant_id", "correlation_id", "created_at"),
        Index("ix_audit_tenant_event_hash", "tenant_id", "event_hash"),
    )

    id = Column(String(AUDIT_ID_LENGTH), primary_key=True, default=generate_audit_id)
    tenant_id = Column(String(MAX_TENANT_ID_LENGTH), nullable=False, index=True)
    actor = Column(String(MAX_ACTOR_LENGTH), nullable=False)
    action = Column(String(MAX_ACTION_LENGTH), nullable=False)
    category = Column(String(MAX_CATEGORY_LENGTH), nullable=False, default="operations", server_default="operations")
    outcome = Column(String(MAX_OUTCOME_LENGTH), nullable=False, default="success", server_default="success")
    severity = Column(String(MAX_SEVERITY_LENGTH), nullable=False, default="info", server_default="info")
    resource_type = Column(String(MAX_RESOURCE_TYPE_LENGTH), nullable=True)
    resource_id = Column(String(MAX_RESOURCE_ID_LENGTH), nullable=True)
    request_id = Column(String(MAX_REQUEST_ID_LENGTH), nullable=True)
    trace_id = Column(String(MAX_TRACE_ID_LENGTH), nullable=True)
    correlation_id = Column(String(MAX_CORRELATION_ID_LENGTH), nullable=True)
    idempotency_key = Column(String(MAX_IDEMPOTENCY_KEY_LENGTH), nullable=True)
    previous_hash = Column(String(MAX_HASH_LENGTH), nullable=True)
    event_hash = Column(String(MAX_HASH_LENGTH), nullable=True)
    signature = Column(String(MAX_SIGNATURE_LENGTH), nullable=True)
    signature_key_id = Column(String(MAX_SIGNATURE_KEY_ID_LENGTH), nullable=True)
    signature_algorithm = Column(String(32), nullable=True)
    schema_version = Column(Integer, nullable=False, default=AUDIT_SCHEMA_VERSION, server_default=str(AUDIT_SCHEMA_VERSION))
    hash_version = Column(Integer, nullable=False, default=AUDIT_HASH_VERSION, server_default=str(AUDIT_HASH_VERSION))
    tenant_sequence = Column(Integer, nullable=True)
    actor_id = Column(String(MAX_ACTOR_LENGTH), nullable=True)
    actor_type = Column(String(32), nullable=False, default="system", server_default="system")
    actor_display_name = Column(String(MAX_ACTOR_LENGTH), nullable=True)
    actor_authentication_method = Column(String(64), nullable=True)
    details = Column(JSON, default=dict, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False,
    )


    @validates("tenant_id")
    def validate_tenant_id(self, key: str, value: str) -> str:
        return _validate_text(value, key, MAX_TENANT_ID_LENGTH)

    @validates("actor")
    def validate_actor(self, key: str, value: str) -> str:
        return _validate_text(value, key, MAX_ACTOR_LENGTH)

    @validates("action")
    def validate_action(self, key: str, value: str) -> str:
        return _validate_text(value, key, MAX_ACTION_LENGTH)

    @validates("category")
    def validate_category(self, key: str, value: str) -> str:
        return _validate_choice(value, key, AUDIT_CATEGORIES)

    @validates("outcome")
    def validate_outcome(self, key: str, value: str) -> str:
        return _validate_choice(value, key, AUDIT_OUTCOMES)

    @validates("severity")
    def validate_severity(self, key: str, value: str) -> str:
        return _validate_choice(value, key, AUDIT_SEVERITIES)

    @validates("resource_type")
    def validate_resource_type(self, key: str, value: Optional[str]) -> Optional[str]:
        return _validate_optional_text(value, key, MAX_RESOURCE_TYPE_LENGTH)

    @validates("resource_id")
    def validate_resource_id(self, key: str, value: Optional[str]) -> Optional[str]:
        return _validate_optional_text(value, key, MAX_RESOURCE_ID_LENGTH)

    @validates("request_id")
    def validate_request_id(self, key: str, value: Optional[str]) -> Optional[str]:
        return _validate_optional_text(value, key, MAX_REQUEST_ID_LENGTH)

    @validates("trace_id")
    def validate_trace_id(self, key: str, value: Optional[str]) -> Optional[str]:
        return _validate_optional_text(value, key, MAX_TRACE_ID_LENGTH)

    @validates("correlation_id")
    def validate_correlation_id(self, key: str, value: Optional[str]) -> Optional[str]:
        return _validate_optional_text(value, key, MAX_CORRELATION_ID_LENGTH)

    @validates("idempotency_key")
    def validate_idempotency_key(self, key: str, value: Optional[str]) -> Optional[str]:
        return None if value is None else _validate_idempotency_key(value)

    @validates("previous_hash", "event_hash")
    def validate_hash(self, key: str, value: Optional[str]) -> Optional[str]:
        return _validate_hash(value, key)

    @validates("signature_key_id")
    def validate_signature_key_id(self, key: str, value: Optional[str]) -> Optional[str]:
        return _validate_optional_text(value, key, MAX_SIGNATURE_KEY_ID_LENGTH)

    @validates("actor_type")
    def validate_actor_type(self, key: str, value: str) -> str:
        return _validate_choice(value, key, {"user", "service", "system", "anonymous", "worker", "admin"})

    @validates("details")
    def copy_details(self, key: str, value: Optional[Mapping[str, Any]]) -> dict[str, Any]:
        return sanitize_details(value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "action": self.action,
            "category": self.category,
            "outcome": self.outcome,
            "severity": self.severity,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "correlation_id": self.correlation_id,
            "idempotency_key": self.idempotency_key,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
            "signature": self.signature,
            "signature_key_id": self.signature_key_id,
            "signature_algorithm": self.signature_algorithm,
            "schema_version": self.schema_version,
            "hash_version": self.hash_version,
            "tenant_sequence": self.tenant_sequence,
            "actor_id": self.actor_id,
            "actor_type": self.actor_type,
            "actor_display_name": self.actor_display_name,
            "actor_authentication_method": self.actor_authentication_method,
            "details": deepcopy(self.details or {}),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


event.listen(
    ActionAuditEntry.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER action_audit_entries_append_only_update
        BEFORE UPDATE ON action_audit_entries
        BEGIN
            SELECT RAISE(ABORT, 'audit entries are append-only');
        END
        """
    ).execute_if(dialect="sqlite"),
)
event.listen(
    ActionAuditEntry.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER action_audit_entries_append_only_delete
        BEFORE DELETE ON action_audit_entries
        BEGIN
            SELECT RAISE(ABORT, 'audit entries are append-only');
        END
        """
    ).execute_if(dialect="sqlite"),
)


def _reject_persisted_audit_change(target: ActionAuditEntry, value: Any, oldvalue: Any, initiator: Any) -> Any:
    state = inspect(target)
    if state.persistent or state.detached:
        raise ValueError("Audit entries are append-only and cannot be updated")
    return value


for _audit_attribute in (
    "id", "tenant_id", "actor", "action", "category", "outcome", "severity",
    "resource_type", "resource_id", "request_id", "trace_id", "correlation_id", "idempotency_key",
    "previous_hash", "event_hash", "signature", "signature_key_id", "signature_algorithm", "schema_version", "hash_version", "tenant_sequence", "actor_id", "actor_type", "actor_display_name", "actor_authentication_method",
    "details", "created_at",
):
    event.listen(
        getattr(ActionAuditEntry, _audit_attribute),
        "set",
        _reject_persisted_audit_change,
        retval=True,
    )


@event.listens_for(ActionAuditEntry, "before_update")
def _reject_audit_update(mapper: Any, connection: Any, target: ActionAuditEntry) -> None:
    raise ValueError("Audit entries are append-only and cannot be updated")


@event.listens_for(ActionAuditEntry, "before_delete")
def _reject_audit_delete(mapper: Any, connection: Any, target: ActionAuditEntry) -> None:
    raise ValueError("Audit entries are append-only and cannot be deleted")


@dataclass(frozen=True)
class ActionAuditRecord:
    tenant_id: str
    actor: str
    action: str
    details: Optional[Mapping[str, Any]] = None
    id: Optional[str] = field(default=None)
    category: str = "operations"
    outcome: str = "success"
    severity: str = "info"
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    correlation_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    actor_id: Optional[str] = None
    actor_type: str = "system"
    actor_display_name: Optional[str] = None
    actor_authentication_method: Optional[str] = None
    schema_version: int = AUDIT_SCHEMA_VERSION
    hash_version: int = AUDIT_HASH_VERSION


class AuditDeliveryStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DELIVERED = "delivered"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


class AuditOutboxEntry(Base):
    __tablename__ = "audit_outbox_entries"
    __table_args__ = (
        UniqueConstraint("audit_id", name="uq_audit_outbox_audit_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_audit_outbox_tenant_idempotency_key"),
        ForeignKeyConstraint(["audit_id", "tenant_id"], ["action_audit_entries.id", "action_audit_entries.tenant_id"], name="fk_audit_outbox_audit_tenant"),
        CheckConstraint("status IN ('pending', 'in_progress', 'delivered', 'failed', 'dead_letter')", name="ck_audit_outbox_status"),
        CheckConstraint("attempt_count >= 0 AND max_attempts > 0", name="ck_audit_outbox_attempt_counts"),
        CheckConstraint("tenant_id <> ''", name="ck_audit_outbox_tenant_not_empty"),
        Index("ix_audit_outbox_due", "status", "next_attempt_at"),
        Index("ix_audit_outbox_tenant_status_created_at", "tenant_id", "status", "created_at"),
        Index("ix_audit_outbox_tenant_delivered_at", "tenant_id", "delivered_at"),
    )

    id = Column(String(64), primary_key=True, default=lambda: f"outbox_{uuid.uuid4().hex}")
    audit_id = Column(String(AUDIT_ID_LENGTH), nullable=False)
    tenant_id = Column(String(MAX_TENANT_ID_LENGTH), nullable=False)
    idempotency_key = Column(String(MAX_IDEMPOTENCY_KEY_LENGTH), nullable=False)
    event_type = Column(String(128), nullable=False, default="audit.created")
    payload = Column(JSON, nullable=False)
    status = Column(String(32), nullable=False, default=AuditDeliveryStatus.PENDING.value)
    attempt_count = Column(Integer, nullable=False, default=0)
    max_attempts = Column(Integer, nullable=False, default=DEFAULT_DELIVERY_MAX_ATTEMPTS)
    next_attempt_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    locked_at = Column(DateTime(timezone=True), nullable=True)
    lease_owner = Column(String(MAX_ACTOR_LENGTH), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    backoff_strategy = Column(String(32), nullable=False, default="exponential_jitter", server_default="exponential_jitter")
    retry_after = Column(Integer, nullable=True)
    last_http_status = Column(Integer, nullable=True)
    last_provider_code = Column(String(64), nullable=True)
    replay_count = Column(Integer, nullable=False, default=0, server_default="0")
    replayed_by = Column(String(MAX_ACTOR_LENGTH), nullable=True)
    replayed_at = Column(DateTime(timezone=True), nullable=True)
    replay_reason = Column(String(4096), nullable=True)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now, server_default=func.now())


class AuditRetentionPolicy(Base):
    __tablename__ = "audit_retention_policies"
    __table_args__ = (UniqueConstraint("tenant_id", name="uq_audit_retention_policy_tenant"),)

    id = Column(String(64), primary_key=True, default=lambda: f"retention_{uuid.uuid4().hex}")
    tenant_id = Column(String(MAX_TENANT_ID_LENGTH), nullable=False)
    audit_retention_days = Column(Integer, nullable=False, default=365)
    archive_before_expiry = Column(Boolean, nullable=False, default=True)
    privacy_mode = Column(String(32), nullable=False, default="strict")
    updated_by = Column(String(MAX_ACTOR_LENGTH), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now, server_default=func.now())


class AuditLegalHold(Base):
    __tablename__ = "audit_legal_holds"
    __table_args__ = (
        Index("ix_audit_legal_hold_tenant_active", "tenant_id", "active"),
        Index("ix_audit_legal_hold_scope", "tenant_id", "scope_type", "scope_id", "active"),
    )

    id = Column(String(64), primary_key=True, default=lambda: f"hold_{uuid.uuid4().hex}")
    tenant_id = Column(String(MAX_TENANT_ID_LENGTH), nullable=False)
    scope_type = Column(String(32), nullable=False, default="tenant")
    scope_id = Column(String(MAX_RESOURCE_ID_LENGTH), nullable=True)
    hold_type = Column(String(32), nullable=False, default="regulatory", server_default="regulatory")
    reason = Column(String(4096), nullable=False)
    active = Column(Boolean, nullable=False, default=True)
    placed_by = Column(String(MAX_ACTOR_LENGTH), nullable=False)
    placed_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now())
    released_by = Column(String(MAX_ACTOR_LENGTH), nullable=True)
    released_at = Column(DateTime(timezone=True), nullable=True)
    release_reason = Column(String(4096), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now, server_default=func.now())


class AuditPrivacySettings(Base):
    __tablename__ = "audit_privacy_settings"
    __table_args__ = (UniqueConstraint("tenant_id", name="uq_audit_privacy_settings_tenant"),)

    id = Column(String(64), primary_key=True, default=lambda: f"privacy_{uuid.uuid4().hex}")
    tenant_id = Column(String(MAX_TENANT_ID_LENGTH), nullable=False)
    pseudonymize_actors = Column(Boolean, nullable=False, default=True)
    pseudonymize_resources = Column(Boolean, nullable=False, default=True)
    include_details = Column(Boolean, nullable=False, default=False)
    privacy_mode = Column(String(32), nullable=False, default="strict", server_default="strict")
    updated_by = Column(String(MAX_ACTOR_LENGTH), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now, server_default=func.now())


class AuditSigningKey(Base):
    __tablename__ = "audit_signing_keys"
    __table_args__ = (
        CheckConstraint("algorithm = 'Ed25519'", name="ck_audit_key_algorithm"),
        CheckConstraint("status IN ('active', 'verification_only', 'retired', 'revoked')", name="ck_audit_key_status"),
        Index("ix_audit_signing_key_status_expires", "status", "expires_at"),
    )

    key_id = Column(String(MAX_SIGNATURE_KEY_ID_LENGTH), primary_key=True)
    algorithm = Column(String(32), nullable=False, default=AUDIT_SIGNATURE_ALGORITHM, server_default=AUDIT_SIGNATURE_ALGORITHM)
    public_key = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="active", server_default="active")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    retired_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)


def _integrity_payload(entry: ActionAuditEntry) -> dict[str, Any]:
    source = entry.to_dict()
    payload = {
        field_name: source.get(field_name)
        for field_name in (
            "id", "tenant_id", "actor", "action", "category", "outcome", "severity",
            "resource_type", "resource_id", "request_id", "trace_id", "correlation_id",
            "idempotency_key", "details", "created_at", "previous_hash", "schema_version",
            "hash_version", "tenant_sequence", "actor_id", "actor_type", "actor_display_name",
            "actor_authentication_method",
        )
    }
    if created_at := payload.get("created_at"):
        parsed_created_at = datetime.fromisoformat(created_at)
        if parsed_created_at.tzinfo is None:
            parsed_created_at = parsed_created_at.replace(tzinfo=timezone.utc)
        payload["created_at"] = parsed_created_at.astimezone(timezone.utc).isoformat()
    for field_name in ("event_hash", "signature", "signature_key_id", "signature_algorithm"):
        payload.pop(field_name, None)
    return payload


def compute_audit_event_hash(entry: ActionAuditEntry) -> str:
    serialized = json.dumps(
        _integrity_payload(entry),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


class AuditSigner:
    """Ed25519 signer for audit event hashes; private material never leaves this object."""

    def __init__(self, private_key: Ed25519PrivateKey, key_id: str):
        self._private_key = private_key
        self.key_id = _validate_text(key_id, "signature_key_id", MAX_SIGNATURE_KEY_ID_LENGTH)

    @classmethod
    def from_environment(cls) -> "AuditSigner":
        configured = os.getenv("PESAGUARD_AUDIT_SIGNING_KEY")
        if not configured:
            raise RuntimeError("PESAGUARD_AUDIT_SIGNING_KEY is required for signed audit writes")
        try:
            if configured.startswith("-----BEGIN"):
                private_key = serialization.load_pem_private_key(configured.encode("utf-8"), password=None)
            else:
                private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(configured, validate=True))
        except (ValueError, TypeError) as exc:
            raise RuntimeError("PESAGUARD_AUDIT_SIGNING_KEY must be a PEM or base64 Ed25519 private key") from exc
        if not isinstance(private_key, Ed25519PrivateKey):
            raise RuntimeError("PESAGUARD_AUDIT_SIGNING_KEY is not an Ed25519 private key")
        return cls(private_key, os.getenv("PESAGUARD_AUDIT_SIGNING_KEY_ID", "audit-primary"))

    def sign_hash(self, event_hash: str) -> str:
        _validate_hash(event_hash, "event_hash")
        return base64.b64encode(self._private_key.sign(event_hash.encode("ascii"))).decode("ascii")

    def verify_hash(self, event_hash: str, signature: str) -> bool:
        try:
            self._private_key.public_key().verify(base64.b64decode(signature, validate=True), event_hash.encode("ascii"))
            return True
        except (ValueError, TypeError):
            return False


def verify_audit_signature(entry: ActionAuditEntry, public_key: Ed25519PublicKey) -> bool:
    if not entry.event_hash or not entry.signature or entry.signature_algorithm != AUDIT_SIGNATURE_ALGORITHM:
        return False
    try:
        public_key.verify(base64.b64decode(entry.signature, validate=True), entry.event_hash.encode("ascii"))
        return True
    except (ValueError, TypeError):
        return False


def verify_audit_signature_from_registry(session: Any, entry: ActionAuditEntry, now: Optional[datetime] = None) -> bool:
    """Resolve a historical public key by ID and enforce its rotation state."""
    if not entry.signature_key_id:
        return False
    key = session.get(AuditSigningKey, entry.signature_key_id)
    if key is None or key.status == "revoked":
        return False
    now = now or utc_now()
    if key.expires_at is not None and key.expires_at <= now:
        return False
    try:
        public_key = serialization.load_pem_public_key(key.public_key.encode("utf-8"))
    except (TypeError, ValueError):
        return False
    return isinstance(public_key, Ed25519PublicKey) and verify_audit_signature(entry, public_key)


@dataclass(frozen=True)
class AuditIntegrityReport:
    tenant_id: str
    checked: int
    valid: int
    unprotected: int
    first_invalid_id: Optional[str]
    first_invalid_reason: Optional[str]


class FileImmutableAuditStore:
    """Write-once local object-store adapter using exclusive creation and fsync."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put_immutable(self, object_name: str, content: bytes, content_hash: str, metadata: Mapping[str, str]) -> str:
        safe_name = Path(object_name).name
        if safe_name != object_name or not safe_name:
            raise ValueError("object_name must be a single safe path component")
        _validate_hash(content_hash, "content_hash")
        if hashlib.sha256(content).hexdigest() != content_hash:
            raise ValueError("content hash does not match content")
        destination = self.root / safe_name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(destination, flags, 0o440)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            with suppress(FileNotFoundError):
                destination.unlink()
            raise
        metadata_path = destination.with_suffix(f"{destination.suffix}.metadata.json")
        metadata_path.write_text(json.dumps(dict(metadata), sort_keys=True), encoding="utf-8")
        return str(destination)


def verify_audit_integrity(
    session: Any,
    principal: Any,
    tenant_id: str,
    *,
    public_key: Optional[Ed25519PublicKey] = None,
) -> AuditIntegrityReport:
    """Verify the tenant chain and signatures without exposing another tenant's rows."""
    tenant_id = _validate_text(tenant_id, "tenant_id", MAX_TENANT_ID_LENGTH)
    if not can_access_audit_tenant(principal, tenant_id):
        raise PermissionError("Principal is not authorized to verify this tenant audit trail")
    entries = session.query(ActionAuditEntry).filter(
        ActionAuditEntry.tenant_id == tenant_id,
    ).order_by(ActionAuditEntry.created_at.asc(), ActionAuditEntry.id.asc()).all()
    expected_previous = None
    valid = 0
    unprotected = 0
    first_invalid_id = None
    first_invalid_reason = None
    for entry in entries:
        if not entry.event_hash:
            unprotected += 1
            expected_previous = None
            continue
        reason = None
        if entry.previous_hash != expected_previous:
            reason = "hash_chain_link_mismatch"
        elif compute_audit_event_hash(entry) != entry.event_hash:
            reason = "event_hash_mismatch"
        elif entry.signature and (public_key is None or not verify_audit_signature(entry, public_key)):
            reason = "signature_verification_failed"
        if reason:
            if first_invalid_id is None:
                first_invalid_id = entry.id
                first_invalid_reason = reason
        else:
            valid += 1
        expected_previous = entry.event_hash
    return AuditIntegrityReport(
        tenant_id=tenant_id,
        checked=len(entries),
        valid=valid,
        unprotected=unprotected,
        first_invalid_id=first_invalid_id,
        first_invalid_reason=first_invalid_reason,
    )


def run_audit_integrity_job(
    session: Any,
    principal: Any,
    tenant_ids: Iterable[str],
    *,
    public_key: Optional[Ed25519PublicKey] = None,
) -> list[AuditIntegrityReport]:
    """Run verification for explicit tenant scopes and return auditable reports."""
    return [
        verify_audit_integrity(session, principal, tenant_id, public_key=public_key)
        for tenant_id in tenant_ids
    ]


def build_siem_event(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Map an audit event to a vendor-neutral ECS-style SIEM envelope."""
    event_id = _validate_text(str(entry.get("id", "")), "id", 128)
    tenant_id = _validate_text(str(entry.get("tenant_id", "")), "tenant_id", MAX_TENANT_ID_LENGTH)
    return {
        "@timestamp": entry.get("created_at"),
        "event": {
            "id": event_id,
            "action": entry.get("action"),
            "category": entry.get("category"),
            "outcome": entry.get("outcome"),
            "severity": entry.get("severity"),
            "dataset": "pesaguard.audit",
        },
        "trace": {"id": entry.get("trace_id")} if entry.get("trace_id") else {},
        "transaction": {"id": entry.get("correlation_id")} if entry.get("correlation_id") else {},
        "http": {"request": {"id": entry.get("request_id")}} if entry.get("request_id") else {},
        "observer": {"vendor": "PesaGuard", "product": "audit"},
        "user": {"id": entry.get("actor")},
        "service": {"name": "pesaguard", "tenant_id": tenant_id},
        "resource": {
            "type": entry.get("resource_type"),
            "id": entry.get("resource_id"),
        },
        "labels": {
            "idempotency_key": entry.get("idempotency_key"),
            "event_hash": entry.get("event_hash"),
            "signature_key_id": entry.get("signature_key_id"),
        },
        "audit": {"details": deepcopy(entry.get("details") or {})},
    }


def export_audit_to_immutable_storage(
    session: Any,
    principal: Any,
    tenant_id: str,
    store: FileImmutableAuditStore,
    object_name: str,
    *,
    public_key: Optional[Ed25519PublicKey] = None,
) -> dict[str, Any]:
    """Export only an intact tenant chain and commit it to write-once storage."""
    report = verify_audit_integrity(session, principal, tenant_id, public_key=public_key)
    if report.first_invalid_id:
        raise ValueError(f"audit integrity verification failed at {report.first_invalid_id}")
    entries = session.query(ActionAuditEntry).filter(
        ActionAuditEntry.tenant_id == report.tenant_id,
    ).order_by(ActionAuditEntry.created_at.asc(), ActionAuditEntry.id.asc()).all()
    content = "".join(
        json.dumps(entry.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for entry in entries
    ).encode("utf-8")
    content_hash = hashlib.sha256(content).hexdigest()
    location = store.put_immutable(
        object_name,
        content,
        content_hash,
        {
            "tenant_id": report.tenant_id,
            "record_count": str(len(entries)),
            "content_hash": content_hash,
            "integrity_checked": "true",
        },
    )
    return {
        "tenant_id": report.tenant_id,
        "object_name": object_name,
        "location": location,
        "record_count": len(entries),
        "content_hash": content_hash,
        "integrity": report,
    }


def can_access_audit_tenant(principal: Any, tenant_id: str) -> bool:
    """Return whether a trusted authenticated principal may read a tenant audit trail."""
    if principal is None:
        return False
    permissions = set(getattr(principal, "permissions", ()) or ())
    return (
        tenant_id == getattr(principal, "tenant_id", None)
        or "manage:all_tenants" in permissions
    )


def _can_manage_audit_policy(principal: Any, tenant_id: str) -> bool:
    permissions = set(getattr(principal, "permissions", ()) or ()) if principal else set()
    return can_access_audit_tenant(principal, tenant_id) and (
        "manage:settings" in permissions
        or "manage:all_tenants" in permissions
        or "admin" in set(getattr(principal, "roles", ()) or ())
    )


def _validated_days(days: int) -> int:
    if not isinstance(days, int) or not 1 <= days <= 3650:
        raise ValueError("audit_retention_days must be between 1 and 3650")
    return days


def set_audit_retention_policy(
    session: Any,
    principal: Any,
    tenant_id: str,
    audit_retention_days: int,
    *,
    archive_before_expiry: bool = True,
    privacy_mode: str = "strict",
) -> AuditRetentionPolicy:
    """Create or replace a tenant policy; policy changes require privileged tenant access."""
    tenant_id = _validate_text(tenant_id, "tenant_id", MAX_TENANT_ID_LENGTH)
    if not _can_manage_audit_policy(principal, tenant_id):
        raise PermissionError("Principal is not authorized to manage audit retention")
    days = _validated_days(audit_retention_days)
    privacy_mode = _validate_text(privacy_mode, "privacy_mode", 32)
    if privacy_mode not in AUDIT_PRIVACY_MODES:
        raise ValueError("unsupported privacy_mode")
    policy = session.query(AuditRetentionPolicy).filter_by(tenant_id=tenant_id).one_or_none()
    actor = _validate_text(str(getattr(principal, "user_id", "")), "updated_by", MAX_ACTOR_LENGTH)
    if policy is None:
        policy = AuditRetentionPolicy(tenant_id=tenant_id, updated_by=actor)
        session.add(policy)
    policy.audit_retention_days = days
    policy.archive_before_expiry = archive_before_expiry
    policy.privacy_mode = privacy_mode
    policy.updated_by = actor
    policy.updated_at = utc_now()
    session.flush()
    return policy


def place_audit_legal_hold(
    session: Any,
    principal: Any,
    tenant_id: str,
    reason: str,
    *,
    scope_type: str = "tenant",
    scope_id: Optional[str] = None,
    hold_type: str = "regulatory",
    expires_at: Optional[datetime] = None,
) -> AuditLegalHold:
    tenant_id = _validate_text(tenant_id, "tenant_id", MAX_TENANT_ID_LENGTH)
    if not _can_manage_audit_policy(principal, tenant_id):
        raise PermissionError("Principal is not authorized to place an audit legal hold")
    scope_type = _validate_text(scope_type, "scope_type", 32)
    if scope_type not in {"tenant", "audit", "resource", "request", "trace", "correlation"}:
        raise ValueError("unsupported legal hold scope_type")
    if scope_type != "tenant" and scope_id is None:
        raise ValueError("scope_id is required for a scoped legal hold")
    hold_type = _validate_text(hold_type, "hold_type", 32)
    if hold_type not in {"regulatory", "litigation", "investigation", "security"}:
        raise ValueError("unsupported hold_type")
    hold = AuditLegalHold(
        tenant_id=tenant_id,
        scope_type=scope_type,
        scope_id=_validate_optional_text(scope_id, "scope_id", MAX_RESOURCE_ID_LENGTH),
        hold_type=hold_type,
        reason=_validate_text(reason, "reason", 4096),
        placed_by=_validate_text(str(getattr(principal, "user_id", "")), "placed_by", MAX_ACTOR_LENGTH),
        expires_at=expires_at,
    )
    session.add(hold)
    session.flush()
    return hold


def release_audit_legal_hold(session: Any, principal: Any, hold_id: str, reason: str = "") -> AuditLegalHold:
    hold_id = _validate_text(hold_id, "hold_id", 64)
    hold = session.get(AuditLegalHold, hold_id)
    if hold is None:
        raise LookupError("audit legal hold not found")
    if not _can_manage_audit_policy(principal, hold.tenant_id):
        raise PermissionError("Principal is not authorized to release this audit legal hold")
    if hold.active:
        hold.active = False
        hold.released_by = _validate_text(str(getattr(principal, "user_id", "")), "released_by", MAX_ACTOR_LENGTH)
        hold.released_at = utc_now()
        hold.release_reason = _validate_text(reason, "release_reason", 4096) if reason else "administrative release"
        session.flush()
    return hold


def set_audit_privacy_settings(
    session: Any,
    principal: Any,
    tenant_id: str,
    *,
    pseudonymize_actors: bool = True,
    pseudonymize_resources: bool = True,
    include_details: bool = False,
    privacy_mode: str = "strict",
) -> AuditPrivacySettings:
    tenant_id = _validate_text(tenant_id, "tenant_id", MAX_TENANT_ID_LENGTH)
    if not _can_manage_audit_policy(principal, tenant_id):
        raise PermissionError("Principal is not authorized to manage audit privacy settings")
    actor = _validate_text(str(getattr(principal, "user_id", "")), "updated_by", MAX_ACTOR_LENGTH)
    privacy_mode = _validate_text(privacy_mode, "privacy_mode", 32)
    if privacy_mode not in AUDIT_PRIVACY_MODES:
        raise ValueError("unsupported privacy_mode")
    settings = session.query(AuditPrivacySettings).filter_by(tenant_id=tenant_id).one_or_none()
    if settings is None:
        settings = AuditPrivacySettings(tenant_id=tenant_id, updated_by=actor)
        session.add(settings)
    settings.pseudonymize_actors = pseudonymize_actors
    settings.pseudonymize_resources = pseudonymize_resources
    settings.include_details = include_details
    settings.privacy_mode = privacy_mode
    settings.updated_by = actor
    settings.updated_at = utc_now()
    session.flush()
    return settings


def privacy_safe_audit_dict(entry: ActionAuditEntry, settings: Optional[AuditPrivacySettings] = None) -> dict[str, Any]:
    """Return a privacy-safe view without mutating or weakening the source event."""
    output = entry.to_dict()
    tenant_id = output["tenant_id"]

    def pseudonym(value: Optional[str], label: str) -> Optional[str]:
        if value is None:
            return None
        digest = hashlib.sha256(f"{tenant_id}|{label}|{value}".encode("utf-8")).hexdigest()
        return f"{label}:{digest[:20]}"

    if settings is None or settings.pseudonymize_actors:
        output["actor"] = pseudonym(output.get("actor"), "actor")
    if settings is None or settings.pseudonymize_resources:
        output["resource_id"] = pseudonym(output.get("resource_id"), "resource")
    if settings is None or not settings.include_details:
        output["details"] = {}
    else:
        output["details"] = sanitize_details(output.get("details"))
    return output


def record_audit_log_access(
    session: Any,
    principal: Any,
    requested_tenant_id: str,
    *,
    filters: Optional[Mapping[str, Any]] = None,
    allowed: Optional[bool] = None,
) -> tuple[ActionAuditEntry, AuditOutboxEntry, bool]:
    """Record both successful and denied audit-log access using trusted identity."""
    requested_tenant_id = _validate_text(requested_tenant_id, "requested_tenant_id", MAX_TENANT_ID_LENGTH)
    actor_tenant = _validate_text(str(getattr(principal, "tenant_id", "")), "tenant_id", MAX_TENANT_ID_LENGTH)
    permitted = can_access_audit_tenant(principal, requested_tenant_id) if allowed is None else bool(allowed)
    target_tenant = requested_tenant_id if permitted else actor_tenant
    actor = _validate_text(str(getattr(principal, "user_id", "")), "actor", MAX_ACTOR_LENGTH)
    details = {
        "requested_tenant_id": requested_tenant_id,
        "filters": sanitize_details(filters or {}),
        "allowed": permitted,
    }
    return persist_audit_event(
        session,
        ActionAuditRecord(
            tenant_id=target_tenant,
            actor=actor,
            action=ACTION_AUDIT_LOG_ACCESSED,
            category="access",
            outcome="success" if permitted else "denied",
            severity="notice" if permitted else "warning",
            resource_type="audit_log",
            resource_id=requested_tenant_id,
            details=details,
            request_id=(filters or {}).get("request_id") if filters else None,
        ),
    )


def audit_entry_is_held(session: Any, entry: ActionAuditEntry) -> bool:
    """Return whether a tenant, event, or correlated resource is under an active hold."""
    holds = session.query(AuditLegalHold).filter(
        AuditLegalHold.tenant_id == entry.tenant_id,
        AuditLegalHold.active.is_(True),
    ).all()
    now = utc_now()
    for hold in holds:
        if hold.expires_at is not None and hold.expires_at <= now:
            continue
        if hold.scope_type == "tenant":
            return True
        if hold.scope_type == "audit" and hold.scope_id == entry.id:
            return True
        if hold.scope_type == "resource" and hold.scope_id == entry.resource_id:
            return True
        if hold.scope_type == "request" and hold.scope_id == entry.request_id:
            return True
        if hold.scope_type == "trace" and hold.scope_id == entry.trace_id:
            return True
        if hold.scope_type == "correlation" and hold.scope_id == entry.correlation_id:
            return True
    return False


def list_audit_retention_candidates(
    session: Any,
    principal: Any,
    tenant_id: str,
    *,
    now: Optional[datetime] = None,
    limit: int = 500,
) -> list[ActionAuditEntry]:
    """List expired rows eligible for archival while honoring every active legal hold."""
    tenant_id = _validate_text(tenant_id, "tenant_id", MAX_TENANT_ID_LENGTH)
    if not can_access_audit_tenant(principal, tenant_id):
        raise PermissionError("Principal is not authorized to inspect audit retention")
    if not isinstance(limit, int) or not 1 <= limit <= 5000:
        raise ValueError("limit must be between 1 and 5000")
    policy = session.query(AuditRetentionPolicy).filter_by(tenant_id=tenant_id).one_or_none()
    retention_days = policy.audit_retention_days if policy else 365
    cutoff = (now or utc_now()) - timedelta(days=retention_days)
    candidates = session.query(ActionAuditEntry).filter(
        ActionAuditEntry.tenant_id == tenant_id,
        ActionAuditEntry.created_at < cutoff,
    ).order_by(ActionAuditEntry.created_at.asc(), ActionAuditEntry.id.asc()).limit(limit).all()
    return [entry for entry in candidates if not audit_entry_is_held(session, entry)]


@dataclass(frozen=True)
class AuditOperationsDashboard:
    tenant_id: str
    delivery: AuditDeliveryMetrics
    integrity: AuditIntegrityReport
    active_legal_holds: int
    retention_days: int
    eligible_for_archive: int
    alerts: tuple[dict[str, Any], ...]


def get_audit_operations_dashboard(
    session: Any,
    principal: Any,
    tenant_id: str,
    *,
    public_key: Optional[Ed25519PublicKey] = None,
    pending_alert_threshold: int = 100,
) -> AuditOperationsDashboard:
    tenant_id = _validate_text(tenant_id, "tenant_id", MAX_TENANT_ID_LENGTH)
    if not can_access_audit_tenant(principal, tenant_id):
        raise PermissionError("Principal is not authorized to view audit operations")
    delivery = get_audit_delivery_metrics(session, principal, tenant_id)
    integrity = verify_audit_integrity(session, principal, tenant_id, public_key=public_key)
    policy = session.query(AuditRetentionPolicy).filter_by(tenant_id=tenant_id).one_or_none()
    retention_days = policy.audit_retention_days if policy else 365
    active_holds = session.query(func.count(AuditLegalHold.id)).filter(
        AuditLegalHold.tenant_id == tenant_id,
        AuditLegalHold.active.is_(True),
    ).scalar() or 0
    eligible = len(list_audit_retention_candidates(session, principal, tenant_id, limit=5000, now=utc_now()))
    alerts = tuple(evaluate_audit_alerts(delivery, integrity, active_holds, pending_alert_threshold))
    return AuditOperationsDashboard(tenant_id, delivery, integrity, active_holds, retention_days, eligible, alerts)


def evaluate_audit_alerts(
    delivery: AuditDeliveryMetrics,
    integrity: AuditIntegrityReport,
    active_legal_holds: int,
    pending_threshold: int = 100,
) -> list[dict[str, Any]]:
    alerts = []
    if delivery.pending >= pending_threshold:
        alerts.append({"code": "audit_delivery_backlog", "severity": "warning", "count": delivery.pending})
    if delivery.failed or delivery.dead_letter:
        alerts.append({"code": "audit_delivery_failure", "severity": "critical", "failed": delivery.failed, "dead_letter": delivery.dead_letter})
    if integrity.first_invalid_id:
        alerts.append({"code": "audit_integrity_failure", "severity": "critical", "entry_id": integrity.first_invalid_id, "reason": integrity.first_invalid_reason})
    if integrity.unprotected:
        alerts.append({"code": "audit_unprotected_legacy_rows", "severity": "notice", "count": integrity.unprotected})
    return alerts


def query_audit_entries(
    session: Any,
    principal: Any,
    tenant_id: str,
    *,
    action: Optional[str] = None,
    category: Optional[str] = None,
    outcome: Optional[str] = None,
    severity: Optional[str] = None,
    actor: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    created_after: Optional[datetime] = None,
    created_before: Optional[datetime] = None,
    limit: int = 200,
    offset: int = 0,
) -> list[ActionAuditEntry]:
    """Query audit entries after enforcing principal and tenant scope."""
    tenant_id = _validate_text(tenant_id, "tenant_id", MAX_TENANT_ID_LENGTH)
    if not can_access_audit_tenant(principal, tenant_id):
        raise PermissionError("Principal is not authorized to access this tenant audit trail")
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    if not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be non-negative")

    query = session.query(ActionAuditEntry).filter(ActionAuditEntry.tenant_id == tenant_id)
    if action is not None:
        canonical_action = canonicalize_action(action)
        action_values = [canonical_action]
        action_values.extend(
            legacy_action
            for legacy_action, mapped_action in LEGACY_ACTION_ALIASES.items()
            if mapped_action == canonical_action
        )
        query = query.filter(ActionAuditEntry.action.in_(action_values))
    filters = {
        ActionAuditEntry.category: _validate_choice(category, "category", AUDIT_CATEGORIES) if category is not None else None,
        ActionAuditEntry.outcome: _validate_choice(outcome, "outcome", AUDIT_OUTCOMES) if outcome is not None else None,
        ActionAuditEntry.severity: _validate_choice(severity, "severity", AUDIT_SEVERITIES) if severity is not None else None,
        ActionAuditEntry.actor: _validate_optional_text(actor, "actor", MAX_ACTOR_LENGTH),
        ActionAuditEntry.resource_type: _validate_optional_text(resource_type, "resource_type", MAX_RESOURCE_TYPE_LENGTH),
        ActionAuditEntry.resource_id: _validate_optional_text(resource_id, "resource_id", MAX_RESOURCE_ID_LENGTH),
        ActionAuditEntry.request_id: _validate_optional_text(request_id, "request_id", MAX_REQUEST_ID_LENGTH),
        ActionAuditEntry.trace_id: _validate_optional_text(trace_id, "trace_id", MAX_TRACE_ID_LENGTH),
        ActionAuditEntry.correlation_id: _validate_optional_text(correlation_id, "correlation_id", MAX_CORRELATION_ID_LENGTH),
    }
    for column, value in filters.items():
        if value is not None:
            query = query.filter(column == value)
    if created_after is not None:
        query = query.filter(ActionAuditEntry.created_at >= created_after)
    if created_before is not None:
        query = query.filter(ActionAuditEntry.created_at <= created_before)
    return query.order_by(ActionAuditEntry.created_at.desc(), ActionAuditEntry.id.desc()).offset(offset).limit(limit).all()


@dataclass(frozen=True)
class AuditDeliveryMetrics:
    tenant_id: str
    pending: int
    in_progress: int
    delivered: int
    failed: int
    dead_letter: int
    oldest_pending_at: Optional[datetime]
    last_delivered_at: Optional[datetime]


def persist_audit_event(
    session: Any,
    record: ActionAuditRecord,
    *,
    event_type: str = "audit.created",
    max_attempts: int = DEFAULT_DELIVERY_MAX_ATTEMPTS,
    signer: Optional[AuditSigner] = None,
) -> tuple[ActionAuditEntry, AuditOutboxEntry, bool]:
    """Atomically stage an audit row and its outbox message in the caller transaction.

    Returns ``(audit, outbox, created)``. A repeated idempotency key returns the
    original pair and ``created=False`` without creating a duplicate event.
    """
    if not isinstance(max_attempts, int) or not 1 <= max_attempts <= 100:
        raise ValueError("max_attempts must be between 1 and 100")
    if record.schema_version != AUDIT_SCHEMA_VERSION or record.hash_version != AUDIT_HASH_VERSION:
        raise ValueError("unsupported audit schema or hash version")
    event_type = _validate_text(event_type, "event_type", 128)
    values = build_audit_entry(record)
    values["created_at"] = utc_now()
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:tenant_id, 1))"), {"tenant_id": values["tenant_id"]})
    idempotency_key = values["idempotency_key"]
    existing = session.query(ActionAuditEntry).filter(
        ActionAuditEntry.tenant_id == values["tenant_id"],
        ActionAuditEntry.idempotency_key == idempotency_key,
    ).one_or_none()
    if existing is not None:
        outbox = session.query(AuditOutboxEntry).filter(AuditOutboxEntry.audit_id == existing.id).one_or_none()
        if outbox is None:
            outbox = AuditOutboxEntry(
                audit_id=existing.id,
                tenant_id=existing.tenant_id,
                idempotency_key=idempotency_key,
                event_type=event_type,
                payload=existing.to_dict(),
                max_attempts=max_attempts,
            )
            session.add(outbox)
            session.flush()
        return existing, outbox, False

    previous = session.query(ActionAuditEntry).filter(
        ActionAuditEntry.tenant_id == values["tenant_id"],
    ).order_by(ActionAuditEntry.created_at.desc(), ActionAuditEntry.id.desc()).first()
    tenant_sequence = session.query(func.max(ActionAuditEntry.tenant_sequence)).filter(
        ActionAuditEntry.tenant_id == values["tenant_id"],
    ).scalar() or 0
    audit = ActionAuditEntry(
        **values,
        previous_hash=previous.event_hash if previous and previous.event_hash else None,
        signature_key_id=signer.key_id if signer else None,
        signature_algorithm=AUDIT_SIGNATURE_ALGORITHM if signer else None,
        tenant_sequence=tenant_sequence + 1,
    )
    audit.event_hash = compute_audit_event_hash(audit)
    if signer:
        audit.signature = signer.sign_hash(audit.event_hash)
    session.add(audit)
    session.flush()
    outbox = AuditOutboxEntry(
        audit_id=audit.id,
        tenant_id=audit.tenant_id,
        idempotency_key=idempotency_key,
        event_type=event_type,
        payload=audit.to_dict(),
        max_attempts=max_attempts,
    )
    session.add(outbox)
    session.flush()
    return audit, outbox, True


def _retry_delay_seconds(attempt_count: int, base_seconds: int = DEFAULT_DELIVERY_BACKOFF_SECONDS) -> int:
    return min(base_seconds * (2 ** max(attempt_count - 1, 0)), 3600)


def claim_audit_deliveries(
    session: Any,
    *,
    now: Optional[datetime] = None,
    batch_size: int = 100,
    tenant_id: Optional[str] = None,
    worker_id: str = "audit-worker",
    lease_seconds: int = 300,
) -> list[AuditOutboxEntry]:
    """Claim due messages atomically; PostgreSQL workers skip rows claimed by peers."""
    if not isinstance(batch_size, int) or not 1 <= batch_size <= MAX_DELIVERY_BATCH_SIZE:
        raise ValueError(f"batch_size must be between 1 and {MAX_DELIVERY_BATCH_SIZE}")
    worker_id = _validate_text(worker_id, "worker_id", MAX_ACTOR_LENGTH)
    if not isinstance(lease_seconds, int) or lease_seconds <= 0:
        raise ValueError("lease_seconds must be positive")
    now = now or utc_now()
    query = session.query(AuditOutboxEntry).filter(
        AuditOutboxEntry.status.in_((AuditDeliveryStatus.PENDING.value, AuditDeliveryStatus.FAILED.value)),
        AuditOutboxEntry.next_attempt_at <= now,
        AuditOutboxEntry.attempt_count < AuditOutboxEntry.max_attempts,
    )
    if tenant_id is not None:
        query = query.filter(AuditOutboxEntry.tenant_id == _validate_text(tenant_id, "tenant_id", MAX_TENANT_ID_LENGTH))
    query = query.order_by(AuditOutboxEntry.next_attempt_at.asc(), AuditOutboxEntry.created_at.asc()).limit(batch_size)
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        query = query.with_for_update(skip_locked=True)
    entries = query.all()
    for entry in entries:
        entry.status = AuditDeliveryStatus.IN_PROGRESS.value
        entry.locked_at = now
        entry.lease_owner = worker_id
        entry.lease_expires_at = now + timedelta(seconds=lease_seconds)
        entry.last_attempt_at = now
        entry.attempt_count += 1
        entry.updated_at = now
    session.flush()
    return entries


def deliver_audit_outbox(
    session: Any,
    dispatcher: Callable[[dict[str, Any]], Any],
    *,
    now: Optional[datetime] = None,
    batch_size: int = 100,
    tenant_id: Optional[str] = None,
    worker_id: str = "audit-worker",
) -> dict[str, int]:
    """Deliver a claimed batch and persist success, retry, or dead-letter state."""
    now = now or utc_now()
    entries = claim_audit_deliveries(session, now=now, batch_size=batch_size, tenant_id=tenant_id, worker_id=worker_id)
    session.commit()
    result = {"claimed": len(entries), "delivered": 0, "retried": 0, "dead_lettered": 0}
    for entry in entries:
        try:
            dispatcher(deepcopy(entry.payload))
        except Exception as exc:
            session.rollback()
            current = session.get(AuditOutboxEntry, entry.id)
            if current is None:
                continue
            current.last_error = str(exc)[:4000]
            current.locked_at = None
            current.lease_owner = None
            current.lease_expires_at = None
            if current.attempt_count >= current.max_attempts:
                current.status = AuditDeliveryStatus.DEAD_LETTER.value
                result["dead_lettered"] += 1
            else:
                current.status = AuditDeliveryStatus.FAILED.value
                current.next_attempt_at = now + timedelta(seconds=_retry_delay_seconds(current.attempt_count))
                result["retried"] += 1
            current.updated_at = now
            session.commit()
            continue

        session.rollback()
        current = session.get(AuditOutboxEntry, entry.id)
        if current is None:
            continue
        current.status = AuditDeliveryStatus.DELIVERED.value
        current.delivered_at = now
        current.locked_at = None
        current.lease_owner = None
        current.lease_expires_at = None
        current.last_error = None
        current.updated_at = now
        session.commit()
        result["delivered"] += 1
    return result


def deliver_audit_to_siem(
    session: Any,
    principal: Any,
    tenant_id: str,
    dispatcher: Callable[[dict[str, Any]], Any],
    *,
    now: Optional[datetime] = None,
    batch_size: int = 100,
) -> dict[str, int]:
    """Send one tenant's audit events to a SIEM with outbox retry guarantees."""
    tenant_id = _validate_text(tenant_id, "tenant_id", MAX_TENANT_ID_LENGTH)
    if not can_access_audit_tenant(principal, tenant_id):
        raise PermissionError("Principal is not authorized to deliver this tenant audit trail")
    return deliver_audit_outbox(
        session,
        lambda payload: dispatcher(build_siem_event(payload)),
        now=now,
        batch_size=batch_size,
        tenant_id=tenant_id,
    )


def recover_stale_audit_deliveries(
    session: Any,
    *,
    now: Optional[datetime] = None,
    lock_timeout: timedelta = timedelta(minutes=10),
) -> int:
    """Return abandoned worker claims to retry or dead-letter state."""
    if lock_timeout <= timedelta(0):
        raise ValueError("lock_timeout must be positive")
    now = now or utc_now()
    stale_before = now - lock_timeout
    entries = session.query(AuditOutboxEntry).filter(
        AuditOutboxEntry.status == AuditDeliveryStatus.IN_PROGRESS.value,
        AuditOutboxEntry.locked_at <= stale_before,
    ).all()
    for entry in entries:
        entry.locked_at = None
        entry.lease_owner = None
        entry.lease_expires_at = None
        entry.last_error = "delivery claim expired and was recovered"
        entry.status = (
            AuditDeliveryStatus.DEAD_LETTER.value
            if entry.attempt_count >= entry.max_attempts
            else AuditDeliveryStatus.FAILED.value
        )
        entry.next_attempt_at = now
        entry.updated_at = now
    session.commit()
    return len(entries)


def replay_dead_letter_audit(
    session: Any,
    principal: Any,
    outbox_id: str,
    reason: str,
) -> AuditOutboxEntry:
    """Explicitly requeue one dead-lettered event and record replay attribution."""
    entry = session.get(AuditOutboxEntry, _validate_text(outbox_id, "outbox_id", 64))
    if entry is None:
        raise LookupError("audit outbox entry not found")
    if not can_access_audit_tenant(principal, entry.tenant_id):
        raise PermissionError("Principal is not authorized to replay this audit event")
    if entry.status != AuditDeliveryStatus.DEAD_LETTER.value:
        raise ValueError("only dead-lettered audit events can be replayed")
    if entry.replay_count >= 3:
        raise ValueError("audit event replay limit reached")
    entry.status = AuditDeliveryStatus.PENDING.value
    entry.next_attempt_at = utc_now()
    entry.replay_count += 1
    entry.replayed_by = _validate_text(str(getattr(principal, "user_id", "")), "replayed_by", MAX_ACTOR_LENGTH)
    entry.replayed_at = utc_now()
    entry.replay_reason = _validate_text(reason, "replay_reason", 4096)
    entry.last_error = None
    session.flush()
    return entry


def get_audit_delivery_metrics(session: Any, principal: Any, tenant_id: str) -> AuditDeliveryMetrics:
    """Return persisted delivery health only after enforcing tenant authorization."""
    tenant_id = _validate_text(tenant_id, "tenant_id", MAX_TENANT_ID_LENGTH)
    if not can_access_audit_tenant(principal, tenant_id):
        raise PermissionError("Principal is not authorized to access this tenant audit delivery")
    rows = session.query(
        AuditOutboxEntry.status,
        func.count(AuditOutboxEntry.id),
    ).filter(AuditOutboxEntry.tenant_id == tenant_id).group_by(AuditOutboxEntry.status).all()
    counts = dict(rows)
    oldest_pending = session.query(func.min(AuditOutboxEntry.next_attempt_at)).filter(
        AuditOutboxEntry.tenant_id == tenant_id,
        AuditOutboxEntry.status.in_((AuditDeliveryStatus.PENDING.value, AuditDeliveryStatus.FAILED.value)),
    ).scalar()
    last_delivered = session.query(func.max(AuditOutboxEntry.delivered_at)).filter(
        AuditOutboxEntry.tenant_id == tenant_id,
        AuditOutboxEntry.status == AuditDeliveryStatus.DELIVERED.value,
    ).scalar()
    return AuditDeliveryMetrics(
        tenant_id=tenant_id,
        pending=counts.get(AuditDeliveryStatus.PENDING.value, 0),
        in_progress=counts.get(AuditDeliveryStatus.IN_PROGRESS.value, 0),
        delivered=counts.get(AuditDeliveryStatus.DELIVERED.value, 0),
        failed=counts.get(AuditDeliveryStatus.FAILED.value, 0),
        dead_letter=counts.get(AuditDeliveryStatus.DEAD_LETTER.value, 0),
        oldest_pending_at=oldest_pending,
        last_delivered_at=last_delivered,
    )


def build_audit_entry(record: ActionAuditRecord) -> dict[str, Any]:
    """
    Transforms an ActionAuditRecord into a dictionary ready for persistence
    or streaming, ensuring a unique ID and normalized timestamps.
    """
    tenant_id = _validate_text(record.tenant_id, "tenant_id", MAX_TENANT_ID_LENGTH)
    actor = _validate_text(record.actor, "actor", MAX_ACTOR_LENGTH)
    action = canonicalize_action(record.action)
    audit_id = validate_audit_id(record.id) if record.id is not None else generate_audit_id()
    details = sanitize_details(record.details)
    idempotency_key = (
        _validate_idempotency_key(record.idempotency_key)
        if record.idempotency_key is not None
        else derive_audit_idempotency_key(
            tenant_id,
            action,
            request_id=record.request_id,
            correlation_id=record.correlation_id,
            resource_type=record.resource_type,
            resource_id=record.resource_id,
        )
    )
    
    return {
        "id": audit_id,
        "tenant_id": tenant_id,
        "actor": actor,
        "action": action,
        "category": _validate_choice(record.category, "category", AUDIT_CATEGORIES),
        "outcome": _validate_choice(record.outcome, "outcome", AUDIT_OUTCOMES),
        "severity": _validate_choice(record.severity, "severity", AUDIT_SEVERITIES),
        "resource_type": _validate_optional_text(record.resource_type, "resource_type", MAX_RESOURCE_TYPE_LENGTH),
        "resource_id": _validate_optional_text(record.resource_id, "resource_id", MAX_RESOURCE_ID_LENGTH),
        "request_id": _validate_optional_text(record.request_id, "request_id", MAX_REQUEST_ID_LENGTH),
        "trace_id": _validate_optional_text(record.trace_id, "trace_id", MAX_TRACE_ID_LENGTH),
        "correlation_id": _validate_optional_text(record.correlation_id, "correlation_id", MAX_CORRELATION_ID_LENGTH),
        "idempotency_key": idempotency_key,
        "actor_id": _validate_optional_text(record.actor_id, "actor_id", MAX_ACTOR_LENGTH),
        "actor_type": _validate_choice(record.actor_type, "actor_type", {"user", "service", "system", "anonymous", "worker", "admin"}),
        "actor_display_name": _validate_optional_text(record.actor_display_name, "actor_display_name", MAX_ACTOR_LENGTH),
        "actor_authentication_method": _validate_optional_text(record.actor_authentication_method, "actor_authentication_method", 64),
        "schema_version": record.schema_version,
        "hash_version": record.hash_version,
        "details": details,
        "created_at": utc_now().isoformat(),
    }
