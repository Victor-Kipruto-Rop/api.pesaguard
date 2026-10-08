"""Core data engineering pipeline for tenant-scoped financial events.

The module deliberately keeps the pipeline independent from Flask and Kafka so
API routes, batch jobs, and event consumers share exactly the same controls:
validation, normalization, idempotency, lineage, and retention policy.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

try:
    from .data_lineage import DataLineage, build_lineage
except ImportError:
    from data_lineage import DataLineage, build_lineage


class SourceConnector(Protocol):
    """Connector contract for pull-based source systems."""

    name: str

    def read(self, *, tenant_id: str, cursor: Optional[str] = None, limit: int = 500) -> Iterable[Mapping[str, Any]]:
        ...


@dataclass(frozen=True)
class RetentionPolicy:
    raw_days: int = 90
    canonical_days: int = 365
    lineage_days: int = 730
    archive_before_delete: bool = True

    def __post_init__(self) -> None:
        if min(self.raw_days, self.canonical_days, self.lineage_days) < 1:
            raise ValueError("retention periods must be positive")


@dataclass(frozen=True)
class CanonicalRecord:
    tenant_id: str
    event_id: str
    transaction_id: str
    source: str
    provider: str
    amount: Decimal
    currency: str
    phone_number: str
    occurred_at: datetime
    status: str
    reference: str
    attributes: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = "1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "event_id": self.event_id,
            "transaction_id": self.transaction_id,
            "source": self.source,
            "provider": self.provider,
            "amount": str(self.amount),
            "currency": self.currency,
            "phone_number": self.phone_number,
            "occurred_at": self.occurred_at.isoformat(),
            "status": self.status,
            "reference": self.reference,
            "attributes": dict(self.attributes),
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class CatalogEntry:
    name: str
    description: str
    data_type: str
    classification: str = "internal"
    nullable: bool = False


class DataRepository(Protocol):
    """Persistence boundary; production implementations must be transactional."""

    def put(self, record: CanonicalRecord, raw: Mapping[str, Any], lineage: DataLineage) -> bool:
        """Persist and return False for an idempotent duplicate."""
        ...

    def records(self, tenant_id: str) -> Iterable[CanonicalRecord]:
        ...

    def archive(self, record: CanonicalRecord) -> None:
        ...

    def delete(self, record: CanonicalRecord) -> None:
        ...


class InMemoryDataRepository:
    """Deterministic repository for local development and unit tests."""

    def __init__(self) -> None:
        self.raw: Dict[Tuple[str, str], Mapping[str, Any]] = {}
        self.items: Dict[Tuple[str, str], CanonicalRecord] = {}
        self.lineage: Dict[Tuple[str, str], DataLineage] = {}
        self.archived: List[CanonicalRecord] = []

    def put(self, record: CanonicalRecord, raw: Mapping[str, Any], lineage: DataLineage) -> bool:
        key = (record.tenant_id, record.event_id)
        if key in self.items:
            return False
        self.raw[key] = dict(raw)
        self.items[key] = record
        self.lineage[key] = lineage
        return True

    def records(self, tenant_id: str) -> Iterable[CanonicalRecord]:
        return (record for (tenant, _), record in self.items.items() if tenant == tenant_id)

    def archive(self, record: CanonicalRecord) -> None:
        key = (record.tenant_id, record.event_id)
        if key in self.items:
            self.archived.append(record)

    def delete(self, record: CanonicalRecord) -> None:
        key = (record.tenant_id, record.event_id)
        self.items.pop(key, None)
        self.raw.pop(key, None)
        self.lineage.pop(key, None)


DEFAULT_CATALOG: Tuple[CatalogEntry, ...] = (
    CatalogEntry("tenant_id", "Owning tenant", "string", "restricted"),
    CatalogEntry("event_id", "Stable source event identity", "string", "internal"),
    CatalogEntry("transaction_id", "Canonical transaction identity", "string", "internal"),
    CatalogEntry("amount", "Monetary value", "decimal", "financial"),
    CatalogEntry("currency", "ISO 4217 currency", "string", "financial"),
    CatalogEntry("phone_number", "Tokenized payer identifier", "string", "personal"),
    CatalogEntry("occurred_at", "Source event time in UTC", "datetime", "internal"),
    CatalogEntry("status", "Canonical lifecycle status", "string", "internal"),
    CatalogEntry("reference", "Provider or merchant reference", "string", "internal"),
)


def _text(payload: Mapping[str, Any], *keys: str, required: bool = True) -> str:
    for key in keys:
        value = payload.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    if required:
        raise ValueError(f"missing required field: {keys[0]}")
    return ""


def _amount(value: Any) -> Decimal:
    try:
        result = Decimal(str(value)).quantize(Decimal("0.01"))
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError("amount must be a valid decimal")
    if result <= 0:
        raise ValueError("amount must be greater than zero")
    return result


def _timestamp(value: Any) -> datetime:
    raw = str(value).strip()
    if len(raw) == 14 and raw.isdigit():
        return datetime.strptime(raw, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _stable_id(tenant_id: str, source: str, payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(f"{tenant_id}:{source}:{encoded}".encode()).hexdigest()
    return f"evt_{digest}"


def normalize_record(tenant_id: str, source: str, payload: Mapping[str, Any]) -> CanonicalRecord:
    """Normalize API, webhook, batch, and event payload aliases to one schema."""
    tenant = str(tenant_id).strip()
    if not tenant:
        raise ValueError("tenant_id is required")
    event_id = _text(payload, "event_id", "id", "TransID", "TransactionID", required=False) or _stable_id(tenant, source, payload)
    reference = _text(payload, "reference", "merchant_ref", "TransID", "TransactionID", required=False) or event_id
    provider = _text(payload, "provider", "Provider", required=False).lower() or source.lower()
    timestamp = _timestamp(_text(payload, "occurred_at", "timestamp", "TransTime", "created_at"))
    phone = _text(payload, "phone_number", "MSISDN", "PhoneNumber", "msisdn", required=False)
    return CanonicalRecord(
        tenant_id=tenant,
        event_id=event_id,
        transaction_id=_text(payload, "transaction_id", "transaction_reference", "TransID", required=False) or event_id,
        source=source,
        provider=provider,
        amount=_amount(payload.get("amount", payload.get("TransAmount"))),
        currency=_text(payload, "currency", "Currency", required=False).upper() or "KES",
        phone_number=phone,
        occurred_at=timestamp,
        status=_text(payload, "status", "Status", required=False).upper() or "RECEIVED",
        reference=reference,
        attributes=dict(payload),
    )


class CoreDataEngineering:
    """Unified ingestion and lifecycle service for core financial data."""

    def __init__(
        self,
        repository: Optional[DataRepository] = None,
        *,
        enrichers: Optional[Sequence[Callable[[CanonicalRecord], Mapping[str, Any]]]] = None,
        retention: RetentionPolicy = RetentionPolicy(),
    ) -> None:
        self.repository = repository or InMemoryDataRepository()
        self.enrichers = tuple(enrichers or ())
        self.retention = retention
        self.catalog = DEFAULT_CATALOG

    def ingest(self, tenant_id: str, source: str, payload: Mapping[str, Any]) -> Optional[CanonicalRecord]:
        record = normalize_record(tenant_id, source, payload)
        attributes = dict(record.attributes)
        for enrich in self.enrichers:
            attributes.update(enrich(record))
        record = CanonicalRecord(**{**record.__dict__, "attributes": attributes})
        lineage = build_lineage(record.event_id, record.transaction_id, record.tenant_id, record.provider)
        lineage = lineage.snapshot("raw_event", "core_data_engineering", "ingest", record.schema_version)
        lineage = lineage.snapshot("normalized", "core_data_engineering", "normalize", record.schema_version)
        return record if self.repository.put(record, payload, lineage) else None

    def ingest_api(self, tenant_id: str, payload: Mapping[str, Any]) -> Optional[CanonicalRecord]:
        return self.ingest(tenant_id, "api", payload)

    def ingest_event(self, tenant_id: str, payload: Mapping[str, Any]) -> Optional[CanonicalRecord]:
        return self.ingest(tenant_id, "event", payload)

    def ingest_batch(self, tenant_id: str, records: Iterable[Mapping[str, Any]], source: str = "batch") -> Dict[str, int]:
        accepted = duplicates = rejected = 0
        for payload in records:
            try:
                if self.ingest(tenant_id, source, payload):
                    accepted += 1
                else:
                    duplicates += 1
            except (TypeError, ValueError, KeyError):
                rejected += 1
        return {"accepted": accepted, "duplicates": duplicates, "rejected": rejected}

    def ingest_connector(self, connector: SourceConnector, tenant_id: str, cursor: Optional[str] = None, limit: int = 500) -> Dict[str, int]:
        return self.ingest_batch(tenant_id, connector.read(tenant_id=tenant_id, cursor=cursor, limit=limit), connector.name)

    def aggregate(self, tenant_id: str, *, by: str = "currency") -> Dict[str, Dict[str, Any]]:
        result: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "amount": Decimal("0.00")})
        for record in self.repository.records(tenant_id):
            key = str(getattr(record, by, record.attributes.get(by, "unknown")))
            result[key]["count"] += 1
            result[key]["amount"] += record.amount
        return {key: {"count": value["count"], "amount": str(value["amount"])} for key, value in result.items()}

    def partition_key(self, record: CanonicalRecord) -> str:
        """Return a stable tenant/time partition key for warehouse or stream sinks."""
        return f"tenant={record.tenant_id}/year={record.occurred_at.year:04d}/month={record.occurred_at.month:02d}"

    def lineage_for(self, tenant_id: str, event_id: str) -> Optional[DataLineage]:
        """Read lineage only through the tenant-scoped repository key."""
        lineage = getattr(self.repository, "lineage", {}).get((tenant_id, event_id))
        return lineage

    def apply_retention(self, tenant_id: str, now: Optional[datetime] = None) -> int:
        cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=self.retention.canonical_days)
        expired = [record for record in self.repository.records(tenant_id) if record.occurred_at < cutoff]
        for record in expired:
            if self.retention.archive_before_delete:
                self.repository.archive(record)
            self.repository.delete(record)
        return len(expired)

    def data_dictionary(self) -> Tuple[CatalogEntry, ...]:
        return self.catalog
