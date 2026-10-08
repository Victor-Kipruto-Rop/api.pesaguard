"""Provider-neutral ingestion boundary for financial events."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
import hashlib
from datetime import datetime, timezone
from decimal import InvalidOperation
from typing import Any, Dict, Mapping, Optional

from event_store import EventStore, ProcessResult, provider_account_id
from idempotency import derive_idempotency_key
from normalization import (
    NormalizationError,
    normalize_amount,
    normalize_currency,
    normalize_identifier,
    normalize_location,
    normalize_phone,
    normalize_provider,
    normalize_status,
    normalize_timestamp,
    normalize_transaction_type,
)
from validators import extract_canonical_event, validate_daraja_payload
from schema_validation import validate_canonical_transaction
from source_contracts import SourceContractError, validate_source_payload


class IngestionError(ValueError):
    """Raised when a source payload cannot become a canonical event."""


@dataclass(frozen=True)
class CanonicalTransaction:
    """Provider-neutral transaction contract used by the application."""

    tenant_id: str
    provider: str
    provider_account_id: str
    transaction_id: str
    provider_transaction_id: str
    account_id: str
    amount: str
    currency: str
    transaction_type: str
    status: str
    transaction_time: str
    phone_number: str
    merchant_id: str = ""
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    account_reference: str = ""

    def to_persistence_payload(self) -> Dict[str, Any]:
        """Map once to the legacy event-store contract at the boundary."""
        return {
            "tenant_id": self.tenant_id,
            "provider": self.provider,
            "provider_account_id": self.provider_account_id,
            "transaction_id": self.transaction_id,
            "provider_transaction_id": self.provider_transaction_id,
            "account_id": self.account_id,
            "merchant_id": self.merchant_id,
            "TransID": self.provider_transaction_id,
            "TransAmount": self.amount,
            "Currency": self.currency,
            "TransactionType": self.transaction_type,
            "Status": self.status,
            "TransTime": self.transaction_time,
            "MSISDN": self.phone_number,
            "BusinessShortCode": self.provider_account_id,
            "BillRefNumber": self.account_reference,
            "source": self.source,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class IngestionEnvelope:
    """The only payload shape accepted by the downstream event handoff."""

    tenant_id: str
    provider: str
    provider_account_id: str
    external_reference: str
    idempotency_key: str
    schema_version: int
    observed_at: str
    canonical: CanonicalTransaction
    payload: Dict[str, Any]
    raw_payload: Dict[str, Any]


class ProviderAdapter(ABC):
    """Translate one source contract into the shared ingestion envelope."""

    provider: str

    @abstractmethod
    def normalize(self, payload: Mapping[str, Any], *, tenant_id: str) -> IngestionEnvelope:
        raise NotImplementedError


class MpesaAdapter(ProviderAdapter):
    provider = "mpesa"

    def normalize(self, payload: Mapping[str, Any], *, tenant_id: str) -> IngestionEnvelope:
        source = dict(payload)
        if "Result" in source:
            raise IngestionError("B2C result callbacks require an explicit provider account mapping")
        try:
            source["TransAmount"] = normalize_amount(source.get("TransAmount"))
        except NormalizationError as exc:
            raise IngestionError(str(exc)) from exc
        valid, error = validate_daraja_payload(source)
        if not valid:
            raise IngestionError(error)
        canonical = extract_canonical_event(source, tenant_id=tenant_id)
        if canonical is None:
            raise IngestionError("M-Pesa payload could not be canonicalized")
        lifecycle_time = datetime.now(timezone.utc).isoformat()
        provider_transaction_id = normalize_identifier(canonical["TransID"])
        account_id = normalize_identifier(provider_account_id(source))
        canonical_model = CanonicalTransaction(
            tenant_id=tenant_id,
            provider=self.provider,
            provider_account_id=account_id,
            transaction_id=_canonical_transaction_id(tenant_id, self.provider, provider_transaction_id),
            provider_transaction_id=provider_transaction_id,
            account_id=account_id,
            amount=normalize_amount(canonical["TransAmount"]),
            currency=normalize_currency(source.get("Currency", "KES")),
            transaction_type=normalize_transaction_type(canonical.get("TransactionType", "PAYMENT")),
            status=normalize_status("RECEIVED"),
            transaction_time=normalize_timestamp(canonical.get("TransTime", "")),
            phone_number=normalize_phone(canonical.get("MSISDN", "")),
            source="mpesa",
            metadata={"location": normalize_location(source.get("location"))},
            created_at=lifecycle_time,
            updated_at=lifecycle_time,
            account_reference=str(canonical.get("BillRefNumber", "")),
        )
        return _build_envelope(canonical_model, source)


class SafaricomApiAdapter(ProviderAdapter):
    """Translate Safaricom API responses without exposing API field names."""

    provider = "safaricom"

    def normalize(self, payload: Mapping[str, Any], *, tenant_id: str) -> IngestionEnvelope:
        source = dict(payload)
        body = source.get("data") or source.get("transaction") or source
        if not isinstance(body, Mapping):
            raise IngestionError("Safaricom API response must contain an object")
        transaction_id = normalize_identifier(str(
            body.get("transactionId")
            or body.get("transaction_id")
            or body.get("receiptNumber")
            or body.get("TransID")
            or ""
        ))
        amount = body.get("amount", body.get("transAmount", body.get("TransAmount")))
        account = normalize_identifier(str(
            body.get("accountId")
            or body.get("businessShortCode")
            or body.get("BusinessShortCode")
            or ""
        ))
        if not transaction_id or not account:
            raise IngestionError("Safaricom API response requires transaction ID and account")
        try:
            normalized_amount = normalize_amount(amount)
        except (InvalidOperation, TypeError, ValueError, NormalizationError) as exc:
            raise IngestionError("transaction amount must be a valid decimal") from exc
        lifecycle_time = datetime.now(timezone.utc).isoformat()
        canonical = CanonicalTransaction(
            tenant_id=tenant_id,
            provider=self.provider,
            provider_account_id=account,
            transaction_id=_canonical_transaction_id(tenant_id, self.provider, transaction_id),
            provider_transaction_id=transaction_id,
            account_id=account,
            amount=normalized_amount,
            currency=normalize_currency(body.get("currency") or body.get("Currency") or "KES"),
            transaction_type=normalize_transaction_type(body.get("transactionType") or body.get("TransactionType") or "PAYMENT"),
            status=normalize_status(body.get("status") or "RECEIVED"),
            transaction_time=normalize_timestamp(body.get("transactionTime") or body.get("TransTime") or datetime.now(timezone.utc).isoformat()),
            phone_number=normalize_phone(body.get("phoneNumber") or body.get("MSISDN") or "unknown"),
            source="safaricom-api",
            metadata={"location": normalize_location(body.get("location"))},
            created_at=lifecycle_time,
            updated_at=lifecycle_time,
            account_reference=str(body.get("reference") or body.get("BillRefNumber") or ""),
        )
        return _build_envelope(canonical, source)


class GenericProviderAdapter(ProviderAdapter):
    """Normalize dict-shaped payment, file, API, or webhook records."""

    def __init__(self, provider: str):
        self.provider = provider

    def normalize(self, payload: Mapping[str, Any], *, tenant_id: str) -> IngestionEnvelope:
        source = dict(payload)
        try:
            reference = normalize_identifier(str(
            source.get("provider_transaction_id")
            or source.get("transaction_id")
            or source.get("external_reference")
            or source.get("id")
            or ""
        ))
        except NormalizationError as exc:
            raise IngestionError(str(exc)) from exc
        if not reference:
            raise IngestionError("provider transaction reference is required")
        amount = source.get("amount", source.get("TransAmount"))
        try:
            normalized_amount = normalize_amount(amount)
        except (InvalidOperation, TypeError, ValueError, NormalizationError):
            raise IngestionError("transaction amount must be a valid decimal")
        account = normalize_identifier(str(source.get("provider_account_id") or source.get("account_id") or "default"))
        if not account:
            raise IngestionError("provider account is required")
        lifecycle_time = datetime.now(timezone.utc).isoformat()
        canonical = CanonicalTransaction(
            tenant_id=tenant_id,
            provider=self.provider,
            provider_account_id=account,
            transaction_id=_canonical_transaction_id(tenant_id, self.provider, reference),
            provider_transaction_id=reference,
            account_id=account,
            amount=normalized_amount,
            currency=normalize_currency(source.get("currency") or source.get("Currency") or "KES"),
            transaction_type=normalize_transaction_type(source.get("transaction_type") or "PAYMENT"),
            status=normalize_status(source.get("status") or "RECEIVED"),
            transaction_time=normalize_timestamp(
                source.get("timestamp")
                or source.get("TransTime")
                or source.get("transaction_time")
                or datetime.now(timezone.utc).isoformat()
            ),
            phone_number=normalize_phone(source.get("phone_number") or source.get("msisdn") or "unknown"),
            source=normalize_provider(self.provider),
            metadata={"location": normalize_location(source.get("location"))},
            created_at=lifecycle_time,
            updated_at=lifecycle_time,
            account_reference=str(source.get("reference") or ""),
        )
        return _build_envelope(canonical, source)


class AirtelMoneyAdapter(GenericProviderAdapter):
    def __init__(self):
        super().__init__("airtel-money")


class BankAdapter(GenericProviderAdapter):
    def __init__(self):
        super().__init__("bank")


class PosAdapter(GenericProviderAdapter):
    def __init__(self):
        super().__init__("pos")


class CsvAdapter(GenericProviderAdapter):
    def __init__(self):
        super().__init__("csv")


class ExternalApiAdapter(GenericProviderAdapter):
    def __init__(self):
        super().__init__("external-api")


class WebhookAdapter(GenericProviderAdapter):
    def __init__(self):
        super().__init__("webhook")


def _build_envelope(canonical: CanonicalTransaction, raw_payload: Dict[str, Any]) -> IngestionEnvelope:
    tenant = str(canonical.tenant_id).strip()
    if not tenant:
        raise IngestionError("tenant context is required")
    reference = canonical.provider_transaction_id.strip()
    account = canonical.provider_account_id.strip()
    if not reference or not account:
        raise IngestionError("provider transaction reference and account are required")
    payload = canonical.to_persistence_payload()
    payload["raw_payload"] = raw_payload
    try:
        validate_canonical_transaction(payload)
    except ValueError as exc:
        raise IngestionError(str(exc)) from exc
    idempotency_key = derive_idempotency_key(payload)
    observed_at = canonical.transaction_time or datetime.now(timezone.utc).isoformat()
    return IngestionEnvelope(
        tenant_id=tenant,
        provider=canonical.provider,
        provider_account_id=account,
        external_reference=reference,
        idempotency_key=idempotency_key,
        schema_version=1,
        observed_at=observed_at,
        canonical=canonical,
        payload=payload,
        raw_payload=raw_payload,
    )


def _canonical_transaction_id(tenant_id: str, provider: str, provider_transaction_id: str) -> str:
    identity = f"{tenant_id}:{provider}:{provider_transaction_id}".encode("utf-8")
    return f"txn_{hashlib.sha256(identity).hexdigest()[:24]}"


ADAPTERS = {
    "mpesa": MpesaAdapter(),
    "safaricom-api": SafaricomApiAdapter(),
    "airtel-money": AirtelMoneyAdapter(),
    "bank": BankAdapter(),
    "pos": PosAdapter(),
    "csv": CsvAdapter(),
    "external-api": ExternalApiAdapter(),
    "webhook": WebhookAdapter(),
}


@dataclass(frozen=True)
class IngestionResult:
    result: ProcessResult
    envelope: IngestionEnvelope


class IngestionService:
    """Single controlled handoff from adapters to durable event persistence."""

    def __init__(self, event_store: EventStore, adapters: Optional[Mapping[str, ProviderAdapter]] = None):
        self.event_store = event_store
        self.adapters = dict(adapters or ADAPTERS)

    def ingest(self, provider: str, payload: Mapping[str, Any], *, tenant_id: str) -> IngestionResult:
        adapter = self.adapters.get(str(provider).strip().lower())
        if adapter is None:
            raise IngestionError(f"unsupported ingestion provider: {provider}")
        try:
            validate_source_payload(provider, payload)
        except SourceContractError as exc:
            raise IngestionError(str(exc)) from exc
        envelope = adapter.normalize(payload, tenant_id=tenant_id)
        result = self.event_store.mark_processed(
            envelope.payload,
            tenant_id=envelope.tenant_id,
            idempotency_key_override=envelope.idempotency_key,
        )
        return IngestionResult(result=result, envelope=envelope)

    def emit(self, envelope: IngestionEnvelope) -> IngestionResult:
        """Persist an already-transformed envelope at the connector boundary."""
        if not isinstance(envelope, IngestionEnvelope):
            raise IngestionError("connector output must be an ingestion envelope")
        if not isinstance(envelope.canonical, CanonicalTransaction):
            raise IngestionError("ingestion envelope must contain a canonical transaction")
        if not isinstance(envelope.raw_payload, Mapping) or not isinstance(envelope.payload, Mapping):
            raise IngestionError("ingestion envelope payloads must be objects")
        if type(envelope.schema_version) is not int or envelope.schema_version != 1:
            raise IngestionError(f"unsupported ingestion envelope schema version: {envelope.schema_version}")

        matching_adapters = [
            (source, adapter)
            for source, adapter in self.adapters.items()
            if adapter.provider == envelope.provider
        ]
        if len(matching_adapters) != 1:
            raise IngestionError(f"ingestion envelope provider is unsupported or ambiguous: {envelope.provider}")
        source, adapter = matching_adapters[0]
        try:
            validate_source_payload(source, envelope.raw_payload)
            expected = adapter.normalize(envelope.raw_payload, tenant_id=envelope.tenant_id)
        except SourceContractError as exc:
            raise IngestionError(str(exc)) from exc

        actual_canonical = asdict(envelope.canonical)
        expected_canonical = asdict(expected.canonical)
        for fields in (actual_canonical, expected_canonical):
            fields.pop("created_at", None)
            fields.pop("updated_at", None)
        actual_payload = dict(envelope.payload)
        expected_payload = dict(expected.payload)
        for fields in (actual_payload, expected_payload):
            fields.pop("created_at", None)
            fields.pop("updated_at", None)
        source_payload = envelope.raw_payload
        if source == "safaricom-api":
            source_payload = source_payload.get("data") or source_payload.get("transaction") or source_payload
            has_transaction_time = bool(
                source_payload.get("transactionTime")
                or source_payload.get("TransTime")
            )
        else:
            has_transaction_time = bool(
                source_payload.get("timestamp")
                or source_payload.get("TransTime")
                or source_payload.get("transaction_time")
            )
        if not has_transaction_time:
            actual_canonical.pop("transaction_time", None)
            expected_canonical.pop("transaction_time", None)
            actual_payload.pop("TransTime", None)
            expected_payload.pop("TransTime", None)

        if (
            actual_canonical != expected_canonical
            or actual_payload != expected_payload
            or envelope.tenant_id != expected.tenant_id
            or envelope.provider != expected.provider
            or envelope.provider_account_id != expected.provider_account_id
            or envelope.external_reference != expected.external_reference
            or envelope.idempotency_key != expected.idempotency_key
            or not (
                envelope.observed_at
                == envelope.canonical.transaction_time
                == envelope.payload.get("TransTime")
            )
            or (has_transaction_time and envelope.observed_at != expected.observed_at)
        ):
            raise IngestionError("ingestion envelope does not match its source payload")

        result = self.event_store.mark_processed(
            envelope.payload,
            tenant_id=envelope.tenant_id,
            idempotency_key_override=envelope.idempotency_key,
        )
        return IngestionResult(result=result, envelope=envelope)