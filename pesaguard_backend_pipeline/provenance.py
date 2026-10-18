"""Phase 9 provenance, data-quality, and quarantine orchestration.

Owned responsibilities:
* Validate incoming provider payloads against the data-quality rule set.
* Build a complete lineage snapshot (provider -> webhook -> raw -> normalized ->
  fraud -> reconciliation -> exception -> report) for each transaction.
* Persist TransactionProvenance as the exit-gate anchor for each transaction.
* Route failing records to QuarantineRecord instead of contaminating production
  transaction datasets.
* Track schema/pipeline versions so every decision is traceable to the version
  that produced it.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from data_lineage import (
    PIPELINE_VERSION_KEY,
    SCHEMA_VERSION_KEY,
    build_lineage,
    lineage_schema_version,
)
from data_profiling import profile_payload
from data_quality import (
    DataQualityFailure,
    DataQualityResult,
    DataQualityStatus,
    run_data_quality,
)
from dq_rules import (
    _rule_amount_positive,
    _rule_currency_valid,
    _rule_provider_valid,
    _rule_reference_valid,
    _rule_schema_version_present,
    _rule_tenant_exists,
    _rule_transaction_id_not_null,
)
from models import QuarantineRecord, TransactionProvenance
from schema_evolution import (
    assess_schema_compatibility,
    schema_version_from_payload,
)

logger = logging.getLogger(__name__)

DEFAULT_SCHEMA_VERSION = os.getenv("DATA_SCHEMA_VERSION", "1.0")
DEFAULT_PIPELINE_VERSION = os.getenv("DATA_PIPELINE_VERSION", "1.0")
DATETIME_FACTORY = datetime.now


def _iso_now() -> str:
    return DATETIME_FACTORY(timezone.utc).isoformat()


def _sha256_json(payload: Dict[str, Any]) -> str:
    serialized = json.dumps(
        payload, sort_keys=True, default=str, separators=(",", ":")
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _safe_json(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {"__list__": value}
    return {"__raw__": str(value)[:4096]}


class ProvenanceError(Exception):
    """Raised when provenance recording cannot be completed safely."""


def _pick(raw: Dict[str, Any], *keys: str) -> Optional[str]:
    for key in keys:
        if key in raw:
            value = raw[key]
            if isinstance(value, str):
                return value.strip() or None
            if isinstance(value, (int, float)):
                return str(value)
    return None


def _provider_from_payload(raw: Dict[str, Any]) -> Optional[str]:
    provider = _pick(raw, "Provider", "provider", "source", "provider_id")
    if provider:
        return provider.strip().lower()
    return None


def _tenant_id_from_payload(raw: Dict[str, Any]) -> Optional[str]:
    return _pick(raw, "TenantID", "tenant_id", "tenantId", "Tenant-Id")


def _require_tenant_id(
    raw: Dict[str, Any], result_tenant_id: Optional[str] = None
) -> str:
    """Return an explicit tenant identity or fail closed.

    Financial records must never be assigned to a shared unknown tenant:
    doing so can weaken isolation and make provenance impossible to attribute.
    Callers should route this error to the ingestion dead-letter/quarantine
    boundary that has enough trusted context to handle an unscoped event.
    """
    tenant_id = (result_tenant_id or _tenant_id_from_payload(raw) or "").strip()
    if not tenant_id or tenant_id.lower() == "unknown":
        raise ProvenanceError(
            "tenant_id is required to process transaction provenance"
        )
    return tenant_id


def _transaction_id_from_payload(raw: Dict[str, Any]) -> Optional[str]:
    return _pick(raw, "TransID", "TransactionID", "transaction_id")


def _normalize_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    normalized = {
        "transaction_id": raw.get("TransID") or raw.get("TransactionID") or raw.get("transaction_id"),
        "tenant_id": raw.get("TenantID") or raw.get("tenant_id") or raw.get("tenantId"),
        "provider_id": raw.get("Provider") or raw.get("provider") or raw.get("provider_id"),
        "amount": raw.get("TransAmount") or raw.get("amount"),
        "currency": raw.get("Currency") or raw.get("currency") or raw.get("TransCurrency"),
        "timestamp": raw.get("TransTime") or raw.get("transaction_time"),
        "reference": raw.get("BillRefNumber") or raw.get("Reference") or raw.get("reference"),
    }
    normalized.update({k: v for k, v in raw.items() if k not in normalized})
    return normalized


def _provenance_row_from_quality(
    result: DataQualityResult,
    raw: Dict[str, Any],
    *,
    schema_version: Optional[str] = None,
    pipeline_version: Optional[str] = None,
) -> Dict[str, Any]:
    provider_id = result.provider_id or _provider_from_payload(raw) or "unknown"
    tx_id = result.transaction_id or _transaction_id_from_payload(raw) or "unknown"
    tenant_id = _require_tenant_id(raw, result.tenant_id)
    schema_version = schema_version or schema_version_from_payload(raw) or DEFAULT_SCHEMA_VERSION
    pipeline_version = pipeline_version or DEFAULT_PIPELINE_VERSION
    normalized_snapshot = _safe_json(_normalize_payload(raw))
    lineage = build_lineage(
        event_id=str(raw.get("event_id") or tx_id),
        transaction_id=tx_id,
        tenant_id=tenant_id,
        provider_id=provider_id,
    )
    lineage = lineage.to_dict()
    lineage["processed_at"] = _iso_now()
    return {
        "transaction_id": tx_id,
        "tenant_id": tenant_id,
        "provider_id": provider_id,
        "lineage_id": lineage["lineage_id"],
        "event_id": lineage["event_id"],
        "schema_version": schema_version,
        "pipeline_version": pipeline_version,
        "dq_status": result.status,
        "dq_completeness": result.completeness,
        "dq_validity": result.validity,
        "dq_timeliness": result.timeliness,
        "dq_accuracy": result.accuracy,
        "dq_consistency": result.consistency,
        "dq_uniqueness": result.uniqueness,
        "dq_failures": result.to_dict()["failures"],
        "raw_hash": _sha256_json(raw),
        "normalized_snapshot": normalized_snapshot,
        "lineage_snapshot": lineage,
    }



def persist_provenance(
    session,
    result: DataQualityResult,
    raw: Dict[str, Any],
    *,
    schema_version: Optional[str] = None,
    pipeline_version: Optional[str] = None,
) -> TransactionProvenance:
    row = _provenance_row_from_quality(
        result, raw, schema_version=schema_version, pipeline_version=pipeline_version
    )
    record = TransactionProvenance(
        lineage_id=row["lineage_id"],
        event_id=row["event_id"],
        transaction_id=row["transaction_id"],
        tenant_id=row["tenant_id"],
        provider_id=row["provider_id"],
        raw_payload_sha256=row["raw_hash"],
        schema_version=row["schema_version"],
        pipeline_version=row["pipeline_version"],
        dq_status=row["dq_status"],
        dq_completeness=row["dq_completeness"],
        dq_validity=row["dq_validity"],
        dq_timeliness=row["dq_timeliness"],
        dq_accuracy=row["dq_accuracy"],
        dq_consistency=row["dq_consistency"],
        dq_uniqueness=row["dq_uniqueness"],
        dq_failures=row["dq_failures"],
        lineage_snapshot=row.get("lineage_snapshot"),
        dq_checked_at=datetime.now(timezone.utc),
        normalized_payload_sha256=_sha256_json(row["normalized_snapshot"]),
    )
    session.add(record)
    session.flush()
    return record



def quarantine_record(
    session,
    result: DataQualityResult,
    raw: Dict[str, Any],
    *,
    schema_version: Optional[str] = None,
    pipeline_version: Optional[str] = None,
    quarantine_reason: Optional[str] = None,
) -> QuarantineRecord:
    row = _provenance_row_from_quality(
        result, raw, schema_version=schema_version, pipeline_version=pipeline_version
    )
    failure_reasons = "; ".join(sorted({f.reason for f in result.failures}))
    if quarantine_reason:
        failure_reasons = f"{quarantine_reason}; {failure_reasons}".strip("; ")
    record = QuarantineRecord(
        transaction_id=row["transaction_id"],
        tenant_id=row["tenant_id"],
        provider_id=row["provider_id"],
        lineage_id=row["lineage_id"],
        reason=failure_reasons or "quality_gate_failure",
        failure_rule=", ".join(sorted({failure.rule.code for failure in result.failures})) or None,
        payload=_safe_json(raw),
        payload_sha256=row["raw_hash"],
        rejection_context={
            "dq_status": row["dq_status"],
            "dimension_scores": result.dimension_scores,
            "failures": row["dq_failures"],
            "schema_version": row["schema_version"],
            "pipeline_version": row["pipeline_version"],
            "event_id": row["event_id"],
        },
    )
    session.add(record)
    session.flush()
    return record



class DataProvenance:
    """Orchestrates validation, lineage, persistence, and quarantine for one payload.

    This is the Phase 9 exit gate for incoming provider data. Every important
    transaction should be able to answer:

    * Where did this data originate?
    * What changed it?
    * Which service processed it?
    * Which version processed it?
    * What was the final decision?
    """

    def __init__(
        self,
        *,
        schema_version: Optional[str] = None,
        pipeline_version: Optional[str] = None,
        lineage_builder=None,
        now_fn=None,
    ):
        self.schema_version = schema_version or DEFAULT_SCHEMA_VERSION
        self.pipeline_version = pipeline_version or DEFAULT_PIPELINE_VERSION
        self.lineage_builder = lineage_builder or build_lineage
        self.now_fn = now_fn or _iso_now

    def evaluate(
        self,
        raw: Dict[str, Any],
        *,
        trusted_tenant_id: Optional[str] = None,
    ) -> DataQualityResult:
        # Prefer tenant identity resolved by authenticated integration
        # configuration. Payload-supplied tenant IDs are untrusted input.
        declared_tenant_id = _tenant_id_from_payload(raw)
        if trusted_tenant_id is not None:
            trusted_tenant_id = trusted_tenant_id.strip()
            if not trusted_tenant_id or trusted_tenant_id.lower() == "unknown":
                raise ProvenanceError("trusted tenant_id must be a concrete tenant identifier")
            if declared_tenant_id and declared_tenant_id != trusted_tenant_id:
                raise ProvenanceError("payload tenant_id does not match authenticated tenant")
            tenant_id = trusted_tenant_id
        else:
            # Compatibility mode for internal/legacy callers. Production
            # webhook/API callers should pass a tenant resolved from credentials,
            # integration configuration, or another authenticated server context.
            tenant_id = _require_tenant_id(raw)

        effective_raw = dict(raw)
        effective_raw["tenant_id"] = tenant_id
        lineage = self.lineage_builder(
            event_id=str(raw.get("event_id") or _transaction_id_from_payload(raw) or "unknown"),
            transaction_id=_transaction_id_from_payload(raw) or "unknown",
            tenant_id=tenant_id,
            provider_id=_provider_from_payload(raw),
        )
        return run_data_quality(effective_raw, lineage=lineage)

    def process(
        self,
        raw: Dict[str, Any],
        session,
        *,
        quarantine_on_failure: bool = True,
        trusted_tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        quality = self.evaluate(raw, trusted_tenant_id=trusted_tenant_id)
        effective_raw = dict(raw)
        effective_raw["tenant_id"] = quality.tenant_id
        from metrics import record_data_quality
        record_data_quality(quality)
        if quality.status == DataQualityStatus.FAIL:
            if quarantine_on_failure:
                quarantine_record(
                    session,
                    quality,
                    effective_raw,
                    schema_version=self.schema_version,
                    pipeline_version=self.pipeline_version,
                )
            return {
                "decision": "quarantined",
                "transaction_id": quality.transaction_id,
                "tenant_id": quality.tenant_id,
                "provider_id": quality.provider_id,
                "quality": quality.to_dict(),
            }
        schema_compat = assess_schema_compatibility(raw, self.schema_version)
        if schema_compat == "incompatible":
            quarantine_record(
                session,
                quality,
                effective_raw,
                schema_version=self.schema_version,
                pipeline_version=self.pipeline_version,
                quarantine_reason="schema_incompatible",
            )
            return {
                "decision": "quarantined",
                "transaction_id": quality.transaction_id,
                "tenant_id": quality.tenant_id,
                "provider_id": quality.provider_id,
                "quality": quality.to_dict(),
            }
        persist_provenance(
            session,
            quality,
            effective_raw,
            schema_version=self.schema_version,
            pipeline_version=self.pipeline_version,
        )
        return {
            "decision": "accepted",
            "transaction_id": quality.transaction_id,
            "tenant_id": quality.tenant_id,
            "provider_id": quality.provider_id,
            "quality": quality.to_dict(),
        }


def record_webhook_provenance(
    session,
    raw: Dict[str, Any],
    *,
    schema_version: Optional[str] = None,
    pipeline_version: Optional[str] = None,
    trusted_tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Convenience wrapper used by the webhook ingestion path.

    Returns the same decision dict as ``DataProvenance.process`` so callers can
    branch on ``decision`` without constructing a full orchestrator instance.
    """
    orchestrator = DataProvenance(
        schema_version=schema_version,
        pipeline_version=pipeline_version,
    )
    return orchestrator.process(
        raw, session, quarantine_on_failure=True, trusted_tenant_id=trusted_tenant_id
    )
