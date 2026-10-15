"""Tenant-scoped orchestration for advisory reconciliation intelligence.

This module composes deterministic algorithms without mutating transactions,
posting ledger entries, or making fraud/approval decisions. Callers must supply
trusted scope from authenticated server context and tenant-scoped persistence queries.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
from zoneinfo import ZoneInfo

try:
    from .advanced_reconciliation_algorithms import seasonal_amount_assessment
    from .smart_reconciliation_algorithms import (
        assess_rule_based_risk, rank_reconciliation_candidates,
        validate_transaction_quality, detect_velocity_breach,
    )
except ImportError:  # pragma: no cover
    from advanced_reconciliation_algorithms import seasonal_amount_assessment
    from smart_reconciliation_algorithms import (
        assess_rule_based_risk, rank_reconciliation_candidates,
        validate_transaction_quality, detect_velocity_breach,
    )

ALGORITHM_PIPELINE_VERSION = "algorithm-evidence-pipeline-v1"
_SCOPE_ALIASES = {
    "tenant_id": ("tenant_id", "tenantId", "TenantID"),
    "provider": ("provider", "provider_name", "providerName"),
    "provider_account_id": (
        "provider_account_id", "account_id", "merchant_account_id",
        "BusinessShortCode", "business_short_code",
    ),
    "currency": ("currency", "Currency"),
}


def _first(record: Mapping[str, Any], names: Sequence[str]) -> Any:
    for name in names:
        value = record.get(name)
        if value not in (None, ""):
            return value
    return None


def _canonical_scope(scope: Mapping[str, Any]) -> dict[str, str]:
    result = {}
    for key in _SCOPE_ALIASES:
        value = scope.get(key)
        if value in (None, ""):
            raise ValueError(f"scope.{key} is required")
        normalized = str(value).strip()
        if not normalized:
            raise ValueError(f"scope.{key} is required")
        result[key] = normalized.upper() if key == "currency" else (
            normalized.casefold() if key == "provider" else normalized
        )
    return result


def _canonical_event_time(value: Any) -> Any:
    """Normalize Daraja YYYYMMDDhhmmss timestamps as Africa/Nairobi time."""
    if isinstance(value, datetime):
        return value.isoformat() if value.tzinfo is not None else value
    raw = str(value or "").strip()
    if len(raw) == 14 and raw.isdigit():
        try:
            parsed = datetime.strptime(raw, "%Y%m%d%H%M%S").replace(
                tzinfo=ZoneInfo("Africa/Nairobi")
            )
            return parsed.isoformat()
        except ValueError:
            return raw
    return value


def _scope_record(record: Mapping[str, Any], scope: Mapping[str, str]) -> tuple[bool, list[str]]:
    reasons = []
    for key, aliases in _SCOPE_ALIASES.items():
        value = _first(record, aliases)
        if value is None:
            reasons.append(f"missing_{key}")
            continue
        normalized = str(value).strip()
        if key == "currency":
            normalized = normalized.upper()
        elif key == "provider":
            normalized = normalized.casefold()
        if normalized != scope[key]:
            reasons.append(f"{key}_scope_conflict")
    return not reasons, reasons


def evaluate_algorithmic_evidence(
    transaction: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
    *,
    scope: Mapping[str, Any],
    amount_history: Sequence[Mapping[str, Any]] = (),
    velocity_history: Sequence[Mapping[str, Any]] = (),
    entity_key: str | None = None,
    now: datetime | None = None,
    window_seconds: int = 900,
    amount_tolerance: str = "0.01",
    seasonal_minimum_samples: int = 8,
    velocity_window_seconds: int = 300,
    velocity_max_events: int = 5,
    duplicate_candidate: bool = False,
) -> dict[str, Any]:
    """Return an evidence bundle for review; never make a financial state change.

    Scope must come from authenticated server context, not webhook claims. Candidate
    and history rows without all four matching scope fields are excluded. Entity keys
    should be stable tenant-local identifiers (prefer keyed hashes for PII).
    Collections must be bounded and queried with tenant-safe database predicates.
    """
    if not isinstance(scope, Mapping):
        raise ValueError("scope must be a mapping derived from trusted server context")
    trusted_scope = _canonical_scope(scope)
    if not isinstance(transaction, Mapping):
        raise ValueError("transaction must be a mapping")
    if now is not None and (now.tzinfo is None or now.utcoffset() is None):
        raise ValueError("now must be timezone-aware")
    clock = now or datetime.now(timezone.utc)
    if window_seconds < 0:
        raise ValueError("window_seconds must be non-negative")
    if isinstance(seasonal_minimum_samples, bool) or seasonal_minimum_samples < 5:
        raise ValueError("seasonal_minimum_samples must be at least 5")
    if velocity_window_seconds <= 0 or velocity_max_events < 1:
        raise ValueError("velocity window and event limit must be positive")

    canonical_transaction = dict(transaction)
    canonical_transaction.update(trusted_scope)
    quality_input = {
        **canonical_transaction,
        "transaction_id": _first(canonical_transaction, ("transaction_id", "TransID", "trans_id")),
        "reference": _first(canonical_transaction, ("reference", "BillRefNumber")),
        "amount": _first(canonical_transaction, ("amount", "TransAmount")),
        "timestamp": _canonical_event_time(_first(canonical_transaction, ("timestamp", "TransTime"))),
    }
    quality = validate_transaction_quality(quality_input)

    scoped_candidates = []
    excluded_candidates = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, Mapping):
            excluded_candidates.append({
                "candidate_id": f"candidate-{index + 1}",
                "reason_codes": ["invalid_candidate_shape"],
            })
            continue
        eligible, reasons = _scope_record(candidate, trusted_scope)
        candidate_id = str(candidate.get("internal_ref") or candidate.get("id") or f"candidate-{index + 1}")
        if eligible:
            scoped_candidates.append(dict(candidate))
        else:
            excluded_candidates.append({"candidate_id": candidate_id, "reason_codes": reasons})

    ranking = rank_reconciliation_candidates(
        quality_input, scoped_candidates,
        window_seconds=window_seconds, amount_tolerance=amount_tolerance,
    )
    if excluded_candidates:
        ranking = {
            **ranking,
            "decision": "REVIEW",
            "reason_codes": sorted(set(ranking.get("reason_codes", [])) | {"candidate_scope_or_metadata_excluded"}),
        }

    def scoped_history(rows: Sequence[Mapping[str, Any]]) -> tuple[list[Mapping[str, Any]], int]:
        accepted = []
        excluded = 0
        for row in rows:
            if not isinstance(row, Mapping):
                excluded += 1
                continue
            eligible, _ = _scope_record(row, trusted_scope)
            if eligible:
                accepted.append(row)
            else:
                excluded += 1
        return accepted, excluded

    valid_amount_history, excluded_amount_rows = scoped_history(amount_history)
    seasonal = {
        "ready": False, "reason": "missing_or_invalid_transaction_timestamp",
        "is_outlier": None, "sample_count": 0,
    }
    amount = quality_input.get("amount")
    event_time = quality_input.get("timestamp")
    if amount not in (None, "") and event_time not in (None, ""):
        try:
            seasonal = seasonal_amount_assessment(
                amount,
                [{
                    "amount": row.get("amount", row.get("TransAmount")),
                    "timestamp": _canonical_event_time(_first(row, ("timestamp", "TransTime", "created_at"))),
                    "currency": trusted_scope["currency"],
                } for row in valid_amount_history],
                event_time=event_time,
                minimum_samples=seasonal_minimum_samples,
                currency=trusted_scope["currency"],
            )
        except (TypeError, ValueError, ArithmeticError):
            seasonal = {
                "ready": False, "reason": "seasonal_assessment_unavailable",
                "is_outlier": None, "sample_count": 0,
            }

    valid_velocity_rows, excluded_velocity_rows = scoped_history(velocity_history)
    if entity_key is not None:
        valid_velocity_rows = [
            row for row in valid_velocity_rows
            if str(row.get("entity_key") or "") == str(entity_key)
        ]
        velocity = detect_velocity_breach(
            [_first(row, ("timestamp", "TransTime", "created_at")) for row in valid_velocity_rows],
            window_seconds=velocity_window_seconds,
            max_events=velocity_max_events,
            now=clock,
        )
        velocity["ready"] = True
    else:
        velocity = {
            "algorithm_version": "smart-reconciliation-v1",
            "ready": False, "reason": "entity_key_not_supplied",
            "count": None, "breach": None,
        }

    top = ranking.get("top_candidate") or {}
    conflicts = set(top.get("conflicts") or ())
    transaction_type = str(_first(canonical_transaction, ("transaction_type", "TransactionType")) or "payment").strip().lower()
    original_reference = _first(canonical_transaction, (
        "original_reference", "OriginalTransID", "OriginalTransactionID", "original_transaction_id"
    ))
    risk = assess_rule_based_risk(
        duplicate=duplicate_candidate,
        amount_outlier=seasonal.get("ready") is True and seasonal.get("is_outlier") is True,
        velocity_breach=velocity.get("breach") is True,
        reference_conflict="reference_conflict" in conflicts,
        phone_conflict="phone_conflict" in conflicts,
        invalid_payload=not quality["valid_for_automatic_matching"],
        reversal_without_original=transaction_type in {"refund", "reversal"} and not str(original_reference or "").strip(),
    )
    return {
        "pipeline_version": ALGORITHM_PIPELINE_VERSION,
        "mode": "advisory",
        "scope_complete": True,
        "quality": quality,
        "candidate_ranking": ranking,
        "scope_exclusions": {
            "candidate_count": len(excluded_candidates),
            "candidates": excluded_candidates,
            "amount_history_rows": excluded_amount_rows,
            "velocity_history_rows": excluded_velocity_rows,
        },
        "seasonal_amount": seasonal,
        "velocity": velocity,
        "risk": {
            "score": risk.score, "level": risk.level, "action": risk.action,
            "signals": list(risk.signals), "algorithm_version": risk.algorithm_version,
            "is_probability": False,
        },
        "automatic_financial_action": False,
        "requires_existing_policy_and_ledger_validation": True,
    }
