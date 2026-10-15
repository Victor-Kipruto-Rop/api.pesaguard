"""Fail-closed validation for refund/reversal lifecycle evidence.

This module is deliberately pure and advisory. It does not call a payment
provider, issue a refund, mutate a ledger, or authorize automatic posting.
Callers must retrieve the original and prior reversals inside the authenticated
tenant/provider-account scope and persist the result with their own transaction.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping


ALGORITHM_VERSION = "transaction-lifecycle-v1"
_SCOPE_ALIASES = {
    "tenant_id": ("tenant_id", "TenantID", "tenantId"),
    "provider": ("provider", "provider_name", "providerName"),
    "provider_account_id": (
        "provider_account_id", "account_id", "merchant_account_id",
        "BusinessShortCode", "business_short_code",
    ),
    "currency": ("currency", "Currency"),
}
_TRANSACTION_ID_KEYS = (
    "TransID", "trans_id", "transaction_id", "provider_transaction_id",
)
_ORIGINAL_ID_KEYS = (
    "OriginalTransID", "OriginalTransactionID", "original_transaction_id",
    "original_reference", "original_ref",
)
_AMOUNT_KEYS = ("TransAmount", "amount", "transaction_amount")
_CONFIRMED_STATES = frozenset({"confirmed", "complete", "completed", "success", "succeeded"})


def _first(record: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    return next((record.get(key) for key in keys if record.get(key) not in (None, "")), None)


def _amount(record: Mapping[str, Any]) -> Decimal | None:
    value = _first(record, _AMOUNT_KEYS)
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError):
        return None
    return parsed if parsed.is_finite() else None


def _timestamp(record: Mapping[str, Any]) -> datetime | None:
    value = _first(record, ("TransTime", "timestamp", "created_at", "event_time"))
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _scope_value(record: Mapping[str, Any], scope: str) -> str | None:
    value = _first(record, _SCOPE_ALIASES[scope])
    if value is None:
        return None
    normalized = str(value).strip()
    if scope in {"provider", "currency"}:
        normalized = normalized.casefold()
    return normalized or None


def assess_reversal_lifecycle(
    reversal: Mapping[str, Any],
    original: Mapping[str, Any] | None,
    prior_reversals: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Validate reversal linkage, scope, chronology, and cumulative amount.

    prior_reversals must contain records from the same tenant/provider/account.
    Only provider-confirmed prior reversals are included in the cumulative total.
    Missing/ambiguous evidence returns REVIEW_REQUIRED; a clean result is
    validation evidence, never posting consent.
    """
    if not isinstance(reversal, Mapping):
        raise ValueError("reversal must be a mapping")
    if original is not None and not isinstance(original, Mapping):
        raise ValueError("original must be a mapping or None")

    reasons: list[str] = []
    reversal_id = str(_first(reversal, _TRANSACTION_ID_KEYS) or "").strip()
    original_ref = str(_first(reversal, _ORIGINAL_ID_KEYS) or "").strip()
    if not reversal_id:
        reasons.append("missing_reversal_transaction_id")
    if not original_ref:
        reasons.append("missing_original_reference")
    if original is None:
        reasons.append("original_transaction_not_found")
        original_id = ""
    else:
        original_id = str(_first(original, _TRANSACTION_ID_KEYS) or "").strip()
        if not original_id:
            reasons.append("original_transaction_id_missing")
        elif original_ref and original_ref != original_id:
            reasons.append("original_reference_mismatch")

    current_amount = _amount(reversal)
    original_amount = _amount(original) if original is not None else None
    if current_amount is None or current_amount <= 0:
        reasons.append("invalid_reversal_amount")
    if original is not None and (original_amount is None or original_amount <= 0):
        reasons.append("invalid_original_amount")

    if original is not None:
        for scope in _SCOPE_ALIASES:
            current_scope = _scope_value(reversal, scope)
            original_scope = _scope_value(original, scope)
            if not current_scope or not original_scope:
                reasons.append(f"scope_context_missing:{scope}")
            elif current_scope != original_scope:
                reasons.append(f"scope_conflict:{scope}")

    reversal_time = _timestamp(reversal)
    original_time = _timestamp(original) if original is not None else None
    if reversal_time is None:
        reasons.append("reversal_timestamp_missing_or_ambiguous")
    if original is not None and original_time is None:
        reasons.append("original_timestamp_missing_or_ambiguous")
    if reversal_time is not None and original_time is not None and reversal_time < original_time:
        reasons.append("reversal_precedes_original")

    prior_total = Decimal("0")
    seen_prior_ids: set[str] = set()
    prior_count = 0
    for prior in prior_reversals:
        if not isinstance(prior, Mapping):
            reasons.append("invalid_prior_reversal_record")
            continue
        prior_id = str(_first(prior, _TRANSACTION_ID_KEYS) or "").strip()
        if prior_id and prior_id == reversal_id:
            reasons.append("duplicate_reversal_transaction_id")
        if prior_id and prior_id in seen_prior_ids:
            reasons.append("duplicate_prior_reversal_record")
        if prior_id:
            seen_prior_ids.add(prior_id)

        prior_original_ref = str(_first(prior, _ORIGINAL_ID_KEYS) or "").strip()
        if not original_id or prior_original_ref != original_id:
            continue

        scope_conflict = False
        for scope in _SCOPE_ALIASES:
            prior_scope = _scope_value(prior, scope)
            original_scope = _scope_value(original or {}, scope)
            if not prior_scope or not original_scope or prior_scope != original_scope:
                reasons.append(f"prior_reversal_scope_conflict:{scope}")
                scope_conflict = True
        if scope_conflict:
            continue

        state = str(prior.get("status") or prior.get("result_code") or "").strip().casefold()
        if state in _CONFIRMED_STATES:
            prior_amount = _amount(prior)
            if prior_amount is None or prior_amount <= 0:
                reasons.append("invalid_confirmed_prior_reversal_amount")
            else:
                prior_total += prior_amount
                prior_count += 1

    if current_amount is not None and original_amount is not None and current_amount > 0 and original_amount > 0:
        if prior_total + current_amount > original_amount:
            reasons.append("cumulative_reversal_exceeds_original_amount")

    reason_codes = list(dict.fromkeys(reasons))
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "status": "REVIEW_REQUIRED" if reason_codes else "VALIDATION_PASS",
        "review_required": bool(reason_codes),
        "can_auto_post": False,
        "reason_codes": reason_codes,
        "original_transaction_id": original_id or None,
        "reversal_transaction_id": reversal_id or None,
        "original_amount": format(original_amount, "f") if original_amount is not None else None,
        "reversal_amount": format(current_amount, "f") if current_amount is not None else None,
        "confirmed_prior_reversal_amount": format(prior_total, "f"),
        "confirmed_prior_reversal_count": prior_count,
    }
