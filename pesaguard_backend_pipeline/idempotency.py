"""Deterministic idempotency keys for provider transaction ingestion.

The provider transaction ID is the preferred identity. The fallback fingerprint
is deliberately strict and remains a deduplication hint, not proof that two
payments are the same: persistence must enforce tenant/provider/account scope
and compare the canonical payload before treating a replay as identical.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Mapping


def _normalize_msisdn(value: Any) -> str:
    return "".join(ch for ch in str(value or "") if ch.isdigit())


def _normalize_amount(value: Any) -> str:
    """Canonicalize finite decimal money without binary float conversion."""
    if isinstance(value, bool) or value is None:
        raise ValueError("amount is required for fallback idempotency fingerprint")
    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("amount must be a finite decimal number") from exc
    if not amount.is_finite():
        raise ValueError("amount must be a finite decimal number")
    # Normalize equivalent representations (10, 10.0, 10.00) without
    # silently rounding or losing large decimal digits.
    return format(amount.normalize(), "f") if amount else "0"


def _normalize_time(value: Any) -> str:
    """Normalize supported timestamps; reject ambiguous fallback timestamps."""
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value or "").strip()
        if not text:
            raise ValueError("timestamp is required for fallback idempotency fingerprint")
        # Daraja's documented compact transaction-time representation has no
        # offset; keep it as a provider-format value rather than guessing UTC.
        if len(text) == 14 and text.isdigit():
            try:
                return datetime.strptime(text, "%Y%m%d%H%M%S").strftime("%Y%m%d%H%M%S")
            except ValueError as exc:
                raise ValueError("timestamp is not a valid YYYYMMDDHHMMSS value") from exc
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError("timestamp must be ISO-8601 or YYYYMMDDHHMMSS") from exc

    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("timestamp must include a timezone for fallback idempotency fingerprint")
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def _normalized_reference(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().casefold())


def derive_idempotency_key(payload: Dict[str, Any]) -> str:
    """Derive a deterministic provider-event key.

    A real provider transaction ID wins. Without one, require a finite amount,
    a valid timestamp, and either a reference or phone. The fallback includes
    available account/reference/phone/currency facts and uses Decimal, not float.
    It must not replace a database uniqueness constraint or payload-conflict
    classification: two legitimate payments can share the same fallback facts.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a mapping")

    trans_id = str(
        payload.get("TransID")
        or payload.get("trans_id")
        or payload.get("provider_transaction_id")
        or payload.get("transaction_id")
        or ""
    ).strip()
    if trans_id:
        return f"transid:{trans_id.upper()}"

    amount = _normalize_amount(payload.get("TransAmount", payload.get("amount")))
    trans_time = _normalize_time(
        payload.get("TransTime") or payload.get("trans_time") or payload.get("timestamp")
    )
    msisdn = _normalize_msisdn(
        payload.get("MSISDN") or payload.get("msisdn") or payload.get("phone_number")
    )
    reference = _normalized_reference(
        payload.get("BillRefNumber") or payload.get("reference") or payload.get("account_reference")
    )
    account = str(
        payload.get("provider_account_id")
        or payload.get("BusinessShortCode")
        or payload.get("business_short_code")
        or payload.get("account_id")
        or ""
    ).strip().casefold()
    currency = str(payload.get("Currency") or payload.get("currency") or "KES").strip().upper()

    if not (msisdn or reference):
        raise ValueError("fallback idempotency fingerprint requires a phone number or reference")
    if len(currency) != 3 or not currency.isalpha():
        raise ValueError("currency must be a three-letter code")

    canonical = {
        "account": account,
        "amount": amount,
        "currency": currency,
        "phone": msisdn,
        "reference": reference,
        "timestamp": trans_time,
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return f"hash:{digest}"
