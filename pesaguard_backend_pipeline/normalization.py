"""Deterministic normalization rules for provider data."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping
from zoneinfo import ZoneInfo


class NormalizationError(ValueError):
    """Raised when a provider value cannot be normalized safely."""


def normalize_amount(value: Any) -> str:
    try:
        amount = Decimal(str(value).replace(",", "").strip())
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise NormalizationError("amount must be a valid decimal") from exc
    if not amount.is_finite():
        raise NormalizationError("amount must be finite")
    try:
        normalized = amount.quantize(Decimal("0.01"))
    except InvalidOperation as exc:
        raise NormalizationError("amount exceeds the supported transaction precision") from exc
    if amount <= 0:
        raise NormalizationError("amount must be greater than zero")
    if amount != normalized:
        raise NormalizationError("amount must not have fractions smaller than one minor unit")
    if normalized >= Decimal("10000000000000000"):
        raise NormalizationError("amount exceeds the supported transaction precision")
    return f"{normalized:.2f}"


def normalize_timestamp(value: Any, *, default_timezone: str = "Africa/Nairobi") -> str:
    text = str(value or "").strip()
    if not text:
        raise NormalizationError("timestamp is required")
    text = re.sub(r"\s+(EAT|UTC)$", lambda match: " +03:00" if match.group(1) == "EAT" else " +00:00", text, flags=re.IGNORECASE)
    parsed = None
    for candidate in (text, text.replace("Z", "+00:00")):
        try:
            parsed = datetime.fromisoformat(candidate)
            break
        except ValueError:
            continue
    if parsed is None:
        for pattern in ("%Y%m%d%H%M%S", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(text, pattern)
                break
            except ValueError:
                continue
    if parsed is None:
        raise NormalizationError("timestamp must be ISO-8601 or a supported provider timestamp")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=ZoneInfo(default_timezone))
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_currency(value: Any, *, default: str = "KES") -> str:
    aliases = {
        "KSH": "KES",
        "KSHS": "KES",
        "KENYAN SHILLING": "KES",
        "US DOLLAR": "USD",
        "$": "USD",
    }
    currency = str(value or default).strip().upper()
    currency = aliases.get(currency, currency)
    if len(currency) != 3 or not currency.isalpha():
        raise NormalizationError("currency must be a three-letter ISO code")
    return currency


def normalize_phone(value: Any, *, default_country_code: str = "254") -> str:
    text = str(value or "").strip()
    if text.lower() in {"", "unknown", "n/a", "none"}:
        return "unknown"
    digits = re.sub(r"\D", "", text)
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith("0"):
        digits = default_country_code + digits[1:]
    if not re.fullmatch(r"\d{10,15}", digits):
        raise NormalizationError("phone number must contain 10 to 15 digits")
    return f"+{digits}"


def normalize_provider(value: Any) -> str:
    provider = re.sub(r"[^a-z0-9]+", " ", str(value or "").strip().lower()).strip()
    aliases = {
        "mpesa": "mpesa",
        "m pesa": "mpesa",
        "safaricom": "safaricom",
        "airtel": "airtel-money",
        "airtel money": "airtel-money",
        "t kash": "t-kash",
    }
    normalized = aliases.get(provider, provider.replace(" ", "-"))
    if not normalized:
        raise NormalizationError("provider is required")
    return normalized


def normalize_transaction_type(value: Any) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", str(value or "PAYMENT").strip().lower()).strip("_")
    aliases = {"pay_bill": "PAYMENT", "c2b": "PAYMENT", "stk_push": "PAYMENT", "credit": "PAYMENT", "debit": "PAYOUT"}
    return aliases.get(text, text.upper() or "PAYMENT")


def normalize_status(value: Any) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", str(value or "RECEIVED").strip().lower()).strip("_")
    aliases = {"success": "COMPLETED", "successful": "COMPLETED", "pending": "PENDING", "failed": "FAILED", "reversed": "REVERSED"}
    return aliases.get(text, text.upper() or "RECEIVED")


def normalize_identifier(value: Any) -> str:
    identifier = re.sub(r"\s+", "", str(value or "")).strip()
    if not identifier:
        raise NormalizationError("identifier is required")
    return identifier.upper()


def normalize_location(value: Any) -> Dict[str, str]:
    if isinstance(value, Mapping):
        return {
            key: str(item).strip().upper() if key in {"country", "country_code", "region"} else str(item).strip()
            for key, item in value.items()
            if item is not None and str(item).strip()
        }
    text = str(value or "").strip()
    return {"value": text} if text else {}