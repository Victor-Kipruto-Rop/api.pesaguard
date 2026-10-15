"""Canonical provider/currency scope for transaction-risk history.

Risk features are only comparable across transactions from the same tenant,
provider, provider account, and currency. Tenant/account filtering belongs to
the database query; this helper resolves the remaining dimensions from the
incoming event and preserves legacy M-Pesa/KES defaults when fields are absent.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def resolve_risk_history_scope(event: Mapping[str, Any]) -> tuple[str, str]:
    """Return normalized (provider, currency) values for scoped history queries.

    Explicit values are normalized but not silently remapped between providers.
    Unknown providers/currencies therefore produce an exact query scope rather
    than broadening the baseline to unrelated transactions.
    """
    if not isinstance(event, Mapping):
        raise ValueError("event must be a mapping")

    provider_value = event.get("provider") or event.get("provider_name") or "mpesa"
    currency_value = event.get("currency") or event.get("Currency") or "KES"

    provider = str(provider_value).strip().casefold()
    currency = str(currency_value).strip().upper()
    if not provider:
        provider = "mpesa"
    if not currency:
        currency = "KES"

    return provider, currency
