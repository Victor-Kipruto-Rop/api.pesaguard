from __future__ import annotations

import pytest

from pesaguard_backend_pipeline.risk_history_scope import resolve_risk_history_scope


def test_legacy_m_pesa_event_defaults_to_m_pesa_and_kes():
    assert resolve_risk_history_scope({"TransID": "tx-1"}) == ("mpesa", "KES")


def test_provider_and_currency_are_normalized_without_cross_provider_aliasing():
    assert resolve_risk_history_scope({
        "provider": "  Safaricom ",
        "currency": " kes ",
    }) == ("safaricom", "KES")


def test_provider_name_and_provider_currency_aliases_are_supported():
    assert resolve_risk_history_scope({
        "provider_name": "Airtel-Money",
        "Currency": "usd",
    }) == ("airtel-money", "USD")


def test_blank_scope_values_use_explicit_legacy_defaults():
    assert resolve_risk_history_scope({"provider": " ", "currency": " "}) == ("mpesa", "KES")


@pytest.mark.parametrize("event", [None, [], "transaction"])
def test_non_mapping_event_is_rejected(event):
    with pytest.raises(ValueError, match="event must be a mapping"):
        resolve_risk_history_scope(event)
