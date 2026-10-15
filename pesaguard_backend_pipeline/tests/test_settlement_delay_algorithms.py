import math

import pytest

from pesaguard_backend_pipeline.settlement_delay_algorithms import (
    ALGORITHM_VERSION,
    assess_settlement_delay,
)


SCOPE = {
    "tenant_id": "tenant-a",
    "provider": "mpesa",
    "account_id": "paybill-123",
    "currency": "KES",
}


def assess(current, history, **overrides):
    return assess_settlement_delay(current, history, **(SCOPE | overrides))


def test_insufficient_history_is_unknown_not_healthy():
    result = assess(1000, [100, 200, 300, 400])
    assert result["ready"] is False
    assert result["is_late"] is None
    assert result["action"] == "INSUFFICIENT_DATA"


def test_typical_settlement_delay_is_not_flagged():
    result = assess(900, [600, 610, 620, 630, 640, 650, 660, 670])
    assert result["ready"] is True
    assert result["is_late"] is False
    assert result["algorithm_version"] == ALGORITHM_VERSION


def test_extreme_settlement_delay_is_flagged_with_explanation():
    result = assess(20_000, [600, 610, 620, 630, 640, 650, 660, 670])
    assert result["ready"] is True
    assert result["is_late"] is True
    assert result["action"] == "INVESTIGATE_SETTLEMENT_DELAY"
    assert result["threshold_seconds"] is not None
    assert result["scope"]["tenant_id"] == "tenant-a"


def test_invalid_history_is_counted_and_excluded():
    result = assess(800, [600, 610, None, "NaN", math.inf, -1, 620, 630, 640, 650, 660, 670])
    assert result["ready"] is True
    assert result["invalid_history_count"] == 4
    assert result["sample_count"] == 8


@pytest.mark.parametrize("bad", [None, -1, True, "NaN", math.inf, "bad"])
def test_invalid_current_delay_fails_closed(bad):
    with pytest.raises(ValueError, match="current_delay_seconds"):
        assess(bad, [600, 610, 620, 630, 640, 650, 660, 670])


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"tenant_id": ""}, "tenant_id"),
        ({"provider": ""}, "provider"),
        ({"account_id": ""}, "account_id"),
        ({"currency": ""}, "currency"),
        ({"minimum_samples": 4}, "minimum_samples"),
        ({"upper_quantile": 1.0}, "upper_quantile"),
        ({"minimum_grace_seconds": -1}, "minimum_grace_seconds"),
        ({"robust_mad_multiplier": 0}, "robust_mad_multiplier"),
    ],
)
def test_invalid_scope_or_configuration_is_rejected(kwargs, message):
    with pytest.raises(ValueError, match=message):
        assess(100, [1, 2, 3, 4, 5, 6, 7, 8], **kwargs)


def test_scope_is_normalized_without_merging_tenants():
    result = assess(100, [1, 2, 3, 4, 5, 6, 7, 8], provider="MPESA", currency="kes")
    assert result["scope"]["provider"] == "mpesa"
    assert result["scope"]["currency"] == "KES"
    assert result["scope"]["tenant_id"] == "tenant-a"


def test_configuration_rejects_non_finite_thresholds():
    with pytest.raises(ValueError):
        assess(100, list(range(8)), minimum_grace_seconds=math.nan)
    with pytest.raises(ValueError):
        assess(100, list(range(8)), robust_mad_multiplier=math.inf)
    with pytest.raises(ValueError, match="upper_quantile"):
        assess(100, list(range(8)), upper_quantile="NaN")
    with pytest.raises(ValueError, match="minimum_grace_seconds"):
        assess(100, list(range(8)), minimum_grace_seconds="not-a-number")
    with pytest.raises(ValueError, match="robust_mad_multiplier"):
        assess(100, list(range(8)), robust_mad_multiplier="Infinity")
