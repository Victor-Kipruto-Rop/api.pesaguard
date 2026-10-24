"""Tests for authenticated tenant context in provenance processing."""

import pytest

from provenance import DataProvenance, ProvenanceError


def _payload(**overrides):
    payload = {
        "event_id": "event-trusted-001",
        "transaction_id": "tx-trusted-001",
        "provider": "mpesa",
        "amount": "125.00",
        "currency": "KES",
        "reference": "REF-TRUSTED-001",
        "schema_version": "1.0",
    }
    payload.update(overrides)
    return payload


def test_trusted_tenant_context_supplies_missing_payload_tenant():
    result = DataProvenance().evaluate(
        _payload(),
        trusted_tenant_id="tenant-from-authenticated-config",
    )

    assert result.tenant_id == "tenant-from-authenticated-config"


def test_trusted_tenant_context_rejects_conflicting_payload_tenant():
    with pytest.raises(ProvenanceError, match="does not match authenticated tenant"):
        DataProvenance().evaluate(
            _payload(tenant_id="tenant-attacker-controlled"),
            trusted_tenant_id="tenant-from-authenticated-config",
        )


@pytest.mark.parametrize("trusted_tenant_id", ["", " ", "unknown", "UNKNOWN"])
def test_trusted_tenant_context_rejects_empty_or_placeholder_ids(trusted_tenant_id):
    with pytest.raises(ProvenanceError, match="trusted tenant_id must be"):
        DataProvenance().evaluate(
            _payload(),
            trusted_tenant_id=trusted_tenant_id,
        )


def test_trusted_tenant_context_is_used_for_lineage():
    result = DataProvenance().evaluate(
        _payload(),
        trusted_tenant_id="tenant-configured",
    )

    assert result.tenant_id == "tenant-configured"
    assert result.lineage_snapshot["tenant_id"] == "tenant-configured"
