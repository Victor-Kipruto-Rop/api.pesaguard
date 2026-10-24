"""Tenant-isolation regression tests for provenance processing."""

import pytest

from provenance import DataProvenance, ProvenanceError


@pytest.mark.parametrize(
    "payload",
    [
        {"transaction_id": "tx-001", "provider": "mpesa"},
        {"transaction_id": "tx-001", "tenant_id": ""},
        {"transaction_id": "tx-001", "tenant_id": "   "},
        {"transaction_id": "tx-001", "tenant_id": "unknown"},
    ],
)
def test_evaluate_rejects_missing_or_placeholder_tenant(payload):
    """Unscoped records must not enter a tenant-isolated processing path."""
    with pytest.raises(ProvenanceError, match="tenant_id is required"):
        DataProvenance().evaluate(payload)


def test_evaluate_accepts_explicit_tenant_identity():
    """An explicit tenant reaches quality evaluation with scoped lineage."""
    payload = {
        "event_id": "event-001",
        "transaction_id": "tx-001",
        "tenant_id": "tenant-001",
        "provider": "mpesa",
        "amount": "125.00",
        "currency": "KES",
        "reference": "REF-001",
    }

    result = DataProvenance().evaluate(payload)

    assert result.tenant_id == "tenant-001"
    assert result.transaction_id == "tx-001"
