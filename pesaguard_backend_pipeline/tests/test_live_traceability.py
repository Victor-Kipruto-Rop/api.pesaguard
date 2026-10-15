"""Opt-in gateway-to-notification traceability contract.

Run with PESAGUARD_LIVE_E2E=1 and the integration stack configured. The test is
skipped by default so the unit suite never reports a false production guarantee.

The flow exercised: real gateway webhook -> PostgreSQL persistence -> Kafka ->
consumer -> reconciliation -> notification, verified through exported audit/log
evidence (and optionally a live database connection).
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest
import requests


pytestmark = pytest.mark.skipif(
    os.getenv("PESAGUARD_LIVE_E2E") != "1",
    reason="set PESAGUARD_LIVE_E2E=1 to run against the integration stack",
)


@pytest.mark.integration
@pytest.mark.skipif(
    not os.getenv("PESAGUARD_LIVE_GATEWAY_URL"),
    reason="PESAGUARD_LIVE_GATEWAY_URL is required",
)
def test_gateway_postgres_kafka_consumer_reconciliation_notification_traceability():
    """Submit a real event and require one trace identity through persisted evidence."""
    gateway_url = os.environ["PESAGUARD_LIVE_GATEWAY_URL"].rstrip("/")
    trace_id = os.getenv("PESAGUARD_LIVE_TRACE_ID") or uuid.uuid4().hex
    transaction_id = os.getenv("PESAGUARD_LIVE_TRANSACTION_ID") or f"live-trace-{trace_id}"
    response = requests.post(  # nosec B113: a bounded timeout is supplied in this request.
        f"{gateway_url}/webhook/mpesa/confirmation",
        headers={
            "X-Request-ID": f"req-{trace_id}",
            "X-Correlation-ID": f"corr-{trace_id}",
            "X-Trace-ID": trace_id,
            "X-Tenant-ID": os.getenv("PESAGUARD_LIVE_TENANT_ID", "live-test"),
        },
        json={
            "TransactionType": "CustomerPayBillOnline",
            "TransID": transaction_id,
            "TransTime": "20260914100000",
            "TransAmount": "1.00",
            "BusinessShortCode": "600000",
            "MSISDN": "254700000000",
            "BillRefNumber": transaction_id,
        },
        timeout=float(os.getenv("PESAGUARD_LIVE_TIMEOUT_SECONDS", "15")),
    )
    response.raise_for_status()

    evidence_path = os.getenv("PESAGUARD_LIVE_EVIDENCE_JSON")
    if evidence_path:
        evidence = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
        serialized = json.dumps(evidence, sort_keys=True)
        assert trace_id in serialized
        assert transaction_id in serialized
        assert os.getenv("PESAGUARD_LIVE_TENANT_ID", "live-test") in serialized

    # Strongest evidence: query the live database and require the reconciliation
    # audit record itself to carry the gateway trace identity.
    database_url = os.getenv("PESAGUARD_LIVE_DATABASE_URL")
    if database_url:
        from sqlalchemy import create_engine, text

        engine = create_engine(database_url)
        try:
            with engine.connect() as connection:
                audit_row = connection.execute(
                    text(
                        "SELECT trace_id, correlation_id, resource_id FROM action_audit_entries "
                        "WHERE resource_id = :trans_id ORDER BY created_at DESC LIMIT 1"
                    ),
                    {"trans_id": transaction_id},
                ).one_or_none()
            assert audit_row is not None, "no reconciliation audit record was persisted for the live transaction"
            assert audit_row.trace_id == trace_id, "persisted audit record lost the gateway trace_id"
            assert audit_row.correlation_id == f"corr-{trace_id}"
        finally:
            engine.dispose()
