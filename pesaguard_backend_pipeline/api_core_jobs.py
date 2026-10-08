"""RQ task entry points for the versioned core API."""

from __future__ import annotations

from typing import Any


def process_reconciliation_request(tenant_id: str, transaction_id: str) -> dict[str, Any]:
    """Process a stored tenant transaction through the canonical reconciliation worker."""
    import reconciliation_job
    from base_connector import ConnectorRegistry
    from models import Transaction

    session = reconciliation_job.AuditSession()
    try:
        transaction = session.query(Transaction).filter(
            Transaction.id == transaction_id,
            Transaction.tenant_id == tenant_id,
        ).one_or_none()
        if transaction is None:
            return {"status": "not_found", "transaction_id": transaction_id}

        payload = dict(transaction.raw_payload or {})
        payload.update({
            "TransID": transaction.trans_id,
            "TransAmount": str(transaction.trans_amount),
            "Currency": transaction.currency,
            "MSISDN": transaction.msisdn,
            "BusinessShortCode": transaction.business_short_code,
            "TransTime": transaction.trans_time,
            "provider": transaction.provider,
            "provider_account_id": transaction.provider_account_id,
            "tenant_id": tenant_id,
        })
    finally:
        session.close()

    processed = reconciliation_job._process_message_unbounded(
        payload,
        consumer=None,
        producer=None,
        connector_registry=ConnectorRegistry.from_env(),
    )
    return {
        "status": "completed" if processed else "retryable_failure",
        "transaction_id": transaction_id,
    }
