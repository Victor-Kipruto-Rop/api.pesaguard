from datetime import datetime, timezone

import pytest

from algorithm_evidence_pipeline import evaluate_algorithmic_evidence

NOW = datetime(2026, 10, 15, 0, 0, tzinfo=timezone.utc)
SCOPE = {"tenant_id": "tenant-a", "provider": "mpesa", "provider_account_id": "paybill-1", "currency": "KES"}


def transaction(**extra):
    return {"transaction_id": "TX-1", "reference": "INV-1", "amount": "100.00",
            "timestamp": "2026-10-15T03:00:00+03:00", **extra}


def scoped_record(**extra):
    return {**SCOPE, "internal_ref": "ledger-1", "reference": "INV-1", "amount": "100.00",
            "timestamp": "2026-10-15T03:00:00+03:00", **extra}


def test_returns_advisory_evidence_and_never_financial_action():
    result = evaluate_algorithmic_evidence(transaction(), [scoped_record()], scope=SCOPE, now=NOW)
    assert result["mode"] == "advisory"
    assert result["scope_complete"] is True
    assert result["candidate_ranking"]["top_candidate"]["candidate_id"] == "ledger-1"
    assert result["automatic_financial_action"] is False
    assert result["requires_existing_policy_and_ledger_validation"] is True
    assert result["risk"]["is_probability"] is False


def test_excludes_cross_tenant_and_missing_scope_candidates():
    result = evaluate_algorithmic_evidence(
        transaction(),
        [scoped_record(tenant_id="tenant-b", internal_ref="cross-tenant"),
         {"internal_ref": "missing-scope", "reference": "INV-1", "amount": "100"}],
        scope=SCOPE, now=NOW,
    )
    assert result["candidate_ranking"]["top_candidate"] is None
    assert result["candidate_ranking"]["decision"] == "REVIEW"
    assert result["scope_exclusions"]["candidate_count"] == 2


def test_scope_is_required_and_trusted_context_is_explicit():
    with pytest.raises(ValueError, match="scope.tenant_id"):
        evaluate_algorithmic_evidence(transaction(), [], scope={"provider": "mpesa"})


def test_naive_clock_is_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate_algorithmic_evidence(transaction(), [], scope=SCOPE, now=datetime(2026, 10, 15))


def test_invalid_payload_produces_review_signal_without_auto_decline():
    result = evaluate_algorithmic_evidence(transaction(amount="-1"), [], scope=SCOPE, now=NOW)
    assert result["quality"]["valid_for_automatic_matching"] is False
    assert result["risk"]["action"] == "REVIEW"
    assert result["automatic_financial_action"] is False


def test_seasonal_baseline_uses_only_matching_explicit_scope():
    history = []
    timestamps = [
        "2026-08-20T03:00:00+03:00", "2026-08-27T03:00:00+03:00",
        "2026-09-03T03:00:00+03:00", "2026-09-10T03:00:00+03:00",
        "2026-09-17T03:00:00+03:00", "2026-09-24T03:00:00+03:00",
        "2026-10-01T03:00:00+03:00", "2026-10-08T03:00:00+03:00",
    ]
    for index, timestamp in enumerate(timestamps):
        history.append(scoped_record(
            internal_ref=f"h-{index}", amount="100", timestamp=timestamp,
        ))
    history.append(scoped_record(tenant_id="tenant-b", amount="999999", internal_ref="other-tenant"))
    result = evaluate_algorithmic_evidence(
        transaction(amount="10000"), [scoped_record()], scope=SCOPE,
        amount_history=history, now=NOW,
    )
    assert result["seasonal_amount"]["ready"] is True
    assert result["seasonal_amount"]["sample_count"] == 8
    assert result["scope_exclusions"]["amount_history_rows"] == 1
    assert result["risk"]["action"] == "REVIEW"


def test_velocity_only_counts_scoped_matching_entity():
    history = [
        {**SCOPE, "entity_key": "entity-hash", "timestamp": "2026-10-15T02:59:00+03:00"}
        for _ in range(6)
    ]
    history.append({**SCOPE, "tenant_id": "tenant-b", "entity_key": "entity-hash",
                    "timestamp": "2026-10-15T02:59:00+03:00"})
    result = evaluate_algorithmic_evidence(
        transaction(), [], scope=SCOPE, velocity_history=history, entity_key="entity-hash",
        velocity_max_events=5, now=NOW,
    )
    assert result["velocity"]["breach"] is True
    assert result["velocity"]["count"] == 6
    assert result["scope_exclusions"]["velocity_history_rows"] == 1


def test_currency_normalizes_but_account_scope_remains_exact():
    result = evaluate_algorithmic_evidence(
        transaction(),
        [scoped_record(currency="kes", provider="MPESA", provider_account_id="paybill-2")],
        scope=SCOPE, now=NOW,
    )
    assert result["candidate_ranking"]["top_candidate"] is None
    assert result["scope_exclusions"]["candidate_count"] == 1


def test_empty_or_insufficient_history_is_unknown_not_normal():
    result = evaluate_algorithmic_evidence(transaction(), [], scope=SCOPE, now=NOW)
    assert result["seasonal_amount"]["ready"] is False
    assert result["seasonal_amount"]["is_outlier"] is None
    assert result["velocity"]["ready"] is False



def test_reconciliation_shadow_hook_exposes_scope_aware_evidence_without_changing_legacy_status():
    from reconciliation_engine import evaluate_transaction

    event = {
        "TransID": "TX-SHADOW-SCOPE",
        "TransAmount": "100.00",
        "MSISDN": "254700000000",
        "TransTime": "20261015030000",
        "BillRefNumber": "INV-SCOPE",
        "provider": "mpesa",
        "provider_account_id": "paybill-1",
        "currency": "KES",
    }
    record = {
        **SCOPE,
        "internal_ref": "ledger-scope",
        "reference": "INV-SCOPE",
        "amount": "100.00",
        "phone_number": "254700000000",
        "timestamp": "2026-10-15T03:00:00+03:00",
    }
    result = evaluate_transaction(
        event,
        [record],
        seen_trans_ids=set(),
        tenant_settings={
            "tenant_id": "tenant-a",
            "reconciliation": {"smart_algorithms_shadow_enabled": True},
        },
    )
    assert result["status"] == "matched"
    evidence = result["smart_analysis"]["scope_aware_evidence"]
    assert evidence["mode"] == "advisory"
    assert evidence["scope_complete"] is True
    assert evidence["automatic_financial_action"] is False
    assert result["smart_analysis"]["legacy_decision_unchanged"] is True
