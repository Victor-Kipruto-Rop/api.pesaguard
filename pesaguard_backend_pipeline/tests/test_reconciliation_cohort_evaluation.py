import pytest

from pesaguard_backend_pipeline.reconciliation_cohort_evaluation import (
    ALGORITHM_VERSION,
    evaluate_reconciliation_cohorts,
)


def _sample(tenant, provider, currency, amount, expected, predicted, decision):
    return {
        "tenant_id": tenant,
        "provider": provider,
        "currency": currency,
        "amount": amount,
        "expected_match_id": expected,
        "predicted_match_id": predicted,
        "decision": decision,
    }


def test_cohort_evaluation_keeps_tenants_separate_and_reports_metrics():
    rows = [
        _sample("tenant-a", "MPESA", "KES", "50", "ledger-1", "ledger-1", "MATCHED"),
        _sample("tenant-a", "mpesa", "kes", "150", "ledger-2", "wrong-ledger", "MATCHED"),
        _sample("tenant-b", "mpesa", "KES", "150", "ledger-3", "ledger-3", "MATCHED"),
        _sample("tenant-b", "mpesa", "KES", "150", None, None, "UNMATCHED"),
    ]
    result = evaluate_reconciliation_cohorts(rows, minimum_cohort_size=2)

    assert result["algorithm_version"] == ALGORITHM_VERSION
    assert result["cross_tenant_pooling"] is False
    assert result["sample_count"] == 4
    assert result["cohort_count"] == 3
    assert result["evaluated_cohort_count"] == 1
    assert result["insufficient_cohort_count"] == 2
    tenant_b = next(
        row for row in result["cohorts"]
        if row["cohort"]["tenant_id"] == "tenant-b"
    )
    assert tenant_b["status"] == "EVALUATED"
    assert tenant_b["metrics"]["true_positives"] == 1
    assert tenant_b["metrics"]["true_negatives"] == 1


def test_small_cohort_metrics_are_unavailable_not_zero():
    result = evaluate_reconciliation_cohorts(
        [_sample("tenant-a", "mpesa", "KES", "100", "l1", "l1", "MATCHED")],
        minimum_cohort_size=5,
    )
    assert result["cohorts"][0]["status"] == "INSUFFICIENT_SAMPLE"
    assert result["cohorts"][0]["metrics"] is None


def test_amount_bands_do_not_mix_currency_cohorts():
    rows = [
        _sample("t", "mpesa", "KES", "99.99", "l1", "l1", "MATCHED"),
        _sample("t", "mpesa", "KES", "100", "l2", "l2", "MATCHED"),
        _sample("t", "mpesa", "USD", "99.99", "l3", "l3", "MATCHED"),
    ]
    result = evaluate_reconciliation_cohorts(rows, minimum_cohort_size=1)
    assert result["cohort_count"] == 3
    assert {row["cohort"]["currency"] for row in result["cohorts"]} == {"KES", "USD"}
    assert {row["cohort"]["amount_band"] for row in result["cohorts"]} == {"lt_100", "100_to_lt_1000"}


@pytest.mark.parametrize("dimensions", [(), ("provider",), ("tenant_id", "tenant_id"), ("tenant_id", "email")])
def test_invalid_dimensions_fail_closed(dimensions):
    with pytest.raises(ValueError):
        evaluate_reconciliation_cohorts([], dimensions=dimensions)


@pytest.mark.parametrize("minimum", [0, -1, True, 1.5])
def test_invalid_minimum_sample_size_fails_closed(minimum):
    with pytest.raises(ValueError):
        evaluate_reconciliation_cohorts([], minimum_cohort_size=minimum)


def test_required_fields_and_decisions_are_validated():
    with pytest.raises(ValueError, match="missing required field"):
        evaluate_reconciliation_cohorts([{"tenant_id": "t"}])
    with pytest.raises(ValueError, match="unsupported decision"):
        evaluate_reconciliation_cohorts(
            [_sample("t", "mpesa", "KES", "1", None, None, "MAYBE")],
            minimum_cohort_size=1,
        )
