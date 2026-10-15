"""Cohort-level evaluation for reconciliation decision policies.

This offline utility prevents aggregate metrics from hiding weak performance for a
specific tenant/provider/currency/amount cohort. It does not alter live decisions.
Inputs must be reviewed ground-truth labels, tenant-scoped, privacy-controlled,
and separated from training/tuning data when used as a holdout.
"""
from __future__ import annotations

from collections import defaultdict
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping

try:
    from .reconciliation_evaluation import evaluate_reconciliation_predictions
except ImportError:  # pragma: no cover - top-level script execution
    from reconciliation_evaluation import evaluate_reconciliation_predictions

ALGORITHM_VERSION = "reconciliation-cohort-evaluation-v1"
DEFAULT_MINIMUM_COHORT_SIZE = 20
_ALLOWED_DIMENSIONS = frozenset({"tenant_id", "provider", "currency", "amount_band"})


def _label(value: Any, field: str, row_number: int) -> str:
    if value is None:
        raise ValueError(f"sample {row_number}: {field} is required")
    normalized = str(value).strip()
    if not normalized:
        raise ValueError(f"sample {row_number}: {field} is required")
    return normalized


def _amount_band(value: Any, row_number: int) -> str:
    if isinstance(value, bool) or value is None:
        return "unknown"
    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError):
        return "unknown"
    if not amount.is_finite() or amount < 0:
        return "unknown"
    if amount < Decimal("100"):
        return "lt_100"
    if amount < Decimal("1000"):
        return "100_to_lt_1000"
    if amount < Decimal("10000"):
        return "1000_to_lt_10000"
    return "gte_10000"


def evaluate_reconciliation_cohorts(
    samples: Iterable[Mapping[str, Any]],
    *,
    dimensions: tuple[str, ...] = ("tenant_id", "provider", "currency", "amount_band"),
    minimum_cohort_size: int = DEFAULT_MINIMUM_COHORT_SIZE,
) -> dict[str, Any]:
    """Compute the existing scorecard separately for each supported cohort.

    Required row fields: tenant_id, provider, currency, amount, expected_match_id,
    predicted_match_id, and decision. Tenant is included by default to prevent
    accidental cross-tenant pooling. Cohorts below the configured minimum are
    marked insufficient; their metrics are not calculated or presented as zero.
    The caller must provide an approved, tenant-authorized holdout dataset.
    """
    if isinstance(minimum_cohort_size, bool) or not isinstance(minimum_cohort_size, int) or minimum_cohort_size < 1:
        raise ValueError("minimum_cohort_size must be a positive integer")
    if not isinstance(dimensions, tuple) or not dimensions:
        raise ValueError("dimensions must be a non-empty tuple")
    if len(set(dimensions)) != len(dimensions):
        raise ValueError("dimensions must not contain duplicates")
    unknown = set(dimensions) - _ALLOWED_DIMENSIONS
    if unknown:
        raise ValueError(f"unsupported cohort dimensions: {sorted(unknown)}")
    if "tenant_id" not in dimensions:
        raise ValueError("tenant_id must remain a cohort dimension; cross-tenant pooling is not supported")

    cohorts: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    total = 0
    invalid_amount_count = 0
    for row_number, sample in enumerate(samples, start=1):
        if not isinstance(sample, Mapping):
            raise ValueError(f"sample {row_number}: each sample must be a mapping")
        for required in ("tenant_id", "provider", "currency", "amount", "expected_match_id", "predicted_match_id", "decision"):
            if required not in sample:
                raise ValueError(f"sample {row_number}: missing required field {required}")
        values = {
            "tenant_id": _label(sample["tenant_id"], "tenant_id", row_number),
            "provider": _label(sample["provider"], "provider", row_number).casefold(),
            "currency": _label(sample["currency"], "currency", row_number).upper(),
            "amount_band": _amount_band(sample["amount"], row_number),
        }
        if values["amount_band"] == "unknown":
            invalid_amount_count += 1
        key = tuple(values[dimension] for dimension in dimensions)
        cohorts[key].append({
            "expected_match_id": sample["expected_match_id"],
            "predicted_match_id": sample["predicted_match_id"],
            "decision": sample["decision"],
        })
        total += 1

    results = []
    for key in sorted(cohorts):
        rows = cohorts[key]
        cohort = dict(zip(dimensions, key))
        item: dict[str, Any] = {
            "cohort": cohort,
            "sample_count": len(rows),
            "eligible_for_metric_review": len(rows) >= minimum_cohort_size,
        }
        if len(rows) < minimum_cohort_size:
            item.update({
                "status": "INSUFFICIENT_SAMPLE",
                "metrics": None,
                "reason": "cohort_below_minimum_sample_size",
            })
        else:
            item.update({
                "status": "EVALUATED",
                "metrics": evaluate_reconciliation_predictions(rows),
                "reason": None,
            })
        results.append(item)

    evaluated = [item for item in results if item["status"] == "EVALUATED"]
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "evaluated": total > 0,
        "sample_count": total,
        "cohort_count": len(results),
        "evaluated_cohort_count": len(evaluated),
        "insufficient_cohort_count": len(results) - len(evaluated),
        "invalid_or_unknown_amount_count": invalid_amount_count,
        "minimum_cohort_size": minimum_cohort_size,
        "dimensions": list(dimensions),
        "cross_tenant_pooling": False,
        "cohorts": results,
        "interpretation": (
            "Cohort metrics describe only the supplied reviewed labels. They are not a production approval; "
            "investigate small samples, false positives, data leakage, and representativeness before changing policy."
            if total else "No labeled samples; metrics are unavailable, not zero."
        ),
    }
