"""Conservative release gate for reconciliation algorithm changes.

The gate evaluates offline, reviewed holdout metrics only. It does not activate
features, deploy code, or change payment decisions. A PASS means the supplied
scorecard meets this policy; it is not a guarantee of production safety.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Mapping


GATE_VERSION = "reconciliation-release-gate-v1"
_RATIO_METRICS = ("precision", "recall", "false_positive_rate", "review_rate")


@dataclass(frozen=True)
class ReleaseGatePolicy:
    """Explicit, reviewable acceptance thresholds for an algorithm release."""

    minimum_sample_count: int = 200
    minimum_precision: float = 0.995
    minimum_recall: float = 0.90
    maximum_false_positive_rate: float = 0.005
    maximum_review_rate: float = 0.50

    def __post_init__(self) -> None:
        if isinstance(self.minimum_sample_count, bool) or self.minimum_sample_count < 1:
            raise ValueError("minimum_sample_count must be a positive integer")
        if not isinstance(self.minimum_sample_count, int):
            raise ValueError("minimum_sample_count must be a positive integer")
        for name in _RATIO_METRICS:
            value = getattr(self, {
                "precision": "minimum_precision",
                "recall": "minimum_recall",
                "false_positive_rate": "maximum_false_positive_rate",
                "review_rate": "maximum_review_rate",
            }[name])
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} threshold must be numeric")
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"{name} threshold must be finite and between 0 and 1")


def evaluate_reconciliation_release_gate(
    metrics: Mapping[str, Any],
    *,
    policy: ReleaseGatePolicy | None = None,
    dataset_version: str = "",
    is_holdout: bool = False,
    reviewed_by: str = "",
) -> dict[str, Any]:
    """Return a deterministic PASS/BLOCKED result with machine-readable reasons.

    Required provenance is intentionally explicit. Empty datasets, unavailable
    metrics, non-holdout evaluation, missing dataset version, and missing reviewer
    all block promotion rather than being interpreted as successful performance.
    """
    if not isinstance(metrics, Mapping):
        raise ValueError("metrics must be a mapping")
    policy = policy or ReleaseGatePolicy()
    reasons: list[str] = []

    sample_count = metrics.get("sample_count")
    if isinstance(sample_count, bool) or not isinstance(sample_count, int) or sample_count < 0:
        reasons.append("invalid_sample_count")
        sample_count = 0
    if metrics.get("evaluated") is not True or sample_count == 0:
        reasons.append("evaluation_unavailable")
    if sample_count < policy.minimum_sample_count:
        reasons.append("insufficient_holdout_samples")
    if is_holdout is not True:
        reasons.append("holdout_dataset_required")
    if not str(dataset_version or "").strip():
        reasons.append("dataset_version_required")
    if not str(reviewed_by or "").strip():
        reasons.append("human_reviewer_required")

    observed: dict[str, float | None] = {}
    threshold_map = {
        "precision": ("minimum_precision", "min"),
        "recall": ("minimum_recall", "min"),
        "false_positive_rate": ("maximum_false_positive_rate", "max"),
        "review_rate": ("maximum_review_rate", "max"),
    }
    for metric_name, (policy_name, direction) in threshold_map.items():
        value = metrics.get(metric_name)
        if value is None:
            observed[metric_name] = None
            reasons.append(f"metric_unavailable:{metric_name}")
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
            observed[metric_name] = None
            reasons.append(f"metric_invalid:{metric_name}")
            continue
        observed[metric_name] = float(value)
        threshold = getattr(policy, policy_name)
        failed = value < threshold if direction == "min" else value > threshold
        if failed:
            reasons.append(f"threshold_failed:{metric_name}")

    # Stable order and de-duplication make output safe for snapshots and audit logs.
    reason_codes = list(dict.fromkeys(reasons))
    return {
        "gate_version": GATE_VERSION,
        "status": "PASS" if not reason_codes else "BLOCKED",
        "promotion_eligible": not reason_codes,
        "reason_codes": reason_codes,
        "sample_count": sample_count,
        "dataset_version": str(dataset_version or "").strip() or None,
        "is_holdout": is_holdout is True,
        "reviewed_by": str(reviewed_by or "").strip() or None,
        "observed_metrics": observed,
        "thresholds": {
            "minimum_sample_count": policy.minimum_sample_count,
            "minimum_precision": policy.minimum_precision,
            "minimum_recall": policy.minimum_recall,
            "maximum_false_positive_rate": policy.maximum_false_positive_rate,
            "maximum_review_rate": policy.maximum_review_rate,
        },
        "note": "PASS applies only to the supplied reviewed holdout scorecard; it does not authorize automatic deployment.",
    }
