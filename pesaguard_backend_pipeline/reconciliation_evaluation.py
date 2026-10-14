"""Offline evaluation metrics for reconciliation decisions.

This module evaluates final decisions against reviewed ground truth. It does not
change payment processing, and deliberately does not interpret ranking scores as
probabilities. Inputs must be curated and tenant-scoped by the caller.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

_AUTO_MATCH_DECISIONS = frozenset({"MATCHED", "AUTO_MATCH", "AUTO_MATCHED"})
_REVIEW_DECISIONS = frozenset({"REVIEW", "NEEDS_REVIEW", "AMBIGUOUS", "EXCEPTION"})
_UNMATCHED_DECISIONS = frozenset({"UNMATCHED", "MISSING_PAYMENT", "NO_MATCH"})


def _identifier(value: Any, *, field: str, row_number: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (str, int)):
        raise ValueError(f"sample {row_number}: {field} must be a string, integer, or None")
    normalized = str(value).strip()
    return normalized or None


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _metrics(*, tp: int, fp: int, fn: int, tn: int, review: int, unmatched: int, total: int) -> dict[str, Any]:
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and precision + recall:
        f1 = round(2 * precision * recall / (precision + recall), 6)
    return {
        "evaluated": total > 0,
        "sample_count": total,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": _ratio(tn, tn + fp),
        "false_positive_rate": _ratio(fp, fp + tn),
        "exact_decision_accuracy": _ratio(tp + tn, total),
        "automatic_match_coverage": _ratio(tp + fp, total),
        "review_rate": _ratio(review, total),
        "unmatched_rate": _ratio(unmatched, total),
        "interpretation": (
            "Metrics describe this labeled sample only; validate representativeness before changing policy."
            if total else "No labeled samples; metrics are unavailable, not zero."
        ),
    }


def evaluate_reconciliation_predictions(
    samples: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Evaluate final auto-match decisions against reviewed ground truth.

    Each sample must contain expected_match_id (adjudicated ledger ID or None),
    predicted_match_id (record actually auto-matched or None), and decision.
    Candidate suggestions in review cases must not be placed in predicted_match_id.

    A wrong auto-match counts as a false positive; when a true match existed it
    also counts as a false negative. Review is not counted as a correct match.
    Missing required keys are rejected rather than silently treated as negatives.
    """
    tp = fp = fn = tn = review = unmatched = total = 0
    for row_number, sample in enumerate(samples, start=1):
        if not isinstance(sample, Mapping):
            raise ValueError(f"sample {row_number}: each sample must be a mapping")
        for key in ("expected_match_id", "predicted_match_id", "decision"):
            if key not in sample:
                raise ValueError(f"sample {row_number}: missing required field {key}")

        expected = _identifier(sample["expected_match_id"], field="expected_match_id", row_number=row_number)
        predicted = _identifier(sample["predicted_match_id"], field="predicted_match_id", row_number=row_number)
        decision = str(sample["decision"] or "").strip().upper().replace("-", "_").replace(" ", "_")
        if decision not in _AUTO_MATCH_DECISIONS | _REVIEW_DECISIONS | _UNMATCHED_DECISIONS:
            raise ValueError(f"sample {row_number}: unsupported decision {decision!r}")
        if decision in _AUTO_MATCH_DECISIONS and predicted is None:
            raise ValueError(f"sample {row_number}: auto-match decision requires predicted_match_id")

        total += 1
        if decision in _REVIEW_DECISIONS:
            review += 1
        if decision in _UNMATCHED_DECISIONS:
            unmatched += 1

        automatic_prediction = decision in _AUTO_MATCH_DECISIONS and predicted is not None
        if automatic_prediction:
            if expected is not None and predicted == expected:
                tp += 1
            else:
                fp += 1
                if expected is not None:
                    fn += 1
        elif expected is not None:
            fn += 1
        else:
            tn += 1

    return {
        "metric_version": "reconciliation-evaluation-v1",
        **_metrics(tp=tp, fp=fp, fn=fn, tn=tn, review=review, unmatched=unmatched, total=total),
    }
