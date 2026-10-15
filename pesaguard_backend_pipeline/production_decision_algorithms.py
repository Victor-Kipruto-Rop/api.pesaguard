"""Production decision safeguards for PesaGuard's algorithmic pipeline.

Pure, deterministic helpers. These functions emit proposals and review signals only;
they do not mutate balances, approve refunds, or post ledger entries. Callers must
enforce tenant scoping and persist decisions with the transaction that consumes them.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import math
import statistics
from typing import Any, Iterable, Mapping, Sequence

ALGORITHM_VERSION = "production-decision-v1"
_ALLOWED_STATES = {
    "PENDING": {"CONFIRMED", "FAILED", "CANCELLED", "EXPIRED"},
    "CONFIRMED": {"REVERSED", "PARTIALLY_REVERSED"},
    "PARTIALLY_REVERSED": {"REVERSED"},
    "FAILED": set(),
    "CANCELLED": set(),
    "EXPIRED": set(),
    "REVERSED": set(),
}


def _decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        result = Decimal(str(value).strip())
    except (InvalidOperation, TypeError, ValueError):
        return None
    return result if result.is_finite() else None


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def classify_settlement_variance(
    expected_amount: Any,
    settled_amount: Any,
    *,
    currency: str,
    expected_currency: str | None = None,
    settled_currency: str | None = None,
    tolerance: Any = "0.00",
    known_fee: Any = None,
    known_tax: Any = None,
) -> dict[str, Any]:
    """Explain settlement difference without silently creating a balancing entry."""
    expected = _decimal(expected_amount)
    settled = _decimal(settled_amount)
    allowed = _decimal(tolerance)
    fee = _decimal(known_fee) if known_fee is not None else Decimal("0")
    tax = _decimal(known_tax) if known_tax is not None else Decimal("0")
    if expected is None or settled is None or expected < 0 or settled < 0:
        raise ValueError("expected_amount and settled_amount must be finite and non-negative")
    if allowed is None or allowed < 0:
        raise ValueError("tolerance must be finite and non-negative")
    if fee is None or tax is None or fee < 0 or tax < 0:
        raise ValueError("known fees and taxes must be finite and non-negative")
    normalized_currency = str(currency or "").strip().upper()
    if not normalized_currency:
        raise ValueError("currency is required")
    currencies = [str(v).strip().upper() for v in (expected_currency or currency, settled_currency or currency)]
    if any(v != normalized_currency for v in currencies):
        return {
            "algorithm_version": ALGORITHM_VERSION,
            "classification": "CURRENCY_MISMATCH",
            "expected_amount": str(expected),
            "settled_amount": str(settled),
            "variance": str(settled - expected),
            "currency": normalized_currency,
            "action": "REVIEW",
            "reason_codes": ["settlement_currency_mismatch"],
        }

    variance = settled - expected
    modeled_net = expected - fee - tax
    unexplained = settled - modeled_net
    if abs(variance) <= allowed:
        classification = "WITHIN_TOLERANCE"
    elif fee > 0 or tax > 0:
        classification = "KNOWN_DEDUCTIONS_EXPLAIN_VARIANCE" if abs(unexplained) <= allowed else "PARTIALLY_EXPLAINED_VARIANCE"
    elif variance < 0:
        classification = "SHORT_SETTLEMENT"
    else:
        classification = "OVER_SETTLEMENT"
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "classification": classification,
        "expected_amount": str(expected),
        "settled_amount": str(settled),
        "variance": str(variance),
        "known_fee": str(fee),
        "known_tax": str(tax),
        "modeled_net_settlement": str(modeled_net),
        "unexplained_variance": str(unexplained),
        "currency": normalized_currency,
        "action": "NO_ACTION" if classification == "WITHIN_TOLERANCE" else "REVIEW",
        "reason_codes": [] if classification == "WITHIN_TOLERANCE" else ["settlement_variance_requires_review"],
    }


def validate_transaction_transition(
    previous_state: str,
    next_state: str,
    *,
    original_transaction_id: str | None = None,
    reversal_transaction_id: str | None = None,
    original_confirmed: bool = True,
    same_scope: bool = True,
    event_time: Any = None,
    original_time: Any = None,
) -> dict[str, Any]:
    """Validate a provider lifecycle transition; never updates persisted state."""
    previous = str(previous_state or "").strip().upper()
    following = str(next_state or "").strip().upper()
    reasons: list[str] = []
    if previous not in _ALLOWED_STATES or following not in _ALLOWED_STATES.get(previous, set()):
        reasons.append("invalid_state_transition")
    is_reversal = following in {"REVERSED", "PARTIALLY_REVERSED"}
    if is_reversal:
        if not original_transaction_id or not reversal_transaction_id:
            reasons.append("reversal_linkage_missing")
        elif str(original_transaction_id).strip() == str(reversal_transaction_id).strip():
            reasons.append("reversal_self_reference")
        if not original_confirmed:
            reasons.append("original_not_confirmed")
        if not same_scope:
            reasons.append("cross_scope_transition")
        event_dt, original_dt = _timestamp(event_time), _timestamp(original_time)
        if event_time is not None and event_dt is None:
            reasons.append("invalid_or_naive_event_time")
        if original_time is not None and original_dt is None:
            reasons.append("invalid_or_naive_original_time")
        if event_dt is not None and original_dt is not None and event_dt < original_dt:
            reasons.append("reversal_precedes_original")
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "allowed": not reasons,
        "previous_state": previous,
        "next_state": following,
        "reason_codes": reasons,
        "action": "PROCEED_TO_TRANSACTIONAL_VALIDATION" if not reasons else "QUARANTINE_FOR_REVIEW",
    }


def conservative_reconciliation_decision(
    *,
    candidate_count: int,
    top_score: Any,
    second_score: Any = None,
    minimum_score: float = 0.95,
    ambiguity_margin: float = 0.05,
    scope_verified: bool = False,
    provider_confirmed: bool = False,
    quality_passed: bool = False,
    exact_external_id: bool = False,
    idempotency_claimed: bool = False,
    reason_codes: Sequence[str] = (),
) -> dict[str, Any]:
    """Return a conservative match proposal; never post or settle funds.

    Auto-match proposal requires a unique, high-scoring candidate and explicit
    verified scope/provider/quality/idempotency guards. A score is not a probability.
    """
    if isinstance(candidate_count, bool) or candidate_count < 0:
        raise ValueError("candidate_count must be a non-negative integer")
    if not math.isfinite(minimum_score) or not 0 <= minimum_score <= 1:
        raise ValueError("minimum_score must be between 0 and 1")
    if not math.isfinite(ambiguity_margin) or not 0 <= ambiguity_margin <= 1:
        raise ValueError("ambiguity_margin must be between 0 and 1")
    top = _decimal(top_score) if top_score is not None else None
    second = _decimal(second_score) if second_score is not None else None
    if top is not None and (top < 0 or top > 1):
        raise ValueError("top_score must be between 0 and 1")
    if second is not None and (second < 0 or second > 1):
        raise ValueError("second_score must be between 0 and 1")
    reasons = list(dict.fromkeys(str(r) for r in reason_codes if str(r).strip()))
    if candidate_count == 0:
        decision = "UNMATCHED"
        reasons.append("no_candidates")
    elif top is None:
        decision = "REVIEW"
        reasons.append("missing_candidate_score")
    elif candidate_count > 1 and second is not None and float(top - second) < ambiguity_margin:
        decision = "REVIEW"
        reasons.append("ambiguous_candidates")
    elif not scope_verified:
        decision = "REVIEW"
        reasons.append("tenant_provider_account_scope_unverified")
    elif not provider_confirmed:
        decision = "REVIEW"
        reasons.append("provider_state_unconfirmed")
    elif not quality_passed:
        decision = "EXCEPTION"
        reasons.append("transaction_quality_gate_failed")
    elif not idempotency_claimed:
        decision = "REVIEW"
        reasons.append("idempotency_not_claimed")
    elif not exact_external_id:
        decision = "REVIEW"
        reasons.append("exact_external_identity_required_for_auto_match")
    elif float(top) < minimum_score:
        decision = "REVIEW"
        reasons.append("score_below_auto_match_threshold")
    else:
        decision = "MATCH_PROPOSAL"
        reasons.append("all_auto_match_guards_satisfied")
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "decision": decision,
        "candidate_count": candidate_count,
        "top_score": str(top) if top is not None else None,
        "second_score": str(second) if second is not None else None,
        "score_is_probability": False,
        "reason_codes": list(dict.fromkeys(reasons)),
        "requires_ledger_transaction": True,
        "posts_ledger": False,
    }


def detect_velocity_burst(
    events: Sequence[Mapping[str, Any]],
    *,
    window_seconds: int = 300,
    count_threshold: int = 10,
    amount_threshold: Any = None,
    now: Any = None,
) -> dict[str, Any]:
    """Detect a short-window volume burst from caller-scoped event history.

    The caller MUST supply events from one tenant and one relevant entity/account.
    Missing or naive timestamps are excluded and counted, not treated as current.
    """
    if isinstance(window_seconds, bool) or window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    if isinstance(count_threshold, bool) or count_threshold < 1:
        raise ValueError("count_threshold must be at least one")
    amount_limit = _decimal(amount_threshold) if amount_threshold is not None else None
    if amount_threshold is not None and (amount_limit is None or amount_limit < 0):
        raise ValueError("amount_threshold must be finite and non-negative")
    end = _timestamp(now) if now is not None else datetime.now(timezone.utc)
    if end is None:
        raise ValueError("now must be timezone-aware")
    start = end.timestamp() - window_seconds
    count, total, invalid = 0, Decimal("0"), 0
    for event in events:
        timestamp = _timestamp(event.get("timestamp"))
        if timestamp is None:
            invalid += 1
            continue
        if start < timestamp.timestamp() <= end.timestamp():
            count += 1
            amount = _decimal(event.get("amount"))
            if amount is not None and amount >= 0:
                total += amount
            else:
                invalid += 1
    count_burst = count >= count_threshold
    amount_burst = amount_limit is not None and total >= amount_limit
    detected = count_burst or amount_burst
    reasons = []
    if count_burst:
        reasons.append("event_count_threshold_exceeded")
    if amount_burst:
        reasons.append("amount_threshold_exceeded")
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "ready": True,
        "window_seconds": window_seconds,
        "event_count": count,
        "amount_total": str(total),
        "invalid_or_untimed_events": invalid,
        "count_threshold": count_threshold,
        "amount_threshold": str(amount_limit) if amount_limit is not None else None,
        "burst_detected": detected,
        "reason_codes": reasons,
        "action": "INVESTIGATE" if detected else "NO_VELOCITY_SIGNAL",
        "score_is_probability": False,
    }


def evaluate_algorithm_release(
    metrics: Mapping[str, Any],
    *,
    minimum_samples: int,
    minimum_precision: float,
    minimum_recall: float,
    maximum_false_positive_rate: float,
    maximum_review_rate: float,
    is_holdout: bool,
    dataset_version: str | None,
    algorithm_version: str,
    reviewer: str | None,
) -> dict[str, Any]:
    """Evaluate explicit promotion criteria; PASS is not an automatic deployment."""
    if isinstance(minimum_samples, bool) or minimum_samples < 1:
        raise ValueError("minimum_samples must be positive")
    limits = {
        "minimum_precision": minimum_precision,
        "minimum_recall": minimum_recall,
        "maximum_false_positive_rate": maximum_false_positive_rate,
        "maximum_review_rate": maximum_review_rate,
    }
    if any(not math.isfinite(v) or not 0 <= v <= 1 for v in limits.values()):
        raise ValueError("all metric thresholds must be finite and between 0 and 1")
    blockers: list[str] = []
    if not is_holdout:
        blockers.append("evaluation_must_use_holdout")
    if not dataset_version or not str(dataset_version).strip():
        blockers.append("dataset_version_missing")
    if not algorithm_version or not str(algorithm_version).strip():
        blockers.append("algorithm_version_missing")
    if not reviewer or not str(reviewer).strip():
        blockers.append("human_reviewer_missing")
    samples = metrics.get("sample_count")
    if isinstance(samples, bool) or not isinstance(samples, (int, float)) or not math.isfinite(samples) or samples < minimum_samples:
        blockers.append("insufficient_holdout_samples")
    checks = [
        ("precision", minimum_precision, lambda value, limit: value >= limit, "precision_below_minimum"),
        ("recall", minimum_recall, lambda value, limit: value >= limit, "recall_below_minimum"),
        ("false_positive_rate", maximum_false_positive_rate, lambda value, limit: value <= limit, "false_positive_rate_above_maximum"),
        ("review_rate", maximum_review_rate, lambda value, limit: value <= limit, "review_rate_above_maximum"),
    ]
    normalized: dict[str, float | None] = {}
    for key, limit, comparator, blocker in checks:
        value = metrics.get(key)
        valid = isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 1
        normalized[key] = float(value) if valid else None
        if not valid:
            blockers.append(f"metric_missing_or_invalid:{key}")
        elif not comparator(float(value), limit):
            blockers.append(blocker)
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "evaluated_algorithm_version": str(algorithm_version or ""),
        "dataset_version": str(dataset_version or ""),
        "reviewer": str(reviewer or ""),
        "is_holdout": bool(is_holdout),
        "sample_count": samples if isinstance(samples, (int, float)) and not isinstance(samples, bool) else None,
        "metrics": normalized,
        "thresholds": limits,
        "decision": "PASS_FOR_REVIEW" if not blockers else "BLOCK",
        "blockers": list(dict.fromkeys(blockers)),
        "automatic_deployment": False,
        "requires_shadow_run_and_approval": True,
    }
