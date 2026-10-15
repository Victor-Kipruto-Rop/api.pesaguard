"""Advanced, explainable baseline algorithms for PesaGuard.

These helpers are advisory analytics only. They require caller-supplied, tenant-
and currency-scoped history; they never change transaction or ledger state.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation
import math
import statistics
from typing import Any, Iterable, Mapping, Sequence
from zoneinfo import ZoneInfo

ALGORITHM_VERSION = "advanced-reconciliation-v1"
DEFAULT_TIMEZONE = "Africa/Nairobi"


def _finite_decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError):
        return None
    return parsed if parsed.is_finite() else None


def _aware_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        raw = value.strip()
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo is not None else None


def seasonal_amount_assessment(
    current_amount: Any,
    history: Sequence[Mapping[str, Any]],
    *,
    event_time: Any,
    timezone_name: str = DEFAULT_TIMEZONE,
    minimum_samples: int = 8,
    modified_z_threshold: float = 3.5,
    currency: str = "KES",
) -> dict[str, Any]:
    """Compare an amount to same-local-weekday/hour observations.

    Each history item must contain amount, timestamp, and currency. Only matching
    currency and matching weekday/hour in the supplied timezone are considered.
    Insufficient history returns ready=False, never evidence the amount is normal.
    """
    if isinstance(minimum_samples, bool) or minimum_samples < 5:
        raise ValueError("minimum_samples must be at least 5")
    if not math.isfinite(modified_z_threshold) or modified_z_threshold <= 0:
        raise ValueError("modified_z_threshold must be finite and positive")
    if not str(currency).strip():
        raise ValueError("currency is required")

    current = _finite_decimal(current_amount)
    timestamp = _aware_datetime(event_time)
    if current is None or current <= 0:
        raise ValueError("current_amount must be a finite positive decimal")
    if timestamp is None:
        raise ValueError("event_time must be timezone-aware")
    try:
        zone = ZoneInfo(timezone_name)
        local_current = timestamp.astimezone(zone)
    except Exception as exc:
        raise ValueError("timezone_name must be a valid IANA timezone") from exc

    values: list[float] = []
    invalid = 0
    for item in history:
        if not isinstance(item, Mapping):
            invalid += 1
            continue
        if str(item.get("currency") or "").strip().upper() != str(currency).strip().upper():
            continue
        historic_time = _aware_datetime(item.get("timestamp"))
        amount = _finite_decimal(item.get("amount"))
        if historic_time is None or amount is None or amount <= 0:
            invalid += 1
            continue
        local_history = historic_time.astimezone(zone)
        if (local_history.weekday(), local_history.hour) == (local_current.weekday(), local_current.hour):
            values.append(float(amount))

    if len(values) < minimum_samples:
        return {
            "algorithm_version": ALGORITHM_VERSION,
            "ready": False,
            "reason": "insufficient_matching_seasonal_samples",
            "sample_count": len(values),
            "minimum_samples": minimum_samples,
            "currency": str(currency).strip().upper(),
            "timezone": timezone_name,
            "is_outlier": None,
            "modified_z": None,
            "baseline_median": None,
            "baseline_mad": None,
            "invalid_history_rows": invalid,
        }

    median = statistics.median(values)
    deviations = [abs(value - median) for value in values]
    mad = statistics.median(deviations)
    current_float = float(current)
    modified_z = None
    if mad > 0:
        modified_z = 0.6745 * (current_float - median) / mad
        is_outlier = abs(modified_z) > modified_z_threshold
    else:
        is_outlier = current_float != median
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "ready": True,
        "sample_count": len(values),
        "minimum_samples": minimum_samples,
        "currency": str(currency).strip().upper(),
        "timezone": timezone_name,
        "cohort": {"weekday": local_current.weekday(), "hour": local_current.hour},
        "baseline_median": str(Decimal(str(median))),
        "baseline_mad": str(Decimal(str(mad))),
        "modified_z": round(modified_z, 4) if modified_z is not None else None,
        "is_outlier": bool(is_outlier),
        "invalid_history_rows": invalid,
        "action": "REVIEW_SIGNAL" if is_outlier else "NO_SEASONAL_OUTLIER_SIGNAL",
    }


def detect_distribution_shift(
    reference_values: Iterable[Any],
    recent_values: Iterable[Any],
    *,
    minimum_samples_per_window: int = 10,
    relative_change_threshold: float = 0.5,
) -> dict[str, Any]:
    """Detect a median shift between windows without claiming causation.

    Intended for operational monitoring, not individual transaction decisions.
    Windows must contain comparable units and cohorts. Small windows are unknown,
    not normal.
    """
    if isinstance(minimum_samples_per_window, bool) or minimum_samples_per_window < 3:
        raise ValueError("minimum_samples_per_window must be at least 3")
    if not math.isfinite(relative_change_threshold) or relative_change_threshold <= 0:
        raise ValueError("relative_change_threshold must be finite and positive")

    def parse(values: Iterable[Any]) -> tuple[list[float], int]:
        parsed: list[float] = []
        invalid = 0
        for value in values:
            number = _finite_decimal(value)
            if number is None:
                invalid += 1
            else:
                parsed.append(float(number))
        return parsed, invalid

    reference, invalid_reference = parse(reference_values)
    recent, invalid_recent = parse(recent_values)
    base = {
        "algorithm_version": ALGORITHM_VERSION,
        "reference_sample_count": len(reference),
        "recent_sample_count": len(recent),
        "invalid_reference_values": invalid_reference,
        "invalid_recent_values": invalid_recent,
        "relative_change_threshold": relative_change_threshold,
    }
    if len(reference) < minimum_samples_per_window or len(recent) < minimum_samples_per_window:
        return {
            **base,
            "ready": False,
            "reason": "insufficient_window_samples",
            "shift_detected": None,
            "reference_median": None,
            "recent_median": None,
            "relative_change": None,
        }

    reference_median = statistics.median(reference)
    recent_median = statistics.median(recent)
    if reference_median == 0:
        relative_change = 0.0 if recent_median == 0 else None
        shift_detected = recent_median != 0
    else:
        relative_change = (recent_median - reference_median) / abs(reference_median)
        shift_detected = abs(relative_change) >= relative_change_threshold
    return {
        **base,
        "ready": True,
        "reference_median": reference_median,
        "recent_median": recent_median,
        "relative_change": round(relative_change, 6) if relative_change is not None else None,
        "shift_detected": bool(shift_detected),
        "action": "INVESTIGATE_DISTRIBUTION_SHIFT" if shift_detected else "NO_SHIFT_SIGNAL",
    }


def _allocation_units(value: Any, quantum: Decimal) -> int | None:
    amount = _finite_decimal(value)
    if amount is None or amount <= 0:
        return None
    units = amount / quantum
    if units != units.to_integral_value():
        return None
    return int(units)


def find_invoice_allocation_candidates(
    payment_amount: Any,
    invoices: Sequence[Mapping[str, Any]],
    *,
    tenant_id: str,
    currency: str = "KES",
    quantum: Decimal = Decimal("0.01"),
    max_invoices: int = 20,
    max_states: int = 50000,
) -> dict[str, Any]:
    """Find exact open-invoice subsets; advisory only, never posts ledger rows."""
    tenant, currency_code = str(tenant_id or "").strip(), str(currency or "").strip().upper()
    if not tenant or not currency_code:
        raise ValueError("tenant_id and currency are required")
    if not isinstance(quantum, Decimal) or not quantum.is_finite() or quantum <= 0:
        raise ValueError("quantum must be a finite positive Decimal")
    if isinstance(max_invoices, bool) or max_invoices < 1 or isinstance(max_states, bool) or max_states < 2:
        raise ValueError("limits must be positive")
    if len(invoices) > max_invoices:
        return {"algorithm_version": ALGORITHM_VERSION, "decision": "REVIEW",
                "reason_codes": ["candidate_set_too_large"], "allocations": []}
    target = _allocation_units(payment_amount, quantum)
    if target is None:
        return {"algorithm_version": ALGORITHM_VERSION, "decision": "REVIEW",
                "reason_codes": ["invalid_or_non_positive_payment_amount"], "allocations": []}

    eligible: list[tuple[str, int]] = []
    excluded: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, row in enumerate(invoices):
        invoice_id = str(row.get("invoice_id") or row.get("id") or row.get("internal_ref") or "").strip()
        if not invoice_id:
            excluded.append({"candidate_id": f"candidate-{index + 1}", "reason": "missing_invoice_id"})
            continue
        if invoice_id in seen:
            excluded.append({"candidate_id": invoice_id, "reason": "duplicate_invoice_id"})
            continue
        seen.add(invoice_id)
        state = str(row.get("status") or "open").strip().casefold()
        if state not in {"open", "unpaid", "partial", "partially_paid"}:
            excluded.append({"candidate_id": invoice_id, "reason": "invoice_not_open"})
            continue
        row_tenant, row_currency = row.get("tenant_id"), row.get("currency")
        if row_tenant not in (None, "") and str(row_tenant).strip() != tenant:
            excluded.append({"candidate_id": invoice_id, "reason": "tenant_scope_conflict"})
            continue
        if row_currency not in (None, "") and str(row_currency).strip().upper() != currency_code:
            excluded.append({"candidate_id": invoice_id, "reason": "currency_scope_conflict"})
            continue
        raw = row.get("outstanding_amount")
        if raw is None:
            raw = row.get("amount")
        units = _allocation_units(raw, quantum)
        if units is None:
            excluded.append({"candidate_id": invoice_id, "reason": "invalid_outstanding_amount"})
            continue
        if units <= target:
            eligible.append((invoice_id, units))

    # Retain at most two paths per total, enough to distinguish unique from ambiguous.
    ways: dict[int, list[tuple[str, ...]]] = {0: [()]}
    for invoice_id, units in eligible:
        additions: dict[int, list[tuple[str, ...]]] = {}
        for subtotal, combos in list(ways.items()):
            total = subtotal + units
            if total > target:
                continue
            bucket = additions.setdefault(total, [])
            for combo in combos:
                next_combo = combo + (invoice_id,)
                if next_combo not in bucket and len(bucket) < 2:
                    bucket.append(next_combo)
        for total, combos in additions.items():
            bucket = ways.setdefault(total, [])
            for combo in combos:
                if combo not in bucket and len(bucket) < 2:
                    bucket.append(combo)
        if len(ways) > max_states:
            return {"algorithm_version": ALGORITHM_VERSION, "decision": "REVIEW",
                    "reason_codes": ["search_state_limit_exceeded"], "allocations": []}

    matches = ways.get(target, [])
    allocations = [{"invoice_ids": list(combo), "amount": format(Decimal(target) * quantum, "f")}
                   for combo in matches[:2]]
    if len(matches) == 1:
        decision, reason = "UNIQUE_CANDIDATE", "unique_exact_allocation"
    elif len(matches) > 1:
        decision, reason = "REVIEW", "ambiguous_exact_allocations"
    else:
        decision, reason = "UNMATCHED", "no_exact_allocation"
    return {"algorithm_version": ALGORITHM_VERSION, "decision": decision, "reason_codes": [reason],
            "target_amount": format(Decimal(target) * quantum, "f"), "candidate_count": len(invoices),
            "eligible_candidate_count": len(eligible), "excluded_candidates": excluded,
            "excluded_candidate_count": len(excluded), "allocations": allocations}


def compare_settlement_totals(
    *, expected_amount: Any, actual_amount: Any, expected_count: int | None = None,
    actual_count: int | None = None, amount_tolerance: Any = "0.01",
) -> dict[str, Any]:
    """Compare settlement amount and optional counts using Decimal arithmetic."""
    expected, actual = _finite_decimal(expected_amount), _finite_decimal(actual_amount)
    tolerance = _finite_decimal(amount_tolerance)
    if expected is None or actual is None:
        raise ValueError("settlement amounts must be finite")
    if tolerance is None or tolerance < 0:
        raise ValueError("amount_tolerance must be finite and non-negative")
    if (expected_count is None) != (actual_count is None):
        raise ValueError("supply both counts or neither")
    if expected_count is not None:
        if (isinstance(expected_count, bool) or isinstance(actual_count, bool)
                or not isinstance(expected_count, int) or not isinstance(actual_count, int)
                or expected_count < 0 or actual_count < 0):
            raise ValueError("counts must be non-negative integers")
    variance = actual - expected
    reasons = []
    if abs(variance) > tolerance:
        reasons.append("settlement_amount_variance")
    count_variance = None if expected_count is None else actual_count - expected_count
    if count_variance not in (None, 0):
        reasons.append("settlement_count_variance")
    return {"algorithm_version": ALGORITHM_VERSION, "status": "MATCHED" if not reasons else "REVIEW",
            "expected_amount": format(expected, "f"), "actual_amount": format(actual, "f"),
            "amount_variance": format(variance, "f"), "amount_tolerance": format(tolerance, "f"),
            "expected_count": expected_count, "actual_count": actual_count,
            "count_variance": count_variance, "reason_codes": reasons}


def calculate_match_quality_metrics(outcomes: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Calculate match metrics from independently reviewed boolean labels."""
    counts = {"true_positive": 0, "false_positive": 0, "true_negative": 0, "false_negative": 0}
    total = 0
    for row in outcomes:
        predicted, actual = row.get("predicted_match"), row.get("actual_match")
        if not isinstance(predicted, bool) or not isinstance(actual, bool):
            raise ValueError("boolean predicted_match and actual_match are required")
        total += 1
        key = ("true_" if predicted == actual else "false_") + ("positive" if predicted else "negative")
        counts[key] += 1
    tp, fp, tn, fn = counts["true_positive"], counts["false_positive"], counts["true_negative"], counts["false_negative"]
    metrics = {"precision": tp / (tp + fp) if tp + fp else None,
               "recall": tp / (tp + fn) if tp + fn else None,
               "specificity": tn / (tn + fp) if tn + fp else None,
               "accuracy": (tp + tn) / total if total else None}
    return {"algorithm_version": ALGORITHM_VERSION, "sample_count": total, **counts, **metrics,
            "undefined_metrics": [name for name, value in metrics.items() if value is None]}
