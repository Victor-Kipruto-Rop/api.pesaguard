"""Bounded, deterministic financial reconciliation helpers."""
from __future__ import annotations
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping, Sequence

ALGORITHM_VERSION = "advanced-reconciliation-v1"


def _money(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        result = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError):
        return None
    return result if result.is_finite() else None


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
    """Find exact open-invoice subsets; never posts or changes ledger rows."""
    tenant, currency_code = str(tenant_id or "").strip(), str(currency or "").strip().upper()
    if not tenant or not currency_code:
        raise ValueError("tenant_id and currency are required")
    if not isinstance(quantum, Decimal) or not quantum.is_finite() or quantum <= 0:
        raise ValueError("quantum must be a finite positive Decimal")
    if max_invoices < 1 or max_states < 2:
        raise ValueError("limits must be positive")
    if len(invoices) > max_invoices:
        return {"algorithm_version": ALGORITHM_VERSION, "decision": "REVIEW",
                "reason_codes": ["candidate_set_too_large"], "allocations": []}

    amount = _money(payment_amount)
    if amount is None or amount <= 0 or amount.quantize(quantum) != amount:
        return {"algorithm_version": ALGORITHM_VERSION, "decision": "REVIEW",
                "reason_codes": ["invalid_or_non_positive_payment_amount"], "allocations": []}
    target = int(amount / quantum)
    eligible, excluded, seen = [], [], set()
    for index, row in enumerate(invoices):
        invoice_id = str(row.get("invoice_id") or row.get("id") or row.get("internal_ref") or "").strip()
        if not invoice_id:
            excluded.append({"candidate_id": f"candidate-{index + 1}", "reason": "missing_invoice_id"})
            continue
        if invoice_id in seen:
            excluded.append({"candidate_id": invoice_id, "reason": "duplicate_invoice_id"})
            continue
        seen.add(invoice_id)
        if str(row.get("status") or "open").strip().casefold() not in {"open", "unpaid", "partial", "partially_paid"}:
            excluded.append({"candidate_id": invoice_id, "reason": "invoice_not_open"})
            continue
        row_tenant = row.get("tenant_id")
        if row_tenant not in (None, "") and str(row_tenant).strip() != tenant:
            excluded.append({"candidate_id": invoice_id, "reason": "tenant_scope_conflict"})
            continue
        row_currency = row.get("currency")
        if row_currency not in (None, "") and str(row_currency).strip().upper() != currency_code:
            excluded.append({"candidate_id": invoice_id, "reason": "currency_scope_conflict"})
            continue
        raw = row.get("outstanding_amount", row.get("amount"))
        value = _money(raw)
        if value is None or value <= 0 or value.quantize(quantum) != value:
            excluded.append({"candidate_id": invoice_id, "reason": "invalid_outstanding_amount"})
            continue
        units = int(value / quantum)
        if units <= target:
            eligible.append((invoice_id, units))

    # Keep at most two paths per total: sufficient to detect ambiguity.
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
    decision = "UNMATCHED" if not matches else ("UNIQUE_CANDIDATE" if len(matches) == 1 else "REVIEW")
    reason = "no_exact_allocation" if not matches else ("unique_exact_allocation" if len(matches) == 1 else "ambiguous_exact_allocations")
    return {"algorithm_version": ALGORITHM_VERSION, "decision": decision, "reason_codes": [reason],
            "target_amount": format(Decimal(target) * quantum, "f"), "candidate_count": len(invoices),
            "eligible_candidate_count": len(eligible), "excluded_candidates": excluded,
            "excluded_candidate_count": len(excluded), "allocations": allocations}


def compare_settlement_totals(
    *, expected_amount: Any, actual_amount: Any, expected_count: int | None = None,
    actual_count: int | None = None, amount_tolerance: Any = "0.01",
) -> dict[str, Any]:
    """Compare settlement totals with exact Decimal arithmetic."""
    expected, actual, tolerance = _money(expected_amount), _money(actual_amount), _money(amount_tolerance)
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
    delta = actual - expected
    reasons = []
    if abs(delta) > tolerance:
        reasons.append("settlement_amount_variance")
    count_delta = None if expected_count is None else actual_count - expected_count
    if count_delta not in (None, 0):
        reasons.append("settlement_count_variance")
    return {"algorithm_version": ALGORITHM_VERSION, "status": "MATCHED" if not reasons else "REVIEW",
            "expected_amount": format(expected, "f"), "actual_amount": format(actual, "f"),
            "amount_variance": format(delta, "f"), "amount_tolerance": format(tolerance, "f"),
            "expected_count": expected_count, "actual_count": actual_count,
            "count_variance": count_delta, "reason_codes": reasons}


def calculate_match_quality_metrics(outcomes: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Calculate metrics from independently reviewed ground-truth labels."""
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
