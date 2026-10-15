"""Fail-closed validation primitives for balanced, currency-safe journal batches.

This module validates proposed journal lines. It does not write to a database,
provide concurrency control, or make a posting operation atomic. Callers must
run validation inside the same database transaction as their idempotency claim
and ledger insert, and must enforce database-level invariants as well.
"""
from __future__ import annotations

from collections import defaultdict
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Sequence

ALGORITHM_VERSION = "ledger-invariants-v1"

# ISO 4217 exceptions used by common payment rails. Unknown currencies fail closed
# unless the caller supplies an explicitly approved exponent.
DEFAULT_CURRENCY_EXPONENTS: dict[str, int] = {
    "KES": 2, "USD": 2, "EUR": 2, "GBP": 2, "TZS": 2, "UGX": 0,
    "JPY": 0, "BHD": 3, "KWD": 3,
}


def _money(value: Any) -> Decimal | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError, AttributeError):
        return None
    return amount if amount.is_finite() else None


def validate_journal_batch(
    entries: Sequence[Mapping[str, Any]],
    *,
    currency_exponents: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Validate proposed journal lines without mutating state.

    Required fields per line: entry_id, journal_id, account_id, currency,
    side (DEBIT/CREDIT), amount. Each journal must balance independently per
    currency; amounts must be positive and representable at that currency's
    configured minor-unit precision. Any finding blocks posting.

    The caller is responsible for tenant authorization, unique constraints,
    account eligibility, period locks, transactional persistence, and audit.
    """
    exponents = dict(DEFAULT_CURRENCY_EXPONENTS)
    if currency_exponents:
        for currency, exponent in currency_exponents.items():
            code = str(currency).strip().upper()
            if not code or isinstance(exponent, bool) or not isinstance(exponent, int) or not 0 <= exponent <= 6:
                raise ValueError("currency exponents require a currency code and integer precision from 0 to 6")
            exponents[code] = exponent

    findings: list[dict[str, Any]] = []
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    seen_entry_ids: set[str] = set()

    def add(code: str, index: int | None, journal_id: str | None, message: str) -> None:
        findings.append({
            "code": code,
            "severity": "critical",
            "entry_index": index,
            "journal_id": journal_id,
            "message": message,
        })

    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise TypeError("entries must be a sequence of journal-line mappings")

    if not entries:
        add("EMPTY_BATCH", None, None, "A journal batch must contain at least one line.")

    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            add("INVALID_ENTRY", index, None, "Journal line must be a mapping.")
            continue

        entry_id = str(entry.get("entry_id") or "").strip()
        journal_id = str(entry.get("journal_id") or "").strip()
        account_id = str(entry.get("account_id") or "").strip()
        currency = str(entry.get("currency") or "").strip().upper()
        side = str(entry.get("side") or "").strip().upper()
        amount = _money(entry.get("amount"))

        if not entry_id:
            add("MISSING_ENTRY_ID", index, journal_id or None, "entry_id is required.")
        elif entry_id in seen_entry_ids:
            add("DUPLICATE_ENTRY_ID", index, journal_id or None, "entry_id repeats within this batch.")
        else:
            seen_entry_ids.add(entry_id)

        if not journal_id:
            add("MISSING_JOURNAL_ID", index, None, "journal_id is required.")
        if not account_id:
            add("MISSING_ACCOUNT_ID", index, journal_id or None, "account_id is required.")
        if not currency:
            add("MISSING_CURRENCY", index, journal_id or None, "currency is required.")
        elif currency not in exponents:
            add("UNKNOWN_CURRENCY_PRECISION", index, journal_id or None,
                "Currency has no approved minor-unit precision; configure it explicitly.")

        if side not in {"DEBIT", "CREDIT"}:
            add("INVALID_SIDE", index, journal_id or None, "side must be DEBIT or CREDIT.")

        if amount is None:
            add("INVALID_AMOUNT", index, journal_id or None, "amount must be a finite decimal.")
        elif amount <= 0:
            add("NON_POSITIVE_AMOUNT", index, journal_id or None, "Journal line amount must be greater than zero.")

        if amount is not None and amount > 0 and currency in exponents:
            quantum = Decimal(1).scaleb(-exponents[currency])
            if amount != amount.quantize(quantum):
                add("EXCESS_CURRENCY_PRECISION", index, journal_id or None,
                    f"Amount exceeds the configured {exponents[currency]} decimal places for {currency}.")

        # Invalid lines are never included in arithmetic, preventing malformed
        # amounts or missing scope from accidentally balancing a journal.
        if (entry_id and journal_id and account_id and currency in exponents
                and side in {"DEBIT", "CREDIT"} and amount is not None and amount > 0
                and amount == amount.quantize(Decimal(1).scaleb(-exponents[currency]))):
            key = (journal_id, currency)
            group = groups.setdefault(key, {
                "journal_id": journal_id,
                "currency": currency,
                "debit_total": Decimal("0"),
                "credit_total": Decimal("0"),
                "line_count": 0,
                "sides": set(),
            })
            group["debit_total" if side == "DEBIT" else "credit_total"] += amount
            group["line_count"] += 1
            group["sides"].add(side)

    summaries: list[dict[str, Any]] = []
    journal_currencies = {(str(e.get("journal_id") or "").strip(), str(e.get("currency") or "").strip().upper())
                          for e in entries if isinstance(e, Mapping)}
    for journal_id, currency in sorted(journal_currencies):
        if not journal_id or not currency or currency not in exponents:
            continue
        group = groups.get((journal_id, currency))
        if group is None:
            add("NO_VALID_LINES", None, journal_id, f"No valid lines remain for {journal_id}/{currency}.")
            continue
        debit = group["debit_total"]
        credit = group["credit_total"]
        balanced = debit == credit
        if group["line_count"] < 2:
            add("INSUFFICIENT_JOURNAL_LINES", None, journal_id, "A journal needs at least two valid lines.")
        if group["sides"] != {"DEBIT", "CREDIT"}:
            add("MISSING_DEBIT_OR_CREDIT", None, journal_id, "Each journal needs both debit and credit lines.")
        if not balanced:
            add("UNBALANCED_JOURNAL", None, journal_id,
                f"Debit and credit totals differ for {journal_id}/{currency}.")
        summaries.append({
            "journal_id": journal_id,
            "currency": currency,
            "line_count": group["line_count"],
            "debit_total": str(debit),
            "credit_total": str(credit),
            "difference": str(debit - credit),
            "balanced": balanced,
        })

    # Detect journal/currency keys represented only by malformed lines too.
    summarized_keys = {(item["journal_id"], item["currency"]) for item in summaries}
    for journal_id, currency in sorted(journal_currencies):
        if journal_id and currency in exponents and (journal_id, currency) not in summarized_keys:
            # NO_VALID_LINES may already exist; avoid duplicate reports.
            if not any(f["code"] == "NO_VALID_LINES" and f["journal_id"] == journal_id for f in findings):
                add("NO_VALID_LINES", None, journal_id, f"No valid lines remain for {journal_id}/{currency}.")

    return {
        "algorithm_version": ALGORITHM_VERSION,
        "can_post": not findings and bool(summaries) and all(item["balanced"] for item in summaries),
        "finding_count": len(findings),
        "findings": findings,
        "journals": summaries,
    }
