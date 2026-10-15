"""Bounded, one-to-one batch reconciliation assignment.

This module is an advisory algorithm primitive. It proposes a globally consistent
assignment so one ledger row cannot be selected for two provider transactions.
It never writes to the ledger, authorizes a payment, or replaces the live engine.
"""
from __future__ import annotations

from functools import lru_cache
import math
from typing import Any, Mapping, Sequence

ALGORITHM_VERSION = "global-batch-assignment-v1"
DEFAULT_MAX_TRANSACTIONS = 16
DEFAULT_MAX_CANDIDATES = 16


def propose_batch_assignment(
    transactions: Sequence[Mapping[str, Any]],
    *,
    minimum_score: float = 0.60,
    ambiguity_margin: float = 0.05,
    max_transactions: int = DEFAULT_MAX_TRANSACTIONS,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> dict[str, Any]:
    """Return a globally optimal one-to-one assignment proposal or REVIEW.

    Input contract:
      transactions = [
        {"transaction_id": "provider-id", "candidates": [
          {"candidate_id": "ledger-id", "score": 0.91, "eligible": True},
          {"candidate_id": "other-ledger-id", "score": 0.42}
        ]}
      ]

    Candidate scores are ranking scores, not probabilities. Ineligible candidates
    are ignored. Candidates below minimum_score are not assigned. A ledger
    candidate can be assigned at most once across the whole batch.

    The exact dynamic-programming search is deliberately bounded. Oversized input,
    malformed identifiers, duplicate transaction IDs, invalid scores, or ambiguous
    optimum returns a fail-closed result rather than a partial assignment.
    """
    if isinstance(max_transactions, bool) or max_transactions < 1:
        raise ValueError("max_transactions must be a positive integer")
    if isinstance(max_candidates, bool) or max_candidates < 1:
        raise ValueError("max_candidates must be a positive integer")
    if not math.isfinite(minimum_score) or not 0 <= minimum_score <= 1:
        raise ValueError("minimum_score must be finite and between 0 and 1")
    if not math.isfinite(ambiguity_margin) or ambiguity_margin < 0:
        raise ValueError("ambiguity_margin must be finite and non-negative")

    if len(transactions) > max_transactions:
        return _unavailable("batch_exceeds_exact_search_limit", len(transactions), max_transactions, max_candidates)

    transaction_ids: list[str] = []
    parsed_options: list[list[tuple[str, float]]] = []
    all_candidate_ids: set[str] = set()

    for row_index, row in enumerate(transactions):
        if not isinstance(row, Mapping):
            raise ValueError(f"transactions[{row_index}] must be a mapping")
        transaction_id = str(row.get("transaction_id") or "").strip()
        if not transaction_id:
            raise ValueError(f"transactions[{row_index}].transaction_id is required")
        if transaction_id in transaction_ids:
            raise ValueError(f"duplicate transaction_id: {transaction_id}")
        transaction_ids.append(transaction_id)

        raw_candidates = row.get("candidates", [])
        if not isinstance(raw_candidates, Sequence) or isinstance(raw_candidates, (str, bytes)):
            raise ValueError(f"candidates for {transaction_id} must be a sequence")
        options: dict[str, float] = {}
        for candidate_index, candidate in enumerate(raw_candidates):
            if not isinstance(candidate, Mapping):
                raise ValueError(f"candidate {candidate_index} for {transaction_id} must be a mapping")
            if candidate.get("eligible", True) is False:
                continue
            candidate_id = str(candidate.get("candidate_id") or "").strip()
            if not candidate_id:
                raise ValueError(f"candidate_id is required for {transaction_id}")
            score_value = candidate.get("score")
            if isinstance(score_value, bool):
                raise ValueError(f"score must be numeric for {transaction_id}/{candidate_id}")
            try:
                score = float(score_value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"score must be numeric for {transaction_id}/{candidate_id}") from exc
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError(f"score must be finite and between 0 and 1 for {transaction_id}/{candidate_id}")
            if candidate_id in options:
                raise ValueError(f"duplicate candidate_id {candidate_id} for {transaction_id}")
            if score >= minimum_score:
                options[candidate_id] = score
                all_candidate_ids.add(candidate_id)
        parsed_options.append(sorted(options.items(), key=lambda item: item[0]))

    candidate_ids = sorted(all_candidate_ids)
    if len(candidate_ids) > max_candidates:
        return _unavailable("candidate_set_exceeds_exact_search_limit", len(transactions), max_transactions, max_candidates, candidate_count=len(candidate_ids))

    candidate_index = {candidate_id: index for index, candidate_id in enumerate(candidate_ids)}

    def solve(forbidden: tuple[int, str] | None = None) -> tuple[float, tuple[str | None, ...]]:
        @lru_cache(maxsize=None)
        def visit(transaction_index: int, used_mask: int) -> tuple[float, tuple[str | None, ...]]:
            if transaction_index == len(transaction_ids):
                return 0.0, ()
            # Leaving a transaction unmatched is always a valid option.
            tail_score, tail_assignment = visit(transaction_index + 1, used_mask)
            best_score = tail_score
            best_assignment: tuple[str | None, ...] = (None,) + tail_assignment
            for candidate_id, score in parsed_options[transaction_index]:
                if forbidden == (transaction_index, candidate_id):
                    continue
                bit = 1 << candidate_index[candidate_id]
                if used_mask & bit:
                    continue
                remaining_score, remaining_assignment = visit(transaction_index + 1, used_mask | bit)
                total = score + remaining_score
                assignment = (candidate_id,) + remaining_assignment
                if total > best_score + 1e-12 or (
                    abs(total - best_score) <= 1e-12 and _assignment_key(assignment) < _assignment_key(best_assignment)
                ):
                    best_score, best_assignment = total, assignment
            return best_score, best_assignment

        return visit(0, 0)

    best_total, best_assignment = solve()
    ambiguous_edges: list[dict[str, Any]] = []
    for tx_index, candidate_id in enumerate(best_assignment):
        if candidate_id is None:
            continue
        alternate_total, _ = solve((tx_index, candidate_id))
        margin = max(0.0, best_total - alternate_total)
        if margin <= ambiguity_margin + 1e-12:
            ambiguous_edges.append({
                "transaction_id": transaction_ids[tx_index],
                "candidate_id": candidate_id,
                "global_alternative_margin": round(margin, 8),
            })

    proposed = [
        {"transaction_id": tx_id, "candidate_id": candidate_id, "score": dict(parsed_options[index])[candidate_id]}
        for index, (tx_id, candidate_id) in enumerate(zip(transaction_ids, best_assignment))
        if candidate_id is not None
    ]
    unmatched = [tx_id for tx_id, candidate_id in zip(transaction_ids, best_assignment) if candidate_id is None]
    ambiguous = bool(ambiguous_edges)
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "ready": True,
        "decision": "REVIEW" if ambiguous else "PROPOSAL",
        "is_ambiguous": ambiguous,
        "reason_codes": ["near_equivalent_global_assignment"] if ambiguous else [],
        "transaction_count": len(transaction_ids),
        "candidate_count": len(candidate_ids),
        "minimum_score": minimum_score,
        "ambiguity_margin": ambiguity_margin,
        "total_score": round(best_total, 8),
        "proposed_assignments": proposed,
        # Do not expose an ambiguous optimum as an approved assignment.
        "assignments": [] if ambiguous else proposed,
        "unmatched_transaction_ids": unmatched,
        "ambiguous_edges": ambiguous_edges,
        "side_effects_performed": False,
    }


def _assignment_key(assignment: tuple[str | None, ...]) -> tuple[str, ...]:
    """Stable tie-break: unmatched sorts after named candidates."""
    return tuple(candidate_id if candidate_id is not None else "\uffff" for candidate_id in assignment)


def _unavailable(
    reason: str,
    transaction_count: int,
    max_transactions: int,
    max_candidates: int,
    *,
    candidate_count: int | None = None,
) -> dict[str, Any]:
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "ready": False,
        "decision": "REVIEW",
        "is_ambiguous": None,
        "reason_codes": [reason],
        "transaction_count": transaction_count,
        "candidate_count": candidate_count,
        "max_transactions": max_transactions,
        "max_candidates": max_candidates,
        "proposed_assignments": [],
        "assignments": [],
        "unmatched_transaction_ids": [],
        "ambiguous_edges": [],
        "side_effects_performed": False,
    }
