"""Fail-closed arbitration of reconciliation algorithm evidence.

This module combines existing algorithm outputs into a deterministic *proposal*.
It is deliberately not a ledger posting authority: callers must still enforce
tenant-scoped retrieval, transactional idempotency, approval policy, and ledger
invariants in the persistence layer.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

ALGORITHM_VERSION = "reconciliation-decision-policy-v1"

_BLOCKING_QUALITY_CODES = {
    "INVALID_AMOUNT",
    "NON_POSITIVE_AMOUNT",
    "MISSING_OR_AMBIGUOUS_TIMESTAMP",
    "MISSING_REFERENCE",
    "MISSING_TRANSACTION_ID",
    "INVALID_CURRENCY",
}
_CRITICAL_SCOPE_CODES = {
    "tenant_scope_conflict",
    "provider_scope_conflict",
    "account_scope_conflict",
    "currency_scope_conflict",
    "candidate_scope_conflict",
}
_REVIEW_RISK_LEVELS = {"HIGH", "CRITICAL"}


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    return value


def _codes(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError("reason codes must be a sequence")
    return {str(item).strip() for item in value if str(item).strip()}


def arbitrate_reconciliation_evidence(
    *,
    tenant_id: str,
    transaction_quality: Mapping[str, Any] | None,
    candidate_ranking: Mapping[str, Any] | None,
    risk_assessment: Mapping[str, Any] | None = None,
    lifecycle_assessment: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a conservative proposal based on precomputed algorithm evidence.

    Decisions:
      EXCEPTION: malformed/critical evidence or incomplete required lifecycle.
      REVIEW: scope conflict, ambiguous candidates, or high/critical risk.
      PROPOSE_MATCH: exactly one unambiguous eligible candidate with no blockers.
      UNMATCHED: no eligible candidate and no scope conflict.

    A PROPOSE_MATCH is not permission to post or settle funds. Scores are carried
    as evidence only; they are never interpreted as calibrated probabilities.
    """
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("tenant_id is required")

    quality = _mapping(transaction_quality, "transaction_quality")
    ranking = _mapping(candidate_ranking, "candidate_ranking")
    risk = _mapping(risk_assessment, "risk_assessment")
    lifecycle = _mapping(lifecycle_assessment, "lifecycle_assessment")

    reasons: list[str] = []
    evidence: dict[str, Any] = {
        "algorithm_version": ALGORITHM_VERSION,
        "tenant_id": tenant_id.strip(),
        "decision_is_posting_authority": False,
    }

    findings = quality.get("findings", [])
    if not isinstance(findings, (list, tuple)):
        raise ValueError("transaction_quality.findings must be a sequence")
    quality_codes = {
        str(item.get("code", "")).strip().upper()
        for item in findings
        if isinstance(item, Mapping) and str(item.get("code", "")).strip()
    }
    quality_valid = quality.get("valid_for_automatic_matching")
    evidence["quality_codes"] = sorted(quality_codes)
    # Missing or unknown quality validation is not equivalent to valid data.
    if quality_valid is not True or quality_codes.intersection(_BLOCKING_QUALITY_CODES):
        reasons.append("transaction_quality_block")
        return _result("EXCEPTION", reasons, evidence)

    ranking_reasons = _codes(ranking.get("reason_codes", []))
    excluded = ranking.get("excluded_candidates", [])
    if not isinstance(excluded, (list, tuple)):
        raise ValueError("candidate_ranking.excluded_candidates must be a sequence")
    scope_conflicts = ranking_reasons.intersection(_CRITICAL_SCOPE_CODES)
    for candidate in excluded:
        if isinstance(candidate, Mapping):
            scope_conflicts.update(_codes(candidate.get("reason_codes", [])).intersection(_CRITICAL_SCOPE_CODES))
    if scope_conflicts:
        evidence["scope_conflict_codes"] = sorted(scope_conflicts)
        reasons.append("candidate_scope_conflict")
        return _result("REVIEW", reasons, evidence)

    lifecycle_required = bool(lifecycle.get("required", False))
    if lifecycle_required:
        lifecycle_status = str(lifecycle.get("status", "")).strip().upper()
        can_auto_post = lifecycle.get("can_auto_post")
        # Lifecycle validation is advisory and never grants posting authority.
        if lifecycle_status not in {"VALID", "CONFIRMED", "CLEAR"} or can_auto_post is not False:
            evidence["lifecycle_status"] = lifecycle_status or "UNKNOWN"
            reasons.append("lifecycle_evidence_incomplete")
            return _result("EXCEPTION", reasons, evidence)

    risk_level = str(risk.get("level", "")).strip().upper()
    risk_action = str(risk.get("action", "")).strip().upper()
    if risk_level in _REVIEW_RISK_LEVELS or risk_action in {"REVIEW", "BLOCK", "ESCALATE"}:
        evidence["risk_level"] = risk_level or "UNKNOWN"
        evidence["risk_signals"] = sorted(_codes(risk.get("signals", [])))
        reasons.append("risk_review_required")
        return _result("REVIEW", reasons, evidence)

    decision = str(ranking.get("decision", "")).strip().upper()
    if not decision:
        reasons.append("candidate_decision_missing")
        return _result("EXCEPTION", reasons, evidence)
    ambiguous = ranking.get("ambiguous")
    top_candidate = ranking.get("top_candidate")
    if ambiguous is True or decision in {"REVIEW", "AMBIGUOUS", "EXCEPTION"}:
        reasons.append("candidate_ambiguity")
        return _result("REVIEW", reasons, evidence)

    if decision in {"UNMATCHED", "NO_MATCH"}:
        if top_candidate is not None:
            reasons.append("inconsistent_unmatched_candidate")
            return _result("EXCEPTION", reasons, evidence)
        reasons.append("no_eligible_candidate")
        return _result("UNMATCHED", reasons, evidence)

    if decision not in {"CANDIDATE", "MATCH", "MATCHED", "PROPOSE_MATCH"}:
        reasons.append("unknown_candidate_decision")
        return _result("EXCEPTION", reasons, evidence)
    if not isinstance(top_candidate, Mapping):
        reasons.append("invalid_candidate_evidence")
        return _result("EXCEPTION", reasons, evidence)

    candidate_id = top_candidate.get("candidate_id")
    if candidate_id is None or not str(candidate_id).strip():
        reasons.append("candidate_identity_missing")
        return _result("EXCEPTION", reasons, evidence)

    evidence["candidate_id"] = str(candidate_id).strip()
    evidence["candidate_score"] = top_candidate.get("score")
    evidence["candidate_evidence"] = top_candidate.get("evidence", [])
    reasons.append("single_candidate_proposal_only")
    return _result("PROPOSE_MATCH", reasons, evidence)


def _result(decision: str, reason_codes: list[str], evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "decision": decision,
        "reason_codes": reason_codes,
        "evidence": evidence,
        "requires_human_review": decision in {"REVIEW", "EXCEPTION"},
        "may_post_to_ledger": False,
    }
