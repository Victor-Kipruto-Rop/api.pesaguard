"""Deterministic, explainable algorithms for PesaGuard's transaction pipeline.

These pure functions are safe to evaluate independently of persistence and providers.
They deliberately do not auto-block or auto-approve payments: callers must combine
signals with tenant policy, verified ledger state, and human review thresholds.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
import math
import statistics
from typing import Any, Iterable, Mapping, Sequence


ALGORITHM_VERSION = "smart-reconciliation-v1"
CENT = Decimal("0.01")


def _decimal(value: Any) -> Decimal | None:
    """Parse finite monetary values without accepting booleans, NaN, or infinity."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError):
        return None
    return parsed if parsed.is_finite() else None


def _normalized_text(value: Any) -> str:
    return " ".join(str(value or "").strip().casefold().split())


def _utc_timestamp(value: Any) -> datetime | None:
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
    if parsed.tzinfo is None:
        # Naive values are ambiguous. Do not silently assume local time.
        return None
    return parsed.astimezone(timezone.utc)


def transaction_fingerprint(
    transaction: Mapping[str, Any],
    *,
    tenant_id: str,
    provider: str = "mpesa",
) -> str:
    """Return a stable, tenant-scoped SHA-256 fingerprint for duplicate triage.

    Provider transaction ID is preferred. Fallback fingerprinting requires a finite
    amount, timezone-aware timestamp, and at least a reference or phone. Incomplete
    payloads raise ValueError rather than collapsing into a shared empty fingerprint.
    Fallback collisions remain candidates, not authoritative duplicates.
    """
    tenant = str(tenant_id).strip()
    if not tenant:
        raise ValueError("tenant_id is required")
    tx_id = _normalized_text(
        transaction.get("transaction_id")
        or transaction.get("TransID")
        or transaction.get("trans_id")
    )
    if tx_id:
        material = {"tenant": tenant, "provider": _normalized_text(provider), "id": tx_id}
    else:
        amount = _decimal(transaction.get("amount", transaction.get("TransAmount")))
        timestamp = _utc_timestamp(transaction.get("timestamp", transaction.get("TransTime")))
        reference = _normalized_text(transaction.get("reference") or transaction.get("BillRefNumber"))
        phone = "".join(ch for ch in str(transaction.get("phone") or transaction.get("MSISDN") or "") if ch.isdigit())

        # Fail closed instead of hashing empty/partial payloads into the same
        # fingerprint. A fallback fingerprint is useful only when it has enough
        # independent evidence to distinguish plausible transactions.
        if amount is None or timestamp is None or not (reference or phone):
            raise ValueError(
                "transaction_id is required unless fallback fingerprint has a finite amount, "
                "timezone-aware timestamp, and reference or phone"
            )

        material = {
            "tenant": tenant,
            "provider": _normalized_text(provider),
            "reference": reference,
            "amount": format(amount.quantize(CENT), "f"),
            "timestamp": timestamp.isoformat(),
            "phone": phone,
        }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256(encoded).hexdigest()


@dataclass(frozen=True)
class CandidateScore:
    candidate_id: str
    score: float
    evidence: tuple[str, ...]
    conflicts: tuple[str, ...]


def score_reconciliation_candidate(
    transaction: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    window_seconds: int = 900,
    amount_tolerance: Decimal | str = Decimal("0.01"),
) -> CandidateScore:
    """Score one ledger candidate using explicit evidence and conflicts.

    The score is a ranking signal, not a probability. Exact reference and amount
    dominate; phone/time conflicts lower the score and are exposed separately.
    """
    if window_seconds < 0:
        raise ValueError("window_seconds must be non-negative")
    tolerance = _decimal(amount_tolerance)
    if tolerance is None or tolerance < 0:
        raise ValueError("amount_tolerance must be a finite non-negative number")

    tx_ref = _normalized_text(transaction.get("reference") or transaction.get("BillRefNumber"))
    ca_ref = _normalized_text(candidate.get("reference") or candidate.get("merchant_ref"))
    tx_amount = _decimal(transaction.get("amount", transaction.get("TransAmount")))
    ca_amount = _decimal(candidate.get("amount", candidate.get("TransAmount")))
    tx_phone = "".join(ch for ch in str(transaction.get("phone") or transaction.get("MSISDN") or "") if ch.isdigit())
    ca_phone = "".join(ch for ch in str(candidate.get("phone") or candidate.get("phone_number") or candidate.get("MSISDN") or "") if ch.isdigit())
    tx_time = _utc_timestamp(transaction.get("timestamp") or transaction.get("TransTime"))
    ca_time = _utc_timestamp(candidate.get("timestamp") or candidate.get("created_at"))

    evidence: list[str] = []
    conflicts: list[str] = []
    points = 0.0
    if tx_ref and ca_ref:
        if tx_ref == ca_ref:
            points += 0.50
            evidence.append("reference_exact")
        else:
            conflicts.append("reference_conflict")
    else:
        conflicts.append("reference_missing")

    if tx_amount is not None and ca_amount is not None:
        delta = abs(tx_amount - ca_amount)
        if delta == 0:
            points += 0.30
            evidence.append("amount_exact")
        elif delta <= tolerance:
            points += 0.20
            evidence.append("amount_within_tolerance")
        else:
            conflicts.append("amount_conflict")
    else:
        conflicts.append("amount_missing_or_invalid")

    if tx_time and ca_time:
        delta_seconds = abs((tx_time - ca_time).total_seconds())
        if delta_seconds <= window_seconds:
            points += 0.12
            evidence.append("timestamp_within_window")
        else:
            conflicts.append("timestamp_outside_window")
    else:
        conflicts.append("timestamp_missing_or_ambiguous")

    if tx_phone and ca_phone:
        if tx_phone == ca_phone:
            points += 0.08
            evidence.append("phone_exact")
        else:
            conflicts.append("phone_conflict")

    candidate_id = str(candidate.get("internal_ref") or candidate.get("id") or ca_ref or "unknown")
    return CandidateScore(candidate_id, round(min(points, 1.0), 4), tuple(evidence), tuple(conflicts))


def _scope_conflicts(
    transaction: Mapping[str, Any], candidate: Mapping[str, Any]
) -> tuple[str, ...]:
    """Identify explicit cross-scope conflicts without inferring missing metadata.

    Candidate lists must already be tenant-scoped by the calling query. This
    helper adds a second line of defense: when both records expose a scope field,
    disagreement makes the candidate ineligible. Missing scope metadata is not
    proof of a mismatch and is surfaced as a caller-side verification requirement.
    """
    aliases = {
        "tenant": ("tenant_id", "TenantID", "tenantId"),
        "provider": ("provider", "provider_name", "providerName"),
        "account": ("account_id", "merchant_account_id", "account"),
        "currency": ("currency", "Currency"),
    }
    conflicts: list[str] = []
    for scope, keys in aliases.items():
        tx_value = next((transaction.get(key) for key in keys if transaction.get(key) not in (None, "")), None)
        candidate_value = next((candidate.get(key) for key in keys if candidate.get(key) not in (None, "")), None)
        if tx_value is None or candidate_value is None:
            continue
        left = str(tx_value).strip()
        right = str(candidate_value).strip()
        # Provider names and ISO currency codes are case-insensitive; tenant and
        # account identifiers remain exact to avoid merging distinct namespaces.
        if scope in {"provider", "currency"}:
            left, right = left.casefold(), right.casefold()
        if left != right:
            conflicts.append(f"{scope}_scope_conflict")
    return tuple(conflicts)


def rank_reconciliation_candidates(
    transaction: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
    *,
    window_seconds: int = 900,
    amount_tolerance: Decimal | str = Decimal("0.01"),
    ambiguity_margin: float = 0.05,
) -> dict[str, Any]:
    """Rank only scope-compatible candidates and fail closed on scope conflicts.

    This function is advisory: even a strong candidate is not an instruction to
    post a ledger entry. The caller remains responsible for tenant-scoped queries,
    transactional idempotency, verified provider state, and review policy.
    """
    if not 0 <= ambiguity_margin <= 1:
        raise ValueError("ambiguity_margin must be between 0 and 1")

    eligible: list[Mapping[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        conflicts = _scope_conflicts(transaction, candidate)
        if conflicts:
            candidate_id = str(
                candidate.get("internal_ref") or candidate.get("id")
                or candidate.get("reference") or f"candidate-{index + 1}"
            )
            excluded.append({
                "candidate_id": candidate_id,
                "reason_codes": list(conflicts),
            })
        else:
            eligible.append(candidate)

    scores = [
        score_reconciliation_candidate(
            transaction, item, window_seconds=window_seconds, amount_tolerance=amount_tolerance
        )
        for item in eligible
    ]
    scores.sort(key=lambda item: (-item.score, item.candidate_id))
    ambiguous = len(scores) > 1 and (scores[0].score - scores[1].score) < ambiguity_margin
    scope_conflict_only = not scores and bool(excluded)
    decision = (
        "REVIEW" if ambiguous or scope_conflict_only
        else ("CANDIDATE" if scores and scores[0].score > 0 else "UNMATCHED")
    )
    reason_codes = []
    if ambiguous:
        reason_codes.append("ambiguous_candidates")
    if scope_conflict_only:
        reason_codes.append("candidate_scope_conflict")
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "decision": decision,
        "ambiguous": ambiguous,
        "reason_codes": reason_codes,
        "candidate_count": len(candidates),
        "eligible_candidate_count": len(eligible),
        "excluded_candidate_count": len(excluded),
        "excluded_candidates": excluded,
        "top_candidate": asdict(scores[0]) if scores else None,
        "candidates": [asdict(item) for item in scores],
    }


def robust_amount_outliers(values: Iterable[Any], *, minimum_samples: int = 5, modified_z_threshold: float = 3.5) -> dict[str, Any]:
    """Detect amount outliers with median absolute deviation (MAD).

    For MAD=0, non-median values are reported only when distinct observations exist;
    the function does not fabricate a z-score. Values are returned by input index.
    """
    if minimum_samples < 3:
        raise ValueError("minimum_samples must be at least 3")
    if not math.isfinite(modified_z_threshold) or modified_z_threshold <= 0:
        raise ValueError("modified_z_threshold must be finite and positive")
    parsed = [(i, _decimal(v)) for i, v in enumerate(values)]
    valid = [(i, v) for i, v in parsed if v is not None]
    if len(valid) < minimum_samples:
        return {"algorithm_version": ALGORITHM_VERSION, "ready": False, "reason": "insufficient_valid_samples", "outliers": []}
    numbers = [float(v) for _, v in valid]
    median = statistics.median(numbers)
    deviations = [abs(v - median) for v in numbers]
    mad = statistics.median(deviations)
    outliers = []
    for (index, value), number in zip(valid, numbers):
        if mad > 0:
            modified_z = 0.6745 * (number - median) / mad
            if abs(modified_z) > modified_z_threshold:
                outliers.append({"index": index, "value": format(value, "f"), "modified_z": round(modified_z, 4)})
        elif number != median and len(set(numbers)) > 1:
            # A zero MAD makes standard robust z-score undefined. Mark as a
            # candidate for review rather than inventing an infinite score.
            outliers.append({"index": index, "value": format(value, "f"), "modified_z": None})
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "ready": True,
        "sample_count": len(valid),
        "median": str(median),
        "mad": str(mad),
        "outliers": outliers,
    }


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    action: str
    signals: tuple[str, ...]
    algorithm_version: str = ALGORITHM_VERSION


def assess_rule_based_risk(
    *,
    duplicate: bool = False,
    amount_outlier: bool = False,
    velocity_breach: bool = False,
    reference_conflict: bool = False,
    phone_conflict: bool = False,
    invalid_payload: bool = False,
    reversal_without_original: bool = False,
) -> RiskAssessment:
    """Combine transparent signals into a bounded review score.

    This is a triage heuristic, not a fraud probability. It never declines, reverses,
    or blocks a payment by itself. Integrators must define policy and monitor drift.
    """
    weights = {
        "duplicate_candidate": (35, duplicate),
        "amount_outlier": (20, amount_outlier),
        "velocity_breach": (20, velocity_breach),
        "reference_conflict": (30, reference_conflict),
        "phone_conflict": (15, phone_conflict),
        "invalid_payload": (25, invalid_payload),
        "reversal_without_original": (35, reversal_without_original),
    }
    signals = tuple(name for name, (_, active) in weights.items() if active)
    score = min(100, sum(weight for weight, active in weights.values() if active))
    level = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH"
    action = "REVIEW" if score >= 25 else "CONTINUE_STANDARD_CONTROLS"
    return RiskAssessment(score, level, action, signals)


def detect_velocity_breach(
    event_timestamps: Sequence[Any],
    *,
    window_seconds: int = 300,
    max_events: int = 5,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Count events inside a rolling window. Caller must pre-filter by tenant/entity."""
    if window_seconds <= 0 or max_events < 1:
        raise ValueError("window_seconds and max_events must be positive")
    current = (now or datetime.now(timezone.utc))
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    current = current.astimezone(timezone.utc)
    parsed = [_utc_timestamp(value) for value in event_timestamps]
    valid = [value for value in parsed if value is not None and value <= current]
    count = sum(1 for value in valid if (current - value).total_seconds() <= window_seconds)
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "count": count,
        "window_seconds": window_seconds,
        "limit": max_events,
        "breach": count > max_events,
        "invalid_or_future_timestamps": len(event_timestamps) - len(valid),
    }


def validate_transaction_quality(transaction: Mapping[str, Any]) -> dict[str, Any]:
    """Return deterministic quality findings without silently coercing bad inputs."""
    findings: list[dict[str, str]] = []
    tx_id = transaction.get("transaction_id") or transaction.get("TransID") or transaction.get("trans_id")
    amount = _decimal(transaction.get("amount", transaction.get("TransAmount")))
    timestamp = _utc_timestamp(transaction.get("timestamp") or transaction.get("TransTime"))
    reference = transaction.get("reference") or transaction.get("BillRefNumber")
    if not str(tx_id or "").strip():
        findings.append({"code": "MISSING_TRANSACTION_ID", "severity": "critical"})
    if amount is None:
        findings.append({"code": "INVALID_AMOUNT", "severity": "critical"})
    elif amount <= 0:
        findings.append({"code": "NON_POSITIVE_AMOUNT", "severity": "high"})
    if timestamp is None:
        findings.append({"code": "MISSING_OR_AMBIGUOUS_TIMESTAMP", "severity": "high"})
    if not str(reference or "").strip():
        findings.append({"code": "MISSING_REFERENCE", "severity": "medium"})
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "valid_for_automatic_matching": not any(item["severity"] in {"critical", "high"} for item in findings),
        "findings": findings,
    }
