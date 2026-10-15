"""
Reconciliation Engine for matching M-Pesa Daraja callbacks to internal ledger records.

Turns raw webhook events into auditable reconciliation outcomes so operational teams
can distinguish between exact matches, partial matches, missing payments, and duplicate callbacks.
"""

from __future__ import annotations

import logging
import time
from decimal import Decimal
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Any, Dict, List, Optional, Sequence, Set, Iterable

from event_store import ProcessResult
from normalization import NormalizationError, normalize_amount
from reconciliation_scoring import score_match

try:
    from .smart_reconciliation_algorithms import (
        assess_rule_based_risk,
        rank_reconciliation_candidates,
        validate_transaction_quality,
    )
except ImportError:  # pragma: no cover - fallback for top-level script execution
    from smart_reconciliation_algorithms import (
        assess_rule_based_risk,
        rank_reconciliation_candidates,
        validate_transaction_quality,
    )

# Import normalization helpers (added in feat/phase1-reconciliation-systematic)
try:
    from .reconciliation_utils import normalize_daraja_event, time_window_match
except ImportError:  # pragma: no cover - fallback for top-level script execution
    from reconciliation_utils import normalize_daraja_event, time_window_match

logger = logging.getLogger("pesaguard.reconciliation_engine")


RECONCILIATION_STATUSES = frozenset({
    "MATCHED", "UNMATCHED", "PARTIAL", "MISMATCH", "DUPLICATE", "PENDING", "EXCEPTION",
})
ENGINE_VERSION = "phase3.2"


class ReconciliationEngine:
    """Versioned raw-transaction-to-ledger reconciliation pipeline."""

    def __init__(self, *, tolerance_percent: Decimal = Decimal("0.5"), window_seconds: int = 900):
        self.tolerance_percent = Decimal(str(tolerance_percent))
        self.window_seconds = max(0, int(window_seconds))

    def reconcile(
        self,
        raw_transaction: Dict[str, Any],
        internal_records: Sequence[Dict[str, Any]],
        *,
        seen_transaction_ids: Optional[Set[str]] = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        started = time.perf_counter()
        now = now or datetime.now(timezone.utc)
        try:
            transaction = self._normalize_transaction(raw_transaction)
            records = [self._normalize_record(record) for record in internal_records]
        except (TypeError, ValueError) as exc:
            return self._result("EXCEPTION", None, [], 0.0, started, now, reason=str(exc))

        transaction_id = transaction.get("transaction_id")
        if not transaction_id:
            return self._result("EXCEPTION", None, [], 0.0, started, now, reason="missing transaction id")

        scope_conflicts = [
            {"candidate_id": str(record.get("internal_ref") or "unknown"), "reason_codes": _explicit_scope_conflicts(transaction, record)}
            for record in records
            if _explicit_scope_conflicts(transaction, record)
        ]
        if scope_conflicts:
            reason_codes = sorted({code for item in scope_conflicts for code in item["reason_codes"]})
            return self._result(
                "EXCEPTION",
                None,
                ["candidate_scope_conflict", *reason_codes],
                0.0,
                started,
                now,
                reason="candidate set contains explicit tenant/provider/account/currency scope conflicts",
            )

        transaction_type = transaction.get("transaction_type")
        if transaction_type in {"refund", "reversal"} and not transaction.get("original_reference"):
            return self._result(
                "EXCEPTION",
                None,
                [f"{transaction_type}_requires_original_reference"],
                0.0,
                started,
                now,
                reason=f"{transaction_type} requires original transaction reference",
            )
        if seen_transaction_ids and transaction_id in seen_transaction_ids:
            return self._result("DUPLICATE", None, ["duplicate_transaction_id"], 1.0, started, now)

        if transaction_type in {"refund", "reversal"}:
            records = [
                record for record in records
                if record.get("original_reference") == transaction.get("original_reference")
                or record.get("reference") == transaction.get("original_reference")
            ]
            if not records:
                return self._result("UNMATCHED", None, ["original_transaction_missing"], 0.0, started, now)

        duplicate_records = [record for record in records if self._reference_matches(transaction, record)]
        if len(duplicate_records) > 1:
            return self._result("DUPLICATE", None, ["duplicate_internal_reference"], 1.0, started, now)
        if not records:
            return self._result("UNMATCHED", None, ["missing_internal_record"], 0.0, started, now)

        exact = self._exact_match(transaction, records)
        if exact:
            status = "PENDING" if exact.get("_pending_match") else "MATCHED"
            return self._result(status, exact, ["reference_exact", "amount_exact", "timestamp_within_window"], 1.0, started, now)

        same_reference = [record for record in records if self._reference_matches(transaction, record)]
        if same_reference:
            candidate = same_reference[0]
            amount_delta = abs(transaction["amount"] - candidate["amount"])
            if candidate.get("amount", Decimal("0")) < transaction["amount"]:
                status = "PARTIAL"
                rules = ["reference_exact", "partial_amount"]
            elif amount_delta > self._tolerance(transaction["amount"]):
                status = "MISMATCH"
                rules = ["reference_exact", "amount_mismatch"]
            else:
                status = "PARTIAL"
                rules = ["reference_exact", "amount_within_tolerance"]
            if not self._time_matches(transaction, candidate):
                rules.append("timestamp_mismatch")
                if status == "PARTIAL":
                    status = "MISMATCH"
            score = self._score(transaction, candidate)
            if transaction_type in {"refund", "reversal"}:
                rules.append(f"{transaction_type}_original_reference")
            return self._result(status, candidate, rules, score, started, now)

        tolerant = [record for record in records if self._amount_matches(transaction, record) and self._time_matches(transaction, record)]
        if tolerant:
            ranked = sorted(
                ((self._score(transaction, record), record) for record in tolerant),
                key=lambda item: item[0],
                reverse=True,
            )
            if len(ranked) > 1 and abs(ranked[0][0] - ranked[1][0]) < 0.05:
                return self._result("EXCEPTION", None, ["ambiguous_candidate_match"], 0.0, started, now)
            score, candidate = ranked[0]
            return self._result("PARTIAL", candidate, ["amount_within_tolerance", "timestamp_within_window"], score, started, now)

        amount_match = [record for record in records if self._amount_matches(transaction, record)]
        if amount_match:
            ranked = sorted(
                ((self._score(transaction, record), record) for record in amount_match),
                key=lambda item: item[0],
                reverse=True,
            )
            if len(ranked) > 1 and abs(ranked[0][0] - ranked[1][0]) < 0.05:
                return self._result("EXCEPTION", None, ["ambiguous_candidate_match"], 0.0, started, now)
            score, candidate = ranked[0]
            return self._result("MISMATCH", candidate, ["amount_match", "timestamp_mismatch_or_reference_mismatch"], score, started, now)

        return self._result("UNMATCHED", None, ["no_matching_candidate"], 0.0, started, now)

    def _normalize_transaction(self, value: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("transaction must be an object")
        amount = self._amount(value.get("TransAmount", value.get("amount")))
        timestamp = _parse_event_time(value.get("TransTime", value.get("timestamp")))
        return {
            "transaction_id": str(value.get("TransID") or value.get("trans_id") or "").strip(),
            "reference": str(value.get("BillRefNumber") or value.get("reference") or value.get("TransID") or "").strip(),
            "amount": amount,
            "timestamp": timestamp,
            "phone": str(value.get("MSISDN") or value.get("phone_number") or "").strip(),
            "transaction_type": str(value.get("TransactionType") or value.get("transaction_type") or "payment").strip().lower(),
            "original_reference": str(
                value.get("OriginalTransID")
                or value.get("OriginalTransactionID")
                or value.get("original_transaction_id")
                or value.get("original_reference")
                or ""
            ).strip(),
            "tenant_id": value.get("tenant_id") or value.get("tenantId") or value.get("TenantID"),
            "provider": value.get("provider") or value.get("provider_name") or value.get("providerName"),
            "provider_account_id": value.get("provider_account_id") or value.get("account_id") or value.get("BusinessShortCode") or value.get("business_short_code"),
            "currency": value.get("currency") or value.get("Currency"),
        }

    def _normalize_record(self, value: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("internal record must be an object")
        amount = self._amount(value.get("amount", value.get("TransAmount")))
        return {
            "internal_ref": value.get("internal_ref"),
            "reference": str(value.get("reference") or value.get("merchant_ref") or value.get("internal_ref") or "").strip(),
            "original_reference": str(
                value.get("original_transaction_id")
                or value.get("original_reference")
                or value.get("original_ref")
                or ""
            ).strip(),
            "amount": amount,
            "timestamp": _parse_record_time(value.get("timestamp") or value.get("created_at") or value.get("synced_at")),
            "phone": str(value.get("phone_number") or value.get("MSISDN") or value.get("msisdn") or "").strip(),
            "status": str(value.get("status") or "").strip().lower(),
            "tenant_id": value.get("tenant_id") or value.get("tenantId") or value.get("TenantID"),
            "provider": value.get("provider") or value.get("provider_name") or value.get("providerName"),
            "provider_account_id": value.get("provider_account_id") or value.get("account_id") or value.get("merchant_account_id") or value.get("BusinessShortCode") or value.get("business_short_code"),
            "currency": value.get("currency") or value.get("Currency"),
            "record": value,
        }

    @staticmethod
    def _amount(value: Any) -> Decimal:
        try:
            return Decimal(normalize_amount(value))
        except NormalizationError as exc:
            raise ValueError(str(exc)) from exc

    def _tolerance(self, amount: Decimal) -> Decimal:
        return max(Decimal("0.01"), abs(amount) * self.tolerance_percent / Decimal("100"))

    def _time_matches(self, transaction: Dict[str, Any], record: Dict[str, Any]) -> bool:
        if transaction["timestamp"] is None:
            return False
        if record["timestamp"] is None:
            # The internal ledger record has no timestamp yet (e.g. it has not
            # finished syncing). That is missing data, not evidence the two
            # events happened far apart, so it must not sink an otherwise
            # exact reference+amount match to MISMATCH.
            return True
        return abs((transaction["timestamp"] - record["timestamp"]).total_seconds()) <= self.window_seconds

    def _amount_matches(self, transaction: Dict[str, Any], record: Dict[str, Any]) -> bool:
        return abs(transaction["amount"] - record["amount"]) <= self._tolerance(transaction["amount"])

    @staticmethod
    def _reference_matches(transaction: Dict[str, Any], record: Dict[str, Any]) -> bool:
        if transaction.get("transaction_type") in {"refund", "reversal"}:
            return bool(transaction.get("original_reference")) and (
                record.get("original_reference") == transaction.get("original_reference")
                or record.get("reference") == transaction.get("original_reference")
            )
        return record.get("reference") == transaction.get("reference")

    def _exact_match(self, transaction: Dict[str, Any], records: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        for record in records:
            if (
                self._reference_matches(transaction, record)
                and record["amount"] == transaction["amount"]
                and self._time_matches(transaction, record)
                and (not transaction["phone"] or not record["phone"] or transaction["phone"] == record["phone"])
            ):
                if record.get("status") == "pending":
                    return {**record, "_pending_match": True}
                return record
        return None

    def _score(self, transaction: Dict[str, Any], record: Dict[str, Any]) -> float:
        score = Decimal("0")
        score += Decimal("0.45") if transaction["reference"] and transaction["reference"] == record["reference"] else Decimal("0")
        score += Decimal("0.30") if transaction["amount"] == record["amount"] else Decimal("0.15") if self._amount_matches(transaction, record) else Decimal("0")
        score += Decimal("0.15") if self._time_matches(transaction, record) else Decimal("0")
        score += Decimal("0.10") if transaction["phone"] and transaction["phone"] == record["phone"] else Decimal("0")
        return float(min(Decimal("1"), score))

    def _result(self, status: str, record: Optional[Dict[str, Any]], rules: List[str], score: float, started: float, now: datetime, *, reason: Optional[str] = None) -> Dict[str, Any]:
        evidence = {
            "matched_record": record.get("record", record) if record else None,
            "matching_rules": rules,
            "match_score": score,
            "match_timestamp": now.isoformat(),
            "engine_version": ENGINE_VERSION,
        }
        result = {
            "status": status,
            "evidence": evidence,
            "processing_latency_ms": (time.perf_counter() - started) * 1000,
        }
        if reason:
            result["reason"] = reason
        return result


def measure_reconciliation(
    results: Iterable[Dict[str, Any]],
    expected_statuses: Iterable[str],
) -> Dict[str, float | None]:
    """Calculate reconciliation metrics without hiding undefined denominators.

    Precision is unavailable when the engine predicts no matches; recall is
    unavailable when the reviewed dataset contains no expected matches. Returning
    1.0 for either case would falsely imply perfect performance. The input lengths
    must agree so a truncated zip cannot silently discard evaluated cases.
    """
    started = time.perf_counter()
    actual = list(results)
    expected = list(expected_statuses)
    if len(actual) != len(expected):
        raise ValueError(
            "results and expected_statuses must contain the same number of cases "
            f"(got {len(actual)} results and {len(expected)} expected statuses)"
        )

    correct = sum(
        result.get("status") == expected_status
        for result, expected_status in zip(actual, expected)
    )
    positives = sum(status == "MATCHED" for status in expected)
    predicted_positives = sum(result.get("status") == "MATCHED" for result in actual)
    true_positives = sum(
        result.get("status") == expected_status == "MATCHED"
        for result, expected_status in zip(actual, expected)
    )
    false_positives = predicted_positives - true_positives
    false_negatives = positives - true_positives
    elapsed = max(time.perf_counter() - started, 0.000001)
    return {
        "precision": true_positives / predicted_positives if predicted_positives else None,
        "recall": true_positives / positives if positives else None,
        "false_positives": float(false_positives),
        "false_negatives": float(false_negatives),
        "known_cases": float(len(expected)),
        "correct_cases": float(correct),
        "processing_latency_ms": (
            sum(float(result.get("processing_latency_ms", 0)) for result in actual) / len(actual)
            if actual else 0.0
        ),
        "throughput_per_second": len(actual) / elapsed,
    }


def record_ground_truth(
    session: Any,
    *,
    tenant_id: str,
    transaction_id: str,
    expected_status: str,
    approved_by: str,
    approval_reference: str,
    actual_status: Optional[str] = None,
    validated_by: Optional[str] = None,
    notes: Optional[str] = None,
) -> Any:
    """Create or validate one certification ground-truth case transactionally."""
    from models import ReconciliationGroundTruth

    if not approved_by.strip() or not approval_reference.strip():
        raise ValueError("approved_by and approval_reference are required")
    if expected_status not in RECONCILIATION_STATUSES:
        raise ValueError(f"unsupported expected reconciliation status: {expected_status}")
    if actual_status is not None and actual_status not in RECONCILIATION_STATUSES:
        raise ValueError(f"unsupported actual reconciliation status: {actual_status}")
    row = session.query(ReconciliationGroundTruth).filter_by(
        tenant_id=tenant_id,
        transaction_id=transaction_id,
    ).one_or_none()
    if row is None:
        row = ReconciliationGroundTruth(
            id=f"truth_{tenant_id}_{transaction_id}",
            tenant_id=tenant_id,
            transaction_id=transaction_id,
            expected_status=expected_status,
            approved_by=approved_by.strip(),
            approval_reference=approval_reference.strip(),
            approved_at=datetime.now(timezone.utc),
        )
        session.add(row)
    elif row.expected_status != expected_status:
        raise ValueError("ground-truth status cannot be changed after registration")
    elif row.approved_by != approved_by.strip() or row.approval_reference != approval_reference.strip():
        raise ValueError("ground-truth approval metadata cannot be changed")
    row.actual_status = actual_status
    row.validated_by = validated_by
    row.notes = notes
    row.validated_at = datetime.now(timezone.utc) if actual_status is not None else None
    return row


def _smart_shadow_assessment(
    event: Dict[str, Any],
    internal_records: Sequence[Dict[str, Any]],
    *,
    tenant_id: str,
    duplicate: bool,
    anomalies: Sequence[str],
    window_minutes: int,
    tolerance_percent: Decimal,
) -> Dict[str, Any]:
    """Run new algorithms in shadow mode; never changes the legacy match decision."""
    event_time = _parse_event_time(event.get("TransTime") or event.get("timestamp"))
    normalized_event = {
        "transaction_id": event.get("TransID") or event.get("trans_id"),
        "reference": event.get("BillRefNumber") or event.get("reference"),
        "amount": event.get("TransAmount", event.get("amount")),
        "timestamp": event_time.isoformat() if event_time else None,
        "phone": event.get("MSISDN") or event.get("phone_number"),
    }
    quality = validate_transaction_quality(normalized_event)
    candidates = []
    for record in internal_records:
        record_time = _parse_record_time(
            record.get("timestamp") or record.get("synced_at") or record.get("created_at")
        )
        candidates.append({
            **record,
            "internal_ref": record.get("internal_ref") or record.get("id"),
            "reference": record.get("reference") or record.get("merchant_ref"),
            "amount": record.get("amount"),
            "timestamp": record_time.isoformat() if record_time else None,
            "phone": record.get("phone_number") or record.get("msisdn"),
        })
    amount = _coerce_amount(normalized_event.get("amount"))
    tolerance = max(
        Decimal("0.01"),
        abs(amount or Decimal("0")) * tolerance_percent / Decimal("100"),
    )
    ranking = rank_reconciliation_candidates(
        normalized_event,
        candidates,
        window_seconds=max(0, int(window_minutes) * 60),
        amount_tolerance=tolerance,
    )
    top = ranking.get("top_candidate") or {}
    conflicts = set(top.get("conflicts") or ())
    risk = assess_rule_based_risk(
        duplicate=duplicate,
        reference_conflict="reference_conflict" in conflicts,
        phone_conflict="phone_conflict" in conflicts,
        invalid_payload=not quality["valid_for_automatic_matching"],
        reversal_without_original=(
            str(event.get("TransactionType") or event.get("transaction_type") or "").strip().lower()
            in {"refund", "reversal"}
            and not str(
                event.get("OriginalTransID")
                or event.get("OriginalTransactionID")
                or event.get("original_transaction_id")
                or event.get("original_reference")
                or ""
            ).strip()
        ),
    )
    return {
        "enabled": True,
        "mode": "shadow",
        "algorithm_version": ranking["algorithm_version"],
        "quality": quality,
        "candidate_ranking": ranking,
        "risk": {
            "score": risk.score,
            "level": risk.level,
            "action": risk.action,
            "signals": list(risk.signals),
        },
        "legacy_decision_unchanged": True,
        "observed_anomalies": list(anomalies),
        "tenant_scope": tenant_id,
    }


def evaluate_transaction(
    event: Dict[str, Any],
    internal_records: Sequence[Dict[str, Any]],
    seen_trans_ids: Set[str],
    window_minutes: int = 15,
    tenant_settings: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluate one M-Pesa event against a set of internal records.

    Args:
        event: Daraja callback payload dict
        internal_records: List of internal order/payment dicts
        seen_trans_ids: Set of recently observed transaction IDs
        window_minutes: Default matching time window in minutes
        tenant_settings: Optional tenant-specific settings dict for custom rules

    Returns:
        Structured evaluation outcome dict
    """
    original_amount = event.get("TransAmount")
    if original_amount is None:
        original_amount = event.get("amount")

    # Normalize incoming event into canonical keys without discarding original keys.
    # This preserves backwards compatibility while centralizing parsing/format logic.
    try:
        norm = normalize_daraja_event(event, tenant_id=str(tenant_settings.get("tenant_id")) if tenant_settings else "default")
    except Exception:
        norm = {}
    # Merge normalized canonical keys into the event for the rest of the engine to use.
    merged_event = dict(event or {})
    merged_event.update(norm or {})
    if original_amount is not None:
        merged_event["TransAmount"] = original_amount
        merged_event["amount"] = original_amount
    # Keep the authenticated tenant context on the event so the matching guard
    # can detect a mistakenly mixed candidate set before any automatic match.
    if tenant_settings and tenant_settings.get("tenant_id"):
        merged_event["tenant_id"] = str(tenant_settings["tenant_id"])
    event = merged_event

    trans_id = str(event.get("TransID") or event.get("trans_id") or "unknown").strip()
    duplicate = trans_id in seen_trans_ids

    anomalies: List[str] = []
    if duplicate:
        anomalies.append("duplicate_transaction_id")

    event_time = _parse_event_time(event.get("TransTime"))
    if event_time:
        latency = (datetime.now(timezone.utc) - event_time).total_seconds()
        if latency > 3600:
            anomalies.append("late_arriving_event")

    amount = _coerce_amount(event.get("TransAmount") or event.get("amount"))
    if amount is None or amount <= 0:
        anomalies.append("invalid_or_zero_amount")

    # Resolve tenant config overrides
    reconciliation_cfg = (tenant_settings or {}).get("reconciliation", {}) if tenant_settings else {}
    tolerance_percent = Decimal(str(reconciliation_cfg.get("tolerance_percent", "0.5")))
    allow_partial = bool(reconciliation_cfg.get("allow_partial", True))
    
    if reconciliation_cfg.get("window_minutes") is not None:
        try:
            window_minutes = int(reconciliation_cfg["window_minutes"])
        except (TypeError, ValueError):
            pass

    smart_analysis = None
    if reconciliation_cfg.get("smart_algorithms_shadow_enabled") is True:
        try:
            smart_analysis = _smart_shadow_assessment(
                event,
                internal_records,
                tenant_id=str((tenant_settings or {}).get("tenant_id") or "default"),
                duplicate=duplicate,
                anomalies=anomalies,
                window_minutes=window_minutes,
                tolerance_percent=tolerance_percent,
            )
        except (TypeError, ValueError, ArithmeticError):
            # Shadow analysis must never break the established payment pipeline.
            smart_analysis = {
                "enabled": True,
                "mode": "shadow",
                "available": False,
                "reason": "shadow_analysis_unavailable",
                "legacy_decision_unchanged": True,
            }

    if not internal_records:
        return {
            "trans_id": trans_id,
            "status": "missing_payment",
            "severity": "critical",
            "duplicate": duplicate,
            "anomalies": anomalies,
            "match": {"match_type": "none", "reason": "no_internal_records"},
            **({"smart_analysis": smart_analysis} if smart_analysis is not None else {}),
        }

    best_match = _find_best_match(
        event,
        internal_records,
        window_minutes=window_minutes,
        tolerance_percent=tolerance_percent,
        allow_partial=allow_partial,
    )

    if best_match and best_match.get("match_type") == "scope_conflict":
        anomalies.append("candidate_scope_conflict")
        return {
            "trans_id": trans_id,
            "status": "needs_review",
            "severity": "critical",
            "duplicate": duplicate,
            "anomalies": anomalies,
            "match": best_match,
            **({"smart_analysis": smart_analysis} if smart_analysis is not None else {}),
        }

    if best_match is None:
        return {
            "trans_id": trans_id,
            "status": "missing_payment",
            "severity": "critical",
            "duplicate": duplicate,
            "anomalies": anomalies,
            "match": {"match_type": "none", "reason": "no_matching_record"},
            **({"smart_analysis": smart_analysis} if smart_analysis is not None else {}),
        }

    # Only exact amount + phone + available timestamp evidence may auto-match.
    # A tolerance-based amount match is useful for ranking, but financial
    # differences—even small ones—must be reviewed rather than silently settled.
    if best_match["match_type"] == "exact" and not best_match.get("ambiguous"):
        return {
            "trans_id": trans_id,
            "status": "matched",
            "severity": "info",
            "duplicate": duplicate,
            "anomalies": anomalies,
            "match": best_match,
            **({"smart_analysis": smart_analysis} if smart_analysis is not None else {}),
        }

    return {
        "trans_id": trans_id,
        "status": "needs_review",
        "severity": "warning",
        "duplicate": duplicate,
        "anomalies": anomalies,
        "match": best_match,
        **({"smart_analysis": smart_analysis} if smart_analysis is not None else {}),
    }


def _explicit_scope_conflicts(event: Dict[str, Any], record: Dict[str, Any]) -> List[str]:
    """Return only explicit scope disagreements; missing metadata is not a match.

    Candidate retrieval must still be tenant-scoped at the database layer. This
    guard is a second line of defense against accidentally mixed candidate sets.
    """
    aliases = {
        "tenant": (
            ("tenant_id", "tenantId", "TenantID"),
            ("tenant_id", "tenantId", "TenantID"),
        ),
        "provider": (
            ("provider", "provider_name", "providerName"),
            ("provider", "provider_name", "providerName"),
        ),
        "account": (
            ("provider_account_id", "account_id", "merchant_account_id", "BusinessShortCode", "business_short_code"),
            ("provider_account_id", "account_id", "merchant_account_id", "BusinessShortCode", "business_short_code"),
        ),
        "currency": (
            ("currency", "Currency"),
            ("currency", "Currency"),
        ),
    }
    conflicts: List[str] = []
    for scope, (left_keys, right_keys) in aliases.items():
        left = next((event.get(key) for key in left_keys if event.get(key) not in (None, "")), None)
        right = next((record.get(key) for key in right_keys if record.get(key) not in (None, "")), None)
        if left is None or right is None:
            continue
        left_text, right_text = str(left).strip(), str(right).strip()
        if scope in {"provider", "currency"}:
            left_text, right_text = left_text.casefold(), right_text.casefold()
        if left_text != right_text:
            conflicts.append(f"{scope}_scope_conflict")
    return conflicts


def _find_best_match(
    event: Dict[str, Any],
    internal_records: Sequence[Dict[str, Any]],
    window_minutes: int = 15,
    tolerance_percent: Decimal = Decimal("0.5"),
    allow_partial: bool = True,
) -> Optional[Dict[str, Any]]:
    """Match callback event against candidate internal records."""
    amount = _coerce_amount(event.get("TransAmount") or event.get("amount"))
    if amount is None or amount <= 0:
        return None

    phone = str(event.get("MSISDN") or event.get("phone_number") or "").strip()
    event_time = _parse_event_time(event.get("TransTime"))
    allowed_delta = max(Decimal("0.01"), abs(amount) * (tolerance_percent / Decimal("100")))

    candidates = []
    scope_conflicts: List[Dict[str, Any]] = []
    for record in internal_records:
        conflicts = _explicit_scope_conflicts(event, record)
        if conflicts:
            scope_conflicts.append({
                "internal_ref": record.get("internal_ref") or record.get("id"),
                "reason_codes": conflicts,
            })
            continue

        record_time = _parse_record_time(record.get("timestamp") or record.get("synced_at") or record.get("created_at"))
        
        latency = 0
        if record_time is not None and event_time is not None:
            latency = int(abs((event_time - record_time).total_seconds()))
            if latency > window_minutes * 60:
                continue

        record_amount = _coerce_amount(record.get("amount"))
        if record_amount is None:
            continue

        amt_diff = abs(record_amount - amount)
        if amt_diff > allowed_delta:
            continue

        record_phone = str(record.get("phone_number") or record.get("msisdn") or "").strip()
        phone_matches = record_phone == phone and len(phone) > 0

        if phone_matches and amt_diff == 0 and event_time is not None and record_time is not None:
            match_type = "exact"
        elif phone_matches and amt_diff <= allowed_delta:
            # Includes near-amount matches and exact amounts without timestamp
            # evidence; both remain reviewable instead of auto-approved.
            match_type = "fuzzy_exact"
        elif not phone_matches and allow_partial:
            match_type = "partial_fuzzy" if amt_diff <= allowed_delta else "partial"
        else:
            continue

        candidate_score, candidate_reasons = score_match(event, record)
        candidates.append({
            "match_type": match_type,
            "internal_ref": record.get("internal_ref"),
            "record": record,
            "latency_seconds": latency,
            "amount_diff": amt_diff,
            "score": candidate_score,
            "reasons": candidate_reasons,
        })

    # An explicitly cross-tenant/provider/account/currency candidate is a
    # data-isolation invariant violation, not merely a weak match. Fail closed
    # even if another candidate looked plausible; the caller must fix the query
    # scope and review the event rather than silently matching from a mixed set.
    if scope_conflicts:
        return {
            "match_type": "scope_conflict",
            "ambiguous": True,
            "candidate_count": 0,
            "excluded_candidate_count": len(scope_conflicts),
            "excluded_candidates": scope_conflicts,
            "reason_codes": sorted({code for item in scope_conflicts for code in item["reason_codes"]}),
        }
    if not candidates:
        return None

    priority = {"exact": 0, "fuzzy_exact": 1, "partial_fuzzy": 2, "partial": 3}
    # Deterministic tie-breaking makes repeated runs auditable and reproducible.
    candidates.sort(
        key=lambda item: (
            -item.get("score", 0.0),
            priority.get(item["match_type"], 99),
            item["latency_seconds"],
            item["amount_diff"],
            str(item.get("internal_ref") or ""),
            str((item.get("record") or {}).get("id") or ""),
        )
    )

    best = dict(candidates[0])
    best_score = float(best.get("score", 0.0))
    second = candidates[1] if len(candidates) > 1 else None
    score_gap = best_score - float(second.get("score", 0.0)) if second else 1.0

    # Never silently auto-approve when two different ledger records are
    # similarly plausible. Equal amount/phone/time values occur legitimately
    # in payment systems; choosing the first row would create a false match.
    ambiguity_gap = 0.03
    ambiguous = bool(second and score_gap <= ambiguity_gap)
    best["candidate_count"] = len(candidates)
    best["confidence_gap"] = round(max(0.0, score_gap), 6)
    best["ambiguous"] = ambiguous
    if ambiguous:
        best["original_match_type"] = best["match_type"]
        best["match_type"] = "ambiguous"
        best["review_reason"] = "multiple_candidates_with_similar_scores"
        best["candidate_internal_refs"] = [
            str(item.get("internal_ref") or (item.get("record") or {}).get("id") or "unknown")
            for item in candidates[:5]
        ]
    return best


def _coerce_amount(value: Any) -> Optional[Decimal]:
    """Safely parse monetary values as fixed-precision decimals."""
    if value is None:
        return None
    try:
        return Decimal(normalize_amount(value))
    except NormalizationError:
        return None


def _parse_event_time(value: Any) -> Optional[datetime]:
    """Parse M-Pesa 14-digit Daraja timestamp strings or ISO timestamps into UTC datetimes."""
    if not value:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    text = str(value).strip()
    if len(text) == 14 and text.isdigit():
        try:
            return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=ZoneInfo("Africa/Nairobi")).astimezone(timezone.utc)
        except ValueError:
            return None

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _parse_record_time(value: Any) -> Optional[datetime]:
    return _parse_event_time(value)


def reconcile_with_idempotency(
    event: Dict[str, Any],
    internal_records: Sequence[Dict[str, Any]],
    event_store: Any,
    discrepancy_dao: Any,
    session: Any,
    tenant_id: Optional[str] = None,
    tenant_settings: Optional[Dict[str, Any]] = None,
    window_minutes: int = 15,
    source_ip: Optional[str] = None,
    signature_verified: bool = False,
) -> Dict[str, Any]:
    """Atomically evaluate and record reconciliation outcomes inside a single database transaction.

    Ensures that both the idempotency ledger write and the Discrepancy write commit
    together or roll back entirely.
    """
    trans_id = str(event.get("TransID") or event.get("trans_id") or "unknown").strip()
    account_id = str(event.get("provider_account_id") or event.get("BusinessShortCode") or event.get("business_short_code") or "legacy-default")

    # Compare canonical facts before taking the duplicate fast path. A repeated
    # transaction ID with changed facts is quarantined, not silently accepted.
    replay_result = None
    if event_store and hasattr(event_store, "classify_existing_replay"):
        replay_result = event_store.classify_existing_replay(
            event,
            tenant_id=str(tenant_id or "default"),
            provider=str(event.get("provider") or event.get("provider_name") or "mpesa").strip().lower(),
            account_id=account_id,
            trans_id=trans_id,
        )
    elif event_store and event_store.already_processed(
        trans_id, tenant_id=tenant_id, provider_account=account_id
    ):
        replay_result = ProcessResult.DUPLICATE

    if replay_result == ProcessResult.DUPLICATE:
        logger.info("Idempotency: identical replay trans_id=%s detected before evaluation", trans_id)
        return {
            "trans_id": trans_id,
            "status": "duplicate_ignored",
            "severity": "info",
            "anomalies": ["duplicate_transaction_id"],
        }
    if replay_result == ProcessResult.CONFLICT:
        logger.error("Conflicting replay trans_id=%s quarantined before reconciliation", trans_id)
        return {
            "trans_id": trans_id,
            "status": "needs_review",
            "severity": "critical",
            "anomalies": ["conflicting_transaction_replay"],
            "reason_codes": ["same_external_id_different_payload"],
        }
    if replay_result == ProcessResult.ERROR:
        raise RuntimeError(f"replay classification failed closed for trans_id={trans_id}")

    seen_trans_ids: Set[str] = set()
    evaluation = evaluate_transaction(
        event,
        internal_records,
        seen_trans_ids,
        window_minutes=window_minutes,
        tenant_settings=tenant_settings,
    )
    evaluation["tenant_id"] = tenant_id or "default"
    evaluation["event"] = event

    try:
        result = ProcessResult.STORED
        if event_store:
            result = event_store.mark_processed_in_session(
                session,
                event,
                tenant_id=tenant_id,
                source_ip=source_ip,
                signature_verified=signature_verified,
            )

        if result == ProcessResult.CONFLICT:
            # The classifier wrote quarantine/audit evidence into this session.
            # Commit only that evidence and never continue with a new transaction.
            session.commit()
            logger.error("Conflicting replay trans_id=%s quarantined during atomic ingestion", trans_id)
            return {
                "trans_id": trans_id,
                "status": "needs_review",
                "severity": "critical",
                "anomalies": ["conflicting_transaction_replay"],
                "reason_codes": ["same_external_id_different_payload"],
            }

        if result == ProcessResult.DUPLICATE:
            session.rollback()
            logger.info("Duplicate trans_id=%s caught during idempotency session flush, skipping", trans_id)
            return {
                "trans_id": trans_id,
                "status": "duplicate_ignored",
                "severity": "info",
                "anomalies": ["duplicate_transaction_id"],
            }

        if result == ProcessResult.ERROR:
            session.rollback()
            raise RuntimeError(f"mark_processed_in_session failed validation for trans_id={trans_id}")

        # Record discrepancy for non-matched or anomalous transactions
        if evaluation.get("status") in {"needs_review", "missing_payment"} or evaluation.get("anomalies"):
            if discrepancy_dao:
                disc_id = f"{trans_id}-{evaluation.get('status', 'unknown')}"
                discrepancy_dao.save_discrepancy(
                    session=session,
                    id=disc_id,
                    trans_id=trans_id,
                    tenant_id=tenant_id,
                    anomaly_type=evaluation.get("status", "unknown"),
                    severity=evaluation.get("severity", "warning"),
                    details=evaluation,
                )

        session.commit()
        evaluation["duplicate"] = False
        return evaluation

    except Exception as exc:
        logger.exception("Error during atomic reconciliation for trans_id=%s — rolling back: %s", trans_id, exc)
        session.rollback()
        raise
