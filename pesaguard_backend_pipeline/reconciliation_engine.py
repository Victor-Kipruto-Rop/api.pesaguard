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
from typing import Any, Dict, List, Optional, Sequence, Set, Iterable

from event_store import ProcessResult
from normalization import NormalizationError, normalize_amount
from reconciliation_scoring import score_match

# Import normalization helpers (added in feat/phase1-reconciliation-systematic)
try:
    from .reconciliation_utils import normalize_daraja_event, time_window_match
except ImportError:  # pragma: no cover - fallback for top-level script execution
    from reconciliation_utils import normalize_daraja_event, time_window_match

logger = logging.getLogger("pesaguard.reconciliation_engine")


RECONCILIATION_STATUSES = frozenset({
    "MATCHED", "UNMATCHED", "PARTIAL", "MISMATCH", "DUPLICATE", "PENDING", "EXCEPTION",
})
ENGINE_VERSION = "phase3.1"


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
            candidate = max(tolerant, key=lambda record: self._score(transaction, record))
            return self._result("PARTIAL", candidate, ["amount_within_tolerance", "timestamp_within_window"], self._score(transaction, candidate), started, now)

        amount_match = [record for record in records if self._amount_matches(transaction, record)]
        if amount_match:
            candidate = max(amount_match, key=lambda record: self._score(transaction, record))
            return self._result("MISMATCH", candidate, ["amount_match", "timestamp_mismatch_or_reference_mismatch"], self._score(transaction, candidate), started, now)

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


def measure_reconciliation(results: Iterable[Dict[str, Any]], expected_statuses: Iterable[str]) -> Dict[str, float]:
    """Calculate precision, recall, error counts, latency, and throughput."""
    started = time.perf_counter()
    actual = list(results)
    expected = list(expected_statuses)
    correct = sum(result.get("status") == expected_status for result, expected_status in zip(actual, expected))
    positives = sum(status == "MATCHED" for status in expected)
    predicted_positives = sum(result.get("status") == "MATCHED" for result in actual)
    true_positives = sum(result.get("status") == expected_status == "MATCHED" for result, expected_status in zip(actual, expected))
    false_positives = predicted_positives - true_positives
    false_negatives = positives - true_positives
    return {
        "precision": true_positives / predicted_positives if predicted_positives else 1.0,
        "recall": true_positives / positives if positives else 1.0,
        "false_positives": float(false_positives),
        "false_negatives": float(false_negatives),
        "known_cases": float(len(expected)),
        "correct_cases": float(correct),
        "processing_latency_ms": sum(float(result.get("processing_latency_ms", 0)) for result in actual) / max(len(actual), 1),
        "throughput_per_second": len(actual) / max(time.perf_counter() - started, 0.000001),
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

    if not internal_records:
        return {
            "trans_id": trans_id,
            "status": "missing_payment",
            "severity": "critical",
            "duplicate": duplicate,
            "anomalies": anomalies,
            "match": {"match_type": "none", "reason": "no_internal_records"},
        }

    best_match = _find_best_match(
        event,
        internal_records,
        window_minutes=window_minutes,
        tolerance_percent=tolerance_percent,
        allow_partial=allow_partial,
    )

    if best_match is None:
        return {
            "trans_id": trans_id,
            "status": "missing_payment",
            "severity": "critical",
            "duplicate": duplicate,
            "anomalies": anomalies,
            "match": {"match_type": "none", "reason": "no_matching_record"},
        }

    if best_match["match_type"] in {"exact", "fuzzy_exact"}:
        return {
            "trans_id": trans_id,
            "status": "matched",
            "severity": "info",
            "duplicate": duplicate,
            "anomalies": anomalies,
            "match": best_match,
        }

    return {
        "trans_id": trans_id,
        "status": "needs_review",
        "severity": "warning",
        "duplicate": duplicate,
        "anomalies": anomalies,
        "match": best_match,
    }


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
    for record in internal_records:
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

        if phone_matches and amt_diff == 0:
            match_type = "exact"
        elif phone_matches and amt_diff <= allowed_delta:
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

    if not candidates:
        return None

    priority = {"exact": 0, "fuzzy_exact": 1, "partial_fuzzy": 2, "partial": 3}
    candidates.sort(
        key=lambda item: (
            -item.get("score", 0.0),
            priority.get(item["match_type"], 99),
            item["latency_seconds"],
            item["amount_diff"],
        )
    )
    return candidates[0]


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
            return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
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

    # Pre-flight duplicate check optimization
    if event_store and event_store.already_processed(trans_id, tenant_id=tenant_id, provider_account=account_id):
        logger.info("Idempotency: duplicate trans_id=%s detected prior to evaluation, skipping", trans_id)
        return {
            "trans_id": trans_id,
            "status": "duplicate_ignored",
            "severity": "info",
            "anomalies": ["duplicate_transaction_id"],
        }

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
