"""Layered fraud and anomaly risk engine for transaction decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import mean, pstdev
from typing import Any, Iterable, Mapping, Sequence

MODEL_VERSION = "fraud-rules-v1"
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass(frozen=True)
class FraudFeatures:
    transaction_frequency: float
    amount_deviation: float
    velocity: float
    customer_history: float
    tenant_baseline: float
    time_pattern: float
    amount: float
    customer_id: str
    merchant_id: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "transaction_frequency": self.transaction_frequency,
            "amount_deviation": self.amount_deviation,
            "velocity": self.velocity,
            "customer_history": self.customer_history,
            "tenant_baseline": self.tenant_baseline,
            "time_pattern": self.time_pattern,
            "amount": self.amount,
            "customer_id": self.customer_id,
            "merchant_id": self.merchant_id,
        }


@dataclass(frozen=True)
class RuleResult:
    code: str
    triggered: bool
    weight: float
    reason: str


@dataclass(frozen=True)
class RiskDecision:
    risk_score: float
    risk_level: str
    action: str
    reason_codes: tuple[str, ...]
    model_version: str
    rules_triggered: tuple[str, ...]
    features: FraudFeatures
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "action": self.action,
            "reason_codes": list(self.reason_codes),
            "model_version": self.model_version,
            "rules_triggered": list(self.rules_triggered),
            "features": self.features.as_dict(),
            "detected_at": self.detected_at.isoformat(),
        }


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _timestamp(transaction: Mapping[str, Any]) -> datetime | None:
    value = transaction.get("TransTime") or transaction.get("timestamp") or transaction.get("created_at")
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value or "").strip()
    if len(text) == 14 and text.isdigit():
        try:
            return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _identity(transaction: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(transaction.get(key) or "").strip()
        if value:
            return value
    return "unknown"


def calculate_features(
    transaction: Mapping[str, Any],
    history: Sequence[Mapping[str, Any]] = (),
    tenant_baseline: Mapping[str, Any] | None = None,
) -> FraudFeatures:
    """Calculate bounded, explainable features from transaction and tenant context."""
    baseline = tenant_baseline or {}
    amount = _number(transaction.get("TransAmount") or transaction.get("amount"))
    customer_id = _identity(transaction, "MSISDN", "customer_id", "customer")
    merchant_id = _identity(transaction, "BusinessShortCode", "merchant_id", "merchant")
    customer_history = [item for item in history if _identity(item, "MSISDN", "customer_id", "customer") == customer_id]
    tenant_amounts = [_number(item.get("TransAmount") or item.get("amount")) for item in history]
    tenant_amounts = [value for value in tenant_amounts if value > 0]
    customer_times = [_timestamp(item) for item in customer_history]
    current_time = _timestamp(transaction)
    recent_customer = [value for value in customer_times if current_time and value and 0 <= (current_time - value).total_seconds() <= 3600]
    frequency = len(recent_customer) / 60.0
    velocity = len([value for value in recent_customer if (current_time - value).total_seconds() <= 60]) if current_time else 0.0
    mean_amount = _number(baseline.get("mean_amount"), mean(tenant_amounts) if tenant_amounts else amount)
    std_amount = _number(baseline.get("std_amount"), pstdev(tenant_amounts) if len(tenant_amounts) > 1 else max(mean_amount * 0.25, 1.0))
    # Use a robust median/MAD score once there is enough tenant history. This
    # prevents a few extreme transactions from inflating the mean and hiding
    # later outliers. Small samples retain the existing conservative fallback.
    try:
        from .algorithmic_intelligence import robust_amount_deviation
    except ImportError:  # pragma: no cover - top-level script execution
        from algorithmic_intelligence import robust_amount_deviation
    robust_deviation = robust_amount_deviation(amount, tenant_amounts)
    amount_deviation = (
        robust_deviation
        if robust_deviation is not None
        else min(abs(amount - mean_amount) / max(std_amount, 1.0), 5.0) / 5.0
    )
    customer_baseline = _number(baseline.get("customer_mean_amount"), mean([_number(item.get("TransAmount") or item.get("amount")) for item in customer_history]) if customer_history else mean_amount)
    customer_history_score = min(len(customer_history) / 20.0, 1.0)
    tenant_baseline_score = min(abs(amount - mean_amount) / max(mean_amount, 1.0), 5.0) / 5.0
    hour = current_time.hour if current_time else 12
    time_pattern = 1.0 if hour < 5 or hour >= 23 else 0.0
    return FraudFeatures(
        transaction_frequency=min(frequency, 1.0),
        amount_deviation=amount_deviation,
        velocity=min(velocity / 5.0, 1.0),
        customer_history=customer_history_score,
        tenant_baseline=max(tenant_baseline_score, min(abs(amount - customer_baseline) / max(customer_baseline, 1.0), 5.0) / 5.0),
        time_pattern=time_pattern,
        amount=amount,
        customer_id=customer_id,
        merchant_id=merchant_id,
    )


def evaluate_rules(
    transaction: Mapping[str, Any],
    features: FraudFeatures,
    history: Sequence[Mapping[str, Any]] = (),
    *,
    amount_threshold: float = 150_000.0,
    velocity_limit: float = 5.0,
) -> tuple[RuleResult, ...]:
    transaction_id = _identity(transaction, "TransID", "trans_id", "transaction_id")
    duplicate = any(_identity(item, "TransID", "trans_id", "transaction_id") == transaction_id for item in history)
    amount = features.amount
    rapid_changes = len({round(_number(item.get("TransAmount") or item.get("amount")), 2) for item in history[-5:]}) >= 4
    return (
        RuleResult("velocity", features.velocity * 5 >= velocity_limit, 0.30, "transaction velocity exceeded the configured limit"),
        RuleResult("amount_threshold", amount > amount_threshold, 0.20, "transaction amount exceeded the tenant threshold"),
        RuleResult("duplicate_activity", duplicate, 0.30, "transaction identity was already observed"),
        RuleResult("unusual_time", features.time_pattern > 0, 0.10, "transaction occurred during an unusual time window"),
        RuleResult("rapid_transaction_changes", rapid_changes, 0.15, "recent transaction amounts changed rapidly"),
    )


def _risk_level(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.35:
        return "MEDIUM"
    return "LOW"


def _action(level: str) -> str:
    return {"LOW": "process", "MEDIUM": "monitor", "HIGH": "review", "CRITICAL": "escalate"}[level]


def assess_transaction(
    transaction: Mapping[str, Any],
    history: Sequence[Mapping[str, Any]] = (),
    tenant_baseline: Mapping[str, Any] | None = None,
    *,
    model_version: str = MODEL_VERSION,
    amount_threshold: float = 150_000.0,
    velocity_limit: float = 5.0,
) -> RiskDecision:
    features = calculate_features(transaction, history, tenant_baseline)
    rules = evaluate_rules(transaction, features, history, amount_threshold=amount_threshold, velocity_limit=velocity_limit)
    feature_score = (
        features.amount_deviation * 0.25
        + features.velocity * 0.25
        + features.tenant_baseline * 0.20
        + features.time_pattern * 0.10
        + min(features.customer_history, 1.0) * 0.10
    )
    rule_score = sum(rule.weight for rule in rules if rule.triggered)
    score = round(min(1.0, max(feature_score, rule_score) + min(feature_score * rule_score, 0.25)), 4)
    triggered = tuple(rule.code for rule in rules if rule.triggered)
    level = _risk_level(score)
    return RiskDecision(score, level, _action(level), triggered, model_version, triggered, features)


def persist_assessment(session: Any, tenant_id: str, transaction_id: str, decision: RiskDecision) -> Any:
    """Upsert the explainable decision for a tenant-scoped transaction."""
    from models import FraudRiskAssessment

    assessment = session.query(FraudRiskAssessment).filter_by(
        tenant_id=tenant_id,
        transaction_id=transaction_id,
    ).one_or_none()
    values = {
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "action": decision.action,
        "reason_codes": list(decision.reason_codes),
        "model_version": decision.model_version,
        "rules_triggered": list(decision.rules_triggered),
        "features": decision.features.as_dict(),
    }
    if assessment is None:
        assessment = FraudRiskAssessment(tenant_id=tenant_id, transaction_id=transaction_id, **values)
        session.add(assessment)
    else:
        for key, value in values.items():
            setattr(assessment, key, value)
    session.flush()
    return assessment


def evaluate_predictions(predictions: Iterable[tuple[RiskDecision, bool]]) -> dict[str, float]:
    """Measure precision, recall, FP/FN counts, and average detection latency."""
    rows = list(predictions)
    true_positive = false_positive = false_negative = true_negative = 0
    latencies: list[float] = []
    for decision, actual_fraud in rows:
        predicted = decision.risk_level in {"HIGH", "CRITICAL"}
        if predicted and actual_fraud:
            true_positive += 1
        elif predicted:
            false_positive += 1
        elif actual_fraud:
            false_negative += 1
        else:
            true_negative += 1
        latency = (datetime.now(timezone.utc) - decision.detected_at).total_seconds() * 1000
        latencies.append(max(0.0, latency))
    return {
        "precision": true_positive / max(true_positive + false_positive, 1),
        "recall": true_positive / max(true_positive + false_negative, 1),
        "false_positives": float(false_positive),
        "false_negatives": float(false_negative),
        "true_negatives": float(true_negative),
        "detection_latency_ms": sum(latencies) / len(latencies) if latencies else 0.0,
    }
