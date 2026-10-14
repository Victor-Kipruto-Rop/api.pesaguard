"""Temporal and seasonality-aware reconciliation signals.

Pure, deterministic helpers only. They never post ledger entries, approve payments,
or label a transaction fraudulent. Callers must pass tenant/account-scoped history.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from statistics import median
from typing import Any, Mapping, Sequence
from zoneinfo import ZoneInfo

ALGORITHM_VERSION = "temporal-seasonal-v1"
DEFAULT_BUSINESS_TIMEZONE = "Africa/Nairobi"


def _decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = Decimal(str(value).strip())
    except (InvalidOperation, TypeError, ValueError):
        return None
    return parsed if parsed.is_finite() else None


def parse_event_time(value: Any, *, business_timezone: str = DEFAULT_BUSINESS_TIMEZONE) -> datetime | None:
    """Parse an aware ISO timestamp or Daraja YYYYMMDDHHMMSS as UTC.

    Daraja compact timestamps are interpreted in Africa/Nairobi by default.
    Naive ISO timestamps are rejected rather than silently assigned a timezone.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        raw = value.strip()
        if len(raw) == 14 and raw.isdigit():
            try:
                parsed = datetime.strptime(raw, "%Y%m%d%H%M%S").replace(
                    tzinfo=ZoneInfo(business_timezone)
                )
            except (ValueError, KeyError):
                return None
        else:
            try:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def classify_temporal_evidence(
    transaction: Mapping[str, Any],
    *,
    max_ingestion_lag_seconds: int = 300,
    max_future_skew_seconds: int = 60,
    business_timezone: str = DEFAULT_BUSINESS_TIMEZONE,
) -> dict[str, Any]:
    """Classify event/ingestion/settlement timing without inferring missing facts.

    event_time is when the provider says the payment occurred; ingested_at is
    when PesaGuard received it; settlement_time is an independently sourced
    provider settlement timestamp. Settlement may be observed before ingestion
    for late callbacks, but it must not predate the payment event.
    """
    if max_ingestion_lag_seconds < 0 or max_future_skew_seconds < 0:
        raise ValueError("temporal thresholds must be non-negative")

    event_value = transaction.get("event_time") or transaction.get("TransTime") or transaction.get("timestamp")
    ingestion_value = transaction.get("ingested_at") or transaction.get("received_at")
    settlement_value = transaction.get("settlement_time") or transaction.get("settled_at")
    event_time = parse_event_time(event_value, business_timezone=business_timezone)
    ingestion_time = parse_event_time(ingestion_value, business_timezone=business_timezone)
    settlement_time = parse_event_time(settlement_value, business_timezone=business_timezone)

    result: dict[str, Any] = {
        "algorithm_version": ALGORITHM_VERSION,
        "evaluated": False,
        "classification": "INSUFFICIENT_DATA",
        "reason_codes": [],
        "event_time_utc": event_time.isoformat() if event_time else None,
        "ingested_at_utc": ingestion_time.isoformat() if ingestion_time else None,
        "settlement_time_utc": settlement_time.isoformat() if settlement_time else None,
        "ingestion_lag_seconds": None,
        "settlement_lag_seconds": None,
    }
    if event_time is None or ingestion_time is None:
        result["reason_codes"].append("event_or_ingestion_time_missing_or_ambiguous")
        return result

    result["evaluated"] = True
    ingestion_lag = (ingestion_time - event_time).total_seconds()
    result["ingestion_lag_seconds"] = round(ingestion_lag, 3)
    if ingestion_lag < -max_future_skew_seconds:
        result["classification"] = "CLOCK_SKEW_OR_FUTURE_EVENT"
        result["reason_codes"].append("event_time_after_ingestion_beyond_skew")
    elif ingestion_lag > max_ingestion_lag_seconds:
        result["classification"] = "LATE_ARRIVAL"
        result["reason_codes"].append("ingestion_lag_exceeded_threshold")
    else:
        result["classification"] = "ON_TIME"

    if settlement_value not in (None, ""):
        if settlement_time is None:
            result["reason_codes"].append("settlement_time_missing_or_ambiguous")
        elif settlement_time < event_time:
            result["classification"] = "INVALID_TEMPORAL_ORDER"
            result["reason_codes"].append("settlement_precedes_payment_event")
        else:
            settlement_lag = (settlement_time - event_time).total_seconds()
            result["settlement_lag_seconds"] = round(settlement_lag, 3)
            if result["classification"] == "ON_TIME":
                result["classification"] = "SETTLEMENT_OBSERVED"
    return result


def seasonal_amount_anomaly(
    transaction: Mapping[str, Any],
    history: Sequence[Mapping[str, Any]],
    *,
    minimum_samples: int = 5,
    modified_z_threshold: float = 3.5,
    business_timezone: str = DEFAULT_BUSINESS_TIMEZONE,
) -> dict[str, Any]:
    """Compare amount with tenant/provider/account seasonality-aware baselines.

    History is filtered to exact tenant and account scope. The baseline hierarchy
    is weekday+hour, weekday, then full scoped history; a less-specific fallback
    is used only if it still meets minimum_samples. This is a screening signal,
    not a fraud probability or a payment decision.
    """
    if minimum_samples < 3:
        raise ValueError("minimum_samples must be at least 3")
    if modified_z_threshold <= 0:
        raise ValueError("modified_z_threshold must be positive")

    tenant = str(transaction.get("tenant_id") or "").strip()
    provider = str(transaction.get("provider") or "").strip().casefold()
    account = str(transaction.get("account_id") or transaction.get("merchant_account_id") or "").strip()
    amount = _decimal(transaction.get("amount", transaction.get("TransAmount")))
    event_time = parse_event_time(
        transaction.get("event_time") or transaction.get("TransTime") or transaction.get("timestamp"),
        business_timezone=business_timezone,
    )
    base = {
        "algorithm_version": ALGORITHM_VERSION,
        "evaluated": False,
        "outlier_candidate": False,
        "baseline_level": None,
        "sample_count": 0,
        "median_amount": None,
        "mad": None,
        "modified_z": None,
        "reason_codes": [],
    }
    if not tenant or not provider or not account:
        base["reason_codes"].append("tenant_provider_account_scope_required")
        return base
    if amount is None or event_time is None:
        base["reason_codes"].append("valid_amount_and_timezone_aware_event_time_required")
        return base

    zone = ZoneInfo(business_timezone)
    local_event = event_time.astimezone(zone)
    scoped: list[tuple[datetime, Decimal]] = []
    for row in history:
        row_tenant = str(row.get("tenant_id") or "").strip()
        row_provider = str(row.get("provider") or "").strip().casefold()
        row_account = str(row.get("account_id") or row.get("merchant_account_id") or "").strip()
        if (row_tenant, row_provider, row_account) != (tenant, provider, account):
            continue
        row_time = parse_event_time(
            row.get("event_time") or row.get("TransTime") or row.get("timestamp"),
            business_timezone=business_timezone,
        )
        row_amount = _decimal(row.get("amount", row.get("TransAmount")))
        if row_time is None or row_amount is None or row_amount <= 0:
            continue
        if row_time >= event_time:
            continue
        scoped.append((row_time, row_amount))

    same_hour = [
        value for stamp, value in scoped
        if stamp.astimezone(zone).weekday() == local_event.weekday()
        and stamp.astimezone(zone).hour == local_event.hour
    ]
    same_weekday = [
        value for stamp, value in scoped
        if stamp.astimezone(zone).weekday() == local_event.weekday()
    ]
    candidates = [
        ("weekday_hour", same_hour),
        ("weekday", same_weekday),
        ("scoped_history", [value for _, value in scoped]),
    ]
    selected_level = None
    values: list[Decimal] = []
    for level, cohort in candidates:
        if len(cohort) >= minimum_samples:
            selected_level, values = level, cohort
            break
    if selected_level is None:
        base["sample_count"] = len(scoped)
        base["reason_codes"].append("insufficient_scoped_baseline_samples")
        return base

    center = median(values)
    deviations = [abs(value - center) for value in values]
    mad = median(deviations)
    base.update({
        "evaluated": True,
        "baseline_level": selected_level,
        "sample_count": len(values),
        "median_amount": str(center),
        "mad": str(mad),
    })
    if mad == 0:
        candidate = amount != center
        base["outlier_candidate"] = candidate
        if candidate:
            base["reason_codes"].append("zero_mad_baseline_requires_review")
        else:
            base["reason_codes"].append("zero_mad_baseline_score_unavailable")
        return base

    modified_z = float(Decimal("0.6745") * (amount - center) / mad)
    outlier = abs(modified_z) > modified_z_threshold
    base.update({
        "modified_z": round(modified_z, 4),
        "outlier_candidate": outlier,
        "reason_codes": ["seasonal_amount_outlier"] if outlier else [],
    })
    return base
