"""Communication cost engine: attribution, forecasting, and wallet health.

Every outbound message records provider, channel, segments, unit cost, and
total cost so tenants get precise attribution and spend forecasting without
estimated or invented numbers.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from .core.enums import CommunicationChannel
from .models import CommunicationAttempt, CommunicationCampaign, CommunicationNotification

DEFAULT_CURRENCY = "KES"

# Default unit cost per SMS segment in KES; override with env JSON.
_DEFAULT_UNIT_COSTS: dict[str, float] = {
    "sms": 0.8,
    "email": 0.1,
    "whatsapp": 0.5,
    "voice": 3.0,
    "ussd": 0.0,
}


def _unit_costs() -> dict[str, float]:
    raw = os.getenv("PESAGUARD_COMMUNICATION_UNIT_COSTS", "")
    if not raw:
        return dict(_DEFAULT_UNIT_COSTS)
    try:
        loaded = json.loads(raw)
        return {**_DEFAULT_UNIT_COSTS, **loaded} if isinstance(loaded, dict) else dict(_DEFAULT_UNIT_COSTS)
    except json.JSONDecodeError:
        return dict(_DEFAULT_UNIT_COSTS)


def unit_cost(channel: str | CommunicationChannel) -> float:
    return _unit_costs().get(str(getattr(channel, "value", channel)).lower(), 0.0)


def estimate_segments(message: str) -> int:
    """GSM-7 vs Unicode segmentation (160/153 vs 70/67 characters)."""
    text = message or ""
    if not text:
        return 1
    gsm7 = "@\u00a3$\u00a5 !\"\u00a4%&\'()*+,-./0123456789:;<=>?\u00a1ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    if not any(char not in gsm7 for char in text):
        return 1 if len(text) <= 160 else -(-len(text) // 153)
    return 1 if len(text) <= 70 else -(-len(text) // 67)


def build_cost(channel: str | CommunicationChannel, message: str) -> dict[str, Any]:
    channel_value = str(getattr(channel, "value", channel)).lower()
    segments = estimate_segments(message) if channel_value == "sms" else 1
    cost = unit_cost(channel_value) * segments
    return {
        "provider_channel": channel_value,
        "segments": segments,
        "unit_cost": round(unit_cost(channel_value), 4),
        "total_cost": round(cost, 4),
        "currency": os.getenv("PESAGUARD_COMMUNICATION_CURRENCY", DEFAULT_CURRENCY),
    }


def _spend_rows(session: Session, since: datetime, tenant_id: str | None = None) -> list[tuple[str, float]]:
    query = session.query(CommunicationAttempt.cost).filter(
        CommunicationAttempt.started_at >= since,
        CommunicationAttempt.cost.isnot(None),
    )
    if tenant_id:
        query = query.join(CommunicationNotification, CommunicationNotification.id == CommunicationAttempt.notification_id).filter(
            CommunicationNotification.tenant_id == tenant_id
        )
    totals: dict[str, float] = {}
    for (cost,) in query.all():
        if not isinstance(cost, dict):
            continue
        currency = str(cost.get("currency", DEFAULT_CURRENCY))
        totals[currency] = totals.get(currency, 0.0) + float(cost.get("total_cost") or 0.0)
    return sorted(totals.items())


def cost_summary(session: Session, *, tenant_id: str | None = None, currency: str | None = None) -> dict[str, Any]:
    """Daily/weekly/monthly spend with trend and projected monthly spend."""
    now = datetime.now(timezone.utc)
    currency = currency or os.getenv("PESAGUARD_COMMUNICATION_CURRENCY", DEFAULT_CURRENCY)

    def spend_since(since: datetime) -> float:
        rows = _spend_rows(session, since, tenant_id)
        return next((value for code, value in rows if code == currency), 0.0)

    daily = spend_since(now - timedelta(days=1))
    weekly = spend_since(now - timedelta(days=7))
    monthly = spend_since(now - timedelta(days=30))

    # Trend compares the trailing 7 days against the prior 7 days.
    last7 = spend_since(now - timedelta(days=7))
    prior7 = spend_since(now - timedelta(days=14)) - last7
    trend_percent = round(((last7 - prior7) / prior7) * 100, 1) if prior7 > 0 else (0.0 if last7 == 0 else 100.0)

    daily_average_30d = monthly / 30.0
    projected_monthly = round(daily_average_30d * 30.4, 2)
    expected_monthly = round(daily * 30.4, 2)

    return {
        "currency": currency,
        "daily_spend": round(daily, 2),
        "weekly_spend": round(weekly, 2),
        "monthly_spend": round(monthly, 2),
        "projected_monthly_spend": projected_monthly,
        "expected_month_end_spend": expected_monthly,
        "weekly_trend_percent": trend_percent,
    }


def cost_by_channel(session: Session, *, tenant_id: str | None = None, days: int = 30) -> dict[str, dict[str, float]]:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    query = session.query(CommunicationAttempt.cost).filter(
        CommunicationAttempt.started_at >= since,
        CommunicationAttempt.cost.isnot(None),
    )
    if tenant_id:
        query = query.join(CommunicationNotification, CommunicationNotification.id == CommunicationAttempt.notification_id).filter(
            CommunicationNotification.tenant_id == tenant_id
        )
    by_channel: dict[str, dict[str, float]] = {}
    for (cost,) in query.all():
        if not isinstance(cost, dict):
            continue
        channel = str(cost.get("provider_channel", "unknown"))
        bucket = by_channel.setdefault(channel, {"total_cost": 0.0, "segments": 0.0, "messages": 0.0})
        bucket["total_cost"] += float(cost.get("total_cost") or 0.0)
        bucket["segments"] += float(cost.get("segments") or 0.0)
        bucket["messages"] += 1
    for bucket in by_channel.values():
        bucket["total_cost"] = round(bucket["total_cost"], 2)
        bucket["segments"] = int(bucket["segments"])
    return by_channel


def campaign_cost(session: Session, campaign: CommunicationCampaign) -> dict[str, Any]:
    query = session.query(CommunicationAttempt.cost).join(
        CommunicationNotification, CommunicationNotification.id == CommunicationAttempt.notification_id
    ).filter(CommunicationNotification.metadata_json["campaign_id"].as_string() == campaign.id)
    total = 0.0
    segments = 0
    for (cost,) in query.all():
        if isinstance(cost, dict):
            total += float(cost.get("total_cost") or 0.0)
            segments += int(cost.get("segments") or 0)
    return {"campaign_id": campaign.id, "total_cost": round(total, 2), "segments": segments, "currency": os.getenv("PESAGUARD_COMMUNICATION_CURRENCY", DEFAULT_CURRENCY)}


def wallet_health(session: Session, *, provider: str = "africas_talking") -> dict[str, Any]:
    """Wallet burn rate and estimated runway against the configured balance."""
    now = datetime.now(timezone.utc)
    configured_balance = os.getenv("PESAGUARD_COMMUNICATION_WALLET_BALANCE", "")
    daily = sum(value for _, value in _spend_rows(session, now - timedelta(days=1)))
    weekly = sum(value for _, value in _spend_rows(session, now - timedelta(days=7)))
    monthly = sum(value for _, value in _spend_rows(session, now - timedelta(days=30)))
    daily_average = monthly / 30.0 if monthly else 0.0

    status = "UNKNOWN"
    runway_days: float | None = None
    balance_value: float | None = None
    if configured_balance:
        try:
            balance_value = float(configured_balance)
        except ValueError:
            balance_value = None
        if balance_value is not None:
            if daily_average > 0:
                runway_days = round(balance_value / daily_average, 1)
            if balance_value <= 0:
                status = "CRITICAL"
            elif runway_days is not None and runway_days < 7:
                status = "CRITICAL"
            elif runway_days is not None and runway_days < 30:
                status = "WARNING"
            else:
                status = "HEALTHY"

    return {
        "provider": provider,
        "status": status,
        "configured_balance": balance_value,
        "daily_burn": round(daily, 2),
        "weekly_burn": round(weekly, 2),
        "monthly_burn": round(monthly, 2),
        "daily_average_burn": round(daily_average, 2),
        "estimated_runway_days": runway_days,
        "currency": os.getenv("PESAGUARD_COMMUNICATION_CURRENCY", DEFAULT_CURRENCY),
    }
