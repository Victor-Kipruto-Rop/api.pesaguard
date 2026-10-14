"""Reconciliation helpers: normalization and basic matching utilities.

- normalize_daraja_event(payload, tenant_id="default") -> dict with canonical keys:
  'TransID', 'TransAmount', 'TransTime', 'MSISDN', plus 'reference'/'amount'/'timestamp' aliases.
- exact_match(tx, settlement) -> bool
- find_exact_match(tx, settlements) -> dict|None
- time_window_match(tx, settlements, window_seconds=300) -> dict|None

Designed to be dependency-light (stdlib only).
"""
from __future__ import annotations
from typing import Dict, Iterable, Optional
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import logging
import re

logger = logging.getLogger(__name__)

DAR_A_TIME_RE = re.compile(r"^\d{14}$")  # YYYYMMDDHHMMSS


def parse_daraja_time(value: str) -> Optional[datetime]:
    """Parse timestamps and return naive UTC for legacy caller compatibility.

    Daraja's compact YYYYMMDDHHMMSS timestamp represents Africa/Nairobi local
    time. ISO timestamps with offsets are converted to UTC; naive ISO values are
    treated as UTC. Returning naive UTC is retained for existing helper callers.
    """
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    if isinstance(value, str):
        val = value.strip()
        if DAR_A_TIME_RE.match(val):
            try:
                local = datetime.strptime(val, "%Y%m%d%H%M%S").replace(tzinfo=ZoneInfo("Africa/Nairobi"))
                return local.astimezone(timezone.utc).replace(tzinfo=None)
            except ValueError:
                return None
        try:
            parsed = datetime.fromisoformat(val.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            return None
    return None


def _get_reference(record: Dict) -> Optional[str]:
    """Extract an explicit business/payment reference, never provider identity."""
    for k in (
        "BillRefNumber",
        "bill_ref_number",
        "reference",
        "transaction_reference",
        "tx_ref",
        "merchant_ref",
        "AccountReference",
        "account_reference",
    ):
        v = record.get(k)
        if v:
            return str(v).strip()
    return None


def _get_amount(record: Dict) -> Optional[float]:
    """Extract numeric amount if present."""
    for k in ("TransAmount", "amount", "amt", "transaction_amount"):
        v = record.get(k)
        if v is None:
            continue
        try:
            return float(v)
        except Exception:
            continue
    return None


def _get_timestamp(record: Dict) -> Optional[datetime]:
    """Try common timestamp fields and parse them."""
    for k in ("TransTime", "timestamp", "time", "created_at", "trans_time"):
        v = record.get(k)
        if not v:
            continue
        # If it's already a datetime, return it (caller must ensure timezone handling)
        if isinstance(v, datetime):
            return v.astimezone(timezone.utc).replace(tzinfo=None) if v.tzinfo else v
        # Parse known Daraja format or ISO
        parsed = parse_daraja_time(str(v))
        if parsed:
            return parsed
    return None


def normalize_daraja_event(payload: Dict, tenant_id: str = "default") -> Dict:
    """Return a normalized event shape derived from Daraja payloads.

    Keeps keys consistent with reconciliation engine expectations:
    - TransID, TransAmount, TransTime, MSISDN
    - Also returns 'reference', 'amount', 'timestamp' aliases to simplify matching.
    """
    out: Dict = {}
    # STK Push nested shape handled upstream in validators; fallback to common fields
    trans_id = payload.get("TransID") or payload.get("TransactionID") or payload.get("ReceiptNumber") or payload.get("CheckoutRequestID")
    if trans_id:
        out["TransID"] = str(trans_id).strip()

    # Amount
    amt = None
    try:
        # Some nested shapes may have numeric values or strings
        amt = payload.get("TransAmount") or payload.get("amount") or payload.get("Amount")
    except Exception:
        amt = None
    if amt is not None:
        try:
            out["TransAmount"] = float(amt)
            out["amount"] = float(amt)
        except Exception:
            pass

    # Timestamp
    tt = payload.get("TransTime") or payload.get("TransactionDate") or payload.get("timestamp")
    parsed_ts = None
    if tt:
        parsed_ts = parse_daraja_time(str(tt))
    if parsed_ts:
        out["TransTime"] = parsed_ts.strftime("%Y-%m-%dT%H:%M:%S")
        out["timestamp"] = parsed_ts
    else:
        # If no parsable time, skip timestamp keys
        pass

    # MSISDN / phone
    msisdn = payload.get("MSISDN") or payload.get("PhoneNumber") or payload.get("msisdn")
    if msisdn:
        out["MSISDN"] = str(msisdn).strip()
        out["phone_number"] = out["MSISDN"]

    # Provide handy aliases for reconciliation helpers
    ref = _get_reference(payload)
    if ref:
        out["reference"] = ref

    return out


def exact_match(tx: Dict, settlement: Dict) -> bool:
    """Return True if transaction and settlement match exactly on reference and amount (when present)."""
    ref_tx = _get_reference(tx)
    ref_st = _get_reference(settlement)
    if not ref_tx or not ref_st:
        return False
    if ref_tx != ref_st:
        return False

    amt_tx = _get_amount(tx)
    amt_st = _get_amount(settlement)
    if (amt_tx is not None) and (amt_st is not None):
        return amt_tx == amt_st
    return True


def find_exact_match(tx: Dict, settlements: Iterable[Dict]) -> Optional[Dict]:
    """Return the first settlement that exactly matches tx (or None)."""
    for s in settlements:
        if exact_match(tx, s):
            return s
    return None


def time_window_match(tx: Dict, settlements: Iterable[Dict], window_seconds: int = 300) -> Optional[Dict]:
    """Find a settlement that matches by reference (or amount) within +/- window_seconds of tx timestamp.

    Matching strategy:
    - Prefer exact reference + amount equality regardless of timestamp.
    - Otherwise, match same reference within the window_seconds.
    - If no reference, fall back to amount + timestamp.
    """
    # Prefer exact
    exact = find_exact_match(tx, settlements)
    if exact:
        return exact

    tx_ts = _get_timestamp(tx)
    ref_tx = _get_reference(tx)
    amt_tx = _get_amount(tx)

    window = timedelta(seconds=window_seconds)

    for s in settlements:
        s_ts = _get_timestamp(s)
        # Match by reference inside window
        if ref_tx:
            ref_s = _get_reference(s)
            if ref_s and (ref_s == ref_tx):
                if (tx_ts is None) or (s_ts is None) or (abs(tx_ts - s_ts) <= window):
                    return s
        # Fallback: amount + timestamp
        if amt_tx is not None:
            amt_s = _get_amount(s)
            if (amt_s is not None) and (amt_s == amt_tx):
                if (tx_ts is None) or (s_ts is None) or (abs(tx_ts - s_ts) <= window):
                    return s
    return None
