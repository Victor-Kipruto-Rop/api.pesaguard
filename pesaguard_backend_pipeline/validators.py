"""Validate M-Pesa callback structures and normalize supported transaction payloads."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional, Tuple

from normalization import NormalizationError, normalize_amount

logger = logging.getLogger("pesaguard.daraja_validator")

# Flat C2B Callback standard required keys
REQUIRED_C2B_FIELDS = [
    "TransactionType",
    "TransID",
    "TransTime",
    "TransAmount",
    "BusinessShortCode",
    "MSISDN",
]


def validate_daraja_payload(payload: Dict[str, Any]) -> Tuple[bool, str]:
    """Validate raw incoming Daraja webhook structure and required fields.

    Args:
        payload: Incoming JSON request body dictionary

    Returns:
        Tuple of (is_valid: bool, error_message: str)
    """
    if not isinstance(payload, dict):
        return False, "Payload must be a JSON object"

    # 1. Evaluate Nested STK Push Callback Structure
    if "Body" in payload:
        body = payload["Body"]
        if not isinstance(body, dict):
            return False, "Body must be a JSON object"
        if "stkCallback" in body:
            return _validate_stk_push_callback(body["stkCallback"])

    # 2. Evaluate Nested B2C Callback Structure
    if "Result" in payload:
        return _validate_b2c_callback(payload["Result"])

    # 3. Evaluate Flat C2B PayBill / Till Confirmation Structure
    missing = [f for f in REQUIRED_C2B_FIELDS if f not in payload or payload[f] is None]
    if missing:
        return False, f"Missing required C2B fields: {', '.join(missing)}"

    # Validate TransAmount numerics
    try:
        normalize_amount(payload["TransAmount"])
    except NormalizationError:
        return False, "TransAmount must be a valid numeric value"

    # Validate TransID non-empty
    trans_id = str(payload.get("TransID", "")).strip()
    if not trans_id:
        return False, "TransID cannot be empty"

    # Validate MSISDN format (12-digit Kenyan phone 2547XXXXXXXX / 2541XXXXXXXX)
    msisdn = str(payload.get("MSISDN", "")).strip()
    if not re.match(r"^254[17]\d{8}$", msisdn):
        return False, f"MSISDN '{msisdn}' must be a valid 12-digit string starting with 254"

    return True, ""


def extract_canonical_event(payload: Dict[str, Any], tenant_id: str = "default") -> Optional[Dict[str, Any]]:
    """Extract flat C2B and STK fields; B2C result envelopes need account mapping first.

    Args:
        payload: Validated incoming JSON payload
        tenant_id: Active tenant context string

    Returns:
        Normalized dictionary ready for the reconciliation pipeline
    """
    is_valid, _ = validate_daraja_payload(payload)
    if not is_valid:
        return None

    # Handle Nested STK Push
    if "Body" in payload and "stkCallback" in payload["Body"]:
        stk = payload["Body"]["stkCallback"]
        if not isinstance(stk, dict):
            return None
        callback_metadata = stk.get("CallbackMetadata")
        items = callback_metadata.get("Item") if isinstance(callback_metadata, dict) else None
        if not isinstance(items, list):
            return None
        meta = {
            item["Name"]: item.get("Value")
            for item in items
            if isinstance(item, dict) and isinstance(item.get("Name"), str)
        }
        try:
            amount = normalize_amount(meta.get("Amount"))
        except NormalizationError:
            return None

        return {
            "tenant_id": tenant_id,
            "TransID": str(meta.get("MpesaReceiptNumber", stk.get("CheckoutRequestID", "unknown"))).strip(),
            "TransAmount": amount,
            "MSISDN": str(meta.get("PhoneNumber", "")).strip(),
            "TransTime": str(meta.get("TransactionDate", datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))),
            "BusinessShortCode": str(payload.get("BusinessShortCode", "")),
            "TransactionType": "STK_PUSH",
            "raw_payload": payload,
        }

    if "Result" in payload:
        return None

    # Handle Flat C2B Payload
    return {
        "tenant_id": tenant_id,
        "TransID": str(payload.get("TransID", "")).strip(),
        "TransAmount": normalize_amount(payload["TransAmount"]),
        "MSISDN": str(payload.get("MSISDN", "")).strip(),
        "TransTime": str(payload.get("TransTime", "")).strip(),
        "BusinessShortCode": str(payload.get("BusinessShortCode", "")).strip(),
        "TransactionType": str(payload.get("TransactionType", "C2B")),
        "BillRefNumber": str(payload.get("BillRefNumber", "")).strip(),
        "raw_payload": payload,
    }


def _validate_stk_push_callback(stk: Dict[str, Any]) -> Tuple[bool, str]:
    """Validate nested STK Push callback envelope."""
    if not isinstance(stk, dict):
        return False, "STK Push callback must be a JSON object"
    result_code = stk.get("ResultCode")
    if result_code is None:
        return False, "STK Push callback missing ResultCode"

    try:
        if isinstance(result_code, bool):
            raise InvalidOperation
        numeric_result_code = Decimal(str(result_code))
        if not numeric_result_code.is_finite() or numeric_result_code != numeric_result_code.to_integral_value():
            raise InvalidOperation
    except (InvalidOperation, TypeError, ValueError):
        return False, "B2C callback ResultCode must be an integer"

    if numeric_result_code != 0:
        return False, f"B2C payment failed with ResultCode={result_code}: {result.get('ResultDesc')}"

    callback_metadata = stk.get("CallbackMetadata")
    meta_items = callback_metadata.get("Item") if isinstance(callback_metadata, dict) else None
    if not isinstance(meta_items, list) or not meta_items:
        return False, "STK Push callback missing CallbackMetadata items"
    if not any(isinstance(item, dict) and item.get("Name") == "Amount" for item in meta_items):
        return False, "STK Push callback missing transaction amount"
    try:
        amount_item = next(item for item in meta_items if isinstance(item, dict) and item.get("Name") == "Amount")
        normalize_amount(amount_item.get("Value"))
    except (StopIteration, NormalizationError):
        return False, "STK Push callback has an invalid transaction amount"

    return True, ""


def _validate_b2c_callback(result: Dict[str, Any]) -> Tuple[bool, str]:
    """Validate nested B2C result envelope."""
    if not isinstance(result, dict):
        return False, "B2C result must be a JSON object"
    result_code = result.get("ResultCode")
    if result_code is None:
        return False, "B2C callback missing ResultCode"

    try:
        if isinstance(result_code, bool):
            raise InvalidOperation
        numeric_result_code = Decimal(str(result_code))
        if not numeric_result_code.is_finite() or numeric_result_code != numeric_result_code.to_integral_value():
            raise InvalidOperation
    except (InvalidOperation, TypeError, ValueError):
        return False, "B2C callback ResultCode must be an integer"

    if numeric_result_code != 0:
        return False, f"B2C payment failed with ResultCode={result_code}: {result.get('ResultDesc')}"

    return True, ""
