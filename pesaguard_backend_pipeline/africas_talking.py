"""Africa's Talking SMS helper for critical alerts (Robust & Production-Ready)."""

import os
import logging
import json
import secrets
import time
import re
from contextlib import suppress
from dataclasses import dataclass
from time import monotonic
from typing import Any, Callable, Dict, Optional, Tuple

import requests

logger = logging.getLogger("pesaguard.sms")

DEFAULT_CONNECT_TIMEOUT_SECONDS = 5.0
DEFAULT_READ_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_MAX_BACKOFF_SECONDS = 30.0
DEFAULT_MAX_MESSAGE_SEGMENTS = 3
MAX_RESPONSE_BYTES = 256 * 1024
USER_AGENT = "PesaGuard-SMS/1.0"
KENYAN_MOBILE_RE = re.compile(r"\+254(?:1|7)\d{8}\Z")


def _first_env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value is not None:
            return value
    return default


class SmsConfigurationError(ValueError):
    """Raised when an SMS client configuration could cause unsafe delivery."""


class SmsValidationError(ValueError):
    """Raised when a recipient or message cannot be safely sent."""


@dataclass(frozen=True)
class SmsRetryPolicy:
    max_retries: int = DEFAULT_MAX_RETRIES
    base_backoff_seconds: float = 1.0
    max_backoff_seconds: float = DEFAULT_MAX_BACKOFF_SECONDS
    jitter_ratio: float = 0.25
    retry_ambiguous: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.max_retries, int) or self.max_retries < 0:
            raise SmsConfigurationError("max_retries must be a non-negative integer")
        if self.base_backoff_seconds <= 0 or self.max_backoff_seconds <= 0:
            raise SmsConfigurationError("backoff values must be positive")
        if self.base_backoff_seconds > self.max_backoff_seconds:
            raise SmsConfigurationError("base_backoff_seconds cannot exceed max_backoff_seconds")
        if not 0 <= self.jitter_ratio <= 1:
            raise SmsConfigurationError("jitter_ratio must be between 0 and 1")


class AfricasTalkingClient:
    """Robust SMS client for critical operational alerts with retries and normalization."""

    def __init__(
        self,
        username: Optional[str] = None,
        api_key: Optional[str] = None,
        environment: Optional[str] = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout_seconds: Optional[float] = None,
        connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS,
        read_timeout_seconds: float = DEFAULT_READ_TIMEOUT_SECONDS,
        retry_ambiguous: bool = False,
        base_backoff_seconds: float = 1.0,
        max_backoff_seconds: float = DEFAULT_MAX_BACKOFF_SECONDS,
        jitter_ratio: float = 0.25,
        session: Optional[requests.Session] = None,
        metrics_hook: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.username = (username if username is not None else _first_env("AFRICASTALKING_USERNAME", "AFRICAS_TALKING_USERNAME")).strip()
        self.api_key = (api_key if api_key is not None else _first_env("AFRICASTALKING_API_KEY", "AFRICAS_TALKING_API_KEY")).strip()
        if timeout_seconds is None:
            timeout_value = _first_env("AFRICASTALKING_TIMEOUT_SECONDS", "AFRICAS_TALKING_TIMEOUT_SECONDS")
            if timeout_value:
                try:
                    timeout_seconds = float(timeout_value)
                except ValueError as exc:
                    raise SmsConfigurationError("AFRICASTALKING_TIMEOUT_SECONDS must be a number") from exc
        if max_retries == DEFAULT_MAX_RETRIES:
            retries_value = _first_env("AFRICASTALKING_MAX_RETRIES", "AFRICAS_TALKING_MAX_RETRIES")
            if retries_value:
                try:
                    max_retries = int(retries_value)
                except ValueError as exc:
                    raise SmsConfigurationError("AFRICASTALKING_MAX_RETRIES must be an integer") from exc
        if timeout_seconds is not None:
            if timeout_seconds <= 0:
                raise SmsConfigurationError("timeout_seconds must be positive")
            connect_timeout_seconds = timeout_seconds
            read_timeout_seconds = timeout_seconds
        if connect_timeout_seconds <= 0 or read_timeout_seconds <= 0:
            raise SmsConfigurationError("connect and read timeouts must be positive")
        self.timeout: Tuple[float, float] = (float(connect_timeout_seconds), float(read_timeout_seconds))
        self.retry_policy = SmsRetryPolicy(
            max_retries=max_retries,
            base_backoff_seconds=base_backoff_seconds,
            max_backoff_seconds=max_backoff_seconds,
            jitter_ratio=jitter_ratio,
            retry_ambiguous=retry_ambiguous,
        )
        self.session = session or requests.Session()
        self.metrics_hook = metrics_hook

        env = (environment if environment is not None else _first_env("AFRICASTALKING_ENVIRONMENT", "AT_ENVIRONMENT", default="production")).strip().lower()
        if env not in {"sandbox", "production"}:
            raise SmsConfigurationError("environment must be exactly 'sandbox' or 'production'")
        self.environment = env
        if env == "sandbox":
            self.base_url = "https://api.sandbox.africastalking.com/version1/messaging"
        else:
            self.base_url = "https://api.africastalking.com/version1/messaging"

    @staticmethod
    def _mask_phone_number(phone: str) -> str:
        return f"{phone[:4]}***{phone[-2:]}" if len(phone) >= 7 else "***"

    def _normalize_phone_number(self, phone: str) -> str:
        """
        Normalizes phone numbers to E.164 format (specifically handling Kenyan numbers
        defaulting to +254 if starting with 0 or 7).
        """
        if not isinstance(phone, str):
            raise SmsValidationError("recipient phone number must be a string")
        cleaned = re.sub(r"[\s().-]+", "", phone.strip())
        if not re.fullmatch(r"\+?\d+", cleaned):
            raise SmsValidationError("recipient phone number contains invalid characters")
        if cleaned.startswith("0") and len(cleaned) == 10:
            cleaned = f"+254{cleaned[1:]}"
        elif cleaned.startswith("7") and len(cleaned) == 9:
            cleaned = f"+254{cleaned}"
        elif cleaned.startswith("1") and len(cleaned) == 9:
            cleaned = f"+254{cleaned}"
        elif cleaned.startswith("254"):
            cleaned = f"+{cleaned}"
        if not KENYAN_MOBILE_RE.fullmatch(cleaned):
            raise SmsValidationError("recipient must be a valid Kenyan mobile number")
        return cleaned

    @staticmethod
    def _validate_message(message: str) -> str:
        if not isinstance(message, str):
            raise SmsValidationError("message must be a string")
        normalized = message.strip()
        if not normalized:
            raise SmsValidationError("message must not be empty")
        per_segment = 160 if all(ord(char) < 128 for char in normalized) else 70
        max_length = per_segment * DEFAULT_MAX_MESSAGE_SEGMENTS
        if len(normalized) > max_length:
            raise SmsValidationError(f"message exceeds the {DEFAULT_MAX_MESSAGE_SEGMENTS}-segment SMS limit")
        return normalized

    def _emit_metric(self, payload: Dict[str, Any]) -> None:
        if self.metrics_hook:
            try:
                self.metrics_hook(dict(payload))
            except Exception:
                logger.debug("SMS metrics hook failed", exc_info=True)

    def _backoff(self, attempt: int, retry_after: Optional[float] = None) -> float:
        if retry_after is not None:
            return min(max(retry_after, 0), self.retry_policy.max_backoff_seconds)
        base = min(
            self.retry_policy.base_backoff_seconds * (2 ** max(attempt - 1, 0)),
            self.retry_policy.max_backoff_seconds,
        )
        jitter = secrets.SystemRandom().uniform(0, base * self.retry_policy.jitter_ratio)
        return min(self.retry_policy.max_backoff_seconds, base + jitter)

    @staticmethod
    def _retry_after(response: requests.Response) -> Optional[float]:
        value = response.headers.get("Retry-After")
        if not value:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _provider_result(data: Any) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        if not isinstance(data, dict):
            return False, "invalid_provider_response", {"raw_response": str(data)[:1000]}
        recipients = data.get("SMSMessageData", {}).get("Recipients") if isinstance(data.get("SMSMessageData"), dict) else None
        if not isinstance(recipients, list) or not recipients:
            return False, "provider_rejected", data
        recipient = recipients[0] if isinstance(recipients[0], dict) else {}
        status = str(recipient.get("status", "")).casefold()
        status_code = str(recipient.get("statusCode", ""))
        if status in {"sent", "success", "delivered"} or status_code == "100":
            return True, None, data
        return False, str(recipient.get("statusCode") or recipient.get("status") or "provider_rejected"), data

    @staticmethod
    def _response_data(response: requests.Response) -> Dict[str, Any]:
        content_length = response.headers.get("Content-Length")
        parsed_content_length = None
        with suppress(ValueError):
            if content_length is not None:
                parsed_content_length = int(content_length)
        if parsed_content_length is not None and parsed_content_length > MAX_RESPONSE_BYTES:
            raise SmsValidationError("response_too_large")
        if hasattr(response, "iter_content"):
            chunks = []
            total = 0
            for chunk in response.iter_content(chunk_size=8192):
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise SmsValidationError("response_too_large")
                chunks.append(chunk)
            raw = b"".join(chunks)
            try:
                return json.loads(raw.decode("utf-8"))
            except ValueError:
                return {"raw_response": raw[:1000].decode("utf-8", errors="replace")}
        try:
            return response.json()
        except (TypeError, ValueError):
            return {"raw_response": response.text[:1000]}

    def send_sms(self, to_phone: str, message: str, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        """Send one SMS with provider-aware status handling and bounded retries."""
        started = monotonic()
        if not self.username or not self.api_key:
            logger.warning("Africa's Talking SMS skipped: credentials not configured.")
            result = {"status": "skipped", "reason": "not_configured", "attempts": 0}
            self._emit_metric({"event": "sms_skipped", "reason": result["reason"]})
            return result

        try:
            normalized_phone = self._normalize_phone_number(to_phone)
            normalized_message = self._validate_message(message)
        except SmsValidationError as exc:
            logger.error("Africa's Talking SMS rejected: %s", exc)
            return {"status": "failed", "reason": "invalid_parameters", "error_code": str(exc), "attempts": 0}

        payload = {"username": self.username, "to": normalized_phone, "message": normalized_message}
        headers = {
            "apiKey": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        if idempotency_key is not None:
            if not isinstance(idempotency_key, str) or not idempotency_key.strip():
                return {"status": "failed", "reason": "invalid_idempotency_key", "attempts": 0}
            headers["X-Idempotency-Key"] = idempotency_key.strip()

        last_error = "unknown_error"
        total_attempts = self.retry_policy.max_retries + 1
        for attempt in range(1, total_attempts + 1):
            try:
                response = self.session.post(
                    self.base_url,
                    headers=headers,
                    data=payload,
                    timeout=self.timeout,
                    stream=True,
                )
                retryable = False
                if response.status_code in {408, 429} or response.status_code >= 500:
                    last_error = f"http_{response.status_code}"
                    retryable = True
                elif response.status_code >= 400:
                    last_error = f"http_{response.status_code}"
                else:
                    try:
                        data = self._response_data(response)
                    except SmsValidationError as exc:
                        last_error = str(exc)
                        data = None
                    if data is None:
                        success, provider_error = False, None
                    else:
                        success, provider_error, data = self._provider_result(data)
                    if success:
                        latency_ms = round((monotonic() - started) * 1000, 2)
                        self._emit_metric({"event": "sms_sent", "attempt": attempt, "status_code": response.status_code, "latency_ms": latency_ms})
                        logger.info("Africa's Talking SMS sent to %s on attempt %s", self._mask_phone_number(normalized_phone), attempt)
                        return {"status": "sent", "attempts": attempt, "response": data, "latency_ms": latency_ms}
                    last_error = provider_error or "provider_rejected"

                self._emit_metric({"event": "sms_attempt_failed", "attempt": attempt, "status_code": response.status_code, "reason": last_error})
                if retryable and attempt < total_attempts:
                    delay = self._backoff(attempt, self._retry_after(response))
                    logger.warning("Africa's Talking SMS retry for %s after %s (attempt %s/%s, delay %.2fs)", self._mask_phone_number(normalized_phone), last_error, attempt, total_attempts, delay)
                    time.sleep(delay)
                    continue
                break
            except requests.exceptions.Timeout:
                last_error = "timeout_ambiguous"
                self._emit_metric({"event": "sms_timeout", "attempt": attempt})
                if self.retry_policy.retry_ambiguous and attempt < total_attempts:
                    time.sleep(self._backoff(attempt))
                    continue
                break
            except requests.exceptions.RequestException:
                last_error = "request_error"
                self._emit_metric({"event": "sms_request_error", "attempt": attempt})
                if attempt < total_attempts:
                    time.sleep(self._backoff(attempt))
                    continue
                break

        latency_ms = round((monotonic() - started) * 1000, 2)
        logger.error("Africa's Talking SMS failed after %s attempts for %s: %s", total_attempts, self._mask_phone_number(normalized_phone), last_error)
        return {"status": "failed", "attempts": total_attempts if last_error != "timeout_ambiguous" or self.retry_policy.retry_ambiguous else 1, "reason": last_error, "latency_ms": latency_ms}
