"""
Security helper functions for IP resolution, payload limit checks, and HMAC source validation.

Provides constant-time HMAC header evaluation, reverse-proxy aware IP parsing,
and strict fail-closed webhook validation for Daraja callback endpoints.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import os
from typing import List

from flask import Request

logger = logging.getLogger("pesaguard.security_helpers")


def get_client_ip(request: Request) -> str:
    """Safely resolve the client IP address from the incoming Flask HTTP request.

    Evaluates `X-Forwarded-For` headers ONLY if `PESAGUARD_TRUSTED_PROXY_COUNT`
    is explicitly set to a positive integer (e.g., 1 when running behind a single
    AWS ALB or NGINX reverse proxy). Otherwise, defaults to `request.remote_addr`
    to prevent header spoofing attacks.

    Args:
        request: Flask request instance

    Returns:
        Resolved client IP string or empty string
    """
    try:
        trusted_proxy_count = int(os.getenv("PESAGUARD_TRUSTED_PROXY_COUNT", "0"))
    except ValueError:
        trusted_proxy_count = 0

    if trusted_proxy_count > 0:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
            client_index = len(hops) - trusted_proxy_count
            if client_index >= 0:
                candidate = hops[client_index]
                try:
                    return str(ipaddress.ip_address(candidate))
                except ValueError:
                    logger.warning("Ignoring invalid trusted-proxy client address")

    return request.remote_addr or ""


def _parse_allowed_ips() -> List[str]:
    """Parse raw comma-separated IP and CIDR definitions from environment variables."""
    raw = os.getenv("DARAJA_ALLOWED_IPS", "")
    if not raw:
        return []
    return [ip.strip() for ip in raw.split(",") if ip.strip()]


def is_payload_within_limit(request: Request, max_body_bytes: int | None = None) -> bool:
    """Guard against oversized HTTP request payloads prior to parsing.

    Args:
        request: Incoming Flask request object

    Returns:
        True if request body is within limit, False otherwise
    """
    if max_body_bytes is None:
        max_body_bytes = int(os.getenv("PESAGUARD_API_MAX_BODY_BYTES", "1048576"))
    content_length = request.content_length
    if content_length is not None:
        return content_length <= max_body_bytes

    body = request.get_data(cache=False, as_text=False)
    return len(body or b"") <= max_body_bytes


def is_allowed_source(client_ip: str, request: Request) -> bool:
    """Validate incoming Daraja webhook origin via constant-time HMAC secret or IP allowlist.

    Fails CLOSED (rejects requests) if neither `DARAJA_SHARED_SECRET` nor
    `DARAJA_ALLOWED_IPS` is configured, unless explicitly overridden for local
    development via `PESAGUARD_ALLOW_UNRESTRICTED_WEBHOOK_SOURCE=1`.

    Args:
        client_ip: Resolved client IP address string
        request: Incoming Flask request object

    Returns:
        True if origin source is authenticated and authorized, False otherwise
    """
    shared_secret = os.getenv("DARAJA_SHARED_SECRET", "").strip()
    configured_ips = _parse_allowed_ips()

    # Fail closed if security parameters are completely unconfigured.
    if not shared_secret and not configured_ips:
        logger.error(
            "Webhook source validation is fully unconfigured (missing DARAJA_SHARED_SECRET "
            "and DARAJA_ALLOWED_IPS). Rejecting all incoming webhook requests."
        )
        return False

    # Check shared secret HMAC header using constant-time digest comparison
    if shared_secret:
        header_secret = request.headers.get("X-Daraja-Shared-Secret", "")
        if not hmac.compare_digest(header_secret, shared_secret):
            logger.warning(
                "Webhook request failed HMAC secret comparison. client_ip=%s",
                client_ip,
            )
            return False

    # Validate client IP / CIDR range if configured
    if configured_ips:
        try:
            parsed_ip = ipaddress.ip_address(client_ip)
        except ValueError:
            logger.warning("Invalid client IP address provided for validation: '%s'", client_ip)
            return False

        ip_allowed = False
        for allowed in configured_ips:
            try:
                if "/" in allowed:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if parsed_ip in network:
                        ip_allowed = True
                        break
                elif parsed_ip == ipaddress.ip_address(allowed):
                    ip_allowed = True
                    break
            except ValueError:
                continue

        if not ip_allowed:
            logger.warning("Webhook request from unauthorized IP: %s", client_ip)
            return False

    return True


def sanitize_error_message(error: object) -> str:
    """Return a generic, safe client error message for external API responses."""
    return "Invalid request"
