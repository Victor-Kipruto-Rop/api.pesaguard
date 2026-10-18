"""IP-pinned HTTPS transport for tenant-configured webhook destinations.

DNS is resolved once per request. Every returned address is checked, and the
connection is opened to a validated literal IP. TLS SNI and certificate
verification continue to use the original hostname. Redirects and environment
proxy configuration are intentionally not followed/used.
"""
from __future__ import annotations

import ipaddress
import json
import socket
from typing import Any, Dict
from urllib.parse import urlsplit

from urllib3 import HTTPSConnectionPool
from urllib3.util import Timeout


def _public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global


def post_json_pinned(
    url: str,
    *,
    payload: Dict[str, Any],
    headers: Dict[str, str],
    timeout: int,
):
    """POST JSON directly to a public resolved IP while preserving HTTPS identity."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("webhook destination must be HTTPS with a hostname")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("webhook URL contains disallowed components")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("webhook URL has an invalid port") from exc
    if port not in (None, 443):
        raise ValueError("webhook URL port is not allowed")

    hostname = parsed.hostname.encode("idna").decode("ascii")
    try:
        records = socket.getaddrinfo(
            hostname,
            443,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise ValueError("webhook hostname cannot be resolved") from exc

    addresses = sorted({record[4][0] for record in records})
    if not addresses:
        raise ValueError("webhook hostname cannot be resolved")
    # Fail closed if any DNS answer is non-public; do not select only the safe
    # answer from a mixed public/private set.
    if any(not _public_ip(address) for address in addresses):
        raise ValueError("webhook hostname resolves to a disallowed address")

    # Deterministic selection makes behavior predictable; a retry performs a
    # new resolution and repeats all checks, then pins that attempt to one IP.
    target_ip = addresses[0]
    request_path = parsed.path or "/"
    if parsed.query:
        request_path += "?" + parsed.query

    request_headers = dict(headers)
    request_headers["Host"] = hostname
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    pool = HTTPSConnectionPool(
        host=target_ip,
        port=443,
        server_hostname=hostname,
        assert_hostname=hostname,
        cert_reqs="CERT_REQUIRED",
        timeout=Timeout(total=timeout),
        maxsize=1,
        block=True,
    )
    try:
        response = pool.request(
            "POST",
            request_path,
            body=body,
            headers=request_headers,
            retries=False,
            redirect=False,
            timeout=Timeout(total=timeout),
            preload_content=True,
        )
        # Keep a requests-compatible minimal shape for the existing caller.
        class _Response:
            status_code = response.status
            is_redirect = 300 <= response.status < 400
            text = ""

        return _Response()
    finally:
        pool.close()
