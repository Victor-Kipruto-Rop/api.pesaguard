#!/usr/bin/env python3
"""Read-only production smoke checks for a deployed PesaGuard API.

This script never writes transactions or triggers payment operations. It verifies
basic reachability and readiness contracts and can optionally check one
authenticated read-only endpoint. It intentionally never prints secrets.
"""
from __future__ import annotations

import json
import os
import sys
import time
from math import isfinite
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def request(url: str, token: str | None = None, timeout: float = 10.0):
    headers = {"Accept": "application/json", "User-Agent": "PesaGuard-Integration-Smoke/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, headers=headers, method="GET")
    started = time.monotonic()
    try:
        with urlopen(req, timeout=timeout) as response:
            body = response.read(1_000_001)
            if len(body) > 1_000_000:
                raise RuntimeError("response exceeded 1 MB safety limit")
            status = response.status
            content_type = response.headers.get("Content-Type", "")
    except HTTPError as exc:
        body = exc.read(1_000_001)
        status = exc.code
        content_type = exc.headers.get("Content-Type", "")
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"request failed ({type(exc).__name__})") from None
    elapsed_ms = round((time.monotonic() - started) * 1000)
    payload = None
    if "json" in content_type.lower():
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
    return status, payload, elapsed_ms


def main() -> int:
    base_url = (os.getenv("PESAGUARD_BASE_URL") or "").strip().rstrip("/")
    parsed_base = urlparse(base_url)
    if (
        parsed_base.scheme not in {"https", "http"}
        or not parsed_base.netloc
        or parsed_base.username is not None
        or parsed_base.password is not None
        or parsed_base.query
        or parsed_base.fragment
    ):
        print("FAIL configuration: PESAGUARD_BASE_URL must be an HTTP(S) URL without credentials, query, or fragment")
        return 2
    try:
        timeout = float(os.getenv("PESAGUARD_SMOKE_TIMEOUT_SECONDS", "10"))
    except (TypeError, ValueError):
        print("FAIL configuration: PESAGUARD_SMOKE_TIMEOUT_SECONDS must be a positive number")
        return 2
    if not isfinite(timeout) or timeout <= 0 or timeout > 60:
        print("FAIL configuration: PESAGUARD_SMOKE_TIMEOUT_SECONDS must be greater than 0 and at most 60")
        return 2
    token = (os.getenv("PESAGUARD_SMOKE_BEARER_TOKEN") or "").strip() or None
    failures = 0

    checks = [
        ("liveness", os.getenv("PESAGUARD_LIVEZ_PATH", "/livez"), {200}),
        ("readiness", os.getenv("PESAGUARD_HEALTH_PATH", "/health"), {200}),
        ("public status", os.getenv("PESAGUARD_PUBLIC_STATUS_PATH", "/public/status"), {200}),
    ]
    optional_path = (os.getenv("PESAGUARD_AUTHENTICATED_READ_PATH") or "").strip()
    if optional_path:
        if not token:
            print("FAIL configuration: authenticated read path set but no smoke bearer token supplied")
            return 2
        checks.append(("authenticated read", optional_path, {200}))

    for name, path, expected in checks:
        url = f"{base_url}{path if path.startswith('/') else '/' + path}"
        try:
            status, payload, elapsed_ms = request(url, token if name == "authenticated read" else None, timeout)
            healthy_payload = True
            if name == "readiness":
                # /health exposes {"status": "ok"|"degraded"|"failed", ...}.
                healthy_payload = isinstance(payload, dict) and payload.get("status") == "ok"
            elif name == "public status":
                # The public contract nests its state under overall.status.
                overall = payload.get("overall") if isinstance(payload, dict) else None
                healthy_payload = isinstance(overall, dict) and overall.get("status") == "operational"
            passed = status in expected and healthy_payload
            print(f'{"PASS" if passed else "FAIL"} {name}: HTTP {status}, {elapsed_ms} ms')
            if not passed:
                failures += 1
        except RuntimeError as exc:
            print(f"FAIL {name}: {exc}")
            failures += 1

    sentry_dsn = (os.getenv("SENTRY_DSN") or "").strip()
    if sentry_dsn:
        # Validate syntax without echoing the DSN or its project key.
        from urllib.parse import urlparse
        parsed = urlparse(sentry_dsn)
        valid = parsed.scheme in {"https", "http"} and bool(parsed.netloc) and bool(parsed.path.strip("/"))
        print(f'{"PASS" if valid else "FAIL"} Sentry DSN syntax: {"configured" if valid else "malformed (value not shown)"}')
        if not valid:
            failures += 1
    else:
        print("INFO Sentry DSN: not configured (optional integration)")

    if os.getenv("PESAGUARD_REQUIRE_OTEL", "").strip().lower() in {"1", "true", "yes"}:
        otel_endpoint = (os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or "").strip()
        parsed_endpoint = urlparse(otel_endpoint)
        if parsed_endpoint.scheme in {"https", "http"} and parsed_endpoint.netloc:
            print("PASS OpenTelemetry endpoint configuration: configured (delivery not verified by this check)")
        else:
            print("FAIL OpenTelemetry endpoint configuration: missing or invalid URL")
            failures += 1
    else:
        print("INFO OpenTelemetry: remote trace delivery must be verified in the configured trace backend")

    print(f"\nSmoke result: {'PASS' if failures == 0 else 'FAIL'} ({failures} failed check(s))")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
