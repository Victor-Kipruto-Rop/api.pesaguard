"""Exercise login and device-list endpoints with bounded-memory concurrency."""

from __future__ import annotations

import argparse
import json
import math
import os
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import local
from typing import Any
from urllib.parse import urlparse

import requests


_LATENCY_BUCKETS_MS = (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000)
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_HTTP_SESSION = local()


class LatencyHistogram:
    def __init__(self) -> None:
        self.counts = [0] * (len(_LATENCY_BUCKETS_MS) + 1)
        self.count = 0
        self.total_ms = 0.0
        self.max_ms = 0.0

    def observe(self, milliseconds: float) -> None:
        self.count += 1
        self.total_ms += milliseconds
        self.max_ms = max(self.max_ms, milliseconds)
        for index, boundary in enumerate(_LATENCY_BUCKETS_MS):
            if milliseconds <= boundary:
                self.counts[index] += 1
                return
        self.counts[-1] += 1

    def merge(self, other: "LatencyHistogram") -> None:
        self.count += other.count
        self.total_ms += other.total_ms
        self.max_ms = max(self.max_ms, other.max_ms)
        self.counts = [left + right for left, right in zip(self.counts, other.counts, strict=True)]

    def percentile(self, percentile: float) -> float:
        if not self.count:
            return 0.0
        target = max(1, math.ceil(self.count * percentile))
        accumulated = 0
        for index, bucket_count in enumerate(self.counts):
            accumulated += bucket_count
            if accumulated >= target:
                if index < len(_LATENCY_BUCKETS_MS):
                    return float(_LATENCY_BUCKETS_MS[index])
                return round(self.max_ms, 3)
        return round(self.max_ms, 3)

    def summary(self) -> dict[str, float | int]:
        return {
            "count": self.count,
            "avg_ms": round(self.total_ms / self.count, 3) if self.count else 0.0,
            "p50_upper_bound_ms": self.percentile(0.50),
            "p95_upper_bound_ms": self.percentile(0.95),
            "p99_upper_bound_ms": self.percentile(0.99),
            "max_ms": round(self.max_ms, 3),
        }


def _decode_payload(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body.decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}


def _request_json(url: str, method: str, payload: dict[str, Any] | None, token: str | None, timeout: float):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    session = getattr(_HTTP_SESSION, "session", None)
    if session is None:
        session = requests.Session()
        _HTTP_SESSION.session = session
    started = time.perf_counter()
    try:
        response = session.request(method, url, json=payload, headers=headers, timeout=timeout)
        return response.status_code, _decode_payload(response.content), (time.perf_counter() - started) * 1000, None
    except requests.RequestException as exc:
        return None, {}, (time.perf_counter() - started) * 1000, type(exc).__name__


def _worker(
    worker_index: int,
    request_count: int,
    concurrency: int,
    users: list[dict[str, str]],
    base_url: str,
    timeout: float,
    probe_devices: bool,
) -> dict[str, Any]:
    login_latency = LatencyHistogram()
    device_latency = LatencyHistogram()
    login_statuses: Counter[str] = Counter()
    device_statuses: Counter[str] = Counter()
    transport_errors: Counter[str] = Counter()
    functional_failures = 0
    device_failures = 0

    for request_index in range(worker_index, request_count, concurrency):
        user = users[request_index % len(users)]
        payload = {
            "username": user["username"],
            "password": user["password"],
            "tenant_id": user["tenant_id"],
            "device_id": user.get("device_id", f"auth-load-{request_index % len(users)}"),
        }
        status, response, duration_ms, error = _request_json(
            f"{base_url}/auth/login", "POST", payload, None, timeout
        )
        login_latency.observe(duration_ms)
        if error:
            transport_errors[error] += 1
        login_statuses[str(status) if status is not None else "transport_error"] += 1
        if status not in {200, 429}:
            functional_failures += 1

        token = response.get("access_token")
        if probe_devices and status == 200 and isinstance(token, str):
            device_status, _, device_duration_ms, device_error = _request_json(
                f"{base_url}/auth/devices", "GET", None, token, timeout
            )
            device_latency.observe(device_duration_ms)
            if device_error:
                transport_errors[device_error] += 1
            device_statuses[str(device_status) if device_status is not None else "transport_error"] += 1
            if device_status != 200:
                device_failures += 1

    session = getattr(_HTTP_SESSION, "session", None)
    if session is not None:
        session.close()
        del _HTTP_SESSION.session
    return {
        "login_latency": login_latency,
        "device_latency": device_latency,
        "login_statuses": login_statuses,
        "device_statuses": device_statuses,
        "transport_errors": transport_errors,
        "functional_failures": functional_failures,
        "device_failures": device_failures,
    }


def _load_users(raw_users: str) -> list[dict[str, str]]:
    try:
        decoded = json.loads(raw_users)
    except json.JSONDecodeError as exc:
        raise ValueError("PESAGUARD_AUTH_LOAD_USERS_JSON must be valid JSON") from exc
    if not isinstance(decoded, list) or not decoded:
        raise ValueError("PESAGUARD_AUTH_LOAD_USERS_JSON must be a non-empty list")
    required = {"username", "password", "tenant_id"}
    users = []
    for index, user in enumerate(decoded):
        if not isinstance(user, dict) or not required.issubset(user):
            raise ValueError(f"load user at index {index} must contain username, password, and tenant_id")
        normalized = {key: str(value) for key, value in user.items() if key in required | {"device_id"}}
        if not all(normalized.get(key) for key in required):
            raise ValueError(f"load user at index {index} contains an empty required value")
        users.append(normalized)
    return users


def run(
    base_url: str,
    users: list[dict[str, str]],
    request_count: int,
    concurrency: int,
    timeout: float,
    probe_devices: bool,
    max_server_error_rate: float,
    max_throttle_rate: float | None = None,
    max_login_p95_ms: float | None = None,
    min_login_requests_per_second: float | None = None,
) -> dict[str, Any]:
    login_latency = LatencyHistogram()
    device_latency = LatencyHistogram()
    login_statuses: Counter[str] = Counter()
    device_statuses: Counter[str] = Counter()
    transport_errors: Counter[str] = Counter()
    functional_failures = 0
    device_failures = 0

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(_worker, worker, request_count, concurrency, users, base_url, timeout, probe_devices)
            for worker in range(concurrency)
        ]
        for future in as_completed(futures):
            worker_result = future.result()
            login_latency.merge(worker_result["login_latency"])
            device_latency.merge(worker_result["device_latency"])
            login_statuses.update(worker_result["login_statuses"])
            device_statuses.update(worker_result["device_statuses"])
            transport_errors.update(worker_result["transport_errors"])
            functional_failures += worker_result["functional_failures"]
            device_failures += worker_result["device_failures"]
    elapsed = time.perf_counter() - started

    throttled = login_statuses.get("429", 0)
    server_errors = sum(count for status, count in login_statuses.items() if status.isdigit() and int(status) >= 500)
    server_errors += sum(count for status, count in device_statuses.items() if status.isdigit() and int(status) >= 500)
    server_errors += sum(transport_errors.values())
    server_error_rate = server_errors / max(1, request_count + device_latency.count)
    throttle_rate = throttled / max(1, request_count)
    requests_per_second = request_count / elapsed if elapsed else 0.0
    slo_checks = {
        "server_error_rate": server_error_rate <= max_server_error_rate,
        "throttle_rate": max_throttle_rate is None or throttle_rate <= max_throttle_rate,
        "login_p95_ms": max_login_p95_ms is None or login_latency.percentile(0.95) <= max_login_p95_ms,
        "login_requests_per_second": min_login_requests_per_second is None or requests_per_second >= min_login_requests_per_second,
    }
    return {
        "target": base_url,
        "requested_login_requests": request_count,
        "completed_login_requests": login_latency.count,
        "concurrency": concurrency,
        "test_user_count": len(users),
        "device_list_probe_enabled": probe_devices,
        "elapsed_seconds": round(elapsed, 3),
        "login_requests_per_second": round(requests_per_second, 2),
        "login_latency": login_latency.summary(),
        "device_list_latency": device_latency.summary(),
        "login_statuses": dict(login_statuses),
        "device_list_statuses": dict(device_statuses),
        "transport_errors": dict(transport_errors),
        "functional_failures": functional_failures,
        "device_list_failures": device_failures,
        "throttle_rate": round(throttle_rate, 5),
        "server_error_rate": round(server_error_rate, 5),
        "slo_checks": slo_checks,
        "passed": functional_failures == 0 and device_failures == 0 and all(slo_checks.values()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Load test PesaGuard password login and device listing")
    parser.add_argument("--base-url", default=os.getenv("PESAGUARD_AUTH_LOAD_BASE_URL", ""))
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--max-server-error-rate", type=float, default=0.01)
    parser.add_argument("--max-throttle-rate", type=float)
    parser.add_argument("--max-login-p95-ms", type=float)
    parser.add_argument("--min-login-requests-per-second", type=float)
    parser.add_argument("--skip-device-probe", action="store_true")
    parser.add_argument("--confirm-test-tenant", action="store_true")
    parser.add_argument("--allow-nonlocal-target", action="store_true")
    parser.add_argument("--json-path", default="auth_load_validation.json")
    args = parser.parse_args()

    if not args.confirm_test_tenant:
        raise SystemExit("Refusing to generate authentication traffic without --confirm-test-tenant")
    if not args.base_url:
        raise SystemExit("--base-url or PESAGUARD_AUTH_LOAD_BASE_URL is required")
    parsed = urlparse(args.base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SystemExit("base URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise SystemExit("base URL must not include embedded credentials")
    is_local_target = parsed.hostname.lower() in _LOCAL_HOSTS
    if not is_local_target and parsed.scheme != "https":
        raise SystemExit("non-local targets must use HTTPS")
    if not is_local_target and not args.allow_nonlocal_target:
        raise SystemExit("non-local targets require the explicit --allow-nonlocal-target option")
    if args.requests < 1 or args.concurrency < 1 or args.timeout <= 0:
        raise SystemExit("requests, concurrency, and timeout must be positive")
    if not 0 <= args.max_server_error_rate <= 1:
        raise SystemExit("max-server-error-rate must be between zero and one")
    if args.max_throttle_rate is not None and not 0 <= args.max_throttle_rate <= 1:
        raise SystemExit("max-throttle-rate must be between zero and one")
    if args.max_login_p95_ms is not None and args.max_login_p95_ms <= 0:
        raise SystemExit("max-login-p95-ms must be positive")
    if args.min_login_requests_per_second is not None and args.min_login_requests_per_second <= 0:
        raise SystemExit("min-login-requests-per-second must be positive")

    try:
        users = _load_users(os.getenv("PESAGUARD_AUTH_LOAD_USERS_JSON", ""))
        result = run(
            args.base_url.rstrip("/"),
            users,
            args.requests,
            args.concurrency,
            args.timeout,
            not args.skip_device_probe,
            args.max_server_error_rate,
            args.max_throttle_rate,
            args.max_login_p95_ms,
            args.min_login_requests_per_second,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    with open(args.json_path, "w", encoding="utf-8") as output:
        json.dump(result, output, indent=2)
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit("Authentication load validation failed functional checks or configured SLOs")


if __name__ == "__main__":
    main()