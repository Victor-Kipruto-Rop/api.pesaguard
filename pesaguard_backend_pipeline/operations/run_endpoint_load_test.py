"""Run bounded load profiles against an explicitly approved HTTP test endpoint."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import re
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import local
from typing import Any
from urllib.parse import urlparse

import requests

from .run_auth_load_test import LatencyHistogram

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_SUPPORTED_METHODS = {"DELETE", "GET", "PATCH", "POST", "PUT"}
_PLACEHOLDER = re.compile(r"\{\{(request_id|sequence|profile|stage)\}\}")
_HTTP_SESSION = local()
_MAX_REQUESTS_PER_STAGE = 1_000_000
_MAX_CONCURRENCY = 1_000
_MAX_STRESS_STEPS = 20
_MAX_DURATION_SECONDS = 86_400
_MAX_TIMEOUT_SECONDS = 300
_REQUIRED_THRESHOLDS = (
    "max_error_rate",
    "max_throttle_rate",
    "max_p95_ms",
    "min_requests_per_second",
)


def validate_target(endpoint_url: str, allow_nonlocal_target: bool) -> str:
    parsed = urlparse(endpoint_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or any(character in endpoint_url for character in "\r\n")
    ):
        raise ValueError("target URL must be an HTTP(S) endpoint without credentials, query, or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("target URL contains an invalid port") from exc
    if port == 0:
        raise ValueError("target URL port must be greater than zero")
    if parsed.hostname.lower() not in _LOCAL_HOSTS:
        if parsed.scheme != "https":
            raise ValueError("non-local targets must use HTTPS")
        if not allow_nonlocal_target:
            raise ValueError("non-local targets require the explicit --allow-nonlocal-target option")
    return endpoint_url.rstrip("/")


def validate_headers(headers: dict[str, str]) -> dict[str, str]:
    if not isinstance(headers, dict):
        raise TypeError("load-test headers must be a JSON object")
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not name or not isinstance(value, str):
            raise ValueError("load-test header names and values must be non-empty strings")
        if any(character in name + value for character in "\r\n"):
            raise ValueError("load-test headers must not contain line breaks")
        if name.lower() in {"connection", "content-length", "host", "transfer-encoding"}:
            raise ValueError(f"load-test header {name!r} is controlled by the HTTP client")
        normalized[name] = value
    return normalized


def build_phase_plan(
    profile: str,
    requests_per_stage: int,
    concurrency: int,
    stress_steps: int,
) -> list[dict[str, int | str]]:
    if profile not in {"load", "stress", "spike", "soak"}:
        raise ValueError("profile must be load, stress, spike, or soak")
    if not 1 <= requests_per_stage <= _MAX_REQUESTS_PER_STAGE:
        raise ValueError(f"requests per stage must be between 1 and {_MAX_REQUESTS_PER_STAGE}")
    if not 1 <= concurrency <= _MAX_CONCURRENCY:
        raise ValueError(f"concurrency must be between 1 and {_MAX_CONCURRENCY}")
    if not 1 <= stress_steps <= _MAX_STRESS_STEPS:
        raise ValueError(f"stress steps must be between 1 and {_MAX_STRESS_STEPS}")

    if profile == "stress":
        levels = sorted(
            {
                max(1, math.ceil(concurrency * step / stress_steps))
                for step in range(1, stress_steps + 1)
            }
        )
        return [
            {"name": f"stress-{index}", "concurrency": level, "requests": requests_per_stage}
            for index, level in enumerate(levels, start=1)
        ]
    if profile == "spike":
        baseline = max(1, concurrency // 4)
        return [
            {"name": "baseline", "concurrency": baseline, "requests": requests_per_stage},
            {"name": "spike", "concurrency": concurrency, "requests": requests_per_stage},
            {"name": "recovery", "concurrency": baseline, "requests": requests_per_stage},
        ]
    return [{"name": profile, "concurrency": concurrency, "requests": requests_per_stage}]


def _render_template(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {key: _render_template(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [_render_template(item, context) for item in value]
    if isinstance(value, str):
        return _PLACEHOLDER.sub(lambda match: context[match.group(1)], value)
    return value


def _validate_template(value: Any) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _validate_template(item)
    elif isinstance(value, list):
        for item in value:
            _validate_template(item)
    elif isinstance(value, str):
        unsupported = {
            name
            for name in re.findall(r"\{\{([^{}]+)\}\}", value)
            if name not in {"request_id", "sequence", "profile", "stage"}
        }
        if unsupported:
            raise ValueError(f"unsupported load-test template placeholder: {min(unsupported)}")


def _request(
    endpoint_url: str,
    method: str,
    payload_template: Any,
    headers_template: dict[str, str],
    context: dict[str, str],
    timeout: float,
    hmac_secret: str | None,
    signature_header: str,
    signature_encoding: str,
) -> tuple[int | None, float, str | None]:
    session = getattr(_HTTP_SESSION, "session", None)
    if session is None:
        session = requests.Session()
        _HTTP_SESSION.session = session
    started = time.perf_counter()
    try:
        payload = _render_template(payload_template, context)
        headers = _render_template(headers_template, context)
        request_body: dict[str, Any] = {"json": payload}
        if hmac_secret is not None:
            raw_body = json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
            digest = hmac.new(
                hmac_secret.encode("utf-8"),
                raw_body,
                hashlib.sha256,
            ).digest()
            signature = (
                digest.hex()
                if signature_encoding == "hex"
                else base64.b64encode(digest).decode("ascii")
            )
            headers[signature_header] = signature
            if not any(name.lower() == "content-type" for name in headers):
                headers["Content-Type"] = "application/json"
            request_body = {"data": raw_body}
        response = session.request(
            method,
            endpoint_url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            **request_body,
        )
        return response.status_code, (time.perf_counter() - started) * 1000, None
    except requests.RequestException as exc:
        return None, (time.perf_counter() - started) * 1000, type(exc).__name__


def _worker(
    worker_index: int,
    worker_count: int,
    request_count: int,
    sequence_offset: int,
    run_id: str,
    phase_name: str,
    profile: str,
    endpoint_url: str,
    method: str,
    payload_template: Any,
    headers_template: dict[str, str],
    timeout: float,
    hmac_secret: str | None,
    signature_header: str,
    signature_encoding: str,
) -> dict[str, Any]:
    latency = LatencyHistogram()
    status_codes: Counter[str] = Counter()
    transport_errors: Counter[str] = Counter()
    throttled = 0
    functional_failures = 0
    server_errors = 0
    try:
        for index in range(worker_index, request_count, worker_count):
            sequence = sequence_offset + index
            context = {
                "request_id": f"{run_id}-{sequence:010d}",
                "sequence": str(sequence),
                "profile": profile,
                "stage": phase_name,
            }
            status, duration_ms, error = _request(
                endpoint_url,
                method,
                payload_template,
                headers_template,
                context,
                timeout,
                hmac_secret,
                signature_header,
                signature_encoding,
            )
            latency.observe(duration_ms)
            if error:
                transport_errors[error] += 1
                status_codes["transport_error"] += 1
                functional_failures += 1
            else:
                status_codes[str(status)] += 1
                if status == 429:
                    throttled += 1
                elif status is None or not 200 <= status < 300:
                    functional_failures += 1
                    if status is not None and status >= 500:
                        server_errors += 1
    finally:
        session = getattr(_HTTP_SESSION, "session", None)
        if session is not None:
            session.close()
            del _HTTP_SESSION.session

    return {
        "latency": latency,
        "status_codes": status_codes,
        "transport_errors": transport_errors,
        "throttled": throttled,
        "functional_failures": functional_failures,
        "server_errors": server_errors,
    }


def _run_phase(
    endpoint_url: str,
    method: str,
    payload_template: Any,
    headers: dict[str, str],
    profile: str,
    phase_name: str,
    request_count: int,
    concurrency: int,
    sequence_offset: int,
    run_id: str,
    timeout: float,
    thresholds: dict[str, float | None],
    hmac_secret: str | None,
    signature_header: str,
    signature_encoding: str,
) -> dict[str, Any]:
    latency = LatencyHistogram()
    status_codes: Counter[str] = Counter()
    transport_errors: Counter[str] = Counter()
    throttled = 0
    functional_failures = 0
    server_errors = 0
    worker_count = min(concurrency, request_count)

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(
                _worker,
                worker_index,
                worker_count,
                request_count,
                sequence_offset,
                run_id,
                phase_name,
                profile,
                endpoint_url,
                method,
                payload_template,
                headers,
                timeout,
                hmac_secret,
                signature_header,
                signature_encoding,
            )
            for worker_index in range(worker_count)
        ]
        for future in as_completed(futures):
            result = future.result()
            latency.merge(result["latency"])
            status_codes.update(result["status_codes"])
            transport_errors.update(result["transport_errors"])
            throttled += result["throttled"]
            functional_failures += result["functional_failures"]
            server_errors += result["server_errors"]
    elapsed = time.perf_counter() - started

    error_rate = (server_errors + sum(transport_errors.values())) / request_count
    throttle_rate = throttled / request_count
    requests_per_second = request_count / elapsed if elapsed else 0.0
    checks: dict[str, bool] = {"functional_success": functional_failures == 0}
    if thresholds["max_error_rate"] is not None:
        checks["error_rate"] = error_rate <= thresholds["max_error_rate"]
    if thresholds["max_throttle_rate"] is not None:
        checks["throttle_rate"] = throttle_rate <= thresholds["max_throttle_rate"]
    if thresholds["max_p95_ms"] is not None:
        checks["p95_latency"] = latency.percentile(0.95) <= thresholds["max_p95_ms"]
    if thresholds["min_requests_per_second"] is not None:
        checks["throughput"] = requests_per_second >= thresholds["min_requests_per_second"]
    acceptance_ready = all(thresholds[name] is not None for name in _REQUIRED_THRESHOLDS)
    passed = all(checks.values()) if acceptance_ready else (
        False if functional_failures else None
    )
    return {
        "name": phase_name,
        "requested_requests": request_count,
        "completed_requests": latency.count,
        "concurrency": concurrency,
        "elapsed_seconds": round(elapsed, 3),
        "requests_per_second": round(requests_per_second, 2),
        "latency": latency.summary(),
        "status_codes": dict(status_codes),
        "transport_errors": dict(transport_errors),
        "functional_failures": functional_failures,
        "server_error_rate": round(error_rate, 5),
        "throttle_rate": round(throttle_rate, 5),
        "slo_checks": checks,
        "acceptance_ready": acceptance_ready,
        "passed": passed,
    }


def run_load_profile(
    endpoint_url: str,
    method: str,
    payload_template: Any,
    headers: dict[str, str],
    profile: str,
    requests_per_stage: int,
    concurrency: int,
    timeout: float,
    stress_steps: int,
    duration_seconds: float,
    max_error_rate: float | None,
    max_throttle_rate: float | None,
    max_p95_ms: float | None,
    min_requests_per_second: float | None,
    confirm_test_tenant: bool,
    allow_nonlocal_target: bool = False,
    hmac_secret: str | None = None,
    signature_header: str = "X-MPESA-SIGNATURE",
    signature_encoding: str = "hex",
) -> dict[str, Any]:
    if not confirm_test_tenant:
        raise ValueError("load generation requires explicit --confirm-test-tenant confirmation")
    endpoint_url = validate_target(endpoint_url, allow_nonlocal_target)
    method = method.upper()
    if method not in _SUPPORTED_METHODS:
        raise ValueError(f"method must be one of {', '.join(sorted(_SUPPORTED_METHODS))}")
    if timeout <= 0 or timeout > _MAX_TIMEOUT_SECONDS or not math.isfinite(timeout):
        raise ValueError(f"timeout must be positive and at most {_MAX_TIMEOUT_SECONDS} seconds")
    if hmac_secret is not None and (not hmac_secret or payload_template is None):
        raise ValueError("HMAC signing requires a non-empty secret and a JSON payload template")
    if signature_encoding not in {"hex", "base64"}:
        raise ValueError("signature encoding must be hex or base64")
    if not 0 < duration_seconds <= _MAX_DURATION_SECONDS or not math.isfinite(duration_seconds):
        raise ValueError(f"duration must be greater than zero and at most {_MAX_DURATION_SECONDS} seconds")
    for name, value in (
        ("max_error_rate", max_error_rate),
        ("max_throttle_rate", max_throttle_rate),
    ):
        if value is not None and not 0 <= value <= 1:
            raise ValueError(f"{name.replace('_', '-')} must be between zero and one")
    for name, value in (
        ("max_p95_ms", max_p95_ms),
        ("min_requests_per_second", min_requests_per_second),
    ):
        if value is not None and (value <= 0 or not math.isfinite(value)):
            raise ValueError(f"{name.replace('_', '-')} must be a positive finite number")

    header_templates = validate_headers(headers)
    if hmac_secret is not None:
        validate_headers({signature_header: "signature"})
        if any(name.lower() == signature_header.lower() for name in header_templates):
            raise ValueError("signature header must not also be set in load-test headers")
    _validate_template(payload_template)
    _validate_template(header_templates)
    phase_plan = build_phase_plan(profile, requests_per_stage, concurrency, stress_steps)
    thresholds = {
        "max_error_rate": max_error_rate,
        "max_throttle_rate": max_throttle_rate,
        "max_p95_ms": max_p95_ms,
        "min_requests_per_second": min_requests_per_second,
    }
    run_id = uuid.uuid4().hex
    phases: list[dict[str, Any]] = []
    sequence_offset = 0
    started = time.perf_counter()

    if profile == "soak":
        deadline = started + duration_seconds
        while not phases or time.perf_counter() < deadline:
            phase_name = f"soak-{len(phases) + 1}"
            phases.append(
                _run_phase(
                    endpoint_url,
                    method,
                    payload_template,
                    header_templates,
                    profile,
                    phase_name,
                    requests_per_stage,
                    concurrency,
                    sequence_offset,
                    run_id,
                    timeout,
                    thresholds,
                    hmac_secret,
                    signature_header,
                    signature_encoding,
                )
            )
            sequence_offset += requests_per_stage
    else:
        for phase in phase_plan:
            request_count = int(phase["requests"])
            phases.append(
                _run_phase(
                    endpoint_url,
                    method,
                    payload_template,
                    header_templates,
                    profile,
                    str(phase["name"]),
                    request_count,
                    int(phase["concurrency"]),
                    sequence_offset,
                    run_id,
                    timeout,
                    thresholds,
                    hmac_secret,
                    signature_header,
                    signature_encoding,
                )
            )
            sequence_offset += request_count

    acceptance_ready = all(thresholds[name] is not None for name in _REQUIRED_THRESHOLDS)
    failed = any(phase["passed"] is False for phase in phases)
    passed = (
        False if failed else
        all(phase["passed"] is True for phase in phases) if acceptance_ready else None
    )
    elapsed = time.perf_counter() - started
    return {
        "run_id": run_id,
        "target_origin": _target_origin(endpoint_url),
        "method": method,
        "profile": profile,
        "requested_duration_seconds": duration_seconds if profile == "soak" else None,
        "elapsed_seconds": round(elapsed, 3),
        "requested_requests": sum(phase["requested_requests"] for phase in phases),
        "completed_requests": sum(phase["completed_requests"] for phase in phases),
        "acceptance_ready": acceptance_ready,
        "passed": passed,
        "phases": phases,
    }


def _target_origin(endpoint_url: str) -> str:
    parsed = urlparse(endpoint_url)
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{parsed.scheme}://{host}{port}"


def _load_json_object(raw: str, environment_name: str) -> dict[str, str]:
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{environment_name} must contain a JSON object") from exc
    if not isinstance(decoded, dict) or not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in decoded.items()
    ):
        raise ValueError(f"{environment_name} must contain a JSON object with string values")
    return decoded


def _load_payload_template(path: str | None) -> Any:
    if path is None:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("payload template file must contain valid JSON") from exc


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run bounded load, stress, spike, or soak traffic against a test HTTP endpoint"
    )
    parser.add_argument("--target-url", default=os.getenv("PESAGUARD_LOAD_TEST_URL", ""))
    parser.add_argument("--method", choices=sorted(_SUPPORTED_METHODS), default="POST")
    parser.add_argument("--payload-template")
    parser.add_argument("--profile", choices=("load", "stress", "spike", "soak"), default="load")
    parser.add_argument("--requests-per-stage", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--stress-steps", type=int, default=4)
    parser.add_argument("--duration-seconds", type=float, default=60)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--max-error-rate", type=float)
    parser.add_argument("--max-throttle-rate", type=float)
    parser.add_argument("--max-p95-ms", type=float)
    parser.add_argument("--min-requests-per-second", type=float)
    parser.add_argument("--hmac-secret-env")
    parser.add_argument("--signature-header", default="X-MPESA-SIGNATURE")
    parser.add_argument("--signature-encoding", choices=("hex", "base64"), default="hex")
    parser.add_argument("--confirm-test-tenant", action="store_true")
    parser.add_argument("--allow-nonlocal-target", action="store_true")
    parser.add_argument("--json-path", default="endpoint_load_validation.json")
    args = parser.parse_args()

    if not args.confirm_test_tenant:
        raise SystemExit("Refusing to generate HTTP traffic without --confirm-test-tenant")
    if not args.target_url:
        raise SystemExit("--target-url or PESAGUARD_LOAD_TEST_URL is required")
    try:
        endpoint_url = validate_target(args.target_url, args.allow_nonlocal_target)
        headers = _load_json_object(
            os.getenv("PESAGUARD_LOAD_TEST_HEADERS_JSON", "{}"),
            "PESAGUARD_LOAD_TEST_HEADERS_JSON",
        )
        payload_template = _load_payload_template(args.payload_template)
        hmac_secret = (
            os.getenv(args.hmac_secret_env)
            if args.hmac_secret_env
            else None
        )
        if args.hmac_secret_env and not hmac_secret:
            raise ValueError(f"{args.hmac_secret_env} must be set and non-empty")
        result = run_load_profile(
            endpoint_url=endpoint_url,
            method=args.method,
            payload_template=payload_template,
            headers=headers,
            profile=args.profile,
            requests_per_stage=args.requests_per_stage,
            concurrency=args.concurrency,
            timeout=args.timeout,
            stress_steps=args.stress_steps,
            duration_seconds=args.duration_seconds,
            max_error_rate=args.max_error_rate,
            max_throttle_rate=args.max_throttle_rate,
            max_p95_ms=args.max_p95_ms,
            min_requests_per_second=args.min_requests_per_second,
            confirm_test_tenant=args.confirm_test_tenant,
            allow_nonlocal_target=args.allow_nonlocal_target,
            hmac_secret=hmac_secret,
            signature_header=args.signature_header,
            signature_encoding=args.signature_encoding,
        )
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

    with open(args.json_path, "w", encoding="utf-8") as output:
        json.dump(result, output, indent=2)
    print(json.dumps(result, indent=2))
    if result["passed"] is False:
        raise SystemExit("HTTP load validation failed functional checks or configured SLOs")
    if result["passed"] is None:
        print("Diagnostic run only: configure all four thresholds before using this as an acceptance result.")


if __name__ == "__main__":
    main()
