import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from operations import run_endpoint_load_test
from shared.daraja.validator import validate_daraja_callback

TEST_SIGNING_SECRET = "load-test-signing-secret-not-for-deployment"


@pytest.fixture
def endpoint_server():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body_size = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(body_size) if body_size else b""
            body = json.loads(raw_body) if raw_body else None
            received.append((body, self.headers.get("X-Load-Secret")))
            signature_header = (
                "X-MPESA-SIGNATURE"
                if self.headers.get("X-MPESA-SIGNATURE")
                else "X-DARAJA-SIGNATURE"
            )
            signature = self.headers.get(signature_header)
            if signature:
                encoding = "base64" if signature_header == "X-DARAJA-SIGNATURE" else "hex"
                valid = validate_daraja_callback(
                    raw_body,
                    signature,
                    TEST_SIGNING_SECRET,
                    signature_encoding=encoding,
                )
                status = 201 if valid else 401
            else:
                status = body.get("response_status", 201) if body else 201
            self.send_response(status)
            self.end_headers()

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/api/v1/webhook", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_load_profile_drives_endpoint_and_keeps_request_data_out_of_report(endpoint_server):
    endpoint_url, received = endpoint_server
    result = run_endpoint_load_test.run_load_profile(
        endpoint_url=endpoint_url,
        method="POST",
        payload_template={
            "event_id": "{{request_id}}",
            "sequence": "{{sequence}}",
            "tenant_id": "load-test-tenant",
        },
        headers={"X-Load-Secret": "test-only-secret"},
        profile="load",
        requests_per_stage=8,
        concurrency=3,
        timeout=2,
        stress_steps=4,
        duration_seconds=1,
        max_error_rate=0,
        max_throttle_rate=0,
        max_p95_ms=1000,
        min_requests_per_second=0.1,
        confirm_test_tenant=True,
    )

    request_ids = [body["event_id"] for body, _ in received]
    sequences = sorted(int(body["sequence"]) for body, _ in received)
    report = json.dumps(result)
    assert len(request_ids) == 8
    assert len(set(request_ids)) == 8
    assert sequences == list(range(8))
    assert all(secret == "test-only-secret" for _, secret in received)
    assert result["completed_requests"] == 8
    assert result["phases"][0]["status_codes"] == {"201": 8}
    assert result["acceptance_ready"] is True
    assert result["passed"] is True
    assert "test-only-secret" not in report
    assert "load-test-tenant" not in report


def test_stress_and_spike_profiles_define_bounded_concurrency_phases():
    stress = run_endpoint_load_test.build_phase_plan(
        "stress", requests_per_stage=12, concurrency=8, stress_steps=4
    )
    spike = run_endpoint_load_test.build_phase_plan(
        "spike", requests_per_stage=12, concurrency=8, stress_steps=4
    )

    assert [phase["concurrency"] for phase in stress] == [2, 4, 6, 8]
    assert [phase["name"] for phase in spike] == ["baseline", "spike", "recovery"]
    assert [phase["concurrency"] for phase in spike] == [2, 8, 2]
    assert all(phase["requests"] == 12 for phase in stress + spike)


@pytest.mark.parametrize(
    ("profile", "expected_names", "expected_concurrency"),
    [
        ("stress", ["stress-1", "stress-2", "stress-3"], [2, 3, 4]),
        ("spike", ["baseline", "spike", "recovery"], [1, 4, 1]),
    ],
)
def test_stress_and_spike_profiles_execute_each_phase(
    endpoint_server,
    profile,
    expected_names,
    expected_concurrency,
):
    endpoint_url, received = endpoint_server
    result = run_endpoint_load_test.run_load_profile(
        endpoint_url=endpoint_url,
        method="POST",
        payload_template={"event_id": "{{request_id}}", "stage": "{{stage}}"},
        headers={},
        profile=profile,
        requests_per_stage=2,
        concurrency=4,
        timeout=2,
        stress_steps=3,
        duration_seconds=1,
        max_error_rate=0,
        max_throttle_rate=0,
        max_p95_ms=1000,
        min_requests_per_second=0.1,
        confirm_test_tenant=True,
    )

    assert [phase["name"] for phase in result["phases"]] == expected_names
    assert [phase["concurrency"] for phase in result["phases"]] == expected_concurrency
    assert result["requested_requests"] == len(expected_names) * 2
    assert len(received) == len(expected_names) * 2
    assert result["passed"] is True


def test_soak_profile_runs_repeated_batches_for_the_requested_duration(endpoint_server):
    endpoint_url, received = endpoint_server
    result = run_endpoint_load_test.run_load_profile(
        endpoint_url=endpoint_url,
        method="POST",
        payload_template={"event_id": "{{request_id}}"},
        headers={},
        profile="soak",
        requests_per_stage=2,
        concurrency=2,
        timeout=2,
        stress_steps=4,
        duration_seconds=0.05,
        max_error_rate=None,
        max_throttle_rate=None,
        max_p95_ms=None,
        min_requests_per_second=None,
        confirm_test_tenant=True,
    )

    assert result["elapsed_seconds"] >= 0.05
    assert result["requested_duration_seconds"] == 0.05
    assert result["completed_requests"] == len(received)
    assert len(received) >= 2
    assert result["acceptance_ready"] is False
    assert result["passed"] is None
    assert all(phase["name"].startswith("soak-") for phase in result["phases"])


@pytest.mark.parametrize(
    ("response_status", "expected_server_error_rate", "expected_throttle_rate"),
    [(500, 1.0, 0.0), (429, 0.0, 1.0)],
)
def test_load_profile_fails_when_server_error_or_throttle_slo_is_breached(
    endpoint_server,
    response_status,
    expected_server_error_rate,
    expected_throttle_rate,
):
    endpoint_url, _ = endpoint_server
    result = run_endpoint_load_test.run_load_profile(
        endpoint_url=endpoint_url,
        method="POST",
        payload_template={"response_status": response_status},
        headers={},
        profile="load",
        requests_per_stage=2,
        concurrency=2,
        timeout=2,
        stress_steps=2,
        duration_seconds=1,
        max_error_rate=0,
        max_throttle_rate=0,
        max_p95_ms=1000,
        min_requests_per_second=0.1,
        confirm_test_tenant=True,
    )

    phase = result["phases"][0]
    assert phase["server_error_rate"] == expected_server_error_rate
    assert phase["throttle_rate"] == expected_throttle_rate
    assert result["passed"] is False


def test_nonlocal_endpoint_requires_explicit_https_opt_in():
    with pytest.raises(ValueError, match="HTTPS"):
        run_endpoint_load_test.validate_target("http://api.example.test/v1/events", False)
    with pytest.raises(ValueError, match="explicit"):
        run_endpoint_load_test.validate_target("https://api.example.test/v1/events", False)

    assert run_endpoint_load_test.validate_target(
        "https://api.example.test/v1/events", True
    ) == "https://api.example.test/v1/events"


def test_load_runner_requires_test_tenant_confirmation_before_sending():
    with pytest.raises(ValueError, match="confirm-test-tenant"):
        run_endpoint_load_test.run_load_profile(
            endpoint_url="https://api.example.test/v1/events",
            method="POST",
            payload_template={},
            headers={},
            profile="load",
            requests_per_stage=1,
            concurrency=1,
            timeout=1,
            stress_steps=1,
            duration_seconds=1,
            max_error_rate=None,
            max_throttle_rate=None,
            max_p95_ms=None,
            min_requests_per_second=None,
            confirm_test_tenant=False,
        )


def test_load_template_rejects_unknown_placeholders_before_sending():
    with pytest.raises(ValueError, match="unsupported"):
        run_endpoint_load_test.run_load_profile(
            endpoint_url="http://127.0.0.1:5000/webhook",
            method="POST",
            payload_template={"id": "{{unknown}}"},
            headers={},
            profile="load",
            requests_per_stage=1,
            concurrency=1,
            timeout=1,
            stress_steps=1,
            duration_seconds=1,
            max_error_rate=None,
            max_throttle_rate=None,
            max_p95_ms=None,
            min_requests_per_second=None,
            confirm_test_tenant=True,
        )


@pytest.mark.parametrize(
    ("overrides", "error_message"),
    [
        ({"endpoint_url": "http://api.example.test/v1/events"}, "HTTPS"),
        ({"endpoint_url": "https://api.example.test/v1/events?token=secret"}, "query"),
        ({"endpoint_url": "https://api.example.test:invalid/v1/events"}, "URL"),
        ({"method": "TRACE"}, "method must"),
        ({"timeout": 301}, "timeout"),
        ({"duration_seconds": 86_401}, "duration"),
        ({"max_error_rate": 1.1}, "max-error-rate"),
        ({"max_p95_ms": 0}, "max-p95-ms"),
        ({"headers": {"Host": "example.test"}}, "controlled"),
        ({"hmac_secret": ""}, "HMAC signing"),
        ({"signature_encoding": "md5"}, "signature encoding"),
        ({"signature_header": "Bad\nHeader", "hmac_secret": "test-secret"}, "line breaks"),
        ({"headers": {"x-mpesa-signature": "provided"}, "hmac_secret": "test-secret"}, "signature header"),
        ({"profile": "unexpected"}, "profile must"),
        ({"requests_per_stage": 1_000_001}, "requests per stage"),
        ({"concurrency": 1_001}, "concurrency"),
        ({"stress_steps": 21}, "stress steps"),
    ],
)
def test_load_runner_rejects_unsafe_or_out_of_bounds_configuration(
    overrides,
    error_message,
):
    options = {
        "endpoint_url": "http://127.0.0.1:5000/events",
        "method": "POST",
        "payload_template": {},
        "headers": {},
        "profile": "load",
        "requests_per_stage": 1,
        "concurrency": 1,
        "timeout": 1,
        "stress_steps": 1,
        "duration_seconds": 1,
        "max_error_rate": None,
        "max_throttle_rate": None,
        "max_p95_ms": None,
        "min_requests_per_second": None,
        "confirm_test_tenant": True,
    }
    options.update(overrides)

    with pytest.raises(ValueError, match=error_message):
        run_endpoint_load_test.run_load_profile(**options)


def test_cli_writes_an_accepted_local_run_report(endpoint_server, tmp_path, monkeypatch, capsys):
    endpoint_url, received = endpoint_server
    payload_file = tmp_path / "payload.json"
    payload_file.write_text(
        json.dumps({"event_id": "{{request_id}}", "sequence": "{{sequence}}"}),
        encoding="utf-8",
    )
    report_file = tmp_path / "report.json"
    monkeypatch.setenv(
        "PESAGUARD_LOAD_TEST_HEADERS_JSON",
        json.dumps({"X-Load-Secret": "environment-only-secret"}),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_endpoint_load_test",
            "--target-url",
            endpoint_url,
            "--payload-template",
            str(payload_file),
            "--requests-per-stage",
            "2",
            "--concurrency",
            "2",
            "--max-error-rate",
            "0",
            "--max-throttle-rate",
            "0",
            "--max-p95-ms",
            "1000",
            "--min-requests-per-second",
            "0.1",
            "--confirm-test-tenant",
            "--json-path",
            str(report_file),
        ],
    )

    run_endpoint_load_test.main()

    report = json.loads(report_file.read_text(encoding="utf-8"))
    assert report["passed"] is True
    assert report["completed_requests"] == 2
    assert len(received) == 2
    assert all(secret == "environment-only-secret" for _, secret in received)
    assert "environment-only-secret" not in capsys.readouterr().out


def test_cli_rejects_unconfirmed_or_missing_hmac_secret_without_traffic(
    endpoint_server,
    monkeypatch,
):
    endpoint_url, received = endpoint_server
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_endpoint_load_test", "--target-url", endpoint_url],
    )
    with pytest.raises(SystemExit, match="confirm-test-tenant"):
        run_endpoint_load_test.main()

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_endpoint_load_test",
            "--target-url",
            endpoint_url,
            "--hmac-secret-env",
            "PESAGUARD_UNSET_LOAD_SIGNING_SECRET",
            "--confirm-test-tenant",
        ],
    )
    with pytest.raises(SystemExit, match="must be set and non-empty"):
        run_endpoint_load_test.main()
    assert received == []


@pytest.mark.parametrize(
    ("signature_header", "signature_encoding"),
    [
        ("X-MPESA-SIGNATURE", "hex"),
        ("X-DARAJA-SIGNATURE", "base64"),
    ],
)
def test_daraja_signature_is_computed_for_each_rendered_request(
    endpoint_server,
    signature_header,
    signature_encoding,
):
    endpoint_url, received = endpoint_server
    result = run_endpoint_load_test.run_load_profile(
        endpoint_url=endpoint_url,
        method="POST",
        payload_template={"event_id": "{{request_id}}"},
        headers={},
        profile="load",
        requests_per_stage=3,
        concurrency=2,
        timeout=2,
        stress_steps=2,
        duration_seconds=1,
        max_error_rate=0,
        max_throttle_rate=0,
        max_p95_ms=1000,
        min_requests_per_second=0.1,
        confirm_test_tenant=True,
        hmac_secret=TEST_SIGNING_SECRET,
        signature_header=signature_header,
        signature_encoding=signature_encoding,
    )

    assert result["passed"] is True
    assert result["phases"][0]["status_codes"] == {"201": 3}
    assert len({body["event_id"] for body, _ in received}) == 3
    assert TEST_SIGNING_SECRET not in json.dumps(result)
