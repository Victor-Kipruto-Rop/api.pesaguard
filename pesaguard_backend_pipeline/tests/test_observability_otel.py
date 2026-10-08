"""OpenTelemetry compatibility and W3C context propagation tests.

These tests verify that PesaGuard's observability layer is OTel-compatible
(optional SDK bootstrap, integration hooks, OTLP exporter reachability probe)
while still providing a correct W3C traceparent fallback when the SDK is absent.
"""

from __future__ import annotations

import pytest
from types import SimpleNamespace

import observability


def test_w3c_traceparent_round_trip():
    trace_id = "1234567890abcdef1234567890abcdef"
    span_id = "abcdef1234567890"
    header = observability.build_traceparent(trace_id, span_id, sampled=True)
    parsed = observability.parse_traceparent(header)
    assert parsed is not None
    assert parsed["trace_id"] == trace_id
    assert parsed["span_id"] == span_id
    assert parsed["sampled"] is True


def test_w3c_traceparent_rejects_malformed_headers():
    assert observability.parse_traceparent("") is None
    assert observability.parse_traceparent("00-123") is None
    assert observability.parse_traceparent("01-1234567890abcdef1234567890abcdef-abcdef1234567890-01") is None
    assert observability.parse_traceparent("00-1234567890abcdef1234567890abcdef-abcdef1234567890-FF") is None


def test_inject_and_extract_are_consistent_without_sdk():
    carrier: dict[str, str] = {}
    observability.inject_trace_context(carrier)
    assert "traceparent" in carrier
    parsed = observability.extract_trace_context(carrier)
    assert parsed is not None
    assert "trace_id" in parsed
    assert "span_id" in parsed


def test_extract_preserves_otel_sdk_contract_when_available():
    carrier = {"traceparent": observability.build_traceparent("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", sampled=False)}
    parsed = observability.extract_trace_context(carrier)
    assert parsed is not None
    assert parsed["sampled"] is False


def test_otel_context_propagation_available_is_stable():
    result = observability.otel_context_propagation_available()
    assert isinstance(result, bool)


def test_otel_exporter_reachable_is_stable_before_and_after_init():
    before = observability.otel_exporter_reachable()
    assert isinstance(before, bool)
    observability.init_opentelemetry()
    after = observability.otel_exporter_reachable()
    assert isinstance(after, bool)


def test_flask_instrumentation_without_exporter_does_not_report_exporter_attached(monkeypatch):
    class FakeTracerProvider:
        def __init__(self, **_kwargs):
            pass

    class FakeFlaskInstrumentor:
        def instrument_app(self, _app):
            pass

    modules = {
        "opentelemetry.trace": SimpleNamespace(
            set_tracer_provider=lambda _provider: None,
            get_tracer=lambda _name: object(),
        ),
        "opentelemetry.sdk.trace": SimpleNamespace(TracerProvider=FakeTracerProvider),
        "opentelemetry.instrumentation.flask": SimpleNamespace(
            FlaskInstrumentor=FakeFlaskInstrumentor
        ),
    }
    monkeypatch.setattr(observability, "_otel_tracer", None)
    monkeypatch.setattr(observability, "_otel_initialized", False)
    monkeypatch.setattr(observability, "_otel_instrumented", False)
    monkeypatch.setattr(observability, "_otel_exporter_attached", False)
    monkeypatch.setattr(
        observability,
        "_try_import_first",
        lambda *names: next((modules[name] for name in names if name in modules), None),
    )

    assert observability.init_opentelemetry(app=object()) is True

    assert observability.otel_exporter_reachable() is False
