"""OpenTelemetry compatible tracing with W3C trace context propagation.

This module is a compatibility façade over the canonical tracing
implementation in :mod:`observability`. It exists so older import sites can
keep ``from otel_tracing import ...`` while every service shares one tracer,
one TracerProvider, and one set of native OpenTelemetry instrumentors
(Flask, SQLAlchemy, Redis, Kafka, RQ).
"""

from __future__ import annotations

from observability import (  # noqa: F401
    build_traceparent,
    extract_trace_context,
    get_current_trace_context,
    init_opentelemetry,
    inject_trace_context,
    instrument_sqlalchemy_engine,
    new_span_id,
    new_trace_id,
    otel_status,
    parse_traceparent,
    trace_span,
)

__all__ = [
    "build_traceparent",
    "extract_trace_context",
    "get_current_trace_context",
    "init_opentelemetry",
    "inject_trace_context",
    "instrument_sqlalchemy_engine",
    "new_span_id",
    "new_trace_id",
    "otel_status",
    "parse_traceparent",
    "trace_span",
]