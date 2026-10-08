"""Centralized Sentry and observability bootstrap for PesaGuard.

This module keeps integration optional, privacy-safe, and development-friendly.
It is intentionally lightweight so that Flask routes and background workers can
share a single Sentry initialization contract without making observability a
critical processing dependency.
"""

from __future__ import annotations

import importlib
import logging
import os
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

logger = logging.getLogger("pesaguard.observability")

_otel_tracer = None
_otel_initialized = False
_otel_instrumented = False
_otel_exporter_attached = False


def _try_import_first(*module_names: str) -> Any:
    """Import the first available module from the provided candidates."""
    for module_name in module_names:
        try:
            return importlib.import_module(module_name)
        except ImportError:
            continue
    return None


def init_opentelemetry(app: Any = None, engine: Any = None) -> bool:
    """Initialize OTLP tracing with per-integration defensive imports.

    This is an optional, defensive bootstrap. When the OpenTelemetry SDK is
    unavailable the process continues to use the lightweight generated span
    and W3C traceparent fallback implemented in this module. OTel is therefore
    compatible but not required.
    """
    global _otel_tracer, _otel_initialized, _otel_instrumented, _otel_exporter_attached
    if _otel_initialized:
        return _otel_tracer is not None
    _otel_initialized = True
    trace_api = _try_import_first("opentelemetry.trace")
    sdk_trace = _try_import_first("opentelemetry.sdk.trace")
    sdk_resources = _try_import_first("opentelemetry.sdk.resources")
    sdk_export = _try_import_first("opentelemetry.sdk.trace.export")
    propagator_api = _try_import_first("opentelemetry.propagators")
    if trace_api is None or sdk_trace is None:
        logger.info("OTel unavailable; using structured trace fallback.")
        return False
    try:
        resource = None
        if sdk_resources is not None:
            try:
                resource = sdk_resources.Resource.create({"service.name": os.getenv("OTEL_SERVICE_NAME", "pesaguard")})
            except Exception:
                resource = None
        try:
            provider = sdk_trace.TracerProvider(resource=resource) if resource is not None else sdk_trace.TracerProvider()
        except TypeError:
            provider = sdk_trace.TracerProvider()
        if sdk_export is not None:
            exp_mod = _try_import_first("opentelemetry.exporter.otlp.proto.grpc.trace_exporter", "opentelemetry.exporter.otlp.proto.http.trace_exporter")
            exp_cls = getattr(exp_mod, "OTLPSpanExporter", None) if exp_mod else None
            batch_cls = getattr(sdk_export, "BatchSpanProcessor", None)
            if exp_cls is not None and batch_cls is not None:
                try:
                    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel_collector:4317")
                    try:
                        exporter = exp_cls(endpoint=endpoint, insecure=True)
                    except TypeError:
                        exporter = exp_cls(endpoint=endpoint)
                    provider.add_span_processor(batch_cls(exporter))
                    _otel_exporter_attached = True
                except Exception:
                    logger.debug("OTLP exporter skipped", exc_info=True)
        try:
            trace_api.set_tracer_provider(provider)
        except Exception:
            try:
                provider = trace_api.get_tracer_provider()
            except Exception:
                pass
        _otel_tracer = trace_api.get_tracer("pesaguard")
        done = False
        if app is not None:
            fm = _try_import_first("opentelemetry.instrumentation.flask")
            fc = getattr(fm, "FlaskInstrumentor", None) if fm else None
            if fc is not None:
                try:
                    fc().instrument_app(app); done = True
                except Exception:
                    logger.debug("Flask OTel skipped", exc_info=True)
        sm = _try_import_first("opentelemetry.instrumentation.sqlalchemy")
        sc = getattr(sm, "SQLAlchemyInstrumentor", None) if sm else None
        if sc is not None:
            try:
                inst = sc()
                inst.instrument(engine=engine) if engine is not None else inst.instrument()
                done = True
            except Exception:
                logger.debug("SA OTel skipped", exc_info=True)
        rm = _try_import_first("opentelemetry.instrumentation.redis")
        rc = getattr(rm, "RedisInstrumentor", None) if rm else None
        if rc is not None:
            try:
                rc().instrument(); done = True
            except Exception:
                logger.debug("Redis OTel skipped", exc_info=True)
        km = _try_import_first("opentelemetry.instrumentation.kafka", "opentelemetry.instrumentation.kafka_python")
        kc = getattr(km, "KafkaInstrumentor", None) if km else None
        if kc is not None:
            try:
                kc().instrument(); done = True
            except Exception:
                logger.debug("Kafka OTel skipped", exc_info=True)
        qm = _try_import_first("opentelemetry.instrumentation.rq", "opentelemetry_instrumentation_rq")
        qc = (getattr(qm, "RqInstrumentor", None) or getattr(qm, "RQInstrumentor", None)) if qm else None
        if qc is not None:
            try:
                qc().instrument(); done = True
            except Exception:
                logger.debug("RQ OTel skipped", exc_info=True)
        _otel_instrumented = bool(done)
        return True
    except Exception:
        logger.exception("OTel init failed; using fallback.")
        return _otel_tracer is not None



def instrument_sqlalchemy_engine(engine: Any) -> bool:
    """Instrument an engine created after OpenTelemetry bootstrap."""
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        SQLAlchemyInstrumentor().instrument(engine=engine)
        return True
    except ImportError:
        return False
    except Exception:
        logger.debug("SQLAlchemy OpenTelemetry instrumentation skipped", exc_info=True)
        return False


def new_trace_id() -> str:
    return secrets.token_hex(16)


def new_span_id() -> str:
    return secrets.token_hex(8)


def build_traceparent(trace_id: str, span_id: str, sampled: bool = True) -> str:
    """Build a W3C `traceparent` header from a 32-hex trace id and 16-hex span id."""
    flags = "01" if sampled else "00"
    return f"00-{trace_id}-{span_id}-{flags}"


def parse_traceparent(header: str) -> Optional[Dict[str, str]]:
    """Parse a W3C `traceparent` header without requiring the OpenTelemetry SDK."""
    if not header:
        return None
    parts = header.strip().split("-")
    if len(parts) != 4:
        return None
    version, trace_id, span_id, flags = parts
    if version != "00":
        return None
    if len(trace_id) != 32 or len(span_id) != 16:
        return None
    if not all(c in "0123456789abcdef" for c in trace_id):
        return None
    if not all(c in "0123456789abcdef" for c in span_id):
        return None
    if len(flags) != 2 or not all(c in "0123456789abcdef" for c in flags):
        return None
    return {
        "version": version,
        "trace_id": trace_id,
        "span_id": span_id,
        "flags": flags,
        "sampled": flags in {"01", "03"},
    }


def inject_trace_context(carrier: Dict[str, str]) -> Dict[str, str]:
    """Inject the active W3C trace context, with a valid fallback when OTel is off.

    When the OpenTelemetry SDK is available this function delegates to the SDK
    propagator. When that path is unavailable or does not populate a traceparent,
    the function falls back to building a valid W3C header from the current
    request context so callers can always rely on traceparent being present.
    """
    if _otel_tracer is not None:
        try:
            from opentelemetry.propagate import inject

            inject(carrier)
            if carrier.get("traceparent"):
                return carrier
            logger.debug(
                "OpenTelemetry trace injection did not populate traceparent; using fallback.",
                exc_info=True,
            )
        except Exception:
            logger.debug(
                "OpenTelemetry trace injection failed; falling back to header build.",
                exc_info=True,
            )
    from logging_utils import get_observability_context

    context = get_observability_context()
    trace_id = context.get("trace_id") or new_trace_id()
    span_id = context.get("span_id") or new_span_id()
    carrier["traceparent"] = build_traceparent(trace_id, span_id)
    return carrier


def extract_trace_context(carrier: Dict[str, str]) -> Optional[Dict[str, str]]:
    """Extract W3C trace context from a carrier (headers/fields).

    Works without the OpenTelemetry SDK installed; when the SDK and a W3C
    propagator are available, the parsed context matches the SDK contract.
    """
    lower_carrier = {str(key).lower(): value for key, value in (carrier or {}).items()}
    traceparent = lower_carrier.get("traceparent")
    if not traceparent:
        return None
    return parse_traceparent(traceparent)


def get_current_trace_context() -> Dict[str, str]:
    """Return the active W3C trace context identifiers for the current execution context."""
    from logging_utils import get_observability_context
    context = get_observability_context()
    trace_id = context.get("trace_id") or new_trace_id()
    span_id = context.get("span_id") or new_span_id()
    traceparent = context.get("traceparent") or build_traceparent(trace_id, span_id)
    return {"trace_id": trace_id, "span_id": span_id, "traceparent": traceparent}


def otel_context_propagation_available() -> bool:
    """True when the OpenTelemetry context propagation API is available.

    Even when this is False, ``inject_trace_context`` and ``extract_trace_context``
    continue to work through the module's W3C traceparent fallback.
    """
    return _try_import_first("opentelemetry.propagate") is not None


def otel_exporter_reachable() -> bool:
    """Return whether an OTLP span exporter was attached during bootstrap.

    This does not probe network reachability. A return value of False means the
    bootstrap did not attach an exporter or the exporter constructor failed.
    """
    return _otel_exporter_attached


@contextmanager
def trace_span(name: str, **fields: Any):
    """Create an OpenTelemetry-compatible trace span with W3C context propagation.

    When the OpenTelemetry SDK is available the span is exported to the configured
    OTLP collector. The optional ``traceparent`` keyword resumes a parent trace from
    an incoming W3C header (e.g. a Kafka message header or HTTP request header) and
    creates a child span so a single trace crosses process boundaries.
    """
    from logging_utils import bind_observability_context, get_observability_context

    context = get_observability_context()
    traceparent = fields.pop("traceparent", None) or context.get("traceparent")
    if not traceparent and context.get("trace_id"):
        # HTTP handlers bind a valid incoming X-Trace-ID directly into the
        # lightweight context. Preserve that trace when a nested span is opened.
        current_trace_id = str(context["trace_id"])
        if len(current_trace_id) == 32 and all(char in "0123456789abcdef" for char in current_trace_id):
            traceparent = build_traceparent(current_trace_id, context.get("span_id") or new_span_id())
    if _otel_tracer is not None:
        parent_context = None
        if traceparent:
            try:
                propagators = _try_import_first(
                    "opentelemetry.propagate", "opentelemetry.trace.propagation"
                )
                extract_fn = getattr(propagators, "extract", None) if propagators else None
                if extract_fn is not None:
                    parent_context = extract_fn({"traceparent": traceparent})
            except Exception:
                logger.debug("Could not extract incoming W3C trace context %s", traceparent, exc_info=True)
        with _otel_tracer.start_as_current_span(name, context=parent_context) as span:
            for key, value in fields.items():
                try:
                    span.set_attribute(key, str(value))
                except Exception:
                    continue
            span_context = span.get_span_context()
            trace_id = f"{span_context.trace_id:032x}"
            span_id = f"{span_context.span_id:016x}"
            bind_observability_context(
                trace_id=trace_id,
                span_id=span_id,
                **({"traceparent": build_traceparent(trace_id, span_id)} if traceparent is not None else {}),
            )
            started = time.perf_counter()
            logger.info(
                "trace_span_started",
                extra={"span_name": name, "span_id": span_id, "trace_id": trace_id, **fields},
            )
            try:
                yield trace_id
            except Exception as exc:
                duration_ms = (time.perf_counter() - started) * 1000
                span.record_exception(exc)
                from opentelemetry.trace import Status, StatusCode
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                logger.exception(
                    "trace_span_failed",
                    extra={
                        "span_name": name,
                        "span_id": span_id,
                        "trace_id": trace_id,
                        "duration_ms": duration_ms,
                        "error_type": type(exc).__name__,
                    },
                )
                raise
            else:
                logger.info(
                    "trace_span_finished",
                    extra={
                        "span_name": name,
                        "span_id": span_id,
                        "trace_id": trace_id,
                        "duration_ms": (time.perf_counter() - started) * 1000,
                    },
                )
        return
    parsed = parse_traceparent(traceparent) if traceparent else None
    trace_id = (parsed or {}).get("trace_id") or context.get("trace_id") or new_trace_id()
    span_id = new_span_id()
    bind_observability_context(
        trace_id=trace_id,
        span_id=span_id,
        **({"traceparent": build_traceparent(trace_id, span_id)} if traceparent is not None else {}),
    )
    started = time.perf_counter()
    logger.info("trace_span_started", extra={"span_name": name, "span_id": span_id, "trace_id": trace_id, **fields})
    try:
        yield trace_id
    except Exception as exc:
        logger.exception(
            "trace_span_failed",
            extra={
                "span_name": name,
                "span_id": span_id,
                "trace_id": trace_id,
                "duration_ms": (time.perf_counter() - started) * 1000,
                "error_type": type(exc).__name__,
            },
        )
        raise
    else:
        logger.info(
            "trace_span_finished",
            extra={
                "span_name": name,
                "span_id": span_id,
                "trace_id": trace_id,
                "duration_ms": (time.perf_counter() - started) * 1000,
            },
        )
def _load_dotenv_file(env_path: str | os.PathLike[str] | None = None) -> None:
    """Compatibility wrapper for the shared backend environment loader."""
    from environment import load_backend_env

    load_backend_env(env_path)


_load_dotenv_file()

try:
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration
    from sentry_sdk.integrations.logging import LoggingIntegration
except ImportError:  # pragma: no cover - dependency optional in local dev
    sentry_sdk = None
    FlaskIntegration = None
    LoggingIntegration = None


_ENVIRONMENT_LOOKUP = {
    "development": "development",
    "dev": "development",
    "staging": "staging",
    "stage": "staging",
    "production": "production",
    "prod": "production",
}


def _normalized_environment() -> str:
    """Return a safe environment label supported by Sentry and project operations."""
    raw = (
        os.getenv("SENTRY_ENVIRONMENT")
        or os.getenv("FLASK_ENV")
        or os.getenv("PESAGUARD_ENV")
        or "development"
    ).lower()
    return _ENVIRONMENT_LOOKUP.get(raw, "development")


def _release_name() -> str:
    """Prefer a CI release or git SHA; otherwise return project-local development label."""
    return os.getenv("SENTRY_RELEASE") or os.getenv("GIT_SHA") or "pesaguard@local"


def _sample_rate(name: str, default: str) -> float:
    """Parse a float preference safely and clamp it to the [0, 1] range."""
    raw = os.getenv(name, default)
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = float(default)
    return max(0.0, min(1.0, value))


def init_sentry(service: str = "webhook", provider: str = "mpesa") -> bool:
    """Initialize Sentry as an optional, privacy-safe dependency.

    Returns True when Sentry is configured and initialized successfully,
    False when no SENTRY_DSN is supplied or the runtime dependency is absent.
    """
    dsn = os.getenv("SENTRY_DSN")
    if not dsn or not sentry_sdk or not FlaskIntegration or not LoggingIntegration:
        logger.info("Sentry initialization skipped because SENTRY_DSN is not configured or sentry-sdk is unavailable.")
        return False

    try:
        sentry_sdk.init(
            dsn=dsn,
            environment=_normalized_environment(),
            release=_release_name(),
            integrations=[
                FlaskIntegration(),
                LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
            ],
            traces_sample_rate=_sample_rate("SENTRY_TRACES_SAMPLE_RATE", "0.1"),
            profiles_sample_rate=_sample_rate("SENTRY_PROFILES_SAMPLE_RATE", "0.0"),
            send_default_pii=False,
        )
        sentry_sdk.set_tag("service", service)
        sentry_sdk.set_tag("provider", provider)
        sentry_sdk.set_tag("environment", _normalized_environment())
        sentry_sdk.set_tag("component", "backend")
        logger.info("Sentry initialized for PesaGuard with environment=%s service=%s provider=%s", _normalized_environment(), service, provider)
        return True
    except Exception as exc:
        logger.warning("Sentry initialization failed gracefully: %s", exc)
        return False


def add_sentry_context(operation: str, **context: Any) -> None:
    """Attach safe, non-PII transaction or workflow context to the current Sentry scope."""
    if sentry_sdk is None:
        return
    try:
        tag_key = "operation"
        sentry_sdk.set_tag(tag_key, operation)
        if context:
            safe_context = {
                key: value for key, value in context.items()
                if isinstance(value, (str, int, float, bool, type(None)))
            }
            sentry_sdk.set_context("pesaguard_context", safe_context)
    except Exception:
        logger.debug("Sentry context enrichment skipped safely.", exc_info=True)


def capture_exception(exc: Exception, *, operation: str = "unhandled", extra: Optional[Dict[str, Any]] = None) -> None:
    """Capture a Python exception without exposing financial or secret payloads."""
    if sentry_sdk is None:
        return
    try:
        sentry_sdk.set_tag("operation", operation)
        if extra:
            sentry_sdk.set_context("pesaguard_safe_context", {k: str(v) for k, v in extra.items()})
        sentry_sdk.capture_exception(exc)
    except Exception:
        logger.debug("Sentry exception capture skipped safely.", exc_info=True)


def capture_message(message: str, *, level: str = "info", **tags: Any) -> None:
    """Capture a structured message with only non-sensitive tags."""
    if sentry_sdk is None:
        return
    try:
        for key, value in tags.items():
            if isinstance(key, str) and isinstance(value, str):
                sentry_sdk.set_tag(key, value)
        sentry_sdk.capture_message(message, level=level)
    except Exception:
        logger.debug("Sentry message capture skipped safely.", exc_info=True)
