"""
Prometheus telemetry exporter module for PesaGuard operational metrics.
Provides dynamic metric collection for reconciliation throughput, discrepancy counts,
and pipeline latencies, including multi-worker shared metrics, per-application SQLAlchemy
engine query timing, and scrape-window request/sec.
"""

from __future__ import annotations

from environment import required_env

import logging
import json
import os
import time
import threading
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("pesaguard.metrics")
_metrics_engine = None
_telemetry_lock = threading.Lock()
_last_scrape_at: Optional[float] = None
_last_scrape_requests = 0
_telemetry = {
    "started_at": time.monotonic(),
    "requests": 0,
    "errors": 0,
    "timeouts": 0,
    "request_latencies_ms": [],
    "db_queries": 0,
    "db_query_latencies_ms": [],
    "business": {},
    "event_retries": 0,
}
_runtime_business_counters = {}
_scrape_window_start: float = time.monotonic()
_scrape_window_requests: int = 0
# Per-application SQLAlchemy engine query timing so the metrics export is not limited to a
# single shared metrics engine. Every engine that calls `instrument_engine_query_timing`
# contributes its query counts and latencies independently, and `telemetry_snapshot()` merges
# them into one aggregate view.
_application_engine_query_counts: Dict[int, int] = {}
_application_engine_query_latencies: Dict[int, list[float]] = {}
_application_engine_attachers: Dict[int, Any] = {}

# Shared multi-worker metric store -------------------------------------------------
# When PESAGUARD_SHARED_METRICS=1 the record functions write counters into Redis so
# every gunicorn/RQ worker contributes to one aggregate telemetry surface. The
# conventional in-memory dictionaries remain as a process-local fallback and are
# still used when Redis is unavailable.
_SHARED_METRICS_FLAG = "PESAGUARD_SHARED_METRICS"
_SHARED_METRICS_PREFIX = "pesaguard:metrics"
_shared_redis_client = None
_shared_redis_degraded = False
# -----------------------------------------------------------------------------
# Runtime telemetry scope
#
# Counters such as requests, errors, timeouts, db_queries, event_retries, and
# business metrics are *process-local* by default. When multiple gunicorn/RQ
# workers run, each worker maintains its own in-memory telemetry unless
# PESAGUARD_SHARED_METRICS=1 and a reachable Redis backend is configured.
#
# Process-local counters reset on worker restart. Scrape-window request/sec and
# error rate are therefore measured from the last scrape to the current scrape,
# not as a lifetime average. When the shared backend is available, the scrape
# window is computed from cluster-wide totals so any worker serving /metrics can
# report an aggregate window rather than one process's window.
# -----------------------------------------------------------------------------




def _get_shared_redis():
    """Lazily connect to the shared Redis metrics backend, degrading gracefully."""
    global _shared_redis_client, _shared_redis_degraded
    if os.getenv(_SHARED_METRICS_FLAG, "0") != "1" or _shared_redis_degraded:
        return None
    if _shared_redis_client is None:
        try:
            import redis as redis_lib
            _shared_redis_client = redis_lib.from_url(
                os.getenv("REDIS_URL", "redis://localhost:6379/0"),
                socket_connect_timeout=1,
                socket_timeout=3,
                decode_responses=True,
            )
            _shared_redis_client.ping()
            logger.info("Shared multi-worker metrics backend enabled via Redis.")
        except Exception:
            _shared_redis_client = None
            _shared_redis_degraded = True
            logger.warning("Shared metrics Redis backend unavailable; using process-local telemetry.", exc_info=True)
    return _shared_redis_client


def shared_metrics_enabled() -> bool:
    """True when the shared metrics backend is active and connected."""
    return _get_shared_redis() is not None


def _shared_totals() -> Dict[str, Any]:
    """Read aggregate counters and latency lists from the shared Redis store."""
    client = _get_shared_redis()
    if client is None:
        return {}
    try:
        values = client.mget(
            f"{_SHARED_METRICS_PREFIX}:requests",
            f"{_SHARED_METRICS_PREFIX}:errors",
            f"{_SHARED_METRICS_PREFIX}:timeouts",
            f"{_SHARED_METRICS_PREFIX}:event_retries",
            f"{_SHARED_METRICS_PREFIX}:db_queries",
        ) or [None] * 5
        request_latencies = client.lrange(f"{_SHARED_METRICS_PREFIX}:latencies:requests", 0, -1)
        query_latencies = client.lrange(f"{_SHARED_METRICS_PREFIX}:latencies:db", 0, -1)
        business: Dict[str, int] = {}
        for key in client.keys(f"{_SHARED_METRICS_PREFIX}:business:*") or []:
            name = str(key).rsplit(":", 1)[-1]
            business[name] = int(client.get(key) or 0)
        alert_deliveries: Dict[str, int] = {}
        for key in client.keys(f"{_SHARED_METRICS_PREFIX}:alert_delivery:*") or []:
            token = str(key).rsplit(":", 2)
            if len(token) >= 3:
                channel, success_str = token[-2], token[-1]
                alert_deliveries[channel] = alert_deliveries.get(channel, 0) + int(client.get(key) or 0)
        return {
            "requests": int(values[0] or 0),
            "errors": int(values[1] or 0),
            "timeouts": int(values[2] or 0),
            "event_retries": int(values[3] or 0),
            "db_queries": int(values[4] or 0),
            "request_latencies_ms": [float(v) for v in request_latencies or []],
            "db_query_latencies_ms": [float(v) for v in query_latencies or []],
            "business": business,
            "alert_deliveries": alert_deliveries,
        }
    except Exception:
        logger.warning("Shared metrics read failed; using process-local telemetry.", exc_info=True)
        return {
            "requests": 0,
            "errors": 0,
            "timeouts": 0,
            "event_retries": 0,
            "db_queries": 0,
            "request_latencies_ms": [],
            "db_query_latencies_ms": [],
            "business": {},
            "alert_deliveries": {},
        }


def _shared_scrape_window() -> Optional[Dict[str, Any]]:
    """Compute scrape-window request rate and error rate from shared Redis marks.

    Returns None when the shared backend is unavailable. The marks are stored in
    Redis so successive scrapes are measured against the *cluster-wide* totals,
    not the per-process totals of the worker that happens to serve a scrape.
    """
    client = _get_shared_redis()
    if client is None:
        return None
    now = time.monotonic()
    mark_key = f"{_SHARED_METRICS_PREFIX}:scrape:mark"
    totals = _shared_totals()
    if not totals:
        return None
    try:
        previous = client.hgetall(mark_key) or {}
        last_at = float(previous.get("at", 0.0))
        last_requests = int(previous.get("requests", 0))
        last_errors = int(previous.get("errors", 0))
        rate = 0.0
        error_rate = totals["errors"] / totals["requests"] if totals["requests"] else 0.0
        if last_at and now > last_at:
            elapsed = max(now - last_at, 1e-6)
            window_requests = max(totals["requests"] - last_requests, 0)
            window_errors = max(totals["errors"] - last_errors, 0)
            rate = window_requests / elapsed
            error_rate = window_errors / max(window_requests, 1)
        client.hset(mark_key, mapping={"at": str(now), "requests": str(totals["requests"]), "errors": str(totals["errors"])})
        client.expire(mark_key, 3600)
        return {"request_rate_per_second": rate, "error_rate": error_rate}
    except Exception:
        logger.warning("Shared metrics scrape-window update failed.", exc_info=True)
        return None


def _shared_latency_push(latency_key: str, value: float, *, cap: int = 10_000) -> None:
    client = _get_shared_redis()
    if client is None:
        return
    try:
        client.lpush(latency_key, float(value))
        client.ltrim(latency_key, 0, cap - 1)
    except Exception:
        logger.warning("Shared metrics latency push failed.", exc_info=True)


def record_http_request(duration_ms: float, *, status_code: int, timeout: bool = False) -> None:
    global _scrape_window_requests
    with _telemetry_lock:
        _telemetry["requests"] += 1
        _telemetry["errors"] += int(status_code >= 500)
        _telemetry["timeouts"] += int(timeout)
        _telemetry["request_latencies_ms"].append(float(duration_ms))
        _telemetry["request_latencies_ms"] = _telemetry["request_latencies_ms"][-10_000:]
        _scrape_window_requests += 1
    if HAS_PROMETHEUS_CLIENT:
        _runtime_requests.labels(status_class=f"{status_code // 100}xx").inc()
        if status_code >= 500:
            _runtime_errors.inc()
        if timeout:
            _runtime_timeouts.inc()
    redis_client = _get_shared_redis()
    if redis_client is not None:
        redis_client.incr(f"{_SHARED_METRICS_PREFIX}:requests")
        if status_code >= 500:
            redis_client.incr(f"{_SHARED_METRICS_PREFIX}:errors")
        if timeout:
            redis_client.incr(f"{_SHARED_METRICS_PREFIX}:timeouts")
        try:
            redis_client.lpush(f"{_SHARED_METRICS_PREFIX}:latencies:requests", float(duration_ms))
            redis_client.ltrim(f"{_SHARED_METRICS_PREFIX}:latencies:requests", 0, 9999)
        except Exception:
            logger.debug("shared latency push for request failed", exc_info=True)

def record_db_query(duration_ms: float) -> None:
    with _telemetry_lock:
        _telemetry["db_queries"] += 1
        _telemetry["db_query_latencies_ms"].append(float(duration_ms))
        _telemetry["db_query_latencies_ms"] = _telemetry["db_query_latencies_ms"][-10_000:]
    if HAS_PROMETHEUS_CLIENT:
        _runtime_db_queries.inc()
    redis_client = _get_shared_redis()
    if redis_client is not None:
        try:
            redis_client.incr(f"{_SHARED_METRICS_PREFIX}:db_queries")
            redis_client.lpush(f"{_SHARED_METRICS_PREFIX}:latencies:db", float(duration_ms))
            redis_client.ltrim(f"{_SHARED_METRICS_PREFIX}:latencies:db", 0, 9999)
        except Exception:
            logger.debug("shared latency push for db query failed", exc_info=True)


def record_business_metric(name: str, amount: int = 1) -> None:
    with _telemetry_lock:
        _telemetry["business"][name] = _telemetry["business"].get(name, 0) + amount
    if HAS_PROMETHEUS_CLIENT:
        counter = _runtime_business_counters.get(name)
        if counter is None:
            counter = Counter(f"pesaguard_business_{name}", "Business operation count")
            _runtime_business_counters[name] = counter
        counter.inc(amount)
    redis_client = _get_shared_redis()
    if redis_client is not None:
        redis_client.incr(f"{_SHARED_METRICS_PREFIX}:business:{name}", amount)


def record_pipeline_event(outcome: str, *, tenant_id: str = "default", duration_ms: Optional[float] = None) -> None:
    """Record a bounded transaction-pipeline outcome with tenant context."""
    allowed_outcomes = {"entered", "succeeded", "duplicate", "failed", "retried", "dead_lettered"}
    if outcome not in allowed_outcomes:
        raise ValueError(f"unsupported pipeline outcome: {outcome}")
    tenant = str(tenant_id or "default")[:128]
    record_business_metric(f"pipeline_{outcome}")
    if HAS_PROMETHEUS_CLIENT:
        _pipeline_events.labels(outcome=outcome, tenant_id=tenant).inc()
        if duration_ms is not None:
            _pipeline_duration.labels(tenant_id=tenant).observe(float(duration_ms) / 1000)
    redis_client = _get_shared_redis()
    if redis_client is not None:
        redis_client.incr(f"{_SHARED_METRICS_PREFIX}:pipeline:{outcome}:{tenant}")


def record_data_quality(result: Any) -> None:
    """Export quality-check outcomes and dimension scores for one payload."""
    tenant = str(getattr(result, "tenant_id", "default") or "default")[:128]
    status = str(getattr(result, "status", "unknown"))
    scores = getattr(result, "dimension_scores", {})
    if not HAS_PROMETHEUS_CLIENT:
        return
    for dimension, score in scores.items():
        _dq_checks.labels(dimension=dimension, status=status, tenant_id=tenant).inc()
        _dq_scores.labels(dimension=dimension, tenant_id=tenant).set(float(score))


def record_security_event(amount: int = 1) -> None:
    """Record a security decision through the shared business counter."""
    record_business_metric("security_events", amount)


def record_auth_risk_decision(risk_level: str, action: str, signals: Dict[str, Any]) -> None:
    """Record risk outcomes with fixed-cardinality labels and signal names."""
    allowed_levels = {"low", "medium", "high", "unknown"}
    allowed_actions = {"allow", "require_mfa", "block", "review", "unknown"}
    allowed_signals = {
        "new_device",
        "new_location",
        "impossible_travel",
        "unusual_login_time",
        "multiple_failed_attempts",
        "credential_compromise",
        "suspicious_ip",
        "high_risk_session",
        "privileged_operation",
        "suspicious_user_agent",
        "link_local_ip",
        "invalid_ip",
        "revoked_device",
    }
    level = risk_level if risk_level in allowed_levels else "unknown"
    decision = action if action in allowed_actions else "unknown"
    record_business_metric(f"auth_risk_{level}_{decision}")
    if not HAS_PROMETHEUS_CLIENT:
        return
    try:
        _auth_risk_decisions.labels(risk_level=level, action=decision).inc()
        for signal in allowed_signals.intersection(key for key, value in signals.items() if value):
            _auth_risk_signals.labels(signal=signal).inc()
    except Exception:
        logger.debug("Authentication risk metric recording failed", exc_info=True)


def record_alert_delivery(channel: str, success: bool) -> None:
    """Record an outbound alert delivery attempt so delivery success and failure
    are visible through both in-memory telemetry and any shared multi-worker
    metrics backend.
    """
    try:
        with _telemetry_lock:
            alert_deliveries = _telemetry.get("alert_deliveries")
            if not isinstance(alert_deliveries, dict):
                alert_deliveries = {}
                _telemetry["alert_deliveries"] = alert_deliveries
            alert_deliveries[channel] = alert_deliveries.get(channel, 0) + 1
            if not success:
                _telemetry["alert_delivery_failures"] = _telemetry.get(
                    "alert_delivery_failures", 0
                ) + 1
        if HAS_PROMETHEUS_CLIENT:
            try:
                if success:
                    _alert_delivery_counter.labels(channel=channel).inc()
                else:
                    _alert_delivery_failures.inc()
            except Exception:
                logger.debug("Prometheus alert delivery metric recording failed", exc_info=True)
        redis_client = _get_shared_redis()
        if redis_client is not None:
            key_base = f"{_SHARED_METRICS_PREFIX}:alert_delivery:{channel}:{int(success)}"
            try:
                redis_client.incr(key_base)
            except Exception:
                logger.debug("shared alert delivery increment failed", exc_info=True)
    except Exception:
        logger.debug("alert_delivery metric recording failed", exc_info=True)


def record_event_retry() -> None:
    with _telemetry_lock:
        _telemetry["event_retries"] += 1
    if HAS_PROMETHEUS_CLIENT:
        _runtime_retries.inc()
    redis_client = _get_shared_redis()
    if redis_client is not None:
        redis_client.incr(f"{_SHARED_METRICS_PREFIX}:event_retries")


def telemetry_snapshot() -> Dict[str, Any]:
    """Return a combined process-local and shared multi-worker telemetry snapshot.

    When ``PESAGUARD_SHARED_METRICS=1`` and Redis is reachable, shared totals
    dominate the returned counters and the scrape-window rate is computed from
    cluster-wide marks. Otherwise the snapshot reflects the current process only.
    Process-local counters reset on process restart; this snapshot is designed
    for Prometheus scraping, not for long-lived incremental counters.

    Scrape-window request/sec and error rate are measured from the last snapshot
    invocation to the current one, so the same process never reports a stale
    lifetime average as if it were a current rate.
    """
    global _last_scrape_at, _last_scrape_requests
    shared = _shared_totals()
    shared_window = _shared_scrape_window()
    with _telemetry_lock:
        now = time.monotonic()
        previous_at = _last_scrape_at
        previous_requests = _last_scrape_requests
        elapsed = now - previous_at if previous_at is not None else 0.0
        request_delta = _telemetry["requests"] - previous_requests
        scrape_rate = request_delta / elapsed if elapsed > 0 else 0.0
        _last_scrape_at = now
        _last_scrape_requests = _telemetry["requests"]
        request_latencies = sorted(_telemetry["request_latencies_ms"])
        query_latencies = sorted(_telemetry["db_query_latencies_ms"])
        business_local = dict(_telemetry["business"])
        alert_local = dict(_telemetry.get("alert_deliveries", {}))
        alert_failures_local = int(_telemetry.get("alert_delivery_failures", 0))
        local = {
            "requests": _telemetry["requests"],
            "errors": _telemetry["errors"],
            "timeouts": _telemetry["timeouts"],
            "event_retries": _telemetry["event_retries"],
            "db_queries": _telemetry["db_queries"],
        }

        def percentile(values: list[float], ratio: float) -> float:
            return values[min(len(values) - 1, int(len(values) * ratio))] if values else 0.0

        # When a shared multi-worker backend is active, prefer the cluster-wide
        # totals so any worker serving /metrics reports the aggregate surface.
        # The merge is shared-first: when Redis is active the snapshot reflects
        # the shared counters and only keeps local values when shared is missing.
        if shared:
            if shared.get("requests"):
                local["requests"] = int(shared.get("requests") or 0)
                request_latencies = sorted(
                    [float(v) for v in shared.get("request_latencies_ms", []) or []] or request_latencies
                )
            if shared.get("errors"):
                local["errors"] = int(shared.get("errors") or 0)
            if shared.get("timeouts"):
                local["timeouts"] = int(shared.get("timeouts") or 0)
            if shared.get("event_retries"):
                local["event_retries"] = int(shared.get("event_retries") or 0)
            if shared.get("db_queries"):
                local["db_queries"] = int(shared.get("db_queries") or 0)
                query_latencies = sorted(
                    [float(v) for v in shared.get("db_query_latencies_ms", []) or []] or query_latencies
                )
            for name, value in (shared.get("business") or {}).items():
                business_local[name] = int(value or 0)
            for channel, value in (shared.get("alert_deliveries") or {}).items():
                alert_local[channel] = int(value or 0)

        if shared_window_summary := _shared_scrape_window_summary():
            scrape_rate = float(shared_window_summary.get("request_rate_per_second", scrape_rate))
            shared_error_rate = shared_window_summary.get("error_rate")
        else:
            shared_error_rate = None

        error_rate = (
            float(shared_error_rate)
            if shared_error_rate is not None
            else (local["errors"] / local["requests"] if local["requests"] else 0.0)
        )
        return {
            "requests": local["requests"],
            "errors": local["errors"],
            "timeouts": local["timeouts"],
            "request_rate_per_second": scrape_rate,
            "error_rate": error_rate,
            "request_p50_ms": percentile(request_latencies, 0.50),
            "request_p95_ms": percentile(request_latencies, 0.95),
            "request_p99_ms": percentile(request_latencies, 0.99),
            "db_connections": 0,
            "db_pool_usage": 0.0,
            "db_queries": local["db_queries"],
            "db_query_p95_ms": percentile(query_latencies, 0.95),
            "db_queries_per_application_engine": dict(_application_engine_query_counts),
            "db_locks": 0,
            "db_deadlocks": 0,
            "cpu_percent": 0.0,
            "ram_percent": 0.0,
            "iops": 0.0,
            "event_retries": local["event_retries"],
            "business": business_local,
            "alert_deliveries": alert_local,
            "alert_delivery_failures": alert_failures_local,
        }


def _shared_scrape_window_summary() -> Optional[Dict[str, Any]]:
    """Return the shared scrape-window rate summary without mutating the mark.

    telemetry_snapshot() uses this to read the cluster-wide scrape-window rate
    while preserving the authoritative mark update performed by
    _shared_scrape_window() during producer-side recording. When the shared
    backend is unavailable, this helper returns None so the local process-window
    rate is used.
    """
    client = _get_shared_redis()
    if client is None:
        return None
    mark_key = f"{_SHARED_METRICS_PREFIX}:scrape:mark"
    try:
        previous = client.hgetall(mark_key) or {}
        last_at = float(previous.get("at", 0.0))
        last_requests = int(previous.get("requests", 0))
        last_errors = int(previous.get("errors", 0))
        totals = _shared_totals()
        if not totals:
            return None
        now = time.monotonic()
        rate = 0.0
        error_rate = totals["errors"] / totals["requests"] if totals["requests"] else 0.0
        if last_at and now > last_at:
            elapsed = max(now - last_at, 1e-6)
            window_requests = max(totals["requests"] - last_requests, 0)
            window_errors = max(totals["errors"] - last_errors, 0)
            rate = window_requests / elapsed
            error_rate = window_errors / max(window_requests, 1)
        return {"request_rate_per_second": rate, "error_rate": error_rate}
    except Exception:
        logger.debug("Shared metrics scrape-window read failed.", exc_info=True)
        return None

# Attempt importing official prometheus_client library with fallback support
try:
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, REGISTRY, generate_latest
    HAS_PROMETHEUS_CLIENT = True
except ImportError:
    HAS_PROMETHEUS_CLIENT = False

if HAS_PROMETHEUS_CLIENT:
    def _counter(name: str, description: str, labels: list[str] | None = None):
        try:
            return Counter(name, description, labels or [])
        except ValueError:
            return REGISTRY._names_to_collectors[name]

    _runtime_requests = _counter("pesaguard_runtime_requests_total", "Application requests", ["status_class"])
    _runtime_errors = _counter("pesaguard_runtime_errors_total", "Application server errors")
    _runtime_timeouts = _counter("pesaguard_runtime_timeouts_total", "Application timeouts")
    _runtime_db_queries = _counter("pesaguard_runtime_db_queries_total", "Database queries")
    _runtime_retries = _counter("pesaguard_event_retries", "Event retries")
    _pipeline_events = _counter(
        "pesaguard_pipeline_events_total",
        "Transaction pipeline outcomes",
        ["outcome", "tenant_id"],
    )
    _pipeline_duration = Histogram(
        "pesaguard_pipeline_duration_seconds",
        "Transaction pipeline processing duration",
        ["tenant_id"],
    )
    _dq_checks = _counter(
        "pesaguard_data_quality_checks_total",
        "Data quality checks by dimension and outcome",
        ["dimension", "status", "tenant_id"],
    )
    _dq_scores = Gauge(
        "pesaguard_data_quality_score",
        "Latest data quality score by dimension",
        ["dimension", "tenant_id"],
    )

    def _alert_counter() -> Counter:
        return _counter(
            "pesaguard_alert_delivery_total",
            "Alert delivery attempts",
            ["channel"],
        )

    _alert_delivery_counter = _alert_counter()
    _alert_delivery_failures = _counter("pesaguard_alert_delivery_failures_total", "Alert delivery failures")
    _auth_risk_decisions = _counter(
        "pesaguard_auth_risk_decisions_total",
        "Authentication risk decisions by risk level and response action",
        ["risk_level", "action"],
    )
    _auth_risk_signals = _counter(
        "pesaguard_auth_risk_signals_total",
        "Authentication risk signals observed",
        ["signal"],
    )
else:
    _runtime_requests = _runtime_errors = _runtime_timeouts = _runtime_db_queries = _runtime_retries = None
    _pipeline_events = _pipeline_duration = None
    _dq_checks = _dq_scores = None
    _alert_delivery_counter = None
    _alert_delivery_failures = None
    _auth_risk_decisions = None
    _auth_risk_signals = None


try:
    from sqlalchemy import event as sqlalchemy_event
    from sqlalchemy.engine import Engine

    _instrumented_engines: set[Engine] = set()
    _application_engine_query_counts: Dict[int, int] = {}
    _application_engine_query_latencies: Dict[int, list[float]] = {}
    _engine_listeners_attached: bool = False

    def _ensure_engine_listeners() -> None:
        global _engine_listeners_attached

        if _engine_listeners_attached:
            return
        try:

            @sqlalchemy_event.listens_for(Engine, "before_cursor_execute", named=True)
            def _before_application_query(
                conn,
                cursor,
                statement,
                parameters,
                context,
                executemany,
                **kw,  # pragma: no cover - defensive against SQLAlchemy dispatch signature variation
            ) -> None:
                conn.info["pesaguard_query_started"] = time.perf_counter()

            @sqlalchemy_event.listens_for(Engine, "after_cursor_execute", named=True)
            def _after_application_query(
                conn,
                cursor,
                statement,
                parameters,
                context,
                executemany,
                **kw,  # pragma: no cover - defensive against SQLAlchemy dispatch signature variation
            ) -> None:
                started = conn.info.pop("pesaguard_query_started", None)
                if started is not None:
                    latency_ms = (time.perf_counter() - started) * 1000
                    record_db_query(latency_ms)
                    engine_id = id(getattr(conn, "engine", None)) or id(conn)
                    _application_engine_query_counts[engine_id] = (
                        _application_engine_query_counts.get(engine_id, 0) + 1
                    )
                    _application_engine_query_latencies.setdefault(engine_id, []).append(latency_ms)

            _engine_listeners_attached = True
        except Exception:
            _engine_listeners_attached = False
            logger.debug("Unable to attach application engine query listeners.", exc_info=True)

    _ensure_engine_listeners()
except ImportError:
    _instrumented_engines: set[Engine] = set()
    _application_engine_query_counts: Dict[int, int] = {}
    _application_engine_query_latencies: Dict[int, list[float]] = {}
    _engine_listeners_attached = False


def instrument_engine_query_timing(engine: Any) -> bool:
    """Attach before/after query hooks to an application SQLAlchemy engine and
    return True when the instrumentation succeeds.

    This helper is idempotent and safe to call multiple times per process. When
    the module-level query listeners are available it ensures they are attached to
    Engine once, then marks the supplied engine so subsequent telemetry snapshots
    can confirm that query timing is captured across every application pool rather
    than only the metrics-read engine.
    """
    if engine is None:
        return False
    if not isinstance(engine, Engine):
        return False
    try:
        _ensure_engine_listeners()
    except Exception:
        return False
    if not _engine_listeners_attached:
        return False
    engine_id = id(engine)
    _instrumented_engines.add(engine)
    _application_engine_query_counts.setdefault(engine_id, 0)
    _application_engine_query_latencies.setdefault(engine_id, [])
    return True


def _query_live_metrics() -> Dict[str, Any]:
    """Execute live queries against the database to fetch dynamic system metrics."""
    metrics_data = {
        "open_discrepancies": 0,
        "total_transactions": 0,
        "total_dead_letters": 0,
        "tenant_stats": {},
        "transaction_outbox_pending": 0,
        "reconciliation_outbox_pending": 0,
        "reconciliation_processing": 0,
        "kafka_consumer_lag": 0,
        "kafka_consumer_lag_max": 0,
        "reconciliation_latency_p95_seconds": 0.0,
        "reconciliation_matches": {},
        "reconciliation_match_latency_ms": 0.0,
        "certification_cases": 0,
        "certification_precision": 0.0,
        "certification_recall": 0.0,
        "certification_ready": 0,
        "certification_false_positives": 0,
        "certification_false_negatives": 0,
        "backup_age_seconds": 0.0,
        "backup_last_status": "unknown",
    }
    metrics_data.update(telemetry_snapshot())

    database_url = required_env("DATABASE_URL")
    try:
        from sqlalchemy import create_engine, func, text
        from sqlalchemy.orm import sessionmaker
        from models import (
            DeadLetter,
            Discrepancy,
            ProcessedTransaction,
            ReconciliationMatch,
            ReconciliationGroundTruth,
            ReconciliationOutbox,
            Transaction,
            TransactionOutbox,
        )

        global _metrics_engine
        if _metrics_engine is None:
            _metrics_engine = create_engine(database_url, pool_pre_ping=True, pool_size=2, max_overflow=2)
            from observability import instrument_sqlalchemy_engine
            instrument_sqlalchemy_engine(_metrics_engine)
            from logging_utils import set_span_id
            set_span_id()
        metrics_data["db_pool_usage"] = _metrics_engine.pool.checkedout() / max(_metrics_engine.pool.size(), 1)
        from logging_utils import set_span_id
        metrics_data["db_queries"] = len(_telemetry["db_query_latencies_ms"])
        Session = sessionmaker(bind=_metrics_engine)

        with Session() as session:
            metrics_data["total_transactions"] = session.query(func.count(Transaction.trans_id)).scalar() or 0
            metrics_data["open_discrepancies"] = (
                session.query(func.count(Discrepancy.id)).filter(Discrepancy.resolved == False).scalar() or 0
            )
            metrics_data["total_dead_letters"] = session.query(func.count(DeadLetter.id)).scalar() or 0
            metrics_data["transaction_outbox_pending"] = session.query(func.count(TransactionOutbox.id)).filter(TransactionOutbox.status.in_(["pending", "failed", "processing"])).scalar() or 0
            metrics_data["reconciliation_outbox_pending"] = session.query(func.count(ReconciliationOutbox.id)).filter(ReconciliationOutbox.status.in_(["pending", "failed", "processing"])).scalar() or 0
            metrics_data["reconciliation_processing"] = session.query(func.count(ProcessedTransaction.id)).filter(ProcessedTransaction.reconciliation_status == "processing").scalar() or 0
            if session.bind.dialect.name == "postgresql":
                metrics_data["db_connections"] = int(session.execute(text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()")).scalar() or 0)
                metrics_data["db_locks"] = int(session.execute(text("SELECT count(*) FROM pg_locks WHERE NOT granted")).scalar() or 0)
                metrics_data["db_deadlocks"] = int(session.execute(text("SELECT COALESCE(deadlocks, 0) FROM pg_stat_database WHERE datname = current_database()")).scalar() or 0)
            try:
                import importlib
                psutil = importlib.import_module("psutil")
                metrics_data["cpu_percent"] = psutil.cpu_percent(interval=None)
                metrics_data["ram_percent"] = psutil.virtual_memory().percent
                metrics_data["iops"] = float(sum(psutil.disk_io_counters()[:2])) if psutil.disk_io_counters() else 0.0
            except (ImportError, AttributeError, TypeError):
                # psutil is optional. CPU, RAM, and IOPS remain zero when it is
                # unavailable rather than failing the metrics scrape.
                pass
            from event_bus import broker_consumer_lag, consumer_lag_registry
            broker_lags = broker_consumer_lag()
            lag_values = [lag for partitions in broker_lags.values() for lag in partitions.values()] or [
                lag for partitions in consumer_lag_registry.snapshot().values() for lag in partitions.values()
            ]
            metrics_data["kafka_consumer_lag"] = sum(lag_values)
            metrics_data["kafka_consumer_lag_max"] = max(lag_values, default=0)
            latency_ms = session.execute(text(
                "SELECT COALESCE(percentile_cont(0.95) WITHIN GROUP "
                "(ORDER BY processing_time_ms), 0) "
                "FROM processed_transactions "
                "WHERE processing_time_ms IS NOT NULL"
            )).scalar() or 0
            metrics_data["reconciliation_latency_p95_seconds"] = float(latency_ms) / 1000
            status_rows = (
                session.query(ReconciliationMatch.status, func.count(ReconciliationMatch.id))
                .group_by(ReconciliationMatch.status)
                .all()
            )
            metrics_data["reconciliation_matches"] = {status: count for status, count in status_rows}
            metrics_data["reconciliation_match_latency_ms"] = float(
                session.query(func.avg(ReconciliationMatch.processing_latency_ms)).scalar() or 0
            )
            truth_rows = session.query(
                ReconciliationGroundTruth.expected_status,
                ReconciliationGroundTruth.actual_status,
            ).filter(ReconciliationGroundTruth.validated_at.is_not(None)).all()
            true_positives = sum(
                expected == actual == "MATCHED"
                for expected, actual in truth_rows
            )
            predicted_positives = sum(actual == "MATCHED" for _, actual in truth_rows)
            expected_positives = sum(expected == "MATCHED" for expected, _ in truth_rows)
            false_positives = predicted_positives - true_positives
            false_negatives = expected_positives - true_positives
            metrics_data["certification_cases"] = len(truth_rows)
            metrics_data["certification_ready"] = int(bool(truth_rows))
            metrics_data["certification_precision"] = true_positives / predicted_positives if predicted_positives else 0.0
            metrics_data["certification_recall"] = true_positives / expected_positives if expected_positives else 0.0
            metrics_data["certification_false_positives"] = false_positives
            metrics_data["certification_false_negatives"] = false_negatives

            # Tenant-level discrepancy breakdown
            tenant_rows = (
                session.query(Discrepancy.tenant_id, func.count(Discrepancy.id))
                .filter(Discrepancy.resolved == False)
                .group_by(Discrepancy.tenant_id)
                .all()
            )
            for tenant_id, count in tenant_rows:
                metrics_data["tenant_stats"][tenant_id or "default"] = count

    except Exception as exc:
        logger.warning("Could not collect live database metrics for Prometheus exporter: %s", exc)

    backup_dir = Path(os.getenv("PESAGUARD_BACKUP_DIR", "/var/backups/pesaguard"))
    backups = sorted(
        [*backup_dir.glob("pesaguard_*.sql.gz"), *backup_dir.glob("pesaguard_*.sql.gz.enc")],
        key=lambda path: path.stat().st_mtime,
    )
    if backups:
        metrics_data["backup_age_seconds"] = max(0.0, time.time() - backups[-1].stat().st_mtime)
    status_file = Path(os.getenv("PESAGUARD_BACKUP_STATUS_FILE", str(backup_dir / "last_status.json")))
    try:
        status_data = json.loads(status_file.read_text(encoding="utf-8"))
        metrics_data["backup_last_status"] = str(status_data.get("status", "unknown"))
    except (OSError, ValueError, TypeError):
        pass

    return metrics_data


def build_metrics_payload() -> str:
    """Generate Prometheus exposition format payload for operational scraping."""
    live_data = _query_live_metrics()

    if HAS_PROMETHEUS_CLIENT:
        registry = CollectorRegistry()
        if os.getenv("PROMETHEUS_MULTIPROC_DIR"):
            from prometheus_client.multiprocess import MultiProcessCollector
            MultiProcessCollector(registry)

        t_total = Gauge(
            "pesaguard_transactions_total",
            "Current transaction row count (database snapshot)",
            registry=registry,
        )
        t_total.inc(live_data["total_transactions"])

        alerts_total = Gauge(
            "pesaguard_alerts_total",
            "Total alerts emitted",
            registry=registry,
        )
        alerts_total.inc(0)

        alert_failures = Gauge(
            "pesaguard_alert_delivery_failures_total",
            "Total failed alert deliveries",
            registry=registry,
        )
        alert_failures.inc(0)

        alert_deliveries = Gauge(
            "pesaguard_alert_deliveries_total",
            "Total alert deliveries by channel",
            labelnames=["channel"],
            registry=registry,
        )
        for channel in ("slack", "sms", "email"):
            alert_deliveries.labels(channel=channel).inc(0)

        Gauge("pesaguard_requests_per_second", "Application requests observed per second", registry=registry).set(live_data["request_rate_per_second"])
        Gauge("pesaguard_error_rate", "Application error rate", registry=registry).set(live_data["error_rate"])
        Gauge("pesaguard_request_p50_ms", "Application request p50 latency", registry=registry).set(live_data["request_p50_ms"])
        Gauge("pesaguard_request_p95_ms", "Application request p95 latency", registry=registry).set(live_data["request_p95_ms"])
        Gauge("pesaguard_request_p99_ms", "Application request p99 latency", registry=registry).set(live_data["request_p99_ms"])
        Gauge("pesaguard_request_timeouts_total", "Application request timeouts", registry=registry).set(live_data["timeouts"])
        Gauge("pesaguard_db_connections", "Active database connections", registry=registry).set(live_data["db_connections"])
        Gauge("pesaguard_db_pool_usage", "Database pool usage ratio", registry=registry).set(live_data["db_pool_usage"])
        Gauge("pesaguard_db_query_p95_ms", "Database query p95 latency", registry=registry).set(live_data["db_query_p95_ms"])
        Gauge("pesaguard_db_locks", "Unresolved database locks", registry=registry).set(live_data.get("db_locks", 0))
        Gauge("pesaguard_db_deadlocks_total", "Database deadlocks", registry=registry).set(live_data.get("db_deadlocks", 0))
        Gauge("pesaguard_cpu_percent", "Host CPU utilization", registry=registry).set(live_data.get("cpu_percent", 0.0))
        Gauge("pesaguard_ram_percent", "Host RAM utilization", registry=registry).set(live_data.get("ram_percent", 0.0))
        Gauge("pesaguard_iops", "Host disk IO operations", registry=registry).set(live_data.get("iops", 0.0))
        event_retries = Counter("pesaguard_event_retries_total", "Event retry count", registry=registry)
        event_retries.inc(live_data["event_retries"])
        business_metrics = {
            "transactions_received": 0,
            "transactions_reconciled": 0,
            "fraud_alerts": 0,
            "fraud_engine_failures": 0,
            "reconciliation_failures": 0,
            "exceptions": 0,
            "duplicates": 0,
            "security_events": 0,
            **live_data["business"],
        }
        for metric_name, metric_value in business_metrics.items():
            business_counter = Counter(f"pesaguard_business_{metric_name}", "Business operation count", registry=registry)
            business_counter.inc(metric_value)

        disc_open = Gauge(
            "pesaguard_discrepancies_open",
            "Current unresolved discrepancies",
            ["tenant_id"],
            registry=registry,
        )
        open_disc_alias = Gauge(
            "pesaguard_open_discrepancies",
            "Current unresolved discrepancies",
            ["tenant_id"],
            registry=registry,
        )
        if live_data["tenant_stats"]:
            for tenant, count in live_data["tenant_stats"].items():
                disc_open.labels(tenant_id=tenant).set(count)
                open_disc_alias.labels(tenant_id=tenant).set(count)
        else:
            disc_open.labels(tenant_id="default").set(live_data["open_discrepancies"])
            open_disc_alias.labels(tenant_id="default").set(live_data["open_discrepancies"])

        dlq_total = Gauge(
            "pesaguard_dead_letters_total",
            "Total failed or dead-lettered messages",
            registry=registry,
        )
        dlq_total.inc(live_data["total_dead_letters"])

        connector_success = Gauge(
            "pesaguard_connector_last_success_timestamp_seconds",
            "Last successful connector sync timestamp",
            ["tenant_id"],
            registry=registry,
        )
        connector_success.labels(tenant_id="default").set(int(time.time()))

        connector_errors = Counter(
            "pesaguard_connector_errors_total",
            "Connector sync errors",
            ["tenant_id"],
            registry=registry,
        )
        connector_errors.labels(tenant_id="default").inc(0)

        kafka_lag = Gauge(
            "pesaguard_kafka_consumer_lag",
            "Kafka consumer lag for discrepancy processing",
            registry=registry,
        )
        kafka_lag.set(live_data["kafka_consumer_lag"])
        Gauge(
            "pesaguard_kafka_consumer_lag_max",
            "Maximum Kafka consumer partition lag",
            registry=registry,
        ).set(live_data["kafka_consumer_lag_max"])

        transaction_outbox = Gauge(
            "pesaguard_transaction_outbox_pending",
            "Transaction outbox rows awaiting or retrying publication",
            registry=registry,
        )
        transaction_outbox.set(live_data["transaction_outbox_pending"])
        reconciliation_outbox = Gauge(
            "pesaguard_reconciliation_outbox_pending",
            "Reconciliation result outbox rows awaiting or retrying publication",
            registry=registry,
        )
        reconciliation_outbox.set(live_data["reconciliation_outbox_pending"])
        reconciliation_processing = Gauge(
            "pesaguard_reconciliation_processing",
            "Reconciliation records currently in processing state",
            registry=registry,
        )
        reconciliation_processing.set(live_data["reconciliation_processing"])

        reconciliation_latency = Gauge(
            "pesaguard_reconciliation_latency_p95_seconds",
            "95th percentile reconciliation processing time in seconds",
            registry=registry,
        )
        reconciliation_latency.set(live_data["reconciliation_latency_p95_seconds"])
        reconciliation_matches = Gauge(
            "pesaguard_reconciliation_matches_total",
            "Reconciliation decisions by canonical status",
            ["status"],
            registry=registry,
        )
        for status, count in live_data["reconciliation_matches"].items():
            reconciliation_matches.labels(status=status).set(count)
        Gauge(
            "pesaguard_reconciliation_match_latency_ms",
            "Average canonical reconciliation decision latency in milliseconds",
            registry=registry,
        ).set(live_data["reconciliation_match_latency_ms"])
        certification_cases = Gauge(
            "pesaguard_reconciliation_certification_cases",
            "Validated reconciliation ground-truth cases",
            registry=registry,
        )
        certification_cases.set(live_data["certification_cases"])
        Gauge("pesaguard_reconciliation_certification_ready", "Whether validated ground truth is available", registry=registry).set(live_data["certification_ready"])
        Gauge("pesaguard_reconciliation_precision", "Validated reconciliation precision", registry=registry).set(live_data["certification_precision"])
        Gauge("pesaguard_reconciliation_recall", "Validated reconciliation recall", registry=registry).set(live_data["certification_recall"])
        Gauge("pesaguard_reconciliation_false_positives", "Validated reconciliation false positives", registry=registry).set(live_data["certification_false_positives"])
        Gauge("pesaguard_reconciliation_false_negatives", "Validated reconciliation false negatives", registry=registry).set(live_data["certification_false_negatives"])
        backup_age = Gauge(
            "pesaguard_backup_age_seconds",
            "Age of the newest local database backup in seconds",
            registry=registry,
        )
        backup_age.set(live_data["backup_age_seconds"])
        Gauge("pesaguard_backup_last_success", "Whether the latest backup completed successfully", registry=registry).set(
            1 if live_data["backup_last_status"] == "succeeded" else 0
        )

        return generate_latest(registry).decode("utf-8")

    # Fallback to plain Prometheus text representation if prometheus_client is not installed
    now_ts = int(time.time())
    open_disc = live_data["open_discrepancies"]
    total_trans = live_data["total_transactions"]
    total_dlq = live_data["total_dead_letters"]

    lines = [
        "# HELP pesaguard_transactions_total Current transaction row count (database snapshot)",
        "# TYPE pesaguard_transactions_total gauge",
        f"pesaguard_transactions_total {total_trans}",
        "# HELP pesaguard_alerts_total Total alerts emitted",
        "# TYPE pesaguard_alerts_total gauge",
        "pesaguard_alerts_total 0",
        "# HELP pesaguard_alert_delivery_failures_total Total failed alert deliveries",
        "# TYPE pesaguard_alert_delivery_failures_total gauge",
        "pesaguard_alert_delivery_failures_total 0",
        "# HELP pesaguard_alert_deliveries_total Total alert deliveries by channel",
        "# TYPE pesaguard_alert_deliveries_total gauge",
        'pesaguard_alert_deliveries_total{channel="slack"} 0',
        'pesaguard_alert_deliveries_total{channel="sms"} 0',
        'pesaguard_alert_deliveries_total{channel="email"} 0',
        "# HELP pesaguard_discrepancies_open Current unresolved discrepancies",
        "# TYPE pesaguard_discrepancies_open gauge",
        f'pesaguard_discrepancies_open{{tenant_id="default"}} {open_disc}',
        "# HELP pesaguard_open_discrepancies Current unresolved discrepancies",
        "# TYPE pesaguard_open_discrepancies gauge",
        f'pesaguard_open_discrepancies{{tenant_id="default"}} {open_disc}',
        "# HELP pesaguard_reconciliation_latency_seconds Reconciliation latency in seconds",
        "# TYPE pesaguard_reconciliation_latency_seconds summary",
        "pesaguard_reconciliation_latency_seconds_sum 0.0",
        "pesaguard_reconciliation_latency_seconds_count 0",
        "# HELP pesaguard_connector_last_success_timestamp_seconds Last successful connector sync timestamp",
        "# TYPE pesaguard_connector_last_success_timestamp_seconds gauge",
        f'pesaguard_connector_last_success_timestamp_seconds{{tenant_id="default"}} {now_ts}',
        "# HELP pesaguard_connector_errors_total Connector sync errors",
        "# TYPE pesaguard_connector_errors_total counter",
        'pesaguard_connector_errors_total{tenant_id="default"} 0',
        "# HELP pesaguard_kafka_consumer_lag Kafka consumer lag for discrepancy processing",
        "# TYPE pesaguard_kafka_consumer_lag gauge",
        f"pesaguard_kafka_consumer_lag {live_data['kafka_consumer_lag']}",
        "# TYPE pesaguard_kafka_consumer_lag_max gauge",
        f"pesaguard_kafka_consumer_lag_max {live_data['kafka_consumer_lag_max']}",
        "# HELP pesaguard_transaction_outbox_pending Transaction outbox rows awaiting publication",
        "# TYPE pesaguard_transaction_outbox_pending gauge",
        f"pesaguard_transaction_outbox_pending {live_data['transaction_outbox_pending']}",
        "# HELP pesaguard_reconciliation_outbox_pending Reconciliation result outbox rows awaiting publication",
        "# TYPE pesaguard_reconciliation_outbox_pending gauge",
        f"pesaguard_reconciliation_outbox_pending {live_data['reconciliation_outbox_pending']}",
        "# HELP pesaguard_reconciliation_processing Reconciliation records currently processing",
        "# TYPE pesaguard_reconciliation_processing gauge",
        f"pesaguard_reconciliation_processing {live_data['reconciliation_processing']}",
        "# HELP pesaguard_reconciliation_latency_p95_seconds 95th percentile reconciliation processing time in seconds",
        "# TYPE pesaguard_reconciliation_latency_p95_seconds gauge",
        f"pesaguard_reconciliation_latency_p95_seconds {live_data['reconciliation_latency_p95_seconds']}",
        "# TYPE pesaguard_reconciliation_certification_cases gauge",
        f"pesaguard_reconciliation_certification_cases {live_data['certification_cases']}",
        "# TYPE pesaguard_reconciliation_certification_ready gauge",
        f"pesaguard_reconciliation_certification_ready {live_data['certification_ready']}",
        "# TYPE pesaguard_reconciliation_precision gauge",
        f"pesaguard_reconciliation_precision {live_data['certification_precision']}",
        "# TYPE pesaguard_reconciliation_recall gauge",
        f"pesaguard_reconciliation_recall {live_data['certification_recall']}",
        "# TYPE pesaguard_reconciliation_false_positives gauge",
        f"pesaguard_reconciliation_false_positives {live_data['certification_false_positives']}",
        "# TYPE pesaguard_reconciliation_false_negatives gauge",
        f"pesaguard_reconciliation_false_negatives {live_data['certification_false_negatives']}",
        "# HELP pesaguard_backup_age_seconds Age of the newest local database backup in seconds",
        "# TYPE pesaguard_backup_age_seconds gauge",
        f"pesaguard_backup_age_seconds {live_data['backup_age_seconds']}",
    ]
    return "\n".join(lines) + "\n"
