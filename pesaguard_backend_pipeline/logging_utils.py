"""
Enterprise-grade structured JSON logging and async correlation context tracing for PesaGuard.

Provides a unified JSON log envelope with correlation ID tracking across web requests,
background queues, and async workers.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Optional

# ContextVar for end-to-end distributed request and transaction correlation tracing
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
_observability_context: ContextVar[Dict[str, str]] = ContextVar("observability_context", default={})
OBSERVABILITY_FIELDS = ("request_id", "correlation_id", "transaction_id", "event_id", "trace_id", "span_id", "traceparent", "tenant_id")

# Standard LogRecord attributes to exclude from custom extra key extraction
_RESERVED_RECORD_ATTRS = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "message", "module",
    "msecs", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "thread", "threadName", "taskName",
}


class JsonFormatter(logging.Formatter):
    """Emit logs as single-line JSON objects with standard telemetry envelopes."""

    def format(self, record: logging.LogRecord) -> str:
        cid = _correlation_id.get() or getattr(record, "correlation_id", "")
        if not cid:
            cid = str(uuid.uuid4())[:8]

        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()

        context = dict(_observability_context.get())
        if cid:
            context.setdefault("correlation_id", cid)
        payload: Dict[str, Any] = {
            "ts": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "correlation_id": cid,
            "message": record.getMessage(),
        }
        for key in OBSERVABILITY_FIELDS:
            if context.get(key):
                payload[key] = context[key]

        # Include exception tracebacks if present
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        # Extract all custom 'extra' kwargs passed into log statements
        for key, value in record.__dict__.items():
            if key not in _RESERVED_RECORD_ATTRS and not key.startswith("_"):
                try:
                    # Verify key value is JSON serializable
                    json.dumps(value)
                    payload[key] = value
                except (TypeError, ValueError):
                    payload[key] = str(value)

        return json.dumps(payload, ensure_ascii=False)


def configure_logging(log_level: Optional[str] = None) -> None:
    """
    Configure the root logger to emit structured JSON logs.
    Prevents duplicate handler instantiation during app startup or re-initialization.
    """
    level = (log_level or os.getenv("LOG_LEVEL", "INFO")).upper()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Avoid adding duplicate handlers if already configured
    if not any(isinstance(h, logging.StreamHandler) and isinstance(h.formatter, JsonFormatter) for h in root_logger.handlers):
        root_logger.handlers = [handler]


def set_correlation_id(correlation_id: str) -> Token[str]:
    """Set the correlation ID for the current request or task context."""
    cid = correlation_id.strip() if correlation_id else str(uuid.uuid4())[:8]
    return _correlation_id.set(cid)


def bind_observability_context(**fields: Optional[str]) -> Dict[str, str]:
    """Merge traceability identifiers into the current execution context."""
    current = dict(_observability_context.get())
    for key in OBSERVABILITY_FIELDS:
        value = fields.get(key)
        if value:
            current[key] = str(value)
    if current.get("correlation_id"):
        _correlation_id.set(current["correlation_id"])
    _observability_context.set(current)
    return current


def clear_observability_context() -> None:
    """Clear request/task-scoped traceability identifiers."""
    _observability_context.set({})
    _correlation_id.set("")


def get_observability_context() -> Dict[str, str]:
    return dict(_observability_context.get())


def get_correlation_id() -> str:
    """Retrieve the current correlation ID, generating a fresh one if unassigned."""
    cid = _correlation_id.get()
    if not cid:
        cid = str(uuid.uuid4())[:8]
        _correlation_id.set(cid)
    return cid


@contextmanager
def correlation_context(correlation_id: Optional[str] = None) -> Generator[str, None, None]:
    """
    Context manager for scoping correlation IDs to specific execution blocks or threads.
    
    Usage:
        with correlation_context(req_id):
            logger.info("Processing webhook")
    """
    cid = correlation_id or str(uuid.uuid4())[:8]
    token = set_correlation_id(cid)
    try:
        yield cid
    finally:
        _correlation_id.reset(token)

def set_span_id(span_id: Optional[str] = None) -> str:
    """Capture or replace the current span identity in the observability context."""
    if not span_id:
        span_id = uuid.uuid4().hex
    bind_observability_context(span_id=span_id)
    return span_id

