"""Versioned batch publication that preserves the existing import boundary.

``batch_ingestion.BatchImportService`` remains the durable import lifecycle:
object storage plus the ``ImportJob`` row are still the only source of truth.
These helpers emit the corresponding registry events after import work reaches a
durable boundary. They deliberately do not re-implement parsing, ingestion, or
stats; they translate an already-computed ``ImportJob`` into events.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Mapping, Sequence

logger = logging.getLogger("pesaguard.batch_events")

MAX_REJECTED_RECORD_DETAILS = 20


def _publish(event_type: str, tenant_id: str, aggregate_id: str, payload: Mapping[str, Any], publisher: Callable[..., Any], *, correlation_id: str | None = None) -> Any:
    from event_bus import build_event
    from producer import publish_versioned_event

    event = build_event(
        event_type,
        tenant_id,
        aggregate_id,
        dict(payload),
        correlation_id=correlation_id,
        producer="pesaguard.batch_events",
        producer_version="1",
    )
    return publish_versioned_event(event, producer=publisher)


def _job_snapshot(job: Any) -> dict[str, Any]:
    return {
        "import_id": getattr(job, "id", None),
        "source": getattr(job, "source", None),
        "filename": getattr(job, "filename", None),
        "status": getattr(job, "status", None),
        "records_received": getattr(job, "records_received", 0),
        "records_valid": getattr(job, "records_valid", 0),
        "records_failed": getattr(job, "records_failed", 0),
        "error_summary": list(getattr(job, "error_summary", None) or []),
    }


def publish_batch_import_received(
    *,
    tenant_id: str,
    import_id: str,
    source: str,
    filename: str,
    publisher: Callable[..., Any],
    correlation_id: str | None = None,
) -> Any:
    """Emit `batch_import.received` after a job row has been submitted."""
    return _publish(
        "batch_import.received",
        tenant_id,
        import_id,
        {"import_id": import_id, "source": source, "filename": filename},
        publisher,
        correlation_id=correlation_id,
    )


def publish_batch_import_started(
    *,
    tenant_id: str,
    import_id: str,
    publisher: Callable[..., Any],
    correlation_id: str | None = None,
) -> Any:
    """Emit `batch.import.started` when processing a durable job begins."""
    return _publish(
        "batch.import.started",
        tenant_id,
        import_id,
        {"import_id": import_id},
        publisher,
        correlation_id=correlation_id,
    )


def _rejected_records(job: Any, limit: int = MAX_REJECTED_RECORD_DETAILS) -> list[dict[str, Any]]:
    rejected: list[dict[str, Any]] = []
    for entry in list(getattr(job, "error_summary", None) or [])[: max(0, limit)]:
        if isinstance(entry, Mapping):
            record = entry.get("record")
            error = entry.get("error")
        else:
            record, error = entry, "record rejected"
        rejected.append({"record": record, "error": error})
    return rejected


def publish_batch_import_outcome(
    *,
    job: Any,
    publisher: Callable[..., Any],
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Emit completion plus bounded per-record rejections after import is durable.

    Returns ``{"completed": <send-result>, "rejected": [<send-result>, ...]}``.
    Rejection detail is intentionally capped at 20 entries; the full failure
    evidence remains on the durable ``ImportJob.error_summary`` row. The
    ``batch.record.rejected`` events reuse the caller's DB transaction boundary
    (callers invoke this after ``service.process`` commits) and publish only.
    """
    tenant_id = str(getattr(job, "tenant_id", "") or "")
    import_id = str(getattr(job, "id", "") or "")
    snapshot = _job_snapshot(job)
    result: dict[str, Any] = {"completed": None, "rejected": []}
    status = str(getattr(job, "status", "") or "").lower()
    if status not in {"completed", "failed"}:
        raise ValueError(f"batch import outcome requires a completed or failed job, got {status!r}")
    outcome_event = "batch_import.completed" if status == "completed" else "batch_import.failed"
    result["completed"] = _publish(
        outcome_event,
        tenant_id,
        import_id,
        snapshot,
        publisher,
        correlation_id=correlation_id,
    )
    rejected = _rejected_records(job)
    rejected_results: list[Any] = []
    for index, entry in enumerate(rejected, start=1):
        rejected_results.append(
            _publish(
                "batch.record.rejected",
                tenant_id,
                f"{import_id}:record:{entry.get('record') or index}",
                {"import_id": import_id, "record": entry.get("record"), "error": entry.get("error")},
                publisher,
                correlation_id=correlation_id,
            )
        )
    result["rejected"] = rejected_results
    return result


def iter_rejected_record_details(job: Any, limit: int = MAX_REJECTED_RECORD_DETAILS) -> Sequence[Mapping[str, Any]]:
    """Expose capped rejection detail for tests and operator tooling."""
    return _rejected_records(job, limit=limit)
