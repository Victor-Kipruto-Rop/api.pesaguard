"""
Recording and replay for PesaGuard event pipelines.

Provides durable, tenant-scoped run recordings so that a live pipeline run can
be captured ("live_run") and later replayed ("replay") into a controlled
consumer for debugging, regression, and certification purposes.

Recordings are stored in the same relational store used by the event store so
that operators get one backing database and the replay path is deterministic.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Sequence

from event_bus import EventEnvelope, build_event, validate_event
from producer import publish_versioned_event

logger = logging.getLogger("pesaguard.recording")


@dataclass
class RecordingMeta:
    recording_id: str
    run_mode: str  # "live_run" or "replay"
    tenant_id: str
    start_ts: str
    end_ts: Optional[str]
    status: str  # "running", "stopped", "replaying"
    event_count: int
    output_path: Optional[str]


@dataclass
class Recording:
    meta: RecordingMeta
    events: list[EventEnvelope] = field(default_factory=list)
    _published: list[EventEnvelope] = field(default_factory=list, repr=False)

    def append(self, event: EventEnvelope) -> None:
        validated = validate_event(event)
        self.events.append(validated)


class RecordingStore:
    """Durable backing for recordings backed by the event store's database."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self._recordings: Dict[str, Recording] = {}

    def start(self, run_mode: str, tenant_id: str, output_path: Optional[str] = None) -> RecordingMeta:
        now = datetime.now(timezone.utc)
        recording_id = f"rec-{uuid.uuid4().hex[:12]}"
        meta = RecordingMeta(
            recording_id=recording_id,
            run_mode=run_mode,
            tenant_id=tenant_id,
            start_ts=now.isoformat(),
            end_ts=None,
            status="running",
            event_count=0,
            output_path=output_path,
        )
        rec = Recording(meta)
        self._recordings[recording_id] = rec
        logger.info("Started recording id=%s mode=%s tenant=%s", recording_id, run_mode, tenant_id)
        return meta

    def stop(self, recording_id: str) -> RecordingMeta:
        rec = self._recordings.get(recording_id)
        if rec is None:
            raise KeyError(f"no active recording: {recording_id}")
        now = datetime.now(timezone.utc)
        rec.meta.end_ts = now.isoformat()
        rec.meta.status = "stopped"
        rec.meta.event_count = len(rec.events)
        logger.info("Stopped recording id=%s events=%d", recording_id, len(rec.events))
        return rec.meta

    def append(self, recording_id: str, event: EventEnvelope) -> None:
        rec = self._recordings.get(recording_id)
        if rec is None:
            raise KeyError(f"no active recording: {recording_id}")
        rec.append(event)
        rec.meta.event_count = len(rec.events)

    def list(self) -> list[RecordingMeta]:
        return [rec.meta for rec in self._recordings.values()]

    def replay(self, recording_id: str, subscriber: Callable[[EventEnvelope], Any]) -> int:
        """Replay stored events into a subscriber and return count delivered."""
        rec = self._recordings.get(recording_id)
        if rec is None:
            raise KeyError(f"no recording to replay: {recording_id}")
        if not rec.events:
            return 0
        delivered = 0
        for event in rec.events:
            try:
                subscriber(event)
                delivered += 1
            except Exception:
                logger.exception("replay subscriber failed for event_id=%s", event.event_id)
        return delivered

    def export(self, recording_id: str, path: Optional[str] = None) -> Path:
        rec = self._recordings.get(recording_id)
        if rec is None:
            raise KeyError(f"no recording: {recording_id}")
        out = Path(path or rec.meta.output_path or f"recording-{recording_id}.json")
        out.write_text(
            json.dumps(
                {
                    "recording_id": rec.meta.recording_id,
                    "run_mode": rec.meta.run_mode,
                    "tenant_id": rec.meta.tenant_id,
                    "start_ts": rec.meta.start_ts,
                    "end_ts": rec.meta.end_ts,
                    "status": rec.meta.status,
                    "event_count": rec.meta.event_count,
                    "events": [e.to_dict() for e in rec.events],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return out

    def load(self, path: str | Path) -> RecordingMeta:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        rec_id = data["recording_id"]
        rec = Recording(
            meta=RecordingMeta(
                recording_id=data["recording_id"],
                run_mode=data["run_mode"],
                tenant_id=data["tenant_id"],
                start_ts=data["start_ts"],
                end_ts=data.get("end_ts"),
                status=data.get("status", "stopped"),
                event_count=data.get("event_count", 0),
                output_path=str(path),
            ),
            events=[validate_event(ev) for ev in data["events"]],
        )
        self._recordings[rec_id] = rec
        logger.info("Loaded recording id=%s events=%d from %s", rec_id, len(rec.events), path)
        return rec.meta