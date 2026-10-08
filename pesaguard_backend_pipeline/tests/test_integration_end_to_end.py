from __future__ import annotations

import json
import logging
import os
import pytest
from pathlib import Path

import sqlalchemy.exc
import yaml
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

import metrics

from models import (
    Base,
    DeadLetter,
    Discrepancy,
    ProcessedTransaction,
    ReconciliationMatch,
    ReconciliationOutbox,
    Transaction,
    TransactionOutbox,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DOCS = [
    BACKEND_ROOT / "docs" / "architecture" / "CURRENT_ARCHITECTURE.md",
    BACKEND_ROOT / "monitoring" / "alerts.yml",
    BACKEND_ROOT / "monitoring" / "alertmanager.yml",
    BACKEND_ROOT / "monitoring" / "prometheus.yml",
]

def test_operational_documents_are_present():
    """The release must ship the documents required by the runtime controls."""
    missing = [str(path.relative_to(BACKEND_ROOT)) for path in REQUIRED_DOCS if not path.exists()]
    assert not missing, f"missing operational documents: {missing}"


def test_metrics_payload_is_prometheus_text():
    """The metrics surface must remain scrapeable by Prometheus."""
    payload = metrics.build_metrics_payload()
    assert isinstance(payload, str)
    assert "# HELP" in payload or "# TYPE" in payload
