"""Stable, explicit provenance for reconciliation algorithm decisions.

This module records what evidence was available; it does not make or authorize
financial decisions. Missing algorithm metadata stays null instead of being
filled with invented defaults.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

PROVENANCE_SCHEMA_VERSION = "algorithm-provenance-v1"


def build_algorithm_provenance(evaluation: Mapping[str, Any]) -> dict[str, Any]:
    """Build a JSON-safe, non-authoritative provenance envelope for an evaluation."""
    evidence = evaluation.get("evidence")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    shadow = evaluation.get("smart_analysis")
    shadow = shadow if isinstance(shadow, Mapping) else {}
    risk = evaluation.get("fraud_risk")
    risk = risk if isinstance(risk, Mapping) else {}

    engine_version = (
        evidence.get("engine_version")
        or evaluation.get("engine_version")
        or evidence.get("algorithm_version")
    )
    rules = evidence.get("matching_rules") or evidence.get("reason_codes") or []
    if not isinstance(rules, (list, tuple)):
        rules = []
    reason_codes = sorted({str(item) for item in rules if str(item).strip()})

    shadow_present = bool(shadow)
    risk_level = risk.get("risk_level") or risk.get("level")
    return {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "reconciliation_engine_version": str(engine_version) if engine_version else None,
        "reconciliation_status": str(
            evaluation.get("phase3_status") or evaluation.get("status") or ""
        ) or None,
        "reason_codes": reason_codes,
        "evidence_available": bool(evidence),
        "shadow_analysis": {
            "present": shadow_present,
            "algorithm_version": (
                str(shadow.get("algorithm_version"))
                if shadow.get("algorithm_version") else None
            ),
            "available": bool(shadow.get("available", True)) if shadow_present else None,
            "legacy_decision_unchanged": (
                shadow.get("legacy_decision_unchanged") is True
                if shadow_present else None
            ),
            "decision_authority": "advisory_only",
        },
        "risk_assessment": {
            "present": bool(risk),
            "algorithm_version": (
                str(risk.get("algorithm_version"))
                if risk.get("algorithm_version") else None
            ),
            "risk_level": str(risk_level) if risk_level else None,
            "decision_authority": "triage_only",
        },
        "algorithm_authorized_funds_movement": False,
    }
