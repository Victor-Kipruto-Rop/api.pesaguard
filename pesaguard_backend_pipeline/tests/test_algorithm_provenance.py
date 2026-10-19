from algorithm_provenance import build_algorithm_provenance


def test_provenance_records_engine_version_and_reason_codes():
    result = build_algorithm_provenance({
        "status": "MATCHED",
        "evidence": {
            "engine_version": "phase3.3",
            "matching_rules": ["reference_exact", "amount_exact", "reference_exact"],
        },
    })

    assert result["schema_version"] == "algorithm-provenance-v1"
    assert result["reconciliation_engine_version"] == "phase3.3"
    assert result["reconciliation_status"] == "MATCHED"
    assert result["reason_codes"] == ["amount_exact", "reference_exact"]
    assert result["algorithm_authorized_funds_movement"] is False


def test_provenance_does_not_invent_missing_versions_or_evidence():
    result = build_algorithm_provenance({"status": "EXCEPTION"})

    assert result["reconciliation_engine_version"] is None
    assert result["evidence_available"] is False
    assert result["reason_codes"] == []
    assert result["shadow_analysis"]["algorithm_version"] is None
    assert result["shadow_analysis"]["legacy_decision_unchanged"] is None


def test_shadow_metadata_is_recorded_as_advisory_without_changing_authority():
    result = build_algorithm_provenance({
        "status": "MATCHED",
        "evidence": {"engine_version": "phase3.3", "matching_rules": ["reference_exact"]},
        "smart_analysis": {
            "algorithm_version": "smart-v2",
            "available": True,
            "legacy_decision_unchanged": True,
        },
        "fraud_risk": {"risk_level": "MEDIUM"},
    })

    assert result["shadow_analysis"]["present"] is True
    assert result["shadow_analysis"]["algorithm_version"] == "smart-v2"
    assert result["shadow_analysis"]["decision_authority"] == "advisory_only"
    assert result["shadow_analysis"]["legacy_decision_unchanged"] is True
    assert result["risk_assessment"]["risk_level"] == "MEDIUM"
    assert result["risk_assessment"]["decision_authority"] == "triage_only"
    assert result["algorithm_authorized_funds_movement"] is False


def test_provenance_ignores_malformed_optional_metadata():
    result = build_algorithm_provenance({
        "evidence": {"matching_rules": "not-a-list"},
        "smart_analysis": [],
        "fraud_risk": None,
    })

    assert result["reason_codes"] == []
    assert result["shadow_analysis"]["present"] is False
    assert result["risk_assessment"]["present"] is False
