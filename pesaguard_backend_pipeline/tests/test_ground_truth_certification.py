from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, ReconciliationGroundTruth, ReconciliationMatch
from operations.ground_truth_certification import register_cases, validate_cases


def test_register_and_validate_approved_business_cases(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'ground-truth.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        cases = [
            {"transaction_id": "case-1", "expected_status": "MATCHED", "name": "approved exact"},
            {"transaction_id": "case-2", "expected_status": "UNMATCHED", "name": "approved missing"},
        ]
        assert register_cases(session, cases, "tenant-a", "finance-approver", "approval-2026-001") == 2
        assert session.query(ReconciliationGroundTruth).count() == 2
        assert session.query(ReconciliationGroundTruth).filter_by(approved_by="finance-approver").count() == 2

        session.add(ReconciliationMatch(
            id="match-1",
            tenant_id="tenant-a",
            transaction_id="case-1",
            matched_record={"internal_ref": "case-1"},
            matching_rules=["reference_exact"],
            match_score=1,
            match_timestamp=datetime.now(timezone.utc),
            engine_version="phase3.1",
            status="MATCHED",
            processing_latency_ms=1,
        ))
        session.commit()
        result = validate_cases(session, "tenant-a", "reconciliation-reviewer")
        assert result["validated_cases"] == 1
        assert result["missing_matches"] == ["case-2"]
        assert result["scorecard"] == {
            "precision": 1.0,
            "recall": 1.0,
            "false_positives": 0,
            "false_negatives": 0,
            "known_cases": 2,
            "correct_cases": 1,
        }
        assert result["certified"] is False
    finally:
        session.close()


def test_validation_reports_false_positive_and_false_negative_metrics(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'ground-truth-metrics.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        cases = [
            {"transaction_id": "true-positive", "expected_status": "MATCHED"},
            {"transaction_id": "false-positive", "expected_status": "UNMATCHED"},
            {"transaction_id": "false-negative", "expected_status": "MATCHED"},
            {"transaction_id": "true-negative", "expected_status": "UNMATCHED"},
        ]
        register_cases(session, cases, "tenant-a", "finance-approver", "approval-2026-002")
        actual_statuses = {
            "true-positive": "MATCHED",
            "false-positive": "MATCHED",
            "false-negative": "UNMATCHED",
            "true-negative": "UNMATCHED",
        }
        for transaction_id, status in actual_statuses.items():
            session.add(ReconciliationMatch(
                id=f"match-{transaction_id}",
                tenant_id="tenant-a",
                transaction_id=transaction_id,
                matched_record={"internal_ref": transaction_id},
                matching_rules=["reference_exact"],
                match_score=1,
                match_timestamp=datetime.now(timezone.utc),
                engine_version="phase3.1",
                status=status,
                processing_latency_ms=1,
            ))
        session.commit()

        result = validate_cases(session, "tenant-a", "reconciliation-reviewer")

        assert result["scorecard"] == {
            "precision": 0.5,
            "recall": 0.5,
            "false_positives": 1,
            "false_negatives": 1,
            "known_cases": 4,
            "correct_cases": 2,
        }
        assert result["certified"] is False
    finally:
        session.close()


def test_validation_does_not_certify_a_sample_without_positive_cases(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'ground-truth-no-positive.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        register_cases(
            session,
            [{"transaction_id": "no-match", "expected_status": "UNMATCHED"}],
            "tenant-a",
            "finance-approver",
            "approval-2026-003",
        )
        session.add(ReconciliationMatch(
            id="match-no-match",
            tenant_id="tenant-a",
            transaction_id="no-match",
            matched_record={},
            matching_rules=[],
            match_score=0,
            match_timestamp=datetime.now(timezone.utc),
            engine_version="phase3.1",
            status="UNMATCHED",
            processing_latency_ms=1,
        ))
        session.commit()

        result = validate_cases(session, "tenant-a", "reconciliation-reviewer")

        assert result["scorecard"]["precision"] is None
        assert result["scorecard"]["recall"] is None
        assert result["certified"] is False
    finally:
        session.close()
