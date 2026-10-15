from datetime import datetime, timezone, timedelta

import pytest

from pesaguard_backend_pipeline.transaction_lifecycle_algorithms import (
    ALGORITHM_VERSION,
    assess_reversal_lifecycle,
)


BASE = {
    "tenant_id": "tenant-a",
    "provider": "mpesa",
    "provider_account_id": "paybill-1",
    "currency": "KES",
}
ORIGINAL_TIME = datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc)


def original(**overrides):
    return {
        **BASE,
        "TransID": "ORIG-1",
        "TransAmount": "100.00",
        "TransTime": ORIGINAL_TIME.isoformat(),
        **overrides,
    }


def reversal(**overrides):
    return {
        **BASE,
        "TransID": "REV-1",
        "OriginalTransID": "ORIG-1",
        "TransAmount": "25.00",
        "TransTime": (ORIGINAL_TIME + timedelta(minutes=5)).isoformat(),
        **overrides,
    }


def test_valid_reversal_is_only_validation_evidence_not_posting_authority():
    result = assess_reversal_lifecycle(reversal(), original())
    assert result["algorithm_version"] == ALGORITHM_VERSION
    assert result["status"] == "VALIDATION_PASS"
    assert result["review_required"] is False
    assert result["can_auto_post"] is False
    assert result["confirmed_prior_reversal_amount"] == "0"


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"OriginalTransID": ""}, "missing_original_reference"),
        ({"TransAmount": "NaN"}, "invalid_reversal_amount"),
        ({"tenant_id": "tenant-b"}, "scope_conflict:tenant_id"),
        ({"provider_account_id": "paybill-2"}, "scope_conflict:provider_account_id"),
        ({"currency": "USD"}, "scope_conflict:currency"),
        ({"TransTime": "2026-10-14T10:00:00"}, "reversal_timestamp_missing_or_ambiguous"),
    ],
)
def test_invalid_reversal_fails_closed(overrides, reason):
    result = assess_reversal_lifecycle(reversal(**overrides), original())
    assert result["status"] == "REVIEW_REQUIRED"
    assert result["can_auto_post"] is False
    assert reason in result["reason_codes"]


def test_reversal_must_not_precede_original():
    result = assess_reversal_lifecycle(
        reversal(TransTime=(ORIGINAL_TIME - timedelta(seconds=1)).isoformat()),
        original(),
    )
    assert "reversal_precedes_original" in result["reason_codes"]


def test_cumulative_confirmed_reversals_cannot_exceed_original_amount():
    prior = {
        **BASE,
        "TransID": "REV-OLD",
        "OriginalTransID": "ORIG-1",
        "TransAmount": "80.00",
        "TransTime": (ORIGINAL_TIME + timedelta(minutes=2)).isoformat(),
        "status": "confirmed",
    }
    result = assess_reversal_lifecycle(reversal(TransAmount="25.00"), original(), [prior])
    assert "cumulative_reversal_exceeds_original_amount" in result["reason_codes"]
    assert result["confirmed_prior_reversal_amount"] == "80.00"


def test_unconfirmed_prior_reversal_does_not_reduce_remaining_amount():
    prior = {
        **BASE,
        "TransID": "REV-OLD",
        "OriginalTransID": "ORIG-1",
        "TransAmount": "80.00",
        "TransTime": (ORIGINAL_TIME + timedelta(minutes=2)).isoformat(),
        "status": "pending",
    }
    result = assess_reversal_lifecycle(reversal(), original(), [prior])
    assert result["status"] == "VALIDATION_PASS"
    assert result["confirmed_prior_reversal_amount"] == "0"


def test_duplicate_reversal_id_is_reviewed():
    result = assess_reversal_lifecycle(reversal(), original(), [reversal(status="confirmed")])
    assert "duplicate_reversal_transaction_id" in result["reason_codes"]


def test_missing_original_never_passes():
    result = assess_reversal_lifecycle(reversal(), None)
    assert result["status"] == "REVIEW_REQUIRED"
    assert "original_transaction_not_found" in result["reason_codes"]


def test_invalid_argument_shapes_are_rejected():
    with pytest.raises(ValueError):
        assess_reversal_lifecycle([], original())
