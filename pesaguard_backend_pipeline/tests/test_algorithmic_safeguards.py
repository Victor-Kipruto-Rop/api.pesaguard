from datetime import datetime, timezone

from algorithmic_safeguards import assess_event_time, classify_replay, profile_data_quality


def transaction(**overrides):
    return {"tenant_id": "tenant-a", "provider": "mpesa", "TransID": "QWE123", "TransAmount": "125.00", "BillRefNumber": "INV-1", "TransTime": "20261014120000", "MSISDN": "254700000001", "Currency": "KES", **overrides}


def test_replay_classifier_distinguishes_new_identical_and_conflicting_events():
    original = transaction()
    assert classify_replay(original, [])["classification"] == "NEW"
    assert classify_replay(original, [original])["classification"] == "IDENTICAL_REPLAY"
    result = classify_replay({**original, "TransAmount": "126.00"}, [original])
    assert result["classification"] == "CONFLICTING_REPLAY"
    assert result["reason_codes"] == ["same_external_id_different_payload"]


def test_replay_classifier_scopes_by_tenant_and_provider():
    original = transaction()
    assert classify_replay(original, [{**original, "tenant_id": "tenant-b"}])["classification"] == "NEW"
    assert classify_replay(original, [{**original, "provider": "other"}])["classification"] == "NEW"


def test_replay_classifier_does_not_infer_identity_from_amount_or_time():
    assert classify_replay(transaction(TransID=""), [transaction(TransID="")])["classification"] == "INSUFFICIENT_IDENTITY"


def test_event_time_classifies_future_stale_and_invalid_separately():
    now = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
    assert assess_event_time("20261014120100", now=now)["classification"] == "CURRENT"
    assert assess_event_time("20261014100000", now=now, stale_after_seconds=3600)["classification"] == "STALE"
    assert assess_event_time("20261014121000", now=now)["classification"] == "FUTURE"
    assert assess_event_time("not-a-time", now=now)["classification"] == "MISSING_OR_INVALID"


def test_data_quality_profile_reports_unknown_uniqueness_not_a_false_pass():
    now = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
    profile = profile_data_quality(transaction(TransAmount="NaN"), now=now)
    assert profile["checks"]["amount_positive_finite"] is False
    assert profile["uniqueness"] == "NOT_EVALUATED"
    assert profile["failure_count"] == 1


def test_data_quality_profile_identifies_missing_fields():
    profile = profile_data_quality({"TransAmount": "10"})
    assert profile["completeness"] < 1
    assert "transaction_id_present" in profile["failures"]
    assert "reference_present" in profile["failures"]
