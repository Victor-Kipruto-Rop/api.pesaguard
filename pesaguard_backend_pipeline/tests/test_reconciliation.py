from reconciliation_engine import evaluate_transaction


def make_event(trans_id="T1", amount="100", phone="254700000000", trans_time="20240601120000"):
    return {
        "TransID": trans_id,
        "TransAmount": amount,
        "MSISDN": phone,
        "TransTime": trans_time,
        "BusinessShortCode": "12345",
    }


def make_internal_record(internal_ref="ORD-1", amount=100.0, phone="254700000000", timestamp="2024-06-01T09:00:00Z", status="pending"):
    return {
        "internal_ref": internal_ref,
        "amount": amount,
        "phone_number": phone,
        "timestamp": timestamp,
        "status": status,
    }


def test_exact_match_is_resolved():
    event = make_event(trans_id="T-100", amount="100", phone="254700000000", trans_time="20240601120000")
    internal_record = make_internal_record(timestamp="2024-06-01T09:00:00Z")

    result = evaluate_transaction(event, [internal_record], seen_trans_ids=set())

    assert result["status"] == "matched"
    assert result["severity"] == "info"
    assert result["match"]["match_type"] == "exact"


def test_partial_match_is_review_required():
    event = make_event(trans_id="T-200", amount="100", phone="254700000001", trans_time="20240601120000")
    internal_record = make_internal_record(internal_ref="ORD-2", phone="254700000000", timestamp="2024-06-01T09:00:00Z")

    result = evaluate_transaction(event, [internal_record], seen_trans_ids=set())

    assert result["status"] == "needs_review"
    assert result["severity"] == "warning"
    assert result["match"]["match_type"] in {"partial", "partial_fuzzy"}


def test_missing_payment_is_critical():
    event = make_event(trans_id="T-300", amount="100", phone="254700000002", trans_time="20240601130000")
    internal_record = make_internal_record(internal_ref="ORD-3", phone="254700000002", amount=100.0, timestamp="2024-06-01T11:00:00Z")

    result = evaluate_transaction(event, [internal_record], seen_trans_ids=set(), window_minutes=15)

    assert result["status"] == "missing_payment"
    assert result["severity"] == "critical"


def test_duplicate_transaction_is_flagged_without_double_alerting():
    event = make_event(trans_id="T-400", amount="100", phone="254700000003", trans_time="20240601120000")
    internal_record = make_internal_record(internal_ref="ORD-4", phone="254700000003", timestamp="2024-06-01T12:00:00Z")

    result = evaluate_transaction(event, [internal_record], seen_trans_ids={"T-400"})

    assert "duplicate_transaction_id" in result["anomalies"]
    assert result["duplicate"] is True



def test_ambiguous_equal_candidates_require_manual_review():
    event = make_event(trans_id="T-AMBIGUOUS", amount="100", phone="254700000000")
    records = [
        make_internal_record(internal_ref="ORD-A"),
        make_internal_record(internal_ref="ORD-B"),
    ]

    result = evaluate_transaction(event, records, seen_trans_ids=set())

    assert result["status"] == "needs_review"
    assert result["severity"] == "warning"
    assert result["match"]["match_type"] == "ambiguous"
    assert result["match"]["ambiguous"] is True
    assert result["match"]["candidate_count"] == 2
    assert result["match"]["review_reason"] == "multiple_candidates_with_similar_scores"
    assert set(result["match"]["candidate_internal_refs"]) == {"ORD-A", "ORD-B"}


def test_unique_candidate_remains_auto_match_compatible():
    event = make_event(trans_id="T-UNIQUE", amount="100", phone="254700000000")
    result = evaluate_transaction(
        event,
        [make_internal_record(internal_ref="ORD-UNIQUE")],
        seen_trans_ids=set(),
    )

    assert result["status"] == "matched"
    assert result["match"]["match_type"] == "exact"
    assert result["match"]["candidate_count"] == 1
    assert result["match"]["ambiguous"] is False



def test_amount_within_tolerance_is_reviewed_not_auto_matched():
    event = make_event(trans_id="T-TOLERANCE", amount="100.40", phone="254700000000")
    record = make_internal_record(internal_ref="ORD-TOLERANCE", amount=100.00)

    result = evaluate_transaction(event, [record], seen_trans_ids=set())

    assert result["status"] == "needs_review"
    assert result["match"]["match_type"] == "fuzzy_exact"


def test_missing_timestamp_evidence_requires_review():
    event = make_event(
        trans_id="T-NO-TIME",
        amount="100",
        phone="254700000000",
        trans_time="not-a-valid-time",
    )
    record = make_internal_record(
        internal_ref="ORD-NO-TIME",
        amount=100.00,
        timestamp=None,
    )

    result = evaluate_transaction(event, [record], seen_trans_ids=set())

    assert result["status"] == "needs_review"
    assert result["match"]["match_type"] == "fuzzy_exact"
