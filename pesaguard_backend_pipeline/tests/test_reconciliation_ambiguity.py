from reconciliation_engine import ReconciliationEngine


ENGINE = ReconciliationEngine(window_seconds=900)


def event(reference="unknown-order", amount="100.00", timestamp="20261014120000"):
    return {
        "TransID": "MPESA-123", "TransAmount": amount,
        "BillRefNumber": reference, "MSISDN": "254700000001",
        "TransTime": timestamp,
    }


def record(reference, *, amount="100.00", timestamp="2026-10-14T12:00:00Z", phone="254700000001"):
    return {
        "internal_ref": reference, "reference": reference, "amount": amount,
        "timestamp": timestamp, "phone_number": phone, "status": "pending",
    }


def test_equal_scoring_tolerant_candidates_do_not_pick_first_row():
    result = ENGINE.reconcile(
        event(),
        [record("order-a"), record("order-b")],
    )
    assert result["status"] == "EXCEPTION"
    assert result["evidence"]["matched_record"] is None
    assert "ambiguous_candidates_requires_review" in result["evidence"]["matching_rules"]
    assert "insufficient score separation" in result["reason"]


def test_clear_candidate_score_winner_remains_review_candidate_not_auto_posting():
    result = ENGINE.reconcile(
        event(),
        [
            record("other-order", timestamp="2026-10-14T10:00:00Z"),
            record("another-order", phone="254700000001", timestamp="2026-10-14T12:00:02Z"),
        ],
    )
    # Candidate selection is diagnostic only; no ledger posting or balance mutation.
    assert result["status"] == "PARTIAL"
    assert result["evidence"]["matched_record"]["internal_ref"] == "another-order"


def test_equal_scoring_amount_mismatch_candidates_are_not_arbitrarily_selected():
    result = ENGINE.reconcile(
        event(amount="100.40"),
        [
            record("order-a", amount="100.00", timestamp="2026-10-14T11:00:00Z"),
            record("order-b", amount="100.00", timestamp="2026-10-14T11:00:00Z"),
        ],
    )
    assert result["status"] == "EXCEPTION"
    assert result["evidence"]["matched_record"] is None
    assert "ambiguous_candidates_requires_review" in result["evidence"]["matching_rules"]
