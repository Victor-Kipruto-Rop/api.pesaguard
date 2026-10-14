"""Regression tests for evidence semantics in reconciliation scoring."""

from reconciliation_scoring import score_match


def test_daraja_compact_timestamp_is_interpreted_as_nairobi_local_time():
    event = {
        "BillRefNumber": "INV-UTC-1",
        "TransID": "MPESA-1",
        "TransAmount": "100.00",
        "TransTime": "20240601120000",
        "MSISDN": "254700000000",
    }
    ledger = {
        "reference": "INV-UTC-1",
        "amount": "100.00",
        "timestamp": "2024-06-01T09:00:00Z",
        "phone_number": "254700000000",
    }

    score, evidence = score_match(event, ledger)

    assert evidence["time_delta_seconds"] == 0
    assert evidence["components"]["ref_exact"] == 1.0
    assert score == 1.0


def test_scoring_never_uses_provider_or_internal_ids_as_reference_evidence():
    event = {
        "TransID": "MPESA-ONLY-ID",
        "TransAmount": "100.00",
        "TransTime": "20240601120000",
        "MSISDN": "254700000000",
    }
    ledger = {
        "internal_ref": "MPESA-ONLY-ID",
        "amount": "100.00",
        "timestamp": "2024-06-01T09:00:00Z",
        "phone_number": "254700000000",
    }

    _, evidence = score_match(event, ledger)

    assert evidence["components"]["ref_exact"] == 0.0
    assert evidence["components"]["ref_similarity"] == 0.0
