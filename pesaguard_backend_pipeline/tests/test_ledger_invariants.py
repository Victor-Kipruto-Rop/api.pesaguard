from decimal import Decimal

import pytest

from pesaguard_backend_pipeline.ledger_invariants import (
    ALGORITHM_VERSION,
    validate_journal_batch,
)


def balanced():
    return [
        {"entry_id": "e1", "journal_id": "j1", "account_id": "cash", "currency": "KES", "side": "DEBIT", "amount": "100.00"},
        {"entry_id": "e2", "journal_id": "j1", "account_id": "receivable", "currency": "KES", "side": "CREDIT", "amount": "100.00"},
    ]


def test_balanced_journal_is_eligible_for_caller_posting_gate():
    result = validate_journal_batch(balanced())
    assert result["algorithm_version"] == ALGORITHM_VERSION
    assert result["can_post"] is True
    assert result["journals"][0]["difference"] == "0.00"


def test_unbalanced_journal_fails_closed():
    lines = balanced()
    lines[1]["amount"] = "99.99"
    result = validate_journal_batch(lines)
    assert result["can_post"] is False
    assert "UNBALANCED_JOURNAL" in {finding["code"] for finding in result["findings"]}


@pytest.mark.parametrize("amount", ["NaN", "Infinity", "-1", "0", True, None, "1.001"])
def test_invalid_or_unrepresentable_amount_blocks_posting(amount):
    lines = balanced()
    lines[0]["amount"] = amount
    result = validate_journal_batch(lines)
    assert result["can_post"] is False


def test_currency_totals_are_never_netted_across_currencies():
    lines = [
        {"entry_id": "e1", "journal_id": "j1", "account_id": "cash", "currency": "KES", "side": "DEBIT", "amount": "100.00"},
        {"entry_id": "e2", "journal_id": "j1", "account_id": "receivable", "currency": "USD", "side": "CREDIT", "amount": "100.00"},
    ]
    result = validate_journal_batch(lines)
    assert result["can_post"] is False
    assert "UNBALANCED_JOURNAL" in {finding["code"] for finding in result["findings"]}


def test_duplicate_entry_identity_blocks_posting():
    lines = balanced()
    lines[1]["entry_id"] = "e1"
    result = validate_journal_batch(lines)
    assert result["can_post"] is False
    assert "DUPLICATE_ENTRY_ID" in {finding["code"] for finding in result["findings"]}


def test_missing_side_blocks_posting_even_if_totals_would_match():
    lines = balanced()
    lines[1]["side"] = "UNKNOWN"
    result = validate_journal_batch(lines)
    assert result["can_post"] is False
    assert "INVALID_SIDE" in {finding["code"] for finding in result["findings"]}


def test_unknown_currency_requires_explicit_precision():
    lines = [
        {"entry_id": "e1", "journal_id": "j1", "account_id": "cash", "currency": "XYZ", "side": "DEBIT", "amount": "10.00"},
        {"entry_id": "e2", "journal_id": "j1", "account_id": "receivable", "currency": "XYZ", "side": "CREDIT", "amount": "10.00"},
    ]
    assert validate_journal_batch(lines)["can_post"] is False
    result = validate_journal_batch(lines, currency_exponents={"XYZ": 2})
    assert result["can_post"] is True


def test_empty_batch_is_not_postable():
    result = validate_journal_batch([])
    assert result["can_post"] is False
    assert result["findings"][0]["code"] == "EMPTY_BATCH"


def test_invalid_precision_configuration_is_rejected():
    with pytest.raises(ValueError):
        validate_journal_batch(balanced(), currency_exponents={"KES": -1})


def test_journals_are_balanced_independently():
    lines = balanced() + [
        {"entry_id": "e3", "journal_id": "j2", "account_id": "cash", "currency": "KES", "side": "DEBIT", "amount": "10.00"},
        {"entry_id": "e4", "journal_id": "j2", "account_id": "receivable", "currency": "KES", "side": "CREDIT", "amount": "9.00"},
    ]
    result = validate_journal_batch(lines)
    assert result["can_post"] is False
    assert {journal["journal_id"]: journal["balanced"] for journal in result["journals"]} == {"j1": True, "j2": False}
