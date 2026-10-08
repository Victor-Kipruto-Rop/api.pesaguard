import pytest

from export_routes import sanitize_csv_cell


@pytest.mark.parametrize("value", ["=1+1", "+SUM(A1:A2)", "-1+2", "@SUM(A1:A2)", " \t=1+1"])
def test_sanitize_csv_cell_prefixes_spreadsheet_formulas(value):
    assert sanitize_csv_cell(value) == f"'{value}"


@pytest.mark.parametrize("value, expected", [(None, ""), ("ordinary text", "ordinary text"), ("  ordinary text", "  ordinary text")])
def test_sanitize_csv_cell_preserves_non_formula_values(value, expected):
    assert sanitize_csv_cell(value) == expected
