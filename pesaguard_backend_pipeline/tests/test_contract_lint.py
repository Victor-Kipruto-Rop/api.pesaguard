import json
from pathlib import Path

from contract_lint import DEFAULT_SCHEMA_ROOTS, lint_contracts, main

REPO_ROOT = Path(__file__).resolve().parents[2]
DRAFT = "https://json-schema.org/draft/2020-12/schema"
NAMESPACE = "https://pesaguard.example/schemas"


def _write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _contract(name: str, **overrides):
    document = {
        "$schema": DRAFT,
        "$id": f"{NAMESPACE}/{name}",
        "type": "object",
        "properties": {"id": {"type": "string"}},
    }
    document.update(overrides)
    return document


def _write_schema(directory: Path, name: str, **overrides) -> None:
    _write(directory / name, _contract(name, **overrides))


def _write_library(directory: Path, name: str, defs) -> None:
    _write(directory / name, {"$schema": DRAFT, "$id": f"{NAMESPACE}/{name}", "$defs": defs})


def _write_registry(directory: Path, names) -> None:
    _write(
        directory / "registry.json",
        {"name": "pesaguard", "version": "1.0.0", "schemas": list(names)},
    )


def _checks(report) -> set[str]:
    return {finding.check for finding in report.findings}


def test_repository_contracts_lint_clean():
    """The shipped contracts must stay lint-clean or the gate is meaningless."""
    report = lint_contracts(DEFAULT_SCHEMA_ROOTS, repo_root=REPO_ROOT)

    assert report.ok, [finding.render() for finding in report.findings]
    assert len(report.files_checked) >= 12


def test_defs_library_and_root_contract_shapes_are_both_accepted(tmp_path):
    directory = tmp_path / "schemas"
    _write_library(directory, "library-1.0.json", {"Id": {"type": "string"}})
    _write_schema(directory, "thing-1.0.json")

    report = lint_contracts((Path("schemas"),), repo_root=tmp_path)

    assert report.ok, [finding.render() for finding in report.findings]


def test_unlisted_and_missing_registry_entries_are_both_reported(tmp_path):
    directory = tmp_path / "schemas"
    _write_schema(directory, "listed-1.0.json")
    _write_schema(directory, "extra-1.0.json")
    _write_registry(directory, ["listed-1.0.json", "missing-1.0.json"])

    report = lint_contracts((Path("schemas"),), repo_root=tmp_path)

    assert _checks(report) == {"registry_missing_file", "registry_unlisted_file"}


def test_duplicate_schema_id_is_reported(tmp_path):
    directory = tmp_path / "schemas"
    _write_schema(directory, "first-1.0.json")
    # Identical $id published from a second file is unaddressable.
    _write(directory / "second-1.0.json", _contract("first-1.0.json"))

    report = lint_contracts((Path("schemas"),), repo_root=tmp_path)

    assert _checks(report) == {"schema_id"}
    assert "already used by" in report.findings[0].message


def test_wrong_draft_and_missing_id_are_reported(tmp_path):
    directory = tmp_path / "schemas"
    _write(
        directory / "legacy-1.0.json",
        {"$schema": "http://json-schema.org/draft-07/schema#", "type": "object"},
    )

    report = lint_contracts((Path("schemas"),), repo_root=tmp_path)

    assert _checks(report) == {"schema_draft", "schema_id"}


def test_schema_without_root_shape_or_defs_is_reported(tmp_path):
    directory = tmp_path / "schemas"
    _write(directory / "empty-1.0.json", {"$schema": DRAFT, "$id": f"{NAMESPACE}/empty-1.0.json"})

    report = lint_contracts((Path("schemas"),), repo_root=tmp_path)

    assert _checks(report) == {"contract_shape"}


def test_empty_defs_section_is_reported(tmp_path):
    directory = tmp_path / "schemas"
    _write_library(directory, "emptyd-1.0.json", {})

    report = lint_contracts((Path("schemas"),), repo_root=tmp_path)

    assert _checks(report) == {"contract_shape"}


def test_unresolvable_and_missing_ref_targets_are_reported(tmp_path):
    directory = tmp_path / "schemas"
    _write_library(directory, "common-1.0.json", {"Identifier": {"type": "string"}})
    _write_schema(
        directory,
        "broken-1.0.json",
        properties={"id": {"$ref": "common-1.0.json#/$defs/Nope"}},
    )
    _write_schema(
        directory,
        "detached-1.0.json",
        properties={"id": {"$ref": "gone-1.0.json#/$defs/Identifier"}},
    )

    report = lint_contracts((Path("schemas"),), repo_root=tmp_path)

    assert {"ref_unresolvable", "ref_missing_target"} <= _checks(report)


def test_in_document_ref_must_resolve(tmp_path):
    directory = tmp_path / "schemas"
    _write_schema(
        directory,
        "selfref-1.0.json",
        properties={"id": {"$ref": "#/$defs/Missing"}},
        **{"$defs": {"Present": {"type": "string"}}},
    )

    report = lint_contracts((Path("schemas"),), repo_root=tmp_path)

    assert _checks(report) == {"ref_unresolvable"}


def test_invalid_json_and_missing_root_are_reported(tmp_path):
    directory = tmp_path / "schemas"
    directory.mkdir(parents=True)
    (directory / "broken-1.0.json").write_text("{not json", encoding="utf-8")

    report = lint_contracts((Path("schemas"), Path("absent")), repo_root=tmp_path)

    assert _checks(report) == {"json_syntax", "root_missing"}


def test_main_writes_a_json_report_and_signals_success(tmp_path, capsys):
    _write_schema(tmp_path / "schemas", "thing-1.0.json")
    report_path = tmp_path / "lint-report.json"

    exit_code = main(
        [
            "--repo-root",
            str(tmp_path),
            "--schema-root",
            "schemas",
            "--json-report",
            str(report_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["status"] == "passed"
    assert payload["findings"] == []
    assert "contract lint: 1 file(s) checked, 0 problem(s)" in capsys.readouterr().out


def test_main_returns_one_when_a_finding_exists(tmp_path):
    _write(tmp_path / "schemas" / "thing-1.0.json", {"type": "object"})

    exit_code = main(["--repo-root", str(tmp_path), "--schema-root", "schemas"])

    assert exit_code == 1
