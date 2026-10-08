import json
import subprocess
from pathlib import Path

import pytest

from contract_diff import (
    GitError,
    compare_against_base,
    main,
    resolve_base_commit,
)

DRAFT = "https://json-schema.org/draft/2020-12/schema"
NAMESPACE = "https://pesaguard.example/schemas"
_GIT_CONFIG = (
    "-c",
    "user.name=PesaGuard Contract CI",
    "-c",
    "user.email=contracts@pesaguard.example",
)


def _git(repo: Path, *args: str) -> None:
    completed = subprocess.run(
        ["git", *_GIT_CONFIG, *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def _write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _contract(name: str, **overrides):
    document = {
        "$schema": DRAFT,
        "$id": f"{NAMESPACE}/{name}",
        "type": "object",
        "properties": {"id": {"type": "string"}},
    }
    document.update(overrides)
    return document


def _write_schema(repo: Path, name: str, **overrides) -> None:
    _write(repo / "schemas" / name, _contract(name, **overrides))


def _write_registry(repo: Path, names) -> None:
    _write(
        repo / "schemas" / "registry.json",
        {"name": "pesaguard", "version": "1.0.0", "schemas": list(names)},
    )


def _init_repo(tmp_path: Path, *, registry_names=("widget-1.0.json",)) -> Path:
    """Create a throwaway repository with a committed contract baseline."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "-c", "init.defaultBranch=main", "init")
    _write_schema(repo, "widget-1.0.json")
    _write_registry(repo, registry_names)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "base contracts")
    return repo


def _diff(repo: Path, base_ref: str, **kwargs):
    return compare_against_base(
        repo_root=repo,
        base_ref=base_ref,
        schema_roots=(Path("schemas"),),
        **kwargs,
    )


def test_additive_optional_field_is_not_breaking(tmp_path):
    repo = _init_repo(tmp_path)
    base = resolve_base_commit(repo, "HEAD")
    _write_schema(
        repo,
        "widget-1.0.json",
        properties={"id": {"type": "string"}, "metadata": {"type": "object"}},
    )

    report = _diff(repo, base)

    assert report.ok
    assert report.compared == ["schemas/widget-1.0.json"]
    assert any(change.kind == "added_optional" for change in report.changes)


def test_removed_field_is_breaking(tmp_path):
    repo = _init_repo(tmp_path)
    base = resolve_base_commit(repo, "HEAD")
    _write_schema(repo, "widget-1.0.json", properties={})

    report = _diff(repo, base)

    assert not report.ok
    assert [change.kind for change in report.breaking] == ["removed"]


def test_new_field_becoming_required_is_breaking(tmp_path):
    repo = _init_repo(tmp_path)
    base = resolve_base_commit(repo, "HEAD")
    _write_schema(repo, "widget-1.0.json", required=["id"])

    report = _diff(repo, base)

    assert not report.ok
    assert "field became required" in report.breaking[0].message


def test_new_contract_file_is_reported_as_added(tmp_path):
    repo = _init_repo(tmp_path, registry_names=("widget-1.0.json", "gadget-1.0.json"))
    base = resolve_base_commit(repo, "HEAD")
    _write_schema(repo, "gadget-1.0.json")
    _write_registry(repo, ["widget-1.0.json", "gadget-1.0.json"])

    report = _diff(repo, base)

    assert report.ok
    assert report.added == ["schemas/gadget-1.0.json"]


def test_removed_contract_file_is_breaking(tmp_path):
    repo = _init_repo(tmp_path)
    base = resolve_base_commit(repo, "HEAD")
    (repo / "schemas" / "widget-1.0.json").unlink()

    report = _diff(repo, base)

    assert [change.kind for change in report.breaking] == ["contract_removed"]


def test_unregistering_a_contract_is_breaking(tmp_path):
    repo = _init_repo(tmp_path)
    base = resolve_base_commit(repo, "HEAD")
    _write_registry(repo, [])

    report = _diff(repo, base)

    assert not report.ok
    kinds = {change.kind for change in report.breaking}
    assert kinds == {"contract_unregistered"}


def test_registry_version_change_is_reported_as_a_note(tmp_path):
    repo = _init_repo(tmp_path)
    base = resolve_base_commit(repo, "HEAD")
    _write(
        repo / "schemas" / "registry.json",
        {"name": "pesaguard", "version": "1.1.0", "schemas": ["widget-1.0.json"]},
    )

    report = _diff(repo, base)

    assert report.ok
    assert report.notes == ["registry version changed: '1.0.0' -> '1.1.0'"]


def test_openapi_removals_are_detected_through_the_shared_comparator(tmp_path):
    repo = _init_repo(tmp_path)
    base = resolve_base_commit(repo, "HEAD")
    old_openapi = tmp_path / "openapi-base.json"
    new_openapi = tmp_path / "openapi-head.json"
    _write(old_openapi, {"paths": {"/transactions": {"get": {"responses": {"200": {}}}}}})
    _write(new_openapi, {"paths": {}})

    report = _diff(repo, base, old_openapi=old_openapi, new_openapi=new_openapi)

    assert not report.ok
    assert [change.kind for change in report.breaking] == ["endpoint_removed"]


def test_unknown_base_revision_raises_and_never_reports_success(tmp_path):
    repo = _init_repo(tmp_path)

    with pytest.raises(GitError):
        resolve_base_commit(repo, "not-a-real-ref")


def test_main_returns_two_on_unusable_base_and_one_on_breaking_change(tmp_path, capsys):
    repo = _init_repo(tmp_path)

    assert main(["--repo-root", str(repo), "--base-ref", "not-a-real-ref"]) == 2
    assert "ERROR base revision" in capsys.readouterr().out

    base = resolve_base_commit(repo, "HEAD")
    _write_schema(repo, "widget-1.0.json", properties={})
    report_path = tmp_path / "diff-report.json"

    assert (
        main(
            [
                "--repo-root",
                str(repo),
                "--base-ref",
                base,
                "--schema-root",
                "schemas",
                "--json-report",
                str(report_path),
            ]
        )
        == 1
    )
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["status"] == "failed"
    assert payload["breaking"][0]["kind"] == "removed"


def test_main_returns_zero_for_a_compatible_change(tmp_path, capsys):
    repo = _init_repo(tmp_path)
    base = resolve_base_commit(repo, "HEAD")
    _write_schema(
        repo,
        "widget-1.0.json",
        properties={"id": {"type": "string"}, "note": {"type": "string"}},
    )

    exit_code = main(
        ["--repo-root", str(repo), "--base-ref", base, "--schema-root", "schemas"]
    )

    assert exit_code == 0
    assert "0 breaking" in capsys.readouterr().out
