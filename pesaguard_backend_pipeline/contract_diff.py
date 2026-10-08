"""Detect breaking contract changes between a git base revision and the work tree.

This covers the *compatibility checking* and *breaking-change detection* stages
of the data-contract pipeline. It reuses the single source of compatibility
semantics already owned by ``schema_compatibility.py``:

* :func:`schema_compatibility.compare_schemas` for event and source JSON Schemas.
* :func:`schema_compatibility.compare_openapi` for the published HTTP contract.

Nothing here decides compatibility policy on its own -- it reports what the
existing comparators consider breaking and exits non-zero when any of it is.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from schema_compatibility import compare_openapi, compare_schemas

REGISTRY_FILENAME = "registry.json"

DEFAULT_SCHEMA_ROOTS: tuple[Path, ...] = (
    Path("pesaguard_backend_pipeline") / "schemas",
    Path("infra") / "redpanda" / "schemas",
)


class GitError(RuntimeError):
    """Raised when the comparison cannot be performed safely."""


@dataclass(frozen=True)
class ContractChange:
    """A single reported difference for one contract."""

    contract: str
    kind: str
    breaking: bool
    message: str

    def render(self) -> str:
        label = "BREAKING" if self.breaking else "SAFE"
        return f"{label} {self.kind}: {self.message} (contract: {self.contract})"


@dataclass
class DiffReport:
    """Outcome of comparing the work tree against ``base_ref``."""

    base_ref: str
    compared: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    changes: list[ContractChange] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def breaking(self) -> list[ContractChange]:
        return [change for change in self.changes if change.breaking]

    @property
    def ok(self) -> bool:
        return not self.breaking

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "passed" if self.ok else "failed",
            "base_ref": self.base_ref,
            "compared": self.compared,
            "added": self.added,
            "breaking": [asdict(change) for change in self.breaking],
            "changes": [asdict(change) for change in self.changes],
            "notes": self.notes,
        }


def _git(repo_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run a read-only git command and return the completed process."""
    return subprocess.run(
        ["git", *args],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )


def resolve_base_commit(repo_root: Path, base_ref: str) -> str:
    """Resolve ``base_ref`` to a commit hash, or raise :class:`GitError`."""
    try:
        completed = _git(repo_root, "rev-parse", "--verify", "--quiet", f"{base_ref}^{{commit}}")
    except OSError as exc:
        raise GitError(f"git is not available: {exc}") from exc
    if completed.returncode != 0 or not completed.stdout.strip():
        raise GitError(f"base revision {base_ref!r} is not a commit in {repo_root}")
    return completed.stdout.strip()


def _show_at_base(repo_root: Path, base_ref: str, relative: str) -> str | None:
    """Return file content at ``base_ref``, or None when the file is absent there."""
    completed = _git(repo_root, "show", f"{base_ref}:{relative}")
    if completed.returncode != 0:
        return None
    return completed.stdout


def _names_at_base(repo_root: Path, base_ref: str, relative_dir: str) -> list[str]:
    """List the file paths under ``relative_dir`` at ``base_ref``."""
    completed = _git(repo_root, "ls-tree", "-r", "--name-only", base_ref, "--", relative_dir)
    if completed.returncode != 0:
        raise GitError(f"cannot list {relative_dir!r} at {base_ref!r}: {completed.stderr.strip()}")
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def _diff_registry(
    *,
    repo_root: Path,
    base_ref: str,
    relative_dir: str,
    report: DiffReport,
) -> None:
    """Treat removal from ``registry.json`` as a breaking contract change."""
    relative = f"{relative_dir}/{REGISTRY_FILENAME}"
    old_text = _show_at_base(repo_root, base_ref, relative)
    if old_text is None:
        return
    current_path = repo_root / relative
    if not current_path.is_file():
        report.changes.append(ContractChange(relative, "registry_removed", True, f"removed {relative}"))
        return
    try:
        old_registry = json.loads(old_text)
        new_registry = json.loads(current_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GitError(f"cannot compare {relative}: {exc}") from exc
    if not isinstance(old_registry, Mapping) or not isinstance(new_registry, Mapping):
        raise GitError(f"cannot compare {relative}: registry must be a JSON object")

    old_listed = {name for name in old_registry.get("schemas", []) if isinstance(name, str)}
    new_listed = {name for name in new_registry.get("schemas", []) if isinstance(name, str)}
    for name in sorted(old_listed - new_listed):
        report.changes.append(
            ContractChange(relative, "contract_unregistered", True, f"schema {name!r} removed from registry")
        )
    for name in sorted(new_listed - old_listed):
        report.changes.append(
            ContractChange(relative, "contract_registered", False, f"schema {name!r} added to registry")
        )
    if old_registry.get("version") != new_registry.get("version"):
        report.notes.append(
            f"registry version changed: {old_registry.get('version')!r} -> {new_registry.get('version')!r}"
        )


def diff_schema_root(
    *,
    repo_root: Path,
    base_ref: str,
    root: Path,
    report: DiffReport,
) -> None:
    """Compare one schema directory against ``base_ref``."""
    relative_dir = root.as_posix()
    directory = root if root.is_absolute() else repo_root / root
    current_names = (
        {path.name for path in directory.glob("*.json") if path.name != REGISTRY_FILENAME}
        if directory.is_dir()
        else set()
    )
    base_names = {
        Path(name).name
        for name in _names_at_base(repo_root, base_ref, relative_dir)
        if name.endswith(".json") and Path(name).name != REGISTRY_FILENAME
    }

    for name in sorted(base_names - current_names):
        relative = f"{relative_dir}/{name}"
        report.changes.append(
            ContractChange(relative, "contract_removed", True, f"removed contract file {relative}")
        )

    for name in sorted(current_names - base_names):
        report.added.append(f"{relative_dir}/{name}")

    for name in sorted(current_names & base_names):
        relative = f"{relative_dir}/{name}"
        old_text = _show_at_base(repo_root, base_ref, relative)
        if old_text is None:
            report.added.append(relative)
            continue
        try:
            old_document = json.loads(old_text)
            new_document = json.loads((directory / name).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise GitError(f"cannot compare {relative}: {exc}") from exc
        if not isinstance(old_document, Mapping) or not isinstance(new_document, Mapping):
            raise GitError(f"cannot compare {relative}: contract must be a JSON object")
        report.compared.append(relative)
        for change in compare_schemas(old_document, new_document):
            report.changes.append(
                ContractChange(relative, change.kind, change.breaking, change.message)
            )


def diff_openapi(*, old_path: Path, new_path: Path, report: DiffReport) -> None:
    """Compare two OpenAPI documents using the shared comparator."""
    try:
        old_document = json.loads(old_path.read_text(encoding="utf-8"))
        new_document = json.loads(new_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GitError(f"cannot compare OpenAPI documents: {exc}") from exc
    if not isinstance(old_document, Mapping) or not isinstance(new_document, Mapping):
        raise GitError("cannot compare OpenAPI documents: both must be JSON objects")
    report.compared.append(f"{old_path} -> {new_path}")
    for change in compare_openapi(old_document, new_document):
        report.changes.append(ContractChange("openapi", change.kind, change.breaking, change.message))


def compare_against_base(
    *,
    repo_root: Path,
    base_ref: str,
    schema_roots: Sequence[Path] = DEFAULT_SCHEMA_ROOTS,
    old_openapi: Path | None = None,
    new_openapi: Path | None = None,
) -> DiffReport:
    """Build the full contract diff report for ``base_ref``."""
    commit = resolve_base_commit(repo_root, base_ref)
    report = DiffReport(base_ref=commit)
    for root in schema_roots:
        diff_schema_root(repo_root=repo_root, base_ref=commit, root=root, report=report)
        _diff_registry(
            repo_root=repo_root, base_ref=commit, relative_dir=root.as_posix(), report=report
        )
    if old_openapi is not None and new_openapi is not None:
        diff_openapi(old_path=old_openapi, new_path=new_openapi, report=report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail when a contract change breaks backward compatibility."
    )
    parser.add_argument("--base-ref", required=True, help="git revision to compare against")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--schema-root",
        dest="schema_roots",
        action="append",
        type=Path,
        default=None,
        help="schema root relative to --repo-root (repeatable; defaults to the two contract roots)",
    )
    parser.add_argument("--old-openapi", type=Path, default=None)
    parser.add_argument("--new-openapi", type=Path, default=None)
    parser.add_argument("--json-report", type=Path, default=None)
    args = parser.parse_args(argv)

    roots = tuple(args.schema_roots) if args.schema_roots else DEFAULT_SCHEMA_ROOTS
    try:
        report = compare_against_base(
            repo_root=args.repo_root,
            base_ref=args.base_ref,
            schema_roots=roots,
            old_openapi=args.old_openapi,
            new_openapi=args.new_openapi,
        )
    except GitError as exc:
        print(f"ERROR {exc}")
        return 2

    for change in report.changes:
        print(change.render())
    for note in report.notes:
        print(f"NOTE {note}")
    print(
        f"contract diff against {report.base_ref}: {len(report.compared)} compared, "
        f"{len(report.added)} added, {len(report.breaking)} breaking"
    )

    if args.json_report is not None:
        args.json_report.write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
