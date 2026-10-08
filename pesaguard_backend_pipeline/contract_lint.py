"""Lint the versioned JSON Schema contracts shipped with PesaGuard.

This is the *schema linting* stage of the data-contract pipeline. It answers one
question only: is every contract file well-formed, addressable, and registered?

It deliberately does **not** validate payloads against a contract (see
``schema_validation.py`` / ``source_contracts.py``) and does not compare
revisions (see ``schema_compatibility.py``). Keeping linting free of payload
data means it can run on every pull request without a database, Redis, or Kafka.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
REGISTRY_FILENAME = "registry.json"

DEFAULT_SCHEMA_ROOTS: tuple[Path, ...] = (
    Path("pesaguard_backend_pipeline") / "schemas",
    Path("pesaguard_backend_pipeline") / "infra" / "redpanda" / "schemas",
)


@dataclass(frozen=True)
class LintFinding:
    """One lint failure, addressed to the file that caused it."""

    path: str
    check: str
    message: str

    def render(self) -> str:
        return f"ERROR [{self.check}] {self.path}: {self.message}"


@dataclass
class LintReport:
    """Outcome of linting one or more contract roots."""

    files_checked: list[str] = field(default_factory=list)
    findings: list[LintFinding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "passed" if self.ok else "failed",
            "files_checked": self.files_checked,
            "findings": [asdict(finding) for finding in self.findings],
        }


def _load_json(path: Path, relative: str, findings: list[LintFinding]) -> Mapping[str, Any] | None:
    """Parse ``path`` as a JSON object, recording a finding when it cannot be."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        findings.append(LintFinding(relative, "json_syntax", f"cannot read file: {exc}"))
        return None
    except json.JSONDecodeError as exc:
        findings.append(LintFinding(relative, "json_syntax", f"cannot parse JSON: {exc}"))
        return None
    if not isinstance(document, Mapping):
        findings.append(LintFinding(relative, "json_syntax", "top-level value must be a JSON object"))
        return None
    return document


def _resolve_pointer(document: Any, pointer: str) -> bool:
    """Return True when a JSON Pointer fragment resolves inside ``document``."""
    if pointer in ("", "/"):
        return True
    current = document
    for raw_token in pointer.lstrip("/").split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return False
    return True


def _iter_refs(node: Any) -> Iterable[str]:
    """Yield every ``$ref`` string found anywhere inside ``node``."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from _iter_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_refs(item)


def _check_refs(
    *,
    document: Mapping[str, Any],
    relative: str,
    directory: Path,
    findings: list[LintFinding],
) -> None:
    """Ensure every non-remote ``$ref`` resolves to a real file and pointer."""
    siblings = {path.name for path in directory.glob("*.json")}
    for ref in _iter_refs(document):
        if "://" in ref or ref.startswith("urn:"):
            # Remote registry references cannot be resolved offline.
            continue
        target_file, _, pointer = ref.partition("#")
        if not target_file:
            if pointer and not _resolve_pointer(document, pointer):
                findings.append(
                    LintFinding(relative, "ref_unresolvable", f"in-document $ref {ref!r} does not resolve")
                )
            continue
        if target_file not in siblings:
            findings.append(
                LintFinding(
                    relative,
                    "ref_missing_target",
                    f"$ref {ref!r} targets missing schema file {target_file!r}",
                )
            )
            continue
        try:
            target_document = json.loads((directory / target_file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(
                LintFinding(relative, "ref_missing_target", f"$ref {ref!r} target cannot be read: {exc}")
            )
            continue
        if pointer and not _resolve_pointer(target_document, pointer):
            findings.append(
                LintFinding(relative, "ref_unresolvable", f"$ref {ref!r} pointer does not resolve")
            )


def _check_contract_shape(
    document: Mapping[str, Any],
    *,
    relative: str,
    findings: list[LintFinding],
) -> None:
    """Require a contract to be usable: either a root shape or a ``$defs`` library.

    This repository uses two legitimate conventions:

    * a root contract document that declares ``type`` (plus ``properties``,
      ``anyOf``, or ``allOf``);
    * a ``$defs``-only library document whose definitions are referenced by
      other contracts (for example ``common-1.0.json``).
    """
    defs = document.get("$defs")
    if defs is not None:
        if not isinstance(defs, Mapping) or not defs:
            findings.append(
                LintFinding(relative, "contract_shape", "'$defs' must be a non-empty object")
            )
        return
    if document.get("type") is None:
        findings.append(
            LintFinding(
                relative,
                "contract_shape",
                'contract must declare a root "type" or a non-empty "$defs" section',
            )
        )


def _lint_document(
    document: Mapping[str, Any],
    *,
    relative: str,
    directory: Path,
    findings: list[LintFinding],
    seen_ids: dict[str, str],
) -> None:
    """Apply every per-file hygiene rule to a single contract document."""
    if document.get("$schema") != DRAFT_2020_12:
        findings.append(
            LintFinding(
                relative,
                "schema_draft",
                f"$schema must be {DRAFT_2020_12!r}, found {document.get('$schema')!r}",
            )
        )

    try:
        Draft202012Validator.check_schema(document)
    except SchemaError as exc:
        findings.append(LintFinding(relative, "schema_valid", f"invalid JSON Schema: {exc.message}"))

    schema_id = document.get("$id")
    if not isinstance(schema_id, str) or not schema_id.strip():
        findings.append(
            LintFinding(relative, "schema_id", "$id is required so consumers can address the contract")
        )
    else:
        owner = seen_ids.get(schema_id)
        if owner is not None:
            findings.append(
                LintFinding(relative, "schema_id", f"$id {schema_id!r} is already used by {owner}")
            )
        else:
            seen_ids[schema_id] = relative

    _check_contract_shape(document, relative=relative, findings=findings)

    _check_refs(document=document, relative=relative, directory=directory, findings=findings)


def _check_registry(
    *,
    directory: Path,
    relative_dir: str,
    documents: Mapping[str, Mapping[str, Any]],
    findings: list[LintFinding],
) -> None:
    """Keep ``registry.json`` and the schema directory from drifting apart."""
    registry_path = directory / REGISTRY_FILENAME
    if not registry_path.is_file():
        return
    registry_relative = f"{relative_dir}/{REGISTRY_FILENAME}"
    registry = _load_json(registry_path, registry_relative, findings)
    if registry is None:
        return
    declared = registry.get("schemas")
    if not isinstance(declared, list) or not all(isinstance(item, str) for item in declared):
        findings.append(
            LintFinding(registry_relative, "registry_format", "'schemas' must be a list of file names")
        )
        return
    for name in declared:
        if name not in documents:
            findings.append(
                LintFinding(
                    registry_relative,
                    "registry_missing_file",
                    f"listed schema {name!r} is not present in {relative_dir}",
                )
            )
    for name in sorted(set(documents) - set(declared)):
        findings.append(
            LintFinding(
                registry_relative,
                "registry_unlisted_file",
                f"schema {name!r} exists but is not listed in {REGISTRY_FILENAME}",
            )
        )


def lint_contracts(
    roots: Sequence[Path] = DEFAULT_SCHEMA_ROOTS,
    *,
    repo_root: Path | None = None,
) -> LintReport:
    """Lint every contract under ``roots`` and return the collected findings."""
    base = Path(repo_root) if repo_root is not None else Path.cwd()
    report = LintReport()
    seen_ids: dict[str, str] = {}

    for root in roots:
        directory = root if root.is_absolute() else base / root
        relative_dir = root.as_posix()
        if not directory.is_dir():
            report.findings.append(
                LintFinding(relative_dir, "root_missing", "schema root directory does not exist")
            )
            continue

        documents: dict[str, Mapping[str, Any]] = {}
        for path in sorted(directory.glob("*.json")):
            if path.name == REGISTRY_FILENAME:
                continue
            relative = f"{relative_dir}/{path.name}"
            document = _load_json(path, relative, report.findings)
            if document is None:
                continue
            documents[path.name] = document
            report.files_checked.append(relative)
            _lint_document(
                document,
                relative=relative,
                directory=directory,
                findings=report.findings,
                seen_ids=seen_ids,
            )

        _check_registry(
            directory=directory,
            relative_dir=relative_dir,
            documents=documents,
            findings=report.findings,
        )

    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lint PesaGuard JSON Schema contracts.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--schema-root",
        dest="schema_roots",
        action="append",
        type=Path,
        default=None,
        help="schema root relative to --repo-root (repeatable; defaults to the two contract roots)",
    )
    parser.add_argument("--json-report", type=Path, default=None)
    args = parser.parse_args(argv)

    roots = tuple(args.schema_roots) if args.schema_roots else DEFAULT_SCHEMA_ROOTS
    report = lint_contracts(roots, repo_root=args.repo_root)

    for finding in report.findings:
        print(finding.render())
    print(
        f"contract lint: {len(report.files_checked)} file(s) checked, "
        f"{len(report.findings)} problem(s)"
    )

    if args.json_report is not None:
        args.json_report.write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
