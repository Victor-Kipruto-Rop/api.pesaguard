"""Regenerate ENDPOINT_PERMISSIONS in authorization_policy.py from the audit.

Reads routes_audit.txt (produced by audit_endpoints.py), validates every route
against its explicit permission or exemption, then rewrites the permission
block. Run from the repo root.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROUTES = ROOT / "routes_audit.txt"
POLICY = ROOT / "pesaguard_backend_pipeline" / "authorization_policy.py"

sys.path.insert(0, str(POLICY.parent))
from authorization_policy import (  # noqa: E402
    ROUTE_AUDIT_UNMAPPED_WITH_RUNTIME_PERMISSION,
    validate_route_audit_records,
)


def main() -> int:
    entries: dict[str, str] = {}
    conflicts: list[str] = []
    # PowerShell redirection may write UTF-16; fall back automatically.
    try:
        route_text = ROUTES.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        route_text = ROUTES.read_text(encoding="utf-16")
    try:
        counts = validate_route_audit_records(route_text.splitlines())
    except ValueError as exc:
        print(f"INVALID ROUTE AUDIT: {exc}")
        return 1

    for raw in route_text.splitlines():
        line = raw.strip()
        if not line or "->" not in line:
            continue
        target, permission = (part.strip() for part in line.rsplit("->", 1))
        if permission == "UNMAPPED":
            continue
        existing = entries.get(target)
        if existing and existing != permission:
            conflicts.append(f"{target}: {existing} vs {permission}")
            continue
        entries[target] = permission
    entries.update(ROUTE_AUDIT_UNMAPPED_WITH_RUNTIME_PERMISSION)
    if conflicts:
        print("CONFLICTS (fix manually):")
        for conflict in conflicts:
            print("  " + conflict)
        return 1
    print(
        f"routes={counts['routes']} mapped={counts['mapped']} "
        f"exempt={counts['exempt']}"
    )

    lines = ["ENDPOINT_PERMISSIONS: Dict[str, str] = {"]
    for key in sorted(entries):
        lines.append(f'    "{key}": "{entries[key]}",')
    lines.append("}")
    block = "\n".join(lines)

    source = POLICY.read_text(encoding="utf-8")
    pattern = re.compile(
        r"ENDPOINT_PERMISSIONS: Dict\[str, str\] = \{.*?\n\}", re.DOTALL)
    if not pattern.search(source):
        print("ERROR: ENDPOINT_PERMISSIONS block not found")
        return 1
    updated = pattern.sub(block, source, count=1)
    POLICY.write_text(updated, encoding="utf-8")
    print(f"wrote {POLICY}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
