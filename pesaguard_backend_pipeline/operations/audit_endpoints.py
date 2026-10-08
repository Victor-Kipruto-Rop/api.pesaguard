"""Extract route -> required-permission pairs from Core API route files.

Dev helper for the authorization audit: reads @app.route/@bp.route decorators
and the nearest @require_auth or @require_resource_access permission. Read-only;
prints findings.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    "api/dashboard_app.py",
    "app_3_features.py",
    "app_4_advanced_features.py",
    "export_routes.py",
    "tenant_org_routes.py",
    "tenant_settings.py",
    "communications/product_routes.py",
    "communications/operations_routes.py",
    "communications/routes.py",
]

# Blueprint url_prefix per file (app routes have none). export_bp is
# registered twice (bare /v1 and aliased /api/v1), so both are emitted.
PREFIXES = {
    "export_routes.py": ["/v1", "/api/v1"],
    "tenant_org_routes.py": ["/api/v1"],
    "tenant_settings.py": ["/api/v1/settings"],
    "communications/product_routes.py": ["/api/v1/communications"],
    "communications/operations_routes.py": ["/api/v1/communications"],
    "communications/routes.py": [""],
}

ROUTE_RE = re.compile(
    r'@(?:app|bp|blueprint|_idempotent_route)\.?(?:route)?\(\s*"([^"]+)"'
    r'(?:.*methods=\[([^\]]+)\])?'
    r'|@(?:blueprint|bp|app)\.(get|post|put|patch|delete)\("([^"]+)"'
)
PERM_RE = re.compile(
    r'@(?:require_auth|require_auth_fn)\(\s*(?:required_permission=)?"([A-Za-z0-9_:]+)"'
)
RESOURCE_PERM_RE = re.compile(
    r'@require_resource_access\(\s*"([A-Za-z0-9_:]+)"'
)
DEF_RE = re.compile(r"^\s*def ")


def _methods(match: re.Match) -> list[str]:
    verb = match.group(3)
    if verb:
        return [verb.upper()]
    methods = match.group(2) or '"GET"'
    return re.findall(r'"(\w+)"', methods)


def main() -> int:
    for rel in FILES:
        path = ROOT / rel
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            match = ROUTE_RE.search(line)
            if not match:
                continue
            route = match.group(1) or match.group(4)
            permission = None
            for offset in range(index + 1, min(index + 6, len(lines))):
                if DEF_RE.match(lines[offset]):
                    break
                perm = PERM_RE.search(lines[offset]) or RESOURCE_PERM_RE.search(
                    lines[offset]
                )
                if perm:
                    permission = perm.group(1)
                    break
            for method in _methods(match):
                key = rel.replace("\\", "/")
                for prefix in PREFIXES.get(key, [""]):
                    full = f"{prefix}{route}" if route.startswith("/") else f"{prefix}/{route}"
                    if permission:
                        print(f"{method} {full} -> {permission}")
                    else:
                        print(f"{method} {full} -> UNMAPPED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
