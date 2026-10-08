"""Guard the private internal API contract and public-docs boundary."""

import json
from pathlib import Path

import yaml


TREE_ROOT = Path(__file__).resolve().parents[1]
INTERNAL_CONTRACT = TREE_ROOT / "docs" / "security" / "internal-api-v1.openapi.yaml"
PUBLIC_CONTRACT = TREE_ROOT / "docs" / "api" / "openapi.json"


def test_private_internal_contract_covers_all_core_service_routes():
    contract = yaml.safe_load(INTERNAL_CONTRACT.read_text(encoding="utf-8"))

    assert contract["openapi"] == "3.1.0"
    assert set(contract["paths"]) == {
        "/internal/v1/tenants/resolve",
        "/internal/v1/developer-api-keys/sync",
        "/internal/v1/keys/{key_id}/revoke",
        "/internal/v1/keys/{key_id}/suspend",
        "/internal/v1/service-jwt/jwks.json",
    }
    for path in (
        "/internal/v1/tenants/resolve",
        "/internal/v1/developer-api-keys/sync",
        "/internal/v1/keys/{key_id}/revoke",
        "/internal/v1/keys/{key_id}/suspend",
    ):
        operation = contract["paths"][path]["get" if path.endswith("/resolve") else "post"]
        assert operation["x-pesaguard-required-service-scope"].startswith("service:")
        assert operation["x-pesaguard-authentication-modes"]["HMAC_ONLY"] == "HmacSignature"
        assert operation["x-pesaguard-authentication-modes"]["DUAL_REQUIRED"] == (
            "ServiceJwt and HmacSignature"
        )
        assert operation["x-pesaguard-authentication-modes"]["JWT_PRIMARY"] == "ServiceJwt"

    assert contract["paths"]["/internal/v1/developer-api-keys/sync"]["post"][
        "parameters"
    ][-1]["$ref"] == "#/components/parameters/IdempotencyKey"
    assert contract["paths"]["/internal/v1/keys/{key_id}/revoke"]["post"][
        "parameters"
    ][-1]["$ref"] == "#/components/parameters/IdempotencyKey"
    assert contract["paths"]["/internal/v1/keys/{key_id}/suspend"]["post"][
        "parameters"
    ][-1]["$ref"] == "#/components/parameters/IdempotencyKey"


def test_private_routes_are_not_published_in_customer_openapi():
    public_contract = json.loads(PUBLIC_CONTRACT.read_text(encoding="utf-8"))

    assert not any(path.startswith("/internal/") for path in public_contract["paths"])
