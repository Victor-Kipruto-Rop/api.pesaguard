import json
import re
from pathlib import Path

from api.dashboard_app import app
from app_4_advanced_features import app as auth_app


def test_authoritative_openapi_contract_covers_required_domains():
    spec = json.loads((Path(__file__).parents[2] / "docs" / "api" / "openapi.json").read_text(encoding="utf-8"))

    assert spec["openapi"] == "3.0.3"
    assert spec["info"]["version"] == "1.0.0"
    for path in (
        "/transactions",
        "/transactions/{transaction_id}",
        "/transactions/search",
        "/reconciliation/requests",
        "/reconciliation/{transaction_id}",
        "/fraud/analyse",
        "/fraud/{transaction_id}",
        "/auth/login",
        "/auth/refresh",
    ):
        assert path in spec["paths"]
    assert "IdempotencyKey" in spec["components"]["parameters"]
    assert "Retry-After" in spec["components"]["responses"]["RateLimited"]["headers"]
    assert "Error" in spec["components"]["schemas"]


def test_authoritative_contract_operations_match_registered_routes():
    spec = json.loads((Path(__file__).parents[2] / "docs" / "api" / "openapi.json").read_text(encoding="utf-8"))
    dashboard_routes = {
        (rule.rule, method.lower()): app.view_functions[rule.endpoint]
        for rule in app.url_map.iter_rules()
        for method in rule.methods
        if method not in {"HEAD", "OPTIONS"}
    }
    auth_routes = {
        (rule.rule, method.lower()): auth_app.view_functions[rule.endpoint]
        for rule in auth_app.url_map.iter_rules()
        for method in rule.methods
        if method not in {"HEAD", "OPTIONS"}
    }

    for path, path_item in spec["paths"].items():
        is_auth_route = path.startswith("/auth/")
        route_path = re.sub(
            r"\{([^}]+)\}",
            r"<\1>",
            path if is_auth_route else f"/api/v1{path}",
        )
        registered_routes = auth_routes if is_auth_route else dashboard_routes
        for method, operation in path_item.items():
            if method in {"get", "post", "put", "patch", "delete"}:
                route_key = (route_path, method)
                assert route_key in registered_routes, f"Unregistered OpenAPI operation: {method.upper()} {route_path}"
                if is_auth_route:
                    assert operation["security"] == []
                    continue

                view = registered_routes[route_key]
                assert operation["x-required-permission"] == getattr(
                    view, "required_permission", None
                ), f"Permission contract mismatch: {method.upper()} {route_path}"
                assert operation["security"] == [
                    {"bearerAuth": []},
                    {"apiKeyAuth": []},
                ]
                assert {
                    parameter.get("$ref")
                    for parameter in operation.get("parameters", [])
                } >= {"#/components/parameters/TenantHeader"}
                if method == "post":
                    assert "#/components/parameters/IdempotencyKey" in {
                        parameter.get("$ref")
                        for parameter in operation["parameters"]
                    }


def test_dashboard_http_errors_include_contract_request_id():
    app.config["TESTING"] = True

    response = app.test_client().get("/route-that-does-not-exist")

    assert response.status_code == 404
    payload = response.get_json()
    assert payload["request_id"] == response.headers["X-Request-ID"]


def test_runtime_contract_uses_root_server_for_legacy_dashboard_routes(monkeypatch):
    monkeypatch.setenv("PESAGUARD_PUBLIC_API_DOCS", "1")
    response = app.test_client().get("/openapi.json")

    assert response.status_code == 200
    spec = response.get_json()
    assert spec["paths"]["/providers"]["servers"] == [{"url": "/"}]
    assert spec["servers"] == [{"url": "/api/v1"}]


def test_root_server_contract_operations_match_registered_dashboard_routes(monkeypatch):
    monkeypatch.setenv("PESAGUARD_PUBLIC_API_DOCS", "1")
    spec = app.test_client().get("/openapi.json").get_json()
    registered = {
        (rule.rule, method.lower())
        for rule in app.url_map.iter_rules()
        for method in rule.methods
        if method not in {"HEAD", "OPTIONS"}
    }

    dashboard_operations = (
        (re.sub(r"\{([^}]+)\}", r"<\1>", path), method)
        for path, path_item in spec["paths"].items()
        if path_item.get("servers") == [{"url": "/"}]
        for method in path_item
        if method in {"get", "post", "put", "patch", "delete"}
    )

    assert all(operation in registered for operation in dashboard_operations)