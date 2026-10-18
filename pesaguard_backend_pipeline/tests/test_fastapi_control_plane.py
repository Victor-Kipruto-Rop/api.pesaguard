"""The ASGI control plane that production starts with uvicorn.

The dashboard Flask app is replaced by a stub so these tests exercise only the
wrapper (probes and the WSGI mount) and never load a second copy of the real
dashboard module, which registers Prometheus metrics at import time.
"""

import importlib
import sys
import types

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from flask import Flask  # noqa: E402

MODULE = "pesaguard_backend_pipeline.fastapi_app"
DASHBOARD = "pesaguard_backend_pipeline.api.dashboard_app"


@pytest.fixture()
def control_plane(monkeypatch):
    stub_flask = Flask("stub-dashboard")

    @stub_flask.route("/discrepancies")
    def discrepancies():
        return {"error": "unauthorized"}, 401

    stub = types.ModuleType(DASHBOARD)
    stub.create_app = lambda: stub_flask
    monkeypatch.setitem(sys.modules, DASHBOARD, stub)
    monkeypatch.delitem(sys.modules, MODULE, raising=False)

    module = importlib.import_module(MODULE)
    yield module
    sys.modules.pop(MODULE, None)


def _payload(status):
    return {"status": status, "service": "pesaguard", "checks": {}}


def test_livez_checks_no_dependencies(control_plane, monkeypatch):
    def boom():
        raise AssertionError("livez must not call build_health_payload")

    monkeypatch.setattr(control_plane, "build_health_payload", boom)
    response = TestClient(control_plane.app).get("/livez")
    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


@pytest.mark.parametrize("status, expected", [("ok", 200), ("degraded", 200), ("failed", 503)])
def test_health_status_code_follows_overall_status(control_plane, monkeypatch, status, expected):
    monkeypatch.setattr(control_plane, "build_health_payload", lambda: _payload(status))
    response = TestClient(control_plane.app).get("/health")
    assert response.status_code == expected
    assert response.json()["status"] == status


def test_flask_routes_are_still_mounted_behind_the_control_plane(control_plane):
    # Anything FastAPI does not own must reach Flask (401 from the stub), not FastAPI's 404.
    assert TestClient(control_plane.app).get("/discrepancies").status_code == 401


def test_root_returns_service_information(control_plane):
    response = TestClient(control_plane.app).get("/")
    assert response.status_code == 200
    assert response.json() == {
        "service": "PesaGuard API",
        "status": "ok",
        "message": "PesaGuard API is running. Use the documented API endpoints for requests.",
        "health": "/health",
        "liveness": "/livez",
    }
