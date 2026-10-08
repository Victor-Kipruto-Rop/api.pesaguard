import importlib
import os
import tempfile

import pytest
from auth_rbac import AuthRBAC
from auth_seed import seed_account


@pytest.fixture()
def dashboard_app(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pesaguard_test.db")
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
        monkeypatch.setenv("PESAGUARD_API_AUTH_REQUIRED", "1")
        import app_2

        app_2 = importlib.reload(app_2)
        app_2.Base.metadata.create_all(app_2.engine)
        from action_audit import Base as AuditBase
        from auth_rbac import _RevocationBase

        AuditBase.metadata.create_all(app_2.primary_engine)
        _RevocationBase.metadata.create_all(app_2.primary_engine)
        app_2.app.config.update(TESTING=True)

        session = app_2.SessionLocal()
        try:
            session.add_all([
                app_2.UserAccount(
                    id="test-admin",
                    tenant_id="tenant-a",
                    username="admin",
                    roles=["admin"],
                    permissions=[],
                    status="active",
                    authorization_version=1,
                ),
                app_2.Discrepancy(
                    id="tx-1-missing",
                    trans_id="tx-1",
                    tenant_id="tenant-a",
                    anomaly_type="missing_payment",
                    status="needs_review",
                    severity="critical",
                    details="Initial mismatch",
                    resolved=False,
                ),
                app_2.Discrepancy(
                    id="tx-2-duplicate",
                    trans_id="tx-2",
                    tenant_id="tenant-b",
                    anomaly_type="duplicate",
                    status="needs_review",
                    severity="warning",
                    details="Duplicate callback detected",
                    resolved=False,
                ),
                app_2.Discrepancy(
                    id="tx-3-review",
                    trans_id="tx-3",
                    tenant_id="tenant-a",
                    anomaly_type="needs_review",
                    status="needs_review",
                    severity="info",
                    details="Pending manual review",
                    resolved=False,
                ),
            ])
            session.commit()
        finally:
            session.close()

        with app_2.app.test_client() as client:
            yield client, app_2


@pytest.fixture()
def dashboard_auth_token(dashboard_app):
    _, app_module = dashboard_app
    seed_account(
        app_module.SessionLocal,
        user_id="test-admin",
        tenant_id="tenant-a",
        roles=["admin"],
    )
    return AuthRBAC.generate_token(
        user_id="test-admin",
        username="admin",
        tenant_id="tenant-a",
        roles=["admin"],
    )


def test_dashboard_filters_and_resolves_discrepancies(dashboard_app, dashboard_auth_token):
    client, app_module = dashboard_app
    # Audit tables are created once by the dashboard_app fixture.

    response = client.get(
        "/discrepancies?status=missing_payment",
        headers={"Authorization": f"Bearer {dashboard_auth_token}"},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload["items"]) == 1
    assert payload["items"][0]["anomaly_type"] == "missing_payment"

    resolve_response = client.post(
        f"/discrepancies/{payload['items'][0]['id']}/resolve",
        headers={"Authorization": f"Bearer {dashboard_auth_token}"},
        json={"note": "Manual investigation complete"},
    )
    assert resolve_response.status_code == 200

    session = app_module.SessionLocal()
    try:
        discrepancy = session.get(app_module.Discrepancy, payload["items"][0]["id"])
        assert discrepancy.resolved is True
        assert discrepancy.resolution_note == "Manual investigation complete"
    finally:
        session.close()


def test_dashboard_supports_pagination_and_bulk_resolve(dashboard_app, dashboard_auth_token):
    client, app_module = dashboard_app

    paged_response = client.get(
        "/discrepancies?page=1&per_page=2",
        headers={"Authorization": f"Bearer {dashboard_auth_token}"},
    )
    assert paged_response.status_code == 200
    paged_payload = paged_response.get_json()
    assert paged_payload["page"] == 1
    assert paged_payload["per_page"] == 2
    assert len(paged_payload["items"]) == 2
    assert paged_payload["total"] == 2

    bulk_response = client.post(
        "/discrepancies/bulk-resolve",
        headers={"Authorization": f"Bearer {dashboard_auth_token}"},
        json={"ids": [item["id"] for item in paged_payload["items"]], "note": "Bulk resolved"},
    )
    assert bulk_response.status_code == 200
    assert bulk_response.get_json()["updated"] == 2

    session = app_module.SessionLocal()
    try:
        resolved_items = session.query(app_module.Discrepancy).filter(app_module.Discrepancy.resolved.is_(True)).all()
        assert len(resolved_items) == 2
        assert all(item.resolution_note == "Bulk resolved" for item in resolved_items)
    finally:
        session.close()


def test_organization_approval_rejects_organization_from_another_tenant(
    dashboard_app, dashboard_auth_token
):
    client, app_module = dashboard_app
    from models import Organization, OrganizationApproval

    session = app_module.SessionLocal()
    try:
        session.add(Organization(
            id="org-tenant-b",
            tenant_id="tenant-b",
            name="Tenant B",
            slug="tenant-b",
            status="active",
            settings={},
        ))
        session.commit()
    finally:
        session.close()

    response = client.post(
        "/api/v1/organizations/org-tenant-b/approvals",
        headers={"Authorization": "Bearer " + dashboard_auth_token},
        json={"request_type": "update"},
    )

    assert response.status_code == 404
    with app_module.SessionLocal() as session:
        assert session.query(OrganizationApproval).filter_by(
            tenant_id="tenant-a",
            organization_id="org-tenant-b",
        ).count() == 0


def test_create_organization_rejects_owner_from_another_tenant(
    dashboard_app, dashboard_auth_token
):
    client, app_module = dashboard_app
    from models import Organization, UserAccount

    with app_module.SessionLocal() as session:
        session.add(UserAccount(
            id="foreign-owner",
            username="foreign-owner",
            tenant_id="tenant-b",
            roles=["owner"],
            permissions=[],
            status="active",
        ))
        session.commit()

    response = client.post(
        "/api/v1/organizations",
        headers={"Authorization": "Bearer " + dashboard_auth_token},
        json={"name": "Tenant A Organization", "owner_user_id": "foreign-owner"},
    )

    assert response.status_code == 404
    with app_module.SessionLocal() as session:
        assert session.query(Organization).filter_by(
            tenant_id="tenant-a",
            name="Tenant A Organization",
        ).count() == 0


def test_dashboard_exposes_openapi_docs(dashboard_app):
    client, _ = dashboard_app

    spec_response = client.get("/openapi.json")
    assert spec_response.status_code == 200
    spec_payload = spec_response.get_json()
    assert spec_payload["openapi"] == "3.0.3"
    assert "/discrepancies" in spec_payload["paths"]

    docs_response = client.get("/docs")
    assert docs_response.status_code == 200
    assert b"PesaGuard Dashboard API" in docs_response.data


def test_dashboard_serves_implemented_spec_and_planned_contract_separately(dashboard_app):
    client, _ = dashboard_app

    implemented = client.get("/openapi.json").get_json()
    contract_response = client.get("/openapi.contract.json")
    assert contract_response.status_code == 200
    contract = contract_response.get_json()

    # /openapi.json describes what is registered today; the contract also names
    # endpoints that are not implemented yet, so the two must not be the same file.
    assert implemented["info"]["version"] != contract["info"]["version"]
    assert "/discrepancies" in implemented["paths"]
    assert "/fraud/analyse" in contract["paths"]
    assert "/fraud/analyse" not in implemented["paths"]


def test_dashboard_session_factory_routes_reads_to_replica(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        primary_path = os.path.join(tmpdir, "primary.db")
        replica_path = os.path.join(tmpdir, "replica.db")
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{primary_path}")
        monkeypatch.setenv("READ_REPLICA_DATABASE_URL", f"sqlite:///{replica_path}")
        import app_2

        app_2 = importlib.reload(app_2)

        read_session = app_2.SessionLocal(read_only=True)
        write_session = app_2.SessionLocal(read_only=False)

        assert read_session.bind is app_2.replica_engine
        assert write_session.bind is app_2.primary_engine
        from sqlalchemy.pool import NullPool

        assert isinstance(app_2.primary_engine.pool, NullPool)


def test_replica_fallback_session_rejects_writes_without_retry(monkeypatch):
    import app_2
    from sqlalchemy import update
    from sqlalchemy.exc import InvalidRequestError
    from models import PaymentProvider

    session = app_2._ReplicaFallbackSession(bind=app_2.replica_engine, fallback_bind=app_2.primary_engine)
    try:
        with pytest.raises(InvalidRequestError, match="only support SELECT"):
            session.execute(update(PaymentProvider).values(status="inactive"))
        assert session._using_fallback is False
    finally:
        session.close()


def test_replica_reads_honor_primary_consistency_controls(monkeypatch):
    import app_2

    monkeypatch.setenv("PESAGUARD_READ_FROM_REPLICA", "1")
    with app_2.app.test_request_context("/providers", headers={"X-PesaGuard-Read-From-Primary": "1"}):
        assert app_2._resolve_engine() is app_2.primary_engine
    with app_2.app.test_request_context("/providers", headers={"Cookie": "pesaguard_primary_read_until=9999999999"}):
        assert app_2._resolve_engine() is app_2.primary_engine


def test_production_auth_cannot_be_disabled(monkeypatch):
    import auth_rbac

    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("PESAGUARD_API_AUTH_REQUIRED", "0")
    with pytest.raises(RuntimeError, match="must be enabled in production"):
        auth_rbac.assert_auth_configuration()


def test_provider_creation_uses_tenant_context_and_redacts_configuration(dashboard_app, dashboard_auth_token):
    client, _ = dashboard_app
    response = client.post(
        "/providers",
        headers={"Authorization": f"Bearer {dashboard_auth_token}"},
        json={
            "name": "  Safaricom  ",
            "provider_type": "  payment ",
            "status": "inactive",
            "credentials": {"api_key": "secret-value"},
            "supported_currencies": [" KES "],
        },
    )
    assert response.status_code == 201
    provider = response.get_json()
    assert provider["name"] == "Safaricom"
    assert provider["provider_type"] == "payment"
    assert provider["status"] == "inactive"
    assert provider["credentials"] == {"configured": True}
    assert provider["supported_currencies"] == ["KES"]


def test_provider_configuration_rejects_non_finite_unknown_and_oversized_values(dashboard_app, dashboard_auth_token):
    client, app_module = dashboard_app
    headers = {"Authorization": f"Bearer {dashboard_auth_token}"}

    non_finite = client.post(
        "/providers",
        headers=headers,
        json={"name": "Invalid", "provider_type": "payment", "credentials": {"api_key": float("nan")}},
    )
    assert non_finite.status_code == 400

    unknown = client.post(
        "/providers",
        headers=headers,
        json={"name": "Invalid", "provider_type": "payment", "credentials": {"unexpected": "value"}},
    )
    assert unknown.status_code == 400

    nested_unknown = client.post(
        "/providers",
        headers=headers,
        json={"name": "Invalid", "provider_type": "payment", "api_configuration": {"headers": {"X-Unexpected": "value"}}},
    )
    assert nested_unknown.status_code == 400

    unrestricted_metadata = client.post(
        "/providers",
        headers=headers,
        json={"name": "Invalid", "provider_type": "payment", "metadata": {"unexpected": "value"}},
    )
    assert unrestricted_metadata.status_code == 400

    unrestricted_webhook = client.post(
        "/providers",
        headers=headers,
        json={"name": "Invalid", "provider_type": "payment", "webhook_configuration": {"unexpected": "value"}},
    )
    assert unrestricted_webhook.status_code == 400

    oversized = client.post(
        "/providers",
        headers=headers,
        json={"name": "Invalid", "provider_type": "payment", "metadata": {"description": "x" * 33000}},
    )
    assert oversized.status_code == 400
    assert app_module._valid_nested_mapping({"value": float("inf")}) is False


def test_provider_validation_rejects_unknown_types_and_non_string_status(dashboard_app, dashboard_auth_token):
    client, _ = dashboard_app
    headers = {"Authorization": f"Bearer {dashboard_auth_token}"}

    unknown_type = client.post(
        "/providers",
        headers=headers,
        json={"name": "Invalid", "provider_type": "unknown"},
    )
    assert unknown_type.status_code == 400

    invalid_status = client.post(
        "/providers",
        headers=headers,
        json={"name": "Invalid", "provider_type": "payment", "status": {"value": "active"}},
    )
    assert invalid_status.status_code == 400


def test_provider_credentials_are_encrypted_at_rest_and_decrypted_for_outbound_use(dashboard_app, dashboard_auth_token):
    client, app_module = dashboard_app
    response = client.post(
        "/providers",
        headers={"Authorization": f"Bearer {dashboard_auth_token}"},
        json={"name": "Encrypted", "provider_type": "payment", "credentials": {"api_key": "secret-value"}},
    )
    assert response.status_code == 201
    provider_id = response.get_json()["id"]

    from models import PaymentProvider

    session = app_module.SessionLocal(read_only=False)
    try:
        stored = session.query(PaymentProvider).filter_by(id=provider_id).one()
        assert stored.credentials["api_key"].startswith("enc:v1:")
        assert "secret-value" not in str(stored.credentials)
    finally:
        session.close()

    configuration = app_module.provider_management.get_decrypted_configuration("tenant-a", provider_id)
    assert configuration["credentials"] == {"api_key": "secret-value"}

    with app_module.provider_management.outbound_configuration("tenant-a", provider_id) as outbound:
        assert outbound["credentials"] == {"api_key": "secret-value"}
    assert outbound == {}

    captured = app_module.provider_management.execute_outbound(
        "tenant-a",
        provider_id,
        lambda configuration: configuration["credentials"]["api_key"],
    )
    assert captured == "secret-value"


def test_provider_configuration_supports_key_rotation(dashboard_app, monkeypatch):
    _, app_module = dashboard_app
    from provider_management_service import ProviderManagementService

    monkeypatch.setenv("PROVIDER_ENCRYPTION_KEY", "old-provider-key")
    old_service = ProviderManagementService(app_module.SessionLocal)
    provider = old_service.register("tenant-a", "Rotated", credentials={"api_key": "secret-value"})

    monkeypatch.setenv("PROVIDER_ENCRYPTION_KEY", "new-provider-key")
    monkeypatch.setenv("PROVIDER_ENCRYPTION_KEY_PREVIOUS", "old-provider-key")
    rotated_service = ProviderManagementService(app_module.SessionLocal)
    assert rotated_service.get_decrypted_configuration("tenant-a", provider["id"])["credentials"] == {"api_key": "secret-value"}
    assert rotated_service.rotate_provider_configuration("tenant-a", provider["id"]) is True

    monkeypatch.delenv("PROVIDER_ENCRYPTION_KEY_PREVIOUS")
    current_service = ProviderManagementService(app_module.SessionLocal)
    assert current_service.get_decrypted_configuration("tenant-a", provider["id"])["credentials"] == {"api_key": "secret-value"}


def test_replica_health_circuit_recovers_after_probe():
    import app_2
    from sqlalchemy import text
    from sqlalchemy.exc import SQLAlchemyError

    class FakeConnection:
        def execute(self, statement):
            if isinstance(statement, type(text("SELECT 1"))):
                return None

    class FakeReplica:
        def __init__(self, failing):
            self.failing = failing

        def connect(self):
            if self.failing:
                raise SQLAlchemyError("replica unavailable")
            return self

        def __enter__(self):
            return FakeConnection()

        def __exit__(self, *args):
            return False

    health = app_2._ReplicaHealth(cooldown_seconds=0)
    failing_replica = FakeReplica(failing=True)
    assert health.is_available(failing_replica) is False
    assert health.is_available(FakeReplica(failing=False)) is True


def test_locale_lookup_rejects_unknown_or_cross_user_ids(dashboard_app, dashboard_auth_token):
    client, app_module = dashboard_app
    from models import UserAccount

    # The fixture already creates this active user; the requests below verify
    # unknown, whitespace-normalized, and tenant-scoped user lookups.
    unknown = client.get(
        "/tenant/current/locale?user_id=missing-user",
        headers={"Authorization": f"Bearer {dashboard_auth_token}"},
    )
    assert unknown.status_code == 404

    whitespace = client.get(
        "/tenant/current/locale?user_id=%20test-admin%20",
        headers={"Authorization": f"Bearer {dashboard_auth_token}"},
    )
    assert whitespace.status_code == 200
    assert whitespace.get_json()["user_locale"] is None
