import pytest
import jwt

from test_config import configure_test_database

configure_test_database()

import app_4_advanced_features as advanced_features
from app_4_advanced_features import SessionLocal, app
from auth_rbac import ACCESS_TOKEN_TTL_MINUTES, AuthRBAC
from data_protection import decrypt_value
from models import (
    ApiClientIdentity,
    ExternalIdentity,
    IAMRole,
    IAMRoleBinding,
    OIDCProvider,
    ServiceIdentity,
    UserAccount,
)


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def iam_token(monkeypatch):
    monkeypatch.setenv("PESAGUARD_AUTH_RISK_POLICY", '{"privileged_operation_requires_mfa": false}')
    with SessionLocal() as session:
        session.query(IAMRoleBinding).filter(IAMRoleBinding.tenant_id.in_(["iam-tenant", "other-tenant"])).delete(synchronize_session=False)
        session.query(UserAccount).filter(
            UserAccount.id.in_(["iam_admin", "iam_other", "iam_limited", "iam_resource_reader"])
        ).delete(synchronize_session=False)
        session.add_all([
            UserAccount(id="iam_admin", username="iam-admin", tenant_id="iam-tenant", roles=["admin"], permissions=[], status="active", authorization_version=1),
            UserAccount(id="iam_other", username="iam-other", tenant_id="other-tenant", roles=["admin"], permissions=[], status="active", authorization_version=1),
        ])
        session.commit()
    token = AuthRBAC.generate_token("iam_admin", "iam-admin", "iam-tenant", ["admin"])
    try:
        yield token
    finally:
        with SessionLocal() as session:
            session.query(ServiceIdentity).filter(ServiceIdentity.tenant_id.in_(["iam-tenant", "other-tenant"])).delete(synchronize_session=False)
            session.query(ApiClientIdentity).filter(ApiClientIdentity.tenant_id.in_(["iam-tenant", "other-tenant"])).delete(synchronize_session=False)
            session.query(ExternalIdentity).filter(ExternalIdentity.tenant_id.in_(["iam-tenant", "other-tenant"])).delete(synchronize_session=False)
            session.query(OIDCProvider).filter(OIDCProvider.tenant_id.in_(["iam-tenant", "other-tenant"])).delete(synchronize_session=False)
            session.query(IAMRoleBinding).filter(IAMRoleBinding.tenant_id.in_(["iam-tenant", "other-tenant"])).delete(synchronize_session=False)
            session.query(IAMRole).filter(IAMRole.tenant_id.in_(["iam-tenant", "other-tenant"])).delete(synchronize_session=False)
            session.query(UserAccount).filter(
                UserAccount.id.in_(["iam_admin", "iam_other", "iam_limited", "iam_resource_reader"])
            ).delete(synchronize_session=False)
            session.commit()


def test_service_identity_and_api_client_secrets_are_one_time(client, iam_token):
    headers = {"Authorization": f"Bearer {iam_token}"}
    service_response = client.post(
        "/api/v1/iam/service-identities",
        headers=headers,
        json={"name": "settlement-worker", "identity_type": "workload", "scopes": ["transactions:read"]},
    )
    assert service_response.status_code == 201, service_response.get_data(as_text=True)
    service_body = service_response.get_json()
    assert service_body["client_secret"]
    service_id = service_body["id"]

    with SessionLocal() as session:
        service = session.get(ServiceIdentity, service_id)
        assert service.attributes["credential_prefix"]
        assert service_body["client_secret"] not in str(service.attributes)

    service_token_response = client.post(
        "/auth/client-token",
        json={
            "tenant_id": "iam-tenant",
            "client_id": service_id,
            "client_secret": service_body["client_secret"],
        },
    )
    assert service_token_response.status_code == 200
    service_token = service_token_response.get_json()["access_token"]
    service_principal = AuthRBAC.verify_token(service_token)
    assert service_principal is not None
    assert service_principal.permissions == ["read:transactions"]

    rotated_service = client.post(
        f"/api/v1/iam/service-identities/{service_id}/rotate-secret",
        headers=headers,
        json={},
    )
    assert rotated_service.status_code == 200
    assert AuthRBAC.verify_token(service_token) is None
    service_body["client_secret"] = rotated_service.get_json()["client_secret"]
    renewed_service_token = client.post(
        "/auth/client-token",
        json={
            "tenant_id": "iam-tenant",
            "client_id": service_id,
            "client_secret": service_body["client_secret"],
        },
    ).get_json()["access_token"]

    client_response = client.post(
        "/api/v1/iam/api-clients",
        headers=headers,
        json={
            "name": "reconciliation-console",
            "service_identity_id": service_id,
            "scopes": ["transactions:read"],
        },
    )
    assert client_response.status_code == 201, client_response.get_data(as_text=True)
    client_body = client_response.get_json()
    assert client_body["client_secret"]
    with SessionLocal() as session:
        api_client = session.query(ApiClientIdentity).filter_by(
            client_identifier=client_body["client_identifier"],
            tenant_id="iam-tenant",
        ).one()
        assert client_body["client_secret"] not in str(api_client.attributes)
    assert ACCESS_TOKEN_TTL_MINUTES <= 15

    token_response = client.post(
        "/auth/client-token",
        json={
            "tenant_id": "iam-tenant",
            "client_id": client_body["client_identifier"],
            "client_secret": client_body["client_secret"],
        },
    )
    assert token_response.status_code == 200, token_response.get_data(as_text=True)
    machine_token = token_response.get_json()["access_token"]
    claims = jwt.decode(machine_token, options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] <= 15 * 60
    machine_principal = AuthRBAC.verify_token(machine_token)
    assert machine_principal is not None
    assert machine_principal.tenant_id == "iam-tenant"
    assert machine_principal.permissions == ["read:transactions"]
    assert token_response.get_json()["expires_in"] <= 15 * 60

    rotated_client = client.post(
        f"/api/v1/iam/api-clients/{client_body['id']}/rotate-secret",
        headers=headers,
        json={},
    )
    assert rotated_client.status_code == 200
    assert AuthRBAC.verify_token(machine_token) is None
    replacement_token_response = client.post(
        "/auth/client-token",
        json={
            "tenant_id": "iam-tenant",
            "client_id": client_body["client_identifier"],
            "client_secret": rotated_client.get_json()["client_secret"],
        },
    )
    assert replacement_token_response.status_code == 200
    replacement_machine_token = replacement_token_response.get_json()["access_token"]

    listed = client.get("/api/v1/iam/service-identities", headers=headers)
    assert listed.status_code == 200, listed.get_data(as_text=True)
    assert listed.get_json()["items"][0]["name"] == "settlement-worker"

    with SessionLocal() as session:
        service = session.get(ServiceIdentity, service_id)
        service.status = "revoked"
        service.authorization_version += 1
        session.commit()
    assert AuthRBAC.verify_token(replacement_machine_token) is None
    assert AuthRBAC.verify_token(renewed_service_token) is None


def test_privileged_iam_mutations_require_mfa_but_reads_do_not(client, iam_token, monkeypatch):
    monkeypatch.setenv(
        "PESAGUARD_AUTH_RISK_POLICY",
        '{"privileged_operation_requires_mfa": true}',
    )
    headers = {"Authorization": f"Bearer {iam_token}"}

    listed = client.get("/api/v1/iam/service-identities", headers=headers)
    assert listed.status_code == 200

    created = client.post(
        "/api/v1/iam/service-identities",
        headers=headers,
        json={"name": "must-not-be-created", "scopes": ["transactions:read"]},
    )
    assert created.status_code == 401
    assert created.get_json()["error"]["code"] == "step_up_required"


def test_oidc_client_secret_is_encrypted_at_rest(client, iam_token, monkeypatch):
    monkeypatch.setattr(advanced_features, "_fetch_oidc_metadata", lambda _issuer: {})
    monkeypatch.setattr(advanced_features, "_validate_provider_trust_policy", lambda *_args: True)
    headers = {"Authorization": f"Bearer {iam_token}"}
    response = client.post(
        "/auth/sso/providers",
        headers=headers,
        json={
            "issuer": "https://identity.example.test",
            "client_id": "pesaguard",
            "client_secret": "oidc-client-secret",
            "authorization_endpoint": "https://identity.example.test/authorize",
            "token_endpoint": "https://identity.example.test/token",
            "jwks_uri": "https://identity.example.test/jwks",
        },
    )
    assert response.status_code == 201, response.get_data(as_text=True)

    with SessionLocal() as session:
        provider = session.query(OIDCProvider).filter_by(
            tenant_id="iam-tenant",
            issuer="https://identity.example.test",
        ).one()
        assert provider.client_secret.startswith("enc:v1:")
        assert decrypt_value(provider.client_secret) == "oidc-client-secret"
    assert "client_secret" not in response.get_json()


def test_payload_encryption_supports_previous_key_and_rewrapping(monkeypatch):
    from data_protection import decrypt_value, encrypt_value, rotate_encrypted_value

    monkeypatch.setenv("PESAGUARD_PAYLOAD_ENCRYPTION_KEY", "old-key")
    monkeypatch.delenv("PROVIDER_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("PESAGUARD_PAYLOAD_ENCRYPTION_KEY_PREVIOUS", raising=False)
    old_ciphertext = encrypt_value("mfa-secret-material")

    monkeypatch.setenv("PESAGUARD_PAYLOAD_ENCRYPTION_KEY", "new-key")
    monkeypatch.setenv("PESAGUARD_PAYLOAD_ENCRYPTION_KEY_PREVIOUS", "old-key")
    assert decrypt_value(old_ciphertext) == "mfa-secret-material"
    rotated = rotate_encrypted_value(old_ciphertext)
    assert rotated != old_ciphertext
    assert decrypt_value(rotated) == "mfa-secret-material"

    monkeypatch.delenv("PESAGUARD_PAYLOAD_ENCRYPTION_KEY_PREVIOUS")
    assert decrypt_value(rotated) == "mfa-secret-material"
    with pytest.raises(ValueError):
        decrypt_value(old_ciphertext)


def test_external_identity_and_role_binding_are_tenant_scoped(client, iam_token):
    headers = {"Authorization": f"Bearer {iam_token}"}
    external = client.post(
        "/api/v1/iam/external-identities",
        headers=headers,
        json={"user_id": "iam_admin", "issuer": "https://idp.example", "subject": "subject-1", "email": "iam@example.com"},
    )
    assert external.status_code == 201, external.get_data(as_text=True)

    cross_tenant = client.post(
        "/api/v1/iam/external-identities",
        headers=headers,
        json={"user_id": "iam_other", "issuer": "https://idp.example", "subject": "subject-2"},
    )
    assert cross_tenant.status_code == 404

    role_response = client.post(
        "/api/v1/iam/roles",
        headers=headers,
        json={"name": "reconciliation-reader", "permissions": ["read:discrepancies"]},
    )
    assert role_response.status_code == 201, role_response.get_data(as_text=True)
    role_id = role_response.get_json()["id"]

    with SessionLocal() as session:
        session.add(UserAccount(
            id="iam_resource_reader",
            username="iam-resource-reader",
            tenant_id="iam-tenant",
            roles=["org-manager"],
            permissions=[],
            status="active",
            authorization_version=1,
        ))
        session.commit()

    binding = client.post(
        "/api/v1/iam/role-bindings",
        headers=headers,
        json={"subject_type": "user", "subject_id": "iam_admin", "role_id": role_id},
    )
    assert binding.status_code == 201, binding.get_data(as_text=True)

    cross_tenant_binding = client.post(
        "/api/v1/iam/role-bindings",
        headers=headers,
        json={"subject_type": "user", "subject_id": "iam_other", "role_id": role_id},
    )
    assert cross_tenant_binding.status_code == 404

    scoped_role = client.post(
        "/api/v1/iam/roles",
        headers=headers,
        json={"name": "report-scoped-reader", "permissions": ["read:analytics"]},
    )
    assert scoped_role.status_code == 201
    resource_binding = client.post(
        "/api/v1/iam/role-bindings",
        headers=headers,
        json={
            "subject_type": "user",
            "subject_id": "iam_resource_reader",
            "role_id": scoped_role.get_json()["id"],
            "scope_type": "resource",
            "scope_id": "report-1",
        },
    )
    assert resource_binding.status_code == 201
    principal = AuthRBAC.verify_token(iam_token)
    assert principal is not None
    assert AuthRBAC.check_permission(principal, "read:discrepancies")
    resource_principal = AuthRBAC.verify_token(
        AuthRBAC.generate_token(
            "iam_resource_reader",
            "iam-resource-reader",
            "iam-tenant",
            ["org-manager"],
        )
    )
    assert resource_principal is not None
    assert AuthRBAC.check_resource_permission(resource_principal, "read:analytics", "report-1")
    assert not AuthRBAC.check_resource_permission(resource_principal, "read:analytics", "report-2")


def test_resource_scoped_role_is_enforced_on_service_identity_route(client, iam_token):
    admin_headers = {"Authorization": f"Bearer {iam_token}"}
    service_ids = []
    for name in ("resource-bound-service", "unbound-service"):
        response = client.post(
            "/api/v1/iam/service-identities",
            headers=admin_headers,
            json={"name": name, "scopes": ["transactions:read"]},
        )
        assert response.status_code == 201, response.get_data(as_text=True)
        service_ids.append(response.get_json()["id"])

    with SessionLocal() as session:
        session.add(UserAccount(
            id="iam_limited",
            username="iam-limited",
            tenant_id="iam-tenant",
            roles=["customer-user"],
            permissions=[],
            status="active",
            authorization_version=1,
        ))
        session.commit()

    role_response = client.post(
        "/api/v1/iam/roles",
        headers=admin_headers,
        json={"name": "service-resource-manager", "permissions": ["manage:users"]},
    )
    assert role_response.status_code == 201
    binding_response = client.post(
        "/api/v1/iam/role-bindings",
        headers=admin_headers,
        json={
            "subject_type": "user",
            "subject_id": "iam_limited",
            "role_id": role_response.get_json()["id"],
            "scope_type": "resource",
            "scope_id": service_ids[0],
        },
    )
    assert binding_response.status_code == 201
    limited_token = AuthRBAC.generate_token(
        "iam_limited",
        "iam-limited",
        "iam-tenant",
        ["customer-user"],
    )
    limited_headers = {"Authorization": f"Bearer {limited_token}"}

    allowed = client.patch(
        f"/api/v1/iam/service-identities/{service_ids[0]}",
        headers=limited_headers,
        json={"status": "suspended"},
    )
    assert allowed.status_code == 200, allowed.get_data(as_text=True)
    denied = client.patch(
        f"/api/v1/iam/service-identities/{service_ids[1]}",
        headers=limited_headers,
        json={"status": "suspended"},
    )
    assert denied.status_code == 403
