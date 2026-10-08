import hashlib
import hmac
import importlib
import json
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa


def test_developer_scope_tenant_id_matches_cross_language_vector():
    from auth_rbac import developer_scope_tenant_id

    assert developer_scope_tenant_id(
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
        "00000000-0000-0000-0000-000000000003",
    ) == "dp_2934bbfdc6fee932108c14a00ca22a9e8b6217d596b1d0988edefd178e1cb1b7"


@pytest.mark.parametrize(
    "organization_id,project_id,environment_id",
    [
        (None, "00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003"),
        (" 00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003"),
        ("00000000-0000-0000-0000-00000000000A", "00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003"),
        ("00000000-0000-0000-0000-000000000001", "1-2-3-4-5", "00000000-0000-0000-0000-000000000003"),
    ],
)
def test_developer_scope_tenant_id_rejects_noncanonical_identifiers(
    organization_id, project_id, environment_id
):
    from auth_rbac import developer_scope_tenant_id

    with pytest.raises(ValueError):
        developer_scope_tenant_id(organization_id, project_id, environment_id)


@pytest.fixture()
def pipeline_sync_client(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'developer-key-sync.db'}")
    monkeypatch.setenv("PESAGUARD_API_AUTH_REQUIRED", "1")
    monkeypatch.setenv("PESAGUARD_PIPELINE_KEY_SYNC_SECRET", "test-bridge-secret-value-32-bytes")
    monkeypatch.setenv("PESAGUARD_PIPELINE_SERVICE_JWT_MODE", "HMAC_ONLY")
    monkeypatch.setenv("PESAGUARD_PIPELINE_SERVICE_JWT_ALLOW_HMAC_FALLBACK", "0")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-with-at-least-32-bytes")
    import api.dashboard_app as dashboard_module

    dashboard_module = importlib.reload(dashboard_module)
    dashboard_module.Base.metadata.create_all(dashboard_module.primary_engine)
    from action_audit import Base as AuditBase
    from auth_rbac import _RevocationBase

    AuditBase.metadata.create_all(dashboard_module.primary_engine)
    _RevocationBase.metadata.create_all(dashboard_module.primary_engine)
    dashboard_module.app.config.update(TESTING=True)
    with dashboard_module.app.test_client() as client:
        yield client, dashboard_module


def _sync_idempotency_key(payload):
    source = "\n".join((
        "developer-platform-key-sync-v1",
        payload["key_id"],
        str(payload["source_version"]),
    ))
    return "pgs_" + hashlib.sha256(source.encode("utf-8")).hexdigest()


def _signed_sync_request(
    client,
    payload,
    secret="test-bridge-secret-value-32-bytes",
    timestamp=None,
    *,
    idempotency_key=None,
    include_idempotency_key=True,
    request_context_headers=None,
):
    timestamp = str(timestamp or int(time.time()))
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    canonical = b"\n".join((
        timestamp.encode("ascii"),
        b"POST",
        b"/internal/v1/developer-api-keys/sync",
        body,
    ))
    signature = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    headers = {
        "X-PesaGuard-Timestamp": timestamp,
        "X-PesaGuard-Signature": signature,
    }
    if include_idempotency_key:
        headers["Idempotency-Key"] = idempotency_key or _sync_idempotency_key(payload)
    headers.update(request_context_headers or {})
    return client.post(
        "/internal/v1/developer-api-keys/sync",
        data=body,
        content_type="application/json",
        headers=headers,
    )


def _signed_tenant_resolve_request(
    client,
    params,
    secret="test-bridge-secret-value-32-bytes",
    timestamp=None,
):
    timestamp = str(timestamp or int(time.time()))
    query = urlencode(params, doseq=True).encode("ascii")
    target = b"/internal/v1/tenants/resolve"
    if query:
        target += b"?" + query
    canonical = b"\n".join((
        timestamp.encode("ascii"),
        b"GET",
        target,
        b"",
    ))
    signature = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return client.get(
        target.decode("ascii"),
        headers={
            "X-PesaGuard-Timestamp": timestamp,
            "X-PesaGuard-Signature": signature,
        },
    )


def _b64url_uint(value):
    import base64

    return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("ascii")


@pytest.fixture()
def service_jwt_material(monkeypatch):
    import internal_service_auth

    internal_service_auth.reset_internal_service_auth_caches()
    keys = {
        "active-1": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "overlap-1": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "unknown-1": rsa.generate_private_key(public_exponent=65537, key_size=2048),
    }
    public_jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": _b64url_uint(key.public_key().public_numbers().n),
                "e": _b64url_uint(key.public_key().public_numbers().e),
            }
            for kid, key in keys.items()
            if kid != "unknown-1"
        ]
    }

    class Response:
        content = json.dumps(public_jwks, separators=(",", ":")).encode("utf-8")

        def raise_for_status(self):
            return None

    calls = []

    def get_jwks(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr(internal_service_auth.requests, "get", get_jwks)
    monkeypatch.setenv(
        "PESAGUARD_PIPELINE_SERVICE_JWT_JWKS_URL",
        "https://developer.example.test/internal/v1/service-jwt/jwks.json",
    )
    yield keys, calls
    internal_service_auth.reset_internal_service_auth_caches()


def _service_token(
    private_key,
    *,
    kid="active-1",
    scope=("service:sync",),
    overrides=None,
):
    now = int(time.time())
    payload = {
        "iss": "developer-platform",
        "aud": "core-api",
        "sub": "svc-developer-platform",
        "iat": now,
        "jti": str(uuid.uuid4()),
        "exp": now + 120,
        "scope": list(scope),
    }
    payload.update(overrides or {})
    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": kid, "typ": "JWT"},
    )


def _hmac_service_headers(method, target, body=b"", secret="test-bridge-secret-value-32-bytes"):
    timestamp = str(int(time.time()))
    canonical = b"\n".join((
        timestamp.encode("ascii"),
        method.encode("ascii"),
        target,
        body,
    ))
    signature = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return {
        "X-PesaGuard-Timestamp": timestamp,
        "X-PesaGuard-Signature": signature,
    }


def _signed_lifecycle_request(
    client,
    operation,
    key_id,
    payload,
    *,
    idempotency_key="lifecycle-request-1",
    secret="test-bridge-secret-value-32-bytes",
    authorization=None,
    request_context_headers=None,
):
    target = f"/internal/v1/keys/{key_id}/{operation}".encode("ascii")
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Idempotency-Key": idempotency_key}
    if authorization:
        headers["Authorization"] = authorization
    else:
        headers.update(_hmac_service_headers("POST", target, body, secret))
    headers.update(request_context_headers or {})
    return client.post(
        target.decode("ascii"),
        data=body,
        content_type="application/json",
        headers=headers,
    )


def test_service_jwt_mode_decisions_and_explicit_hmac_fallback(
    pipeline_sync_client, service_jwt_material, monkeypatch
):
    _, dashboard_module = pipeline_sync_client
    from internal_service_auth import (
        ServiceAuthError,
        authenticate_internal_request,
    )

    keys, _ = service_jwt_material
    method = "POST"
    target = b"/internal/v1/developer-api-keys/sync"
    body = b'{"scope":"test"}'
    hmac_headers = _hmac_service_headers(method, target, body)

    def authenticate(mode, headers):
        monkeypatch.setenv("PESAGUARD_PIPELINE_SERVICE_JWT_MODE", mode)
        with dashboard_module.app.test_request_context(
            target.decode("ascii"), method=method, data=body, headers=headers
        ):
            return authenticate_internal_request(
                method=method,
                raw_target=target,
                raw_body=body,
                required_scope="service:sync",
                operation="sync",
            )

    assert authenticate("HMAC_ONLY", hmac_headers) is None
    dual_no_jwt = None
    try:
        authenticate("DUAL_REQUIRED", hmac_headers)
    except ServiceAuthError as error:
        dual_no_jwt = error.code
    assert dual_no_jwt == "missing_service_token"

    signed_jwt = _service_token(keys["active-1"])
    jwt_headers = {"Authorization": f"Bearer {signed_jwt}"}
    with pytest.raises(ServiceAuthError, match="invalid_signature"):
        authenticate("DUAL_REQUIRED", jwt_headers)
    assert authenticate(
        "DUAL_REQUIRED",
        {**jwt_headers, **hmac_headers},
    )["iss"] == "developer-platform"

    monkeypatch.setenv("PESAGUARD_PIPELINE_SERVICE_JWT_MODE", "JWT_PRIMARY")
    assert authenticate("JWT_PRIMARY", jwt_headers)["sub"] == "svc-developer-platform"

    monkeypatch.setenv("PESAGUARD_PIPELINE_SERVICE_JWT_ALLOW_HMAC_FALLBACK", "1")
    assert authenticate("JWT_PRIMARY", hmac_headers) is None
    with pytest.raises(ServiceAuthError, match="invalid_service_token"):
        authenticate(
            "JWT_PRIMARY",
            {**hmac_headers, "Authorization": "Bearer malformed"},
        )
    monkeypatch.setenv("PESAGUARD_PIPELINE_SERVICE_JWT_MODE", "DUAL_REQUIRED")
    with pytest.raises(ServiceAuthError, match="missing_service_token"):
        authenticate("DUAL_REQUIRED", hmac_headers)


@pytest.mark.parametrize(
    "overrides,scope,reason",
    [
        ({"iss": "wrong-issuer"}, ("service:sync",), "invalid_service_token"),
        ({"aud": "wrong-audience"}, ("service:sync",), "invalid_service_token"),
        ({"sub": "wrong-subject"}, ("service:sync",), "invalid_service_token"),
        ({"time_case": "future_iat"}, ("service:sync",), "invalid_service_token"),
        ({"time_case": "expired"}, ("service:sync",), "invalid_service_token"),
        ({"time_case": "expired_beyond_skew"}, ("service:sync",), "invalid_service_token"),
        ({"time_case": "long_lifetime"}, ("service:sync",), "invalid_service_token"),
        ({"time_case": "short_lifetime"}, ("service:sync",), "invalid_service_token"),
        ({}, ("service:tenant:read",), "insufficient_service_scope"),
        ({}, ("service:sync", "service:other"), "insufficient_service_scope"),
        ({}, ("service:sync", "service:tenant:read"), "insufficient_service_scope"),
        ({"jti": "not-a-uuid"}, ("service:sync",), "invalid_service_token"),
    ],
)
def test_service_jwt_rejects_claim_scope_and_time_violations(
    pipeline_sync_client,
    service_jwt_material,
    monkeypatch,
    overrides,
    scope,
    reason,
):
    _, dashboard_module = pipeline_sync_client
    from internal_service_auth import ServiceAuthError, authenticate_internal_request

    monkeypatch.setenv("PESAGUARD_PIPELINE_SERVICE_JWT_MODE", "JWT_PRIMARY")
    keys, _ = service_jwt_material
    token_overrides = dict(overrides)
    time_case = token_overrides.pop("time_case", None)
    now = int(time.time())
    if time_case == "future_iat":
        token_overrides["iat"] = now + 31
    elif time_case == "expired":
        token_overrides["exp"] = now - 1
    elif time_case == "expired_beyond_skew":
        token_overrides["iat"] = now - 150
        token_overrides["exp"] = now - 30
    elif time_case == "long_lifetime":
        token_overrides["exp"] = now + 301
    elif time_case == "short_lifetime":
        token_overrides["exp"] = now + 59
    token = _service_token(
        keys["active-1"], scope=scope, overrides=token_overrides
    )
    dashboard_module.app.config.update(TESTING=True)
    with dashboard_module.app.test_request_context(
        "/internal/v1/developer-api-keys/sync",
        method="POST",
        headers={"Authorization": f"Bearer {token}"},
    ):
        with pytest.raises(ServiceAuthError) as raised:
            authenticate_internal_request(
                method="POST",
                raw_target=b"/internal/v1/developer-api-keys/sync",
                raw_body=b"",
                required_scope="service:sync",
                operation="sync",
            )
    assert raised.value.code == reason


def test_service_jwt_allows_configured_clock_skew(
    pipeline_sync_client, service_jwt_material, monkeypatch
):
    _, dashboard_module = pipeline_sync_client
    from internal_service_auth import authenticate_internal_request

    monkeypatch.setenv("PESAGUARD_PIPELINE_SERVICE_JWT_MODE", "JWT_PRIMARY")
    keys, _ = service_jwt_material
    now = int(time.time())
    for iat, exp in ((now + 20, now + 140), (now - 140, now - 20)):
        token = _service_token(
            keys["active-1"],
            overrides={"iat": iat, "exp": exp},
        )
        with dashboard_module.app.test_request_context(
            "/internal/v1/developer-api-keys/sync",
            method="POST",
            headers={"Authorization": f"Bearer {token}"},
        ):
            claims = authenticate_internal_request(
                method="POST",
                raw_target=b"/internal/v1/developer-api-keys/sync",
                raw_body=b"",
                required_scope="service:sync",
                operation="sync",
            )
        assert claims["iat"] == iat


def test_service_jwt_requires_rs256_known_kid_and_accepts_overlap_keys(
    pipeline_sync_client, service_jwt_material
):
    _, _ = pipeline_sync_client
    from internal_service_auth import (
        SERVICE_JWT_JWKS_CACHE_SECONDS,
        ServiceAuthError,
        _parse_service_token,
    )

    assert SERVICE_JWT_JWKS_CACHE_SECONDS <= 60
    keys, calls = service_jwt_material
    assert _parse_service_token(
        _service_token(keys["active-1"]), "service:sync"
    )[0]["sub"] == "svc-developer-platform"
    assert _parse_service_token(
        _service_token(keys["overlap-1"], kid="overlap-1"), "service:sync"
    )[0]["sub"] == "svc-developer-platform"
    unknown = _service_token(keys["unknown-1"], kid="unknown-1")
    with pytest.raises(ServiceAuthError) as raised:
        _parse_service_token(unknown, "service:sync")
    assert raised.value.code == "invalid_service_token"
    # Unknown kid forces a refresh so active/overlap rotation is observed.
    assert len(calls) == 2

    hs_token = jwt.encode(
        {"iss": "developer-platform"},
        "not-an-rsa-key-that-is-at-least-32-bytes-long",
        algorithm="HS256",
        headers={"kid": "active-1"},
    )
    with pytest.raises(ServiceAuthError) as raised:
        _parse_service_token(hs_token, "service:sync")
    assert raised.value.code == "invalid_service_token"

    bad_signature = _service_token(
        keys["unknown-1"], kid="active-1"
    )
    with pytest.raises(ServiceAuthError) as raised:
        _parse_service_token(bad_signature, "service:sync")
    assert raised.value.code == "invalid_service_token"


def test_service_jwt_jwks_unavailability_fails_closed(
    pipeline_sync_client, service_jwt_material, monkeypatch
):
    _, _ = pipeline_sync_client
    import internal_service_auth

    keys, _ = service_jwt_material
    internal_service_auth.reset_internal_service_auth_caches()

    def jwks_unavailable(*args, **kwargs):
        raise OSError("JWKS endpoint unavailable")

    monkeypatch.setattr(internal_service_auth.requests, "get", jwks_unavailable)
    with pytest.raises(internal_service_auth.ServiceAuthError) as raised:
        internal_service_auth._parse_service_token(
            _service_token(keys["active-1"]), "service:sync"
        )
    assert raised.value.code == "service_auth_unavailable"


def test_service_jwt_replay_is_rejected_and_redis_errors_fail_closed(
    pipeline_sync_client, service_jwt_material, monkeypatch
):
    client, _ = pipeline_sync_client
    import internal_service_auth

    keys, _ = service_jwt_material
    monkeypatch.setenv("PESAGUARD_PIPELINE_SERVICE_JWT_MODE", "JWT_PRIMARY")
    monkeypatch.setenv("REDIS_URL", "redis://redis.test/0")
    raw_key = "pgk_service_jwt_replay"
    org, project, environment = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    from auth_rbac import developer_scope_tenant_id

    payload = {
        "key_id": str(uuid.uuid4()),
        "tenant_id": developer_scope_tenant_id(org, project, environment),
        "organization_id": org,
        "project_id": project,
        "environment_id": environment,
        "source_version": 1,
        "key_hash": hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
        "key_prefix": raw_key[:16],
        "scopes": ["read:analytics"],
        "ip_allowlist": [],
        "status": "ACTIVE",
        "expires_at": None,
    }

    class FakeRedis:
        seen = set()
        ttl = None

        def set(self, key, value, nx=False, ex=None):
            self.ttl = ex
            if nx and key in self.seen:
                return None
            self.seen.add(key)
            return True

    fake_redis = FakeRedis()
    monkeypatch.setattr(
        "redis.from_url",
        lambda *args, **kwargs: fake_redis,
    )
    token = _service_token(keys["active-1"])
    headers = {"Authorization": f"Bearer {token}"}
    headers["Idempotency-Key"] = _sync_idempotency_key(payload)
    first = client.post(
        "/internal/v1/developer-api-keys/sync", json=payload, headers=headers
    )
    assert first.status_code == 200
    assert 1 <= fake_redis.ttl <= 330

    replay = client.post(
        "/internal/v1/developer-api-keys/sync", json=payload, headers=headers
    )
    assert replay.status_code == 401
    assert replay.get_json()["error"] == "service_token_replayed"

    internal_service_auth.reset_internal_service_auth_caches()

    def redis_down(*args, **kwargs):
        raise OSError("unavailable")

    monkeypatch.setattr("redis.from_url", redis_down)
    unavailable_token = _service_token(keys["active-1"])
    unavailable_payload = {**payload, "key_id": str(uuid.uuid4())}
    unavailable_headers = {
        "Authorization": f"Bearer {unavailable_token}",
        "Idempotency-Key": _sync_idempotency_key(unavailable_payload),
    }
    unavailable = client.post(
        "/internal/v1/developer-api-keys/sync",
        json=unavailable_payload,
        headers=unavailable_headers,
    )
    assert unavailable.status_code == 503
    assert unavailable.get_json()["error"] == "service_replay_protection_unavailable"


def test_developer_key_suspend_and_revoke_are_tenant_version_and_idempotency_safe(
    pipeline_sync_client,
):
    client, _ = pipeline_sync_client
    from action_audit import ActionAuditEntry
    from auth_rbac import AuthRBAC, _RevocationSession, developer_scope_tenant_id
    from datetime import timedelta
    from models import ApiKeyLifecycleIdempotencyRecord, ApiKeyRecord

    raw_key = "pgk_lifecycle_enforcement_test"
    organization_id, project_id, environment_id = (
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        str(uuid.uuid4()),
    )
    key_payload = {
        "key_id": str(uuid.uuid4()),
        "tenant_id": developer_scope_tenant_id(
            organization_id, project_id, environment_id
        ),
        "organization_id": organization_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "source_version": 1,
        "key_hash": hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
        "key_prefix": raw_key[:16],
        "scopes": ["read:analytics"],
        "ip_allowlist": [],
        "status": "ACTIVE",
        "expires_at": None,
    }
    assert _signed_sync_request(client, key_payload).status_code == 200
    assert AuthRBAC.verify_api_key(raw_key) is not None

    lifecycle_payload = {
        "organization_id": organization_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "tenant_id": key_payload["tenant_id"],
        "source_version": 2,
    }
    invalid_signature = _signed_lifecycle_request(
        client,
        "suspend",
        key_payload["key_id"],
        lifecycle_payload,
        secret="wrong-bridge-secret-value-32-bytes",
        idempotency_key="invalid-signature",
    )
    assert invalid_signature.status_code == 401
    missing_idempotency_key = _signed_lifecycle_request(
        client,
        "suspend",
        key_payload["key_id"],
        lifecycle_payload,
        idempotency_key="",
    )
    assert missing_idempotency_key.status_code == 400
    invalid_tenant = _signed_lifecycle_request(
        client,
        "suspend",
        key_payload["key_id"],
        {**lifecycle_payload, "tenant_id": "dp_" + "0" * 64},
        idempotency_key="invalid-tenant",
    )
    assert invalid_tenant.status_code == 400
    suspended = _signed_lifecycle_request(
        client, "suspend", key_payload["key_id"], lifecycle_payload
    )
    assert suspended.status_code == 200
    suspended_response = suspended.get_json()
    assert suspended_response == {
        "status": "suspended",
        "key_id": key_payload["key_id"],
        "source_version": 2,
        "active": False,
    }
    assert AuthRBAC.verify_api_key(raw_key) is None
    session = _RevocationSession()
    try:
        suspended_record = session.query(ApiKeyRecord).filter_by(
            id=key_payload["key_id"]
        ).one()
        assert not suspended_record.active
        assert suspended_record.revoked_at is None
        assert suspended_record.api_metadata["source_status"] == "SUSPENDED"
    finally:
        session.close()
    replay = _signed_lifecycle_request(
        client, "suspend", key_payload["key_id"], lifecycle_payload
    )
    assert replay.status_code == 200
    assert replay.get_json() == suspended_response

    changed_request = {**lifecycle_payload, "source_version": 3}
    conflict = _signed_lifecycle_request(
        client, "suspend", key_payload["key_id"], changed_request
    )
    assert conflict.status_code == 409
    assert conflict.get_json()["error"] == "idempotency_key_reused"

    other_organization = str(uuid.uuid4())
    cross_tenant_payload = {
        **changed_request,
        "organization_id": other_organization,
        "tenant_id": developer_scope_tenant_id(
            other_organization, project_id, environment_id
        ),
    }
    cross_tenant = _signed_lifecycle_request(
        client,
        "suspend",
        key_payload["key_id"],
        cross_tenant_payload,
        idempotency_key="cross-tenant-attempt",
    )
    assert cross_tenant.status_code == 409
    assert cross_tenant.get_json()["error"] == "tenant_mismatch"

    resumed_payload = {**key_payload, "source_version": 3}
    assert _signed_sync_request(client, resumed_payload).status_code == 200
    assert AuthRBAC.verify_api_key(raw_key) is not None

    stale = _signed_lifecycle_request(
        client,
        "suspend",
        key_payload["key_id"],
        changed_request,
        idempotency_key="stale-version",
    )
    assert stale.status_code == 409
    assert stale.get_json()["error"] == "stale_source_version"

    revoke_payload = {**lifecycle_payload, "source_version": 4}
    revoked = _signed_lifecycle_request(
        client,
        "revoke",
        key_payload["key_id"],
        revoke_payload,
        idempotency_key="terminal-revoke",
    )
    assert revoked.status_code == 200
    assert revoked.get_json()["status"] == "revoked"
    assert AuthRBAC.verify_api_key(raw_key) is None
    for version, status in ((5, "SUSPENDED"), (6, "ACTIVE")):
        attempted_revival = _signed_sync_request(
            client,
            {**key_payload, "source_version": version, "status": status},
        )
        assert attempted_revival.status_code == 409
        assert attempted_revival.get_json()["error"] == "terminal_key_state"

    session = _RevocationSession()
    try:
        record = session.query(ApiKeyRecord).filter_by(id=key_payload["key_id"]).one()
        assert not record.active
        assert record.revoked_at is not None
        assert record.source_version == 4
        idem = session.query(ApiKeyLifecycleIdempotencyRecord).filter_by(
            operation="suspend",
        ).all()
        idem.extend(
            session.query(ApiKeyLifecycleIdempotencyRecord).filter_by(
                operation="revoke",
            ).all()
        )
        assert len(idem) == 2
        assert all(
            item.expires_at <= item.created_at + timedelta(hours=24)
            for item in idem
        )
        audit_entries = session.query(ActionAuditEntry).filter_by(
            tenant_id=key_payload["tenant_id"],
            resource_id=key_payload["key_id"],
        ).all()
        assert {entry.action for entry in audit_entries} == {
            "api_key.suspend",
            "api_key.revoke",
        }
        for entry in audit_entries:
            assert raw_key not in json.dumps(entry.details)
            assert "key_hash" not in entry.details
    finally:
        session.close()


def test_jwt_primary_lifecycle_requires_exact_scope_and_consumes_jti(
    pipeline_sync_client, service_jwt_material, monkeypatch
):
    client, _ = pipeline_sync_client
    from auth_rbac import developer_scope_tenant_id

    raw_key = "pgk_jwt_lifecycle_test"
    organization_id, project_id, environment_id = (
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        str(uuid.uuid4()),
    )
    key_payload = {
        "key_id": str(uuid.uuid4()),
        "tenant_id": developer_scope_tenant_id(
            organization_id, project_id, environment_id
        ),
        "organization_id": organization_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "source_version": 1,
        "key_hash": hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
        "key_prefix": raw_key[:16],
        "scopes": ["read:analytics"],
        "ip_allowlist": [],
        "status": "ACTIVE",
        "expires_at": None,
    }
    assert _signed_sync_request(client, key_payload).status_code == 200

    class FakeRedis:
        def __init__(self):
            self.seen = set()

        def set(self, key, value, nx=False, ex=None):
            if nx and key in self.seen:
                return None
            self.seen.add(key)
            return True

    fake_redis = FakeRedis()
    monkeypatch.setattr("redis.from_url", lambda *args, **kwargs: fake_redis)
    monkeypatch.setenv("REDIS_URL", "redis://redis.test/0")
    monkeypatch.setenv("PESAGUARD_PIPELINE_SERVICE_JWT_MODE", "JWT_PRIMARY")
    keys, _ = service_jwt_material
    lifecycle_payload = {
        "organization_id": organization_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "tenant_id": key_payload["tenant_id"],
        "source_version": 2,
    }
    overbroad = _signed_lifecycle_request(
        client,
        "suspend",
        key_payload["key_id"],
        lifecycle_payload,
        authorization=(
            f"Bearer {_service_token(keys['active-1'], scope=('service:key:suspend', 'service:sync'))}"
        ),
    )
    assert overbroad.status_code == 403
    assert overbroad.get_json()["error"] == "insufficient_service_scope"

    token = _service_token(
        keys["active-1"], scope=("service:key:suspend",)
    )

    def lifecycle_request(authorization):
        return _signed_lifecycle_request(
            client,
            "suspend",
            key_payload["key_id"],
            lifecycle_payload,
            authorization=f"Bearer {authorization}",
        )

    first = lifecycle_request(token)
    assert first.status_code == 200
    assert lifecycle_request(token).status_code == 401
    replay_with_fresh_token = lifecycle_request(
        _service_token(keys["active-1"], scope=("service:key:suspend",))
    )
    assert replay_with_fresh_token.get_json() == first.get_json()


def test_jwt_primary_resolve_requires_tenant_read_scope(
    pipeline_sync_client, service_jwt_material, monkeypatch
):
    client, _ = pipeline_sync_client
    keys, _ = service_jwt_material
    monkeypatch.setenv("PESAGUARD_PIPELINE_SERVICE_JWT_MODE", "JWT_PRIMARY")
    params = {
        "organization_id": "00000000-0000-0000-0000-000000000001",
        "project_id": "00000000-0000-0000-0000-000000000002",
        "environment_id": "00000000-0000-0000-0000-000000000003",
    }
    wrong_scope = client.get(
        "/internal/v1/tenants/resolve",
        query_string=params,
        headers={"Authorization": f"Bearer {_service_token(keys['active-1'])}"},
    )
    assert wrong_scope.status_code == 403
    right_scope_token = _service_token(
        keys["active-1"], scope=("service:tenant:read",)
    )
    resolved = client.get(
        "/internal/v1/tenants/resolve",
        query_string=params,
        headers={"Authorization": f"Bearer {right_scope_token}"},
    )
    assert resolved.status_code == 200
    assert resolved.get_json() == {
        "tenant_id": "dp_2934bbfdc6fee932108c14a00ca22a9e8b6217d596b1d0988edefd178e1cb1b7"
    }


def test_developer_platform_key_authenticates_scoped_pipeline_requests(pipeline_sync_client):
    client, _ = pipeline_sync_client
    raw_key = "pgk_test_key_for_pipeline"
    key_id = str(uuid.uuid4())
    organization_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    environment_id = str(uuid.uuid4())
    from auth_rbac import developer_scope_tenant_id

    payload = {
        "key_id": key_id,
        "tenant_id": developer_scope_tenant_id(organization_id, project_id, environment_id),
        "organization_id": organization_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "source_version": 1,
        "key_hash": hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
        "key_prefix": raw_key[:16],
        "scopes": ["read:analytics"],
        "ip_allowlist": [],
        "status": "ACTIVE",
        "expires_at": None,
    }

    sync = _signed_sync_request(client, payload)
    assert sync.status_code == 200
    assert _signed_sync_request(client, payload).get_json() == sync.get_json()
    from auth_rbac import AuthRBAC

    key_user = AuthRBAC.verify_api_key(raw_key)
    assert key_user is not None
    assert key_user.roles == []
    assert key_user.permissions == ["read:analytics"]
    assert not AuthRBAC.check_permission(key_user, "manage:api_keys")

    conflicting_project = str(uuid.uuid4())
    conflicting_environment = str(uuid.uuid4())
    conflicting_binding = {
        **payload,
        "source_version": 2,
        "project_id": conflicting_project,
        "environment_id": conflicting_environment,
        "tenant_id": developer_scope_tenant_id(
            organization_id, conflicting_project, conflicting_environment
        ),
    }
    assert _signed_sync_request(client, conflicting_binding).status_code == 409

    response = client.get(
        "/api/v1/lineage/transactions/test-transaction",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert response.status_code == 200
    assert response.get_json()["tenant_id"] == payload["tenant_id"]
    assert client.get(
        "/api/v1/lineage/transactions/test-transaction",
        headers={"X-API-Key": raw_key, "X-Tenant-ID": organization_id},
    ).status_code == 403
    assert client.get(
        "/api/v1/lineage/transactions/test-transaction",
        headers={"Authorization": f"Bearer {raw_key}", "X-API-Key": raw_key},
    ).status_code == 400

    second_key = "pgk_test_key_for_another_project"
    second_organization = organization_id
    second_project = str(uuid.uuid4())
    second_environment = str(uuid.uuid4())
    second_payload = {
        **payload,
        "key_id": str(uuid.uuid4()),
        "tenant_id": developer_scope_tenant_id(second_organization, second_project, second_environment),
        "project_id": second_project,
        "environment_id": second_environment,
        "key_hash": hashlib.sha256(second_key.encode("utf-8")).hexdigest(),
        "key_prefix": second_key[:16],
        "source_version": 1,
    }
    assert _signed_sync_request(client, second_payload).status_code == 200
    from models import LineageRecord
    from auth_rbac import _RevocationSession
    from datetime import datetime, timezone

    session = _RevocationSession()
    try:
        session.add(LineageRecord(
            tenant_id=payload["tenant_id"],
            transaction_id="shared-transaction-id",
            event_id="scoped-event",
            stage="stored",
            source="test",
            ingestion_time=datetime.now(timezone.utc),
            pipeline_version="1",
            transformation_version="1",
        ))
        session.commit()
    finally:
        session.close()
    first_scope_data = client.get(
        "/api/v1/lineage/transactions/shared-transaction-id",
        headers={"X-API-Key": raw_key},
    )
    other_project_data = client.get(
        "/api/v1/lineage/transactions/shared-transaction-id",
        headers={"X-API-Key": second_key},
    )
    assert first_scope_data.status_code == 200
    assert len(first_scope_data.get_json()["items"]) == 1
    assert other_project_data.status_code == 200
    assert other_project_data.get_json()["items"] == []

    payload["source_version"] = 2
    payload["status"] = "REVOKED"
    payload["key_hash"] = None
    assert _signed_sync_request(client, payload).status_code == 200
    assert client.get(
        "/api/v1/lineage/transactions/test-transaction",
        headers={"X-API-Key": raw_key},
    ).status_code == 401


def test_developer_key_sync_rejects_bad_and_expired_signatures(pipeline_sync_client):
    client, _ = pipeline_sync_client
    payload = {
        "key_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "environment_id": str(uuid.uuid4()),
        "source_version": 1,
        "key_hash": "0" * 64,
        "key_prefix": "pgk_test_key",
        "scopes": ["read:analytics"],
        "ip_allowlist": [],
        "status": "ACTIVE",
        "expires_at": None,
    }
    assert _signed_sync_request(client, payload, secret="wrong-secret").status_code == 401
    assert _signed_sync_request(client, payload, timestamp=int(time.time()) - 301).status_code == 401


def test_tenant_resolve_requires_signed_canonical_query_and_preserves_correlation_id(
    pipeline_sync_client,
):
    client, _ = pipeline_sync_client
    params = {
        "organization_id": "00000000-0000-0000-0000-000000000001",
        "project_id": "00000000-0000-0000-0000-000000000002",
        "environment_id": "00000000-0000-0000-0000-000000000003",
    }
    response = _signed_tenant_resolve_request(client, params)
    assert response.status_code == 200
    assert response.get_json() == {
        "tenant_id": "dp_2934bbfdc6fee932108c14a00ca22a9e8b6217d596b1d0988edefd178e1cb1b7"
    }

    public_response = client.get(
        "/internal/v1/tenants/resolve",
        query_string=params,
    )
    assert public_response.status_code == 401

    signed_response = _signed_tenant_resolve_request(client, params)
    assert signed_response.status_code == 200
    assert "organization_id" not in signed_response.get_json()
    assert "project_id" not in signed_response.get_json()
    assert "environment_id" not in signed_response.get_json()

    signed_timestamp = str(int(time.time()))
    signed_query = urlencode(params).encode("ascii")
    signed_canonical = b"\n".join((
        signed_timestamp.encode("ascii"),
        b"GET",
        b"/internal/v1/tenants/resolve?" + signed_query,
        b"",
    ))
    signed_signature = hmac.new(
        b"test-bridge-secret-value-32-bytes",
        signed_canonical,
        hashlib.sha256,
    ).hexdigest()
    changed_params = {**params, "project_id": str(uuid.uuid4())}
    target_query = urlencode(changed_params)
    tampered = client.get(
        f"/internal/v1/tenants/resolve?{target_query}",
        headers={
            "X-PesaGuard-Timestamp": signed_timestamp,
            "X-PesaGuard-Signature": signed_signature,
            "X-Request-ID": "resolve-request-123",
        },
    )
    assert tampered.status_code == 401
    assert tampered.headers["X-Correlation-ID"] == "resolve-request-123"


def test_tenant_resolve_rejects_invalid_and_ambiguous_ids(pipeline_sync_client):
    client, _ = pipeline_sync_client
    params = {
        "organization_id": "not-a-uuid",
        "project_id": str(uuid.uuid4()),
        "environment_id": str(uuid.uuid4()),
    }
    invalid = _signed_tenant_resolve_request(client, params)
    assert invalid.status_code == 400
    assert "not-a-uuid" not in invalid.get_data(as_text=True)

    valid_ids = {
        "organization_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "environment_id": str(uuid.uuid4()),
    }
    missing = _signed_tenant_resolve_request(client, {
        "organization_id": valid_ids["organization_id"],
        "project_id": valid_ids["project_id"],
    })
    assert missing.status_code == 400
    duplicate = _signed_tenant_resolve_request(client, [
        ("organization_id", valid_ids["organization_id"]),
        ("organization_id", valid_ids["organization_id"]),
        ("project_id", valid_ids["project_id"]),
        ("environment_id", valid_ids["environment_id"]),
    ])
    assert duplicate.status_code == 400


def test_developer_key_sync_persists_only_normalized_approved_scopes(pipeline_sync_client):
    client, _ = pipeline_sync_client
    from auth_rbac import _RevocationSession
    from models import ApiKeyRecord

    raw_key = "pgk_scope_validation_test"
    organization_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    environment_id = str(uuid.uuid4())
    from auth_rbac import developer_scope_tenant_id

    payload = {
        "key_id": str(uuid.uuid4()),
        "tenant_id": developer_scope_tenant_id(
            organization_id, project_id, environment_id
        ),
        "organization_id": organization_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "source_version": 1,
        "key_hash": hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
        "key_prefix": raw_key[:16],
        "scopes": ["analytics:read", "read:analytics"],
        "ip_allowlist": [],
        "status": "ACTIVE",
        "expires_at": None,
    }
    accepted = _signed_sync_request(client, payload)
    assert accepted.status_code == 200

    session = _RevocationSession()
    try:
        record = session.query(ApiKeyRecord).filter_by(id=payload["key_id"]).one()
        assert record.scopes == ["read:analytics"]
        payload["source_version"] = 2
        for scope in (
            "fraud:write",
            "service:publish",
            "service:key:revoke",
            "service:key:suspend",
        ):
            payload["scopes"] = [scope]
            rejected = _signed_sync_request(client, payload)
            assert rejected.status_code == 400
            assert rejected.get_json()["reason"] == "invalid_scopes"
        session.refresh(record)
        assert record.scopes == ["read:analytics"]
    finally:
        session.close()


def test_developer_key_sync_idempotency_replays_and_rejects_changed_requests(
    pipeline_sync_client,
):
    client, _ = pipeline_sync_client
    from datetime import timedelta
    from auth_rbac import _RevocationSession, developer_scope_tenant_id
    from models import ApiKeyLifecycleIdempotencyRecord

    organization_id, project_id, environment_id = (
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        str(uuid.uuid4()),
    )
    payload = {
        "key_id": str(uuid.uuid4()),
        "tenant_id": developer_scope_tenant_id(
            organization_id, project_id, environment_id
        ),
        "organization_id": organization_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "source_version": 1,
        "key_hash": hashlib.sha256(b"pgk_sync_idempotency").hexdigest(),
        "key_prefix": "pgk_sync_idempot",
        "scopes": ["read:analytics"],
        "ip_allowlist": [],
        "status": "ACTIVE",
        "expires_at": None,
    }
    idem = "sync-operation-1"
    first = _signed_sync_request(client, payload, idempotency_key=idem)
    replay = _signed_sync_request(client, payload, idempotency_key=idem)
    assert first.status_code == 200
    assert replay.status_code == 200
    assert replay.get_json() == first.get_json()

    changed_request = {**payload, "key_prefix": "pgk_changed_prefix"}
    conflict = _signed_sync_request(client, changed_request, idempotency_key=idem)
    assert conflict.status_code == 409
    assert conflict.get_json()["error"] == "idempotency_key_reused"

    missing_key = _signed_sync_request(
        client, {**payload, "key_id": str(uuid.uuid4())},
        include_idempotency_key=False,
    )
    assert missing_key.status_code == 400
    assert missing_key.get_json()["error"] == "invalid_idempotency_key"

    session = _RevocationSession()
    try:
        records = session.query(ApiKeyLifecycleIdempotencyRecord).filter_by(
            operation="sync",
            key_id=payload["key_id"],
        ).all()
        assert len(records) == 1
        assert records[0].response == first.get_json()
        assert records[0].expires_at - records[0].created_at == timedelta(hours=24)
    finally:
        session.close()


def test_internal_service_rate_limit_is_scoped_to_authenticated_service_and_operation(
    pipeline_sync_client, monkeypatch,
):
    client, dashboard_module = pipeline_sync_client
    calls = []

    class RateLimited:
        def is_allowed(self, identity, operation):
            calls.append((identity, operation))
            return False, {"retry_after": 9}

    monkeypatch.setitem(
        dashboard_module.internal_service_rate_limiters,
        "sync",
        RateLimited(),
    )
    payload = {
        "key_id": str(uuid.uuid4()),
        "tenant_id": "dp_" + "a" * 64,
        "organization_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "environment_id": str(uuid.uuid4()),
        "source_version": 1,
        "key_hash": hashlib.sha256(b"pgk_rate_limit").hexdigest(),
        "key_prefix": "pgk_rate_limit",
        "scopes": ["read:analytics"],
        "ip_allowlist": [],
        "status": "ACTIVE",
        "expires_at": None,
    }

    response = _signed_sync_request(client, payload)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "9"
    assert calls == [
        ("service:svc-developer-platform-hmac", "internal_v1_sync"),
    ]


def test_internal_service_rate_limiter_failure_fails_closed(pipeline_sync_client, monkeypatch):
    _, dashboard_module = pipeline_sync_client

    class Unavailable:
        def is_allowed(self, identity, operation):
            return False, {"unavailable": True}

    monkeypatch.setitem(
        dashboard_module.internal_service_rate_limiters,
        "resolve",
        Unavailable(),
    )
    with dashboard_module.app.test_request_context("/internal/v1/tenants/resolve"):
        response, status = dashboard_module._internal_service_rate_limit_response(
            "resolve",
            {"sub": "svc-developer-platform"},
        )

    assert status == 503
    assert response.get_json()["error"] == "rate_limiter_unavailable"


def test_internal_service_request_context_is_returned_to_caller(pipeline_sync_client):
    client, _ = pipeline_sync_client
    organization_id, project_id, environment_id = (
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        str(uuid.uuid4()),
    )
    from auth_rbac import developer_scope_tenant_id

    payload = {
        "key_id": str(uuid.uuid4()),
        "tenant_id": developer_scope_tenant_id(
            organization_id, project_id, environment_id
        ),
        "organization_id": organization_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "source_version": 1,
        "key_hash": hashlib.sha256(b"pgk_context_propagation").hexdigest(),
        "key_prefix": "pgk_context_test",
        "scopes": ["read:analytics"],
        "ip_allowlist": [],
        "status": "ACTIVE",
        "expires_at": None,
    }
    request_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    trace_id = "1234567890abcdef1234567890abcdef"
    traceparent = f"00-{trace_id}-1234567890abcdef-01"

    response = _signed_sync_request(
        client,
        payload,
        request_context_headers={
            "X-Request-ID": request_id,
            "X-Correlation-ID": correlation_id,
            "traceparent": traceparent,
        },
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == request_id
    assert response.headers["X-Correlation-ID"] == correlation_id
    assert response.headers["X-Trace-ID"] == trace_id
    assert response.headers["traceparent"].startswith(f"00-{trace_id}-")


def test_internal_key_sync_and_lifecycle_preserve_supported_correlation_header(
    pipeline_sync_client,
):
    client, _ = pipeline_sync_client
    from auth_rbac import developer_scope_tenant_id

    organization_id, project_id, environment_id = (
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        str(uuid.uuid4()),
    )
    key_id = str(uuid.uuid4())
    tenant_id = developer_scope_tenant_id(
        organization_id, project_id, environment_id
    )
    context_headers = {
        "X-Request-ID": str(uuid.uuid4()),
        "X-Correlation-ID": "corr:api-key-lifecycle-17",
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    }
    sync_payload = {
        "key_id": key_id,
        "tenant_id": tenant_id,
        "organization_id": organization_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "source_version": 1,
        "key_hash": hashlib.sha256(b"api-key-context-test").hexdigest(),
        "key_prefix": "pgk_context_test",
        "scopes": ["read:analytics"],
        "ip_allowlist": [],
        "status": "ACTIVE",
        "expires_at": None,
    }

    sync_response = _signed_sync_request(
        client, sync_payload, request_context_headers=context_headers
    )
    assert sync_response.status_code == 200

    lifecycle_response = _signed_lifecycle_request(
        client,
        "suspend",
        key_id,
        {
            "organization_id": organization_id,
            "project_id": project_id,
            "environment_id": environment_id,
            "tenant_id": tenant_id,
            "source_version": 2,
        },
        request_context_headers=context_headers,
    )
    assert lifecycle_response.status_code == 200

    for response in (sync_response, lifecycle_response):
        assert response.headers["X-Correlation-ID"] == context_headers["X-Correlation-ID"]
        assert response.headers["X-Request-ID"] == context_headers["X-Request-ID"]
        assert response.headers["X-Trace-ID"] == context_headers["traceparent"][3:35]
        assert response.headers["traceparent"].startswith(
            "00-" + context_headers["traceparent"][3:35] + "-"
        )


def test_api_key_lifecycle_event_schema_requires_safe_versioned_scope_context():
    from jsonschema import Draft202012Validator, FormatChecker
    from auth_rbac import developer_scope_tenant_id

    organization_id, project_id, environment_id, key_id = (
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        str(uuid.uuid4()),
    )
    schema_path = Path(__file__).parents[1] / "schemas" / "developer-api-key-lifecycle-1.0.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "developer.api_key.suspended",
        "event_version": 1,
        "occurred_at": "2026-10-07T12:00:00Z",
        "organization_id": organization_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "tenant_id": developer_scope_tenant_id(
            organization_id, project_id, environment_id
        ),
        "source": "developer-platform",
        "payload": {
            "id": key_id,
            "status": "SUSPENDED",
            "sourceVersion": 7,
            "organizationId": organization_id,
            "projectId": project_id,
            "environmentId": environment_id,
        },
    }

    assert validator.is_valid(event)
    without_version = json.loads(json.dumps(event))
    del without_version["payload"]["sourceVersion"]
    assert not validator.is_valid(without_version)
    with_secret = json.loads(json.dumps(event))
    with_secret["payload"]["key_hash"] = "a" * 64
    assert not validator.is_valid(with_secret)


def test_developer_key_sync_reports_safe_validation_reason(pipeline_sync_client):
    client, _ = pipeline_sync_client
    from auth_rbac import developer_scope_tenant_id

    organization_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    environment_id = str(uuid.uuid4())
    payload = {
        "key_id": str(uuid.uuid4()),
        "tenant_id": developer_scope_tenant_id(organization_id, project_id, environment_id),
        "organization_id": organization_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "source_version": True,
        "key_hash": "0" * 64,
        "key_prefix": "pgk_test_key",
        "scopes": ["read:analytics"],
        "ip_allowlist": [],
        "status": "ACTIVE",
        "expires_at": None,
    }

    response = _signed_sync_request(client, payload)
    assert response.status_code == 400
    assert response.get_json()["reason"] == "invalid_source_version"

    payload["source_version"] = 1
    payload["ip_allowlist"] = ["not-an-ip-address"]
    response = _signed_sync_request(client, payload)
    assert response.status_code == 400
    assert response.get_json()["reason"] == "invalid_ip_allowlist"
    assert "not-an-ip-address" not in response.get_data(as_text=True)


def test_developer_key_ip_allowlist_is_enforced(pipeline_sync_client):
    client, _ = pipeline_sync_client
    raw_key = "pgk_ip_restricted_key"
    organization_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    environment_id = str(uuid.uuid4())
    from auth_rbac import developer_scope_tenant_id

    payload = {
        "key_id": str(uuid.uuid4()),
        "tenant_id": developer_scope_tenant_id(organization_id, project_id, environment_id),
        "organization_id": organization_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "source_version": 1,
        "key_hash": hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
        "key_prefix": raw_key[:16],
        "scopes": ["read:analytics"],
        "ip_allowlist": ["203.0.113.10"],
        "status": "ACTIVE",
        "expires_at": None,
    }
    assert _signed_sync_request(client, payload).status_code == 200
    response = client.get(
        "/api/v1/lineage/transactions/test-transaction",
        headers={"X-API-Key": raw_key},
        environ_base={"REMOTE_ADDR": "198.51.100.20"},
    )
    assert response.status_code == 403
