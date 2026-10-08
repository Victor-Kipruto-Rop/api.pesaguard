"""Enterprise-grade Authentication and Role-Based Access Control (RBAC) for PesaGuard API.

Role Hierarchy (from most to least privileged):
  1. admin: Full access to all features (settings, users, escalation rules, webhooks)
  2. operator: Read/write discrepancies, view analytics, perform bulk operations
  3. customer-user: Read-only access to discrepancies and analytics (customer portal)
  4. read-only: Read-only viewer access (minimal permissions)

Access tokens expire after at most 15 minutes. Refresh tokens use persisted rotation state.
Auth Required: Default on; controlled via PESAGUARD_API_AUTH_REQUIRED
"""

from __future__ import annotations

from environment import required_env, runtime_environment

import logging
import hashlib
import hmac
import ipaddress
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from threading import Lock
from typing import Any, Dict, List, Optional

import jwt
from flask import g, jsonify, request
from sqlalchemy import Boolean, Column, DateTime, String, Text, and_, create_engine, inspect, or_, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

logger = logging.getLogger("pesaguard.auth_rbac")


def _record_security_event() -> None:
    try:
        from metrics import record_security_event
        record_security_event()
    except Exception:
        logger.debug("Unable to record authentication security metric", exc_info=True)

_INSECURE_DEV_SECRET = "pesaguard-secret-key-change-in-prod"


SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    if (
        os.getenv("PESAGUARD_ALLOW_INSECURE_DEV_SECRET") == "1"
        and runtime_environment() != "production"
    ):
        SECRET_KEY = _INSECURE_DEV_SECRET
        logger.warning(
            "JWT_SECRET_KEY is not set â€” using an insecure dev secret because "
            "PESAGUARD_ALLOW_INSECURE_DEV_SECRET=1. Never use this in production."
        )
    else:
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable is required and was not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
            "and set it as JWT_SECRET_KEY."
        )
if len(SECRET_KEY.encode("utf-8")) < 32:
    raise RuntimeError("JWT_SECRET_KEY must contain at least 32 bytes.")

ALGORITHM = "HS256"
JWT_ISSUER = os.getenv("JWT_ISSUER", "pesaguard")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "pesaguard-api")
TENANT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
JWT_LEEWAY_SECONDS = 30
JWT_ACTIVE_KID = os.getenv("JWT_ACTIVE_KID", "current")
try:
    _configured_keys = json.loads(os.getenv("JWT_KEYS_JSON", "{}"))
except json.JSONDecodeError as exc:
    raise RuntimeError("JWT_KEYS_JSON must be a JSON object mapping key IDs to secrets.") from exc
if not isinstance(_configured_keys, dict) or any(not isinstance(kid, str) or not isinstance(secret, str) for kid, secret in _configured_keys.items()):
    raise RuntimeError("JWT_KEYS_JSON must be a JSON object mapping key IDs to secrets.")
JWT_KEYS = dict(_configured_keys) or {JWT_ACTIVE_KID: SECRET_KEY}
if JWT_ACTIVE_KID not in JWT_KEYS:
    raise RuntimeError("JWT_ACTIVE_KID must identify a configured JWT signing key.")
if any(len(secret.encode("utf-8")) < 32 for secret in JWT_KEYS.values()):
    raise RuntimeError("All configured JWT signing keys must contain at least 32 bytes.")
_JWT_REQUIRED_CLAIMS = [
    "exp",
    "iat",
    "nbf",
    "jti",
    "sub",
    "tenant_id",
    "type",
    "iss",
    "aud",
    "auth_version",
    "scope",
]
_REFRESH_TOKEN_REQUIRED_CLAIMS = [
    "exp",
    "iat",
    "jti",
    "user_id",
    "username",
    "tenant_id",
    "type",
    "iss",
    "aud",
    "auth_version",
    "family_id",
]
try:
    ACCESS_TOKEN_TTL_MINUTES = int(os.getenv("PESAGUARD_ACCESS_TOKEN_TTL_MINUTES", "15"))
except ValueError as exc:
    raise RuntimeError("PESAGUARD_ACCESS_TOKEN_TTL_MINUTES must be an integer from 1 to 15.") from exc
if not 1 <= ACCESS_TOKEN_TTL_MINUTES <= 15:
    raise RuntimeError("PESAGUARD_ACCESS_TOKEN_TTL_MINUTES must be an integer from 1 to 15.")


class AuthenticationUnavailable(RuntimeError):
    """Raised when authentication state cannot be verified safely."""


def _valid_tenant_id(value: Any) -> bool:
    return isinstance(value, str) and bool(TENANT_ID_PATTERN.fullmatch(value))


def developer_scope_tenant_id(organization_id: str, project_id: str, environment_id: str) -> str:
    """Create the canonical Developer Platform tenant partition.

    The IDs must already use lowercase, hyphenated UUID spelling. The digest
    input is UTF-8("developer-platform:v1|<org>|<project>|<environment>").
    """
    try:
        canonical_ids = tuple(
            str(uuid.UUID(value))
            for value in (organization_id, project_id, environment_id)
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("Organization, project, and environment IDs must be UUIDs.") from exc
    if canonical_ids != (organization_id, project_id, environment_id):
        raise ValueError("Organization, project, and environment IDs must be canonical lowercase UUIDs.")
    scope = "developer-platform:v1|" + "|".join(canonical_ids)
    return "dp_" + hashlib.sha256(scope.encode("utf-8")).hexdigest()


def parse_bearer_token(header: str) -> Optional[str]:
    """Parse one bearer token using the same rules across middleware layers."""
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return None
    return parts[1]


def _sanitize_revocation_reason(reason: Optional[str]) -> Optional[str]:
    if reason is None:
        return None
    if not isinstance(reason, str):
        raise ValueError("Revocation reason must be a string.")
    sanitized = "".join(char for char in reason if char in "\t\n" or ord(char) >= 32)
    return sanitized[:512]


def _jwt_signing_key() -> str:
    return JWT_KEYS[JWT_ACTIVE_KID]


def _jwt_verification_key(token: str) -> str:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError:
        raise
    kid = header.get("kid", JWT_ACTIVE_KID)
    key = JWT_KEYS.get(kid)
    if not key:
        raise jwt.InvalidTokenError("Unknown JWT key ID")
    return key


def _session_is_active(session_id: Optional[str], user_id: str, tenant_id: str) -> bool:
    if not session_id:
        return True
    if not isinstance(session_id, str):
        return False
    _ensure_revocation_store_ready()
    session = _RevocationSession()
    try:
        row = session.execute(
            text("SELECT active, state, last_activity_at, expires_at, absolute_expires_at FROM user_sessions WHERE id = :session_id AND user_id = :user_id AND tenant_id = :tenant_id"),
            {"session_id": session_id, "user_id": user_id, "tenant_id": tenant_id},
        ).first()
        if not row or not row[0] or (row[1] or "ACTIVE") != "ACTIVE":
            return False
        now = datetime.now(timezone.utc)
        last_activity = row[2]
        expires_at = row[3]
        absolute_expires_at = row[4]
        for timestamp in (last_activity, expires_at, absolute_expires_at):
            if timestamp is not None and timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        idle_minutes = max(1, int(os.getenv("PESAGUARD_SESSION_IDLE_TIMEOUT_MINUTES", "60")))
        expired = (
            (expires_at is not None and (expires_at.replace(tzinfo=timezone.utc) if expires_at.tzinfo is None else expires_at) <= now)
            or (absolute_expires_at is not None and (absolute_expires_at.replace(tzinfo=timezone.utc) if absolute_expires_at.tzinfo is None else absolute_expires_at) <= now)
            or (last_activity is not None and (last_activity.replace(tzinfo=timezone.utc) if last_activity.tzinfo is None else last_activity) + timedelta(minutes=idle_minutes) <= now)
        )
        if expired:
            session.execute(
                text("UPDATE user_sessions SET active = false, state = 'EXPIRED' WHERE id = :session_id"),
                {"session_id": session_id},
            )
            session.commit()
            return False
        session.execute(
            text("UPDATE user_sessions SET last_activity_at = :last_activity_at WHERE id = :session_id AND state = 'ACTIVE'"),
            {"last_activity_at": now, "session_id": session_id},
        )
        session.commit()
        return True
    except Exception as exc:
        session.rollback()
        # Keep older test/bootstrap schemas readable while production migrations
        # add the lifecycle columns used by the primary path above.
        try:
            legacy_row = session.execute(
                text("SELECT active FROM user_sessions WHERE id = :session_id AND user_id = :user_id AND tenant_id = :tenant_id"),
                {"session_id": session_id, "user_id": user_id, "tenant_id": tenant_id},
            ).first()
            return bool(legacy_row and legacy_row[0])
        except Exception:
            session.rollback()
            raise AuthenticationUnavailable("Session state is unavailable") from exc
    finally:
        session.close()


def _account_authorization_version(user_id: str, tenant_id: str) -> int:
    _ensure_revocation_store_ready()
    session = _RevocationSession()
    try:
        row = session.execute(
            text("SELECT authorization_version FROM user_accounts WHERE id = :user_id AND tenant_id = :tenant_id"),
            {"user_id": user_id, "tenant_id": tenant_id},
        ).first()
        return int(row[0]) if row else 1
    except Exception as exc:
        session.rollback()
        raise AuthenticationUnavailable("Account authorization state is unavailable") from exc
    finally:
        session.close()


def _account_is_active_and_current(user_id: str, tenant_id: str, authorization_version: Any) -> bool:
    _ensure_revocation_store_ready()
    session = _RevocationSession()
    try:
        row = session.execute(
            text("SELECT status, authorization_version FROM user_accounts WHERE id = :user_id AND tenant_id = :tenant_id"),
            {"user_id": user_id, "tenant_id": tenant_id},
        ).first()
        if row is None:
            return False
        return row[0] == "active" and int(row[1]) == authorization_version
    except Exception as exc:
        session.rollback()
        raise AuthenticationUnavailable("Account authorization state is unavailable") from exc
    finally:
        session.close()


def auth_required() -> bool:
    """Allow auth bypass only outside production deployments."""
    environment = runtime_environment()
    if environment in {"production", "prod"}:
        return True
    return os.getenv("PESAGUARD_API_AUTH_REQUIRED", "1") == "1"


def assert_auth_configuration() -> None:
    """Reject an explicitly disabled API auth policy in production."""
    environment = runtime_environment()
    if environment in {"production", "prod"} and os.getenv("PESAGUARD_API_AUTH_REQUIRED", "1") != "1":
        raise RuntimeError("PESAGUARD_API_AUTH_REQUIRED must be enabled in production")

# ----------------------------------------------------------------------------
# Distributed Database Token Revocation Store
# ----------------------------------------------------------------------------
_RevocationBase = declarative_base()


class RevokedToken(_RevocationBase):
    __tablename__ = "revoked_tokens"

    jti = Column(String, primary_key=True)
    revoked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    reason = Column(Text, nullable=True)


class RefreshTokenRecord(_RevocationBase):
    """Persisted refresh-token state used for rotation and reuse detection."""

    __tablename__ = "refresh_token_records"

    jti = Column(String, primary_key=True)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    family_id = Column(String, nullable=False, index=True)
    user_id = Column(String, nullable=False)
    username = Column(String, nullable=False)
    tenant_id = Column(String, nullable=False)
    session_id = Column(String, nullable=True)
    device_id = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    issued_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    family_revoked = Column(Boolean, nullable=False, default=False)


_revocation_engine = None
_RevocationSession = None
_revocation_init_lock = Lock()
_revocation_store_checked = False


def configure_revocation_store(engine, session_factory) -> None:
    """Bind authentication state to the application's primary database session."""
    global _revocation_engine, _RevocationSession, _revocation_store_checked
    with _revocation_init_lock:
        _revocation_engine = engine
        _RevocationSession = session_factory
        _revocation_store_checked = False


def _ensure_revocation_store_ready() -> None:
    """Initialize the revocation store only after its migration has run."""
    global _revocation_engine, _RevocationSession, _revocation_store_checked
    if _RevocationSession is not None and _revocation_store_checked:
        return

    with _revocation_init_lock:
        if _RevocationSession is not None and _revocation_store_checked:
            return
        try:
            if _RevocationSession is None:
                database_url = required_env("DATABASE_URL")
                if database_url.startswith("sqlite"):
                    engine_kwargs = {"connect_args": {"check_same_thread": False}}
                    if database_url in {"sqlite://", "sqlite:///:memory:"}:
                        engine_kwargs["poolclass"] = StaticPool
                    engine = create_engine(database_url, **engine_kwargs)
                else:
                    engine = create_engine(
                        database_url,
                        pool_pre_ping=True,
                        pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
                        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
                    )
                try:
                    from metrics import instrument_engine_query_timing
                    instrument_engine_query_timing(engine)
                except Exception:
                    logger.debug("Revocation store engine query timing instrumentation skipped.", exc_info=True)
                _revocation_engine = engine
                _RevocationSession = sessionmaker(bind=engine, expire_on_commit=False)
            engine = _revocation_engine
            required_tables = {"revoked_tokens", "refresh_token_records", "user_accounts"}
            missing_tables = {
                table_name for table_name in required_tables
                if not inspect(engine).has_table(table_name)
            }
            if missing_tables:
                raise RuntimeError(
                    "Required authentication tables are missing; run database migrations: "
                    + ", ".join(sorted(missing_tables))
                )
            _revocation_store_checked = True
        except Exception as exc:
            raise AuthenticationUnavailable("Authentication state is unavailable") from exc


class User:
    """Represents an authenticated user principal with roles and computed permissions."""

    def __init__(
        self,
        user_id: str,
        username: str,
        tenant_id: str,
        roles: List[str],
        permissions: List[str],
        organization_id: Optional[str] = None,
        session_id: Optional[str] = None,
        principal_type: str = "user",
        api_key_ip_allowlist: Optional[List[str]] = None,
    ):
        self.user_id = user_id
        self.username = username
        self.tenant_id = tenant_id
        self.organization_id = organization_id
        self.roles = roles
        self.permissions = permissions
        self.session_id = session_id
        self.principal_type = principal_type
        self.api_key_ip_allowlist = api_key_ip_allowlist or []


class IdentityAccessService:
    """Simple identity-factory used by external IdP integrations and policy enforcement."""

    @staticmethod
    def create_principal(
        user_id: str,
        username: str,
        tenant_id: str,
        roles: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
        organization_id: Optional[str] = None,
    ) -> User:
        normalized_roles = []
        for role in (roles or []):
            if not isinstance(role, str):
                raise ValueError("Roles must contain only strings.")
            normalized = AuthRBAC.normalize_role_name(role)
            if normalized is None:
                raise ValueError(f"Unknown role: {role}")
            if normalized not in normalized_roles:
                normalized_roles.append(normalized)
        if not normalized_roles:
            normalized_roles = ["read-only"]

        role_permissions = set(AuthRBAC._get_permissions_for_roles(normalized_roles))
        if permissions is None:
            trusted_permissions = sorted(role_permissions)
        else:
            if not isinstance(permissions, list) or not all(isinstance(permission, str) for permission in permissions):
                raise ValueError("Permissions must be a list of permission strings.")
            trusted_permissions = sorted(role_permissions.intersection(set(permissions)))

        return User(
            user_id=user_id,
            username=username,
            tenant_id=tenant_id,
            roles=normalized_roles,
            permissions=trusted_permissions,
            organization_id=organization_id,
        )


class AuthRBAC:
    """Authentication, JWT lifecycle, and Role-Based Access Control manager."""

    ACCESS_TOKEN_TTL_MINUTES = ACCESS_TOKEN_TTL_MINUTES

    ROLE_PERMISSIONS: Dict[str, List[str]] = {
        "owner": [
            "read:discrepancies",
            "write:discrepancies",
            "delete:discrepancies",
            "read:analytics",
            "write:escalation_rules",
            "read:settings",
            "write:settings",
            "manage:webhooks",
            "manage:users",
            "manage:on_call",
            "manage:settings",
            "manage:organizations",
            "manage:teams",
            "manage:departments",
            "manage:billing",
            "manage:providers",
            "read:providers",
            "read:usage",
            "bulk:operations",
            "read:metrics",
            "send:communications",
            "read:communications",
            "export:communications",
            "manage:api_keys",
            "manage:mfa",
            "manage:all_tenants",
            "manage:tenant_isolation",
            "manage:security",
            "manage:sso",
        ],
        "admin": [
            "read:discrepancies",
            "write:discrepancies",
            "delete:discrepancies",
            "read:analytics",
            "write:escalation_rules",
            "read:settings",
            "write:settings",
            "manage:webhooks",
            "manage:users",
            "manage:on_call",
            "manage:settings",
            "manage:organizations",
            "manage:teams",
            "manage:departments",
            "manage:billing",
            "manage:providers",
            "read:providers",
            "read:usage",
            "bulk:operations",
            "read:metrics",
            "send:communications",
            "read:communications",
            "export:communications",
            "manage:api_keys",
            "manage:mfa",
            "manage:sso",
        ],
        "finance": [
            "read:discrepancies",
            "read:analytics",
            "read:settings",
            "read:providers",
            "read:usage",
            "read:metrics",
            "export:communications",
            "read:reports",
            "read:transactions",
            "read:revenue",
        ],
        "operations": [
            "read:discrepancies",
            "write:discrepancies",
            "read:analytics",
            "read:settings",
            "read:providers",
            "read:usage",
            "bulk:operations",
            "read:metrics",
            "read:transactions",
        ],
        "analyst": [
            "read:discrepancies",
            "read:analytics",
            "read:settings",
            "read:providers",
            "read:usage",
            "read:metrics",
            "read:reports",
            "read:transactions",
        ],
        "auditor": [
            "read:discrepancies",
            "read:analytics",
            "read:settings",
            "read:providers",
            "read:usage",
            "read:metrics",
            "read:reports",
            "read:transactions",
            "read:audit_logs",
            "read:revenue",
        ],
        "read-only": [
            "read:discrepancies",
            "read:analytics",
            "read:providers",
            "read:usage",
        ],
        "platform-admin": [
            "read:discrepancies",
            "write:discrepancies",
            "delete:discrepancies",
            "read:analytics",
            "write:escalation_rules",
            "read:settings",
            "write:settings",
            "manage:webhooks",
            "manage:users",
            "manage:on_call",
            "manage:settings",
            "manage:organizations",
            "manage:teams",
            "manage:departments",
            "manage:billing",
            "manage:providers",
            "read:providers",
            "read:usage",
            "bulk:operations",
            "read:metrics",
            "send:communications",
            "read:communications",
            "export:communications",
            "manage:api_keys",
            "manage:mfa",
            "manage:all_tenants",
            "manage:sso",
        ],
        "operator": [
            "read:discrepancies",
            "write:discrepancies",
            "read:analytics",
            "read:providers",
            "read:settings",
            "manage:teams",
            "manage:departments",
            "read:usage",
            "bulk:operations",
            "read:metrics",
        ],
        "customer-user": [
            "read:discrepancies",
            "read:analytics",
            "read:providers",
            "read:settings",
            "read:usage",
        ],
        "org-admin": [
            "manage:organizations",
            "manage:teams",
            "manage:departments",
            "manage:billing",
            "read:usage",
            "read:settings",
            "write:settings",
        ],
        "org-manager": [
            "manage:teams",
            "manage:departments",
            "read:usage",
            "read:settings",
        ],
        "department-admin": [
            "manage:departments",
            "read:usage",
            "read:settings",
        ],
    }

    @classmethod
    def normalize_role_name(cls, role: Optional[str]) -> Optional[str]:
        """Canonicalize names like "Customer User" or "customer-user" into internal names."""
        if role is None:
            return None
        normalized = str(role).strip().lower().replace(" ", "-").replace("_", "-")
        normalized = normalized.replace("/", "-")
        if normalized in {"customer-user", "customer_user"}:
            return "customer-user"
        if normalized in {"read-only", "read_only"}:
            return "read-only"
        if normalized in {"customeruser"}:
            return "customer-user"
        if normalized in {"org-admin", "org_admin"}:
            return "org-admin"
        if normalized in {"org-manager", "org_manager"}:
            return "org-manager"
        if normalized in {"department-admin", "department_admin"}:
            return "department-admin"
        if normalized in {"admin", "platform-admin", "operator", "read-only", "customer-user", "org-admin", "org-manager", "department-admin"}:
            return normalized
        return normalized if normalized in cls.ROLE_PERMISSIONS else None

    @classmethod
    def _normalize_roles_for_token(cls, roles: List[str]) -> List[str]:
        if not isinstance(roles, list) or not roles:
            raise ValueError("Roles must be a non-empty list.")
        normalized_roles = []
        for role in roles:
            if not isinstance(role, str):
                raise ValueError("Roles must contain only strings.")
            normalized = cls.normalize_role_name(role)
            if normalized is None:
                raise ValueError(f"Unknown role: {role}")
            if normalized not in normalized_roles:
                normalized_roles.append(normalized)
        return normalized_roles

    @staticmethod
    def normalize_machine_scopes(scopes: List[str]) -> List[str]:
        """Normalize machine scopes against the least-privilege registry.

        Deny by default, split by failure class:

        - REJECTED (raises ValueError): malformed input, wildcards, internal
          and privileged namespaces, machine-denied privileges, and scopes
          absent from Core's customer scope registry.
        """
        if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
            raise ValueError("Machine scopes must be a list of strings.")
        if not scopes:
            raise ValueError("Machine scopes must be a non-empty list.")
        try:
            from pesaguard_backend_pipeline.authorization_policy import (
                CORE_PERMISSIONS,
                MACHINE_DENIED,
                is_forbidden_customer_scope,
            )
        except ImportError:
            from authorization_policy import (
                CORE_PERMISSIONS,
                MACHINE_DENIED,
                is_forbidden_customer_scope,
            )
        normalized = set()
        for scope in scopes:
            value = scope.strip()
            if not value or value.count(":") != 1:
                raise ValueError("Machine scopes must use resource:action or action:resource form.")
            left, right = (part.strip() for part in value.split(":", 1))
            if not left or not right:
                raise ValueError("Machine scopes must use resource:action or action:resource form.")
            route_ordered = f"{left}:{right}"
            reverse_ordered = f"{right}:{left}"
            for candidate in (route_ordered, reverse_ordered):
                if is_forbidden_customer_scope(candidate):
                    raise ValueError(
                        f"Machine scope is not grantable to customers: {candidate}"
                    )
                if candidate in MACHINE_DENIED:
                    raise ValueError(
                        f"Machine scope is restricted to human roles: {candidate}"
                    )
            chosen = route_ordered if route_ordered in CORE_PERMISSIONS else (
                reverse_ordered if reverse_ordered in CORE_PERMISSIONS else None)
            if chosen is None:
                raise ValueError("Machine scope is not present in Core's customer scope registry.")
            normalized.add(chosen)
        return sorted(normalized)

    @classmethod
    def generate_machine_access_token(
        cls,
        principal_id: str,
        principal_type: str,
        tenant_id: str,
        authorization_version: int,
        scopes: List[str],
    ) -> str:
        """Issue a short-lived access token for a persisted service or API-client identity."""
        if principal_type not in {"service", "api_client"}:
            raise ValueError("Unsupported machine principal type.")
        if not isinstance(principal_id, str) or not principal_id.strip():
            raise ValueError("principal_id must be a non-empty string.")
        if not _valid_tenant_id(tenant_id):
            raise ValueError("tenant_id must match the configured tenant ID format.")
        permissions = cls.normalize_machine_scopes(scopes)
        now = datetime.now(timezone.utc)
        payload = {
            "type": "access",
            "principal_type": principal_type,
            "principal_id": principal_id,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "sub": principal_id,
            "user_id": principal_id,
            "username": f"{principal_type}:{principal_id}",
            "tenant_id": tenant_id,
            "auth_version": int(authorization_version),
            "jti": str(uuid.uuid4()),
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES),
            "scope": " ".join(permissions),
            "permissions": permissions,
            "roles": [],
        }
        return jwt.encode(payload, _jwt_signing_key(), algorithm=ALGORITHM, headers={"kid": JWT_ACTIVE_KID})

    @classmethod
    def _verify_machine_principal(
        cls,
        principal_type: str,
        principal_id: str,
        tenant_id: str,
        authorization_version: Any,
        token_permissions: Any,
    ) -> Optional[User]:
        """Resolve current machine-identity status and scopes for every authenticated request."""
        if not isinstance(token_permissions, list) or not all(
            isinstance(permission, str) for permission in token_permissions
        ):
            return None
        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            try:
                from pesaguard_backend_pipeline.models import ApiClientIdentity, ServiceIdentity
            except ImportError:
                from models import ApiClientIdentity, ServiceIdentity

            if principal_type == "service":
                record = session.query(ServiceIdentity).filter_by(
                    id=principal_id, tenant_id=tenant_id, status="active"
                ).first()
                if record is None or record.authorization_version != authorization_version:
                    return None
                current_scopes = record.scopes or []
            elif principal_type == "api_client":
                record = session.query(ApiClientIdentity).filter_by(
                    id=principal_id, tenant_id=tenant_id, status="active"
                ).first()
                if record is None:
                    return None
                attributes = record.attributes or {}
                if int(attributes.get("authorization_version", 1)) != authorization_version:
                    return None
                current_scopes = record.scopes or []
                if record.service_identity_id:
                    service = session.query(ServiceIdentity).filter_by(
                        id=record.service_identity_id, tenant_id=tenant_id, status="active"
                    ).first()
                    if service is None:
                        return None
                    current_scopes = sorted(set(current_scopes).intersection(service.scopes or []))
            else:
                return None
            allowed_permissions = set(cls.normalize_machine_scopes(current_scopes))
            permissions = sorted(set(token_permissions).intersection(allowed_permissions))
            if set(token_permissions) != set(permissions):
                return None
            principal = User(
                user_id=principal_id,
                username=f"{principal_type}:{principal_id}",
                tenant_id=tenant_id,
                roles=[],
                permissions=permissions,
                principal_type=principal_type,
            )
            principal.permissions = sorted(
                set(principal.permissions).union(cls._assigned_role_permissions(principal))
            )
            return principal
        except (TypeError, ValueError):
            logger.warning("Machine identity has invalid authorization state", exc_info=True)
            return None
        except Exception as exc:
            session.rollback()
            logger.exception("Failed to verify machine identity status")
            raise AuthenticationUnavailable("Machine identity authentication is unavailable") from exc
        finally:
            session.close()

    @classmethod
    def generate_token(
        cls,
        user_id: str,
        username: str,
        tenant_id: str,
        roles: List[str],
        session_id: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> str:
        """Generate a short-lived access JWT with explicit security claims and minimal payload data."""
        if not _valid_tenant_id(tenant_id):
            raise ValueError("tenant_id must match the configured tenant ID format.")
        authorization_version = _account_authorization_version(user_id, tenant_id)
        normalized_roles = cls._normalize_roles_for_token(roles)
        permissions = cls._get_permissions_for_roles(normalized_roles)
        now = datetime.now(timezone.utc)
        jti = str(uuid.uuid4())
        token_scope = " ".join(sorted(permissions))
        payload = {
            "type": "access",
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "sub": user_id,
            "auth_version": authorization_version,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "jti": jti,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES),
            "scope": token_scope,
        }
        if organization_id:
            payload["organization_id"] = str(organization_id)
        if session_id:
            payload["session_id"] = str(session_id)
        if username:
            payload["username"] = username
        if normalized_roles:
            payload["roles"] = normalized_roles
        if permissions:
            payload["permissions"] = permissions
        return jwt.encode(payload, _jwt_signing_key(), algorithm=ALGORITHM, headers={"kid": JWT_ACTIVE_KID})

    @classmethod
    def generate_refresh_token(
        cls,
        user_id: str,
        username: str,
        tenant_id: str,
        roles: List[str],
        session_id: Optional[str] = None,
        family_id: Optional[str] = None,
        device_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> str:
        """Generate and persist a refresh token in a revocable token family."""
        if not _valid_tenant_id(tenant_id):
            raise ValueError("tenant_id must match the configured tenant ID format.")
        authorization_version = _account_authorization_version(user_id, tenant_id)
        normalized_roles = cls._normalize_roles_for_token(roles)
        permissions = cls._get_permissions_for_roles(normalized_roles)
        now = datetime.now(timezone.utc)
        token_jti = str(uuid.uuid4())
        token_family_id = family_id or str(uuid.uuid4())
        expires_at = now + timedelta(days=30)
        payload = {
            "type": "refresh",
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "auth_version": authorization_version,
            "user_id": user_id,
            "username": username,
            "tenant_id": tenant_id,
            "roles": normalized_roles,
            "permissions": permissions,
            "jti": token_jti,
            "family_id": token_family_id,
            "iat": now,
            "exp": expires_at,
        }
        if session_id:
            payload["session_id"] = str(session_id)
        if device_id:
            payload["device_id"] = str(device_id)
        token = jwt.encode(payload, _jwt_signing_key(), algorithm=ALGORITHM, headers={"kid": JWT_ACTIVE_KID})
        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            session.add(RefreshTokenRecord(
                jti=token_jti,
                token_hash=cls._hash_refresh_token(token),
                family_id=token_family_id,
                user_id=user_id,
                username=username,
                tenant_id=tenant_id,
                session_id=str(session_id) if session_id else None,
                device_id=str(device_id) if device_id else None,
                user_agent=user_agent,
                ip_address=ip_address,
                issued_at=now,
                expires_at=expires_at,
            ))
            session.commit()
        except Exception:
            session.rollback()
            logger.exception("Failed to persist refresh token state for JTI %s", token_jti)
            raise
        finally:
            session.close()
        return token

    @staticmethod
    def _hash_refresh_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @classmethod
    def verify_token(cls, token: str) -> Optional[User]:
        """Verify JWT signature, expiry, and revocation state to return a User principal."""
        try:
            payload = jwt.decode(
                token,
                _jwt_verification_key(token),
                algorithms=[ALGORITHM],
                issuer=JWT_ISSUER,
                audience=JWT_AUDIENCE,
                leeway=JWT_LEEWAY_SECONDS,
                options={"require": _JWT_REQUIRED_CLAIMS},
            )
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return None

        if payload.get("type", "access") != "access":
            return None

        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti.strip():
            return None
        if cls.is_token_revoked(jti):
            logger.warning("Attempted authentication with revoked JTI: %s", jti)
            return None

        try:
            user_id = payload.get("sub") or payload["user_id"]
            username = payload.get("username") or payload.get("sub") or "unknown-user"
            tenant_id = payload["tenant_id"]
        except KeyError as exc:
            logger.warning("JWT payload missing mandatory claim: %s", exc)
            return None

        if not isinstance(user_id, str) or not user_id.strip():
            logger.warning("JWT payload has invalid user_id claim")
            return None
        if not isinstance(username, str) or not username.strip():
            logger.warning("JWT payload has invalid username claim")
            return None
        if not _valid_tenant_id(tenant_id):
            logger.warning("JWT payload has invalid tenant_id claim")
            return None
        principal_type = payload.get("principal_type")
        if principal_type is not None:
            principal_id = payload.get("principal_id")
            if principal_id != user_id:
                return None
            return cls._verify_machine_principal(
                principal_type,
                principal_id,
                tenant_id,
                payload.get("auth_version"),
                payload.get("permissions"),
            )
        if not _session_is_active(payload.get("session_id"), user_id, tenant_id):
            logger.warning("JWT payload references an inactive or unknown session")
            return None
        if not _account_is_active_and_current(user_id, tenant_id, payload.get("auth_version")):
            logger.warning("JWT payload references a disabled or stale account")
            return None

        roles = payload.get("roles")
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            logger.warning("JWT payload has invalid roles claim")
            return None

        normalized_roles: List[str] = []
        for role in roles:
            normalized = cls.normalize_role_name(role)
            if normalized not in cls.ROLE_PERMISSIONS:
                logger.warning("JWT payload contains unknown role")
                return None
            if normalized not in normalized_roles:
                normalized_roles.append(normalized)

        if not normalized_roles:
            logger.warning("JWT payload contains no valid roles")
            return None

        permissions_claim = payload.get("permissions")
        if permissions_claim is not None and (not isinstance(permissions_claim, list) or not all(isinstance(permission, str) for permission in permissions_claim)):
            logger.warning("JWT payload has invalid permissions claim")
            return None

        trusted_permissions = cls._get_permissions_for_roles(normalized_roles)
        if permissions_claim is not None and any(permission not in trusted_permissions for permission in permissions_claim):
            logger.warning("JWT payload contains permissions not consistent with confirmed roles for user %s", user_id)
            return None

        principal = User(
            user_id=user_id,
            username=username,
            tenant_id=tenant_id,
            roles=normalized_roles,
            permissions=trusted_permissions,
            organization_id=payload.get("organization_id"),
            session_id=payload.get("session_id"),
        )
        principal.permissions = sorted(
            set(principal.permissions).union(cls._assigned_role_permissions(principal))
        )
        return principal

    @classmethod
    def verify_refresh_token(cls, token: str) -> Optional[User]:
        """Verify a refresh JWT and require an active persisted token record."""
        try:
            payload = jwt.decode(
                token,
                _jwt_verification_key(token),
                algorithms=[ALGORITHM],
                issuer=JWT_ISSUER,
                audience=JWT_AUDIENCE,
                leeway=JWT_LEEWAY_SECONDS,
                options={"require": _REFRESH_TOKEN_REQUIRED_CLAIMS},
            )
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return None

        if payload.get("type", "access") != "refresh":
            return None

        jti = payload.get("jti")
        family_id = payload.get("family_id")
        if not isinstance(jti, str) or not jti.strip() or not isinstance(family_id, str):
            return None
        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            record = session.get(RefreshTokenRecord, jti)
            if (
                record is None
                or record.token_hash != cls._hash_refresh_token(token)
                or record.family_id != family_id
                or record.used_at is not None
                or record.revoked_at is not None
                or record.family_revoked
            ):
                return None
        finally:
            session.close()

        if cls.is_token_revoked(jti):
            logger.warning("Attempted authentication with revoked JTI: %s", jti)
            return None

        try:
            user_id = payload["user_id"]
            username = payload["username"]
            tenant_id = payload["tenant_id"]
        except KeyError as exc:
            logger.warning("JWT payload missing mandatory claim: %s", exc)
            return None

        if not isinstance(user_id, str) or not user_id.strip():
            logger.warning("JWT payload has invalid user_id claim")
            return None
        if not isinstance(username, str) or not username.strip():
            logger.warning("JWT payload has invalid username claim")
            return None
        if not _valid_tenant_id(tenant_id):
            logger.warning("JWT payload has invalid tenant_id claim")
            return None
        if not _session_is_active(payload.get("session_id"), user_id, tenant_id):
            logger.warning("JWT payload references an inactive or unknown session")
            return None
        if not _account_is_active_and_current(user_id, tenant_id, payload.get("auth_version")):
            logger.warning("JWT payload references a disabled or stale account")
            return None

        roles = payload.get("roles")
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            logger.warning("JWT payload has invalid roles claim")
            return None

        normalized_roles: List[str] = []
        for role in roles:
            normalized = cls.normalize_role_name(role)
            if normalized not in cls.ROLE_PERMISSIONS:
                logger.warning("JWT payload contains unknown role")
                return None
            if normalized not in normalized_roles:
                normalized_roles.append(normalized)

        if not normalized_roles:
            logger.warning("JWT payload contains no valid roles")
            return None

        permissions_claim = payload.get("permissions")
        if permissions_claim is not None and (not isinstance(permissions_claim, list) or not all(isinstance(permission, str) for permission in permissions_claim)):
            logger.warning("JWT payload has invalid permissions claim")
            return None

        trusted_permissions = cls._get_permissions_for_roles(normalized_roles)
        if permissions_claim is not None and any(permission not in trusted_permissions for permission in permissions_claim):
            logger.warning("JWT payload contains permissions not consistent with confirmed roles for user %s", user_id)
            return None

        return User(
            user_id=user_id,
            username=username,
            tenant_id=tenant_id,
            roles=normalized_roles,
            permissions=trusted_permissions,
        )

    @classmethod
    def rotate_refresh_token(
        cls,
        token: str,
        device_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Optional[tuple[User, str]]:
        """Atomically consume a refresh token and issue its replacement.

        Reuse of a consumed or revoked token revokes every token in its family.
        """
        user = cls.verify_refresh_token(token)
        if user is None:
            try:
                payload = jwt.decode(
                    token,
                    _jwt_verification_key(token),
                    algorithms=[ALGORITHM],
                    issuer=JWT_ISSUER,
                    audience=JWT_AUDIENCE,
                    leeway=JWT_LEEWAY_SECONDS,
                    options={"verify_exp": False, "require": _REFRESH_TOKEN_REQUIRED_CLAIMS},
                )
                family_id = payload.get("family_id")
            except jwt.InvalidTokenError:
                return None
            if isinstance(family_id, str):
                cls._revoke_refresh_family(family_id, "refresh token reuse detected")
            return None

        try:
            payload = jwt.decode(
                token,
                _jwt_verification_key(token),
                algorithms=[ALGORITHM],
                issuer=JWT_ISSUER,
                audience=JWT_AUDIENCE,
                leeway=JWT_LEEWAY_SECONDS,
                options={"require": _REFRESH_TOKEN_REQUIRED_CLAIMS},
            )
        except jwt.InvalidTokenError:
            return None
        family_id = payload["family_id"]
        jti = payload["jti"]
        _ensure_revocation_store_ready()
        session = _RevocationSession()
        now = datetime.now(timezone.utc)
        try:
            record = session.query(RefreshTokenRecord).filter_by(jti=jti).with_for_update().one_or_none()
            if record is None or record.used_at is not None or record.revoked_at is not None or record.family_revoked:
                session.rollback()
                cls._revoke_refresh_family(family_id, "refresh token reuse detected")
                return None
            if record.device_id and record.device_id != device_id:
                session.rollback()
                cls._revoke_refresh_family(family_id, "refresh token device mismatch")
                return None
            record.used_at = now
            record.revoked_at = now
            session.commit()
        finally:
            session.close()

        replacement = cls.generate_refresh_token(
            user_id=user.user_id,
            username=user.username,
            tenant_id=user.tenant_id,
            roles=user.roles,
            session_id=payload.get("session_id"),
            family_id=family_id,
            device_id=device_id or record.device_id,
            user_agent=user_agent or record.user_agent,
            ip_address=ip_address or record.ip_address,
        )
        return user, replacement

    @classmethod
    def _revoke_refresh_family(cls, family_id: str, reason: str) -> None:
        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            now = datetime.now(timezone.utc)
            session.query(RefreshTokenRecord).filter(
                RefreshTokenRecord.family_id == family_id,
                RefreshTokenRecord.family_revoked.is_(False),
            ).update({
                RefreshTokenRecord.family_revoked: True,
                RefreshTokenRecord.revoked_at: now,
            }, synchronize_session=False)
            session.commit()
            logger.warning("Revoked refresh-token family %s: %s", family_id, reason)
        except Exception:
            session.rollback()
            logger.exception("Failed to revoke refresh-token family %s", family_id)
            raise AuthenticationUnavailable("Refresh-token revocation is unavailable")
        finally:
            session.close()

    @classmethod
    def revoke_session_tokens(cls, session_id: str, reason: str = "session revoked") -> None:
        """Revoke all refresh tokens bound to a server-side session."""
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string.")
        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            now = datetime.now(timezone.utc)
            session.query(RefreshTokenRecord).filter(
                RefreshTokenRecord.session_id == session_id,
                RefreshTokenRecord.revoked_at.is_(None),
            ).update({"revoked_at": now}, synchronize_session=False)
            session.commit()
        except Exception as exc:
            session.rollback()
            logger.exception("Failed to revoke refresh tokens for session %s", session_id)
            raise AuthenticationUnavailable("Session revocation is unavailable") from exc
        finally:
            session.close()

    @classmethod
    def _get_permissions_for_roles(cls, roles: List[str]) -> List[str]:
        """Compute the unique set of permission strings for a given list of roles."""
        permissions = set()
        unknown_roles = []
        for role in roles:
            if role in cls.ROLE_PERMISSIONS:
                permissions.update(cls.ROLE_PERMISSIONS[role])
            else:
                unknown_roles.append(role)

        if unknown_roles:
            logger.warning("Unrecognized roles requested during token generation: %s", unknown_roles)
        return sorted(permissions)

    @classmethod
    def is_token_revoked(cls, jti: str) -> bool:
        """Check if a token's JTI exists in the database revocation store."""
        if not isinstance(jti, str) or not jti.strip():
            return True
        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            return session.get(RevokedToken, jti) is not None
        except Exception as exc:
            session.rollback()
            logger.exception("Failed checking token revocation status for JTI %s", jti)
            raise AuthenticationUnavailable("Token revocation status is unavailable") from exc
        finally:
            session.close()

    @classmethod
    def revoke_token(cls, token: str, reason: Optional[str] = None) -> None:
        """Extract a token's JTI and insert it into the distributed revocation table."""
        reason = _sanitize_revocation_reason(reason)
        try:
            payload = jwt.decode(
                token, _jwt_verification_key(token), algorithms=[ALGORITHM],
                options={"verify_exp": False},
            )
        except jwt.InvalidTokenError:
            logger.warning("revoke_token called with unparseable or invalid signature token.")
            return

        jti = payload.get("jti")
        if not jti:
            logger.warning("revoke_token called on token lacking a JTI claim.")
            return

        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            existing = session.get(RevokedToken, jti)
            if not existing:
                session.add(RevokedToken(jti=jti, reason=reason, revoked_at=datetime.now(timezone.utc)))
                session.commit()
                logger.info("Token JTI %s successfully revoked.", jti)
        except Exception as exc:
            logger.exception("Failed to persist token revocation for JTI %s", jti)
            session.rollback()
            raise AuthenticationUnavailable("Token revocation is unavailable") from exc
        finally:
            session.close()

    @classmethod
    def revoke_refresh_token(cls, token: str, reason: str = "refresh token revoked") -> None:
        """Revoke a specific refresh token or an entire refresh family if reuse is detected."""
        try:
            payload = jwt.decode(
                token,
                _jwt_verification_key(token),
                algorithms=[ALGORITHM],
                issuer=JWT_ISSUER,
                audience=JWT_AUDIENCE,
                leeway=JWT_LEEWAY_SECONDS,
                options={"verify_exp": False, "require": ["jti", "family_id"]},
            )
        except jwt.InvalidTokenError:
            return
        family_id = payload.get("family_id")
        if not isinstance(family_id, str):
            return
        cls._revoke_refresh_family(family_id, reason)

    @classmethod
    def revoke_api_key(cls, key_id: str, tenant_id: str, reason: str = "api key revoked") -> None:
        """Mark a tenant API key as no longer trusted."""
        from models import ApiKeyRecord

        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            record = session.query(ApiKeyRecord).filter_by(id=key_id, tenant_id=tenant_id).first()
            if record is not None:
                record.active = False
                record.revoked_at = datetime.now(timezone.utc)
                record.api_metadata = {**(record.api_metadata or {}), "revoked_reason": reason}
                session.commit()
        finally:
            session.close()

    @classmethod
    def revoke_service_credential(cls, credential_id: str, tenant_id: str, reason: str = "service credential revoked") -> None:
        """Mark a workload/service credential as revoked."""
        from models import ServiceCredentialRecord

        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            record = session.query(ServiceCredentialRecord).filter_by(id=credential_id, tenant_id=tenant_id).first()
            if record is not None:
                record.status = "revoked"
                record.revoked_at = datetime.now(timezone.utc)
                record.reason = reason
                record.revoked_by = "system"
                session.commit()
        finally:
            session.close()

    @classmethod
    def revoke_user_access(cls, user_id: str, tenant_id: str, reason: str = "user revocation") -> None:
        """Terminate all sessions, refresh tokens, and per-user credentials for a user."""
        from models import ApiKeyRecord, ServiceCredentialRecord, UserSession

        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            now = datetime.now(timezone.utc)
            for record in session.query(UserSession).filter_by(user_id=user_id, tenant_id=tenant_id).all():
                record.active = False
                record.state = "REVOKED"
                record.revoked_at = now
                try:
                    cls.revoke_session_tokens(record.id, reason=reason)
                except AuthenticationUnavailable:
                    logger.warning("Unable to revoke refresh tokens for revoked session %s", record.id)
            session.query(ApiKeyRecord).filter(
                ApiKeyRecord.tenant_id == tenant_id,
                ApiKeyRecord.active.is_(True),
                ApiKeyRecord.api_metadata.isnot(None),
            ).all()
            for record in session.query(ApiKeyRecord).filter(
                ApiKeyRecord.tenant_id == tenant_id,
                ApiKeyRecord.active.is_(True),
            ).all():
                metadata = record.api_metadata or {}
                if isinstance(metadata, dict) and metadata.get("owner_user_id") == user_id:
                    record.active = False
                    record.revoked_at = now
            for record in session.query(ServiceCredentialRecord).filter(
                ServiceCredentialRecord.tenant_id == tenant_id,
                ServiceCredentialRecord.status == "active",
            ).all():
                metadata = record.credential_metadata or {}
                if isinstance(metadata, dict) and metadata.get("owner_user_id") == user_id:
                    record.status = "revoked"
                    record.revoked_at = now
                    record.reason = reason
                    record.revoked_by = "system"
            session.commit()
        finally:
            session.close()

    @classmethod
    def revoke_device_access(cls, device_id: str, tenant_id: str, reason: str = "device revocation") -> None:
        """End all sessions and refresh tokens associated with a specific device."""
        from models import UserSession

        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            now = datetime.now(timezone.utc)
            records = session.query(UserSession).filter_by(device_id=device_id, tenant_id=tenant_id, active=True).all()
            for record in records:
                record.active = False
                record.state = "REVOKED"
                record.revoked_at = now
                cls.revoke_session_tokens(record.id, reason=reason)
            session.commit()
        finally:
            session.close()

    @classmethod
    def revoke_session_access(cls, session_id: str, tenant_id: Optional[str] = None, reason: str = "session revocation") -> None:
        """Close one specific user session and its refresh family."""
        from models import UserSession

        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            query = session.query(UserSession).filter_by(id=session_id)
            if tenant_id is not None:
                query = query.filter_by(tenant_id=tenant_id)
            record = query.first()
            if record is not None:
                record.active = False
                record.state = "REVOKED"
                record.revoked_at = datetime.now(timezone.utc)
                cls.revoke_session_tokens(record.id, reason=reason)
                session.commit()
        finally:
            session.close()

    @classmethod
    def emergency_global_revocation(cls, reason: str = "emergency global revocation") -> None:
        """Immediately disable all active sessions, refresh tokens, and trusted API credentials."""
        from models import ApiKeyRecord, ServiceCredentialRecord, UserSession

        _ensure_revocation_store_ready()
        session = _RevocationSession()
        try:
            now = datetime.now(timezone.utc)
            for record in session.query(UserSession).filter(UserSession.active.is_(True)).all():
                record.active = False
                record.state = "REVOKED"
                record.revoked_at = now
                cls.revoke_session_tokens(record.id, reason=reason)
            for record in session.query(ApiKeyRecord).filter(ApiKeyRecord.active.is_(True)).all():
                record.active = False
                record.revoked_at = now
            for record in session.query(ServiceCredentialRecord).filter(ServiceCredentialRecord.status == "active").all():
                record.status = "revoked"
                record.revoked_at = now
                record.reason = reason
            session.commit()
        finally:
            session.close()

    @classmethod
    def check_permission(cls, user: User, required_permission: str) -> bool:
        """Check token scopes and active database-backed role assignments."""
        if required_permission in user.permissions:
            return True
        if getattr(user, "principal_type", "") in {"api_key", "developer_api_key"}:
            return False
        return required_permission in cls._assigned_role_permissions(user)

    @classmethod
    def check_resource_permission(cls, user: User, required_permission: str, resource_id: str) -> bool:
        """Check a permission granted for the exact resource or a broader active scope."""
        if cls.check_permission(user, required_permission):
            return True
        if not isinstance(resource_id, str) or not resource_id.strip():
            return False
        return required_permission in cls._assigned_role_permissions(user, resource_id=resource_id)

    @classmethod
    def _assigned_role_permissions(cls, user: User, resource_id: Optional[str] = None) -> set[str]:
        """Resolve active tenant/organization/team/resource role bindings without trusting JWT role data."""
        if getattr(user, "principal_type", "") in {"api_key", "developer_api_key"}:
            return set()
        try:
            try:
                from pesaguard_backend_pipeline.models import (
                    IAMPermission,
                    IAMRole,
                    IAMRoleBinding,
                    IAMRolePermission,
                    OrganizationMembership,
                )
            except ImportError:
                from models import IAMPermission, IAMRole, IAMRoleBinding, IAMRolePermission, OrganizationMembership

            subject_type = getattr(user, "principal_type", "user")
            scope_filters = [
                and_(
                    IAMRoleBinding.scope_type == "tenant",
                    IAMRoleBinding.scope_id == user.tenant_id,
                )
            ]
            if subject_type == "user":
                _ensure_revocation_store_ready()
                membership_session = _RevocationSession()
                try:
                    memberships = membership_session.query(OrganizationMembership).filter_by(
                        tenant_id=user.tenant_id,
                        user_id=user.user_id,
                        active=True,
                    ).all()
                    for membership in memberships:
                        scope_filters.append(and_(
                            IAMRoleBinding.scope_type == "organization",
                            IAMRoleBinding.scope_id == membership.organization_id,
                        ))
                        if membership.team_id:
                            scope_filters.append(and_(
                                IAMRoleBinding.scope_type == "team",
                                IAMRoleBinding.scope_id == membership.team_id,
                            ))
                finally:
                    membership_session.close()
            if resource_id is not None:
                scope_filters.append(and_(
                    IAMRoleBinding.scope_type == "resource",
                    IAMRoleBinding.scope_id == resource_id,
                ))

            _ensure_revocation_store_ready()
            session = _RevocationSession()
            try:
                rows = session.query(IAMPermission.name).join(
                    IAMRolePermission, IAMRolePermission.permission_id == IAMPermission.id
                ).join(
                    IAMRole, IAMRole.id == IAMRolePermission.role_id
                ).join(
                    IAMRoleBinding, IAMRoleBinding.role_id == IAMRole.id
                ).filter(
                    IAMRoleBinding.tenant_id == user.tenant_id,
                    IAMRoleBinding.subject_type == subject_type,
                    IAMRoleBinding.subject_id == user.user_id,
                    IAMRoleBinding.status == "active",
                    IAMRole.status == "active",
                    or_(*scope_filters),
                ).all()
                permissions = set()
                for (name,) in rows:
                    try:
                        permissions.add(cls.normalize_machine_scopes([name])[0])
                    except ValueError:
                        logger.warning("Ignoring malformed database role permission")
                return permissions
            finally:
                session.close()
        except AuthenticationUnavailable:
            raise
        except Exception as exc:
            logger.exception("Failed to resolve database-backed role permissions")
            raise AuthenticationUnavailable("Authorization state is unavailable") from exc

    @classmethod
    def check_tenant_access(cls, user: User, tenant_id: str) -> bool:
        """Verify that a user is scoped to access the specified tenant_id."""
        return _valid_tenant_id(tenant_id) and (
            user.tenant_id == tenant_id or cls.check_permission(user, "manage:all_tenants")
        )

    @classmethod
    def verify_api_key(cls, api_key: str) -> Optional[User]:
        """Verify a tenant-scoped API key and return a constrained principal."""
        if not isinstance(api_key, str) or not api_key.startswith(("pk_", "pgk_")):
            return None

        _ensure_revocation_store_ready()
        try:
            from pesaguard_backend_pipeline.models import ApiKeyRecord
        except ImportError:
            from models import ApiKeyRecord

        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        session = _RevocationSession()
        try:
            record = session.query(ApiKeyRecord).filter(
                ApiKeyRecord.key_hash == key_hash,
                ApiKeyRecord.active.is_(True),
                ApiKeyRecord.revoked_at.is_(None),
            ).first()
            now = datetime.now(timezone.utc)
            if record is None or (record.expires_at is not None and record.expires_at <= now):
                return None

            scopes = record.scopes or []
            if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
                return None
            try:
                normalized_scopes = cls.normalize_machine_scopes(scopes)
            except (TypeError, ValueError):
                logger.warning("API key %s contains invalid scopes", record.id)
                return None
            metadata = record.api_metadata or {}
            if not isinstance(metadata, dict):
                return None
            is_developer_key = metadata.get("source") == "developer-platform"
            if is_developer_key:
                ip_allowlist = metadata.get("ip_allowlist", [])
                if not isinstance(ip_allowlist, list) or not all(
                    isinstance(network, str) for network in ip_allowlist
                ):
                    return None
            # The role column is retained for compatibility and display only.
            # Every API key is authorized solely by validated persisted scopes.
            record.last_used_at = now
            session.commit()
            return User(
                user_id=record.id,
                username=f"api-key:{record.key_prefix}",
                tenant_id=record.tenant_id,
                roles=[],
                permissions=normalized_scopes,
                organization_id=metadata.get("organization_id"),
                principal_type="developer_api_key" if is_developer_key else "api_key",
                api_key_ip_allowlist=metadata.get("ip_allowlist", []) if is_developer_key else [],
            )
        except Exception as exc:
            session.rollback()
            logger.exception("Failed to verify API key")
            raise AuthenticationUnavailable("API-key authentication is unavailable") from exc
        finally:
            session.close()


def require_auth(required_permission: Optional[str] = None):
    """Route decorator enforcing JWT bearer token authentication and permission checks."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            authentication_required = auth_required()
            auth_header = request.headers.get("Authorization", "")
            api_key = request.headers.get("X-API-Key", "").strip()
            bearer_token = parse_bearer_token(auth_header) if auth_header else None
            if bearer_token and bearer_token.startswith("pgk_"):
                if api_key:
                    return jsonify({"error": "ambiguous_authentication", "message": "Use either bearer or API-key authentication, not both."}), 400
                api_key = bearer_token

            if api_key and (not auth_header or (bearer_token and bearer_token.startswith("pgk_"))):
                user = getattr(g, "user", None) or AuthRBAC.verify_api_key(api_key)
                if user is None:
                    _record_security_event()
                    return jsonify({"error": "invalid_api_key", "message": "API key is invalid, expired, or revoked."}), 401
            elif not auth_header:
                if not authentication_required:
                    return f(*args, **kwargs)
                _record_security_event()
                return jsonify({"error": "missing_auth_header", "message": "Authorization header is required."}), 401

            else:
                user = getattr(g, "user", None)
                if user is None:
                    token = parse_bearer_token(auth_header)
                    if token is None:
                        _record_security_event()
                        return jsonify({"error": "invalid_auth_header", "message": "Malformed Authorization header format."}), 401
                    try:
                        user = AuthRBAC.verify_token(token)
                    except AuthenticationUnavailable:
                        _record_security_event()
                        return jsonify({
                            "error": "authentication_unavailable",
                            "message": "Authentication state is temporarily unavailable.",
                        }), 503
            if not user:
                _record_security_event()
                return jsonify({"error": "invalid_token", "message": "Token is invalid, expired, or revoked."}), 401

            if getattr(user, "principal_type", "") == "developer_api_key" and user.api_key_ip_allowlist:
                try:
                    from security_helpers import get_client_ip

                    client_ip = ipaddress.ip_address(get_client_ip(request))
                    ip_permitted = any(
                        client_ip in ipaddress.ip_network(network, strict=False)
                        for network in user.api_key_ip_allowlist
                    )
                except ValueError:
                    ip_permitted = False
                if not ip_permitted:
                    _record_security_event()
                    return jsonify({"error": "ip_not_allowed", "message": "This API key is not allowed from this IP address."}), 403

            if required_permission:
                try:
                    permitted = AuthRBAC.check_permission(user, required_permission)
                except AuthenticationUnavailable:
                    _record_security_event()
                    return jsonify({
                        "error": "authorization_unavailable",
                        "message": "Authorization state is temporarily unavailable.",
                    }), 503
                if not permitted:
                    _record_security_event()
                    # Safe denial: internal reason stays server-side; the
                    # caller learns only the mapped public error code.
                    try:
                        from pesaguard_backend_pipeline.authorization_policy import (
                            safe_public_error,
                        )
                    except ImportError:
                        from authorization_policy import safe_public_error
                    internal_reason = (
                        "missing_scope"
                        if required_permission not in user.permissions
                        else "resource_denied"
                    )
                    logger.warning(
                        "authorization.denied reason=%s user=%s permission=%s",
                        user.user_id, internal_reason, required_permission,
                    )
                    public_error = safe_public_error(internal_reason)
                    status = 403
                    return jsonify({"error": public_error, "message": "Access denied."}), status

            g.user = user
            try:
                from logging_utils import bind_observability_context
                bind_observability_context(tenant_id=user.tenant_id)
            except Exception:
                logger.debug("Unable to bind authenticated observability context", exc_info=True)
            return f(*args, **kwargs)

        setattr(decorated_function, "required_permission", required_permission)
        return decorated_function

    return decorator


def require_tenant_access():
    """Route decorator enforcing strict tenant boundary isolation matching the caller context."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, "user") or g.user is None:
                return jsonify({"error": "not_authenticated", "message": "Authentication required."}), 401

            json_payload = request.get_json(silent=True) or {}
            tenant_id = (
                (request.view_args or {}).get("tenant_id")
                or json_payload.get("tenant_id")
                or request.args.get("tenant_id")
            )

            if not tenant_id:
                return jsonify({"error": "missing_tenant_id", "message": "tenant_id parameter is required."}), 400

            if not _valid_tenant_id(tenant_id):
                return jsonify({"error": "invalid_tenant_id", "message": "tenant_id has an invalid format."}), 400

            try:
                tenant_access = AuthRBAC.check_tenant_access(g.user, tenant_id)
            except AuthenticationUnavailable:
                _record_security_event()
                return jsonify({
                    "error": "authorization_unavailable",
                    "message": "Authorization state is temporarily unavailable.",
                }), 503
            if not tenant_access:
                _record_security_event()
                logger.warning("Tenant access violation attempt by user %s on tenant %s", g.user.user_id, tenant_id)
                return jsonify({"error": "tenant_access_denied", "message": "Access to this tenant scope is forbidden."}), 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_resource_access(required_permission: str, resource_id_argument: str = "resource_id"):
    """Enforce permission + tenant ownership bound to the exact resource ID.

    Deny by default: missing auth -> 401 authentication_required; missing
    scope -> 403 insufficient_scope; tenant/resource mismatch -> 404
    resource_not_found (no existence oracle); internal details stay in logs.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, "user", None)
            resource_id = kwargs.get(resource_id_argument) or (request.view_args or {}).get(resource_id_argument)
            if user is None:
                return jsonify({"error": "authentication_required", "message": "Authentication is required."}), 401
            if not isinstance(resource_id, str) or not resource_id.strip():
                return jsonify({"error": "resource_not_found", "message": "The requested resource was not found."}), 404
            try:
                permitted = AuthRBAC.check_resource_permission(user, required_permission, resource_id)
            except AuthenticationUnavailable:
                _record_security_event()
                return jsonify({
                    "error": "authorization_unavailable",
                    "message": "Authorization state is temporarily unavailable.",
                }), 503
            if not permitted:
                _record_security_event()
                logger.warning(
                    "authorization.denied reason=resource_denied user=%s permission=%s",
                    getattr(user, "user_id", "unknown"), required_permission,
                )
                if not AuthRBAC.check_permission(user, required_permission):
                    return jsonify({"error": "insufficient_scope", "message": "The credential lacks the required scope."}), 403
                return jsonify({"error": "resource_not_found", "message": "The requested resource was not found."}), 404
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_current_user() -> Optional[User]:
    """Retrieve the authenticated User principal from the Flask request context."""
    return getattr(g, "user", None)
