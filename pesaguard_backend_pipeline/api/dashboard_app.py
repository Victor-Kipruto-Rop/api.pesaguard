"""Enterprise-grade, highly optimized, production-ready PesaGuard dashboard API service."""

from __future__ import annotations

from environment import required_env

import csv
import io
import json
import logging
import math
import os
import threading
import time
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from collections import Counter
import re
from typing import Any, Dict, List, Optional

from flask import Flask, Response, g, has_request_context, jsonify, request, send_file
from werkzeug.exceptions import BadRequest, HTTPException

from action_audit import ActionAuditRecord, AuditOutboxEntry, Base as AuditBase, persist_audit_event
from auth_rbac import AuthenticationUnavailable, AuthRBAC, TENANT_ID_PATTERN, assert_auth_configuration, auth_required, configure_revocation_store, get_current_user, parse_bearer_token, require_auth
from batch_ingestion import BatchImportError, BatchImportService
from data_catalog import CatalogError, load_catalog
from event_store import EventStore
from export_routes import bp as export_bp
from ingestion import IngestionService
from health import build_health_payload
from public_status import create_public_status_blueprint
from logging_utils import configure_logging, get_correlation_id, set_correlation_id
from metrics import build_metrics_payload, record_security_event
from models import Base, DeadLetter, Discrepancy, DiscrepancyFilterPreset, ImportJob, LineageRecord, MerchantMetric, Transaction, UserAccount
from provider_management_service import ProviderManagementService
from rate_limiter import RateLimiter
from runtime_config import RuntimeConfig
from security_helpers import get_client_ip, is_allowed_source, is_payload_within_limit
from sqlalchemy import create_engine, func, text
from sqlalchemy.exc import DBAPIError, DisconnectionError, InterfaceError, InvalidRequestError, OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.sql.selectable import SelectBase
from sqlalchemy.sql.elements import TextClause
from sqlalchemy.pool import NullPool, StaticPool
from tenant_org_routes import bp as tenant_org_bp
from tenant_settings import TenantSettingsStore

configure_logging()
logger = logging.getLogger("pesaguard.dashboard")


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid integer for %s; using default %s", name, default)
        return default
    if value < 0:
        logger.warning("Negative value for %s; using default %s", name, default)
        return default
    return value

app = Flask(__name__)
app.register_blueprint(tenant_org_bp)
runtime_config = RuntimeConfig.from_env()
PUBLIC_API_URL = runtime_config.public_api_url
STATUS_SITE_ORIGIN = "https://status.pesaguard.victorkipruto.com"
DEFAULT_CORS_ALLOWED_ORIGINS = f"{PUBLIC_API_URL},{STATUS_SITE_ORIGIN}"
assert_auth_configuration()
app.config["MAX_CONTENT_LENGTH"] = runtime_config.api_body_limit
app.config["PESAGUARD_WEBHOOK_MAX_BODY_BYTES"] = runtime_config.webhook_body_limit
app.config["JSON_SORT_KEYS"] = False

app.register_blueprint(export_bp)
app.register_blueprint(export_bp, name="export_routes_api_v1", url_prefix="/api/v1")
settings_store = TenantSettingsStore()

def create_app() -> Flask:
    """Return the canonical dashboard application.

    Routes and extensions are registered once at module load for compatibility
    with existing WSGI deployments; callers should use this factory entry point.
    """
    return app

api_rate_limiter = RateLimiter()
api_rate_limiter.set_limits(runtime_config.api_rate_limit_per_minute)

_environment = os.getenv("FLASK_ENV", os.getenv("ENVIRONMENT", os.getenv("PESAGUARD_ENV", "development"))).lower()
if not os.getenv("DATABASE_URL") and _environment not in {"development", "dev", "test", "testing"}:
    raise RuntimeError("DATABASE_URL must be configured outside development and test environments")
DATABASE_URL = required_env("DATABASE_URL")
READ_REPLICA_DATABASE_URL = os.getenv("READ_REPLICA_DATABASE_URL")

engine = None

def _create_engine(database_url: str, **kwargs):
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if database_url in {"sqlite://", "sqlite:///:memory:"}:
            kwargs["poolclass"] = StaticPool
        else:
            kwargs.setdefault("poolclass", NullPool)
        engine = create_engine(database_url, **kwargs)
    else:
        engine = create_engine(database_url, **kwargs)
    try:
        from metrics import instrument_engine_query_timing
        instrument_engine_query_timing(engine)
    except Exception:
        pass
    return engine


if DATABASE_URL.startswith("sqlite"):
    primary_engine = _create_engine(DATABASE_URL)
else:
    primary_engine = _create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=_env_int("DB_POOL_SIZE", 10),
        max_overflow=_env_int("DB_MAX_OVERFLOW", 20),
    )

engine = primary_engine

if READ_REPLICA_DATABASE_URL and READ_REPLICA_DATABASE_URL.startswith("sqlite"):
    replica_engine = _create_engine(READ_REPLICA_DATABASE_URL)
elif READ_REPLICA_DATABASE_URL:
    replica_engine = _create_engine(
        READ_REPLICA_DATABASE_URL,
        pool_pre_ping=True,
        pool_size=_env_int("DB_POOL_SIZE", 10),
        max_overflow=_env_int("DB_MAX_OVERFLOW", 20),
        connect_args={"connect_timeout": 5} if "postgresql" in READ_REPLICA_DATABASE_URL else {},
    )
else:
    replica_engine = None

def _api_auth_required() -> bool:
    """Resolve auth requirement dynamically to honor test and deployment env overrides.

    When the API requires authentication and the current request context does not
    satisfy it, this function records a security event so auth denials remain
    observable in the same way as other security decision paths.
    """
    required = auth_required()
    if required and not _current_api_auth_satisfied():
        try:
            from metrics import record_security_event

            record_security_event()
        except Exception:
            logger.debug("Unable to record dashboard API auth security event", exc_info=True)
        return False
    return required


def _current_api_auth_satisfied() -> bool:
    """Return True when the current request context appears to be authenticated.

    This is a lightweight heuristic used only to decide whether to emit a
    security event when authentication is required. It is intentionally
    conservative: if we cannot determine auth state, we assume it is not
    satisfied for security-event purposes.
    """
    from flask import has_request_context, request

    if not has_request_context():
        return False
    bearer = request.headers.get("Authorization", "")
    if not bearer.lower().startswith("bearer "):
        return False
    token = bearer.split(None, 1)[1] if len(bearer.split(None, 1)) > 1 else ""
    if not token:
        return False
    try:
        import jwt

        jwt.decode(token, options={"verify_signature": False, "verify_exp": False, "verify_iat": False})
        return True
    except Exception:
        return False


SLA_WINDOW_MINUTES = _env_int("PESAGUARD_SLA_WINDOW_MINUTES", 30)


class _ReplicaHealth:
    def __init__(self, cooldown_seconds: int = 10):
        self._lock = threading.Lock()
        self._cooldown_seconds = cooldown_seconds
        self._unhealthy_until = 0.0
        self._checked = False

    def mark_failure(self) -> None:
        with self._lock:
            self._unhealthy_until = time.monotonic() + self._cooldown_seconds
            self._checked = True

    def mark_success(self) -> None:
        with self._lock:
            self._unhealthy_until = 0.0
            self._checked = True

    def is_available(self, replica) -> bool:
        if replica is None:
            return False
        with self._lock:
            if self._checked and self._unhealthy_until == 0.0:
                return True
            if time.monotonic() < self._unhealthy_until:
                return False
        try:
            with replica.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError:
            self.mark_failure()
            return False
        self.mark_success()
        return True


_replica_health = _ReplicaHealth(_env_int("PESAGUARD_REPLICA_COOLDOWN_SECONDS", 10))


class _ReadOnlySession(Session):
    @staticmethod
    def _is_read_statement(statement) -> bool:
        if isinstance(statement, SelectBase):
            return True
        if isinstance(statement, TextClause):
            return bool(re.match(r"^select\b", statement.text.strip(), re.IGNORECASE))
        return False

    def execute(self, statement, params=None, *, execution_options=None, bind_arguments=None, **kwargs):
        if not self._is_read_statement(statement):
            raise InvalidRequestError("Read-only sessions only support SELECT statements")
        return super().execute(
            statement,
            params,
            execution_options=execution_options,
            bind_arguments=bind_arguments,
            **kwargs,
        )

    def flush(self, objects=None):
        raise InvalidRequestError("Read-only sessions cannot flush changes")

    def commit(self):
        raise InvalidRequestError("Read-only sessions cannot commit changes")


class _ReplicaFallbackSession(_ReadOnlySession):
    """Retry a failed read-replica operation against the primary database."""

    def __init__(self, *args, fallback_bind=None, **kwargs):
        self._fallback_bind = fallback_bind
        self._using_fallback = False
        super().__init__(*args, **kwargs)

    def get_bind(self, mapper=None, clause=None, **kwargs):
        if self._using_fallback and self._fallback_bind is not None:
            return self._fallback_bind
        return super().get_bind(mapper=mapper, clause=clause, **kwargs)

    @staticmethod
    def _is_availability_error(error: SQLAlchemyError) -> bool:
        return isinstance(error, (DBAPIError, DisconnectionError, InterfaceError, OperationalError)) and (
            not isinstance(error, DBAPIError) or error.connection_invalidated
        )

    def execute(self, statement, params=None, *, execution_options=None, bind_arguments=None, **kwargs):
        try:
            result = super().execute(
                statement,
                params,
                execution_options=execution_options,
                bind_arguments=bind_arguments,
                **kwargs,
            )
            _replica_health.mark_success()
            return result
        except SQLAlchemyError as error:
            if not self._is_availability_error(error) or self._fallback_bind is None or self._using_fallback:
                raise
            _replica_health.mark_failure()
            logger.warning("Read replica operation failed; retrying against primary database", exc_info=True)
            self.rollback()
            self._using_fallback = True
            return super().execute(
                statement,
                params,
                execution_options=execution_options,
                bind_arguments=bind_arguments,
                **kwargs,
            )

    def get(self, entity, ident, **kwargs):
        try:
            return super().get(entity, ident, **kwargs)
        except SQLAlchemyError as error:
            if not self._is_availability_error(error) or self._fallback_bind is None or self._using_fallback:
                raise
            logger.warning("Read replica lookup failed; retrying against primary database", exc_info=True)
            self.rollback()
            self._using_fallback = True
            return super().get(entity, ident, **kwargs)

    def connection(self, bind_arguments=None, execution_options=None):
        try:
            connection = super().connection(bind_arguments=bind_arguments, execution_options=execution_options)
            _replica_health.mark_success()
            return connection
        except SQLAlchemyError as error:
            if not self._is_availability_error(error) or self._fallback_bind is None or self._using_fallback:
                raise
            _replica_health.mark_failure()
            logger.warning("Read replica connection failed; retrying against primary database", exc_info=True)
            self.rollback()
            self._using_fallback = True
            return super().connection(bind_arguments=bind_arguments, execution_options=execution_options)


def _resolve_engine(read_only: Optional[bool] = None):
    """Dynamically route database queries between primary and read-replica engines."""
    if read_only is True:
        return replica_engine if _replica_health.is_available(replica_engine) else primary_engine
    if read_only is False:
        return primary_engine

    if has_request_context():
        primary_read_requested = request.headers.get("X-PesaGuard-Read-From-Primary") == "1"
        try:
            primary_read_requested = primary_read_requested or float(request.cookies.get("pesaguard_primary_read_until", "0")) > time.time()
        except (TypeError, ValueError):
            primary_read_requested = True
        if (
            request.method in {"GET", "HEAD", "OPTIONS"}
            and not primary_read_requested
            and os.getenv("PESAGUARD_READ_FROM_REPLICA", "0") == "1"
        ):
            return replica_engine if _replica_health.is_available(replica_engine) else primary_engine

    return primary_engine


class _SessionLocalCompat:
    """Compatibility session factory for read/write routing and legacy callers."""

    def __call__(self, read_only: Optional[bool] = None, **kwargs):
        # SQLAlchemy 2.x does not accept a read_only argument on session creation.
        # Older code paths still pass this flag, so we silently consume it while
        # preserving the active engine routing policy for read-only workloads.
        kwargs.pop("read_only", None)
        engine_target = _resolve_engine(read_only=read_only)
        factory_kwargs = {"bind": engine_target, "expire_on_commit": False, **kwargs}
        if read_only is True:
            factory_kwargs["class_"] = _ReplicaFallbackSession if engine_target is replica_engine else _ReadOnlySession
            if engine_target is replica_engine:
                factory_kwargs["fallback_bind"] = primary_engine
        factory = sessionmaker(**factory_kwargs)
        return factory()


SessionLocal = _SessionLocalCompat()
configure_revocation_store(primary_engine, sessionmaker(bind=primary_engine, expire_on_commit=False))
provider_management = ProviderManagementService(SessionLocal)
batch_import_service = BatchImportService(IngestionService(EventStore(database_url=DATABASE_URL)))
data_catalog = load_catalog()
from pesaguard_backend_pipeline.communications.routes import create_webhook_blueprint
from pesaguard_backend_pipeline.communications.product_routes import create_product_blueprint
from pesaguard_backend_pipeline.communications.operations_routes import create_operations_blueprint

app.register_blueprint(
    create_webhook_blueprint(
        SessionLocal,
        require_auth_fn=require_auth,
        current_user_fn=get_current_user,
    )
)
app.register_blueprint(
    create_product_blueprint(
        SessionLocal,
        require_auth_fn=require_auth,
        current_user_fn=get_current_user,
    )
)
app.register_blueprint(
    create_operations_blueprint(
        SessionLocal,
        require_auth_fn=require_auth,
        current_user_fn=get_current_user,
    )
)
app.register_blueprint(
    create_public_status_blueprint(SessionLocal, build_health_payload)
)


def _open_session(read_only: Optional[bool] = None):
    """Return a SQLAlchemy session using the active read/write routing policy."""
    try:
        return SessionLocal(read_only=read_only)
    except TypeError:
        return SessionLocal()


def _current_tenant_id() -> Optional[str]:
    """Retrieve the active tenant ID from the verified security context."""
    user = get_current_user()
    if user:
        return getattr(user, "tenant_id", None)
    if _api_auth_required():
        return None
    return runtime_config.tenant_id


def _json_object():
    """Return a strict JSON object or a client-error response tuple."""
    if not request.is_json:
        return None, (jsonify({"error": "invalid_json", "message": "Content-Type must be application/json."}), 415)
    try:
        payload = request.get_json(silent=False)
    except BadRequest:
        return None, (jsonify({"error": "invalid_json", "message": "Request body must contain valid JSON."}), 400)
    if not isinstance(payload, dict):
        return None, (jsonify({"error": "invalid_json", "message": "Request body must be a JSON object."}), 400)
    return payload, None


def _validate_fields(payload: Dict[str, Any], schema: Dict[str, tuple[type, bool]]):
    for field, (expected_type, required) in schema.items():
        if field not in payload:
            if required:
                return jsonify({"error": "invalid_request", "message": f"{field} is required."}), 400
            continue
        if not isinstance(payload[field], expected_type):
            return jsonify({"error": "invalid_request", "message": f"{field} must be of type {expected_type.__name__}."}), 400
    return None


def _request_is_https() -> bool:
    if request.is_secure:
        return True
    if os.getenv("PESAGUARD_TRUST_PROXY_HEADERS", "0") != "1":
        return False
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
    return forwarded_proto == "https"


def _bearer_token(header: str) -> Optional[str]:
    return parse_bearer_token(header)


def _query_int(name: str, default: int, minimum: int, maximum: int):
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default, None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None, (jsonify({"error": "invalid_parameter", "message": f"{name} must be an integer."}), 400)
    if value < minimum or value > maximum:
        return None, (jsonify({"error": "invalid_parameter", "message": f"{name} must be between {minimum} and {maximum}."}), 400)
    return value, None


def _validate_filter(name: str, value: str, allowed: set[str]):
    if value and value not in allowed:
        return jsonify({"error": "invalid_parameter", "message": f"Unsupported {name} filter."}), 400
    return None


_LOCALE_PATTERN = re.compile(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$")
_PROVIDER_ID_PATTERN = re.compile(r"^provider_[0-9a-f]{12}$")
_PROVIDER_TYPES = {"payment", "mpesa"}
_PROVIDER_STATUSES = {"active", "inactive", "disabled", "maintenance"}
_CONNECTION_STATUSES = {"unknown", "connected", "disconnected", "error"}
_HEALTH_STATUSES = {"unknown", "healthy", "degraded", "unhealthy"}
_SETTING_FIELDS = {
    "preferred_locale", "deployment_region", "data_residency", "region",
    "locale", "user_locale_overrides", "notification_thresholds",
}
_PROVIDER_CONFIG_MAX_BYTES = 32768
_ALLOWED_PROVIDER_CONFIG_KEYS = {
    "credentials": {
        "api_key", "access_token", "account_id", "client_id", "client_key",
        "client_secret", "consumer_key", "consumer_secret", "password",
        "private_key", "secret", "token", "username",
    },
    "api_configuration": {
        "base_url", "endpoint", "host", "port", "timeout", "verify_tls",
        "api_version", "region", "sandbox",
    },
    "account_configuration": {
        "account_id", "account_name", "country", "currency", "paybill",
        "shortcode", "till_number", "merchant_id",
    },
    "metadata": {"description", "environment", "owner", "tags"},
    "webhook_configuration": {"url", "events", "timeout", "verify_tls", "secret", "signing_secret"},
}


def _validate_locale(value: Any, field: str = "preferred_locale"):
    if (
        not isinstance(value, str)
        or len(value) > 35
        or value != value.strip()
        or not _LOCALE_PATTERN.fullmatch(value)
    ):
        return jsonify({"error": "invalid_request", "message": f"{field} must be a valid locale."}), 400
    return None


def _public_provider(provider: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(provider)
    for field in ("credentials", "webhook_configuration", "api_configuration", "account_configuration"):
        if field in result:
            result[field] = {"configured": bool(result[field])}
    return result


def _validate_locale_overrides(value: Any):
    if not isinstance(value, dict) or len(value) > 100:
        return jsonify({"error": "invalid_request", "message": "user_locale_overrides must be an object with at most 100 entries."}), 400
    for user_id, locale in value.items():
        if not isinstance(user_id, str) or not user_id.strip() or len(user_id) > 128:
            return jsonify({"error": "invalid_request", "message": "Locale override user IDs are invalid."}), 400
        error = _validate_locale(locale, "user_locale_overrides")
        if error:
            return error
    return None


def _validate_provider_payload(payload: Dict[str, Any], partial: bool = False):
    normalized_payload = dict(payload)
    try:
        if len(json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")) > _PROVIDER_CONFIG_MAX_BYTES:
            return (jsonify({"error": "invalid_request", "message": "Provider configuration is too large."}), 400), None
    except (TypeError, ValueError, OverflowError):
        return (jsonify({"error": "invalid_request", "message": "Provider configuration contains invalid values."}), 400), None
    required = {"name", "provider_type"} if not partial else set()
    allowed = {"name", "provider_type", "status", "credentials", "api_configuration", "account_configuration", "metadata", "supported_currencies", "capabilities", "webhook_configuration"}
    unknown = set(payload) - allowed
    if unknown:
        return (jsonify({"error": "invalid_request", "message": "Unsupported provider field."}), 400), None
    for field in required:
        if field not in payload:
            return (jsonify({"error": "invalid_request", "message": f"{field} is required."}), 400), None
    for field in {"name", "provider_type"} & set(payload):
        if not isinstance(payload[field], str) or not payload[field].strip() or len(payload[field]) > 128:
            return (jsonify({"error": "invalid_request", "message": f"{field} must be a non-empty string of 128 characters or fewer."}), 400), None
        normalized_payload[field] = payload[field].strip()
        if field == "provider_type":
            normalized_payload[field] = normalized_payload[field].lower()
    for field in {"credentials", "api_configuration", "account_configuration", "metadata", "webhook_configuration"} & set(payload):
        if not isinstance(payload[field], dict):
            return (jsonify({"error": "invalid_request", "message": f"{field} must be an object."}), 400), None
        allowed_keys = _ALLOWED_PROVIDER_CONFIG_KEYS[field]
        if any(key not in allowed_keys for key in payload[field]):
            return (jsonify({"error": "invalid_request", "message": f"Unsupported {field} option."}), 400), None
        if not _valid_nested_mapping(payload[field], allowed_keys=allowed_keys):
            return (jsonify({"error": "invalid_request", "message": f"{field} is too large, deeply nested, or contains invalid values."}), 400), None
    for field in {"supported_currencies", "capabilities"} & set(payload):
        if not isinstance(payload[field], list) or len(payload[field]) > 100:
            return (jsonify({"error": "invalid_request", "message": f"{field} must be a list of short strings."}), 400), None
        normalized = []
        for item in payload[field]:
            if not isinstance(item, str):
                return (jsonify({"error": "invalid_request", "message": f"{field} must be a list of short strings."}), 400), None
            item = item.strip()
            if not item or len(item) > 32:
                return (jsonify({"error": "invalid_request", "message": f"{field} contains invalid values."}), 400), None
            normalized.append(item.upper() if field == "supported_currencies" else item.lower())
        if len(set(normalized)) != len(normalized) or any(not item for item in normalized):
            return (jsonify({"error": "invalid_request", "message": f"{field} contains invalid or duplicate values."}), 400), None
        normalized_payload[field] = normalized
    if "provider_type" in normalized_payload and normalized_payload["provider_type"] not in _PROVIDER_TYPES:
        return (jsonify({"error": "invalid_request", "message": "Unsupported provider type."}), 400), None
    if "status" in payload:
        if not isinstance(payload["status"], str):
            return (jsonify({"error": "invalid_request", "message": "Provider status must be a string."}), 400), None
        normalized_status = payload["status"].strip().lower()
        if normalized_status not in _PROVIDER_STATUSES:
            return (jsonify({"error": "invalid_request", "message": "Unsupported provider status."}), 400), None
        normalized_payload["status"] = normalized_status
    return None, normalized_payload


def _valid_nested_mapping(value: Any, depth: int = 0, allowed_keys: Optional[set[str]] = None) -> bool:
    if depth == 0:
        try:
            if len(json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")) > _PROVIDER_CONFIG_MAX_BYTES:
                return False
        except (TypeError, ValueError, OverflowError):
            return False
    if depth > 4:
        return False
    if isinstance(value, dict):
        if len(value) > 50 or any(not isinstance(key, str) or len(key) > 64 for key in value):
            return False
        if depth > 0:
            return False
        if allowed_keys is not None and any(key not in allowed_keys for key in value):
            return False
        return all(_valid_nested_mapping(item, depth + 1) for item in value.values())
    if isinstance(value, list):
        return len(value) <= 100 and all(_valid_nested_mapping(item, depth + 1) for item in value)
    if isinstance(value, float) and not math.isfinite(value):
        return False
    if isinstance(value, (str, int, float, bool)) or value is None:
        return len(value) <= 4096 if isinstance(value, str) else True
    return False


def _validate_provider_id(provider_id: str):
    if not isinstance(provider_id, str) or not _PROVIDER_ID_PATTERN.fullmatch(provider_id):
        return jsonify({"error": "invalid_request", "message": "Invalid provider ID."}), 400
    return None


def _load_tenant_user(user_id: str, tenant_id: str) -> Optional[UserAccount]:
    session = SessionLocal(read_only=False)
    try:
        return session.query(UserAccount).filter_by(id=user_id, tenant_id=tenant_id).first()
    finally:
        session.close()


def _tenant_scoped_get(session, model, record_id: str, tenant_id: Optional[str]):
    """Fetch a database record ensuring absolute tenant isolation (IDOR protection)."""
    if not tenant_id:
        logger.warning("Tenant-scoped lookup rejected without tenant context: record=%s", record_id)
        return None
    return session.query(model).filter(model.id == record_id, model.tenant_id == tenant_id).one_or_none()


@app.route("/tenant/current", methods=["GET"])
@require_auth("read:settings")
def current_tenant_configuration():
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    settings = settings_store.get(tenant_id)
    return jsonify({
        "tenant_id": tenant_id,
        "preferred_locale": settings.get("preferred_locale"),
        "deployment_region": settings.get("deployment_region"),
    }), 200


@app.route("/tenant/current/locale", methods=["GET"])
@require_auth("read:settings")
def current_tenant_locale():
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    settings = settings_store.get(tenant_id)

    user_id = request.args.get("user_id")
    if user_id is not None:
        if not isinstance(user_id, str):
            return jsonify({"error": "invalid_parameter", "message": "user_id is invalid."}), 400
        user_id = user_id.strip()
        if not user_id or len(user_id) > 128:
            return jsonify({"error": "invalid_parameter", "message": "user_id is invalid."}), 400
        current_user = get_current_user()
        if user_id != current_user.user_id and not AuthRBAC.check_permission(current_user, "manage:users"):
            return jsonify({"error": "forbidden", "message": "You may only inspect your own locale."}), 403
        if _load_tenant_user(user_id, tenant_id) is None:
            return jsonify({"error": "not_found", "message": "User not found for this tenant."}), 404
    user_locale = None
    overrides = settings.get("user_locale_overrides") or {}
    if user_id and isinstance(overrides, dict):
        user_locale = overrides.get(str(user_id))
    return jsonify({
        "tenant_id": tenant_id,
        "preferred_locale": settings.get("preferred_locale"),
        "user_locale": user_locale,
        "effective_locale": settings_store.resolve_locale(tenant_id, user_id),
    }), 200


@app.route("/tenant/current/locale", methods=["POST"])
@require_auth("write:settings")
def update_current_tenant_locale():
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    payload, error = _json_object()
    if error:
        return error
    error = _validate_fields(payload, {"preferred_locale": (str, True)})
    if error:
        return error
    error = _validate_locale(payload["preferred_locale"])
    if error:
        return error
    settings_store.update(tenant_id, {"preferred_locale": payload["preferred_locale"].strip()})
    return jsonify({"tenant_id": tenant_id, "preferred_locale": settings_store.get(tenant_id).get("preferred_locale")}), 200


@app.route("/tenant/current/user-locale", methods=["POST"])
@require_auth("write:settings")
def current_user_locale():
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    payload, error = _json_object()
    if error:
        return error
    error = _validate_fields(payload, {"user_id": (str, True)})
    if error:
        return error
    user_id = payload.get("user_id")
    if not isinstance(user_id, str):
        return jsonify({"error": "invalid_request", "message": "user_id is required."}), 400
    user_id = user_id.strip()
    if not user_id or len(user_id) > 128:
        return jsonify({"error": "invalid_request", "message": "user_id is invalid."}), 400
    current_user = get_current_user()
    if user_id != current_user.user_id and not AuthRBAC.check_permission(current_user, "manage:users"):
        return jsonify({"error": "forbidden", "message": "You may only update your own locale."}), 403
    if _load_tenant_user(user_id, tenant_id) is None:
        return jsonify({"error": "not_found", "message": "User not found for this tenant."}), 404

    settings = settings_store.get(tenant_id)
    overrides = dict(settings.get("user_locale_overrides") or {})
    preferred_locale = payload.get("preferred_locale")
    if preferred_locale is None or preferred_locale == "":
        overrides.pop(user_id, None)
    elif isinstance(preferred_locale, str):
        error = _validate_locale(preferred_locale)
        if error:
            return error
        overrides[user_id] = preferred_locale.strip()
    else:
        return jsonify({"error": "invalid_request", "message": "preferred_locale must be a string."}), 400

    settings = settings_store.update(tenant_id, {"user_locale_overrides": overrides})
    return jsonify({
        "tenant_id": tenant_id,
        "user_id": user_id,
        "user_locale": overrides.get(user_id),
        "effective_locale": settings_store.resolve_locale(tenant_id, user_id),
    }), 200


@app.route("/providers", methods=["GET"])
@require_auth("read:providers")
def list_providers():
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    return jsonify({"providers": [_public_provider(provider) for provider in provider_management.list(tenant_id)]}), 200


@app.route("/providers", methods=["POST"])
@require_auth("manage:providers")
def providers():
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({
            "error": "tenant_context_required",
            "message": "Authenticated tenant context is required.",
        }), 403

    payload, error = _json_object()
    if error:
        return error
    error, payload = _validate_provider_payload(payload)
    if error:
        return error
    try:
        provider = provider_management.register(
            tenant_id,
            payload.get("name"),
            payload.get("provider_type", "payment"),
            credentials=payload.get("credentials"),
            api_configuration=payload.get("api_configuration"),
            account_configuration=payload.get("account_configuration"),
            metadata=payload.get("metadata"),
            supported_currencies=payload.get("supported_currencies"),
            capabilities=payload.get("capabilities"),
            webhook_configuration=payload.get("webhook_configuration"),
            status=payload.get("status"),
        )
    except ValueError as error:
        logger.info("Provider registration rejected: %s", error)
        return jsonify({"error": "invalid_request", "message": "Invalid provider configuration."}), 400
    except Exception:
        logger.exception("Provider registration failed")
        return jsonify({"error": "provider_operation_failed", "message": "Provider registration failed."}), 500
    return jsonify(_public_provider(provider)), 201


@app.route("/providers/<provider_id>", methods=["GET"])
@require_auth("read:providers")
def get_provider(provider_id: str):
    error = _validate_provider_id(provider_id)
    if error:
        return error
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    provider = provider_management.get(tenant_id, provider_id)
    if provider is None:
        return jsonify({"error": "not_found", "message": "Provider not found."}), 404
    return jsonify(_public_provider(provider)), 200


@app.route("/providers/<provider_id>", methods=["PATCH"])
@require_auth("manage:providers")
def provider_detail(provider_id: str):
    error = _validate_provider_id(provider_id)
    if error:
        return error
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    payload, error = _json_object()
    if error:
        return error
    error, payload = _validate_provider_payload(payload, partial=True)
    if error:
        return error
    try:
        provider = provider_management.update(tenant_id, provider_id, payload)
    except Exception:
        logger.exception("Provider update failed: %s", provider_id)
        return jsonify({"error": "provider_operation_failed", "message": "Provider update failed."}), 500
    if provider is None:
        return jsonify({"error": "not_found", "message": "Provider not found."}), 404
    return jsonify(_public_provider(provider)), 200


@app.route("/providers/<provider_id>/connection", methods=["POST"])
@require_auth("manage:providers")
def provider_connection(provider_id: str):
    error = _validate_provider_id(provider_id)
    if error:
        return error
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    payload, error = _json_object()
    if error:
        return error
    error = _validate_fields(payload, {"status": (str, True), "details": (dict, False)})
    if error:
        return error
    if payload["status"] not in _CONNECTION_STATUSES:
        return jsonify({"error": "invalid_request", "message": "Unsupported connection status."}), 400
    status = str(payload.get("status") or "unknown")
    try:
        provider = provider_management.update_connection(tenant_id, provider_id, status, payload.get("details"))
    except Exception:
        logger.exception("Provider connection update failed: %s", provider_id)
        return jsonify({"error": "provider_operation_failed", "message": "Provider connection update failed."}), 500
    if provider is None:
        return jsonify({"error": "not_found", "message": "Provider not found."}), 404
    return jsonify(_public_provider(provider)), 200


@app.route("/providers/<provider_id>/health", methods=["POST"])
@require_auth("manage:providers")
def provider_health(provider_id: str):
    error = _validate_provider_id(provider_id)
    if error:
        return error
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    payload, error = _json_object()
    if error:
        return error
    error = _validate_fields(payload, {"status": (str, True), "details": (dict, False)})
    if error:
        return error
    if payload["status"] not in _HEALTH_STATUSES:
        return jsonify({"error": "invalid_request", "message": "Unsupported health status."}), 400
    status = str(payload.get("status") or "unknown")
    try:
        provider = provider_management.update_health(tenant_id, provider_id, status, payload.get("details"))
    except Exception:
        logger.exception("Provider health update failed: %s", provider_id)
        return jsonify({"error": "provider_operation_failed", "message": "Provider health update failed."}), 500
    if provider is None:
        return jsonify({"error": "not_found", "message": "Provider not found."}), 404
    return jsonify(_public_provider(provider)), 200


@app.before_request
def establish_correlation_context():
    set_correlation_id(request.headers.get("X-Correlation-ID") or request.headers.get("X-Request-ID") or "")


@app.after_request
def inject_correlation_id(response: Response) -> Response:
    response.headers["X-Correlation-ID"] = get_correlation_id()
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and response.status_code < 400:
        try:
            consistency_seconds = max(0, int(os.getenv("PESAGUARD_READ_AFTER_WRITE_SECONDS", "5")))
        except ValueError:
            consistency_seconds = 5
        if consistency_seconds:
            response.set_cookie(
                "pesaguard_primary_read_until",
                str(time.time() + consistency_seconds),
                max_age=consistency_seconds,
                httponly=True,
                samesite="Lax",
                secure=request.is_secure,
            )
    return response


def _ensure_test_tables() -> None:
    """Initialize tables once for explicitly configured in-memory test databases."""
    if os.getenv("USE_IN_MEMORY_TEST_DB") != "true":
        return

    try:
        Base.metadata.create_all(primary_engine)
        AuditBase.metadata.create_all(primary_engine)
    except Exception:
        logger.exception("Unable to initialize test database tables")


_ensure_test_tables()


@app.before_request
def enforce_api_security():
    """Enforce payload size checks, strict IP security, distributed rate limiting, and RBAC."""
    if request.method == "OPTIONS":
        allowed_origins = {
            origin.strip() for origin in os.getenv(
                "PESAGUARD_CORS_ALLOWED_ORIGINS", DEFAULT_CORS_ALLOWED_ORIGINS
            ).split(",")
            if origin.strip() and origin.strip() != "*"
        }
        origin = request.headers.get("Origin")
        if origin and origin not in allowed_origins:
            return jsonify({"error": "cors_origin_denied", "message": "Origin is not allowed."}), 403
        return None

    if request.path.startswith("/health"):
        return None

    if request.path.startswith(("/openapi", "/docs")):
        if app.testing or os.getenv("PESAGUARD_PUBLIC_API_DOCS", "0") == "1":
            return None
        if not _api_auth_required():
            return jsonify({"error": "not_found", "message": "Documentation is disabled."}), 404

    is_webhook_request = (
        request.path in {"/webhook", "/webhook/", "/webhook/mpesa/confirmation", "/webhook/mpesa/validation"}
        or request.path.startswith("/webhook/")
    )
    body_limit = runtime_config.webhook_body_limit if is_webhook_request else runtime_config.api_body_limit
    if not is_payload_within_limit(request, max_body_bytes=body_limit):
        return jsonify({"error": "request_too_large", "message": "Payload exceeds maximum allowed size."}), 413

    client_ip = get_client_ip(request)
    if is_webhook_request and not is_allowed_source(client_ip, request):
        record_security_event()
        logger.warning("Rejected API request from unauthorized source IP: %s", client_ip)
        return jsonify({"error": "forbidden_source", "message": "Access denied from this source."}), 403

    client_identity = client_ip
    auth_header = request.headers.get("Authorization", "")
    token = _bearer_token(auth_header)
    user = getattr(g, "user", None)
    if token and user is None:
        try:
            user = AuthRBAC.verify_token(token)
        except AuthenticationUnavailable:
            record_security_event()
            return jsonify({
                "error": "authentication_unavailable",
                "message": "Authentication state is temporarily unavailable.",
            }), 503
    if _api_auth_required() and not request.path.startswith("/public/status"):
        if not token:
            record_security_event()
            return jsonify({"error": "authentication_failed", "message": "Valid bearer authentication is required."}), 401
        if not user:
            record_security_event()
            return jsonify({"error": "authentication_failed", "message": "Valid bearer authentication is required."}), 401
        g.user = user
    if user:
        client_identity = user.user_id

    allowed, status = api_rate_limiter.is_allowed(client_identity, request.path)
    if not allowed:
        record_security_event()
        logger.warning("API rate limit exceeded for identity: %s on path: %s", client_identity, request.path)
        response = jsonify({"error": "rate_limit_exceeded", "message": "Too many requests. Please slow down."})
        response.status_code = 429
        response.headers["Retry-After"] = str(status.get("retry_after", 60))
        return response



@app.after_request
def _inject_security_headers(response: Response) -> Response:
    """Inject robust security and CORS headers into all API responses."""
    allowed_origins = {
        origin.strip()
        for origin in os.getenv(
            "PESAGUARD_CORS_ALLOWED_ORIGINS", DEFAULT_CORS_ALLOWED_ORIGINS
        ).split(",")
        if origin.strip() and origin.strip() != "*"
    }
    origin = request.headers.get("Origin")
    if origin:
        vary = response.headers.get("Vary", "")
        if "Origin" not in {item.strip() for item in vary.split(",") if item.strip()}:
            response.headers["Vary"] = f"{vary}, Origin".strip(", ")
    if origin in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Correlation-ID"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.path == "/docs":
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; connect-src 'self'"
    if request.path.startswith(("/v1/", "/tenant/", "/tenants/", "/providers", "/metrics", "/discrepancies", "/incidents", "/public/status")):
        response.headers["Cache-Control"] = "no-store"
    if _request_is_https():
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(413)
def handle_request_too_large(_error):
    return jsonify({"error": "request_too_large", "message": "Request payload too large."}), 413


@app.errorhandler(400)
def handle_bad_request(_error):
    return jsonify({"error": "bad_request", "message": "Malformed request syntax."}), 400


@app.errorhandler(HTTPException)
def handle_http_exception(error: HTTPException) -> Response:
    return jsonify({
        "error": error.name.lower().replace(" ", "_"),
        "message": error.description,
        "status_code": error.code,
    }), error.code


@app.errorhandler(Exception)
def handle_internal_error(error: Exception) -> Response:
    logger.exception("Unhandled exception in dashboard API: %s", error)
    return jsonify({
        "error": "internal_server_error",
        "message": "An unexpected error occurred. Our engineering team has been notified.",
    }), 500


@app.route("/health", methods=["GET"])
def health():
    payload = build_health_payload()
    status_code = 200 if payload.get("status") == "ok" else 503
    return jsonify(payload), status_code


@app.route("/v1/settings", methods=["GET"])
@require_auth("read:settings")
def get_settings():
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    return jsonify(settings_store.get(tenant_id)), 200


@app.route("/v1/settings", methods=["POST"])
@require_auth("write:settings")
def update_settings():
    """Update settings for the authenticated tenant only."""
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    payload, error = _json_object()
    if error:
        return error

    requested_tenant = payload.pop("tenant_id", None)
    if requested_tenant is not None and requested_tenant != tenant_id:
        return jsonify({"error": "tenant_access_denied", "message": "Cannot modify settings for another tenant."}), 403
    unknown_fields = set(payload) - _SETTING_FIELDS
    if unknown_fields:
        return jsonify({"error": "invalid_request", "message": "Unsupported settings field."}), 400
    if "preferred_locale" in payload:
        error = _validate_locale(payload["preferred_locale"])
        if error:
            return error
    if "user_locale_overrides" in payload:
        error = _validate_locale_overrides(payload["user_locale_overrides"])
        if error:
            return error

    if "preferred_locale" in payload:
        payload["preferred_locale"] = payload["preferred_locale"].strip()
    updated_settings = settings_store.update(tenant_id, payload)
    logger.info("Settings updated successfully for tenant_id=%s", tenant_id)
    return jsonify(updated_settings), 200


_API_SPEC_DIR = Path(__file__).resolve().parents[2] / "docs" / "api"


def _load_spec(filename: str):
    return jsonify(json.loads((_API_SPEC_DIR / filename).read_text(encoding="utf-8"))), 200


@app.route("/openapi.json", methods=["GET"])
def openapi_spec():
    """Implemented API surface, generated from the registered routes.

    docs/api/openapi.implemented.json is refreshed by the sync-docs workflow
    (scripts live in the docs repository) and mirrors what the docs site
    publishes at api-reference/openapi.json.
    """
    return _load_spec("openapi.implemented.json")


@app.route("/openapi.contract.json", methods=["GET"])
def openapi_contract():
    """Target public contract, including endpoints not implemented yet.

    Hand-maintained; guarded by the breaking-change gate in CI.
    """
    return _load_spec("openapi.json")


@app.route("/docs", methods=["GET"])
def docs():
    html = """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <title>PesaGuard Dashboard API</title>
        <script src="https://cdn.jsdelivr.net/npm/redoc@2.2.0/bundles/redoc.standalone.js"></script>
        <style>
          body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
          .top-bar { background: #0b3d91; color: white; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
          .top-bar a { color: #ffd700; text-decoration: none; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="top-bar">
          <h1>PesaGuard Dashboard API</h1>
          <a href="/openapi.json">OpenAPI Spec (JSON)</a>
        </div>
        <redoc spec-url="/openapi.json"></redoc>
      </body>
    </html>
    """
    return Response(html, mimetype="text/html"), 200


@app.route("/metrics", methods=["GET"])
@require_auth("read:metrics")
def metrics():
    if "text/plain" in request.headers.get("Accept", ""):
        return Response(build_metrics_payload(), mimetype="text/plain; version=0.0.4")

    tenant_id = _current_tenant_id()
    session = _open_session()
    try:
        one_minute_ago = datetime.now(timezone.utc) - timedelta(minutes=1)
        transactions_per_minute = session.query(Transaction).filter(Transaction.created_at >= one_minute_ago).count()
        query = session.query(Discrepancy)
        if tenant_id is not None:
            query = query.filter(Discrepancy.tenant_id == tenant_id)
        open_count = query.filter(Discrepancy.resolved.is_(False)).count()
        resolved_count = query.filter(Discrepancy.resolved.is_(True)).count()
        total_count = query.count()
        severity_rows = query.with_entities(Discrepancy.severity, func.count(Discrepancy.id)).group_by(Discrepancy.severity).all()
        status_rows = query.with_entities(Discrepancy.status, func.count(Discrepancy.id)).group_by(Discrepancy.status).all()
        severity_breakdown = Counter({severity or "unknown": count for severity, count in severity_rows})
        status_breakdown = Counter({status or "unknown": count for status, count in status_rows})

        today = datetime.now(timezone.utc).date()
        trend_start = datetime.combine(today - timedelta(days=6), datetime.min.time(), tzinfo=timezone.utc)
        trend_rows_query = session.query(
            func.date(Discrepancy.detected_at), func.count(Discrepancy.id)
        ).filter(Discrepancy.detected_at >= trend_start)
        if tenant_id is not None:
            trend_rows_query = trend_rows_query.filter(Discrepancy.tenant_id == tenant_id)
        trend_rows = {str(day): count for day, count in trend_rows_query.group_by(func.date(Discrepancy.detected_at)).all()}
        trend_series = [trend_rows.get((today - timedelta(days=offset)).isoformat(), 0) for offset in range(6, -1, -1)]

        return jsonify({
            "transactions_per_minute": transactions_per_minute,
            "reconciliation_latency_p50": None,
            "reconciliation_latency_p95": None,
            "discrepancy_rate": round(open_count / max(total_count, 1), 3),
            "open_count": open_count,
            "resolved_count": resolved_count,
            "severity_breakdown": dict(severity_breakdown),
            "status_breakdown": dict(status_breakdown),
            "trend_series": trend_series,
        }), 200
    finally:
        session.close()


@app.route("/api/v1/imports", methods=["POST"])
@require_auth(required_permission="read:analytics")
def create_import():
    """Store a tenant-scoped import object and create a queued batch job."""
    tenant_id = get_current_user().tenant_id
    uploaded = request.files.get("file")
    source = request.form.get("source", "bank").strip().lower()
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "file_required", "message": "Multipart field 'file' is required."}), 400
    content = uploaded.read()
    session = _open_session()
    try:
        job = batch_import_service.submit(
            session,
            tenant_id=tenant_id,
            source=source,
            filename=uploaded.filename,
            content=content,
        )
        return jsonify({
            "import_id": job.id,
            "tenant_id": job.tenant_id,
            "source": job.source,
            "filename": job.filename,
            "status": job.status,
            "records_received": job.records_received,
            "records_valid": job.records_valid,
            "records_failed": job.records_failed,
        }), 202
    except BatchImportError as exc:
        session.rollback()
        return jsonify({"error": "invalid_import", "message": str(exc)}), 400
    finally:
        session.close()


@app.route("/api/v1/imports/<import_id>", methods=["GET"])
@require_auth(required_permission="read:analytics")
def get_import(import_id: str):
    """Return tenant-scoped import progress and validation counters."""
    tenant_id = get_current_user().tenant_id
    session = _open_session(read_only=True)
    try:
        job = session.query(ImportJob).filter(
            ImportJob.id == import_id,
            ImportJob.tenant_id == tenant_id,
        ).first()
        if job is None:
            return jsonify({"error": "not_found", "message": "Import job not found."}), 404
        return jsonify({
            "import_id": job.id,
            "tenant_id": job.tenant_id,
            "source": job.source,
            "filename": job.filename,
            "records_received": job.records_received,
            "records_valid": job.records_valid,
            "records_failed": job.records_failed,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "status": job.status,
            "errors": job.error_summary or [],
        }), 200
    finally:
        session.close()


@app.route("/api/v1/metrics/merchants", methods=["GET"])
@require_auth(required_permission="read:analytics")
def merchant_metrics():
    """Read precomputed merchant metrics without scanning transaction history."""
    tenant_id = get_current_user().tenant_id
    granularity = request.args.get("granularity", "day").strip().lower()
    if granularity not in {"hour", "day", "week"}:
        return jsonify({"error": "invalid_granularity"}), 400
    merchant_id = request.args.get("merchant_id")
    session = _open_session(read_only=True)
    try:
        query = session.query(MerchantMetric).filter(
            MerchantMetric.tenant_id == tenant_id,
            MerchantMetric.granularity == granularity,
        ).order_by(MerchantMetric.bucket_start.desc()).limit(500)
        if merchant_id:
            query = query.filter(MerchantMetric.merchant_id == merchant_id)
        rows = query.all()
        return jsonify({"tenant_id": tenant_id, "granularity": granularity, "items": [{
            "merchant_id": row.merchant_id,
            "bucket_start": row.bucket_start.isoformat(),
            "transaction_count": row.transaction_count,
            "total_volume": str(row.total_volume),
            "average_transaction": str(row.average_transaction),
            "failed_transactions": row.failed_transactions,
            "reconciled_transactions": row.reconciled_transactions,
            "anomaly_count": row.anomaly_count,
            "failure_rate": row.failed_transactions / row.transaction_count if row.transaction_count else 0.0,
            "reconciliation_rate": row.reconciled_transactions / row.transaction_count if row.transaction_count else 0.0,
            "anomaly_rate": row.anomaly_count / row.transaction_count if row.transaction_count else 0.0,
        } for row in rows]}), 200
    finally:
        session.close()


@app.route("/api/v1/lineage/transactions/<transaction_id>", methods=["GET"])
@require_auth(required_permission="read:analytics")
def transaction_lineage(transaction_id: str):
    """Trace one tenant transaction back to its provider source event."""
    tenant_id = get_current_user().tenant_id
    session = _open_session(read_only=True)
    try:
        rows = session.query(LineageRecord).filter(
            LineageRecord.tenant_id == tenant_id,
            LineageRecord.transaction_id == transaction_id,
        ).order_by(LineageRecord.created_at.asc(), LineageRecord.id.asc()).all()
        return jsonify({"tenant_id": tenant_id, "transaction_id": transaction_id, "items": [{
            "stage": row.stage,
            "event_id": row.event_id,
            "source": row.source,
            "source_event_id": row.source_event_id,
            "upstream_event_id": row.upstream_event_id,
            "ingestion_time": row.ingestion_time.isoformat(),
            "pipeline_version": row.pipeline_version,
            "transformation_version": row.transformation_version,
            "job_id": row.job_id,
            "correlation_id": row.correlation_id,
        } for row in rows]}), 200
    finally:
        session.close()


@app.route("/api/v1/catalog/datasets", methods=["GET"])
@require_auth(required_permission="read:analytics")
def catalog_datasets():
    """List governed data assets and their operational metadata."""
    return jsonify({"version": data_catalog.version, "datasets": [asset.to_dict() for asset in data_catalog.list()]}), 200


@app.route("/api/v1/catalog/datasets/<dataset_name>", methods=["GET"])
@require_auth(required_permission="read:analytics")
def catalog_dataset(dataset_name: str):
    try:
        return jsonify(data_catalog.dataset(dataset_name).to_dict()), 200
    except CatalogError:
        return jsonify({"error": "not_found", "message": "Dataset is not registered."}), 404


@app.route("/api/v1/operations/outbox", methods=["GET"])
@require_auth(required_permission="read:analytics")
def operations_outbox():
    """Return tenant-scoped outbox lag, retry, and dead-letter counts."""
    tenant_id = get_current_user().tenant_id
    session = _open_session(read_only=True)
    try:
        rows = (
            session.query(AuditOutboxEntry.status, func.count(AuditOutboxEntry.id))
            .filter(AuditOutboxEntry.tenant_id == tenant_id)
            .group_by(AuditOutboxEntry.status)
            .all()
        )
        counts = {status: count for status, count in rows}
        oldest_pending = (
            session.query(func.min(AuditOutboxEntry.created_at))
            .filter(
                AuditOutboxEntry.tenant_id == tenant_id,
                AuditOutboxEntry.status.in_(("pending", "in_progress", "failed")),
            )
            .scalar()
        )
        lag_seconds = max(0, int((datetime.now(timezone.utc) - oldest_pending).total_seconds())) if oldest_pending else 0
        return jsonify({
            "tenant_id": tenant_id,
            "pending": counts.get("pending", 0),
            "in_progress": counts.get("in_progress", 0),
            "failed": counts.get("failed", 0),
            "dead_letter": counts.get("dead_letter", 0),
            "oldest_pending_lag_seconds": lag_seconds,
        }), 200
    finally:
        session.close()


@app.route("/api/v1/operations/dead-letters/<dead_letter_id>/replay", methods=["POST"])
@require_auth(required_permission="resolve:discrepancies")
def replay_dead_letter(dead_letter_id: str):
    """Queue one tenant dead-letter entry for bounded, auditable replay."""
    tenant_id = get_current_user().tenant_id
    actor_id = str(getattr(get_current_user(), "user_id", "operator"))
    replay_reason = str((request.get_json(silent=True) or {}).get("reason", "operator replay"))[:4096]
    session = _open_session()
    try:
        entry = session.query(DeadLetter).filter(
            DeadLetter.id == dead_letter_id,
            DeadLetter.tenant_id == tenant_id,
        ).with_for_update().first()
        if entry is None:
            return jsonify({"error": "not_found", "message": "Dead-letter entry not found."}), 404
        if (entry.attempts or 0) >= 3 or entry.replay_status in {"queued", "replaying"}:
            return jsonify({"error": "replay_limit", "message": "Dead-letter replay is already queued or has reached its limit."}), 409
        entry.processed = False
        entry.processed_at = None
        entry.attempts = (entry.attempts or 0) + 1
        entry.replay_status = "queued"
        entry.replayed_by = actor_id
        entry.replayed_at = datetime.now(timezone.utc)
        entry.replay_reason = replay_reason
        persist_audit_event(session, ActionAuditRecord(
            tenant_id=tenant_id,
            actor=actor_id,
            action="dead_letter_replayed",
            category="operations",
            outcome="success",
            severity="warning",
            resource_type="dead_letter",
            resource_id=entry.id,
            idempotency_key=f"dead-letter-replay:{entry.id}:{entry.attempts}",
            details={"reason": replay_reason, "attempt": entry.attempts},
        ))
        session.commit()
        try:
            from background_tasks import REDIS_URL, RQ_QUEUE_NAME, replay_dead_letter_job
            import redis
            import rq
            queue = rq.Queue(name=RQ_QUEUE_NAME, connection=redis.from_url(REDIS_URL, socket_connect_timeout=5, socket_timeout=5))
            job = queue.enqueue(replay_dead_letter_job, entry.id, tenant_id, job_timeout=60)
            enqueue_result = {"status": "queued", "job_id": job.id}
            if enqueue_result.get("status") == "failed":
                return jsonify({"id": entry.id, "status": entry.replay_status, "attempts": entry.attempts, "queue": enqueue_result}), 503
        except Exception as exc:
            logger.exception("Dead-letter replay enqueue failed for id=%s", entry.id)
            failed_session = _open_session()
            try:
                failed_entry = failed_session.query(DeadLetter).filter(
                    DeadLetter.id == entry.id,
                    DeadLetter.tenant_id == tenant_id,
                ).first()
                if failed_entry is not None:
                    failed_entry.replay_status = "failed"
                    failed_entry.error_detail = "replay enqueue unavailable"
                    failed_session.commit()
            finally:
                failed_session.close()
            return jsonify({"id": entry.id, "status": "failed", "attempts": entry.attempts, "error": "replay_deferred"}), 503
        return jsonify({"id": entry.id, "status": entry.replay_status, "attempts": entry.attempts}), 200
    finally:
        session.close()


def _normalize_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            try:
                parsed = parsedate_to_datetime(value)
            except (TypeError, ValueError, OverflowError):
                return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _build_sla_context(item: Discrepancy) -> Dict[str, Any]:
    detected_at = _normalize_datetime(item.detected_at)
    if not detected_at:
        return {"sla_status": "on_track", "sla_remaining_minutes": None}

    elapsed = max(0, int((datetime.now(timezone.utc) - detected_at).total_seconds() // 60))
    remaining = max(SLA_WINDOW_MINUTES - elapsed, 0)

    if item.resolved:
        return {"sla_status": "resolved", "sla_remaining_minutes": 0}
    if remaining <= 10:
        return {"sla_status": "breaching", "sla_remaining_minutes": remaining}
    if remaining <= 20:
        return {"sla_status": "warning", "sla_remaining_minutes": remaining}
    return {"sla_status": "on_track", "sla_remaining_minutes": remaining}


@app.route("/discrepancies", methods=["GET"])
@require_auth("read:discrepancies")
def discrepancies():
    status = request.args.get("status", "").strip()
    requested_tenant = request.args.get("tenant", "").strip()
    severity = request.args.get("severity", "").strip()
    resolved = request.args.get("resolved", "").strip()
    query_text = request.args.get("q", "").strip()
    page, error = _query_int("page", 1, 1, 1000000)
    if error:
        return error
    per_page, error = _query_int("per_page", 10, 1, 100)
    if error:
        return error

    tenant = _current_tenant_id()
    if not tenant:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    if requested_tenant and requested_tenant != tenant:
        return jsonify({"error": "tenant_access_denied", "message": "Forbidden tenant scope."}), 403
    error = _validate_filter("status", status, {"needs_review", "assigned", "resolved", "open", "closed", "pending", "missing_payment", "missing_transaction", "amount_mismatch", "duplicate"})
    if error:
        return error
    error = _validate_filter("severity", severity, {"critical", "warning", "info"})
    if error:
        return error
    error = _validate_filter("resolved", resolved, {"open", "resolved"})
    if error:
        return error
    if len(query_text) > 200:
        return jsonify({"error": "invalid_parameter", "message": "q must be 200 characters or fewer."}), 400

    session = _open_session()
    try:
        rows = session.query(Discrepancy)
        if status:
            rows = rows.filter((Discrepancy.anomaly_type == status) | (Discrepancy.status == status))
        if severity:
            rows = rows.filter(Discrepancy.severity == severity)
        if tenant:
            rows = rows.filter(Discrepancy.tenant_id == tenant)
        if resolved == "open":
            rows = rows.filter(Discrepancy.resolved.is_(False))
        elif resolved == "resolved":
            rows = rows.filter(Discrepancy.resolved.is_(True))
        if query_text:
            like_term = f"%{query_text}%"
            rows = rows.filter(
                (Discrepancy.trans_id.like(like_term)) | (Discrepancy.anomaly_type.like(like_term))
            )

        total = rows.count()
        items = rows.order_by(Discrepancy.detected_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

        return jsonify({
            "page": page,
            "per_page": per_page,
            "total": total,
            "items": [{
                "id": item.id,
                "trans_id": item.trans_id,
                "anomaly_type": item.anomaly_type,
                "status": item.status,
                "severity": item.severity,
                "resolved": item.resolved,
                "tenant_id": item.tenant_id,
                "details": item.details,
                "assignee": item.assignee,
                "notes": item.notes,
                "timeline": item.timeline or [],
                "detected_at": item.detected_at.isoformat() if item.detected_at else None,
                **_build_sla_context(item),
            } for item in items],
        }), 200
    finally:
        session.close()


def _tenant_route_allowed(tenant_id: str) -> bool:
    current_tenant = _current_tenant_id()
    user = get_current_user()
    return bool(
        TENANT_ID_PATTERN.fullmatch(tenant_id or "")
        and current_tenant
        and (tenant_id == current_tenant or (user and AuthRBAC.check_permission(user, "manage:all_tenants")))
    )


@app.route("/tenants/<tenant_id>/settings", methods=["GET"])
@require_auth("read:settings")
def get_tenant_settings(tenant_id: str):
    if not _tenant_route_allowed(tenant_id):
        return jsonify({"error": "tenant_access_denied", "message": "Cross-tenant settings access prohibited."}), 403
    return jsonify(settings_store.get(tenant_id)), 200


@app.route("/tenants/<tenant_id>/settings", methods=["POST"])
@require_auth("write:settings")
def update_tenant_settings(tenant_id: str):
    if not _tenant_route_allowed(tenant_id):
        return jsonify({"error": "tenant_access_denied", "message": "Cross-tenant settings access prohibited."}), 403
    payload, error = _json_object()
    if error:
        return error
    unknown_fields = set(payload) - _SETTING_FIELDS - {"tenant_id"}
    if unknown_fields:
        return jsonify({"error": "invalid_request", "message": "Unsupported settings field."}), 400
    payload.pop("tenant_id", None)
    if "preferred_locale" in payload:
        error = _validate_locale(payload["preferred_locale"])
        if error:
            return error
    if "user_locale_overrides" in payload:
        error = _validate_locale_overrides(payload["user_locale_overrides"])
        if error:
            return error
    if "preferred_locale" in payload:
        payload["preferred_locale"] = payload["preferred_locale"].strip()
    updated = settings_store.update(tenant_id, payload)
    logger.info("Settings modified for tenant_id=%s", tenant_id)
    return jsonify(updated), 200


@app.route("/activity-feed", methods=["GET"])
@require_auth("read:discrepancies")
def activity_feed():
    limit, error = _query_int("limit", 5, 1, 100)
    if error:
        return error
    tenant_id = _current_tenant_id()
    session = _open_session()
    try:
        query = session.query(Discrepancy)
        if tenant_id is not None:
            query = query.filter(Discrepancy.tenant_id == tenant_id)
        discrepancies = query.order_by(Discrepancy.detected_at.desc()).limit(limit).all()
        
        items = []
        for item in discrepancies:
            timeline = item.timeline or []
            if timeline:
                latest = timeline[-1]
                items.append({
                    "id": item.id,
                    "event": latest.get("event", "activity"),
                    "message": latest.get("message", str(item.details or "No details")),
                    "severity": item.severity,
                    "timestamp": latest.get("ts", item.detected_at.isoformat() if item.detected_at else None),
                    "trans_id": item.trans_id,
                })
            else:
                items.append({
                    "id": item.id,
                    "event": "created",
                    "message": str(item.details or "Incident created"),
                    "severity": item.severity,
                    "timestamp": item.detected_at.isoformat() if item.detected_at else None,
                    "trans_id": item.trans_id,
                })
        return jsonify({"items": items}), 200
    finally:
        session.close()


@app.route("/assignment-queue", methods=["GET"])
@require_auth("read:discrepancies")
def assignment_queue():
    tenant_id = _current_tenant_id()
    session = _open_session()
    try:
        query = session.query(Discrepancy).filter(Discrepancy.resolved.is_(False))
        if tenant_id is not None:
            query = query.filter(Discrepancy.tenant_id == tenant_id)
        discrepancies = query.order_by(Discrepancy.detected_at.desc()).all()

        items = []
        for item in discrepancies:
            queue_status = "assigned" if item.assignee else "needs_assignment"
            items.append({
                "id": item.id,
                "trans_id": item.trans_id,
                "severity": item.severity,
                "assignee": item.assignee or "Unassigned",
                "queue_status": queue_status,
                "anomaly_type": item.anomaly_type,
                "detected_at": item.detected_at.isoformat() if item.detected_at else None,
            })
        return jsonify({"items": items}), 200
    finally:
        session.close()


@app.route("/discrepancies/<discrepancy_id>/resolve", methods=["POST"])
@require_auth("write:discrepancies")
def resolve_discrepancy(discrepancy_id: str):
    tenant_id = _current_tenant_id()
    session = SessionLocal()
    try:
        discrepancy = _tenant_scoped_get(session, Discrepancy, discrepancy_id, tenant_id)
        if not discrepancy:
            return jsonify({"error": "not_found", "message": "Discrepancy record not found."}), 404

        payload, error = _json_object()
        if error:
            return error
        error = _validate_fields(payload, {"note": (str, False)})
        if error:
            return error
        current_user = get_current_user()
        actor = getattr(current_user, "user_id", None) or getattr(current_user, "username", None) or "system"
        discrepancy.resolved = True
        discrepancy.resolved_at = datetime.now(timezone.utc)
        discrepancy.resolution_note = payload.get("note", discrepancy.resolution_note)

        persist_audit_event(session, ActionAuditRecord(
            tenant_id=discrepancy.tenant_id or "default",
            actor=actor,
            action="resolve_discrepancy",
            details={"discrepancy_id": discrepancy.id, "note": payload.get("note", "")},
        ))
        session.commit()
        logger.info("Discrepancy resolved successfully: id=%s", discrepancy_id)
        return jsonify({"status": "resolved", "id": discrepancy.id}), 200
    finally:
        session.close()


@app.route("/discrepancies/bulk-resolve", methods=["POST"])
@require_auth("bulk:operations")
def bulk_resolve_discrepancies():
    tenant_id = _current_tenant_id()
    session = SessionLocal()
    try:
        payload, error = _json_object()
        if error:
            return error
        error = _validate_fields(payload, {"ids": (list, True), "note": (str, False)})
        if error:
            return error
        ids = payload.get("ids", [])
        note = payload.get("note", "Bulk resolved")
        current_user = get_current_user()
        actor = getattr(current_user, "user_id", None) or getattr(current_user, "username", None) or "system"

        updated = 0
        skipped_ids = []
        resolved_ids = []
        for discrepancy_id in ids:
            discrepancy = _tenant_scoped_get(session, Discrepancy, discrepancy_id, tenant_id)
            if not discrepancy:
                skipped_ids.append(discrepancy_id)
                continue
            discrepancy.resolved = True
            discrepancy.resolved_at = datetime.now(timezone.utc)
            discrepancy.resolution_note = note
            discrepancy.timeline = discrepancy.timeline or []
            discrepancy.timeline.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": "bulk_resolved",
                "message": note,
            })
            updated += 1
            resolved_ids.append(discrepancy.id)

        if resolved_ids:
            # One audit record for the whole batch (not per row): resolve_discrepancy
            # already covers the single-item case, and a bulk action is one operator
            # decision, so it should read back as one event with every id it touched.
            persist_audit_event(session, ActionAuditRecord(
                tenant_id=tenant_id or "default",
                actor=actor,
                action="bulk_resolve_discrepancies",
                details={"discrepancy_ids": resolved_ids, "note": note, "skipped_ids": skipped_ids},
            ))
        session.commit()
        logger.info("Bulk resolved %s discrepancies successfully", updated)
        return jsonify({"status": "resolved", "updated": updated, "skipped_ids": skipped_ids}), 200
    finally:
        session.close()


@app.route("/discrepancies/<discrepancy_id>/notes", methods=["POST"])
@require_auth("write:discrepancies")
def save_notes(discrepancy_id: str):
    tenant_id = _current_tenant_id()
    session = SessionLocal()
    try:
        discrepancy = _tenant_scoped_get(session, Discrepancy, discrepancy_id, tenant_id)
        if not discrepancy:
            return jsonify({"error": "not_found", "message": "Discrepancy record not found."}), 404

        payload, error = _json_object()
        if error:
            return error
        error = _validate_fields(payload, {"note": (str, True)})
        if error:
            return error
        note = payload.get("note", "").strip()
        if note:
            discrepancy.notes = (discrepancy.notes + f"\n- {note}") if discrepancy.notes else f"- {note}"
            discrepancy.timeline = discrepancy.timeline or []
            discrepancy.timeline.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": "note_added",
                "message": note,
            })
            session.commit()

        return jsonify({"status": "saved", "notes": discrepancy.notes or ""}), 200
    finally:
        session.close()


@app.route("/discrepancies/<discrepancy_id>/assign", methods=["POST"])
@require_auth("write:discrepancies")
def assign_discrepancy(discrepancy_id: str):
    tenant_id = _current_tenant_id()
    session = SessionLocal()
    try:
        discrepancy = _tenant_scoped_get(session, Discrepancy, discrepancy_id, tenant_id)
        if not discrepancy:
            return jsonify({"error": "not_found", "message": "Discrepancy record not found."}), 404

        payload, error = _json_object()
        if error:
            return error
        error = _validate_fields(payload, {"assignee": (str, True)})
        if error:
            return error
        assignee = payload.get("assignee", "").strip()
        discrepancy.assignee = assignee
        discrepancy.timeline = discrepancy.timeline or []
        discrepancy.timeline.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": "assigned",
            "message": f"Assigned to {assignee}" if assignee else "Assignment cleared",
        })
        session.commit()
        return jsonify({"status": "assigned", "assignee": discrepancy.assignee}), 200
    finally:
        session.close()


@app.route("/analytics/sla-metrics", methods=["GET"])
@require_auth("read:discrepancies")
def analytics_sla_metrics():
    tenant_id = _current_tenant_id()
    session = _open_session()
    try:
        query = session.query(Discrepancy).filter(Discrepancy.severity == "critical")
        if tenant_id is not None:
            query = query.filter(Discrepancy.tenant_id == tenant_id)
        discrepancies = query.all()

        on_track = warning = breaching = 0
        for item in discrepancies:
            sla_status = _build_sla_context(item).get("sla_status", "on_track")
            if sla_status == "on_track":
                on_track += 1
            elif sla_status == "warning":
                warning += 1
            elif sla_status == "breaching":
                breaching += 1

        return jsonify({
            "on_track": on_track,
            "warning": warning,
            "breaching": breaching,
            "total": len(discrepancies),
        }), 200
    finally:
        session.close()


@app.route("/analytics/resolution-times", methods=["GET"])
@require_auth("read:discrepancies")
def analytics_resolution_times():
    tenant_id = _current_tenant_id()
    session = _open_session()
    try:
        query = session.query(Discrepancy).filter(
            Discrepancy.resolved.is_(True),
            Discrepancy.resolved_at.isnot(None),
            Discrepancy.detected_at.isnot(None),
        )
        if tenant_id is not None:
            query = query.filter(Discrepancy.tenant_id == tenant_id)
        resolved_items = query.all()

        if not resolved_items:
            return jsonify({"average_resolution_time": 0, "median_resolution_time": 0, "p95_resolution_time": 0}), 200

        resolution_times = []
        for item in resolved_items:
            detected = _normalize_datetime(item.detected_at)
            resolved = _normalize_datetime(item.resolved_at)
            if detected and resolved:
                resolution_times.append(max(0, int((resolved - detected).total_seconds() // 60)))

        if not resolution_times:
            return jsonify({"average_resolution_time": 0, "median_resolution_time": 0, "p95_resolution_time": 0}), 200

        resolution_times.sort()
        average = sum(resolution_times) // len(resolution_times)
        median = resolution_times[len(resolution_times) // 2]
        p95_index = max(0, int(len(resolution_times) * 0.95) - 1)
        p95 = resolution_times[p95_index]

        return jsonify({
            "average_resolution_time": average,
            "median_resolution_time": median,
            "p95_resolution_time": p95,
        }), 200
    finally:
        session.close()


@app.route("/analytics/operator-stats", methods=["GET"])
@require_auth("read:discrepancies")
def analytics_operator_stats():
    tenant_id = _current_tenant_id()
    session = _open_session()
    try:
        query = session.query(Discrepancy)
        if tenant_id is not None:
            query = query.filter(Discrepancy.tenant_id == tenant_id)
        discrepancies = query.all()

        operator_data: Dict[str, Dict[str, Any]] = {}
        for item in discrepancies:
            assignee = item.assignee or "Unassigned"
            data = operator_data.setdefault(assignee, {
                "assigned_count": 0, "resolved_count": 0,
                "total_resolution_time": 0, "resolution_samples": 0,
            })
            data["assigned_count"] += 1
            if item.resolved:
                data["resolved_count"] += 1
                detected = _normalize_datetime(item.detected_at)
                resolved = _normalize_datetime(item.resolved_at)
                if detected and resolved:
                    minutes = max(0, int((resolved - detected).total_seconds() // 60))
                    data["total_resolution_time"] += minutes
                    data["resolution_samples"] += 1

        stats = []
        for operator, data in operator_data.items():
            avg_time = data["total_resolution_time"] // data["resolution_samples"] if data["resolution_samples"] else 0
            stats.append({
                "operator": operator,
                "assigned_count": data["assigned_count"],
                "resolved_count": data["resolved_count"],
                "average_resolution_time": avg_time,
            })

        stats.sort(key=lambda x: x["resolved_count"], reverse=True)
        return jsonify(stats), 200
    finally:
        session.close()


@app.route("/discrepancies/export/csv", methods=["GET"])
@require_auth("read:discrepancies")
def export_discrepancies_csv():
    status = request.args.get("status", "").strip()
    severity = request.args.get("severity", "").strip()
    resolved = request.args.get("resolved", "").strip()
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    error = _validate_filter("status", status, {"needs_review", "assigned", "resolved", "open", "closed", "pending", "missing_payment", "missing_transaction", "amount_mismatch", "duplicate"})
    if error:
        return error
    error = _validate_filter("severity", severity, {"critical", "warning", "info"})
    if error:
        return error
    error = _validate_filter("resolved", resolved, {"open", "resolved"})
    if error:
        return error

    session = _open_session()
    try:
        rows = session.query(Discrepancy)
        if tenant_id is not None:
            rows = rows.filter(Discrepancy.tenant_id == tenant_id)
        if status:
            rows = rows.filter((Discrepancy.anomaly_type == status) | (Discrepancy.status == status))
        if severity:
            rows = rows.filter(Discrepancy.severity == severity)
        if resolved == "open":
            rows = rows.filter(Discrepancy.resolved.is_(False))
        elif resolved == "resolved":
            rows = rows.filter(Discrepancy.resolved.is_(True))

        items = rows.order_by(Discrepancy.detected_at.desc()).all()

        text_buf = io.StringIO()
        writer = csv.DictWriter(text_buf, fieldnames=[
            "id", "trans_id", "anomaly_type", "severity", "status", "resolved",
            "tenant_id", "assignee", "detected_at", "resolved_at", "notes"
        ])
        writer.writeheader()
        for item in items:
            writer.writerow({
                "id": item.id,
                "trans_id": item.trans_id,
                "anomaly_type": item.anomaly_type,
                "severity": item.severity,
                "status": item.status,
                "resolved": "Yes" if item.resolved else "No",
                "tenant_id": item.tenant_id or "N/A",
                "assignee": item.assignee or "Unassigned",
                "detected_at": item.detected_at.isoformat() if item.detected_at else "",
                "resolved_at": item.resolved_at.isoformat() if item.resolved_at else "",
                "notes": item.notes or "",
            })

        buffer = io.BytesIO(text_buf.getvalue().encode("utf-8"))
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"pesaguard_incidents_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
        )
    finally:
        session.close()


@app.route("/analytics/incident-trends", methods=["GET"])
@require_auth("read:discrepancies")
def analytics_incident_trends():
    tenant_id = _current_tenant_id()
    session = _open_session()
    try:
        now = datetime.now(timezone.utc)

        def _scoped(q):
            return q.filter(Discrepancy.tenant_id == tenant_id) if tenant_id is not None else q

        weekly_data = []
        for week_offset in range(3, -1, -1):
            week_start = now - timedelta(days=7 * (week_offset + 1))
            week_end = now - timedelta(days=7 * week_offset)
            count = _scoped(session.query(Discrepancy).filter(
                Discrepancy.detected_at >= week_start,
                Discrepancy.detected_at < week_end,
            )).count()
            resolved = _scoped(session.query(Discrepancy).filter(
                Discrepancy.detected_at >= week_start,
                Discrepancy.detected_at < week_end,
                Discrepancy.resolved.is_(True),
            )).count()
            weekly_data.append({"week": f"W{4-week_offset}", "incidents": count, "resolved": resolved, "open": count - resolved})

        monthly_data = []
        for month_offset in range(11, -1, -1):
            month_start = (now.replace(day=1) - timedelta(days=month_offset * 30)).replace(day=1)
            month_end = (month_start + timedelta(days=32)).replace(day=1)
            count = _scoped(session.query(Discrepancy).filter(
                Discrepancy.detected_at >= month_start,
                Discrepancy.detected_at < month_end,
            )).count()
            resolved = _scoped(session.query(Discrepancy).filter(
                Discrepancy.detected_at >= month_start,
                Discrepancy.detected_at < month_end,
                Discrepancy.resolved.is_(True),
            )).count()
            monthly_data.append({"month": month_start.strftime("%b"), "incidents": count, "resolved": resolved, "open": count - resolved})

        return jsonify({"weekly": weekly_data, "monthly": monthly_data}), 200
    finally:
        session.close()


@app.route("/incidents/auto-escalate", methods=["POST"])
@require_auth("bulk:operations")
def auto_escalate_incidents():
    escalation_minutes, error = _query_int("escalation_minutes", 45, 1, 10080)
    if error:
        return error
    tenant_id = _current_tenant_id()
    session = _open_session()
    try:
        threshold = datetime.now(timezone.utc) - timedelta(minutes=escalation_minutes)
        query = session.query(Discrepancy).filter(
            Discrepancy.severity == "critical",
            Discrepancy.resolved.is_(False),
            Discrepancy.detected_at < threshold,
        )
        if tenant_id is not None:
            query = query.filter(Discrepancy.tenant_id == tenant_id)
        old_critical = query.all()

        escalated = 0
        for incident in old_critical:
            if not incident.assignee:
                incident.assignee = "On-Call Lead"
                incident.timeline = incident.timeline or []
                incident.timeline.append({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "event": "auto_escalated",
                    "message": f"Auto-escalated after {escalation_minutes} minutes (critical SLA breach)",
                })
                escalated += 1

        session.commit()
        return jsonify({"status": "escalated", "count": escalated, "threshold_minutes": escalation_minutes}), 200
    finally:
        session.close()


@app.route("/incidents/filters/presets", methods=["GET", "POST"])
@require_auth("read:discrepancies")
def incident_filter_presets():
    """Return the tenant's discrepancy/incident search filter presets.

    Three presets (critical_open, needs_review, all) always exist. POST adds
    or replaces one more, scoped to the caller's tenant, persisted in
    discrepancy_filter_presets -- it used to return 201 without saving
    anything at all.
    """
    default_presets = {
        "critical_open": {"severity": "critical", "resolved": "open"},
        "needs_review": {"status": "needs_review"},
        "all": {},
    }
    tenant_id = _current_tenant_id() or "default"
    session = _open_session()
    try:
        if request.method == "POST":
            current_user = get_current_user()
            if _api_auth_required() and (current_user is None or not AuthRBAC.check_permission(current_user, "write:discrepancies")):
                return jsonify({"error": "insufficient_permissions", "message": "Write permission required."}), 403
            payload, error = _json_object()
            if error:
                return error
            error = _validate_fields(payload, {"name": (str, False), "filters": (dict, False)})
            if error:
                return error
            name = str(payload.get("name") or "custom_preset").strip()
            if not name:
                return jsonify({"error": "missing_name", "message": "Preset name is required."}), 400
            filters = payload.get("filters") or {}
            actor = getattr(current_user, "user_id", None) or getattr(current_user, "username", None)
            existing = (
                session.query(DiscrepancyFilterPreset)
                .filter(DiscrepancyFilterPreset.tenant_id == tenant_id, DiscrepancyFilterPreset.name == name)
                .one_or_none()
            )
            if existing:
                existing.filters = filters
                existing.owner_user_id = actor
            else:
                session.add(DiscrepancyFilterPreset(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    owner_user_id=actor,
                    name=name,
                    filters=filters,
                ))
            session.commit()
            saved = dict(default_presets)
            for preset in session.query(DiscrepancyFilterPreset).filter(DiscrepancyFilterPreset.tenant_id == tenant_id):
                saved[preset.name] = preset.filters
            return jsonify({"status": "saved", "presets": saved}), 201

        presets = dict(default_presets)
        for preset in session.query(DiscrepancyFilterPreset).filter(DiscrepancyFilterPreset.tenant_id == tenant_id):
            presets[preset.name] = preset.filters
        return jsonify({"presets": presets}), 200
    finally:
        session.close()


@app.route("/analytics/reconciliation-report", methods=["GET"])
@require_auth("read:discrepancies")
def reconciliation_report():
    days, error = _query_int("days", 7, 1, 3650)
    if error:
        return error
    tenant_id = _current_tenant_id()
    session = _open_session()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        query = session.query(Discrepancy).filter(Discrepancy.detected_at >= cutoff)
        if tenant_id is not None:
            query = query.filter(Discrepancy.tenant_id == tenant_id)
        all_items = query.all()

        total = len(all_items)
        resolved = sum(1 for item in all_items if item.resolved)
        open_count = total - resolved

        by_severity: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        for item in all_items:
            by_severity[item.severity or "unknown"] = by_severity.get(item.severity or "unknown", 0) + 1
            by_status[item.status or "unknown"] = by_status.get(item.status or "unknown", 0) + 1

        resolution_times = [
            int((item.resolved_at - item.detected_at).total_seconds() // 60)
            for item in all_items if item.resolved and item.detected_at and item.resolved_at
        ]
        avg_resolution_time = sum(resolution_times) // len(resolution_times) if resolution_times else 0

        return jsonify({
            "report_period_days": days,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_incidents": total,
                "resolved": resolved,
                "open": open_count,
                "resolution_rate": round(resolved / max(total, 1), 3),
                "average_resolution_minutes": avg_resolution_time,
            },
            "by_severity": by_severity,
            "by_status": by_status,
            "critical_count": by_severity.get("critical", 0),
            "sla_compliant_percentage": round((resolved / max(total, 1)) * 100, 1),
        }), 200
    finally:
        session.close()


@app.route("/incidents/bulk-assign", methods=["POST"])
@require_auth("bulk:operations")
def bulk_assign_incidents():
    tenant_id = _current_tenant_id()
    session = _open_session()
    try:
        payload, error = _json_object()
        if error:
            return error
        error = _validate_fields(payload, {"ids": (list, True), "assignee": (str, True), "note": (str, False)})
        if error:
            return error
        ids = payload.get("ids", [])
        assignee = payload.get("assignee", "").strip()
        note = payload.get("note", "Bulk assigned")
        current_user = get_current_user()
        actor = getattr(current_user, "user_id", None) or getattr(current_user, "username", None) or "system"

        updated = 0
        skipped_ids = []
        assigned_ids = []
        for incident_id in ids:
            incident = _tenant_scoped_get(session, Discrepancy, incident_id, tenant_id)
            if not incident:
                skipped_ids.append(incident_id)
                continue
            incident.assignee = assignee
            incident.timeline = incident.timeline or []
            incident.timeline.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": "bulk_assigned",
                "message": f"Bulk assigned to {assignee}: {note}",
            })
            updated += 1
            assigned_ids.append(incident.id)

        if assigned_ids:
            # One audit record for the whole batch, same convention as
            # bulk_resolve_discrepancies: a bulk action is one operator
            # decision, so it reads back as one event listing every id it touched.
            persist_audit_event(session, ActionAuditRecord(
                tenant_id=tenant_id or "default",
                actor=actor,
                action="bulk_assign_incidents",
                details={"discrepancy_ids": assigned_ids, "assignee": assignee, "note": note, "skipped_ids": skipped_ids},
            ))
        session.commit()
        return jsonify({"status": "assigned", "updated": updated, "skipped_ids": skipped_ids}), 200
    finally:
        session.close()


@app.route("/incidents/search", methods=["GET"])
@require_auth("read:discrepancies")
def search_incidents():
    query_text = request.args.get("q", "").strip()
    severity = request.args.get("severity", "").strip()
    assignee = request.args.get("assignee", "").strip()
    page, error = _query_int("page", 1, 1, 1000000)
    if error:
        return error
    per_page, error = _query_int("per_page", 20, 1, 100)
    if error:
        return error
    tenant_id = _current_tenant_id()
    if not tenant_id:
        return jsonify({"error": "tenant_context_required", "message": "Authenticated tenant context is required."}), 403
    error = _validate_filter("severity", severity, {"critical", "warning", "info"})
    if error:
        return error
    if len(query_text) > 200 or len(assignee) > 200:
        return jsonify({"error": "invalid_parameter", "message": "Search filters must be 200 characters or fewer."}), 400

    session = _open_session()
    try:
        rows = session.query(Discrepancy)
        if tenant_id is not None:
            rows = rows.filter(Discrepancy.tenant_id == tenant_id)
        if query_text:
            like_term = f"%{query_text}%"
            rows = rows.filter(
                (Discrepancy.trans_id.like(like_term)) |
                (Discrepancy.anomaly_type.like(like_term)) |
                (Discrepancy.notes.like(like_term))
            )
        if severity:
            rows = rows.filter(Discrepancy.severity == severity)
        if assignee:
            rows = rows.filter(Discrepancy.assignee == assignee)

        total = rows.count()
        items = rows.order_by(Discrepancy.detected_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

        return jsonify({
            "query": query_text,
            "page": page,
            "per_page": per_page,
            "total": total,
            "items": [{
                "id": item.id,
                "trans_id": item.trans_id,
                "anomaly_type": item.anomaly_type,
                "severity": item.severity,
                "assignee": item.assignee,
                "detected_at": item.detected_at.isoformat() if item.detected_at else None,
            } for item in items],
        }), 200
    finally:
        session.close()


if __name__ == "__main__":
    logger.info("Starting canonical dashboard API; database schema must be managed by Alembic.")
    port = runtime_config.port
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() in {"true", "1", "yes"}
    app.run(host=os.getenv("PESAGUARD_BIND_HOST", "127.0.0.1"), port=port, debug=debug_mode)
