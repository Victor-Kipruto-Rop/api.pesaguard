"""
Enterprise-grade, modern, and production-ready PesaGuard Advanced Features API.
Integrates webhook management, RBAC, email notifications, escalation rules,
on-call schedules, advanced search, rate limiting, and audit logging.
"""

from __future__ import annotations

from environment import required_env, runtime_environment

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import base64
import struct
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import quote, urlencode, urlparse

import qrcode
import requests
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import Flask, Response, jsonify, request, g
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from werkzeug.exceptions import HTTPException

from pesaguard_backend_pipeline.webhook_manager import WebhookManager
from pesaguard_backend_pipeline.auth_rbac import AuthenticationUnavailable, AuthRBAC, IdentityAccessService, configure_revocation_store, require_auth, require_tenant_access, require_resource_access, get_current_user
from pesaguard_backend_pipeline.rate_limiter import ENABLE_REDIS_RATE_LIMITING, RateLimiter, rate_limit, get_rate_limit_status
from pesaguard_backend_pipeline.email_service import EmailService
from pesaguard_backend_pipeline.escalation_engine import EscalationEngine
from pesaguard_backend_pipeline.on_call_service import OnCallService
from pesaguard_backend_pipeline.search_engine import AdvancedSearchEngine
from pesaguard_backend_pipeline.action_audit import ActionAuditEntry
from pesaguard_backend_pipeline.models import (
    Base,
    Discrepancy,
    Report,
    DeadLetter,
    UserAccount,
    UserIdentity,
    DeviceIdentity,
    PasswordCredential,
    PasswordHistory,
    PasswordResetState,
    PasswordPolicy,
    EmailNotification,
    Organization,
    OrganizationMembership,
    Team,
    UserSession,
    ApiKeyRecord,
    OIDCProvider,
    MFAChallenge,
    PasswordlessChallenge,
    PlatformIdentity,
    TenantRecord,
    ServiceIdentity,
    ApiClientIdentity,
    ExternalIdentity,
    IAMRole,
    IAMPermission,
    IAMRolePermission,
    IAMRoleBinding,
    MFAFactor,
    MFARecovery,
    MFAPolicy,
    MFAEvent,
)
from pesaguard_backend_pipeline.tenant_settings import TenantSettingsStore
from pesaguard_backend_pipeline.data_protection import encrypt_value, decrypt_value

configure_logging = lambda: None  # Import from logging_utils if available
logger = logging.getLogger("pesaguard.advanced_features")

from pesaguard_backend_pipeline.app import app

if getattr(app, "_got_first_request", False):
    app._got_first_request = False


def _idempotent_route(rule, **options):
    """Register a route so repeated imports/reloads of this module stay safe.

    Flask's uniqueness constraint is on the ENDPOINT name, not on the URL rule:
    the same rule may legitimately be registered more than once with different
    methods (e.g. ``POST /webhooks`` to create and ``GET /webhooks`` to list).
    Deduping on the rule alone silently dropped the second registration and made
    those methods answer 405 Method Not Allowed, so we key on
    (endpoint, methods) instead.
    """
    if getattr(app, "_got_first_request", False):
        def _noop(view_func):
            return view_func
        return _noop

    def decorator(view_func):
        endpoint = options.get("endpoint") or view_func.__name__
        methods = {str(m).upper() for m in (options.get("methods") or ["GET"])}

        # Same endpoint already bound (module reload) â€” keep the existing view.
        if endpoint in app.view_functions:
            return view_func

        # Same rule already serving every method requested â€” nothing to add.
        for existing_rule in app.url_map.iter_rules():
            if existing_rule.rule != rule:
                continue
            existing_methods = {str(m).upper() for m in (existing_rule.methods or set())}
            if methods.issubset(existing_methods):
                return view_func

        route_options = {k: v for k, v in options.items() if k != "endpoint"}
        return app.route(rule, endpoint=endpoint, **route_options)(view_func)

    return decorator


DATABASE_URL = required_env("DATABASE_URL")


def create_db_engine(url: str):
    """Create a robust database engine with appropriate pooling and timeout settings."""
    if url.startswith("sqlite"):
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    else:
        engine = create_engine(
            url,
            pool_pre_ping=True,
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
            connect_args={"connect_timeout": 5} if "postgresql" in url else {},
        )
    _instrument_engine_query_timing(engine)
    return engine


def _instrument_engine_query_timing(engine) -> None:
    try:
        from metrics import instrument_engine_query_timing
        instrument_engine_query_timing(engine)
    except Exception:
        logger.debug("Engine query timing instrumentation skipped.", exc_info=True)


engine = create_db_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
configure_revocation_store(engine, SessionLocal)

email_service = EmailService()
settings_store = TenantSettingsStore()

ERROR_CODE_TAXONOMY = {
    "missing_credentials": {"status_code": 400, "description": "Request is missing username or password."},
    "invalid_credentials": {"status_code": 401, "description": "Authentication failed for the supplied credentials."},
    "not_authenticated": {"status_code": 401, "description": "Authentication token is missing or expired."},
    "missing_token": {"status_code": 400, "description": "A token value is required for this action."},
    "invalid_request": {"status_code": 400, "description": "Request payload is malformed or missing required fields."},
    "tenant_access_denied": {"status_code": 403, "description": "The caller does not have access to the requested tenant."},
    "resource_not_found": {"status_code": 404, "description": "The requested resource does not exist."},
    "rate_limit_exceeded": {"status_code": 429, "description": "The client exceeded the allowed request rate."},
    "internal_server_error": {"status_code": 500, "description": "The server encountered an unexpected error."},
}


def _request_id_value() -> str:
    return request.headers.get("X-Request-ID") or request.headers.get("X-Correlation-ID") or str(uuid.uuid4())


def _provider_trust_policy_for_tenant(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """Return the tenant's external-IdP trust policy with sensible provider defaults."""
    tenant_key = tenant_id or request.args.get("tenant_id") or os.getenv("TENANT_ID") or "default"
    provider_family = str(os.getenv("OIDC_PROVIDER_FAMILY", "")).strip().lower() or "generic"
    env_issuer = str(os.getenv("OIDC_ISSUER", "")).strip()
    env_jwks = str(os.getenv("OIDC_JWKS_URI", "")).strip()

    def _normalize_list(values: Iterable[str]) -> List[str]:
        return [str(item).strip() for item in values if str(item).strip()]

    policy = {
        "provider_type": "oidc",
        "allowed_issuers": _normalize_list((os.getenv("OIDC_ALLOWED_ISSUERS", "")).split(",")),
        "allowed_jwks_hosts": _normalize_list(item.strip().lower() for item in (os.getenv("OIDC_ALLOWED_JWKS_HOSTS", "")).split(",")),
        "allow_legacy_pkce": True,
        "pin_jwks": os.getenv("OIDC_PIN_JWKS", "1") == "1",
        "require_verified_email": os.getenv("OIDC_REQUIRE_VERIFIED_EMAIL", "1") == "1",
        "require_mfa": os.getenv("OIDC_REQUIRE_MFA", "0") == "1",
        "saml_entity_id": os.getenv("SAML_ENTITY_ID") or None,
        "allowed_saml_idps": _normalize_list((os.getenv("SAML_ALLOWED_IDPS", "")).split(",")),
        "provider_family": provider_family,
    }

    if provider_family == "microsoft_entra":
        tenant_hint = str(tenant_id or os.getenv("TENANT_ID") or "").strip()
        issuer_template = "https://login.microsoftonline.com/{tenant}/v2.0"
        if tenant_hint:
            policy["allowed_issuers"].append(issuer_template.format(tenant=tenant_hint))
        else:
            policy["allowed_issuers"].append("https://login.microsoftonline.com/")
        policy["allowed_jwks_hosts"].append("login.microsoftonline.com")
        policy["pin_jwks"] = True
    elif provider_family == "okta":
        issuer_hint = env_issuer or "https://{tenant}.okta.com/oauth2/default"
        if "{tenant}" in issuer_hint and tenant_key and tenant_key != "default":
            issuer_hint = issuer_hint.format(tenant=tenant_key)
        policy["allowed_issuers"].append(issuer_hint.rstrip("/"))
        if "okta.com" in issuer_hint:
            policy["allowed_jwks_hosts"].append(issuer_hint.split("//", 1)[-1].split("/", 1)[0].lower())
    elif provider_family == "auth0":
        issuer_hint = env_issuer or "https://{tenant}.auth0.com"
        if "{tenant}" in issuer_hint and tenant_key and tenant_key != "default":
            issuer_hint = issuer_hint.format(tenant=tenant_key)
        policy["allowed_issuers"].append(issuer_hint.rstrip("/"))
        if "auth0.com" in issuer_hint:
            policy["allowed_jwks_hosts"].append(issuer_hint.split("//", 1)[-1].split("/", 1)[0].lower())
    elif provider_family == "google":
        policy["allowed_issuers"].extend(["https://accounts.google.com", "https://openidconnect.googleapis.com/"])
        policy["allowed_jwks_hosts"].extend(["accounts.google.com", "www.googleapis.com", "openidconnect.googleapis.com"])
        policy["pin_jwks"] = bool(env_jwks) or True

    policy["allowed_issuers"] = list(dict.fromkeys(policy["allowed_issuers"]))
    policy["allowed_jwks_hosts"] = list(dict.fromkeys(host.lower() for host in policy["allowed_jwks_hosts"]))

    try:
        tenant_cfg = settings_store.get(str(tenant_key)) if hasattr(settings_store, "get") else {}
        if isinstance(tenant_cfg, dict):
            external_policy = tenant_cfg.get("external_idp_policy") or tenant_cfg.get("sso_policy") or {}
            if isinstance(external_policy, dict):
                for key, value in external_policy.items():
                    if value is not None:
                        policy[key] = value
    except Exception:
        logger.debug("No tenant trust policy configured for %s; using env defaults.", tenant_key)

    return policy


def _validate_provider_trust_policy(tenant_id: Optional[str], policy: Optional[Dict[str, Any]], metadata: Optional[Dict[str, Any]]) -> bool:
    """Enforce tenant-specific provider trust rules for OIDC or SAML providers."""
    provider_policy = (policy or _provider_trust_policy_for_tenant(tenant_id)) or {}
    provider_type = str(provider_policy.get("provider_type", "oidc")).lower()
    metadata = metadata or {}

    if provider_type == "saml":
        return _validate_saml_provider_policy(provider_policy, metadata)

    issuer = str(metadata.get("issuer") or provider_policy.get("issuer") or "").strip()
    allowed_issuers = {str(item).strip() for item in (provider_policy.get("allowed_issuers") or []) if str(item).strip()}
    if allowed_issuers and issuer and issuer not in allowed_issuers:
        return False

    jwks_uri = str(metadata.get("jwks_uri") or provider_policy.get("jwks_uri") or "").strip()
    if jwks_uri:
        allowed_hosts = {
            str(item).strip().lower() for item in (provider_policy.get("allowed_jwks_hosts") or []) if str(item).strip()
        }
        if allowed_hosts:
            host = (jwks_uri.split("//", 1)[-1].split("/", 1)[0]).split(":", 1)[0].lower()
            if host not in allowed_hosts:
                return False

    if provider_policy.get("pin_jwks"):
        expected_jwks = str(provider_policy.get("jwks_uri") or "").strip()
        if expected_jwks and jwks_uri and jwks_uri.lower() != expected_jwks.lower():
            return False

    if provider_policy.get("require_verified_email") and metadata.get("email_verified") is False:
        return False

    if provider_policy.get("review_required") and not str(provider_policy.get("approved_by") or "").strip():
        return False

    return True


def _validate_saml_provider_policy(provider_policy: Optional[Dict[str, Any]], metadata: Optional[Dict[str, Any]] = None) -> bool:
    """Validate SAML IdP trust policy requirements. This is intentionally explicit and fail-closed."""
    provider = provider_policy or {}
    if str(provider.get("provider_type", "")).lower() != "saml":
        return True

    metadata = metadata or {}
    entity_id = str(provider.get("entity_id") or metadata.get("entity_id") or metadata.get("issuer") or "").strip()
    if not entity_id:
        return False

    allowed = {str(item).strip() for item in (provider.get("allowed_saml_idps") or []) if str(item).strip()}
    if allowed and entity_id not in allowed:
        return False

    if provider.get("require_signed_assertions") and not bool(metadata.get("want_authn_requests_signed") or metadata.get("signed_assertions") or metadata.get("x509_cert")):
        return False

    if provider.get("require_explicit_entity_id") and not str(provider.get("entity_id") or metadata.get("entity_id") or "").strip():
        return False

    return True


def _redis_fail_closed_config() -> Dict[str, Any]:
    """Return production Redis defaults and fail-closed controls for auth/session infrastructure."""
    return {
        "enabled": bool(os.getenv("REDIS_URL") or os.getenv("ENABLE_REDIS_RATE_LIMITING", "0") == "1"),
        "url": os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        "ssl": os.getenv("REDIS_SSL", "0") == "1",
        "password": os.getenv("REDIS_PASSWORD"),
        "socket_timeout": int(os.getenv("REDIS_SOCKET_TIMEOUT", "3")),
        "socket_connect_timeout": int(os.getenv("REDIS_CONNECT_TIMEOUT", "3")),
        "fail_closed": os.getenv("PESAGUARD_FAIL_CLOSED_REDIS", "1") == "1",
    }


def _evaluate_session_risk(
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    device_id: Optional[str] = None,
    known_devices: Optional[List[str]] = None,
    country: Optional[str] = None,
    known_country: Optional[str] = None,
    signals_override: Optional[Dict[str, bool]] = None,
    tenant_policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Score trusted login signals against tenant-configurable weights and actions."""
    policy = tenant_policy or _auth_risk_policy_for_tenant(tenant_id)
    signals: Dict[str, bool] = dict(signals_override or {})
    known_devices = set((known_devices or []) if isinstance(known_devices, list) else [])
    signals.setdefault("new_device", bool(device_id and device_id not in known_devices))
    signals.setdefault("new_location", bool(country and known_country and country.upper() != str(known_country).upper()))
    if user_agent:
        signals.setdefault("suspicious_user_agent", any(marker in user_agent.lower() for marker in ("curl/", "bot", "python-requests", "wget")))
    if ip_address:
        try:
            signals.setdefault("link_local_ip", ipaddress.ip_address(ip_address).is_link_local)
        except ValueError:
            signals.setdefault("invalid_ip", True)

    risk_score = sum(
        float(weight) for signal, weight in policy["weights"].items() if signals.get(signal)
    )
    risk_score = min(1.0, max(0.0, risk_score))
    risk_level = "high" if risk_score >= policy["high_threshold"] else "medium" if risk_score >= policy["medium_threshold"] else "low"
    action = policy["high_action"] if risk_level == "high" else policy["medium_action"] if risk_level == "medium" else "allow"
    requires_reauth = action == "require_mfa"
    alert_summary = "session risk elevated" if risk_level != "low" else "session risk within policy"

    return {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "risk_score": round(risk_score, 3),
        "risk_level": risk_level,
        "action": action,
        "requires_reauth": requires_reauth,
        "signals": signals,
        "alert": {
            "level": risk_level,
            "summary": alert_summary,
            "channels": ["audit_log", "security_alert"] if requires_reauth else ["audit_log"],
        },
    }


_DEFAULT_AUTH_RISK_POLICY = {
    "medium_threshold": 0.35,
    "high_threshold": 0.70,
    "medium_action": "require_mfa",
    "high_action": "block",
    "privileged_operation_requires_mfa": True,
    "unusual_login_minimum_samples": 5,
    "unusual_login_hour_deviation": 6,
    "impossible_travel_minimum_speed_kmh": 900,
    "weights": {
        "new_device": 0.20,
        "new_location": 0.25,
        "impossible_travel": 0.70,
        "unusual_login_time": 0.20,
        "multiple_failed_attempts": 0.25,
        "credential_compromise": 0.80,
        "suspicious_ip": 0.60,
        "high_risk_session": 0.60,
        "privileged_operation": 0.15,
        "suspicious_user_agent": 0.15,
        "link_local_ip": 0.20,
    },
}


def _auth_risk_policy_for_tenant(tenant_id: Optional[str]) -> Dict[str, Any]:
    """Resolve validated risk controls from environment and tenant settings."""
    policy = {
        **_DEFAULT_AUTH_RISK_POLICY,
        "weights": dict(_DEFAULT_AUTH_RISK_POLICY["weights"]),
        "suspicious_ip_cidrs": [],
        "compromised_ip_addresses": [],
    }
    raw = os.getenv("PESAGUARD_AUTH_RISK_POLICY", "")
    if raw:
        try:
            configured = json.loads(raw)
            if isinstance(configured, dict):
                policy.update({key: value for key, value in configured.items() if key != "weights"})
                if isinstance(configured.get("weights"), dict):
                    policy["weights"].update(configured["weights"])
        except (TypeError, json.JSONDecodeError):
            logger.error("PESAGUARD_AUTH_RISK_POLICY is invalid JSON; using defaults")
    try:
        tenant_config = settings_store.get(str(tenant_id)) if tenant_id and hasattr(settings_store, "get") else {}
        tenant_policy = tenant_config.get("authentication_risk_policy", {}) if isinstance(tenant_config, dict) else {}
        if isinstance(tenant_policy, dict):
            policy.update({key: value for key, value in tenant_policy.items() if key != "weights"})
            if isinstance(tenant_policy.get("weights"), dict):
                policy["weights"].update(tenant_policy["weights"])
    except Exception:
        logger.warning("Unable to resolve tenant authentication risk policy", exc_info=True)

    for key, default in (("medium_threshold", 0.35), ("high_threshold", 0.70)):
        try:
            policy[key] = min(1.0, max(0.0, float(policy[key])))
        except (TypeError, ValueError):
            logger.warning("Invalid authentication risk threshold %s; using default", key)
            policy[key] = default
    if policy["high_threshold"] <= policy["medium_threshold"]:
        policy["high_threshold"] = min(1.0, policy["medium_threshold"] + 0.01)

    for key, default, minimum, maximum in (
        ("unusual_login_minimum_samples", 5, 1, 1000),
        ("unusual_login_hour_deviation", 6.0, 0.0, 12.0),
        ("impossible_travel_minimum_speed_kmh", 900.0, 1.0, 20_000.0),
    ):
        try:
            value = int(policy[key]) if key == "unusual_login_minimum_samples" else float(policy[key])
            policy[key] = min(maximum, max(minimum, value))
        except (KeyError, TypeError, ValueError, OverflowError):
            logger.warning("Invalid authentication risk control %s; using default", key)
            policy[key] = default

    for key, parser in (
        ("suspicious_ip_cidrs", ipaddress.ip_network),
        ("compromised_ip_addresses", ipaddress.ip_address),
    ):
        configured_values = policy.get(key, [])
        if not isinstance(configured_values, (list, tuple, set)):
            logger.warning("Invalid authentication risk control %s; expected a list", key)
            policy[key] = []
            continue
        valid_values = []
        for value in list(configured_values)[:2048]:
            try:
                valid_values.append(str(parser(str(value).strip(), strict=False)) if key == "suspicious_ip_cidrs" else str(parser(str(value).strip())))
            except ValueError:
                logger.warning("Ignoring invalid value in authentication risk control %s", key)
        policy[key] = valid_values

    for signal, weight in list(policy["weights"].items()):
        try:
            policy["weights"][signal] = min(1.0, max(0.0, float(weight)))
        except (TypeError, ValueError):
            policy["weights"].pop(signal, None)
    if policy.get("medium_action") not in {"require_mfa", "block", "allow"}:
        policy["medium_action"] = "require_mfa"
    if policy.get("high_action") not in {"block", "review", "require_mfa"}:
        policy["high_action"] = "block"
    return policy


def _trusted_location_from_request() -> Dict[str, Any]:
    """Read proxy-provided geo data only when deployment explicitly trusts that proxy."""
    if os.getenv("PESAGUARD_TRUST_GEO_HEADERS", "0").strip().lower() not in {"1", "true", "yes"}:
        return {}
    location: Dict[str, Any] = {}
    country = request.headers.get("X-Geo-Country", "").strip().upper()
    if re.fullmatch(r"[A-Z]{2}", country):
        location["country"] = country
    for header, field, minimum, maximum in (
        ("X-Geo-Latitude", "latitude", -90.0, 90.0),
        ("X-Geo-Longitude", "longitude", -180.0, 180.0),
    ):
        try:
            value = float(request.headers.get(header, ""))
            if minimum <= value <= maximum:
                location[field] = value
        except (TypeError, ValueError):
            pass
    return location


def _distance_km(first: Dict[str, Any], second: Dict[str, Any]) -> Optional[float]:
    try:
        lat1, lon1 = math.radians(float(first["latitude"])), math.radians(float(first["longitude"]))
        lat2, lon2 = math.radians(float(second["latitude"])), math.radians(float(second["longitude"]))
    except (KeyError, TypeError, ValueError):
        return None
    delta_lat, delta_lon = lat2 - lat1, lon2 - lon1
    value = math.sin(delta_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    return 6371.0 * 2 * math.atan2(math.sqrt(value), math.sqrt(max(0.0, 1 - value)))


def _browser_and_os(user_agent: Optional[str]) -> tuple[str, str]:
    agent = str(user_agent or "")[:2048]
    browser = "Unknown browser"
    for marker, label in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"), ("Safari/", "Safari")):
        if marker in agent:
            browser = label
            break
    operating_system = "Unknown OS"
    for marker, label in (("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iOS"), ("iPad", "iPadOS"), ("Mac OS", "macOS"), ("Linux", "Linux")):
        if marker in agent:
            operating_system = label
            break
    return browser, operating_system


def require_privileged_operation_mfa(view_func):
    """Require fresh MFA for sensitive actions, bound to the caller's validated session."""
    @wraps(view_func)
    def guarded(*args, **kwargs):
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return view_func(*args, **kwargs)
        user = get_current_user()
        policy = _auth_risk_policy_for_tenant(user.tenant_id)
        if not policy.get("privileged_operation_requires_mfa", True):
            return view_func(*args, **kwargs)

        session_id = getattr(user, "session_id", None)
        payload = request.get_json(silent=True) or {}
        code = str(payload.get("mfa_code") or payload.get("recovery_code") or "").strip()
        webauthn_proof_id = str(payload.get("mfa_challenge_id") or "").strip()
        db_session = SessionLocal()
        try:
            auth_session = db_session.query(UserSession).filter_by(
                id=session_id,
                tenant_id=user.tenant_id,
                user_id=user.user_id,
                active=True,
                state="ACTIVE",
            ).first() if session_id else None
            account = db_session.query(UserAccount).filter_by(id=user.user_id, tenant_id=user.tenant_id).first()
            if auth_session is None or account is None:
                return _api_error("step_up_required", "A valid session-bound MFA proof is required for this operation.", 401)
            if not account.mfa_enabled:
                return _api_error("mfa_enrollment_required", "MFA enrollment is required for this privileged operation.", 403)

            session_risk = (auth_session.session_metadata or {}).get("risk", {})
            signals = dict(session_risk.get("signals", {}))
            signals["privileged_operation"] = True
            risk_result = _evaluate_session_risk(
                tenant_id=user.tenant_id,
                user_id=user.user_id,
                signals_override=signals,
                tenant_policy=policy,
            )
            if risk_result.get("action") in {"block", "review"}:
                return _api_error("operation_blocked_for_review", "This privileged operation is blocked by authentication risk policy.", 403)
            if code:
                if not _verify_mfa_code(account, code):
                    db_session.rollback()
                    return _api_error("mfa_required", "A valid MFA code is required for this privileged operation.", 401)
            elif webauthn_proof_id:
                proof = db_session.query(MFAChallenge).filter_by(
                    id=webauthn_proof_id,
                    tenant_id=user.tenant_id,
                    user_id=user.user_id,
                    challenge_type="webauthn_step_up",
                    status="verified",
                ).with_for_update().first()
                if (
                    proof is None
                    or _is_expired(proof.expires_at)
                    or (proof.challenge_data or {}).get("session_id") != session_id
                ):
                    db_session.rollback()
                    return _api_error("mfa_required", "A valid, unused WebAuthn step-up proof is required.", 401)
                proof.status = "consumed"
                _record_mfa_event(
                    db_session,
                    user.tenant_id,
                    user.user_id,
                    "step_up.webauthn.consumed",
                    "success",
                    challenge_id=proof.id,
                    details={"operation": request.endpoint or "privileged_operation"},
                )
            else:
                db_session.rollback()
                return _api_error("mfa_required", "A valid MFA proof is required for this privileged operation.", 401)
            auth_session.mfa_verified = True
            db_session.commit()
        finally:
            db_session.close()
        return view_func(*args, **kwargs)
    return guarded


def _fetch_oidc_metadata(issuer: str) -> Dict[str, Any]:
    """Fetch and validate the OIDC metadata document from a real provider issuer."""
    if not issuer:
        raise ValueError("issuer is required")
    issuer_url = issuer.strip().rstrip("/")
    parsed_issuer = urlparse(issuer_url)
    if parsed_issuer.scheme != "https" or not parsed_issuer.hostname:
        raise ValueError("OIDC issuer must use HTTPS and include a hostname")
    metadata_url = f"{issuer_url}/.well-known/openid-configuration"
    try:
        response = requests.get(
            metadata_url,
            headers={"Accept": "application/json"},
            timeout=10,
            allow_redirects=False,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to fetch OIDC metadata for issuer {issuer}: {exc}") from exc

    required_fields = ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"]
    missing = [field for field in required_fields if not payload.get(field)]
    if missing:
        raise ValueError(f"OIDC metadata missing required fields: {missing}")
    return payload


def _resolve_oidc_provider(tenant_id: Optional[str] = None, issuer: Optional[str] = None) -> Optional[OIDCProvider]:
    """Resolve the configured tenant OIDC provider, or fall back to the environment/default issuer when no explicit provider has been registered."""
    session = SessionLocal()
    try:
        query = session.query(OIDCProvider).filter(OIDCProvider.enabled.is_(True))
        candidate_tenant = tenant_id or request.args.get("tenant_id") or os.getenv("TENANT_ID") or "default"
        if issuer:
            provider = query.filter(OIDCProvider.issuer == issuer, OIDCProvider.tenant_id == candidate_tenant).first()
            if provider:
                return provider
        if tenant_id or request.args.get("tenant_id"):
            provider = query.filter(OIDCProvider.tenant_id == candidate_tenant).order_by(OIDCProvider.created_at.desc()).first()
            if provider:
                return provider
        env_issuer = os.getenv("OIDC_ISSUER") or (request.url_root.rstrip("/") if request.url_root else "https://api.pesaguard.victorkipruto.com")
        provider = query.filter(OIDCProvider.issuer == env_issuer).order_by(OIDCProvider.created_at.desc()).first()
        if provider:
            return provider
        if not issuer and not query.count():
            return OIDCProvider(
                id=str(uuid.uuid4()),
                tenant_id=candidate_tenant,
                provider_name="default-local-oidc",
                issuer=env_issuer,
                authorization_endpoint=f"{env_issuer.rstrip('/')}/auth/sso/oidc/authorize",
                token_endpoint=f"{env_issuer.rstrip('/')}/auth/sso/oidc/token",
                userinfo_endpoint=f"{env_issuer.rstrip('/')}/auth/sso/oidc/userinfo",
                jwks_uri=f"{env_issuer.rstrip('/')}/auth/sso/oidc/jwks",
                scopes=["openid", "profile", "email"],
                enabled=True,
                provider_metadata={
                    "issuer": env_issuer,
                    "authorization_endpoint": f"{env_issuer.rstrip('/')}/auth/sso/oidc/authorize",
                    "token_endpoint": f"{env_issuer.rstrip('/')}/auth/sso/oidc/token",
                    "userinfo_endpoint": f"{env_issuer.rstrip('/')}/auth/sso/oidc/userinfo",
                    "jwks_uri": f"{env_issuer.rstrip('/')}/auth/sso/oidc/jwks",
                    "scopes_supported": ["openid", "profile", "email"],
                },
            )
        return None
    finally:
        session.close()


def _api_success(payload: Any, status_code: int = 200, meta: Optional[Dict[str, Any]] = None):
    body = {
        "status": "success",
        "data": payload,
        "request_id": _request_id_value(),
        "tenant_id": request.headers.get("X-Tenant-ID") or os.getenv("TENANT_ID", "default"),
    }
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key not in body and key not in {"status", "error", "data", "request_id", "tenant_id", "meta", "ResultCode", "ResultDesc"}:
                body[key] = value
    if meta is not None:
        body["meta"] = meta
    return jsonify(body), status_code


def _api_error(code: str, message: str, status_code: int = 400, details: Optional[Dict[str, Any]] = None):
    body = {
        "status": "error",
        "error": {"code": code, "message": message},
        "request_id": _request_id_value(),
        "tenant_id": request.headers.get("X-Tenant-ID") or os.getenv("TENANT_ID", "default"),
        "ResultCode": 1,
        "ResultDesc": message,
    }
    if details:
        body["error"]["details"] = details
    return jsonify(body), status_code


def resolve_email_locale(tenant_id: str | None, user_id: str | None = None, settings_path=None) -> str:
    """Resolve the locale to use for email notifications based on tenant settings."""
    if not tenant_id:
        tenant_id = "default"
    if settings_path is not None:
        store = TenantSettingsStore(str(settings_path))
    else:
        store = settings_store

    tenant_settings = store.get(str(tenant_id))
    if not isinstance(tenant_settings, dict):
        return "en"

    if user_id:
        user_overrides = tenant_settings.get("user_locale_overrides") or {}
        if isinstance(user_overrides, dict):
            override = user_overrides.get(str(user_id)) or user_overrides.get(user_id)
            if override:
                return str(override)

        user_locales = tenant_settings.get("user_locales") or {}
        if isinstance(user_locales, dict):
            override = user_locales.get(str(user_id)) or user_locales.get(user_id)
            if override:
                return str(override)

    locale = tenant_settings.get("preferred_locale") or tenant_settings.get("locale")
    if locale:
        return str(locale)

    return "en"


def _record_action_audit(session, tenant_id: str, actor: str, action: str, details: Optional[Dict[str, Any]] = None) -> None:
    """Record an immutable audit trail entry for privileged operations."""
    try:
        entry = ActionAuditEntry(
            id=f"audit_{int(datetime.now(timezone.utc).timestamp() * 1000)}_{uuid.uuid4().hex[:8]}",
            tenant_id=tenant_id,
            actor=actor,
            action=action,
            details=details or {},
            created_at=datetime.now(timezone.utc),
        )
        session.add(entry)
        session.commit()
    except Exception as exc:
        logger.exception("Failed to persist action audit entry: %s", exc)
        if session:
            session.rollback()


def _incident_belongs_to_tenant(session, incident_id: str, tenant_id: str) -> Optional[Discrepancy]:
    """Fetch a discrepancy record ensuring absolute tenant isolation (IDOR protection)."""
    return (
        session.query(Discrepancy)
        .filter(Discrepancy.id == incident_id, Discrepancy.tenant_id == tenant_id)
        .first()
    )


@app.after_request
def _inject_security_headers(response: Response) -> Response:
    """Inject robust security and CORS headers into all API responses."""
    response.headers["Access-Control-Allow-Origin"] = os.getenv("PESAGUARD_ALLOWED_ORIGIN", "")
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(HTTPException)
def handle_http_exception(error: HTTPException) -> Response:
    return jsonify({
        "error": error.name.lower().replace(" ", "_"),
        "message": error.description,
        "status_code": error.code,
    }), error.code


@app.errorhandler(Exception)
def handle_internal_error(error: Exception) -> Response:
    logger.exception("Unhandled exception in Advanced Features API: %s", error)
    return jsonify({
        "error": "internal_server_error",
        "message": "An unexpected error occurred. Our engineering team has been notified.",
    }), 500


# ============================================================================
# AUTHENTICATION & TOKENS
# ============================================================================

_PBKDF2_ITERATIONS = 200_000
_ARGON2_TIME_COST = 3
_ARGON2_MEMORY_COST_KIB = 65_536
_ARGON2_PARALLELISM = 2
_ARGON2_HASH_LENGTH = 32
_ARGON2_SALT_LENGTH = 16
_ARGON2_PARAMETERS = {
    "time_cost": _ARGON2_TIME_COST,
    "memory_cost_kib": _ARGON2_MEMORY_COST_KIB,
    "parallelism": _ARGON2_PARALLELISM,
    "hash_length": _ARGON2_HASH_LENGTH,
    "salt_length": _ARGON2_SALT_LENGTH,
    "version": 19,
}
_ARGON2 = PasswordHasher(
    time_cost=_ARGON2_TIME_COST,
    memory_cost=_ARGON2_MEMORY_COST_KIB,
    parallelism=_ARGON2_PARALLELISM,
    hash_len=_ARGON2_HASH_LENGTH,
    salt_len=_ARGON2_SALT_LENGTH,
)
_COMMON_PASSWORDS = frozenset({
    "password", "password123", "1234567890", "qwerty", "qwerty123", "letmein",
    "welcome", "admin", "admin123", "iloveyou", "monkey", "dragon", "changeme",
})


def _argon2_hash_password(password: str) -> str:
    return _ARGON2.hash(password)


def _argon2_verify_password(password_hash: str, password: str) -> bool:
    try:
        return bool(_ARGON2.verify(password_hash, password))
    except (VerifyMismatchError, VerificationError, InvalidHashError, TypeError, ValueError):
        return False


def _password_reset_token_hash(token: str) -> str:
    return hmac.new(os.getenv("JWT_SECRET_KEY", "").encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def _active_password_credential(session, user_id: str, tenant_id: str) -> Optional[PasswordCredential]:
    return session.query(PasswordCredential).filter_by(
        user_id=user_id,
        tenant_id=tenant_id,
        status="ACTIVE",
    ).order_by(PasswordCredential.changed_at.desc()).first()


def _password_matches(user_record: UserAccount, password: str) -> tuple[bool, bool]:
    """Return (valid, legacy) while keeping credential verification server-side."""
    with SessionLocal() as session:
        credential = _active_password_credential(session, user_record.id, user_record.tenant_id)
        if credential is not None:
            return _argon2_verify_password(credential.password_hash, password), False
    try:
        computed = _hash_password(password, user_record.password_salt or "")
        return hmac.compare_digest(computed, user_record.password_hash or ""), True
    except (TypeError, ValueError):
        return False, True


def _rotate_password_credential(session, account: UserAccount, password: str, reason: str) -> PasswordCredential:
    """Revoke the active password, preserve its hash in history, and issue Argon2id."""
    current = _active_password_credential(session, account.id, account.tenant_id)
    if current is not None and _argon2_verify_password(current.password_hash, password):
        raise ValueError("password_reuse")
    history_rows = session.query(PasswordHistory).filter_by(
        user_id=account.id,
        tenant_id=account.tenant_id,
    ).order_by(PasswordHistory.created_at.desc()).limit(12).all()
    if any(_argon2_verify_password(row.password_hash, password) for row in history_rows):
        raise ValueError("password_reuse")

    now = _now_utc()
    if current is not None:
        session.add(PasswordHistory(
            history_id=f"ph_{uuid.uuid4().hex[:16]}",
            user_id=account.id,
            tenant_id=account.tenant_id,
            password_hash=current.password_hash,
            algorithm=current.algorithm,
            parameters=current.parameters or _ARGON2_PARAMETERS,
            created_at=now,
        ))
        current.status = "REVOKED"
        current.revoked_at = now
        current.revoked_reason = reason

    encoded = _argon2_hash_password(password)
    credential = PasswordCredential(
        credential_id=f"cred_{uuid.uuid4().hex[:16]}",
        user_id=account.id,
        tenant_id=account.tenant_id,
        password_hash=encoded,
        algorithm="argon2id",
        parameters=_ARGON2_PARAMETERS,
        version=1,
        status="ACTIVE",
        created_at=now,
        changed_at=now,
        expires_at=now + timedelta(days=int(os.getenv("PESAGUARD_PASSWORD_EXPIRY_DAYS", "90"))),
    )
    session.add(credential)
    account.password_hash = None
    account.password_salt = None
    attrs = dict(account.attributes or {})
    attrs["password_expires_at"] = credential.expires_at.isoformat()
    account.attributes = attrs
    return credential


def _hash_password(password: str, salt_hex: str) -> str:
    """Compute secure PBKDF2-HMAC-SHA256 password hashes."""
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS).hex()


def _password_policy_error(password: Any) -> Optional[str]:
    """Return a policy failure without imposing predictable character classes."""
    if not isinstance(password, str):
        return "Password must be a string."
    if len(password) < 12:
        return "Password must be at least 12 characters long."
    if len(password) > 128:
        return "Password must not exceed 128 characters."
    if len(set(password.casefold())) < 4:
        return "Password does not contain enough variation."
    if password.casefold() in _COMMON_PASSWORDS:
        return "Password is too common."
    if os.getenv("PESAGUARD_HIBP_ENABLED", "0").strip().lower() in {"1", "true", "yes"}:
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        try:
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{digest[:5]}",
                headers={"Add-Padding": "true", "User-Agent": "PesaGuard-password-policy"},
                timeout=2,
            )
            if response.status_code != 200:
                return "Password breach screening is temporarily unavailable."
            suffix = digest[5:]
            if any(line.split(":", 1)[0].strip().upper() == suffix for line in response.text.splitlines() if ":" in line):
                return "Password has appeared in a known breach."
        except requests.RequestException:
            return "Password breach screening is temporarily unavailable."
    return None


def _validate_password(password: str) -> bool:
    return _password_policy_error(password) is None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _is_expired(value: Optional[datetime]) -> bool:
    """Compare database timestamps safely regardless of driver timezone behavior."""
    if value is None:
        return True
    normalized = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return normalized <= _now_utc()


def _identity_status(account_status: str, email_verified: bool) -> str:
    if account_status == "pending_verification" or not email_verified:
        return "PENDING_VERIFICATION"
    if account_status == "locked":
        return "LOCKED"
    if account_status in {"suspended", "deactivated", "deleted"}:
        return account_status.upper()
    return "ACTIVE"


def _upsert_user_identity(
    session,
    account: UserAccount,
    *,
    email_verified: Optional[bool] = None,
    email_verified_at: Optional[datetime] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
    phone_verified: Optional[bool] = None,
) -> UserIdentity:
    """Synchronize the canonical identity projection from the credential account."""
    attrs = dict(account.attributes or {})
    verified = bool(attrs.get("email_verified", False)) if email_verified is None else email_verified
    identity = session.get(UserIdentity, account.id)
    if identity is None:
        identity = session.query(UserIdentity).filter_by(tenant_id=account.tenant_id, email=account.email).first()
    if identity is None:
        identity = UserIdentity(
            user_id=account.id,
            tenant_id=account.tenant_id,
            external_id=f"ext_{uuid.uuid4().hex}",
            email=account.email,
            email_verified=verified,
            email_verified_at=email_verified_at if verified else None,
            phone=phone,
            phone_verified=bool(phone_verified) if phone_verified is not None else False,
            first_name=first_name,
            last_name=last_name,
            display_name=display_name or account.username,
            status=_identity_status(account.status, verified),
        )
        session.add(identity)
    else:
        identity.email = account.email
        identity.email_verified = verified
        if verified and email_verified_at is not None:
            identity.email_verified_at = email_verified_at
        if first_name is not None:
            identity.first_name = first_name
        if last_name is not None:
            identity.last_name = last_name
        if display_name is not None:
            identity.display_name = display_name
        if phone is not None:
            identity.phone = phone
        if phone_verified is not None:
            identity.phone_verified = phone_verified
        identity.status = _identity_status(account.status, verified)
    identity.updated_at = _now_utc()
    return identity


def _get_user_account_by_email(email: str, tenant_id: Optional[str] = None) -> Optional[UserAccount]:
    normalized = (email or "").strip().lower()
    if not normalized:
        return None
    session = SessionLocal()
    try:
        query = session.query(UserAccount).filter(UserAccount.email == normalized)
        if tenant_id:
            query = query.filter(UserAccount.tenant_id == tenant_id)
        return query.order_by(UserAccount.created_at.desc()).first()
    finally:
        session.close()


def _resolve_local_user(identifier: str, tenant_id: Optional[str] = None) -> Optional[UserAccount]:
    """Resolve an account by either username or email for internal local-auth flows."""
    value = (identifier or "").strip()
    if not value:
        return None

    normalized = value.lower()
    session = SessionLocal()
    try:
        query = session.query(UserAccount)
        if tenant_id:
            query = query.filter(UserAccount.tenant_id == tenant_id)
        user = query.filter(
            (UserAccount.username == value) |
            (UserAccount.email == normalized)
        ).order_by(UserAccount.created_at.desc()).first()
        return user
    finally:
        session.close()


def _build_local_jwt_user(user_record: UserAccount):
    roles = list(user_record.roles or [])
    permissions = list(user_record.permissions or [])
    if not roles:
        roles = ["operator"]
    if not permissions:
        permissions = AuthRBAC._get_permissions_for_roles(roles)
    return IdentityAccessService.create_principal(
        user_id=user_record.id,
        username=user_record.username,
        tenant_id=user_record.tenant_id,
        roles=roles,
        permissions=permissions,
    )


def _persist_email_verification(user_record: UserAccount, token: Optional[str] = None) -> str:
    generated = token or secrets.token_urlsafe(24)
    attrs = dict(user_record.attributes or {})
    attrs["email_verification"] = {
        "token": generated,
        "expires_at": (_now_utc() + timedelta(minutes=30)).isoformat(),
    }
    attrs["email_verified"] = False
    user_record.attributes = attrs
    return generated


def _normalize_registration_email(value: Any) -> Optional[str]:
    """Normalize and validate an email without accepting display-name or control input."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().casefold()
    if len(normalized) > 254 or any(ord(char) < 33 for char in normalized):
        return None
    if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,63}", normalized):
        return None
    return normalized


def _is_production_environment() -> bool:
    return runtime_environment() == "production"


def _deliver_verification_email(tenant_id: str, user_id: str, email: Optional[str], token: str) -> bool:
    """Deliver verification through the configured notification service in production."""
    subject = "Verify your PesaGuard account"
    body = f"Use this verification token to activate your account: {token}"
    delivered = False
    error = None
    if not _is_production_environment():
        status = "skipped"
        error = "development delivery disabled"
    elif not email or not email_service.smtp_server:
        status = "failed"
        error = "verification email delivery is not configured"
    else:
        delivered, error = email_service._send_email(email, subject, body, body)
        status = "sent" if delivered else "failed"

    session = SessionLocal()
    try:
        session.add(EmailNotification(
            id=f"email_{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            recipient_email=email or "unknown",
            report_type="email_verification",
            subject=subject,
            status=status,
            content_hash=hashlib.sha256(f"verification:{email or ''}".encode("utf-8")).hexdigest(),
            error_message=error,
            sent_at=_now_utc() if delivered else None,
            created_at=_now_utc(),
        ))
        if not delivered and status == "failed":
            session.query(PasswordlessChallenge).filter_by(
                user_id=user_id,
                tenant_id=tenant_id,
                status="pending",
            ).update({PasswordlessChallenge.status: "delivery_failed"}, synchronize_session=False)
        session.commit()
    finally:
        session.close()
    if error and status == "failed":
        logger.error("Verification email delivery failed: %s", error)
    return delivered or status == "skipped"


def _deliver_password_reset_email(tenant_id: str, user_id: str, email: Optional[str], token: str) -> bool:
    """Persist reset-email delivery and revoke the reset state when delivery fails."""
    subject = "Reset your PesaGuard password"
    body = f"Use this password-reset token within 20 minutes: {token}"
    delivered = False
    error = None
    if not _is_production_environment():
        status = "skipped"
        error = "development delivery disabled"
    elif not email or not email_service.smtp_server:
        status = "failed"
        error = "password reset email delivery is not configured"
    else:
        delivered, error = email_service._send_email(email, subject, body, body)
        status = "sent" if delivered else "failed"
    session = SessionLocal()
    try:
        session.add(EmailNotification(
            id=f"email_{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            recipient_email=email or "unknown",
            report_type="password_reset",
            subject=subject,
            status=status,
            content_hash=hashlib.sha256(f"password-reset:{email or ''}".encode("utf-8")).hexdigest(),
            error_message=error,
            sent_at=_now_utc() if delivered else None,
            created_at=_now_utc(),
        ))
        if status == "failed":
            session.query(PasswordResetState).filter_by(
                user_id=user_id,
                tenant_id=tenant_id,
                status="PENDING",
            ).update({PasswordResetState.status: "REVOKED"}, synchronize_session=False)
        session.commit()
    finally:
        session.close()
    if status == "failed":
        logger.error("Password reset email delivery failed: %s", error)
    return delivered or status == "skipped"


def _create_email_verification_state(session, account: UserAccount) -> str:
    """Issue a hashed, expiring, single-active email verification challenge."""
    token = secrets.token_urlsafe(32)
    session.query(PasswordlessChallenge).filter_by(
        user_id=account.id,
        tenant_id=account.tenant_id,
        status="pending",
    ).update({PasswordlessChallenge.status: "revoked"}, synchronize_session=False)
    session.add(PasswordlessChallenge(
        id=f"email_verify_{uuid.uuid4().hex[:16]}",
        user_id=account.id,
        tenant_id=account.tenant_id,
        token_hash=_password_reset_token_hash(token),
        status="pending",
        created_at=_now_utc(),
        expires_at=_now_utc() + timedelta(minutes=30),
        attempts=0,
    ))
    attrs = dict(account.attributes or {})
    attrs["email_verified"] = False
    attrs["email_verification_expires_at"] = (_now_utc() + timedelta(minutes=30)).isoformat()
    attrs.pop("email_verification", None)
    account.attributes = attrs
    return token


def _registration_audit(session, account: UserAccount, action: str, outcome: str = "success") -> None:
    session.add(ActionAuditEntry(
        tenant_id=account.tenant_id,
        actor="anonymous",
        actor_type="anonymous",
        action=action,
        category="authentication",
        outcome=outcome,
        resource_type="user_identity",
        resource_id=account.id,
        details={"email_hash": _password_reset_token_hash(account.email or "")},
        idempotency_key=f"{action}:{account.id}:{uuid.uuid4().hex}",
    ))


def _register_local_user(data: Dict[str, Any]) -> Dict[str, Any]:
    username = str(data.get("username") or "").strip()
    email = _normalize_registration_email(data.get("email"))
    password = data.get("password")
    tenant_id = str(data.get("tenant_id") or "default").strip() or "default"
    first_name = str(data.get("first_name") or "").strip() or None
    last_name = str(data.get("last_name") or "").strip() or None
    display_name = str(data.get("display_name") or "").strip() or None
    phone = str(data.get("phone") or "").strip() or None

    if data.get("website") or data.get("company_website"):
        return {"status": "accepted"}
    if not username or not email or not isinstance(password, str):
        return {"error": "invalid_request", "message": "username, email, and password are required."}
    policy_error = _password_policy_error(password)
    if policy_error:
        return {"error": "weak_password", "message": policy_error}
    if "@" not in email:
        return {"error": "invalid_email", "message": "A valid email address is required."}

    session = SessionLocal()
    try:
        existing = session.query(UserAccount).filter(
            UserAccount.tenant_id == tenant_id,
            (UserAccount.username == username) | (UserAccount.email == email),
        ).first()
        if existing is not None:
            if existing.status not in {"pending_verification", "locked"}:
                _registration_audit(session, existing, "registration.duplicate", "denied")
                session.commit()
                return {"status": "accepted"}

            verification_token = _create_email_verification_state(session, existing)
            existing.status = "pending_verification"
            _upsert_user_identity(session, existing, email_verified=False, first_name=first_name, last_name=last_name, display_name=display_name, phone=phone)
            _registration_audit(session, existing, "registration.verification_resent")
            session.commit()
            _deliver_verification_email(existing.tenant_id, existing.id, existing.email, verification_token)
            result = {
                "status": "verification_resent",
                "user": {
                    "id": existing.id,
                    "username": existing.username,
                    "email": existing.email,
                    "tenant_id": existing.tenant_id,
                    "roles": existing.roles,
                    "status": existing.status,
                },
            }
            if not _is_production_environment():
                result["verification_token"] = verification_token
            return result

        user_id = f"user_{uuid.uuid4().hex[:12]}"
        account = UserAccount(
            id=user_id,
            tenant_id=tenant_id,
            username=username,
            email=email,
            password_hash=None,
            password_salt="argon2id",
            roles=["operator"],
            permissions=AuthRBAC._get_permissions_for_roles(["operator"]),
            attributes={
                "email_verified": False,
                "failed_login_count": 0,
                "password_expires_at": (_now_utc() + timedelta(days=int(os.getenv("PESAGUARD_PASSWORD_EXPIRY_DAYS", "90")))).isoformat(),
            },
            mfa_enabled=False,
            status="pending_verification",
        )
        session.add(account)
        session.flush()
        _rotate_password_credential(session, account, password, "initial credential")
        verification_token = _create_email_verification_state(session, account)
        _upsert_user_identity(
            session,
            account,
            email_verified=False,
            first_name=first_name,
            last_name=last_name,
            display_name=display_name,
            phone=phone,
        )
        _registration_audit(session, account, "registration.created")
        session.commit()
        _deliver_verification_email(account.tenant_id, account.id, account.email, verification_token)
        result = {
            "user": {
                "id": account.id,
                "username": account.username,
                "email": account.email,
                "tenant_id": account.tenant_id,
                "roles": account.roles,
                "status": account.status,
            },
        }
        if not _is_production_environment():
            result["verification_token"] = verification_token
        return result
    except Exception:
        session.rollback()
        logger.exception("Local user registration failed")
        return {"error": "registration_failed", "message": "User registration failed due to an internal error."}
    finally:
        session.close()


def _verify_local_email(user_record: UserAccount, token: str) -> bool:
    attrs = dict(user_record.attributes or {})
    with SessionLocal() as session:
        challenge = session.query(PasswordlessChallenge).filter_by(
            user_id=user_record.id,
            tenant_id=user_record.tenant_id,
            status="pending",
        ).order_by(PasswordlessChallenge.created_at.desc()).first()
        if challenge is None:
            return False
        if _is_expired(challenge.expires_at):
            challenge.status = "expired"
            session.commit()
            return False
        if challenge.attempts >= 5:
            challenge.status = "failed"
            session.commit()
            return False
        challenge.attempts += 1
        if not hmac.compare_digest(challenge.token_hash, _password_reset_token_hash(token)):
            challenge.status = "failed" if challenge.attempts >= 5 else "pending"
            session.commit()
            return False
        challenge.status = "verified"
        session.commit()
    attrs["email_verified"] = True
    attrs.pop("email_verification", None)
    attrs.pop("email_verification_expires_at", None)
    user_record.attributes = attrs
    if user_record.status == "pending_verification":
        user_record.status = "active"
    return True


def _login_protection_int(name: str, default: int, *, maximum: int = 1_000_000) -> int:
    """Read bounded integer login controls without accepting unsafe values."""
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        logger.error("Invalid integer value for %s; using the safe default", name)
        return default
    if not 1 <= value <= maximum:
        logger.error("Out-of-range value for %s; using the safe default", name)
        return default
    return value


def _parse_lockout_deadline(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def _check_account_lockout(user_record: UserAccount) -> Optional[datetime]:
    """Read and automatically clear expired lockouts using a row-locked database update."""
    session = SessionLocal()
    try:
        stored = session.query(UserAccount).filter_by(
            id=user_record.id,
            tenant_id=user_record.tenant_id,
        ).with_for_update().first()
        if stored is None:
            return None
        attrs = dict(stored.attributes or {})
        now = _now_utc()
        lock_deadline = _parse_lockout_deadline(attrs.get("locked_until"))
        if lock_deadline is not None and lock_deadline > now:
            user_record.attributes = attrs
            user_record.status = stored.status
            return lock_deadline

        malformed_lock = bool(attrs.get("locked_until")) and lock_deadline is None
        if malformed_lock and stored.status == "locked":
            lock_deadline = now + timedelta(
                minutes=_login_protection_int("PESAGUARD_ACCOUNT_LOCKOUT_MINUTES", 15, maximum=1440)
            )
            attrs["locked_until"] = lock_deadline.isoformat()
            stored.attributes = attrs
            _upsert_user_identity(session, stored)
            session.commit()
            user_record.attributes = attrs
            user_record.status = stored.status
            return lock_deadline

        if attrs.get("locked_until") or stored.status == "locked":
            attrs.pop("locked_until", None)
            attrs.pop("failed_login_count", None)
            attrs.pop("failed_login_window_started_at", None)
            attrs.pop("next_login_allowed_at", None)
            attrs.pop("last_failed_login_at", None)
            stored.attributes = attrs
            if stored.status == "locked":
                stored.status = "active"
            _upsert_user_identity(session, stored)
            session.commit()
        user_record.attributes = dict(stored.attributes or {})
        user_record.status = stored.status
        return None
    finally:
        session.close()


def _account_login_retry_after(user_record: UserAccount) -> int:
    with SessionLocal() as session:
        stored = session.query(UserAccount).filter_by(
            id=user_record.id,
            tenant_id=user_record.tenant_id,
        ).with_for_update().first()
        if stored is None:
            return 0
        attrs = dict(stored.attributes or {})
        user_record.attributes = attrs
    deadline = _parse_lockout_deadline(attrs.get("next_login_allowed_at"))
    if deadline is None:
        return 0
    return max(0, math.ceil((deadline - _now_utc()).total_seconds()))


_LOGIN_PROTECTION_LIMITERS = {
    "account": RateLimiter(default_max_per_minute=_login_protection_int("PESAGUARD_LOGIN_ACCOUNT_RATE_LIMIT", 5), fail_closed=True),
    "ip": RateLimiter(default_max_per_minute=_login_protection_int("PESAGUARD_LOGIN_IP_RATE_LIMIT", 5), fail_closed=True),
    "device": RateLimiter(default_max_per_minute=_login_protection_int("PESAGUARD_LOGIN_DEVICE_RATE_LIMIT", 5), fail_closed=True),
}


def _login_throttle_scope(scope: str, tenant_id: str, identifier: str) -> str:
    digest = hashlib.sha256(f"{scope}:{tenant_id}:{identifier}".encode("utf-8")).hexdigest()[:32]
    return f"login:{scope}:{tenant_id}:{digest}"


def _reset_account_login_throttle(tenant_id: str, user_id: str) -> None:
    client_id = _login_throttle_scope("account", tenant_id, user_id)
    _LOGIN_PROTECTION_LIMITERS["account"].reset(client_id, "login:account")


def _record_login_failure(
    user_record: UserAccount,
    *,
    tenant_id: Optional[str] = None,
    identifier: Optional[str] = None,
    ip_address: Optional[str] = None,
    device_id: Optional[str] = None,
    persist_account: bool = True,
) -> Dict[str, Any]:
    """Apply distributed account/IP/device throttles and persist progressive lockout state."""
    tenant_key = str(tenant_id or user_record.tenant_id or "default").strip() or "default"
    ip_key = (ip_address or "unknown").strip() or "unknown"
    device_key = (device_id or "unknown").strip() or "unknown"
    account_key = (
        str(user_record.id) if persist_account else str(identifier or "unknown").strip().casefold()
    )
    throttle_limits = {
        "account": _login_protection_int("PESAGUARD_LOGIN_ACCOUNT_RATE_LIMIT", 5),
        "ip": _login_protection_int("PESAGUARD_LOGIN_IP_RATE_LIMIT", 5),
        "device": _login_protection_int("PESAGUARD_LOGIN_DEVICE_RATE_LIMIT", 5),
    }
    detection_window = _login_protection_int("PESAGUARD_LOGIN_DETECTION_WINDOW_SECONDS", 600, maximum=86_400)
    stuffing_threshold = _login_protection_int("PESAGUARD_LOGIN_STUFFING_ACCOUNT_THRESHOLD", 5, maximum=10_000)
    account_fingerprint = hashlib.sha256(account_key.encode("utf-8")).hexdigest()
    distinct_accounts: Dict[str, int] = {}
    try:
        for scope, source in (("ip", ip_key), ("device", device_key)):
            client_id = _login_throttle_scope(scope, tenant_key, source)
            distinct_accounts[scope] = _LOGIN_PROTECTION_LIMITERS[scope].record_distinct(
                client_id,
                f"login:{scope}:identifiers",
                account_fingerprint,
                detection_window,
            )
    except RuntimeError:
        return {
            "locked": False,
            "failed_login_count": 0,
            "retry_after": 1,
            "throttle_reason": "distributed_limiter",
            "account_locked": False,
            "rate_limited": False,
            "limiter_unavailable": True,
        }

    throttled_scopes = []
    retry_after = 0
    for scope, limit in throttle_limits.items():
        _LOGIN_PROTECTION_LIMITERS[scope].set_limits(limit)
        scope_value = {"account": account_key, "ip": ip_key, "device": device_key}[scope]
        client_id = _login_throttle_scope(scope, tenant_key, scope_value)
        try:
            is_allowed, status = _LOGIN_PROTECTION_LIMITERS[scope].is_allowed(client_id, f"login:{scope}")
        except RuntimeError:
            is_allowed, status = False, {"unavailable": True, "retry_after": 1}
        if status.get("unavailable"):
            return {
                "locked": False,
                "failed_login_count": 0,
                "retry_after": int(status.get("retry_after", 1) or 1),
                "throttle_reason": scope,
                "account_locked": False,
                "rate_limited": False,
                "limiter_unavailable": True,
            }
        if not is_allowed:
            throttled_scopes.append(scope)
            retry_after = max(retry_after, int(status.get("retry_after", 0) or 0))

    account_locked = False
    count = 0
    locked_until = None
    failure_window = _login_protection_int("PESAGUARD_LOGIN_FAILURE_WINDOW_MINUTES", 15, maximum=1440)
    failure_threshold = _login_protection_int("PESAGUARD_LOGIN_FAILURE_LIMIT", 5, maximum=1000)
    base_lockout = _login_protection_int("PESAGUARD_ACCOUNT_LOCKOUT_MINUTES", 15, maximum=1440)
    max_lockout = _login_protection_int("PESAGUARD_ACCOUNT_LOCKOUT_MAX_MINUTES", 240, maximum=10_080)
    base_delay = _login_protection_int("PESAGUARD_LOGIN_PROGRESSIVE_DELAY_BASE_SECONDS", 1, maximum=60)
    max_delay = _login_protection_int("PESAGUARD_LOGIN_PROGRESSIVE_DELAY_MAX_SECONDS", 30, maximum=600)
    escalation_reset_hours = _login_protection_int("PESAGUARD_ACCOUNT_LOCKOUT_ESCALATION_RESET_HOURS", 24, maximum=8760)
    session = SessionLocal()
    try:
        stored = session.query(UserAccount).filter_by(
            id=user_record.id,
            tenant_id=user_record.tenant_id,
        ).with_for_update().first() if persist_account else None
        if stored is not None:
            attrs = dict(stored.attributes or {})
            now = _now_utc()
            window_started = _parse_lockout_deadline(attrs.get("failed_login_window_started_at"))
            if window_started is None or now - window_started >= timedelta(minutes=failure_window):
                count = 0
                attrs["failed_login_window_started_at"] = now.isoformat()
            else:
                count = int(attrs.get("failed_login_count", 0) or 0)
            count += 1
            attrs["failed_login_count"] = count
            attrs["last_failed_login_at"] = now.isoformat()
            delay_seconds = min(max_delay, base_delay * (2 ** min(max(count - 1, 0), 16)))
            attrs["next_login_allowed_at"] = (now + timedelta(seconds=delay_seconds)).isoformat()
            if count >= failure_threshold:
                previous_lockout = _parse_lockout_deadline(attrs.get("last_lockout_at"))
                lockout_count = int(attrs.get("lockout_count", 0) or 0)
                if previous_lockout is None or now - previous_lockout >= timedelta(hours=escalation_reset_hours):
                    lockout_count = 0
                duration = min(max_lockout, base_lockout * (2 ** min(lockout_count, 16)))
                locked_until = now + timedelta(minutes=duration)
                attrs["lockout_count"] = lockout_count + 1
                attrs["last_lockout_at"] = now.isoformat()
                attrs["locked_until"] = locked_until.isoformat()
                stored.status = "locked"
                account_locked = True
            stored.attributes = attrs
            if account_locked:
                _upsert_user_identity(session, stored)
            session.commit()
            user_record.attributes = attrs
            user_record.status = stored.status
        else:
            count = 1
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    throttle_reason = throttled_scopes[0] if throttled_scopes else None
    retry_after = max(
        retry_after,
        int((locked_until - _now_utc()).total_seconds()) if locked_until else 0,
    )
    if not locked_until and stored is not None:
        retry_after = max(retry_after, delay_seconds)
    return {
        "locked": account_locked,
        "failed_login_count": count,
        "retry_after": retry_after,
        "throttle_reason": throttle_reason,
        "account_locked": account_locked,
        "rate_limited": bool(throttled_scopes),
        "credential_stuffing_detected": any(
            value >= stuffing_threshold for value in distinct_accounts.values()
        ),
        "brute_force_detected": account_locked or "account" in throttled_scopes,
        "distinct_account_counts": distinct_accounts,
        "progressive_delay_seconds": delay_seconds if stored is not None else 0,
    }


def _clear_login_failures(user_record: UserAccount) -> None:
    attrs = dict(user_record.attributes or {})
    attrs["failed_login_count"] = 0
    attrs.pop("locked_until", None)
    attrs.pop("failed_login_window_started_at", None)
    attrs.pop("next_login_allowed_at", None)
    attrs.pop("last_failed_login_at", None)
    attrs.pop("lockout_count", None)
    attrs.pop("last_lockout_at", None)
    user_record.attributes = attrs


def _password_is_expired(user_record: UserAccount) -> bool:
    """Return whether the account password has passed its resolved policy."""
    expired, _, _, _ = _password_expiration_state(user_record)
    return expired


def _password_policy_for_account(user_record: UserAccount) -> Dict[str, Any]:
    """Resolve tenant, organization, platform, and legacy environment policy."""
    fallback_age = int(os.getenv("PESAGUARD_PASSWORD_EXPIRY_DAYS", "90"))
    policy = {
        "enabled": True,
        "max_age_days": fallback_age,
        "privileged_max_age_days": None,
        "notify_before_days": 14,
        "force_change": True,
        "source": "environment",
    }
    with SessionLocal() as session:
        credential = _active_password_credential(session, user_record.id, user_record.tenant_id)
        scopes = [("tenant", user_record.tenant_id)]
        memberships = session.query(OrganizationMembership).filter_by(
            user_id=user_record.id,
            tenant_id=user_record.tenant_id,
            active=True,
        ).all()
        scopes.extend(("organization", membership.organization_id) for membership in memberships)
        tenant = session.get(TenantRecord, user_record.tenant_id)
        if tenant is not None:
            scopes.append(("platform", tenant.platform_id))
        records = session.query(PasswordPolicy).filter(
            PasswordPolicy.scope_type.in_([scope_type for scope_type, _ in scopes]),
            PasswordPolicy.scope_id.in_([scope_id for _, scope_id in scopes]),
        ).all()
        priority = {"tenant": 0, "organization": 1, "platform": 2}
        records.sort(key=lambda row: priority.get(row.scope_type, 99))
        if records:
            selected = records[0]
            policy.update({
                "enabled": selected.enabled,
                "max_age_days": selected.max_age_days,
                "privileged_max_age_days": selected.privileged_max_age_days,
                "notify_before_days": selected.notify_before_days,
                "force_change": selected.force_change,
                "source": f"{selected.scope_type}:{selected.scope_id}",
            })
        return policy


def _password_expiration_state(user_record: UserAccount) -> tuple[bool, bool, Optional[datetime], bool]:
    """Return expired, should-notify, expiry timestamp, and force-change state."""
    with SessionLocal() as session:
        credential = _active_password_credential(session, user_record.id, user_record.tenant_id)
        if credential is None:
            return False, False, None, False
        policy = _password_policy_for_account(user_record)
        if not policy["enabled"] or policy["max_age_days"] is None:
            return False, False, None, bool(policy["force_change"])
        privileged = bool({AuthRBAC.normalize_role_name(role) for role in (user_record.roles or [])}.intersection({"admin", "owner", "platform-admin"}))
        max_age = policy["privileged_max_age_days"] if privileged and policy["privileged_max_age_days"] is not None else policy["max_age_days"]
        changed_at = credential.changed_at or credential.created_at
        if changed_at.tzinfo is None:
            changed_at = changed_at.replace(tzinfo=timezone.utc)
        expires_at = changed_at + timedelta(days=max(0, int(max_age)))
        if policy["source"] == "environment" and credential.expires_at is not None:
            credential_expiry = credential.expires_at
            if credential_expiry.tzinfo is None:
                credential_expiry = credential_expiry.replace(tzinfo=timezone.utc)
            expires_at = min(expires_at, credential_expiry)
        expired = expires_at <= _now_utc()
        notify_at = expires_at - timedelta(days=max(0, int(policy["notify_before_days"])))
        return expired, (not expired and _now_utc() >= notify_at), expires_at, bool(policy["force_change"])


def _notify_password_expiration(user_record: UserAccount, expires_at: datetime) -> None:
    """Send at most one expiration notice per account per UTC day and persist delivery state."""
    if not user_record.email:
        return
    now = _now_utc()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    session = SessionLocal()
    try:
        already_sent = session.query(EmailNotification).filter(
            EmailNotification.tenant_id == user_record.tenant_id,
            EmailNotification.recipient_email == user_record.email,
            EmailNotification.report_type == "password_expiration",
            EmailNotification.created_at >= day_start,
        ).first()
        if already_sent is not None:
            return
        delivered = False
        error = None
        if email_service.smtp_server:
            body = f"Your PesaGuard password expires on {expires_at.isoformat()}. Change it before expiration."
            delivered, error = email_service._send_email(user_record.email, "PesaGuard password expiration notice", body, body)
        else:
            error = "email delivery is not configured"
        session.add(EmailNotification(
            id=f"email_{uuid.uuid4().hex[:12]}",
            tenant_id=user_record.tenant_id,
            recipient_email=user_record.email,
            report_type="password_expiration",
            subject="PesaGuard password expiration notice",
            status="sent" if delivered else "failed",
            error_message=error,
            sent_at=now if delivered else None,
            created_at=now,
        ))
        session.commit()
    except Exception:
        session.rollback()
        logger.exception("Password expiration notification failed for user %s", user_record.id)
    finally:
        session.close()


_DEFAULT_MFA_POLICY = {
    "allowed_factors": ["totp", "webauthn"],
    "required_for_roles": ["admin", "owner", "platform-admin", "org-admin", "org-manager", "department-admin"],
    "email_otp_for_login": False,
    "require_user_verification": True,
    "totp_clock_skew_steps": 1,
    "attempt_limit": 5,
    "lockout_seconds": 300,
    "challenge_ttl_seconds": 300,
    "recovery_code_count": 10,
}


def _normalize_mfa_policy(
    candidate: Dict[str, Any],
    tenant_id: Optional[str],
    *,
    strict: bool = False,
) -> Optional[Dict[str, Any]]:
    policy = dict(candidate)
    invalid = False
    factors = policy.get("allowed_factors")
    if not isinstance(factors, list) or any(value not in {"totp", "webauthn"} for value in factors):
        logger.warning("Invalid MFA allowed_factors policy; using defaults")
        invalid = True
        factors = _DEFAULT_MFA_POLICY["allowed_factors"]
    policy["allowed_factors"] = sorted({
        value for value in factors if value in {"totp", "webauthn"}
    })
    if not policy["allowed_factors"]:
        logger.warning("MFA policy disabled all factors; restoring TOTP")
        invalid = True
        policy["allowed_factors"] = ["totp"]

    roles = policy.get("required_for_roles")
    if not isinstance(roles, list) or any(not isinstance(role, str) for role in roles):
        logger.warning("Invalid MFA required_for_roles policy; using defaults")
        invalid = True
        roles = _DEFAULT_MFA_POLICY["required_for_roles"]
    policy["required_for_roles"] = sorted({
        AuthRBAC.normalize_role_name(role)
        for role in roles
        if isinstance(role, str) and AuthRBAC.normalize_role_name(role)
    } | set(_DEFAULT_MFA_POLICY["required_for_roles"]))
    for key, default, minimum, maximum in (
        ("totp_clock_skew_steps", 1, 0, 2),
        ("attempt_limit", 5, 1, 10),
        ("lockout_seconds", 300, 60, 3600),
        ("challenge_ttl_seconds", 300, 60, 600),
        ("recovery_code_count", 10, 5, 20),
    ):
        try:
            value = policy[key]
            if isinstance(value, bool):
                raise ValueError("boolean is not an integer control")
            value = int(value)
            if strict and not minimum <= value <= maximum:
                raise ValueError("integer control is out of range")
            policy[key] = min(maximum, max(minimum, value))
        except (KeyError, TypeError, ValueError, OverflowError):
            logger.warning("Invalid MFA policy value %s; using default", key)
            invalid = True
            policy[key] = default

    for key, default in (("require_user_verification", True), ("email_otp_for_login", False)):
        if not isinstance(policy.get(key), bool):
            logger.warning("Invalid MFA policy value %s; using default", key)
            invalid = True
            policy[key] = default
    if policy["email_otp_for_login"] and policy["required_for_roles"]:
        logger.error("Email OTP cannot satisfy privileged MFA; disabling it for tenant %s", tenant_id)
        policy["email_otp_for_login"] = False
        invalid = True
    return None if strict and invalid else policy


def _mfa_policy_for_tenant(tenant_id: Optional[str]) -> Dict[str, Any]:
    """Resolve and bound environment-backed defaults and persisted tenant MFA policy."""
    policy = dict(_DEFAULT_MFA_POLICY)
    raw = os.getenv("PESAGUARD_MFA_POLICY", "")
    if raw:
        try:
            configured = json.loads(raw)
            if isinstance(configured, dict):
                policy.update(configured)
        except (TypeError, json.JSONDecodeError):
            logger.error("PESAGUARD_MFA_POLICY is invalid JSON; using defaults")

    if tenant_id:
        with SessionLocal() as session:
            stored = session.query(MFAPolicy).filter_by(tenant_id=tenant_id).first()
            if stored is not None and isinstance(stored.policy, dict):
                policy.update(stored.policy)

    normalized = _normalize_mfa_policy(policy, tenant_id)
    if normalized is None:
        return dict(_DEFAULT_MFA_POLICY)
    return normalized


def _record_mfa_event(
    session,
    tenant_id: str,
    user_id: str,
    event_type: str,
    outcome: str,
    *,
    factor_id: Optional[str] = None,
    challenge_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    session.add(MFAEvent(
        id=f"mfa_event_{uuid.uuid4().hex}",
        tenant_id=tenant_id,
        user_id=user_id,
        factor_id=factor_id,
        challenge_id=challenge_id,
        event_type=event_type,
        outcome=outcome,
        details=details or {},
        created_at=_now_utc(),
    ))


def _mfa_is_required(user_record: UserAccount) -> bool:
    """Require factors for configured roles when enterprise enforcement is on."""
    policy = _mfa_policy_for_tenant(user_record.tenant_id)
    roles = {AuthRBAC.normalize_role_name(role) for role in (user_record.roles or [])}
    enforced = os.getenv("PESAGUARD_MFA_ADMIN_ENFORCED", "1").strip().lower() in {"1", "true", "yes"}
    return enforced and bool(roles.intersection(policy["required_for_roles"]))


def _totp_code(secret: str, timestamp: Optional[int] = None) -> str:
    """Generate an RFC 6238 SHA-1 six-digit TOTP value."""
    normalized = "".join(str(secret).split()).upper()
    padded = normalized + "=" * (-len(normalized) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int((timestamp if timestamp is not None else time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1_000_000:06d}"


def _matching_totp_counter(
    secret: str,
    code: str,
    *,
    clock_skew_steps: int = 1,
    timestamp: Optional[int] = None,
) -> Optional[int]:
    normalized_code = str(code or "").strip()
    if len(normalized_code) != 6 or not normalized_code.isdigit():
        return None
    current = int((timestamp if timestamp is not None else time.time()) // 30)
    for step in range(-clock_skew_steps, clock_skew_steps + 1):
        candidate = current + step
        if candidate >= 0 and hmac.compare_digest(_totp_code(secret, candidate * 30), normalized_code):
            return candidate
    return None


def _verify_totp(secret: str, code: str) -> bool:
    return _matching_totp_counter(secret, code) is not None


def _hash_recovery_code(code: str) -> str:
    pepper = os.getenv("JWT_SECRET_KEY", "").encode("utf-8")
    return hmac.new(pepper, code.encode("utf-8"), hashlib.sha256).hexdigest()


def _new_recovery_codes(count: int = 10) -> tuple[List[str], List[str]]:
    codes = [secrets.token_hex(8).upper() for _ in range(count)]
    return codes, [_hash_recovery_code(code) for code in codes]


def _verify_mfa_code(user_record: UserAccount, code: str) -> bool:
    """Consume a replay-safe TOTP counter or a one-time persisted recovery code."""
    policy = _mfa_policy_for_tenant(user_record.tenant_id)
    if not isinstance(code, str) or not code:
        return False
    session = SessionLocal()
    try:
        now = _now_utc()
        factors = []
        if "totp" in policy["allowed_factors"]:
            factors = session.query(MFAFactor).filter_by(
                tenant_id=user_record.tenant_id,
                user_id=user_record.id,
                factor_type="totp",
            ).filter(MFAFactor.status.in_(("active", "locked"))).with_for_update().all()
        for factor in factors:
            if factor.locked_until is not None:
                locked_until = factor.locked_until
                if locked_until.tzinfo is None:
                    locked_until = locked_until.replace(tzinfo=timezone.utc)
                if locked_until > now:
                    continue
                factor.status = "active"
                factor.locked_until = None
                factor.failed_attempts = 0

            counter = None
            try:
                if factor.secret_encrypted:
                    secret = str(decrypt_value(factor.secret_encrypted))
                    counter = _matching_totp_counter(
                        secret,
                        code,
                        clock_skew_steps=policy["totp_clock_skew_steps"],
                    )
            except (TypeError, ValueError, RuntimeError):
                logger.error("Unable to decrypt TOTP factor %s for account %s", factor.id, user_record.id, exc_info=True)

            if counter is not None and (
                factor.last_used_counter is None or counter > factor.last_used_counter
            ):
                factor.last_used_counter = counter
                factor.failed_attempts = 0
                factor.locked_until = None
                factor.status = "active"
                factor.last_used_at = now
                _record_mfa_event(
                    session,
                    user_record.tenant_id,
                    user_record.id,
                    "factor.totp.verified",
                    "success",
                    factor_id=factor.id,
                )
                session.commit()
                return True

            if counter is not None:
                event_type = "factor.totp.replay_rejected"
            else:
                event_type = "factor.totp.verification_failed"
            factor.failed_attempts = int(factor.failed_attempts or 0) + 1
            if factor.failed_attempts >= policy["attempt_limit"]:
                factor.status = "locked"
                factor.locked_until = now + timedelta(seconds=policy["lockout_seconds"])
                event_type = "factor.totp.locked"
            _record_mfa_event(
                session,
                user_record.tenant_id,
                user_record.id,
                event_type,
                "denied",
                factor_id=factor.id,
                details={"attempts": factor.failed_attempts},
            )

        recovery_hash = _hash_recovery_code(code.strip())
        recovery = session.query(MFARecovery).filter_by(
            tenant_id=user_record.tenant_id,
            user_id=user_record.id,
            code_hash=recovery_hash,
            used_at=None,
        ).with_for_update().first()
        if recovery is not None:
            recovery.used_at = now
            _record_mfa_event(
                session,
                user_record.tenant_id,
                user_record.id,
                "recovery_code.consumed",
                "success",
                details={"recovery_code_id": recovery.id},
            )
            session.commit()
            return True

        _record_mfa_event(
            session,
            user_record.tenant_id,
            user_record.id,
            "verification.failed",
            "denied",
        )
        session.commit()
        return False
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _revoke_user_sessions(user_id: str, tenant_id: str, reason: str) -> None:
    session_ids: List[str] = []
    session = SessionLocal()
    try:
        session_ids = [row.id for row in session.query(UserSession.id).filter(
            UserSession.user_id == user_id,
            UserSession.tenant_id == tenant_id,
            UserSession.active.is_(True),
        ).all()]
        if session_ids:
            session.query(UserSession).filter(UserSession.id.in_(session_ids)).update(
                {UserSession.active: False, UserSession.revoked_at: _now_utc()},
                synchronize_session=False,
            )
            session.commit()
    finally:
        session.close()
    for session_id in session_ids:
        AuthRBAC.revoke_session_tokens(session_id, reason=reason)


def _issue_refresh_and_access_tokens(user_record: UserAccount, device_id: Optional[str] = None, user_agent: Optional[str] = None, ip_address: Optional[str] = None):
    session_id = f"sess_{uuid.uuid4().hex[:12]}"
    roles = list(user_record.roles or []) or ["operator"]
    access_token = AuthRBAC.generate_token(
        user_id=user_record.id,
        username=user_record.username,
        tenant_id=user_record.tenant_id,
        roles=roles,
        session_id=session_id,
    )
    refresh_token = AuthRBAC.generate_refresh_token(
        user_id=user_record.id,
        username=user_record.username,
        tenant_id=user_record.tenant_id,
        roles=roles,
        session_id=session_id,
        device_id=device_id,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    return access_token, refresh_token, session_id


def _create_session_record(
    user_record: UserAccount,
    session_id: str,
    device_id: Optional[str],
    user_agent: Optional[str],
    ip_address: Optional[str],
    *,
    organization_id: Optional[str] = None,
    authentication_method: str = "password",
    mfa_verified: bool = False,
    location_info: Optional[Dict[str, Any]] = None,
    risk_result: Optional[Dict[str, Any]] = None,
) -> None:
    now = _now_utc()
    absolute_expires_at = now + timedelta(days=max(1, int(os.getenv("PESAGUARD_SESSION_ABSOLUTE_TIMEOUT_DAYS", "30"))))
    session = SessionLocal()
    try:
        if device_id:
            device = _upsert_device_identity(
                session,
                user_record,
                device_id,
                user_agent,
                ip_address,
                now,
                risk_result or {},
            )
            if device.revoked_at is not None:
                raise ValueError("revoked device cannot create a new session")
        session.add(UserSession(
            id=session_id,
            tenant_id=user_record.tenant_id,
            user_id=user_record.id,
            organization_id=organization_id,
            device_id=device_id,
            user_agent=user_agent,
            ip_address=ip_address,
            location_info=location_info or {},
            state="ACTIVE",
            active=True,
            issued_at=now,
            last_activity_at=now,
            expires_at=absolute_expires_at,
            absolute_expires_at=absolute_expires_at,
            authentication_method=authentication_method,
            mfa_verified=mfa_verified,
            session_metadata={
                "source": "local-password",
                "device_id": device_id,
                "risk": {
                    "score": (risk_result or {}).get("risk_score", 0),
                    "level": (risk_result or {}).get("risk_level", "low"),
                    "signals": (risk_result or {}).get("signals", {}),
                },
            },
        ))
        session.commit()
    finally:
        session.close()


def _upsert_device_identity(
    session,
    user_record: UserAccount,
    device_id: str,
    user_agent: Optional[str],
    ip_address: Optional[str],
    now: datetime,
    risk_result: Dict[str, Any],
) -> DeviceIdentity:
    """Create or update the user-owned device row under a row lock."""
    browser, operating_system = _browser_and_os(user_agent)
    risk_metadata = {
        "last_risk_score": (risk_result or {}).get("risk_score", 0),
        "last_risk_level": (risk_result or {}).get("risk_level", "low"),
        "last_risk_signals": (risk_result or {}).get("signals", {}),
    }
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        statement = postgresql_insert(DeviceIdentity).values(
            id=f"dev_{hashlib.sha256(f'{user_record.tenant_id}:{user_record.id}:{device_id}'.encode('utf-8')).hexdigest()[:32]}",
            tenant_id=user_record.tenant_id,
            user_id=user_record.id,
            device_id=device_id,
            device_name=f"{browser} on {operating_system}",
            browser=browser,
            operating_system=operating_system,
            user_agent=str(user_agent or "")[:2048] or None,
            first_seen_at=now,
            last_seen_at=now,
            last_ip_address=ip_address,
            session_count=1,
            trusted=False,
            revoked_at=None,
            risk_metadata=risk_metadata,
        ).on_conflict_do_update(
            index_elements=["tenant_id", "user_id", "device_id"],
            set_={
                "browser": browser,
                "operating_system": operating_system,
                "user_agent": str(user_agent or "")[:2048] or DeviceIdentity.user_agent,
                "last_seen_at": now,
                "last_ip_address": ip_address,
                "session_count": DeviceIdentity.session_count + 1,
                "risk_metadata": risk_metadata,
            },
            where=DeviceIdentity.revoked_at.is_(None),
        ).returning(DeviceIdentity)
        device = session.execute(statement).scalar_one_or_none()
        if device is None:
            raise ValueError("revoked device cannot create a new session")
        return device

    device = session.query(DeviceIdentity).filter_by(
        tenant_id=user_record.tenant_id,
        user_id=user_record.id,
        device_id=device_id,
    ).with_for_update().one_or_none()
    if device is None:
        device = DeviceIdentity(
            id=f"dev_{hashlib.sha256(f'{user_record.tenant_id}:{user_record.id}:{device_id}'.encode('utf-8')).hexdigest()[:32]}",
            tenant_id=user_record.tenant_id,
            user_id=user_record.id,
            device_id=device_id,
            device_name=f"{browser} on {operating_system}",
            browser=browser,
            operating_system=operating_system,
            user_agent=str(user_agent or "")[:2048] or None,
            first_seen_at=now,
            last_seen_at=now,
            last_ip_address=ip_address,
            session_count=0,
            trusted=False,
            risk_metadata={},
        )
        session.add(device)
        session.flush()
    elif device.revoked_at is not None:
        raise ValueError("revoked device cannot create a new session")
    else:
        device.browser = browser
        device.operating_system = operating_system
        device.user_agent = str(user_agent or "")[:2048] or device.user_agent
        device.last_seen_at = now
        device.last_ip_address = ip_address

    device.session_count = int(device.session_count or 0) + 1
    device.last_seen_at = now
    device.last_ip_address = ip_address
    device.risk_metadata = risk_metadata
    return device


def _record_auth_risk_metrics(result: Dict[str, Any]) -> None:
    try:
        from metrics import record_auth_risk_decision
        record_auth_risk_decision(
            str(result.get("risk_level", "unknown")),
            str(result.get("action", "unknown")),
            result.get("signals", {}),
        )
    except Exception:
        logger.warning("Unable to record authentication risk decision metrics", exc_info=True)


def _assess_login_risk(
    user_record: UserAccount,
    device_id: str,
    ip_address: Optional[str],
    user_agent: Optional[str],
    location: Dict[str, Any],
) -> tuple[Dict[str, Any], bool]:
    """Assess persisted identity, location, time, failure, and compromise signals."""
    now = _now_utc()
    policy = _auth_risk_policy_for_tenant(user_record.tenant_id)
    attrs = dict(user_record.attributes or {})
    with SessionLocal() as session:
        device = session.query(DeviceIdentity).filter_by(
            tenant_id=user_record.tenant_id,
            user_id=user_record.id,
            device_id=device_id,
        ).first()
        if device is not None and device.revoked_at is not None:
            result = {"risk_level": "high", "action": "block", "risk_score": 1.0, "signals": {"revoked_device": True}}
            _record_auth_risk_metrics(result)
            return result, True

        recent_sessions = session.query(UserSession).filter(
            UserSession.tenant_id == user_record.tenant_id,
            UserSession.user_id == user_record.id,
        ).order_by(UserSession.last_activity_at.desc()).limit(100).all()

    known_countries = {
        str((row.location_info or {}).get("country", "")).upper()
        for row in recent_sessions
        if isinstance(row.location_info, dict) and row.location_info.get("country")
    }
    current_country = str(location.get("country") or "").upper()
    signals: Dict[str, bool] = {
        "new_device": device is None,
        "new_location": bool(current_country and known_countries and current_country not in known_countries),
        "multiple_failed_attempts": int(attrs.get("failed_login_count", 0) or 0) >= _login_protection_int(
            "PESAGUARD_RISK_FAILED_ATTEMPT_THRESHOLD",
            3,
            maximum=1000,
        ),
        "credential_compromise": bool(attrs.get("credential_compromised") or attrs.get("credential_compromise_indicators")),
        "high_risk_session": bool(device and (device.risk_metadata or {}).get("last_risk_level") == "high"),
        "privileged_operation": False,
    }

    suspicious_ip_values = set(str(value).strip() for value in policy.get("compromised_ip_addresses", []) if value)
    suspicious_ip = (ip_address or "") in suspicious_ip_values
    try:
        client_ip = ipaddress.ip_address(ip_address) if ip_address else None
    except ValueError:
        client_ip = None
    if client_ip:
        for cidr in policy.get("suspicious_ip_cidrs", []):
            try:
                if client_ip in ipaddress.ip_network(str(cidr), strict=False):
                    suspicious_ip = True
                    break
            except ValueError:
                logger.warning("Ignoring invalid suspicious IP network in risk policy")
    signals["suspicious_ip"] = suspicious_ip

    if location.get("latitude") is not None and location.get("longitude") is not None:
        for prior in recent_sessions:
            prior_location = prior.location_info if isinstance(prior.location_info, dict) else {}
            distance = _distance_km(prior_location, location)
            if distance is None:
                continue
            prior_time = prior.last_activity_at or prior.issued_at
            if prior_time and prior_time.tzinfo is None:
                prior_time = prior_time.replace(tzinfo=timezone.utc)
            elapsed_hours = max(0.01, (now - prior_time).total_seconds() / 3600) if prior_time else 0
            if elapsed_hours <= 24 and distance / elapsed_hours >= float(policy.get("impossible_travel_minimum_speed_kmh", 900)):
                signals["impossible_travel"] = True
                break

    samples = []
    for row in recent_sessions:
        timestamp = row.last_activity_at or row.issued_at
        if timestamp and timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        if timestamp and (now - timestamp).days <= 30:
            samples.append(timestamp.hour + timestamp.minute / 60)
    min_samples = max(1, int(policy.get("unusual_login_minimum_samples", 5)))
    if len(samples) >= min_samples:
        baseline_hour = sorted(samples)[len(samples) // 2]
        hour_distance = abs(now.hour + now.minute / 60 - baseline_hour)
        hour_distance = min(hour_distance, 24 - hour_distance)
        signals["unusual_login_time"] = hour_distance >= float(policy.get("unusual_login_hour_deviation", 6))

    result = _evaluate_session_risk(
        tenant_id=user_record.tenant_id,
        user_id=user_record.id,
        ip_address=ip_address,
        user_agent=user_agent,
        device_id=device_id,
        country=current_country or None,
        known_country=next(iter(known_countries), None),
        signals_override=signals,
        tenant_policy=policy,
    )
    _record_auth_risk_metrics(result)
    return result, False


def _validate_password(password: str) -> bool:
    return _password_policy_error(password) is None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _get_user_account_by_email(email: str, tenant_id: Optional[str] = None) -> Optional[UserAccount]:
    normalized = (email or "").strip().lower()
    if not normalized:
        return None
    session = SessionLocal()
    try:
        query = session.query(UserAccount).filter(UserAccount.email == normalized)
        if tenant_id:
            query = query.filter(UserAccount.tenant_id == tenant_id)
        return query.order_by(UserAccount.created_at.desc()).first()
    finally:
        session.close()


def _get_user_account_by_username(username: str, tenant_id: Optional[str] = None) -> Optional[UserAccount]:
    normalized = (username or "").strip()
    if not normalized:
        return None
    session = SessionLocal()
    try:
        query = session.query(UserAccount).filter(UserAccount.username == normalized)
        if tenant_id:
            query = query.filter(UserAccount.tenant_id == tenant_id)
        return query.order_by(UserAccount.created_at.desc()).first()
    finally:
        session.close()


def _upsert_user_account_for_registration(username: str, email: str, tenant_id: str) -> Optional[UserAccount]:
    session = SessionLocal()
    try:
        existing = session.query(UserAccount).filter(
            UserAccount.tenant_id == tenant_id,
            (UserAccount.email == email.lower() if email else False) | (UserAccount.username == username),
        ).first()
        if existing is not None:
            return existing
        return None
    finally:
        session.close()


def _password_expires_at() -> datetime:
    days = int(os.getenv("PESAGUARD_PASSWORD_EXPIRY_DAYS", "90"))
    return _now_utc() + timedelta(days=max(1, days))


def _password_reset_token_payload(user_record: UserAccount) -> Optional[Dict[str, Any]]:
    attrs = dict(user_record.attributes or {})
    payload = attrs.get("password_reset")
    if not isinstance(payload, dict):
        return None
    return payload


def _email_verification_payload(user_record: UserAccount) -> Optional[Dict[str, Any]]:
    attrs = dict(user_record.attributes or {})
    payload = attrs.get("email_verification")
    if not isinstance(payload, dict):
        return None
    return payload


def _login_requires_verified_email(user_record: UserAccount) -> bool:
    attrs = dict(user_record.attributes or {})
    if attrs.get("email_verified") is not None:
        return bool(attrs.get("email_verified")) is False
    return user_record.status == "pending_verification"


def _approve_user_password_reset(user_record: UserAccount, token: str) -> bool:
    payload = _password_reset_token_payload(user_record)
    if not payload:
        return False
    if payload.get("token") != token:
        return False
    expires_at = payload.get("expires_at")
    if isinstance(expires_at, str):
        try:
            expires_at_dt = datetime.fromisoformat(expires_at)
            if expires_at_dt.tzinfo is None:
                expires_at_dt = expires_at_dt.replace(tzinfo=timezone.utc)
            if expires_at_dt <= _now_utc():
                return False
        except ValueError:
            return False
    return True


def _authentication_audit(
    tenant_id: str,
    action: str,
    outcome: str,
    *,
    user_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    identifier: Optional[str] = None,
    reason: Optional[str] = None,
) -> None:
    """Persist authentication telemetry without storing credentials or raw identifiers."""
    session = SessionLocal()
    try:
        details = {
            "identifier_hash": _password_reset_token_hash(identifier or ""),
            "reason": reason or "unspecified",
            "source_ip_hash": _password_reset_token_hash(request.remote_addr or ""),
        }
        session.add(ActionAuditEntry(
            tenant_id=str(tenant_id or "default"),
            actor=actor_id or user_id or "anonymous",
            actor_type="user" if actor_id or user_id else "anonymous",
            action=action,
            category="authentication",
            outcome=outcome,
            resource_type="user_identity" if user_id else "authentication",
            resource_id=user_id,
            actor_authentication_method="password" if action.startswith("login") else None,
            details=details,
            idempotency_key=f"{action}:{uuid.uuid4().hex}",
        ))
        session.commit()
    except Exception:
        session.rollback()
        logger.exception("Authentication audit persistence failed for action=%s", action)
    finally:
        session.close()
    if action in {
        "login.failed",
        "login.account_locked",
        "login.brute_force_detected",
        "login.credential_stuffing_detected",
        "login.suspicious",
        "login.account_unlocked",
        "password.reset.account_recovered",
        "login.risk_blocked",
        "login.risk_step_up_required",
    }:
        from metrics import record_security_event
        record_security_event()


def _load_auth_users() -> Dict[str, Dict[str, Any]]:
    """Load authorized user database from secure environment variables.

    In test and local-development execution, a small default user set is provided
    so authentication contracts remain stable without external configuration.
    """
    raw = os.getenv("PESAGUARD_AUTH_USERS_JSON", "")
    if raw:
        try:
            users = json.loads(raw)
            return {u["username"]: u for u in users if "username" in u}
        except (json.JSONDecodeError, TypeError, KeyError):
            logger.exception("PESAGUARD_AUTH_USERS_JSON payload is malformed.")
            return {}

    if runtime_environment() in {"test", "development"}:
        password = "password"
        salt_hex = hashlib.sha256(b"testuser-salt").hexdigest()
        password_hash_hex = _hash_password(password, salt_hex)
        return {
            "testuser": {
                "username": "testuser",
                "tenant_id": "test-tenant",
                "roles": ["admin"],
                "salt_hex": salt_hex,
                "password_hash_hex": password_hash_hex,
            }
        }

    logger.error("PESAGUARD_AUTH_USERS_JSON environment variable is not configured.")
    return {}


def _verify_credentials(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Verify user credentials in constant time to prevent timing attacks."""
    users = _load_auth_users()
    user = users.get(username)
    if not user:
        return None
    try:
        computed = _hash_password(password, user["salt_hex"])
    except (KeyError, ValueError):
        logger.exception("Malformed auth record for username=%s", username)
        return None

    if not hmac.compare_digest(computed, user.get("password_hash_hex", "")):
        return None
    return user


@_idempotent_route("/auth/login", methods=["POST"])
@rate_limit(max_requests_per_minute=30, tokens_per_request=1, endpoint_name="auth_login", fail_closed=True)
def login():
    """Authenticate operational users and issue secure signed session tokens."""
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    tenant_id = str(data.get("tenant_id") or "default").strip() or "default"
    supplied_device_id = data.get("device_id")
    device_id = str(supplied_device_id or uuid.uuid4().hex).strip()
    if len(device_id) > 255 or not re.fullmatch(r"[A-Za-z0-9._:-]+", device_id):
        return jsonify({"error": "invalid_request", "message": "device_id has an invalid format."}), 400
    device_throttle_id = str(supplied_device_id or "").strip()
    if not device_throttle_id:
        device_throttle_id = hashlib.sha256(
            f"{request.headers.get('User-Agent', '')}\0{request.remote_addr or ''}".encode("utf-8")
        ).hexdigest()
    location_info = _trusted_location_from_request()

    if _is_production_environment() and not ENABLE_REDIS_RATE_LIMITING:
        _authentication_audit(tenant_id, "login.failed", "unavailable", identifier=str(username or ""), reason="distributed_rate_limiter_not_configured")
        return jsonify({
            "error": "rate_limiter_unavailable",
            "message": "Authentication is temporarily unavailable.",
            "retry_after": 1,
        }), 503

    if not username or not password:
        _authentication_audit(tenant_id, "login.failed", "failure", identifier=str(username or ""), reason="missing_credentials")
        return jsonify({"error": "invalid_credentials", "message": "Invalid email or password."}), 401

    user_record = _resolve_local_user(str(username), tenant_id)

    if user_record is not None:
        if user_record.status in {"suspended", "deactivated", "deleted"}:
            _authentication_audit(tenant_id, "login.failed", "denied", user_id=user_record.id, identifier=str(username), reason="account_unavailable")
            return jsonify({"error": "invalid_credentials", "message": "Invalid email or password."}), 401
        if user_record.status == "pending_verification":
            _authentication_audit(tenant_id, "login.failed", "denied", user_id=user_record.id, identifier=str(username), reason="email_not_verified")
            return jsonify({"error": "invalid_credentials", "message": "Invalid email or password."}), 401

        lock_deadline = _check_account_lockout(user_record)
        if lock_deadline is not None:
            _authentication_audit(tenant_id, "login.failed", "denied", user_id=user_record.id, identifier=str(username), reason="account_locked")
            response = jsonify({"error": "account_locked", "message": "Invalid username or password.", "locked_until": lock_deadline.isoformat()})
            response.headers["Retry-After"] = str(max(1, math.ceil((lock_deadline - _now_utc()).total_seconds())))
            return response, 423

        progressive_retry = _account_login_retry_after(user_record)
        if progressive_retry:
            _authentication_audit(
                tenant_id,
                "login.failed",
                "denied",
                user_id=user_record.id,
                identifier=str(username),
                reason="progressive_backoff",
            )
            response = jsonify({
                "error": "rate_limit_exceeded",
                "message": "Too many failed attempts. Please retry after the stated delay.",
                "retry_after": progressive_retry,
                "throttle_reason": "account",
            })
            response.headers["Retry-After"] = str(progressive_retry)
            return response, 429

        password_expired, password_needs_notice, password_expires_at, force_password_change = _password_expiration_state(user_record)
        if password_needs_notice and password_expires_at is not None:
            _notify_password_expiration(user_record, password_expires_at)
        if password_expired and force_password_change:
            _authentication_audit(tenant_id, "login.failed", "denied", user_id=user_record.id, identifier=str(username), reason="password_expired")
            return jsonify({"error": "password_expired", "message": "Password expiration requires a password reset before login."}), 403

        valid, legacy_password = _password_matches(user_record, password)

        if not valid:
            failure_state = _record_login_failure(
                user_record,
                tenant_id=tenant_id,
                identifier=str(username),
                ip_address=request.remote_addr,
                device_id=device_throttle_id,
            )
            if failure_state.get("limiter_unavailable"):
                _authentication_audit(tenant_id, "login.failed", "unavailable", user_id=user_record.id, identifier=str(username), reason="rate_limiter_unavailable")
                return jsonify({"error": "rate_limiter_unavailable", "message": "Authentication is temporarily unavailable.", "retry_after": failure_state.get("retry_after", 1)}), 503
            if failure_state.get("credential_stuffing_detected"):
                _authentication_audit(
                    tenant_id,
                    "login.credential_stuffing_detected",
                    "denied",
                    user_id=user_record.id,
                    identifier=str(username),
                    reason="multiple_identifiers_from_shared_source",
                )
            if failure_state.get("brute_force_detected"):
                _authentication_audit(
                    tenant_id,
                    "login.brute_force_detected",
                    "denied",
                    user_id=user_record.id,
                    identifier=str(username),
                    reason=failure_state.get("throttle_reason") or "account_lockout_threshold",
                )
            if failure_state.get("account_locked"):
                _authentication_audit(
                    tenant_id,
                    "login.account_locked",
                    "denied",
                    user_id=user_record.id,
                    identifier=str(username),
                    reason="progressive_lockout_threshold",
                )
                response = jsonify({
                    "error": "account_locked",
                    "message": "Too many failed login attempts. Account locked temporarily.",
                    "retry_after": failure_state.get("retry_after", 0),
                    "locked_until": user_record.attributes.get("locked_until"),
                })
                response.headers["Retry-After"] = str(max(1, int(failure_state.get("retry_after", 1) or 1)))
                return response, 423
            if failure_state.get("rate_limited"):
                _authentication_audit(tenant_id, "login.failed", "denied", user_id=user_record.id, identifier=str(username), reason=f"rate_limited:{failure_state.get('throttle_reason')}")
                response = jsonify({
                    "error": "rate_limit_exceeded",
                    "message": "Too many login attempts from this account, device, or IP. Please retry later.",
                    "retry_after": failure_state.get("retry_after", 0),
                    "throttle_reason": failure_state.get("throttle_reason"),
                })
                response.headers["Retry-After"] = str(max(1, int(failure_state.get("retry_after", 1) or 1)))
                return response, 429
            _authentication_audit(tenant_id, "login.failed", "failure", user_id=user_record.id, identifier=str(username), reason="invalid_password")
            response = jsonify({"error": "invalid_credentials", "message": "Invalid username or password."})
            response.headers["Retry-After"] = str(max(1, int(failure_state.get("progressive_delay_seconds", 1) or 1)))
            return response, 401

        risk_result, revoked_device = _assess_login_risk(
            user_record,
            device_id,
            request.remote_addr,
            request.headers.get("User-Agent"),
            location_info,
        )
        if revoked_device or risk_result.get("action") in {"block", "review"}:
            _authentication_audit(
                tenant_id,
                "login.risk_blocked",
                "denied",
                user_id=user_record.id,
                identifier=str(username),
                reason="revoked_device" if revoked_device else f"risk_{risk_result.get('risk_level')}",
            )
            return jsonify({
                "error": "device_revoked" if revoked_device else "login_blocked_for_review",
                "message": "This sign-in cannot be completed. Contact your administrator or use account recovery.",
                "risk_level": "high",
            }), 403

        risk_requires_mfa = risk_result.get("action") == "require_mfa"
        if risk_requires_mfa and not user_record.mfa_enabled:
            _authentication_audit(tenant_id, "login.risk_step_up_required", "denied", user_id=user_record.id, identifier=str(username), reason="mfa_enrollment_required")
            return jsonify({
                "error": "risk_mfa_enrollment_required",
                "message": "This sign-in requires multi-factor authentication enrollment.",
                "risk_level": risk_result["risk_level"],
                "risk_score": risk_result["risk_score"],
                "signals": risk_result["signals"],
            }), 403

        if _mfa_is_required(user_record) and not user_record.mfa_enabled:
            _authentication_audit(tenant_id, "login.failed", "denied", user_id=user_record.id, identifier=str(username), reason="mfa_enrollment_required")
            return jsonify({"error": "mfa_enrollment_required", "message": "Administrator MFA enrollment is required before login."}), 403
        mfa_verified = False
        if user_record.mfa_enabled or risk_requires_mfa:
            mfa_code = data.get("mfa_code") or data.get("totp_code") or data.get("recovery_code")
            if not mfa_code:
                mfa_policy = _mfa_policy_for_tenant(user_record.tenant_id)
                if "webauthn" in mfa_policy["allowed_factors"]:
                    session = SessionLocal()
                    try:
                        webauthn_factors = session.query(MFAFactor).filter_by(
                            tenant_id=user_record.tenant_id,
                            user_id=user_record.id,
                            factor_type="webauthn",
                            status="active",
                        ).all()
                        if webauthn_factors:
                            try:
                                challenge, options = _start_webauthn_assertion(
                                    session,
                                    tenant_id=user_record.tenant_id,
                                    user_id=user_record.id,
                                    factors=webauthn_factors,
                                    challenge_type="webauthn_login",
                                    challenge_data={
                                        "device_id": device_id,
                                        "risk": risk_result,
                                        "authorization_version": int(user_record.authorization_version or 0),
                                    },
                                    policy=mfa_policy,
                                )
                            except (ValueError, RuntimeError) as exc:
                                logger.warning("WebAuthn login configuration rejected: %s", exc)
                                return jsonify({
                                    "error": "webauthn_unavailable",
                                    "message": "WebAuthn authentication is not configured for this origin.",
                                }), 503
                            session.commit()
                            return jsonify({
                                "status": "mfa_challenge_required",
                                "challenge_id": challenge.id,
                                "challenge_type": "webauthn",
                                "options": options,
                                "expires_in": mfa_policy["challenge_ttl_seconds"],
                            }), 202
                    finally:
                        session.close()
                _authentication_audit(tenant_id, "login.failed", "denied", user_id=user_record.id, identifier=str(username), reason="mfa_required")
                return jsonify({
                    "error": "mfa_required",
                    "message": "An enrolled TOTP/recovery code or WebAuthn factor is required.",
                    "risk_level": risk_result["risk_level"],
                    "risk_score": risk_result["risk_score"],
                }), 401
            if not _verify_mfa_code(user_record, str(mfa_code)):
                _authentication_audit(tenant_id, "login.failed", "failure", user_id=user_record.id, identifier=str(username), reason="invalid_mfa")
                return jsonify({"error": "invalid_mfa", "message": "The MFA code is invalid."}), 401
            mfa_verified = True

        attrs = dict(user_record.attributes or {})
        _clear_login_failures(user_record)
        attrs = dict(user_record.attributes or {})
        user_record.status = "active"
        with SessionLocal() as session:
            db_user = session.get(UserAccount, user_record.id)
            if db_user is not None:
                if legacy_password:
                    _rotate_password_credential(session, db_user, password, "legacy hash upgrade")
                db_user.attributes = user_record.attributes
                db_user.status = user_record.status
                identity = _upsert_user_identity(session, db_user, email_verified=bool(user_record.attributes.get("email_verified", False)))
                identity.last_login_at = _now_utc()
                identity.last_activity_at = identity.last_login_at
                session.commit()

        access_token, refresh_token, session_id = _issue_refresh_and_access_tokens(
            user_record,
            device_id=device_id,
            user_agent=request.headers.get("User-Agent"),
            ip_address=request.remote_addr,
        )
        _create_session_record(
            user_record,
            session_id,
            device_id,
            request.headers.get("User-Agent"),
            request.remote_addr,
            authentication_method="password+mfa" if mfa_verified else "password",
            mfa_verified=mfa_verified,
            location_info=location_info,
            risk_result=risk_result,
        )
        _authentication_audit(tenant_id, "login.succeeded", "success", user_id=user_record.id, identifier=str(username), reason="password_verified")
        principal = _build_local_jwt_user(user_record)
        return jsonify({
            "token": access_token,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "session_id": session_id,
            "user": {
                "id": principal.user_id,
                "username": principal.username,
                "tenant_id": principal.tenant_id,
                "roles": principal.roles,
                "permissions": principal.permissions,
            },
            "user_id": principal.user_id,
            "username": principal.username,
            "tenant_id": principal.tenant_id,
            "roles": principal.roles,
            "permissions": principal.permissions,
            "expires_in": AuthRBAC.ACCESS_TOKEN_TTL_MINUTES * 60,
            "device_id": device_id,
            "risk": {
                "score": risk_result["risk_score"],
                "level": risk_result["risk_level"],
                "signals": risk_result["signals"],
            },
        }), 200

    user = _verify_credentials(username, password)
    if not user:
        if user_record is None:
            unknown_user = UserAccount(
                id="unknown-user",
                username=str(username),
                tenant_id=tenant_id,
                attributes={},
                roles=[],
                permissions=[],
                status="active",
                email="",
            )
            failure_state = _record_login_failure(
                unknown_user,
                tenant_id=tenant_id,
                ip_address=request.remote_addr,
                device_id=device_throttle_id,
                identifier=str(username),
                persist_account=False,
            )
            if failure_state.get("limiter_unavailable"):
                _authentication_audit(tenant_id, "login.failed", "unavailable", identifier=str(username), reason="rate_limiter_unavailable")
                return jsonify({"error": "rate_limiter_unavailable", "message": "Authentication is temporarily unavailable.", "retry_after": failure_state.get("retry_after", 1)}), 503
            if failure_state.get("credential_stuffing_detected"):
                _authentication_audit(
                    tenant_id,
                    "login.credential_stuffing_detected",
                    "denied",
                    identifier=str(username),
                    reason="multiple_identifiers_from_shared_source",
                )
            if failure_state.get("brute_force_detected"):
                _authentication_audit(
                    tenant_id,
                    "login.brute_force_detected",
                    "denied",
                    identifier=str(username),
                    reason=failure_state.get("throttle_reason") or "account_rate_limit",
                )
            if failure_state.get("rate_limited"):
                _authentication_audit(
                    tenant_id,
                    "login.failed",
                    "denied",
                    identifier=str(username),
                    reason=f"rate_limited:{failure_state.get('throttle_reason')}",
                )
                return jsonify({
                    "error": "rate_limit_exceeded",
                    "message": "Too many login attempts for this IP or device.",
                    "retry_after": failure_state.get("retry_after", 0),
                    "throttle_reason": failure_state.get("throttle_reason"),
                }), 429
        _authentication_audit(tenant_id, "login.failed", "failure", identifier=str(username), reason="invalid_credentials")
        return jsonify({"error": "invalid_credentials", "message": "Invalid username or password."}), 401

    user_id = f"user_{username}"
    roles = user.get("roles", ["operator"])
    session_id = f"sess_{uuid.uuid4().hex[:12]}"
    token = AuthRBAC.generate_token(
        user_id=user_id,
        username=username,
        tenant_id=user["tenant_id"],
        roles=roles,
        session_id=session_id,
    )
    refresh_token = AuthRBAC.generate_refresh_token(
        user_id=user_id,
        username=username,
        tenant_id=user["tenant_id"],
        roles=roles,
        session_id=session_id,
        device_id=device_id,
        user_agent=request.headers.get("User-Agent"),
        ip_address=request.remote_addr,
    )

    logger.info("Successful login for username=%s tenant_id=%s", username, user["tenant_id"])
    _authentication_audit(user["tenant_id"], "login.succeeded", "success", user_id=f"user_{username}", identifier=str(username), reason="password_verified")
    return jsonify({
        "token": token,
        "access_token": token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "session_id": session_id,
        "user_id": f"user_{username}",
        "username": username,
        "tenant_id": user["tenant_id"],
        "roles": user.get("roles", ["operator"]),
        "permissions": AuthRBAC._get_permissions_for_roles(user.get("roles", ["operator"])),
        "expires_in": AuthRBAC.ACCESS_TOKEN_TTL_MINUTES * 60,
    }), 200


@_idempotent_route("/auth/refresh", methods=["POST"])
@rate_limit(max_requests_per_minute=30, tokens_per_request=1, endpoint_name="auth_refresh", fail_closed=True)
def refresh_auth_tokens():
    """Rotate a single-use refresh token and return its replacement token pair."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _api_error("invalid_request", "A JSON object is required.", 400)
    token = payload.get("refresh_token")
    if not isinstance(token, str) or not token.strip():
        return _api_error("invalid_request", "refresh_token is required.", 400)

    rotated = AuthRBAC.rotate_refresh_token(
        token.strip(),
        device_id=payload.get("device_id"),
        user_agent=request.headers.get("User-Agent"),
        ip_address=request.remote_addr,
    )
    if rotated is None:
        return _api_error("invalid_grant", "Refresh token is invalid, expired, revoked, or already used.", 401)

    user, replacement_refresh_token = rotated
    access_token = AuthRBAC.generate_token(
        user_id=user.user_id,
        username=user.username,
        tenant_id=user.tenant_id,
        roles=user.roles,
    )
    return jsonify({
        "access_token": access_token,
        "refresh_token": replacement_refresh_token,
        "token_type": "Bearer",
        "expires_in": AuthRBAC.ACCESS_TOKEN_TTL_MINUTES * 60,
    }), 200


@_idempotent_route("/auth/register", methods=["POST"])
@rate_limit(max_requests_per_minute=30, tokens_per_request=1, endpoint_name="auth_register")
def register_user():
    """Create a new local user account with password and email verification rules."""
    data = request.json or {}
    result = _register_local_user(data)
    if result.get("status") in {"accepted", "verification_resent"}:
        return jsonify({"status": "accepted"}), 202
    if "error" in result:
        return jsonify(result), 400
    return jsonify({"status": "success", **result}), 201


@_idempotent_route("/auth/verify-email", methods=["POST"])
@rate_limit(max_requests_per_minute=30, tokens_per_request=1, endpoint_name="auth_verify_email")
def verify_email():
    """Verify a local-user email using the issued token."""
    data = request.json or {}
    email = _normalize_registration_email(data.get("email"))
    tenant_id = str(data.get("tenant_id") or "default").strip() or "default"
    token = str(data.get("token") or "").strip()

    if not email or not token:
        return jsonify({"error": "invalid_request", "message": "email and verification token are required."}), 400

    user_record = _get_user_account_by_email(email, tenant_id)
    if user_record is None:
        return jsonify({"error": "invalid_verification_token", "message": "The verification token is invalid or expired."}), 400

    if not _verify_local_email(user_record, token):
        return jsonify({"error": "invalid_verification_token", "message": "The verification token is invalid or expired."}), 400

    session = SessionLocal()
    verified_account = None
    try:
        stored = session.get(UserAccount, user_record.id)
        if stored is not None:
            stored.attributes = user_record.attributes
            stored.status = user_record.status
            _upsert_user_identity(
                session,
                stored,
                email_verified=True,
                email_verified_at=_now_utc(),
            )
            session.commit()
            verified_account = stored
    finally:
        session.close()

    if verified_account is None:
        return _api_error("user_not_found", "User account could not be activated.", 404)
    access_token, refresh_token, session_id = _issue_refresh_and_access_tokens(
        verified_account,
        device_id=data.get("device_id"),
        user_agent=request.headers.get("User-Agent"),
        ip_address=request.remote_addr,
    )
    _create_session_record(
        verified_account,
        session_id,
        data.get("device_id"),
        request.headers.get("User-Agent"),
        request.remote_addr,
        authentication_method="email_verification",
    )
    return jsonify({
        "status": "verified",
        "user_id": user_record.id,
        "email": email,
        "tenant_id": tenant_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_id": session_id,
    }), 200


@_idempotent_route("/auth/verify-email/resend", methods=["POST"])
@rate_limit(max_requests_per_minute=3, tokens_per_request=1, endpoint_name="auth_verify_email_resend")
def resend_verification_email():
    """Resend verification without revealing whether an account exists."""
    data = request.json or {}
    email = _normalize_registration_email(data.get("email"))
    tenant_id = str(data.get("tenant_id") or "default").strip() or "default"
    response = {"status": "accepted"}
    if not email:
        return jsonify(response), 202

    session = SessionLocal()
    try:
        account = session.query(UserAccount).filter_by(email=email, tenant_id=tenant_id).first()
        if account is None or account.status not in {"pending_verification", "locked"}:
            session.commit()
            return jsonify(response), 202
        token = _create_email_verification_state(session, account)
        account.status = "pending_verification"
        _upsert_user_identity(session, account, email_verified=False)
        _registration_audit(session, account, "registration.verification_resent")
        session.commit()
        _deliver_verification_email(account.tenant_id, account.id, account.email, token)
        if not _is_production_environment():
            response["verification_token"] = token
        return jsonify(response), 202
    finally:
        session.close()


@_idempotent_route("/auth/password-reset/request", methods=["POST"])
@rate_limit(max_requests_per_minute=5, tokens_per_request=1, endpoint_name="auth_password_reset_request")
def password_reset_request():
    """Issue a password-reset token for a known local user email."""
    data = request.json or {}
    email = _normalize_registration_email(data.get("email"))
    tenant_id = str(data.get("tenant_id") or "default").strip() or "default"
    if not email:
        return jsonify({"error": "invalid_request", "message": "email is required."}), 400

    user_record = _get_user_account_by_email(email, tenant_id)
    if user_record is None:
        _authentication_audit(tenant_id, "password.reset.requested", "success", identifier=email, reason="unknown_account_generic_response")
        return jsonify({"status": "accepted"}), 200

    token = secrets.token_urlsafe(24)
    expires_at = _now_utc() + timedelta(minutes=20)
    attrs = dict(user_record.attributes or {})
    attrs["password_reset_expires_at"] = expires_at.isoformat()
    user_record.attributes = attrs

    session = SessionLocal()
    try:
        stored = session.get(UserAccount, user_record.id)
        if stored is not None:
            stored.attributes = attrs
            session.query(PasswordResetState).filter_by(
                user_id=user_record.id,
                tenant_id=tenant_id,
                status="PENDING",
            ).update({PasswordResetState.status: "REVOKED"}, synchronize_session=False)
            session.add(PasswordResetState(
                reset_id=f"reset_{uuid.uuid4().hex[:16]}",
                user_id=user_record.id,
                tenant_id=tenant_id,
                token_hash=_password_reset_token_hash(token),
                status="PENDING",
                requested_at=_now_utc(),
                expires_at=expires_at,
                attempts=0,
            ))
            session.commit()
            _authentication_audit(tenant_id, "password.reset.requested", "success", user_id=user_record.id, identifier=email, reason="reset_state_created")
            _deliver_password_reset_email(tenant_id, user_record.id, stored.email, token)
    finally:
        session.close()

    response = {"status": "accepted"}
    if not _is_production_environment():
        response["reset_token"] = token
    return jsonify(response), 200


@_idempotent_route("/auth/password-reset/confirm", methods=["POST"])
@rate_limit(max_requests_per_minute=10, tokens_per_request=1, endpoint_name="auth_password_reset_confirm")
def password_reset_confirm():
    """Use a valid reset token to rotate the user's password."""
    data = request.json or {}
    email = _normalize_registration_email(data.get("email"))
    tenant_id = str(data.get("tenant_id") or "default").strip() or "default"
    token = str(data.get("token") or "").strip()
    new_password = data.get("new_password")

    if not email or not token or not isinstance(new_password, str):
        return jsonify({"error": "invalid_request", "message": "email, token, and new_password are required."}), 400
    policy_error = _password_policy_error(new_password)
    if policy_error:
        return jsonify({"error": "weak_password", "message": policy_error}), 400

    user_record = _get_user_account_by_email(email, tenant_id)
    if user_record is None:
        _authentication_audit(tenant_id, "password.reset.failed", "failure", identifier=email, reason="unknown_account")
        return jsonify({"error": "invalid_reset_token", "message": "The reset token is invalid or expired."}), 400

    attrs = dict(user_record.attributes or {})
    reset_state = None
    with SessionLocal() as lookup_session:
        reset_state = lookup_session.query(PasswordResetState).filter_by(
            user_id=user_record.id,
            tenant_id=tenant_id,
            status="PENDING",
        ).order_by(PasswordResetState.requested_at.desc()).first()
        if reset_state is None:
            _authentication_audit(tenant_id, "password.reset.failed", "failure", user_id=user_record.id, identifier=email, reason="no_pending_reset")
            return jsonify({"error": "invalid_reset_token", "message": "The reset token is invalid or expired."}), 400
        if _is_expired(reset_state.expires_at):
            reset_state.status = "EXPIRED"
            lookup_session.commit()
            _authentication_audit(tenant_id, "password.reset.failed", "failure", user_id=user_record.id, identifier=email, reason="expired_reset_token")
            return jsonify({"error": "invalid_reset_token", "message": "The reset token is invalid or expired."}), 400
        if reset_state.attempts >= 5:
            reset_state.status = "REVOKED"
            lookup_session.commit()
            return jsonify({"error": "invalid_reset_token", "message": "The reset token is invalid or expired."}), 400
        reset_state.attempts += 1
        if not hmac.compare_digest(reset_state.token_hash, _password_reset_token_hash(token)):
            if reset_state.attempts >= 5:
                reset_state.status = "REVOKED"
            lookup_session.commit()
            _authentication_audit(tenant_id, "password.reset.failed", "failure", user_id=user_record.id, identifier=email, reason="invalid_reset_token")
            return jsonify({"error": "invalid_reset_token", "message": "The reset token is invalid or expired."}), 400

    was_locked = user_record.status == "locked" or bool(attrs.get("locked_until"))
    attrs.pop("password_reset", None)
    attrs.pop("password_reset_expires_at", None)
    _clear_login_failures(user_record)
    attrs = dict(user_record.attributes or {})
    attrs["password_expires_at"] = (_now_utc() + timedelta(days=int(os.getenv("PESAGUARD_PASSWORD_EXPIRY_DAYS", "90")))).isoformat()
    user_record.attributes = attrs
    user_record.status = "active"
    user_record.authorization_version += 1
    try:
        _reset_account_login_throttle(tenant_id, user_record.id)
    except RuntimeError:
        return jsonify({
            "error": "rate_limiter_unavailable",
            "message": "Account recovery is temporarily unavailable.",
            "retry_after": 1,
        }), 503

    session = SessionLocal()
    try:
        stored = session.get(UserAccount, user_record.id)
        if stored is not None:
            consumed = session.query(PasswordResetState).filter_by(
                reset_id=reset_state.reset_id if reset_state is not None else None,
                user_id=user_record.id,
                tenant_id=tenant_id,
                status="PENDING",
            ).update({
                PasswordResetState.status: "USED",
                PasswordResetState.consumed_at: _now_utc(),
            }, synchronize_session=False)
            if consumed != 1:
                session.rollback()
                _authentication_audit(
                    tenant_id, "password.reset.failed", "failure",
                    user_id=user_record.id, identifier=email, reason="reset_already_consumed",
                )
                return jsonify({"error": "invalid_reset_token", "message": "The reset token is invalid or expired."}), 400
            try:
                _rotate_password_credential(session, stored, new_password, "password reset")
            except ValueError as exc:
                session.rollback()
                if str(exc) == "password_reuse":
                    return jsonify({"error": "password_reuse", "message": "The new password was recently used."}), 400
                raise
            stored.attributes = attrs
            stored.status = user_record.status
            stored.authorization_version = user_record.authorization_version
            _upsert_user_identity(
                session,
                stored,
                email_verified=bool(attrs.get("email_verified", False)),
            )
            session.commit()

            active_session_ids = [
                row.id for row in session.query(UserSession.id).filter(
                    UserSession.user_id == user_record.id,
                    UserSession.tenant_id == tenant_id,
                    UserSession.active.is_(True),
                ).all()
            ]
            for session_id in active_session_ids:
                session.query(UserSession).filter_by(id=session_id).update({
                    UserSession.active: False,
                    UserSession.revoked_at: _now_utc(),
                })
            session.commit()
            for session_id in active_session_ids:
                try:
                    AuthRBAC.revoke_session_tokens(session_id, reason="password reset")
                except AuthenticationUnavailable:
                    logger.exception("Failed to revoke refresh tokens for reset session %s", session_id)
                    raise
    finally:
        session.close()

    _authentication_audit(tenant_id, "password.reset.completed", "success", user_id=user_record.id, identifier=email, reason="credential_rotated")
    if was_locked:
        _authentication_audit(
            tenant_id,
            "password.reset.account_recovered",
            "success",
            user_id=user_record.id,
            identifier=email,
            reason="verified_password_reset",
        )
    return jsonify({"status": "success", "message": "Password reset successful."}), 200


@_idempotent_route("/auth/password/change", methods=["POST"])
@require_auth()
def change_password():
    """Change the current user's password after verifying the existing credential."""
    current_user = get_current_user()
    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    if not isinstance(current_password, str) or not isinstance(new_password, str):
        return _api_error("invalid_request", "current_password and new_password are required.", 400)
    policy_error = _password_policy_error(new_password)
    if policy_error:
        return _api_error("weak_password", policy_error, 400)

    with SessionLocal() as lookup_session:
        account = lookup_session.query(UserAccount).filter_by(id=current_user.user_id, tenant_id=current_user.tenant_id).first()
        if account is None:
            return _api_error("invalid_credentials", "Invalid current password.", 401)
        valid, _ = _password_matches(account, current_password)
        if not valid:
            _authentication_audit(current_user.tenant_id, "password.change.failed", "failure", user_id=current_user.user_id, reason="invalid_current_password")
            return _api_error("invalid_credentials", "Invalid current password.", 401)

    session = SessionLocal()
    try:
        account = session.query(UserAccount).filter_by(id=current_user.user_id, tenant_id=current_user.tenant_id).first()
        if account is None:
            return _api_error("resource_not_found", "User account not found.", 404)
        try:
            _rotate_password_credential(session, account, new_password, "user password change")
        except ValueError as exc:
            session.rollback()
            if str(exc) == "password_reuse":
                return _api_error("password_reuse", "The new password was recently used.", 400)
            raise
        try:
            _reset_account_login_throttle(current_user.tenant_id, account.id)
        except RuntimeError:
            session.rollback()
            return _api_error("rate_limiter_unavailable", "Password change is temporarily unavailable.", 503)
        _clear_login_failures(account)
        attrs = dict(account.attributes or {})
        account.status = "active"
        account.authorization_version += 1
        _upsert_user_identity(session, account, email_verified=bool(attrs.get("email_verified", False)))
        session.commit()
    finally:
        session.close()
    _revoke_user_sessions(current_user.user_id, current_user.tenant_id, "password changed")
    _authentication_audit(current_user.tenant_id, "password.change.succeeded", "success", user_id=current_user.user_id, reason="user_initiated")
    return _api_success({"status": "password_changed", "reauthentication_required": True}, 200)


@_idempotent_route("/auth/admin/users/<user_id>/password-reset", methods=["POST"])
@require_auth("manage:users")
@require_privileged_operation_mfa
def admin_password_reset(user_id: str):
    """Reset a tenant user's password through an authorized administrative action."""
    current_user = get_current_user()
    data = request.get_json(silent=True) or {}
    new_password = data.get("new_password")
    if not isinstance(new_password, str):
        return _api_error("invalid_request", "new_password is required.", 400)
    policy_error = _password_policy_error(new_password)
    if policy_error:
        return _api_error("weak_password", policy_error, 400)

    session = SessionLocal()
    try:
        account = session.query(UserAccount).filter_by(id=user_id, tenant_id=current_user.tenant_id).first()
        if account is None:
            return _api_error("resource_not_found", "User account not found for this tenant.", 404)
        try:
            _rotate_password_credential(session, account, new_password, "administrator password reset")
        except ValueError as exc:
            session.rollback()
            if str(exc) == "password_reuse":
                return _api_error("password_reuse", "The new password was recently used.", 400)
            raise
        try:
            _reset_account_login_throttle(current_user.tenant_id, account.id)
        except RuntimeError:
            session.rollback()
            return _api_error("rate_limiter_unavailable", "Account recovery is temporarily unavailable.", 503)
        _clear_login_failures(account)
        attrs = dict(account.attributes or {})
        account.status = "active"
        account.authorization_version += 1
        _upsert_user_identity(session, account, email_verified=bool(attrs.get("email_verified", False)))
        session.commit()
    finally:
        session.close()
    _revoke_user_sessions(user_id, current_user.tenant_id, "administrator password reset")
    _authentication_audit(current_user.tenant_id, "password.admin_reset", "success", user_id=user_id, reason="administrator_initiated")
    return _api_success({"status": "password_reset", "user_id": user_id, "reauthentication_required": True}, 200)


@_idempotent_route("/auth/admin/users/<user_id>/emergency-credential-rotation", methods=["POST"])
@require_auth("manage:security")
@require_privileged_operation_mfa
def emergency_credential_rotation(user_id: str):
    """Immediately rotate a credential and revoke every active session for the user."""
    current_user = get_current_user()
    data = request.get_json(silent=True) or {}
    new_password = data.get("new_password")
    if not isinstance(new_password, str):
        return _api_error("invalid_request", "new_password is required for emergency rotation.", 400)
    policy_error = _password_policy_error(new_password)
    if policy_error:
        return _api_error("weak_password", policy_error, 400)
    session = SessionLocal()
    try:
        account = session.query(UserAccount).filter_by(id=user_id, tenant_id=current_user.tenant_id).first()
        if account is None:
            return _api_error("resource_not_found", "User account not found for this tenant.", 404)
        try:
            _rotate_password_credential(session, account, new_password, "emergency credential rotation")
        except ValueError as exc:
            session.rollback()
            if str(exc) == "password_reuse":
                return _api_error("password_reuse", "The new password was recently used.", 400)
            raise
        try:
            _reset_account_login_throttle(current_user.tenant_id, account.id)
        except RuntimeError:
            session.rollback()
            return _api_error("rate_limiter_unavailable", "Credential recovery is temporarily unavailable.", 503)
        account.status = "active"
        account.authorization_version += 1
        _clear_login_failures(account)
        attrs = dict(account.attributes or {})
        _upsert_user_identity(session, account, email_verified=bool(attrs.get("email_verified", False)))
        session.commit()
    finally:
        session.close()
    _revoke_user_sessions(user_id, current_user.tenant_id, "emergency credential rotation")
    _authentication_audit(current_user.tenant_id, "password.emergency_rotation", "success", user_id=user_id, reason="security_emergency")
    return _api_success({"status": "emergency_rotation_complete", "user_id": user_id, "reauthentication_required": True}, 200)


@_idempotent_route("/auth/verify", methods=["GET"])
@require_auth()
def verify_token():
    """Verify current authentication token state and permissions."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "not_authenticated", "message": "Authentication context missing."}), 401

    return jsonify({
        "user_id": user.user_id,
        "username": user.username,
        "tenant_id": user.tenant_id,
        "roles": user.roles,
        "permissions": user.permissions,
    }), 200


@_idempotent_route("/auth/revoke", methods=["POST"])
@require_auth("manage:users")
def revoke_token():
    """Revoke an active authentication token."""
    payload = request.json or {}
    token = payload.get("token")
    if not token:
        return jsonify({"error": "missing_token", "message": "Token parameter is required."}), 400

    AuthRBAC.revoke_token(token)
    return _api_success({"status": "revoked"}, 200)


@_idempotent_route("/auth/revoke/user", methods=["POST"])
@require_auth("manage:users")
@require_privileged_operation_mfa
def revoke_user_access_route():
    """Revoke every active access path belonging to a user."""
    payload = request.json or {}
    user_id = payload.get("user_id")
    tenant_id = payload.get("tenant_id") or get_current_user().tenant_id
    if not user_id:
        return _api_error("invalid_request", "user_id is required.", 400)
    AuthRBAC.revoke_user_access(str(user_id), str(tenant_id), reason=payload.get("reason") or "user revocation")
    return _api_success({"status": "user_revoked", "user_id": str(user_id), "tenant_id": str(tenant_id)}, 200)


@_idempotent_route("/auth/revoke/device", methods=["POST"])
@require_auth()
def revoke_device_access_route():
    """Revoke all active sessions for a device and invalidate associated refresh tokens."""
    payload = request.json or {}
    device_id = payload.get("device_id")
    tenant_id = payload.get("tenant_id") or get_current_user().tenant_id
    current_user = get_current_user()
    if not device_id:
        return _api_error("invalid_request", "device_id is required.", 400)
    if str(tenant_id) != current_user.tenant_id and "manage:all_tenants" not in current_user.permissions:
        return _api_error("tenant_access_denied", "You cannot revoke devices outside your tenant.", 403)

    session = SessionLocal()
    try:
        query = session.query(DeviceIdentity).filter_by(tenant_id=str(tenant_id), device_id=str(device_id))
        if "manage:users" not in current_user.permissions:
            query = query.filter_by(user_id=current_user.user_id)
        device = query.first()
        if device is None:
            return _api_error("resource_not_found", "Device not found for this user and tenant.", 404)
        device.trusted = False
        device.revoked_at = _now_utc()
        session.query(UserSession).filter_by(
            tenant_id=device.tenant_id,
            user_id=device.user_id,
            device_id=device.device_id,
            active=True,
        ).update({
            UserSession.active: False,
            UserSession.state: "REVOKED",
            UserSession.revoked_at: _now_utc(),
        }, synchronize_session=False)
        session.commit()
        session_ids = [row.id for row in session.query(UserSession.id).filter_by(
            tenant_id=device.tenant_id,
            user_id=device.user_id,
            device_id=device.device_id,
        ).all()]
        device_owner = device.user_id
    finally:
        session.close()
    for session_id in session_ids:
        AuthRBAC.revoke_session_tokens(session_id, reason=payload.get("reason") or "device revocation")
    return _api_success({"status": "device_revoked", "device_id": str(device_id), "tenant_id": str(tenant_id), "user_id": device_owner}, 200)


@_idempotent_route("/auth/revoke/refresh", methods=["POST"])
@require_auth()
def revoke_refresh_token_route():
    """Revoke a refresh token or the entire refresh-token family for compromise detection."""
    payload = request.json or {}
    token = payload.get("refresh_token") or payload.get("token")
    if not token:
        return _api_error("invalid_request", "refresh_token is required.", 400)
    AuthRBAC.revoke_refresh_token(str(token), reason=payload.get("reason") or "refresh token revoked")
    return _api_success({"status": "refresh_revoked"}, 200)


@_idempotent_route("/auth/security/global-revoke", methods=["POST"])
@require_auth("manage:settings")
@require_privileged_operation_mfa
def emergency_global_revocation_route():
    """Emergency global invalidation of active sessions and trusted credentials."""
    payload = request.json or {}
    AuthRBAC.emergency_global_revocation(reason=payload.get("reason") or "emergency global revocation")
    return _api_success({"status": "global_revocation_complete", "reason": payload.get("reason") or "emergency global revocation"}, 200)


@_idempotent_route("/auth/account/lockouts", methods=["GET"])
@require_auth("manage:users")
def list_account_lockouts_route():
    """Expose only tenant-authorized active lockouts to security administrators."""
    caller = get_current_user()
    requested_tenant = request.args.get("tenant_id")
    tenant_id = str(requested_tenant or caller.tenant_id)
    if tenant_id != caller.tenant_id and "manage:all_tenants" not in caller.permissions:
        return _api_error("tenant_access_denied", "Access to this tenant scope is forbidden.", 403)

    limit = min(max(request.args.get("limit", 50, type=int), 1), 100)
    offset = max(request.args.get("offset", 0, type=int), 0)
    with SessionLocal() as session:
        total = session.query(UserAccount).filter_by(tenant_id=tenant_id, status="locked").count()
        rows = session.query(UserAccount).filter_by(
            tenant_id=tenant_id,
            status="locked",
        ).order_by(UserAccount.updated_at.asc()).offset(offset).limit(limit).all()
    items = []
    for account in rows:
        locked_until = _check_account_lockout(account)
        if locked_until is None:
            continue
        attrs = dict(account.attributes or {})
        items.append({
            "user_id": account.id,
            "username": account.username,
            "email": account.email,
            "failed_attempts": int(attrs.get("failed_login_count", 0) or 0),
            "lockout_count": int(attrs.get("lockout_count", 0) or 0),
            "last_failed_login_at": attrs.get("last_failed_login_at"),
            "locked_until": locked_until.isoformat(),
        })
    with SessionLocal() as session:
        total = session.query(UserAccount).filter_by(tenant_id=tenant_id, status="locked").count()
    return _api_success({
        "tenant_id": tenant_id,
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }, 200)


@_idempotent_route("/auth/account/unlock", methods=["POST"])
@require_auth("manage:users")
@require_privileged_operation_mfa
def unlock_account_route():
    """Allow security operators to reset an account lock and clear failed-login state."""
    payload = request.json or {}
    user_id = payload.get("user_id")
    caller = get_current_user()
    tenant_id = str(payload.get("tenant_id") or caller.tenant_id)
    if not user_id:
        return _api_error("invalid_request", "user_id is required.", 400)
    if tenant_id != caller.tenant_id and "manage:all_tenants" not in caller.permissions:
        return _api_error("tenant_access_denied", "Access to this tenant scope is forbidden.", 403)

    try:
        _reset_account_login_throttle(tenant_id, str(user_id))
    except RuntimeError:
        return _api_error("rate_limiter_unavailable", "Account unlock is temporarily unavailable.", 503)

    session = SessionLocal()
    try:
        record = session.query(UserAccount).filter_by(id=str(user_id), tenant_id=str(tenant_id)).first()
        if record is None:
            return _api_error("resource_not_found", "User account not found for this tenant.", 404)

        _clear_login_failures(record)
        record.status = "active"
        _upsert_user_identity(session, record)
        session.commit()
        _authentication_audit(
            str(tenant_id),
            "login.account_unlocked",
            "success",
            user_id=record.id,
            actor_id=caller.user_id,
            identifier=record.username,
            reason=str(payload.get("reason") or "manual unlock"),
        )
        return _api_success({
            "status": "account_unlocked",
            "tenant_id": str(tenant_id),
            "user_id": str(user_id),
            "reason": payload.get("reason") or "manual unlock",
        }, 200)
    finally:
        session.close()


@_idempotent_route("/auth/service-credentials/<credential_id>/revoke", methods=["POST"])
@require_auth("manage:settings")
def revoke_service_credential_route(credential_id: str):
    """Revoke a workload or service credential and preserve the audit trail."""
    payload = request.json or {}
    tenant_id = str(payload.get("tenant_id") or get_current_user().tenant_id)
    AuthRBAC.revoke_service_credential(str(credential_id), tenant_id, reason=payload.get("reason") or "service credential revoked")
    return _api_success({"status": "service_credential_revoked", "credential_id": str(credential_id), "tenant_id": tenant_id}, 200)


@_idempotent_route("/auth/sessions", methods=["GET"])
@require_auth()
def list_sessions():
    """List the caller's sessions, or all tenant sessions for user managers."""
    current_user = get_current_user()
    session = SessionLocal()
    try:
        query = session.query(UserSession).filter(UserSession.tenant_id == current_user.tenant_id)
        if "manage:users" not in current_user.permissions:
            query = query.filter(UserSession.user_id == current_user.user_id)
        records = query.order_by(UserSession.last_activity_at.desc()).all()
        active_ips = {row.ip_address for row in records if row.ip_address}
        active_agents = {row.user_agent for row in records if row.user_agent}
        return _api_success({
            "sessions": [{
                "session_id": row.id,
                "user_id": row.user_id,
                "tenant_id": row.tenant_id,
                "organization_id": row.organization_id,
                "device_id": row.device_id,
                "user_agent": row.user_agent,
                "ip_address": row.ip_address,
                "location_info": row.location_info,
                "state": row.state,
                "active": row.active,
                "authentication_method": row.authentication_method,
                "mfa_verified": row.mfa_verified,
                "created_at": row.issued_at.isoformat() if row.issued_at else None,
                "last_activity_at": row.last_activity_at.isoformat() if row.last_activity_at else None,
                "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                "absolute_expires_at": row.absolute_expires_at.isoformat() if row.absolute_expires_at else None,
                "suspicious": bool(row.ip_address and len(active_ips) > 3) or bool(row.user_agent and len(active_agents) > 3),
            } for row in records]}, 200)
    finally:
        session.close()


@_idempotent_route("/auth/sessions/<session_id>/revoke", methods=["POST"])
@require_auth()
def revoke_session_route(session_id):
    """Revoke a device session and persist the session state."""
    tenant_id = get_current_user().tenant_id
    session = SessionLocal()
    try:
        current_user = get_current_user()
        record = session.query(UserSession).filter_by(id=session_id, tenant_id=tenant_id).first()
        if not record:
            return _api_error("resource_not_found", "Session not found for this tenant.", 404)
        if record.user_id != current_user.user_id and "manage:users" not in current_user.permissions:
            return _api_error("permission_denied", "You cannot revoke another user's session.", 403)

        record.active = False
        record.state = "REVOKED"
        record.revoked_at = datetime.now(timezone.utc)
        try:
            AuthRBAC.revoke_session_tokens(session_id)
        except AuthenticationUnavailable:
            session.rollback()
            return _api_error("authentication_unavailable", "Session revocation is temporarily unavailable.", 503)
        session.commit()
        return _api_success({"status": "revoked", "session_id": record.id, "tenant_id": tenant_id}, 200)
    finally:
        session.close()


@_idempotent_route("/auth/sessions/<session_id>/renew", methods=["POST"])
@require_auth()
def renew_session_route(session_id):
    """Renew activity and idle validity without extending the absolute session limit."""
    current_user = get_current_user()
    session = SessionLocal()
    try:
        record = session.query(UserSession).filter_by(id=session_id, tenant_id=current_user.tenant_id, user_id=current_user.user_id).first()
        if record is None:
            return _api_error("resource_not_found", "Session not found.", 404)
        if record.state != "ACTIVE" or not record.active or (record.absolute_expires_at and _is_expired(record.absolute_expires_at)):
            return _api_error("session_expired", "Session is no longer renewable.", 401)
        record.last_activity_at = _now_utc()
        session.commit()
        return _api_success({"session_id": record.id, "state": record.state, "last_activity_at": record.last_activity_at.isoformat()}, 200)
    finally:
        session.close()


@_idempotent_route("/auth/logout", methods=["POST"])
@require_auth()
def logout_current_session():
    """Revoke one caller-owned session and its refresh-token family."""
    current_user = get_current_user()
    session_id = str((request.get_json(silent=True) or {}).get("session_id") or "").strip()
    if not session_id:
        return _api_error("invalid_request", "session_id is required.", 400)
    return revoke_session_route(session_id)


@_idempotent_route("/auth/logout-all", methods=["POST"])
@require_auth()
def logout_all_sessions():
    """Revoke every active session and refresh-token family for the caller."""
    current_user = get_current_user()
    session = SessionLocal()
    session_ids = []
    try:
        records = session.query(UserSession).filter_by(user_id=current_user.user_id, tenant_id=current_user.tenant_id, active=True).all()
        session_ids = [record.id for record in records]
        for record in records:
            record.active = False
            record.state = "REVOKED"
            record.revoked_at = _now_utc()
        session.commit()
    finally:
        session.close()
    for session_id in session_ids:
        try:
            AuthRBAC.revoke_session_tokens(session_id, reason="logout all devices")
        except AuthenticationUnavailable:
            logger.exception("Failed revoking refresh tokens for session %s", session_id)
    return _api_success({"status": "logged_out_all_devices", "revoked_sessions": len(session_ids)}, 200)


def _oidc_roles_from_claims(claims: Dict[str, Any]) -> List[str]:
    """Map incoming IdP claims like groups or roles to the local canonical role model."""
    candidates: List[str] = []
    raw_groups = claims.get("groups") or claims.get("roles") or claims.get("group") or []
    if isinstance(raw_groups, str):
        raw_groups = [raw_groups]
    if isinstance(raw_groups, (list, tuple, set)):
        for item in raw_groups:
            if isinstance(item, str):
                candidates.extend(part.strip() for part in item.split(",") if part.strip())
    if not candidates:
        role_claim = claims.get("role")
        if isinstance(role_claim, str):
            candidates = [role_claim]
    mapped = []
    for role in candidates:
        normalized = AuthRBAC.normalize_role_name(role)
        if normalized and normalized in AuthRBAC.ROLE_PERMISSIONS:
            mapped.append(normalized)
    return mapped or ["read_only"]


def _allowed_oidc_groups() -> set[str]:
    raw = os.getenv("OIDC_ALLOWED_GROUPS", "")
    if not raw:
        return set()
    return {AuthRBAC.normalize_role_name(part.strip()) for part in raw.split(",") if part.strip()}


def _apply_provider_claim_mapping(claims: Dict[str, Any], claim_mapping: Optional[Dict[str, str]]) -> Dict[str, Any]:
    """Normalize provider claim names to the standard internal names used by the callback policy layer."""
    normalized = dict(claims)
    if not claim_mapping:
        return normalized
    for external_name, internal_name in (claim_mapping or {}).items():
        if external_name in claims and internal_name not in normalized:
            normalized[internal_name] = claims[external_name]
    return normalized


def _provision_external_user_from_claims(tenant_id: str, email: Optional[str], username: str, roles: List[str], claims: Dict[str, Any]) -> UserAccount:
    """Provision or update a local UserAccount from validated external claims."""
    session = SessionLocal()
    try:
        user_record = session.query(UserAccount).filter(UserAccount.tenant_id == tenant_id, UserAccount.email == email).first()
        if user_record is None:
            username = username or (email.split("@", 1)[0] if email else f"oidc_{uuid.uuid4().hex[:8]}")
            user_record = UserAccount(
                id=f"user_{uuid.uuid4().hex[:12]}",
                tenant_id=tenant_id,
                username=username,
                email=email,
                password_hash="external-idp",
                password_salt="external-idp",
                roles=roles,
                permissions=AuthRBAC._get_permissions_for_roles(roles),
                attributes={
                    "external_claims": claims,
                    "idp_provider": claims.get("issuer") or "oidc",
                },
                mfa_enabled=False,
                status="active",
            )
            session.add(user_record)
            session.commit()
            return user_record

        merged_roles = sorted({*user_record.roles, *roles})
        if merged_roles != sorted(user_record.roles):
            user_record.authorization_version += 1
        user_record.username = username or user_record.username
        user_record.email = email or user_record.email
        user_record.roles = merged_roles
        user_record.permissions = AuthRBAC._get_permissions_for_roles(merged_roles)
        user_record.attributes = {**(user_record.attributes or {}), "external_claims": claims, "idp_provider": claims.get("issuer") or "oidc"}
        session.commit()
        return user_record
    finally:
        session.close()


@_idempotent_route("/auth/sso/providers", methods=["GET", "POST"])
@require_auth("manage:sso")
@require_privileged_operation_mfa
def oidc_provider_registry():
    """Register or list external OIDC providers for a tenant."""
    if request.method == "GET":
        tenant_id = request.args.get("tenant_id") or get_current_user().tenant_id
        session = SessionLocal()
        try:
            providers = session.query(OIDCProvider).filter(OIDCProvider.tenant_id == tenant_id).all()
            return _api_success({
                "providers": [{
                    "id": row.id,
                    "name": row.provider_name,
                    "issuer": row.issuer,
                    "client_id": row.client_id,
                    "enabled": row.enabled,
                    "authorization_endpoint": row.authorization_endpoint,
                    "token_endpoint": row.token_endpoint,
                    "userinfo_endpoint": row.userinfo_endpoint,
                    "jwks_uri": row.jwks_uri,
                } for row in providers]}, 200)
        finally:
            session.close()

    data = request.get_json(silent=True) or {}
    tenant_id = data.get("tenant_id") or get_current_user().tenant_id
    provider_name = data.get("provider_name") or data.get("name") or "default-oidc"
    issuer = data.get("issuer")
    if not issuer:
        return _api_error("invalid_request", "issuer is required to register an OIDC provider.", 400)

    metadata = data.get("metadata") or {}
    provider_type = str(data.get("provider_type", "oidc")).strip().lower()
    if provider_type not in {"oidc", "saml"}:
        return _api_error("invalid_provider", "provider_type must be oidc or saml.", 400)
    try:
        if provider_type == "oidc":
            discovered = _fetch_oidc_metadata(issuer)
            if discovered:
                metadata = discovered
    except ValueError:
        if not metadata and not any(data.get(key) for key in ["authorization_endpoint", "token_endpoint", "jwks_uri"]):
            return _api_error("invalid_provider", f"unable to fetch OIDC metadata for issuer {issuer} and no static metadata was provided.", 400)

    trust_policy = data.get("trust_policy") or _provider_trust_policy_for_tenant(tenant_id)
    if provider_type == "saml":
        if not _validate_saml_provider_policy(trust_policy, metadata):
            return _api_error("policy_denied", "The SAML trust policy does not allow the supplied provider configuration.", 403)
    else:
        provider_metadata = {"issuer": issuer, "jwks_uri": data.get("jwks_uri") or metadata.get("jwks_uri"), **metadata}
        if not _validate_provider_trust_policy(tenant_id, trust_policy, provider_metadata):
            return _api_error("policy_denied", "The tenant's external IdP trust policy rejects this issuer or JWKS binding.", 403)

    session = SessionLocal()
    try:
        existing = session.query(OIDCProvider).filter_by(tenant_id=tenant_id, issuer=issuer).first()
        if existing:
            existing.provider_name = provider_name
            existing.client_id = data.get("client_id") or existing.client_id
            if data.get("client_secret"):
                existing.client_secret = encrypt_value(data["client_secret"])
            existing.authorization_endpoint = data.get("authorization_endpoint") or metadata.get("authorization_endpoint") or existing.authorization_endpoint
            existing.token_endpoint = data.get("token_endpoint") or metadata.get("token_endpoint") or existing.token_endpoint
            existing.userinfo_endpoint = data.get("userinfo_endpoint") or metadata.get("userinfo_endpoint") or existing.userinfo_endpoint
            existing.jwks_uri = data.get("jwks_uri") or metadata.get("jwks_uri") or existing.jwks_uri
            existing.scopes = data.get("scopes") or metadata.get("scopes_supported") or existing.scopes or ["openid", "profile", "email"]
            existing.allowed_roles = data.get("allowed_roles") or existing.allowed_roles or []
            existing.auto_provision = bool(data.get("auto_provision", existing.auto_provision))
            existing.claim_mapping = data.get("claim_mapping") or existing.claim_mapping or {"groups": "groups", "role": "role"}
            existing.provider_metadata = metadata
            existing.enabled = data.get("enabled", True)
            session.commit()
            record = existing
        else:
            record = OIDCProvider(
                id=f"oidc_{uuid.uuid4().hex[:12]}",
                tenant_id=tenant_id,
                provider_name=provider_name,
                issuer=issuer,
                client_id=data.get("client_id"),
                client_secret=encrypt_value(data["client_secret"]) if data.get("client_secret") else None,
                authorization_endpoint=data.get("authorization_endpoint") or metadata.get("authorization_endpoint"),
                token_endpoint=data.get("token_endpoint") or metadata.get("token_endpoint"),
                userinfo_endpoint=data.get("userinfo_endpoint") or metadata.get("userinfo_endpoint"),
                jwks_uri=data.get("jwks_uri") or metadata.get("jwks_uri"),
                scopes=data.get("scopes") or metadata.get("scopes_supported") or ["openid", "profile", "email"],
                allowed_roles=data.get("allowed_roles") or [],
                auto_provision=bool(data.get("auto_provision", False)),
                claim_mapping=data.get("claim_mapping") or {"groups": "groups", "role": "role"},
                enabled=data.get("enabled", True),
                provider_metadata=metadata,
            )
            session.add(record)
            session.commit()

        return _api_success({
            "id": record.id,
            "provider_name": record.provider_name,
            "tenant_id": record.tenant_id,
            "issuer": record.issuer,
            "authorization_endpoint": record.authorization_endpoint,
            "token_endpoint": record.token_endpoint,
            "userinfo_endpoint": record.userinfo_endpoint,
            "jwks_uri": record.jwks_uri,
            "enabled": record.enabled,
            "allowed_roles": record.allowed_roles,
            "auto_provision": record.auto_provision,
            "claim_mapping": record.claim_mapping,
            "trust_policy": trust_policy,
            "metadata": record.provider_metadata,
        }, 201)
    finally:
        session.close()


@_idempotent_route("/auth/sso/policy", methods=["GET", "POST"])
@require_auth("manage:sso")
@require_privileged_operation_mfa
def external_idp_policy_route():
    """Get or configure tenant-level external IdP trust policy for OIDC/SAML providers."""
    tenant_id = request.args.get("tenant_id") or request.get_json(silent=True, force=False).get("tenant_id") if request.get_json(silent=True) else None or get_current_user().tenant_id
    if request.method == "GET":
        return _api_success({"policy": _provider_trust_policy_for_tenant(tenant_id)}, 200)

    data = request.get_json(silent=True) or {}
    trust_policy = data.get("trust_policy") or data
    policy = _provider_trust_policy_for_tenant(tenant_id)
    if isinstance(trust_policy, dict):
        policy.update(trust_policy)

    if bool(policy.get("review_required")) and not str(policy.get("approved_by") or "").strip():
        return _api_error("policy_denied", "The tenant external IdP policy requires admin approval before activation.", 403)

    if policy.get("provider_type", "oidc").lower() == "saml":
        if not _validate_saml_provider_policy(policy):
            return _api_error("policy_denied", "The SAML trust policy is missing the required explicit entity identifier.", 403)

    return _api_success({"policy": policy, "tenant_id": tenant_id}, 200)


@_idempotent_route("/auth/sso/policy/review", methods=["POST"])
@require_auth("manage:sso")
@require_privileged_operation_mfa
def external_idp_policy_review_route():
    """Approve or reject a tenant external IdP policy after admin review."""
    data = request.get_json(silent=True) or {}
    tenant_id = data.get("tenant_id") or get_current_user().tenant_id
    decision = str(data.get("decision") or "approve").strip().lower()
    reviewer = str(data.get("reviewer") or get_current_user().username or "admin").strip()
    policy = _provider_trust_policy_for_tenant(tenant_id)
    if isinstance(data.get("trust_policy"), dict):
        policy.update(data.get("trust_policy"))

    if decision not in {"approve", "reject"}:
        return _api_error("invalid_request", "decision must be either approve or reject.", 400)

    if decision == "approve":
        policy["review_required"] = False
        policy["approved_by"] = reviewer
        policy["approved_at"] = datetime.now(timezone.utc).isoformat()
    else:
        policy["approved_by"] = None
        policy["approved_at"] = None
        policy["review_required"] = True

    return _api_success({"policy": policy, "tenant_id": tenant_id, "decision": decision}, 200)


@_idempotent_route("/auth/sso/oidc/validate", methods=["POST"])
@require_auth("manage:sso")
def oidc_provider_validate():
    """Validate a real issuer by fetching and checking its OIDC metadata document."""
    data = request.get_json(silent=True) or {}
    issuer = data.get("issuer") or data.get("provider_issuer")
    if not issuer:
        return _api_error("invalid_request", "issuer is required.", 400)

    try:
        metadata = _fetch_oidc_metadata(issuer)
    except ValueError as exc:
        return _api_error("invalid_provider", str(exc), 400)

    return _api_success({
        "valid": True,
        "issuer": metadata["issuer"],
        "authorization_endpoint": metadata.get("authorization_endpoint"),
        "token_endpoint": metadata.get("token_endpoint"),
        "jwks_uri": metadata.get("jwks_uri"),
        "metadata": metadata,
    }, 200)


@_idempotent_route("/auth/sso/oidc/config", methods=["GET"])
@require_auth("manage:sso")
def oidc_config_route():
    """Expose a minimal OIDC discovery document for external identity providers."""
    provider = None
    tenant_id = get_current_user().tenant_id
    if tenant_id:
        session = SessionLocal()
        try:
            provider = session.query(OIDCProvider).filter_by(tenant_id=tenant_id, enabled=True).first()
        finally:
            session.close()
    if provider is None:
        issuer = os.getenv("OIDC_ISSUER") or (request.url_root.rstrip("/") or "https://api.pesaguard.victorkipruto.com")
        base_url = issuer.rstrip("/")
    else:
        base_url = provider.issuer.rstrip("/")

    config = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/auth/sso/oidc/authorize",
        "token_endpoint": f"{base_url}/auth/sso/oidc/token",
        "userinfo_endpoint": f"{base_url}/auth/sso/oidc/userinfo",
        "jwks_uri": f"{base_url}/auth/sso/oidc/jwks",
        "callback_endpoint": f"{base_url}/auth/sso/oidc/callback",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }
    return _api_success(config, 200)


@_idempotent_route("/auth/devices", methods=["GET"])
@require_auth()
def list_devices():
    """List durable device identities owned by the caller, or by its tenant when managing users."""
    user = get_current_user()
    session = SessionLocal()
    try:
        query = session.query(DeviceIdentity).filter(DeviceIdentity.tenant_id == user.tenant_id)
        if "manage:users" not in user.permissions:
            query = query.filter(DeviceIdentity.user_id == user.user_id)
        rows = query.order_by(DeviceIdentity.last_seen_at.desc()).limit(500).all()
        return _api_success({
            "devices": [{
                "id": row.id,
                "user_id": row.user_id,
                "device_id": row.device_id,
                "device_name": row.device_name,
                "browser": row.browser,
                "operating_system": row.operating_system,
                "user_agent": row.user_agent,
                "first_seen": row.first_seen_at.isoformat() if row.first_seen_at else None,
                "last_seen": row.last_seen_at.isoformat() if row.last_seen_at else None,
                "last_ip": row.last_ip_address,
                "session_count": row.session_count,
                "trusted": row.trusted,
                "state": "revoked" if row.revoked_at else "active",
                "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
            } for row in rows]}, 200)
    finally:
        session.close()


@_idempotent_route("/auth/devices/<device_id>/rename", methods=["POST"])
@require_auth()
def rename_device(device_id: str):
    """Set a caller-visible name for an owned device identity."""
    user = get_current_user()
    payload = request.get_json(silent=True) or {}
    name = payload.get("device_name")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 128:
        return _api_error("invalid_request", "device_name must contain 1 to 128 characters.", 400)
    session = SessionLocal()
    try:
        query = session.query(DeviceIdentity).filter_by(tenant_id=user.tenant_id, device_id=device_id)
        if "manage:users" not in user.permissions:
            query = query.filter_by(user_id=user.user_id)
        device = query.first()
        if device is None:
            return _api_error("resource_not_found", "Device not found for this user and tenant.", 404)
        device.device_name = name.strip()
        session.commit()
        return _api_success({"device_id": device.device_id, "device_name": device.device_name}, 200)
    finally:
        session.close()


@_idempotent_route("/auth/devices/<device_id>/trust", methods=["POST"])
@require_auth()
def trust_device(device_id: str):
    """Require a fresh MFA proof before marking an owned device as trusted."""
    user = get_current_user()
    payload = request.get_json(silent=True) or {}
    code = str(payload.get("mfa_code") or payload.get("recovery_code") or "").strip()
    session = SessionLocal()
    try:
        device = session.query(DeviceIdentity).filter_by(
            tenant_id=user.tenant_id,
            user_id=user.user_id,
            device_id=device_id,
        ).first()
        if device is None:
            return _api_error("resource_not_found", "Device not found for this user and tenant.", 404)
        if device.revoked_at is not None:
            return _api_error("device_revoked", "A revoked device cannot be trusted.", 409)
        account = session.query(UserAccount).filter_by(id=user.user_id, tenant_id=user.tenant_id).first()
        if account is None or not account.mfa_enabled or not code or not _verify_mfa_code(account, code):
            session.rollback()
            return _api_error("mfa_required", "A valid MFA code is required to trust a device.", 401)
        device.trusted = True
        session.commit()
        return _api_success({"device_id": device.device_id, "trusted": True}, 200)
    finally:
        session.close()


@_idempotent_route("/auth/devices/<device_id>/logout", methods=["POST"])
@require_auth()
def logout_device(device_id: str):
    """End sessions on one owned device without permanently revoking its identity."""
    user = get_current_user()
    session = SessionLocal()
    try:
        query = session.query(DeviceIdentity).filter_by(tenant_id=user.tenant_id, device_id=device_id)
        if "manage:users" not in user.permissions:
            query = query.filter_by(user_id=user.user_id)
        device = query.first()
        if device is None:
            return _api_error("resource_not_found", "Device not found for this user and tenant.", 404)
        session_ids = [row.id for row in session.query(UserSession.id).filter_by(
            tenant_id=device.tenant_id,
            user_id=device.user_id,
            device_id=device.device_id,
            active=True,
        ).all()]
        session.query(UserSession).filter(UserSession.id.in_(session_ids)).update({
            UserSession.active: False,
            UserSession.state: "REVOKED",
            UserSession.revoked_at: _now_utc(),
        }, synchronize_session=False)
        session.commit()
    finally:
        session.close()
    for session_id in session_ids:
        AuthRBAC.revoke_session_tokens(session_id, reason="device logout")
    return _api_success({"status": "device_logged_out", "device_id": device_id, "sessions_revoked": len(session_ids)}, 200)


@_idempotent_route("/auth/devices/<device_id>/revoke", methods=["POST"])
@require_auth()
def revoke_managed_device(device_id: str):
    """Persist a device revocation and invalidate all owned sessions and refresh tokens."""
    user = get_current_user()
    session = SessionLocal()
    try:
        query = session.query(DeviceIdentity).filter_by(tenant_id=user.tenant_id, device_id=device_id)
        if "manage:users" not in user.permissions:
            query = query.filter_by(user_id=user.user_id)
        device = query.first()
        if device is None:
            return _api_error("resource_not_found", "Device not found for this user and tenant.", 404)
        device.trusted = False
        device.revoked_at = device.revoked_at or _now_utc()
        session_ids = [row.id for row in session.query(UserSession.id).filter_by(
            tenant_id=device.tenant_id,
            user_id=device.user_id,
            device_id=device.device_id,
            active=True,
        ).all()]
        if session_ids:
            session.query(UserSession).filter(UserSession.id.in_(session_ids)).update({
                UserSession.active: False,
                UserSession.state: "REVOKED",
                UserSession.revoked_at: _now_utc(),
            }, synchronize_session=False)
        session.commit()
    finally:
        session.close()
    for session_id in session_ids:
        AuthRBAC.revoke_session_tokens(session_id, reason="device revoked")
    return _api_success({"status": "device_revoked", "device_id": device_id, "sessions_revoked": len(session_ids)}, 200)


@_idempotent_route("/auth/sso/oidc/authorize", methods=["GET"])
@require_auth("manage:sso")
def oidc_authorize():
    """Issue a one-time authorization code only for a validated, configured external Issuer."""
    return _api_error(
        "oidc_provider_exchange_required",
        "OIDC authorization requires a configured provider integration and is not available through the local mock flow.",
        501,
    )


@_idempotent_route("/auth/sso/oidc/callback", methods=["GET", "POST"])
def oidc_callback():
    """Handle an external OIDC callback, enforce tenant policy, and provision the user from claims."""
    return _api_error(
        "oidc_exchange_required",
        "OIDC callbacks must be processed through a validated provider code exchange.",
        501,
    )

    payload = request.get_json(silent=True) or request.args.to_dict(flat=True)
    code = payload.get("code")
    state = payload.get("state")
    email = payload.get("email") or payload.get("preferred_username") or payload.get("email_address")
    tenant_id = payload.get("tenant_id") or payload.get("tenant") or "default"
    issuer = payload.get("issuer")

    provider = _resolve_oidc_provider(tenant_id=tenant_id, issuer=issuer)
    policy = _provider_trust_policy_for_tenant(tenant_id)
    if provider is not None:
        trust_metadata = {
            "issuer": provider.issuer,
            "jwks_uri": provider.jwks_uri,
            "email_verified": bool(payload.get("email_verified") or payload.get("email_verified") is True),
        }
        if not _validate_provider_trust_policy(tenant_id, policy, trust_metadata):
            return _api_error("policy_denied", "The tenant's external IdP trust policy rejects this authentication attempt.", 403)

    claim_mapping = provider.claim_mapping if provider else {"groups": "groups", "role": "role"}
    normalized_payload = _apply_provider_claim_mapping(payload, claim_mapping)

    raw_groups = normalized_payload.get("groups") or normalized_payload.get("roles") or normalized_payload.get("group") or []
    if isinstance(raw_groups, str):
        groups = [role.strip() for role in raw_groups.split(",") if role.strip()]
    elif isinstance(raw_groups, (list, tuple, set)):
        groups = [str(role).strip() for role in raw_groups if str(role).strip()]
    else:
        groups = []

    roles = _oidc_roles_from_claims({"groups": groups, "role": normalized_payload.get("role")})
    allowed_roles = set((provider.allowed_roles or []) if provider else [])
    global_allowed = _allowed_oidc_groups()
    if allowed_roles:
        allowed = {AuthRBAC.normalize_role_name(role) for role in allowed_roles}
        filtered_roles = [role for role in roles if role in allowed or role == "read_only"]
        if not filtered_roles:
            return _api_error("policy_denied", "The external IdP claims do not satisfy the allowed-role policy for this tenant.", 403)
        roles = filtered_roles
    elif global_allowed:
        filtered_roles = [role for role in roles if role in global_allowed or role == "read_only"]
        if not filtered_roles:
            return _api_error("policy_denied", "The external IdP claims do not satisfy the allowed-role policy for this tenant.", 403)
        roles = filtered_roles

    username = payload.get("username") or (email.split("@", 1)[0] if email else "oidc-user")
    auto_provision = bool((provider.auto_provision if provider else False) or os.getenv("OIDC_AUTO_PROVISION", "0") == "1")
    if auto_provision:
        user_record = _provision_external_user_from_claims(tenant_id, email, username, roles, normalized_payload)
        if user_record.status != "active":
            return _api_error("account_disabled", "This account is not active.", 403)
        user = IdentityAccessService.create_principal(
            user_id=user_record.id,
            username=user_record.username,
            tenant_id=user_record.tenant_id,
            roles=user_record.roles,
            permissions=user_record.permissions,
            attributes=user_record.attributes or {},
        )
    else:
        user = IdentityAccessService.create_principal(
            user_id=f"oidc_{uuid.uuid4().hex[:12]}",
            username=username,
            tenant_id=tenant_id,
            roles=roles,
        )

    access_token = AuthRBAC.generate_token(
        user_id=user.user_id,
        username=user.username,
        tenant_id=user.tenant_id,
        roles=user.roles,
    )
    return _api_success({
        "user_id": user.user_id,
        "username": user.username,
        "tenant_id": user.tenant_id,
        "roles": user.roles,
        "email": email,
        "code": code,
        "state": state,
        "token": access_token,
    }, 200)


@_idempotent_route("/auth/sso/oidc/token", methods=["POST"])
def oidc_token():
    """Exchange an authorization code for a signed access token and ID token."""
    data = request.get_json(silent=True) or {}
    grant_type = data.get("grant_type")
    if grant_type == "refresh_token":
        rotated = AuthRBAC.rotate_refresh_token(
            data.get("refresh_token", ""),
            device_id=data.get("device_id"),
            user_agent=request.headers.get("User-Agent"),
            ip_address=request.remote_addr,
        )
        if rotated is None:
            return _api_error("invalid_grant", "Refresh token is invalid, expired, revoked, or already used.", 401)
        user, refresh_token = rotated
        access_token = AuthRBAC.generate_token(
            user_id=user.user_id,
            username=user.username,
            tenant_id=user.tenant_id,
            roles=user.roles,
        )
        return _api_success({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": AuthRBAC.ACCESS_TOKEN_TTL_MINUTES * 60,
            "refresh_token": refresh_token,
        }, 200)

    code = data.get("code")
    client_id = data.get("client_id")
    redirect_uri = data.get("redirect_uri")
    if grant_type != "authorization_code" or not code or not client_id or not redirect_uri:
        return _api_error("invalid_request", "authorization_code grant requires client_id, code, and redirect_uri.", 400)

    return _api_error(
        "oidc_exchange_required",
        "Authorization-code exchange is unavailable until provider token and state validation is configured.",
        501,
    )

    session_id = f"oidc_{uuid.uuid4().hex[:12]}"
    access_token = AuthRBAC.generate_token(
        user_id=user.user_id,
        username=user.username,
        tenant_id=user.tenant_id,
        roles=user.roles,
        session_id=session_id,
    )
    id_token = AuthRBAC.generate_token(
        user_id=user.user_id,
        username=user.username,
        tenant_id=user.tenant_id,
        roles=user.roles,
        session_id=session_id,
    )
    session = SessionLocal()
    try:
        session.add(UserSession(
            id=session_id,
            tenant_id=user.tenant_id,
            user_id=user.user_id,
            device_id=data.get("device_id"),
            user_agent=request.headers.get("User-Agent"),
            ip_address=request.remote_addr,
            active=True,
            session_metadata={"source": "oidc"},
        ))
        session.commit()
    finally:
        session.close()
    return _api_success({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": AuthRBAC.ACCESS_TOKEN_TTL_MINUTES * 60,
        "id_token": id_token,
        "scope": "openid profile email",
        "refresh_token": AuthRBAC.generate_refresh_token(
            user_id=user.user_id,
            username=user.username,
            tenant_id=user.tenant_id,
            roles=user.roles,
            session_id=session_id,
            device_id=data.get("device_id"),
            user_agent=request.headers.get("User-Agent"),
            ip_address=request.remote_addr,
        ),
    }, 200)


@_idempotent_route("/auth/users", methods=["GET"])
@require_auth("manage:users")
def list_users():
    """List persisted users for the current tenant."""
    session = SessionLocal()
    try:
        users = session.query(UserAccount).filter(UserAccount.tenant_id == get_current_user().tenant_id).all()
        return _api_success({
            "users": [{
                "user_id": row.id,
                "username": row.username,
                "tenant_id": row.tenant_id,
                "email": row.email,
                "roles": row.roles,
                "mfa_enabled": row.mfa_enabled,
                "status": row.status,
            } for row in users]}, 200)
    finally:
        session.close()


def _iam_tenant_id() -> str:
    current_user = get_current_user()
    if current_user is None or not current_user.tenant_id:
        raise AuthenticationUnavailable("Tenant identity is unavailable")
    return str(current_user.tenant_id)


def _iam_secret_hash(secret: str) -> str:
    return hmac.new(os.getenv("JWT_SECRET_KEY", "").encode("utf-8"), secret.encode("utf-8"), hashlib.sha256).hexdigest()


def _audit_iam_mutation(session, tenant_id: str, action: str, resource_type: str, resource_id: str, details=None) -> None:
    current_user = get_current_user()
    session.add(ActionAuditEntry(
        tenant_id=tenant_id,
        actor=current_user.user_id if current_user is not None else "system",
        category="security",
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
    ))


@_idempotent_route("/auth/client-token", methods=["POST"])
@rate_limit(max_requests_per_minute=10, tokens_per_request=1, endpoint_name="auth_client_token", fail_closed=True)
def issue_machine_access_token():
    """Exchange an issued service or confidential API-client secret for a short-lived token."""
    data = request.get_json(silent=True) or {}
    tenant_id = str(data.get("tenant_id") or "").strip()
    client_id = str(data.get("client_id") or "").strip()
    client_secret = data.get("client_secret")
    if not tenant_id or not client_id or not isinstance(client_secret, str) or not client_secret:
        return _api_error("invalid_client", "Client authentication failed.", 401)

    session = SessionLocal()
    try:
        service = None
        client = session.query(ApiClientIdentity).filter_by(
            tenant_id=tenant_id,
            client_identifier=client_id,
            status="active",
        ).first()
        if client is not None:
            attributes = dict(client.attributes or {})
            valid_secret = hmac.compare_digest(
                str(attributes.get("client_secret_hash") or ""),
                _iam_secret_hash(client_secret),
            )
            if not valid_secret or client.client_type == "public":
                client = None
            else:
                scopes = list(client.scopes or [])
                version = int(attributes.get("authorization_version", 1))
                if client.service_identity_id:
                    service = session.query(ServiceIdentity).filter_by(
                        id=client.service_identity_id,
                        tenant_id=tenant_id,
                        status="active",
                    ).first()
                    if service is None:
                        client = None
                    else:
                        scopes = sorted(set(scopes).intersection(service.scopes or []))
        else:
            service = session.query(ServiceIdentity).filter_by(
                id=client_id,
                tenant_id=tenant_id,
                status="active",
            ).first()
            attributes = dict(service.attributes or {}) if service is not None else {}
            valid_secret = service is not None and hmac.compare_digest(
                str(attributes.get("credential_hash") or ""),
                _iam_secret_hash(client_secret),
            )
            if not valid_secret:
                service = None
                scopes = []
                version = 0
            else:
                scopes = list(service.scopes or [])
                version = int(service.authorization_version)

        principal_type = "api_client" if client is not None else "service"
        principal = client or service
        if principal is None:
            _authentication_audit(tenant_id, "machine.login.failed", "failure", identifier=client_id, reason="invalid_client")
            return _api_error("invalid_client", "Client authentication failed.", 401)

        try:
            granted_scopes = AuthRBAC.normalize_machine_scopes(scopes)
            requested = data.get("scopes")
            if requested is None and data.get("scope") is not None:
                requested = data["scope"].split() if isinstance(data["scope"], str) else data["scope"]
            requested_scopes = granted_scopes if requested is None else AuthRBAC.normalize_machine_scopes(requested)
        except (TypeError, ValueError):
            return _api_error("invalid_scope", "Requested scopes are invalid.", 400)
        if not set(requested_scopes).issubset(granted_scopes):
            return _api_error("invalid_scope", "Requested scopes exceed the client grant.", 400)

        access_token = AuthRBAC.generate_machine_access_token(
            principal_id=principal.id,
            principal_type=principal_type,
            tenant_id=tenant_id,
            authorization_version=version,
            scopes=requested_scopes,
        )
        _authentication_audit(
            tenant_id,
            "machine.login.succeeded",
            "success",
            user_id=principal.id,
            identifier=client_id,
            reason=principal_type,
        )
        return _api_success({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": AuthRBAC.ACCESS_TOKEN_TTL_MINUTES * 60,
            "scope": requested_scopes,
        }, 200)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/identity", methods=["GET"])
@require_auth()
def iam_current_identity():
    """Return the canonical platform, tenant, user, and granted identity context."""
    current_user = get_current_user()
    session = SessionLocal()
    try:
        tenant = session.query(TenantRecord).filter_by(tenant_id=current_user.tenant_id).first()
        return _api_success({
            "platform": {"id": tenant.platform_id, "status": "active"} if tenant else None,
            "tenant": {
                "id": tenant.tenant_id,
                "name": tenant.name,
                "slug": tenant.slug,
                "status": tenant.status,
                "residency_region": tenant.residency_region,
            } if tenant else {"id": current_user.tenant_id, "status": "legacy"},
            "subject": {
                "type": "user",
                "id": current_user.user_id,
                "username": current_user.username,
                "roles": current_user.roles,
                "permissions": current_user.permissions,
            },
        }, 200)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/password-policy", methods=["GET", "PUT"])
@require_auth("manage:settings")
@require_privileged_operation_mfa
def iam_password_policy():
    """Read or configure a tenant-scoped password expiration policy."""
    current_user = get_current_user()
    tenant_id = _iam_tenant_id()
    data = request.get_json(silent=True) or {}
    scope_type = str(data.get("scope_type") or "tenant").strip()
    scope_id = str(data.get("scope_id") or tenant_id).strip()
    if scope_type not in {"tenant", "organization", "platform"}:
        return _api_error("invalid_scope", "scope_type must be tenant, organization, or platform.", 400)
    if scope_type == "tenant":
        scope_id = tenant_id
    elif scope_type == "platform":
        if "manage:all_tenants" not in current_user.permissions:
            return _api_error("permission_denied", "Platform policy requires platform-level authority.", 403)
    else:
        with SessionLocal() as check_session:
            if check_session.query(Organization).filter_by(id=scope_id, tenant_id=tenant_id).first() is None:
                return _api_error("resource_not_found", "Organization not found for this tenant.", 404)

    session = SessionLocal()
    try:
        policy = session.query(PasswordPolicy).filter_by(scope_type=scope_type, scope_id=scope_id).first()
        if request.method == "GET":
            if policy is None:
                return _api_success(_password_policy_for_account(
                    session.query(UserAccount).filter_by(id=current_user.user_id, tenant_id=tenant_id).first() or UserAccount(id=current_user.user_id, tenant_id=tenant_id, roles=current_user.roles, attributes={}),
                ), 200)
            return _api_success({
                "scope_type": policy.scope_type,
                "scope_id": policy.scope_id,
                "enabled": policy.enabled,
                "max_age_days": policy.max_age_days,
                "privileged_max_age_days": policy.privileged_max_age_days,
                "notify_before_days": policy.notify_before_days,
                "force_change": policy.force_change,
                "emergency_rotation_at": policy.emergency_rotation_at.isoformat() if policy.emergency_rotation_at else None,
            }, 200)

        def _int_value(name: str, default: Optional[int] = None) -> Optional[int]:
            value = data.get(name, default)
            if value is None:
                return None
            try:
                parsed = int(value)
            except (TypeError, ValueError):
                raise ValueError(name)
            if not 0 <= parsed <= 3650:
                raise ValueError(name)
            return parsed

        try:
            max_age_days = _int_value("max_age_days")
            privileged_max_age_days = _int_value("privileged_max_age_days")
            notify_before_days = _int_value("notify_before_days", 14)
        except ValueError as exc:
            return _api_error("invalid_policy", f"Invalid password policy field: {exc.args[0]}.", 400)
        if max_age_days is not None and notify_before_days is not None and notify_before_days > max_age_days:
            return _api_error("invalid_policy", "notify_before_days cannot exceed max_age_days.", 400)
        if policy is None:
            policy = PasswordPolicy(policy_id=f"pwdpol_{uuid.uuid4().hex[:16]}", scope_type=scope_type, scope_id=scope_id, tenant_id=None if scope_type == "platform" else tenant_id)
            session.add(policy)
        policy.enabled = bool(data.get("enabled", policy.enabled if policy.enabled is not None else True))
        policy.max_age_days = max_age_days
        policy.privileged_max_age_days = privileged_max_age_days
        policy.notify_before_days = notify_before_days if notify_before_days is not None else 14
        policy.force_change = bool(data.get("force_change", policy.force_change if policy.force_change is not None else True))
        policy.updated_at = _now_utc()
        session.commit()
        return _api_success({"scope_type": policy.scope_type, "scope_id": policy.scope_id, "enabled": policy.enabled, "max_age_days": policy.max_age_days, "privileged_max_age_days": policy.privileged_max_age_days, "notify_before_days": policy.notify_before_days, "force_change": policy.force_change}, 200)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/platforms", methods=["POST"])
@require_auth("manage:all_tenants")
@require_privileged_operation_mfa
def create_iam_platform():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()
    slug = str(data.get("slug") or name).strip().lower()
    if not name or not slug:
        return _api_error("invalid_request", "name and slug are required.", 400)
    session = SessionLocal()
    try:
        if session.query(PlatformIdentity).filter_by(slug=slug).first() is not None:
            return _api_error("already_exists", "Platform slug already exists.", 409)
        record = PlatformIdentity(id=f"platform_{uuid.uuid4().hex[:12]}", name=name, slug=slug, attributes=data.get("attributes") or {})
        session.add(record)
        session.commit()
        return _api_success({"id": record.id, "name": record.name, "slug": record.slug, "status": record.status}, 201)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/tenants", methods=["POST"])
@require_auth("manage:all_tenants")
@require_privileged_operation_mfa
def create_iam_tenant():
    data = request.get_json(silent=True) or {}
    platform_id = str(data.get("platform_id") or "").strip()
    name = str(data.get("name") or "").strip()
    slug = str(data.get("slug") or name).strip().lower()
    tenant_id = str(data.get("tenant_id") or f"tenant_{uuid.uuid4().hex[:12]}").strip()
    if not platform_id or not name or not slug:
        return _api_error("invalid_request", "platform_id, name, and slug are required.", 400)
    session = SessionLocal()
    try:
        if session.get(PlatformIdentity, platform_id) is None:
            return _api_error("resource_not_found", "Platform not found.", 404)
        if session.get(TenantRecord, tenant_id) is not None:
            return _api_error("already_exists", "Tenant already exists.", 409)
        record = TenantRecord(
            tenant_id=tenant_id,
            platform_id=platform_id,
            name=name,
            slug=slug,
            owner_user_id=data.get("owner_user_id"),
            residency_region=data.get("residency_region") or "ke-central",
            status="active",
            attributes=data.get("attributes") or {},
        )
        session.add(record)
        _audit_iam_mutation(
            session, tenant_id, "iam_tenant.created", "tenant", record.tenant_id,
            {"platform_id": platform_id},
        )
        session.commit()
        return _api_success({"tenant_id": record.tenant_id, "platform_id": record.platform_id, "name": record.name, "status": record.status}, 201)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/service-identities", methods=["GET", "POST"])
@require_auth("manage:users")
@require_privileged_operation_mfa
def iam_service_identities():
    tenant_id = _iam_tenant_id()
    session = SessionLocal()
    try:
        if request.method == "GET":
            records = session.query(ServiceIdentity).filter_by(tenant_id=tenant_id).all()
            return _api_success({"items": [{"id": row.id, "name": row.name, "identity_type": row.identity_type, "owner_user_id": row.owner_user_id, "status": row.status, "scopes": row.scopes} for row in records]}, 200)
        data = request.get_json(silent=True) or {}
        name = str(data.get("name") or "").strip()
        if not name:
            return _api_error("invalid_request", "name is required.", 400)
        try:
            scopes = AuthRBAC.normalize_machine_scopes(data.get("scopes") or [])
        except (TypeError, ValueError):
            return _api_error("invalid_scope", "scopes must be valid resource:action permissions.", 400)
        if session.query(ServiceIdentity).filter_by(tenant_id=tenant_id, name=name).first() is not None:
            return _api_error("already_exists", "Service identity name already exists.", 409)
        identity_type = data.get("identity_type") or "service"
        if identity_type not in {"service", "workload", "machine"}:
            return _api_error("invalid_identity_type", "Unsupported service identity type.", 400)
        secret = f"svc_{secrets.token_urlsafe(32)}"
        record = ServiceIdentity(
            id=f"svc_{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            name=name,
            identity_type=identity_type,
            owner_user_id=data.get("owner_user_id") or get_current_user().user_id,
            scopes=scopes,
            attributes={"credential_hash": _iam_secret_hash(secret), "credential_prefix": secret[:12]},
        )
        session.add(record)
        _audit_iam_mutation(
            session, tenant_id, "service_identity.issued", "service_identity", record.id,
            {"identity_type": record.identity_type, "scopes": scopes},
        )
        session.commit()
        return _api_success({"id": record.id, "name": record.name, "identity_type": record.identity_type, "status": record.status, "scopes": record.scopes, "client_secret": secret}, 201)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/service-identities/<identity_id>", methods=["PATCH"])
@require_auth()
@require_resource_access("manage:users", "identity_id")
@require_privileged_operation_mfa
def update_iam_service_identity(identity_id: str):
    session = SessionLocal()
    try:
        record = session.query(ServiceIdentity).filter_by(id=identity_id, tenant_id=_iam_tenant_id()).first()
        if record is None:
            return _api_error("resource_not_found", "Service identity not found.", 404)
        status = (request.get_json(silent=True) or {}).get("status")
        if status not in {"active", "suspended", "revoked", "decommissioned"}:
            return _api_error("invalid_status", "Unsupported service identity status.", 400)
        record.status = status
        record.authorization_version += 1
        _audit_iam_mutation(
            session, record.tenant_id, "service_identity.status_changed", "service_identity", record.id,
            {"status": status},
        )
        session.commit()
        return _api_success({"id": record.id, "status": record.status}, 200)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/service-identities/<identity_id>/rotate-secret", methods=["POST"])
@require_auth()
@require_resource_access("manage:users", "identity_id")
@require_privileged_operation_mfa
def rotate_iam_service_identity_secret(identity_id: str):
    session = SessionLocal()
    try:
        record = session.query(ServiceIdentity).filter_by(
            id=identity_id, tenant_id=_iam_tenant_id(), status="active"
        ).first()
        if record is None:
            return _api_error("resource_not_found", "Active service identity not found.", 404)
        secret = f"svc_{secrets.token_urlsafe(32)}"
        attributes = dict(record.attributes or {})
        attributes.update({
            "credential_hash": _iam_secret_hash(secret),
            "credential_prefix": secret[:12],
        })
        record.attributes = attributes
        record.authorization_version += 1
        _audit_iam_mutation(
            session, record.tenant_id, "service_identity.secret_rotated", "service_identity", record.id,
        )
        session.commit()
        return _api_success({"id": record.id, "client_secret": secret}, 200)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/api-clients", methods=["GET", "POST"])
@require_auth("manage:api_keys")
@require_privileged_operation_mfa
def iam_api_clients():
    tenant_id = _iam_tenant_id()
    session = SessionLocal()
    try:
        if request.method == "GET":
            records = session.query(ApiClientIdentity).filter_by(tenant_id=tenant_id).all()
            return _api_success({"items": [{"id": row.id, "client_identifier": row.client_identifier, "name": row.name, "client_type": row.client_type, "status": row.status, "scopes": row.scopes} for row in records]}, 200)
        data = request.get_json(silent=True) or {}
        name = str(data.get("name") or "").strip()
        client_identifier = str(data.get("client_identifier") or f"client_{secrets.token_urlsafe(12)}").strip()
        if not name:
            return _api_error("invalid_request", "name is required.", 400)
        if session.query(ApiClientIdentity).filter_by(tenant_id=tenant_id, client_identifier=client_identifier).first() is not None:
            return _api_error("already_exists", "API client identifier already exists.", 409)
        client_type = data.get("client_type") or "confidential"
        if client_type not in {"confidential", "service"}:
            return _api_error("invalid_client_type", "Only confidential and service clients may use client-secret authentication.", 400)
        service_identity_id = data.get("service_identity_id")
        if service_identity_id is not None and session.query(ServiceIdentity).filter_by(id=service_identity_id, tenant_id=tenant_id, status="active").first() is None:
            return _api_error("resource_not_found", "Service identity not found for this tenant.", 404)
        service = session.query(ServiceIdentity).filter_by(
            id=service_identity_id, tenant_id=tenant_id, status="active"
        ).first() if service_identity_id is not None else None
        try:
            scopes = AuthRBAC.normalize_machine_scopes(data.get("scopes") or [])
        except (TypeError, ValueError):
            return _api_error("invalid_scope", "scopes must be valid resource:action permissions.", 400)
        if service is not None and not set(scopes).issubset(AuthRBAC.normalize_machine_scopes(service.scopes or [])):
            return _api_error("invalid_scope", "API-client scopes exceed the linked service identity grant.", 400)
        secret = f"cli_{secrets.token_urlsafe(32)}"
        record = ApiClientIdentity(
            id=f"client_{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            client_identifier=client_identifier,
            name=name,
            client_type=client_type,
            service_identity_id=service_identity_id,
            owner_user_id=get_current_user().user_id,
            scopes=scopes,
            redirect_uris=data.get("redirect_uris") or [],
            attributes={"client_secret_hash": _iam_secret_hash(secret), "client_secret_prefix": secret[:12], "authorization_version": 1},
        )
        session.add(record)
        _audit_iam_mutation(
            session, tenant_id, "api_client.issued", "api_client", record.id,
            {"client_type": record.client_type, "scopes": scopes},
        )
        session.commit()
        return _api_success({"id": record.id, "client_identifier": record.client_identifier, "name": record.name, "client_type": record.client_type, "status": record.status, "client_secret": secret}, 201)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/api-clients/<client_id>", methods=["PATCH"])
@require_auth()
@require_resource_access("manage:api_keys", "client_id")
@require_privileged_operation_mfa
def update_iam_api_client(client_id: str):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in {"active", "suspended", "revoked", "expired"}:
        return _api_error("invalid_status", "Unsupported API-client status.", 400)
    session = SessionLocal()
    try:
        record = session.query(ApiClientIdentity).filter_by(
            id=client_id, tenant_id=_iam_tenant_id()
        ).first()
        if record is None:
            return _api_error("resource_not_found", "API client not found.", 404)
        attributes = dict(record.attributes or {})
        attributes["authorization_version"] = int(attributes.get("authorization_version", 1)) + 1
        record.attributes = attributes
        record.status = status
        _audit_iam_mutation(
            session, record.tenant_id, "api_client.status_changed", "api_client", record.id,
            {"status": status},
        )
        session.commit()
        return _api_success({"id": record.id, "status": record.status}, 200)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/api-clients/<client_id>/rotate-secret", methods=["POST"])
@require_auth()
@require_resource_access("manage:api_keys", "client_id")
@require_privileged_operation_mfa
def rotate_iam_api_client_secret(client_id: str):
    session = SessionLocal()
    try:
        record = session.query(ApiClientIdentity).filter_by(
            id=client_id, tenant_id=_iam_tenant_id(), status="active"
        ).first()
        if record is None:
            return _api_error("resource_not_found", "Active API client not found.", 404)
        secret = f"cli_{secrets.token_urlsafe(32)}"
        attributes = dict(record.attributes or {})
        attributes.update({
            "client_secret_hash": _iam_secret_hash(secret),
            "client_secret_prefix": secret[:12],
            "authorization_version": int(attributes.get("authorization_version", 1)) + 1,
        })
        record.attributes = attributes
        _audit_iam_mutation(
            session, record.tenant_id, "api_client.secret_rotated", "api_client", record.id,
        )
        session.commit()
        return _api_success({"id": record.id, "client_identifier": record.client_identifier, "client_secret": secret}, 200)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/external-identities", methods=["GET", "POST"])
@require_auth("manage:users")
@require_privileged_operation_mfa
def iam_external_identities():
    tenant_id = _iam_tenant_id()
    session = SessionLocal()
    try:
        if request.method == "GET":
            records = session.query(ExternalIdentity).filter_by(tenant_id=tenant_id).all()
            return _api_success({"items": [{"id": row.id, "user_id": row.user_id, "provider_id": row.provider_id, "issuer": row.issuer, "subject": row.subject, "status": row.status, "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None} for row in records]}, 200)
        data = request.get_json(silent=True) or {}
        user_id = str(data.get("user_id") or "").strip()
        issuer = str(data.get("issuer") or "").strip()
        subject = str(data.get("subject") or "").strip()
        if not user_id or not issuer or not subject:
            return _api_error("invalid_request", "user_id, issuer, and subject are required.", 400)
        if session.query(UserAccount).filter_by(id=user_id, tenant_id=tenant_id).first() is None:
            return _api_error("resource_not_found", "User does not belong to this tenant.", 404)
        if session.query(ExternalIdentity).filter_by(tenant_id=tenant_id, issuer=issuer, subject=subject).first() is not None:
            return _api_error("already_exists", "External identity is already linked.", 409)
        record = ExternalIdentity(
            id=f"ext_{uuid.uuid4().hex[:12]}", tenant_id=tenant_id, user_id=user_id,
            provider_id=data.get("provider_id"), issuer=issuer, subject=subject,
            email=data.get("email"), claims=data.get("claims") or {},
        )
        session.add(record)
        session.commit()
        return _api_success({"id": record.id, "user_id": record.user_id, "issuer": record.issuer, "subject": record.subject, "status": record.status}, 201)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/roles", methods=["POST"])
@require_auth("manage:users")
@require_privileged_operation_mfa
def create_iam_role():
    tenant_id = _iam_tenant_id()
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()
    if not name:
        return _api_error("invalid_request", "name is required.", 400)
    session = SessionLocal()
    try:
        if session.query(IAMRole).filter_by(tenant_id=tenant_id, name=name).first() is not None:
            return _api_error("already_exists", "Role already exists.", 409)
        role = IAMRole(id=f"role_{uuid.uuid4().hex[:12]}", tenant_id=tenant_id, name=name, description=data.get("description"), managed=False)
        session.add(role)
        permissions = data.get("permissions") or []
        for permission_name in permissions:
            permission_name = str(permission_name).strip()
            if not permission_name or ":" not in permission_name:
                return _api_error("invalid_permission", "Permissions must use resource:action form.", 400)
            resource, action = permission_name.split(":", 1)
            permission = session.query(IAMPermission).filter_by(name=permission_name).first()
            if permission is None:
                permission = IAMPermission(id=f"perm_{uuid.uuid4().hex[:12]}", name=permission_name, resource=resource, action=action)
                session.add(permission)
                session.flush()
            session.add(IAMRolePermission(id=f"roleperm_{uuid.uuid4().hex[:12]}", role_id=role.id, permission_id=permission.id))
        _audit_iam_mutation(
            session, tenant_id, "iam_role.created", "iam_role", role.id,
            {"permissions": permissions},
        )
        session.commit()
        return _api_success({"id": role.id, "tenant_id": role.tenant_id, "name": role.name, "permissions": permissions}, 201)
    finally:
        session.close()


@_idempotent_route("/api/v1/iam/role-bindings", methods=["POST"])
@require_auth("manage:users")
@require_privileged_operation_mfa
def create_iam_role_binding():
    tenant_id = _iam_tenant_id()
    data = request.get_json(silent=True) or {}
    subject_type = str(data.get("subject_type") or "").strip()
    subject_id = str(data.get("subject_id") or "").strip()
    role_id = str(data.get("role_id") or "").strip()
    scope_type = str(data.get("scope_type") or "tenant").strip()
    scope_id = str(data.get("scope_id") or tenant_id).strip()
    if subject_type not in {"user", "service", "api_client"} or not subject_id or not role_id:
        return _api_error("invalid_request", "subject_type, subject_id, and role_id are required.", 400)
    if scope_type not in {"tenant", "organization", "team", "resource"} or not scope_id:
        return _api_error("invalid_scope", "scope_type and scope_id are invalid.", 400)
    if scope_type == "tenant" and scope_id != tenant_id:
        return _api_error("invalid_scope", "Tenant role bindings must use the current tenant scope.", 400)
    session = SessionLocal()
    try:
        role = session.query(IAMRole).filter_by(id=role_id, tenant_id=tenant_id, status="active").first()
        if role is None:
            return _api_error("resource_not_found", "Role not found for this tenant.", 404)
        if scope_type == "organization" and session.query(Organization).filter_by(
            id=scope_id, tenant_id=tenant_id
        ).first() is None:
            return _api_error("resource_not_found", "Organization scope not found for this tenant.", 404)
        if scope_type == "team" and session.query(Team).filter_by(
            id=scope_id, tenant_id=tenant_id
        ).first() is None:
            return _api_error("resource_not_found", "Team scope not found for this tenant.", 404)
        subject_models = {"user": UserAccount, "service": ServiceIdentity, "api_client": ApiClientIdentity}
        subject = session.query(subject_models[subject_type]).filter_by(id=subject_id, tenant_id=tenant_id).first()
        if subject is None:
            return _api_error("resource_not_found", "Subject not found for this tenant.", 404)
        binding = IAMRoleBinding(id=f"binding_{uuid.uuid4().hex[:12]}", tenant_id=tenant_id, subject_type=subject_type, subject_id=subject_id, role_id=role_id, scope_type=scope_type, scope_id=scope_id, granted_by=get_current_user().user_id)
        session.add(binding)
        _audit_iam_mutation(
            session, tenant_id, "iam_role_binding.created", "iam_role_binding", binding.id,
            {"subject_type": subject_type, "subject_id": subject_id, "role_id": role_id, "scope_type": scope_type, "scope_id": scope_id},
        )
        session.commit()
        return _api_success({"id": binding.id, "tenant_id": binding.tenant_id, "subject_type": binding.subject_type, "subject_id": binding.subject_id, "role_id": binding.role_id, "scope_type": binding.scope_type, "scope_id": binding.scope_id, "status": binding.status}, 201)
    finally:
        session.close()


@_idempotent_route("/auth/api-keys", methods=["POST"])
@require_auth("manage:api_keys")
@require_privileged_operation_mfa
def issue_api_key_route():
    """Issue a tenant-scoped API key."""
    data = request.json or {}
    tenant_id = data.get("tenant_id") or get_current_user().tenant_id
    if tenant_id != get_current_user().tenant_id:
        return _api_success({"error": "tenant_access_denied"}, 403)
    role = AuthRBAC.normalize_role_name(data.get("role") or "read_only")
    if role is None:
        return _api_success({"error": "invalid_role"}, 400)
    key_value = f"pk_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(key_value.encode("utf-8")).hexdigest()
    scopes = data.get("scopes")
    if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
        return _api_success({"error": "invalid_scopes"}, 400)
    try:
        scopes = AuthRBAC.normalize_machine_scopes(scopes)
    except (TypeError, ValueError):
        return _api_success({"error": "invalid_scopes"}, 400)
    expires_at = None
    if data.get("expires_in_days") is not None:
        try:
            expires_in_days = int(data["expires_in_days"])
        except (TypeError, ValueError):
            return _api_success({"error": "invalid_expiry"}, 400)
        if not 1 <= expires_in_days <= 3650:
            return _api_success({"error": "invalid_expiry"}, 400)
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
    session = SessionLocal()
    try:
        record = ApiKeyRecord(
            id=f"key_{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            key_hash=key_hash,
            key_prefix=key_value[:16],
            role=role,
            scopes=scopes,
            expires_at=expires_at,
            api_metadata=data.get("metadata") or {},
            active=True,
        )
        session.add(record)
        session.add(ActionAuditEntry(
            tenant_id=tenant_id,
            actor=get_current_user().user_id,
            action="api_key.issued",
            category="authentication",
            resource_type="api_key",
            resource_id=record.id,
            details={"scopes": scopes, "expires_at": expires_at.isoformat() if expires_at else None},
        ))
        session.commit()
        return _api_success({"api_key": key_value, "tenant_id": tenant_id, "role": record.role, "scopes": scopes, "expires_at": expires_at.isoformat() if expires_at else None}, 201)
    finally:
        session.close()


@_idempotent_route("/auth/api-keys/<key_id>/revoke", methods=["POST"])
@require_auth()
@require_resource_access("manage:api_keys", "key_id")
@require_privileged_operation_mfa
def revoke_api_key_route(key_id: str):
    """Revoke a tenant-scoped machine credential."""
    session = SessionLocal()
    try:
        record = session.query(ApiKeyRecord).filter(
            ApiKeyRecord.id == key_id,
            ApiKeyRecord.tenant_id == get_current_user().tenant_id,
        ).first()
        if record is None:
            return _api_success({"error": "not_found"}, 404)
        record.active = False
        record.revoked_at = datetime.now(timezone.utc)
        session.add(ActionAuditEntry(
            tenant_id=record.tenant_id,
            actor=get_current_user().user_id,
            action="api_key.revoked",
            category="authentication",
            resource_type="api_key",
            resource_id=record.id,
            details={},
        ))
        session.commit()
        return _api_success({"id": record.id, "status": "revoked"}, 200)
    finally:
        session.close()


@_idempotent_route("/auth/api-keys/<key_id>/rotate", methods=["POST"])
@require_auth()
@require_resource_access("manage:api_keys", "key_id")
@require_privileged_operation_mfa
def rotate_api_key_route(key_id: str):
    """Revoke an existing key and issue a replacement in one transaction."""
    session = SessionLocal()
    try:
        current_user = get_current_user()
        old_record = session.query(ApiKeyRecord).filter(
            ApiKeyRecord.id == key_id,
            ApiKeyRecord.tenant_id == current_user.tenant_id,
            ApiKeyRecord.active.is_(True),
        ).first()
        if old_record is None:
            return _api_success({"error": "not_found"}, 404)
        replacement_value = f"pk_{secrets.token_urlsafe(32)}"
        replacement = ApiKeyRecord(
            id=f"key_{uuid.uuid4().hex[:12]}",
            tenant_id=old_record.tenant_id,
            key_hash=hashlib.sha256(replacement_value.encode("utf-8")).hexdigest(),
            key_prefix=replacement_value[:16],
            role=old_record.role,
            scopes=old_record.scopes or [],
            expires_at=old_record.expires_at,
            api_metadata=old_record.api_metadata or {},
            rotated_from_id=old_record.id,
            active=True,
        )
        old_record.active = False
        old_record.revoked_at = datetime.now(timezone.utc)
        session.add(replacement)
        session.add(ActionAuditEntry(
            tenant_id=old_record.tenant_id,
            actor=current_user.user_id,
            action="api_key.rotated",
            category="authentication",
            resource_type="api_key",
            resource_id=replacement.id,
            details={"rotated_from_id": old_record.id},
        ))
        session.commit()
        return _api_success({
            "api_key": replacement_value,
            "id": replacement.id,
            "rotated_from_id": old_record.id,
            "expires_at": replacement.expires_at.isoformat() if replacement.expires_at else None,
        }, 201)
    finally:
        session.close()


def _store_mfa_recovery_codes(session, tenant_id: str, user_id: str, hashes: List[str]) -> None:
    now = _now_utc()
    session.query(MFARecovery).filter_by(
        tenant_id=tenant_id,
        user_id=user_id,
        used_at=None,
    ).update({MFARecovery.used_at: now}, synchronize_session=False)
    for code_hash in hashes:
        session.add(MFARecovery(
            id=f"mfa_recovery_{uuid.uuid4().hex}",
            tenant_id=tenant_id,
            user_id=user_id,
            code_hash=code_hash,
            created_at=now,
        ))


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _webauthn_settings() -> tuple[str, str, str]:
    """Resolve a single explicit WebAuthn origin and a compatible RP ID."""
    production = _is_production_environment()
    origin = os.getenv("PESAGUARD_WEBAUTHN_ORIGIN", "").strip().rstrip("/")
    if not origin and not production:
        origin = request.host_url.rstrip("/")
    if not origin:
        raise ValueError("PESAGUARD_WEBAUTHN_ORIGIN must be configured in production")
    parsed_origin = urlparse(origin)
    if parsed_origin.scheme not in {"https", "http"} or not parsed_origin.hostname or parsed_origin.path:
        raise ValueError("WebAuthn origin must be an absolute origin without a path")
    if production and parsed_origin.scheme != "https":
        raise ValueError("WebAuthn origin must use HTTPS in production")
    rp_id = os.getenv("PESAGUARD_WEBAUTHN_RP_ID", "").strip().lower() or parsed_origin.hostname.lower()
    if parsed_origin.hostname.lower() != rp_id and not parsed_origin.hostname.lower().endswith(f".{rp_id}"):
        raise ValueError("WebAuthn RP ID must be the origin host or one of its parent domains")
    rp_name = os.getenv("PESAGUARD_WEBAUTHN_RP_NAME", "PesaGuard").strip()[:64] or "PesaGuard"
    return rp_id, rp_name, origin


def _mfa_factor_view(factor: MFAFactor) -> Dict[str, Any]:
    return {
        "factor_id": factor.id,
        "factor_type": factor.factor_type,
        "factor_kind": factor.factor_kind,
        "display_name": factor.display_name,
        "status": factor.status,
        "created_at": factor.created_at.isoformat() if factor.created_at else None,
        "confirmed_at": factor.confirmed_at.isoformat() if factor.confirmed_at else None,
        "last_used_at": factor.last_used_at.isoformat() if factor.last_used_at else None,
        "revoked_at": factor.revoked_at.isoformat() if factor.revoked_at else None,
    }


def _add_mfa_challenge(
    session,
    *,
    tenant_id: str,
    user_id: str,
    challenge_type: str,
    challenge: bytes,
    challenge_data: Optional[Dict[str, Any]] = None,
    factor_id: Optional[str] = None,
    expires_in: int = 300,
) -> MFAChallenge:
    challenge_id = f"mfa_challenge_{uuid.uuid4().hex}"
    record = MFAChallenge(
        id=challenge_id,
        user_id=user_id,
        tenant_id=tenant_id,
        code_hash=hashlib.sha256(challenge).hexdigest(),
        challenge_type=challenge_type,
        factor_id=factor_id,
        challenge_data={
            "challenge": _b64url_encode(challenge),
            **(challenge_data or {}),
        },
        status="pending",
        created_at=_now_utc(),
        expires_at=_now_utc() + timedelta(seconds=expires_in),
        attempts=0,
    )
    session.add(record)
    return record


def _webauthn_credentials(factors: List[MFAFactor]) -> List[PublicKeyCredentialDescriptor]:
    credentials = []
    for factor in factors:
        if factor.credential_id:
            try:
                credentials.append(PublicKeyCredentialDescriptor(id=base64url_to_bytes(factor.credential_id)))
            except (TypeError, ValueError):
                logger.error("Stored WebAuthn credential ID is invalid for factor %s", factor.id)
    return credentials


def _start_webauthn_assertion(
    session,
    *,
    tenant_id: str,
    user_id: str,
    factors: List[MFAFactor],
    challenge_type: str,
    challenge_data: Dict[str, Any],
    policy: Dict[str, Any],
) -> tuple[MFAChallenge, Dict[str, Any]]:
    rp_id, _, _ = _webauthn_settings()
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=_webauthn_credentials(factors),
        user_verification=(
            UserVerificationRequirement.REQUIRED
            if policy["require_user_verification"]
            else UserVerificationRequirement.PREFERRED
        ),
        timeout=policy["challenge_ttl_seconds"] * 1000,
    )
    challenge = _add_mfa_challenge(
        session,
        tenant_id=tenant_id,
        user_id=user_id,
        challenge_type=challenge_type,
        challenge=options.challenge,
        challenge_data=challenge_data,
        expires_in=policy["challenge_ttl_seconds"],
    )
    _record_mfa_event(
        session,
        tenant_id,
        user_id,
        "challenge.webauthn.created",
        "pending",
        challenge_id=challenge.id,
        details={"purpose": challenge_type},
    )
    return challenge, json.loads(options_to_json(options))


def _record_webauthn_failure(
    session,
    challenge: MFAChallenge,
    policy: Dict[str, Any],
    *,
    factor: Optional[MFAFactor] = None,
    event_type: str = "challenge.webauthn.verification_failed",
) -> None:
    challenge.attempts = int(challenge.attempts or 0) + 1
    if challenge.attempts >= policy["attempt_limit"]:
        challenge.status = "failed"
    if factor is not None:
        factor.failed_attempts = int(factor.failed_attempts or 0) + 1
        if factor.failed_attempts >= policy["attempt_limit"]:
            factor.status = "locked"
            factor.locked_until = _now_utc() + timedelta(seconds=policy["lockout_seconds"])
    _record_mfa_event(
        session,
        challenge.tenant_id,
        challenge.user_id,
        event_type,
        "denied",
        factor_id=factor.id if factor else challenge.factor_id,
        challenge_id=challenge.id,
        details={"attempts": challenge.attempts},
    )


def _verify_webauthn_credential(response: Any, expected_challenge: str, *, registration: bool, factor: Optional[MFAFactor] = None):
    rp_id, _, origin = _webauthn_settings()
    challenge = base64url_to_bytes(expected_challenge)
    if registration:
        return verify_registration_response(
            credential=response,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
    if factor is None or not factor.credential_public_key:
        raise ValueError("WebAuthn credential is unavailable")
    return verify_authentication_response(
        credential=response,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=base64url_to_bytes(factor.credential_public_key),
        credential_current_sign_count=int(factor.sign_count or 0),
        require_user_verification=_mfa_policy_for_tenant(factor.tenant_id)["require_user_verification"],
    )


@_idempotent_route("/auth/mfa/webauthn/enroll/options", methods=["POST"])
@require_auth()
def begin_webauthn_enrollment_route():
    current_user = get_current_user()
    policy = _mfa_policy_for_tenant(current_user.tenant_id)
    if "webauthn" not in policy["allowed_factors"]:
        return _api_error("mfa_factor_not_allowed", "WebAuthn enrollment is disabled by tenant policy.", 403)
    session = SessionLocal()
    try:
        account = session.query(UserAccount).filter_by(
            id=current_user.user_id,
            tenant_id=current_user.tenant_id,
        ).first()
        if account is None:
            return _api_error("resource_not_found", "MFA user not found.", 404)
        factors = session.query(MFAFactor).filter_by(
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            factor_type="webauthn",
            status="active",
        ).all()
        try:
            rp_id, rp_name, _ = _webauthn_settings()
            options = generate_registration_options(
                rp_id=rp_id,
                rp_name=rp_name,
                user_id=hashlib.sha256(
                    f"{current_user.tenant_id}:{current_user.user_id}".encode("utf-8")
                ).digest(),
                user_name=str(account.email or account.username)[:255],
                user_display_name=str(account.username)[:255],
                exclude_credentials=_webauthn_credentials(factors),
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    require_resident_key=True,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
                timeout=policy["challenge_ttl_seconds"] * 1000,
            )
        except (ValueError, RuntimeError) as exc:
            logger.warning("WebAuthn enrollment configuration rejected: %s", exc)
            return _api_error("webauthn_unavailable", "WebAuthn is not configured for this origin.", 503)
        challenge = _add_mfa_challenge(
            session,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            challenge_type="webauthn_registration",
            challenge=options.challenge,
            expires_in=policy["challenge_ttl_seconds"],
        )
        _record_mfa_event(
            session,
            current_user.tenant_id,
            current_user.user_id,
            "challenge.webauthn.registration_started",
            "pending",
            challenge_id=challenge.id,
        )
        session.commit()
        return _api_success({
            "challenge_id": challenge.id,
            "options": json.loads(options_to_json(options)),
            "expires_in": policy["challenge_ttl_seconds"],
        }, 201)
    finally:
        session.close()


@_idempotent_route("/auth/mfa/webauthn/enroll/verify", methods=["POST"])
@require_auth()
def verify_webauthn_enrollment_route():
    current_user = get_current_user()
    payload = request.get_json(silent=True) or {}
    challenge_id = str(payload.get("challenge_id") or "")
    credential = payload.get("credential")
    if not challenge_id or not isinstance(credential, dict):
        return _api_error("invalid_request", "challenge_id and credential are required.", 400)
    policy = _mfa_policy_for_tenant(current_user.tenant_id)
    session = SessionLocal()
    try:
        challenge = session.query(MFAChallenge).filter_by(
            id=challenge_id,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            challenge_type="webauthn_registration",
        ).with_for_update().first()
        if challenge is None:
            return _api_error("resource_not_found", "WebAuthn registration challenge not found.", 404)
        if challenge.status != "pending" or _is_expired(challenge.expires_at) or challenge.attempts >= policy["attempt_limit"]:
            return _api_error("invalid_mfa_challenge", "The WebAuthn registration challenge is expired or exhausted.", 401)
        try:
            verification = _verify_webauthn_credential(
                credential,
                str((challenge.challenge_data or {}).get("challenge") or ""),
                registration=True,
            )
        except Exception as exc:
            logger.info("WebAuthn registration verification rejected (%s)", type(exc).__name__)
            _record_webauthn_failure(session, challenge, policy)
            session.commit()
            return _api_error("invalid_webauthn_credential", "The WebAuthn credential could not be verified.", 401)

        credential_id = _b64url_encode(verification.credential_id)
        if session.query(MFAFactor.id).filter_by(credential_id=credential_id).first():
            _record_webauthn_failure(
                session,
                challenge,
                policy,
                event_type="factor.webauthn.duplicate_registration",
            )
            session.commit()
            return _api_error("webauthn_credential_exists", "This security key is already registered.", 409)
        device_type = getattr(verification.credential_device_type, "value", str(verification.credential_device_type))
        factor_kind = "passkey" if device_type == "multi_device" else "security_key"
        existing_active = session.query(MFAFactor.id).filter_by(
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            status="active",
        ).first() is not None
        factor_id = f"mfa_factor_{uuid.uuid4().hex}"
        now = _now_utc()
        factor = MFAFactor(
            id=factor_id,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            factor_type="webauthn",
            factor_kind=factor_kind,
            display_name=str(payload.get("display_name") or ("Passkey" if factor_kind == "passkey" else "Security key")).strip()[:128] or "WebAuthn authenticator",
            credential_id=credential_id,
            credential_public_key=_b64url_encode(verification.credential_public_key),
            sign_count=int(verification.sign_count or 0),
            status="active",
            failed_attempts=0,
            metadata_json={
                "backup_eligible": bool(getattr(verification, "credential_backed_up", False)),
                "aaguid": str(getattr(verification, "aaguid", "")),
                "transports": [
                    value for value in (credential.get("response", {}).get("transports") or [])
                    if value in {"usb", "nfc", "ble", "internal", "hybrid", "smart-card"}
                ],
            },
            created_at=now,
            confirmed_at=now,
            last_used_at=now,
        )
        session.add(factor)
        account = session.query(UserAccount).filter_by(
            id=current_user.user_id,
            tenant_id=current_user.tenant_id,
        ).with_for_update().first()
        if account is None:
            return _api_error("resource_not_found", "MFA user not found.", 404)
        account.mfa_enabled = True
        account.authorization_version += 1
        challenge.status = "verified"
        if not existing_active and session.query(MFARecovery.id).filter_by(
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            used_at=None,
        ).first() is None:
            recovery_codes, recovery_hashes = _new_recovery_codes(policy["recovery_code_count"])
            _store_mfa_recovery_codes(session, current_user.tenant_id, current_user.user_id, recovery_hashes)
        else:
            recovery_codes = []
        _record_mfa_event(
            session,
            current_user.tenant_id,
            current_user.user_id,
            "factor.webauthn.enrolled",
            "success",
            factor_id=factor.id,
            challenge_id=challenge.id,
            details={"factor_kind": factor_kind},
        )
        session.commit()
        return _api_success({
            "status": "enabled",
            "factor": _mfa_factor_view(factor),
            "recovery_codes": recovery_codes,
            "recovery_codes_shown_once": bool(recovery_codes),
        }, 201)
    finally:
        session.close()


def _webauthn_assertion_factor(
    session,
    *,
    tenant_id: str,
    user_id: str,
    credential: Dict[str, Any],
) -> Optional[MFAFactor]:
    credential_id = credential.get("id")
    raw_id = credential.get("rawId")
    if (
        credential.get("type") != "public-key"
        or not isinstance(credential_id, str)
        or not isinstance(raw_id, str)
        or not hmac.compare_digest(credential_id, raw_id)
    ):
        return None
    return session.query(MFAFactor).filter_by(
        tenant_id=tenant_id,
        user_id=user_id,
        factor_type="webauthn",
        credential_id=credential_id,
        status="active",
    ).with_for_update().first()


def _verify_webauthn_assertion(
    session,
    challenge: MFAChallenge,
    credential: Dict[str, Any],
    policy: Dict[str, Any],
) -> tuple[Optional[MFAFactor], Optional[str]]:
    factor = _webauthn_assertion_factor(
        session,
        tenant_id=challenge.tenant_id,
        user_id=challenge.user_id,
        credential=credential,
    )
    if factor is None:
        return None, "unknown_credential"
    now = _now_utc()
    if factor.locked_until is not None:
        locked_until = factor.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > now:
            return factor, "factor_locked"
        factor.status = "active"
        factor.locked_until = None
        factor.failed_attempts = 0
    try:
        verification = _verify_webauthn_credential(
            credential,
            str((challenge.challenge_data or {}).get("challenge") or ""),
            registration=False,
            factor=factor,
        )
    except Exception as exc:
        logger.info("WebAuthn assertion verification rejected (%s)", type(exc).__name__)
        return factor, "invalid_assertion"
    new_sign_count = int(verification.new_sign_count or 0)
    current_sign_count = int(factor.sign_count or 0)
    if current_sign_count > 0 and new_sign_count <= current_sign_count:
        return factor, "signature_counter_replay"
    factor.sign_count = max(current_sign_count, new_sign_count)
    factor.failed_attempts = 0
    factor.locked_until = None
    factor.last_used_at = now
    return factor, None


@_idempotent_route("/auth/mfa/webauthn/login/verify", methods=["POST"])
@rate_limit(max_requests_per_minute=10, endpoint_name="mfa_webauthn_login_verify", fail_closed=True)
def verify_webauthn_login_route():
    payload = request.get_json(silent=True) or {}
    challenge_id = str(payload.get("challenge_id") or "")
    credential = payload.get("credential")
    if not challenge_id or not isinstance(credential, dict):
        return _api_error("invalid_request", "challenge_id and credential are required.", 400)
    session = SessionLocal()
    user_record = None
    try:
        challenge = session.query(MFAChallenge).filter_by(
            id=challenge_id,
            challenge_type="webauthn_login",
        ).with_for_update().first()
        if challenge is None:
            return _api_error("invalid_mfa_challenge", "The WebAuthn sign-in challenge is invalid.", 401)
        policy = _mfa_policy_for_tenant(challenge.tenant_id)
        if challenge.status != "pending" or _is_expired(challenge.expires_at) or challenge.attempts >= policy["attempt_limit"]:
            return _api_error("invalid_mfa_challenge", "The WebAuthn sign-in challenge is expired or exhausted.", 401)
        account = session.query(UserAccount).filter_by(
            id=challenge.user_id,
            tenant_id=challenge.tenant_id,
        ).with_for_update().first()
        challenge_data = dict(challenge.challenge_data or {})
        if (
            account is None
            or account.status != "active"
            or int(account.authorization_version or 0) != int(challenge_data.get("authorization_version", -1))
        ):
            challenge.status = "failed"
            _record_mfa_event(
                session,
                challenge.tenant_id,
                challenge.user_id,
                "challenge.webauthn.account_changed",
                "denied",
                challenge_id=challenge.id,
            )
            session.commit()
            return _api_error("invalid_mfa_challenge", "The account changed after this sign-in challenge was issued.", 401)
        factor, failure_reason = _verify_webauthn_assertion(session, challenge, credential, policy)
        if failure_reason:
            _record_webauthn_failure(session, challenge, policy, factor=factor)
            session.commit()
            return _api_error("invalid_webauthn_credential", "The WebAuthn assertion could not be verified.", 401)
        challenge.status = "verified"
        _record_mfa_event(
            session,
            challenge.tenant_id,
            challenge.user_id,
            "factor.webauthn.verified",
            "success",
            factor_id=factor.id if factor else None,
            challenge_id=challenge.id,
        )
        user_record = account
        device_id = str(challenge_data.get("device_id") or "")
        session.commit()
    finally:
        session.close()

    if user_record is None:
        return _api_error("invalid_mfa_challenge", "The WebAuthn sign-in challenge is invalid.", 401)
    location_info = _trusted_location_from_request()
    risk_result, revoked_device = _assess_login_risk(
        user_record,
        device_id,
        request.remote_addr,
        request.headers.get("User-Agent"),
        location_info,
    )
    if revoked_device or risk_result.get("action") in {"block", "review"}:
        _authentication_audit(
            user_record.tenant_id,
            "login.risk_blocked",
            "denied",
            user_id=user_record.id,
            reason="revoked_device" if revoked_device else f"risk_{risk_result.get('risk_level')}",
        )
        return _api_error("login_blocked_for_review", "This sign-in cannot be completed under current risk policy.", 403)

    _clear_login_failures(user_record)
    user_record.status = "active"
    with SessionLocal() as account_session:
        db_user = account_session.query(UserAccount).filter_by(
            id=user_record.id,
            tenant_id=user_record.tenant_id,
        ).with_for_update().first()
        if db_user is None or db_user.status != "active":
            return _api_error("invalid_mfa_challenge", "The account is no longer active.", 401)
        db_user.attributes = user_record.attributes
        db_user.status = "active"
        identity = _upsert_user_identity(
            account_session,
            db_user,
            email_verified=bool(user_record.attributes.get("email_verified", False)),
        )
        identity.last_login_at = _now_utc()
        identity.last_activity_at = identity.last_login_at
        account_session.commit()

    access_token, refresh_token, session_id = _issue_refresh_and_access_tokens(
        user_record,
        device_id=device_id,
        user_agent=request.headers.get("User-Agent"),
        ip_address=request.remote_addr,
    )
    _create_session_record(
        user_record,
        session_id,
        device_id,
        request.headers.get("User-Agent"),
        request.remote_addr,
        authentication_method="password+webauthn",
        mfa_verified=True,
        location_info=location_info,
        risk_result=risk_result,
    )
    _authentication_audit(
        user_record.tenant_id,
        "login.succeeded",
        "success",
        user_id=user_record.id,
        reason="password+webauthn_verified",
    )
    principal = _build_local_jwt_user(user_record)
    return jsonify({
        "token": access_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_id": session_id,
        "user": {
            "id": principal.user_id,
            "username": principal.username,
            "tenant_id": principal.tenant_id,
            "roles": principal.roles,
            "permissions": principal.permissions,
        },
        "user_id": principal.user_id,
        "username": principal.username,
        "tenant_id": principal.tenant_id,
        "roles": principal.roles,
        "permissions": principal.permissions,
        "expires_in": AuthRBAC.ACCESS_TOKEN_TTL_MINUTES * 60,
        "device_id": device_id,
        "risk": {
            "score": risk_result["risk_score"],
            "level": risk_result["risk_level"],
            "signals": risk_result["signals"],
        },
    }), 200


@_idempotent_route("/auth/mfa/webauthn/step-up/options", methods=["POST"])
@require_auth()
def begin_webauthn_step_up_route():
    current_user = get_current_user()
    policy = _mfa_policy_for_tenant(current_user.tenant_id)
    if "webauthn" not in policy["allowed_factors"]:
        return _api_error("mfa_factor_not_allowed", "WebAuthn step-up is disabled by tenant policy.", 403)
    session_id = getattr(current_user, "session_id", None)
    with SessionLocal() as session:
        auth_session = session.query(UserSession).filter_by(
            id=session_id,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            active=True,
            state="ACTIVE",
        ).first() if session_id else None
        if auth_session is None:
            return _api_error("step_up_required", "A valid authenticated session is required.", 401)
        factors = session.query(MFAFactor).filter_by(
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            factor_type="webauthn",
            status="active",
        ).all()
        if not factors:
            return _api_error("mfa_factor_unavailable", "No active WebAuthn factor is enrolled.", 400)
        try:
            challenge, options = _start_webauthn_assertion(
                session,
                tenant_id=current_user.tenant_id,
                user_id=current_user.user_id,
                factors=factors,
                challenge_type="webauthn_step_up",
                challenge_data={"session_id": session_id},
                policy=policy,
            )
        except (ValueError, RuntimeError) as exc:
            logger.warning("WebAuthn step-up configuration rejected: %s", exc)
            return _api_error("webauthn_unavailable", "WebAuthn is not configured for this origin.", 503)
        session.commit()
        return _api_success({
            "challenge_id": challenge.id,
            "options": options,
            "expires_in": policy["challenge_ttl_seconds"],
        }, 201)


@_idempotent_route("/auth/mfa/webauthn/step-up/verify", methods=["POST"])
@require_auth()
def verify_webauthn_step_up_route():
    current_user = get_current_user()
    session_id = getattr(current_user, "session_id", None)
    payload = request.get_json(silent=True) or {}
    challenge_id = str(payload.get("challenge_id") or "")
    credential = payload.get("credential")
    if not challenge_id or not isinstance(credential, dict):
        return _api_error("invalid_request", "challenge_id and credential are required.", 400)
    policy = _mfa_policy_for_tenant(current_user.tenant_id)
    session = SessionLocal()
    try:
        challenge = session.query(MFAChallenge).filter_by(
            id=challenge_id,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            challenge_type="webauthn_step_up",
        ).with_for_update().first()
        if (
            challenge is None
            or challenge.status != "pending"
            or _is_expired(challenge.expires_at)
            or challenge.attempts >= policy["attempt_limit"]
            or (challenge.challenge_data or {}).get("session_id") != session_id
        ):
            return _api_error("invalid_mfa_challenge", "The WebAuthn step-up challenge is invalid or expired.", 401)
        factor, failure_reason = _verify_webauthn_assertion(session, challenge, credential, policy)
        if failure_reason:
            _record_webauthn_failure(session, challenge, policy, factor=factor)
            session.commit()
            return _api_error("invalid_webauthn_credential", "The WebAuthn assertion could not be verified.", 401)
        challenge.status = "verified"
        _record_mfa_event(
            session,
            current_user.tenant_id,
            current_user.user_id,
            "step_up.webauthn.verified",
            "success",
            factor_id=factor.id if factor else None,
            challenge_id=challenge.id,
        )
        session.commit()
        return _api_success({
            "verified": True,
            "mfa_challenge_id": challenge.id,
            "expires_at": challenge.expires_at.isoformat(),
            "single_use": True,
        }, 200)
    finally:
        session.close()


@_idempotent_route("/auth/mfa/factors", methods=["GET"])
@require_auth()
def list_mfa_factors_route():
    current_user = get_current_user()
    with SessionLocal() as session:
        factors = session.query(MFAFactor).filter_by(
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
        ).order_by(MFAFactor.created_at.desc()).all()
        recovery_count = session.query(MFARecovery).filter_by(
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            used_at=None,
        ).count()
        policy = _mfa_policy_for_tenant(current_user.tenant_id)
        return _api_success({
            "mfa_enabled": bool(current_user.mfa_enabled),
            "factors": [_mfa_factor_view(factor) for factor in factors],
            "unused_recovery_codes": recovery_count,
            "policy": policy,
        }, 200)


@_idempotent_route("/auth/mfa/policy", methods=["GET"])
@require_auth()
def get_mfa_policy_route():
    current_user = get_current_user()
    return _api_success({"policy": _mfa_policy_for_tenant(current_user.tenant_id)}, 200)


@_idempotent_route("/auth/mfa/policy", methods=["PUT"])
@require_auth("manage:mfa")
@require_privileged_operation_mfa
def update_mfa_policy_route():
    current_user = get_current_user()
    payload = request.get_json(silent=True) or {}
    allowed_fields = set(_DEFAULT_MFA_POLICY)
    if not isinstance(payload, dict) or set(payload) - allowed_fields:
        return _api_error("invalid_mfa_policy", "The MFA policy contains unsupported fields.", 400)
    previous = _mfa_policy_for_tenant(current_user.tenant_id)
    candidate = {**previous, **payload}
    policy = _normalize_mfa_policy(candidate, current_user.tenant_id, strict=True)
    if policy is None:
        return _api_error("invalid_mfa_policy", "The MFA policy values are invalid or unsafe.", 400)
    session = SessionLocal()
    try:
        record = session.query(MFAPolicy).filter_by(tenant_id=current_user.tenant_id).with_for_update().first()
        if record is None:
            record = MFAPolicy(
                id=f"mfa_policy_{uuid.uuid4().hex}",
                tenant_id=current_user.tenant_id,
                policy=policy,
                version=1,
                updated_by=current_user.user_id,
                created_at=_now_utc(),
                updated_at=_now_utc(),
            )
            session.add(record)
        else:
            record.policy = policy
            record.version += 1
            record.updated_by = current_user.user_id
            record.updated_at = _now_utc()
        _record_mfa_event(
            session,
            current_user.tenant_id,
            current_user.user_id,
            "policy.updated",
            "success",
            details={"version": record.version},
        )
        session.commit()
        return _api_success({"policy": policy, "version": record.version}, 200)
    finally:
        session.close()


@_idempotent_route("/auth/mfa/enroll", methods=["POST"])
@require_auth()
def enroll_mfa_route():
    """Create an encrypted pending TOTP factor and reveal setup material once."""
    current_user = get_current_user()
    policy = _mfa_policy_for_tenant(current_user.tenant_id)
    if "totp" not in policy["allowed_factors"]:
        return _api_error("mfa_factor_not_allowed", "TOTP enrollment is disabled by tenant policy.", 403)
    payload = request.get_json(silent=True) or {}
    replace_factor_id = str(payload.get("replace_factor_id") or "").strip() or None
    if replace_factor_id:
        with SessionLocal() as check_session:
            old_factor = check_session.query(MFAFactor).filter_by(
                id=replace_factor_id,
                tenant_id=current_user.tenant_id,
                user_id=current_user.user_id,
                status="active",
            ).first()
            account = check_session.query(UserAccount).filter_by(
                id=current_user.user_id,
                tenant_id=current_user.tenant_id,
            ).first()
            if old_factor is None or account is None:
                return _api_error("resource_not_found", "Active MFA factor not found.", 404)
        if not _verify_mfa_code(account, str(payload.get("current_code") or "")):
            return _api_error("invalid_mfa", "A valid current MFA code is required to replace this factor.", 401)

    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    recovery_codes, recovery_hashes = _new_recovery_codes(policy["recovery_code_count"])
    now = _now_utc()
    session = SessionLocal()
    try:
        account = session.query(UserAccount).filter_by(
            id=current_user.user_id,
            tenant_id=current_user.tenant_id,
        ).first()
        if account is None:
            return _api_error("resource_not_found", "MFA user not found.", 404)
        session.query(MFAFactor).filter_by(
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            factor_type="totp",
            status="pending",
        ).update({MFAFactor.status: "revoked", MFAFactor.revoked_at: now}, synchronize_session=False)
        factor_id = f"mfa_factor_{uuid.uuid4().hex}"
        session.add(MFAFactor(
            id=factor_id,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            factor_type="totp",
            factor_kind="totp",
            display_name="Authenticator",
            secret_encrypted=encrypt_value(secret),
            status="pending",
            failed_attempts=0,
            metadata_json={
                "pending_recovery_code_hashes": recovery_hashes,
                "replacement_factor_id": replace_factor_id,
            },
            created_at=now,
            expires_at=now + timedelta(minutes=15),
        ))
        _record_mfa_event(
            session,
            current_user.tenant_id,
            current_user.user_id,
            "factor.totp.enrollment_started",
            "pending",
            factor_id=factor_id,
            details={"replacement": bool(replace_factor_id)},
        )
        session.commit()
        issuer = os.getenv("PESAGUARD_MFA_ISSUER", "PesaGuard").strip()[:64] or "PesaGuard"
        label = f"{issuer}:{account.email or account.username}"
        uri = f"otpauth://totp/{quote(label, safe='')}?{urlencode({'secret': secret, 'issuer': issuer, 'algorithm': 'SHA1', 'digits': 6, 'period': 30})}"
        qr_buffer = BytesIO()
        qrcode.make(uri).save(qr_buffer, format="PNG")
        return _api_success({
            "status": "pending",
            "factor_id": factor_id,
            "secret": secret,
            "otpauth_uri": uri,
            "qr_code": "data:image/png;base64," + base64.b64encode(qr_buffer.getvalue()).decode("ascii"),
            "recovery_codes": recovery_codes,
            "expires_in": 900,
            "secret_exposed_once": True,
        }, 201)
    finally:
        session.close()


@_idempotent_route("/auth/mfa/enroll/verify", methods=["POST"])
@require_auth()
def verify_mfa_enrollment_route():
    """Activate a pending TOTP factor after bounded, replay-safe verification."""
    code = str((request.get_json(silent=True) or {}).get("code") or "").strip()
    current_user = get_current_user()
    policy = _mfa_policy_for_tenant(current_user.tenant_id)
    session = SessionLocal()
    try:
        factor = session.query(MFAFactor).filter_by(
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            factor_type="totp",
            status="pending",
        ).order_by(MFAFactor.created_at.desc()).with_for_update().first()
        if factor is None:
            return _api_error("mfa_enrollment_not_started", "Start MFA enrollment before verification.", 400)
        if factor.expires_at is None or _is_expired(factor.expires_at):
            factor.status = "revoked"
            factor.revoked_at = _now_utc()
            _record_mfa_event(
                session,
                current_user.tenant_id,
                current_user.user_id,
                "factor.totp.enrollment_expired",
                "denied",
                factor_id=factor.id,
            )
            session.commit()
            return _api_error("mfa_enrollment_expired", "The pending MFA enrollment has expired.", 401)
        if factor.failed_attempts >= policy["attempt_limit"]:
            return _api_error("mfa_factor_locked", "Too many invalid enrollment codes; start enrollment again.", 423)
        try:
            secret = str(decrypt_value(factor.secret_encrypted))
        except (TypeError, ValueError, RuntimeError):
            logger.error("Unable to decrypt pending TOTP factor %s", factor.id, exc_info=True)
            return _api_error("mfa_configuration_error", "MFA enrollment state is invalid.", 500)
        counter = _matching_totp_counter(
            secret,
            code,
            clock_skew_steps=policy["totp_clock_skew_steps"],
        )
        if counter is None:
            factor.failed_attempts = int(factor.failed_attempts or 0) + 1
            locked = factor.failed_attempts >= policy["attempt_limit"]
            if locked:
                factor.status = "locked"
                factor.locked_until = _now_utc() + timedelta(seconds=policy["lockout_seconds"])
            _record_mfa_event(
                session,
                current_user.tenant_id,
                current_user.user_id,
                "factor.totp.enrollment_failed",
                "denied",
                factor_id=factor.id,
                details={"attempts": factor.failed_attempts},
            )
            session.commit()
            return _api_error(
                "invalid_mfa",
                "The TOTP code is invalid." if not locked else "Enrollment locked after too many invalid codes.",
                401 if not locked else 423,
            )
        account = session.query(UserAccount).filter_by(
            id=current_user.user_id,
            tenant_id=current_user.tenant_id,
        ).first()
        if account is None:
            return _api_error("resource_not_found", "MFA user not found.", 404)
        now = _now_utc()
        factor.status = "active"
        factor.last_used_counter = counter
        factor.confirmed_at = now
        factor.last_used_at = now
        factor.failed_attempts = 0
        factor.locked_until = None
        metadata = dict(factor.metadata_json or {})
        pending_hashes = metadata.pop("pending_recovery_code_hashes", [])
        replacement_factor_id = metadata.pop("replacement_factor_id", None)
        factor.metadata_json = metadata
        _store_mfa_recovery_codes(
            session,
            current_user.tenant_id,
            current_user.user_id,
            pending_hashes if isinstance(pending_hashes, list) else [],
        )
        if replacement_factor_id:
            old_factor = session.query(MFAFactor).filter_by(
                id=replacement_factor_id,
                tenant_id=current_user.tenant_id,
                user_id=current_user.user_id,
                status="active",
            ).with_for_update().first()
            if old_factor is None:
                session.rollback()
                return _api_error("replacement_factor_changed", "The factor selected for replacement is no longer active.", 409)
            old_factor.status = "revoked"
            old_factor.revoked_at = now
            _record_mfa_event(
                session,
                current_user.tenant_id,
                current_user.user_id,
                "factor.replaced",
                "success",
                factor_id=old_factor.id,
                details={"replacement_factor_id": factor.id},
            )
        account.mfa_enabled = True
        account.authorization_version += 1
        _record_mfa_event(
            session,
            current_user.tenant_id,
            current_user.user_id,
            "factor.totp.enrolled",
            "success",
            factor_id=factor.id,
            details={"replacement": bool(replacement_factor_id)},
        )
        session.commit()
        return _api_success({
            "status": "enabled",
            "factor_id": factor.id,
            "mfa_enabled": True,
            "recovery_codes_saved": len(pending_hashes) if isinstance(pending_hashes, list) else 0,
        }, 200)
    finally:
        session.close()


@_idempotent_route("/auth/mfa/factors/<factor_id>/revoke", methods=["POST"])
@require_auth()
def revoke_mfa_factor_route(factor_id: str):
    current_user = get_current_user()
    code = str((request.get_json(silent=True) or {}).get("code") or "").strip()
    with SessionLocal() as lookup:
        account = lookup.query(UserAccount).filter_by(
            id=current_user.user_id,
            tenant_id=current_user.tenant_id,
        ).first()
        factor = lookup.query(MFAFactor).filter_by(
            id=factor_id,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            status="active",
        ).first()
    if account is None or factor is None:
        return _api_error("resource_not_found", "Active MFA factor not found.", 404)
    if not _verify_mfa_code(account, code):
        return _api_error("invalid_mfa", "A valid MFA code is required to revoke a factor.", 401)
    session = SessionLocal()
    try:
        factor = session.query(MFAFactor).filter_by(
            id=factor_id,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            status="active",
        ).with_for_update().first()
        if factor is None:
            return _api_error("resource_not_found", "Active MFA factor not found.", 404)
        remaining = session.query(MFAFactor).filter(
            MFAFactor.tenant_id == current_user.tenant_id,
            MFAFactor.user_id == current_user.user_id,
            MFAFactor.status == "active",
            MFAFactor.id != factor.id,
        ).count()
        if remaining == 0 and _mfa_is_required(account):
            return _api_error("required_factor", "Privileged account policy requires at least one active factor.", 409)
        factor.status = "revoked"
        factor.revoked_at = _now_utc()
        factor.secret_encrypted = None
        factor.credential_public_key = None
        account = session.query(UserAccount).filter_by(
            id=current_user.user_id,
            tenant_id=current_user.tenant_id,
        ).with_for_update().first()
        if account is not None:
            account.mfa_enabled = remaining > 0
            account.authorization_version += 1
        _record_mfa_event(
            session,
            current_user.tenant_id,
            current_user.user_id,
            "factor.revoked",
            "success",
            factor_id=factor.id,
        )
        session.commit()
    finally:
        session.close()
    _revoke_user_sessions(current_user.user_id, current_user.tenant_id, "MFA factor revoked")
    return _api_success({"status": "factor_revoked", "factor_id": factor_id}, 200)


@_idempotent_route("/auth/mfa/recovery-codes/regenerate", methods=["POST"])
@require_auth()
def regenerate_mfa_recovery_codes_route():
    """Replace all outstanding recovery codes after current-factor verification."""
    current_user = get_current_user()
    code = str((request.get_json(silent=True) or {}).get("code") or "").strip()
    with SessionLocal() as session:
        account = session.query(UserAccount).filter_by(
            id=current_user.user_id,
            tenant_id=current_user.tenant_id,
        ).first()
    if account is None or not account.mfa_enabled:
        return _api_error("mfa_not_enabled", "MFA is not enabled for this account.", 400)
    if not _verify_mfa_code(account, code):
        return _api_error("invalid_mfa", "The current MFA code is invalid.", 401)
    policy = _mfa_policy_for_tenant(current_user.tenant_id)
    recovery_codes, recovery_hashes = _new_recovery_codes(policy["recovery_code_count"])
    with SessionLocal() as session:
        _store_mfa_recovery_codes(session, current_user.tenant_id, current_user.user_id, recovery_hashes)
        _record_mfa_event(
            session,
            current_user.tenant_id,
            current_user.user_id,
            "recovery_codes.regenerated",
            "success",
            details={"count": len(recovery_codes)},
        )
        session.commit()
    return _api_success({"status": "rotated", "recovery_codes": recovery_codes}, 200)


@_idempotent_route("/auth/mfa/email/request", methods=["POST"])
@require_auth()
def request_mfa_email_verification_route():
    """Create a short-lived email MFA challenge for the authenticated account."""
    current_user = get_current_user()
    session = SessionLocal()
    try:
        account = session.query(UserAccount).filter_by(id=current_user.user_id, tenant_id=current_user.tenant_id).first()
        if account is None or not account.email:
            return _api_error("email_unavailable", "No verified email is available for this account.", 400)
        code = f"{secrets.randbelow(1_000_000):06d}"
        challenge_id = f"mfa_email_{uuid.uuid4().hex[:12]}"
        session.add(MFAChallenge(
            id=challenge_id,
            user_id=account.id,
            tenant_id=account.tenant_id,
            code_hash=hashlib.sha256(code.encode("utf-8")).hexdigest(),
            status="pending",
            expires_at=_now_utc() + timedelta(minutes=10),
            attempts=0,
        ))
        session.commit()
        if _is_production_environment():
            if not email_service.smtp_server:
                return _api_error("email_unavailable", "Email delivery is not configured.", 503)
            delivered, delivery_error = email_service._send_email(
                account.email,
                "PesaGuard MFA verification code",
                f"Your PesaGuard verification code is {code}. It expires in 10 minutes.",
                f"Your PesaGuard verification code is {code}. It expires in 10 minutes.",
            )
            if not delivered:
                session.query(MFAChallenge).filter_by(id=challenge_id).update({MFAChallenge.status: "delivery_failed"})
                session.commit()
                logger.error("MFA email delivery failed for challenge %s: %s", challenge_id, delivery_error)
                return _api_error("email_delivery_failed", "Unable to deliver the MFA verification email.", 503)
            return _api_success({"challenge_id": challenge_id, "status": "sent", "expires_in": 600}, 201)
        return _api_success({"challenge_id": challenge_id, "status": "sent", "verification_code": code, "expires_in": 600}, 201)
    finally:
        session.close()


@_idempotent_route("/auth/mfa/email/verify", methods=["POST"])
@require_auth()
def verify_mfa_email_route():
    """Consume an email MFA challenge with bounded attempts and expiry."""
    data = request.json or {}
    current_user = get_current_user()
    challenge_id = str(data.get("challenge_id") or "")
    code = str(data.get("code") or "")
    session = SessionLocal()
    try:
        record = session.query(MFAChallenge).filter_by(
            id=challenge_id,
            user_id=current_user.user_id,
            tenant_id=current_user.tenant_id,
        ).first()
        if record is None:
            return _api_error("resource_not_found", "Email MFA challenge not found.", 404)
        if record.status != "pending" or _is_expired(record.expires_at) or record.attempts >= 5:
            return _api_error("invalid_mfa", "The email MFA challenge is expired or exhausted.", 401)
        record.attempts += 1
        verified = hmac.compare_digest(record.code_hash, hashlib.sha256(code.encode("utf-8")).hexdigest())
        record.status = "verified" if verified else ("failed" if record.attempts >= 5 else "pending")
        session.commit()
        return _api_success({"verified": verified, "challenge_id": challenge_id, "status": record.status}, 200)
    finally:
        session.close()


@_idempotent_route("/auth/mfa/reset/request", methods=["POST"])
@require_auth()
def request_mfa_reset_route():
    """Start a reset workflow for the caller or a tenant-scoped user."""
    current_user = get_current_user()
    data = request.json or {}
    target_user_id = data.get("user_id") or current_user.user_id
    if target_user_id != current_user.user_id and "manage:mfa" not in current_user.permissions:
        return _api_error("permission_denied", "MFA reset for another user requires manage:mfa.", 403)
    session = SessionLocal()
    try:
        account = session.query(UserAccount).filter_by(id=target_user_id, tenant_id=current_user.tenant_id).first()
        if account is None or not account.email:
            return _api_error("resource_not_found", "MFA user not found.", 404)
        code = f"{secrets.randbelow(1_000_000):06d}"
        challenge_id = f"mfa_reset_{uuid.uuid4().hex[:12]}"
        session.add(MFAChallenge(
            id=challenge_id,
            user_id=account.id,
            tenant_id=account.tenant_id,
            code_hash=hashlib.sha256(code.encode("utf-8")).hexdigest(),
            status="pending",
            expires_at=_now_utc() + timedelta(minutes=15),
            attempts=0,
        ))
        session.commit()
        if _is_production_environment():
            if not email_service.smtp_server:
                return _api_error("email_unavailable", "Email delivery is not configured.", 503)
            delivered, delivery_error = email_service._send_email(account.email, "PesaGuard MFA reset verification", f"Your MFA reset code is {code}.", f"Your MFA reset code is {code}.")
            if not delivered:
                session.query(MFAChallenge).filter_by(id=challenge_id).update({MFAChallenge.status: "delivery_failed"})
                session.commit()
                logger.error("MFA reset email delivery failed for challenge %s: %s", challenge_id, delivery_error)
                return _api_error("email_delivery_failed", "Unable to deliver the MFA reset email.", 503)
            return _api_success({"challenge_id": challenge_id, "status": "sent", "expires_in": 900}, 201)
        return _api_success({"challenge_id": challenge_id, "status": "sent", "verification_code": code, "expires_in": 900}, 201)
    finally:
        session.close()


@_idempotent_route("/auth/mfa/reset/confirm", methods=["POST"])
@require_auth()
def confirm_mfa_reset_route():
    """Complete a verified MFA reset and invalidate all existing sessions."""
    data = request.json or {}
    current_user = get_current_user()
    target_user_id = data.get("user_id") or current_user.user_id
    if target_user_id != current_user.user_id and "manage:mfa" not in current_user.permissions:
        return _api_error("permission_denied", "MFA reset for another user requires manage:mfa.", 403)
    session = SessionLocal()
    try:
        record = session.query(MFAChallenge).filter_by(
            id=data.get("challenge_id"),
            user_id=target_user_id,
            tenant_id=current_user.tenant_id,
            status="pending",
        ).first()
        if record is None or _is_expired(record.expires_at) or record.attempts >= 5:
            return _api_error("invalid_mfa_reset", "The MFA reset challenge is invalid or expired.", 401)
        record.attempts += 1
        if not hmac.compare_digest(record.code_hash, hashlib.sha256(str(data.get("code") or "").encode("utf-8")).hexdigest()):
            if record.attempts >= 5:
                record.status = "failed"
            session.commit()
            return _api_error("invalid_mfa_reset", "The MFA reset code is invalid.", 401)
        account = session.query(UserAccount).filter_by(id=target_user_id, tenant_id=current_user.tenant_id).first()
        if account is None:
            return _api_error("resource_not_found", "MFA user not found.", 404)
        attrs = dict(account.attributes or {})
        for key in ("mfa_totp_secret", "mfa_pending_secret", "mfa_recovery_code_hashes", "mfa_pending_recovery_code_hashes"):
            attrs.pop(key, None)
        account.attributes = attrs
        account.mfa_enabled = False
        account.authorization_version += 1
        record.status = "verified"
        session.commit()
    finally:
        session.close()
    _revoke_user_sessions(target_user_id, current_user.tenant_id, "mfa reset")
    return _api_success({"status": "reset", "mfa_enabled": False}, 200)


@_idempotent_route("/auth/mfa/challenge", methods=["POST"])
@require_auth("manage:mfa")
def create_mfa_challenge_route():
    """Create an MFA challenge for a user."""
    data = request.json or {}
    current_user = get_current_user()
    user_id = data.get("user_id") or current_user.user_id
    if user_id != current_user.user_id:
        target_session = SessionLocal()
        try:
            target = target_session.query(UserAccount).filter_by(id=user_id, tenant_id=current_user.tenant_id).first()
        finally:
            target_session.close()
        if target is None:
            return _api_error("resource_not_found", "MFA user not found.", 404)
    challenge_id = f"mfa_{uuid.uuid4().hex[:12]}"
    code = f"{secrets.randbelow(1_000_000):06d}"
    session = SessionLocal()
    try:
        record = MFAChallenge(
            id=challenge_id,
            user_id=user_id,
            tenant_id=current_user.tenant_id,
            code_hash=hashlib.sha256(code.encode("utf-8")).hexdigest(),
            status="pending",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            attempts=0,
        )
        session.add(record)
        session.commit()
        return _api_success({"challenge_id": challenge_id, "status": "pending", "user_id": user_id}, 201)
    finally:
        session.close()


@_idempotent_route("/auth/mfa/verify", methods=["POST"])
@require_auth("manage:mfa")
def verify_mfa_route():
    """Verify an MFA challenge code."""
    data = request.json or {}
    user_id = data.get("user_id")
    challenge_id = data.get("challenge_id")
    code = data.get("code")
    if not user_id or not challenge_id or not code:
        return _api_error("invalid_request", "user_id, challenge_id, and code are required.", 400)

    session = SessionLocal()
    try:
        current_user = get_current_user()
        record = session.query(MFAChallenge).filter_by(
            id=challenge_id,
            user_id=user_id,
            tenant_id=current_user.tenant_id,
        ).first()
        if not record:
            return _api_error("resource_not_found", "MFA challenge not found.", 404)
        now = datetime.now(timezone.utc)
        if record.status != "pending" or record.expires_at <= now or record.attempts >= 5:
            return _api_success({"verified": False, "status": record.status}, 200)
        record.attempts += 1
        verified = hmac.compare_digest(record.code_hash, hashlib.sha256(str(code).encode("utf-8")).hexdigest())
        if not verified:
            from metrics import record_security_event
            record_security_event()
        record.status = "verified" if verified else ("failed" if record.attempts >= 5 else "pending")
        session.commit()
        return _api_success({"verified": verified, "status": record.status, "challenge_id": challenge_id}, 200)
    finally:
        session.close()


@_idempotent_route("/auth/passwordless/challenge", methods=["POST"])
@require_auth("manage:users")
def create_passwordless_challenge_route():
    """Create a passwordless challenge for a user."""
    data = request.json or {}
    current_user = get_current_user()
    user_id = data.get("user_id") or current_user.user_id
    if user_id != current_user.user_id:
        target_session = SessionLocal()
        try:
            target = target_session.query(UserAccount).filter_by(id=user_id, tenant_id=current_user.tenant_id).first()
        finally:
            target_session.close()
        if target is None:
            return _api_error("resource_not_found", "Passwordless user not found.", 404)
    challenge_id = f"pw_{uuid.uuid4().hex[:12]}"
    token = secrets.token_urlsafe(32)
    session = SessionLocal()
    try:
        record = PasswordlessChallenge(
            id=challenge_id,
            user_id=user_id,
            tenant_id=current_user.tenant_id,
            token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            status="pending",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            attempts=0,
        )
        session.add(record)
        session.commit()
        return _api_success({"challenge_id": challenge_id, "status": "pending", "user_id": user_id}, 201)
    finally:
        session.close()


@_idempotent_route("/auth/passwordless/verify", methods=["POST"])
@require_auth("manage:users")
def verify_passwordless_route():
    """Verify a passwordless challenge token."""
    data = request.json or {}
    user_id = data.get("user_id")
    challenge_id = data.get("challenge_id")
    token = data.get("token")
    if not user_id or not challenge_id or not token:
        return _api_error("invalid_request", "user_id, challenge_id, and token are required.", 400)

    session = SessionLocal()
    try:
        current_user = get_current_user()
        record = session.query(PasswordlessChallenge).filter_by(
            id=challenge_id,
            user_id=user_id,
            tenant_id=current_user.tenant_id,
        ).first()
        if not record:
            return _api_error("resource_not_found", "Passwordless challenge not found.", 404)
        now = datetime.now(timezone.utc)
        if record.status != "pending" or record.expires_at <= now or record.attempts >= 5:
            return _api_success({"verified": False, "status": record.status}, 200)
        record.attempts += 1
        verified = hmac.compare_digest(record.token_hash, hashlib.sha256(str(token).encode("utf-8")).hexdigest())
        if not verified:
            from metrics import record_security_event
            record_security_event()
        record.status = "verified" if verified else ("failed" if record.attempts >= 5 else "pending")
        session.commit()
        return _api_success({"verified": verified, "status": record.status, "challenge_id": challenge_id}, 200)
    finally:
        session.close()


# ============================================================================
# WEBHOOK MANAGEMENT
# ============================================================================

@_idempotent_route("/webhooks", methods=["POST"])
@require_auth("manage:webhooks")
@require_tenant_access()
def create_webhook():
    """Register a new outbound webhook configuration for a tenant."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    session = SessionLocal()

    try:
        webhook_mgr = WebhookManager(session)
        result = webhook_mgr.register_webhook(
            tenant_id=tenant_id,
            url=data.get("url"),
            event_types=data.get("event_types", ["escalation"]),
            retry_attempts=data.get("retry_attempts", 3),
            timeout_seconds=data.get("timeout_seconds", 10),
        )
        if "error" in result:
            return jsonify(result), 400

        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="create_webhook",
            details={"webhook_id": result.get("id"), "url": data.get("url"), "event_types": result.get("event_types")},
        )
        return jsonify(result), 201
    finally:
        session.close()


@_idempotent_route("/webhooks", methods=["GET"])
@require_auth("manage:webhooks")
@require_tenant_access()
def list_webhooks():
    """List all registered webhooks for a tenant."""
    tenant_id = request.args.get("tenant_id")
    session = SessionLocal()

    try:
        webhook_mgr = WebhookManager(session)
        webhooks = webhook_mgr.get_webhooks(tenant_id)
        return jsonify({
            "tenant_id": tenant_id,
            "webhooks": [
                {
                    "id": w.id,
                    "url": w.url,
                    "event_types": w.event_types,
                    "active": w.active,
                    "created_at": w.created_at.isoformat() if w.created_at else None,
                }
                for w in webhooks
            ],
        }), 200
    finally:
        session.close()


@_idempotent_route("/webhooks/<webhook_id>", methods=["PUT"])
@require_auth()
@require_resource_access("manage:webhooks", "webhook_id")
def update_webhook(webhook_id: str):
    """Update webhook configuration details strictly scoped to caller tenant."""
    data = request.json or {}
    data.pop("tenant_id", None)
    current_user = get_current_user()
    tenant_id = getattr(current_user, "tenant_id", None)
    session = SessionLocal()

    try:
        webhook_mgr = WebhookManager(session)
        result = webhook_mgr.update_webhook(webhook_id, tenant_id=tenant_id, **data)
        if result.get("error") == "webhook_not_found":
            return jsonify(result), 404

        _record_action_audit(
            session,
            tenant_id=tenant_id or "default",
            actor=getattr(current_user, "user_id", "system"),
            action="update_webhook",
            details={"webhook_id": webhook_id, **data},
        )
        return jsonify(result), 200
    finally:
        session.close()


@_idempotent_route("/webhooks/<webhook_id>/deliveries", methods=["GET"])
@require_auth()
@require_resource_access("manage:webhooks", "webhook_id")
def get_webhook_deliveries(webhook_id: str):
    """Retrieve delivery history logs for a specific webhook."""
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    current_user = get_current_user()
    tenant_id = getattr(current_user, "tenant_id", None)
    session = SessionLocal()

    try:
        webhook_mgr = WebhookManager(session)
        deliveries = webhook_mgr.get_delivery_history(webhook_id, tenant_id=tenant_id, limit=limit)
        return jsonify({
            "webhook_id": webhook_id,
            "deliveries": deliveries,
        }), 200
    finally:
        session.close()


# ============================================================================
# ESCALATION RULES
# ============================================================================

@_idempotent_route("/escalation-rules", methods=["POST"])
@require_auth("write:escalation_rules")
@require_tenant_access()
def create_escalation_rule():
    """Create a custom automated escalation rule for a tenant."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    session = SessionLocal()

    try:
        engine_instance = EscalationEngine(session)
        result = engine_instance.create_rule(
            tenant_id=tenant_id,
            name=data.get("name"),
            description=data.get("description"),
            condition_field=data.get("condition_field"),
            condition_operator=data.get("condition_operator"),
            condition_value=data.get("condition_value"),
            action=data.get("action"),
            target=data.get("target"),
            webhook_url=data.get("webhook_url"),
            priority=data.get("priority", 0),
        )
        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="create_escalation_rule",
            details={"rule_id": result.get("id"), "name": data.get("name")},
        )
        return jsonify(result), 201
    finally:
        session.close()


@_idempotent_route("/escalation-rules", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def list_escalation_rules():
    """List active escalation rules for a tenant."""
    tenant_id = request.args.get("tenant_id")
    session = SessionLocal()

    try:
        engine_instance = EscalationEngine(session)
        rules = engine_instance.get_rules(tenant_id)
        return jsonify({
            "tenant_id": tenant_id,
            "rules": rules,
        }), 200
    finally:
        session.close()


@_idempotent_route("/escalation-rules/<rule_id>", methods=["PUT"])
@require_auth()
@require_tenant_access()
@require_resource_access("write:escalation_rules", "rule_id")
def update_escalation_rule(rule_id: str):
    """Update an existing escalation rule configuration."""
    data = request.json or {}
    session = SessionLocal()

    try:
        engine_instance = EscalationEngine(session)
        tenant_id = data.get("tenant_id") or get_current_user().tenant_id
        rule_data = dict(data)
        rule_data.pop("tenant_id", None)
        result = engine_instance.update_rule(rule_id, tenant_id=tenant_id, **rule_data)
        return jsonify(result), 200
    finally:
        session.close()


# ============================================================================
# ON-CALL ROTATIONS
# ============================================================================

@_idempotent_route("/on-call/rotations", methods=["POST"])
@require_auth("manage:on_call")
@require_tenant_access()
def create_on_call_rotation():
    """Create an on-call schedule rotation entry."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    session = SessionLocal()

    try:
        service = OnCallService(session)
        shift_start = datetime.fromisoformat(data.get("shift_start"))
        shift_end = datetime.fromisoformat(data.get("shift_end"))

        result = service.create_rotation(
            tenant_id=tenant_id,
            operator_id=data.get("operator_id"),
            operator_name=data.get("operator_name"),
            operator_email=data.get("operator_email"),
            operator_phone=data.get("operator_phone"),
            shift_start=shift_start,
            shift_end=shift_end,
            escalation_level=data.get("escalation_level", 1),
        )
        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="create_on_call_rotation",
            details={"operator_id": data.get("operator_id"), "shift_start": shift_start.isoformat(), "shift_end": shift_end.isoformat()},
        )
        return jsonify(result), 201
    finally:
        session.close()


@_idempotent_route("/on-call/rotations/active", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def get_active_on_call():
    """Retrieve active on-call coverage status for a tenant."""
    tenant_id = request.args.get("tenant_id")
    session = SessionLocal()

    try:
        service = OnCallService(session)
        rotations = service.get_active_rotations(tenant_id)
        coverage = service.get_coverage_status(tenant_id)

        return jsonify({
            "tenant_id": tenant_id,
            "coverage": coverage,
            "active_rotations": rotations,
        }), 200
    finally:
        session.close()


@_idempotent_route("/on-call/schedule/<operator_id>", methods=["GET"])
@require_auth()
@require_tenant_access()
@require_resource_access("read:discrepancies", "operator_id")
def get_operator_schedule(operator_id: str):
    """Retrieve an operator's on-call schedule window."""
    tenant_id = request.args.get("tenant_id")
    days = min(max(request.args.get("days", 30, type=int), 1), 365)
    session = SessionLocal()

    try:
        service = OnCallService(session)
        schedule = service.get_operator_schedule(tenant_id, operator_id, days)
        return jsonify({
            "operator_id": operator_id,
            "tenant_id": tenant_id,
            "days": days,
            "schedule": schedule,
        }), 200
    finally:
        session.close()


@_idempotent_route("/on-call/bulk", methods=["POST"])
@require_auth("manage:on_call")
@require_tenant_access()
def bulk_create_on_call():
    """Bulk create multiple on-call schedule rotations."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    rotations_data = data.get("rotations", [])
    session = SessionLocal()

    try:
        service = OnCallService(session)
        result = service.bulk_create_rotations(tenant_id, rotations_data)
        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="bulk_create_on_call_rotations",
            details={"created": result.get("created", 0)},
        )
        return jsonify(result), 201
    finally:
        session.close()


# ============================================================================
# EMAIL NOTIFICATIONS
# ============================================================================

@_idempotent_route("/emails/reconciliation", methods=["POST"])
@require_auth("write:discrepancies")
@require_tenant_access()
def send_reconciliation_email():
    """Dispatch structured reconciliation report via email."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    recipient = data.get("recipient_email")
    report_data = data.get("report_data", {})
    session = SessionLocal()

    try:
        current_user = get_current_user()
        locale = resolve_email_locale(
            tenant_id,
            user_id=getattr(current_user, "user_id", None) or data.get("user_id") or request.args.get("user_id"),
        )
        result = email_service.send_reconciliation_report(
            session, tenant_id, recipient, report_data, locale=locale
        )
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="send_reconciliation_email",
            details={"recipient": recipient, "report_data": report_data},
        )
        return jsonify(result), 200
    finally:
        session.close()


@_idempotent_route("/emails/escalation", methods=["POST"])
@require_auth("write:discrepancies")
@require_tenant_access()
def send_escalation_email():
    """Dispatch critical incident escalation alert via email."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    recipient = data.get("recipient_email")
    incident = data.get("incident_data", {})
    session = SessionLocal()

    try:
        current_user = get_current_user()
        locale = resolve_email_locale(
            tenant_id,
            user_id=getattr(current_user, "user_id", None) or data.get("user_id") or request.args.get("user_id"),
        )
        result = email_service.send_escalation_notification(
            session, tenant_id, recipient, incident, locale=locale
        )
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="send_escalation_email",
            details={"recipient": recipient, "incident": incident},
        )
        return jsonify(result), 200
    finally:
        session.close()


@_idempotent_route("/emails/history", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def get_email_history():
    """Retrieve historical email notification delivery logs."""
    tenant_id = request.args.get("tenant_id")
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    session = SessionLocal()

    try:
        history = email_service.get_email_history(session, tenant_id, limit)
        return jsonify({
            "tenant_id": tenant_id,
            "emails": history,
        }), 200
    finally:
        session.close()


# ============================================================================
# ADVANCED SEARCH
# ============================================================================

@_idempotent_route("/search", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def advanced_search():
    """Execute advanced boolean text queries across discrepancies."""
    tenant_id = request.args.get("tenant_id")
    query = request.args.get("q", "")
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    session = SessionLocal()

    try:
        search = AdvancedSearchEngine(session)
        result = search.search(tenant_id, query, limit=limit, offset=offset)
        return jsonify(result), 200
    finally:
        session.close()


@_idempotent_route("/search/filters", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def search_filters():
    """Retrieve available filter facets for advanced search."""
    tenant_id = request.args.get("tenant_id")
    session = SessionLocal()

    try:
        search = AdvancedSearchEngine(session)
        filters = search.suggest_filters(tenant_id)
        return jsonify({
            "tenant_id": tenant_id,
            "available_filters": filters,
        }), 200
    finally:
        session.close()


@_idempotent_route("/search/structured", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def structured_search():
    """Execute structured filtering queries against reconciliation records."""
    tenant_id = request.args.get("tenant_id")
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    session = SessionLocal()

    try:
        search = AdvancedSearchEngine(session)
        result = search.search_by_filters(
            tenant_id=tenant_id,
            severity=request.args.get("severity"),
            status=request.args.get("status"),
            anomaly_type=request.args.get("anomaly_type"),
            resolved=request.args.get("resolved", type=lambda x: x.lower() == "true"),
            assignee=request.args.get("assignee"),
            days_back=min(max(request.args.get("days_back", 30, type=int), 1), 365),
            limit=limit,
            offset=offset,
        )
        return jsonify(result), 200
    finally:
        session.close()


# ============================================================================
# PUBLIC CUSTOMER-FACING ENDPOINTS
# ============================================================================

@_idempotent_route("/public/customers/<tenant_id>/reconciliations", methods=["GET"])
@require_auth("read:discrepancies")
@require_tenant_access()
def public_get_reconciliations(tenant_id: str):
    """Retrieve secure, tenant-scoped recent reconciliation outcomes."""
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    session = SessionLocal()

    try:
        q = (
            session.query(Discrepancy)
            .filter(Discrepancy.tenant_id == tenant_id)
            .order_by(Discrepancy.detected_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = q.all()
        return jsonify({
            "tenant_id": tenant_id,
            "count": len(rows),
            "reconciliations": [
                {
                    "id": r.id,
                    "trans_id": r.trans_id,
                    "anomaly_type": r.anomaly_type,
                    "status": r.status,
                    "severity": r.severity,
                    "details": r.details,
                    "detected_at": r.detected_at.isoformat() if r.detected_at else None,
                    "resolved": bool(r.resolved),
                }
                for r in rows
            ],
        }), 200
    finally:
        session.close()


@_idempotent_route("/public/customers/<tenant_id>/reports", methods=["GET"])
@require_auth("read:analytics")
@require_tenant_access()
def public_get_reports(tenant_id: str):
    """Retrieve generated financial discrepancy reports for a tenant."""
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    session = SessionLocal()

    try:
        q = (
            session.query(Report)
            .filter(Report.tenant_id == tenant_id)
            .order_by(Report.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = q.all()
        return jsonify({
            "tenant_id": tenant_id,
            "count": len(rows),
            "reports": [
                {
                    "id": r.id,
                    "report_type": r.report_type,
                    "period_start": r.period_start.isoformat() if r.period_start else None,
                    "period_end": r.period_end.isoformat() if r.period_end else None,
                    "status": r.status,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "content": r.content,
                }
                for r in rows
            ],
        }), 200
    finally:
        session.close()


# ============================================================================
# RATE LIMITED BULK OPERATIONS
# ============================================================================

@_idempotent_route("/bulk/assign", methods=["POST"])
@require_auth("bulk:operations")
@rate_limit(max_requests_per_minute=5, tokens_per_request=1, endpoint_name="bulk_assign")
@require_tenant_access()
def bulk_assign_incidents():
    """Bulk assign incidents securely with rate limiting and strict tenant scoping."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    incident_ids = data.get("incident_ids", [])
    assignee = data.get("assignee")
    session = SessionLocal()

    try:
        updated = 0
        skipped_ids = []
        for incident_id in incident_ids[:100]:  # Hard cap at 100 per request
            incident = _incident_belongs_to_tenant(session, incident_id, tenant_id)
            if incident:
                incident.assignee = assignee
                updated += 1
            else:
                skipped_ids.append(incident_id)

        session.commit()
        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="bulk_assign_incidents",
            details={"updated": updated, "skipped_ids": skipped_ids, "assignee": assignee},
        )
        return jsonify({
            "updated": updated,
            "skipped_ids": skipped_ids,
            "rate_limit": get_rate_limit_status(),
        }), 200
    finally:
        session.close()


@_idempotent_route("/bulk/escalate", methods=["POST"])
@require_auth("bulk:operations")
@rate_limit(max_requests_per_minute=3, tokens_per_request=2, endpoint_name="bulk_escalate")
@require_tenant_access()
def bulk_escalate_incidents():
    """Bulk escalate incidents securely with rate limiting and strict tenant scoping."""
    data = request.json or {}
    tenant_id = data.get("tenant_id")
    incident_ids = data.get("incident_ids", [])
    session = SessionLocal()

    try:
        escalated = []
        skipped_ids = []
        engine_instance = EscalationEngine(session)

        for incident_id in incident_ids[:50]:  # Hard cap at 50 per request
            incident = _incident_belongs_to_tenant(session, incident_id, tenant_id)
            if incident:
                result = engine_instance.evaluate_and_escalate(tenant_id, incident)
                escalated.append(result)
            else:
                skipped_ids.append(incident_id)

        current_user = get_current_user()
        _record_action_audit(
            session,
            tenant_id=tenant_id,
            actor=getattr(current_user, "user_id", "system"),
            action="bulk_escalate_incidents",
            details={"escalated_count": len(escalated), "skipped_ids": skipped_ids},
        )
        return jsonify({
            "escalated": len(escalated),
            "details": escalated,
            "skipped_ids": skipped_ids,
            "rate_limit": get_rate_limit_status(),
        }), 200
    finally:
        session.close()


if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    if debug_mode:
        logger.warning("Running with debug=True â€” never do this in production.")
    port = int(os.getenv("PORT", 5002))
    app.run(debug=debug_mode, host=os.getenv("PESAGUARD_BIND_HOST", "127.0.0.1"), port=port)
