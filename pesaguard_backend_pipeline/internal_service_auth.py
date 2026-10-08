"""Authentication primitives for the private Developer Platform/Core API bridge."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

SERVICE_JWT_ISSUER = "developer-platform"
SERVICE_JWT_AUDIENCE = "core-api"
SERVICE_JWT_SUBJECT = "svc-developer-platform"
SERVICE_JWT_ALLOWED_SCOPES = frozenset({
    "service:sync",
    "service:tenant:read",
    "service:key:revoke",
    "service:key:suspend",
})
SERVICE_JWT_JWKS_CACHE_SECONDS = 30
SERVICE_JWT_MAX_JWKS_BYTES = 65536
SERVICE_JWT_MAX_JWKS_KEYS = 32
SERVICE_JWT_MAX_LIFETIME_SECONDS = 300
SERVICE_JWT_MIN_LIFETIME_SECONDS = 60
SERVICE_JWT_CLOCK_SKEW_SECONDS = 30
_KID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})
_jwks_cache_lock = threading.Lock()
_jwks_cache: Dict[str, Any] = {"expires_at": 0.0, "keys": {}}
_unknown_kid_refresh_at = 0.0
_redis_client_lock = threading.Lock()
_redis_clients: Dict[str, Any] = {}


@dataclass(frozen=True)
class ServiceAuthError(Exception):
    """A safe internal-auth failure suitable for an HTTP JSON response."""

    code: str
    message: str
    status_code: int


def _service_jwt_mode() -> str:
    mode = os.getenv("PESAGUARD_PIPELINE_SERVICE_JWT_MODE", "HMAC_ONLY")
    if mode not in {"HMAC_ONLY", "DUAL_REQUIRED", "JWT_PRIMARY"}:
        raise ServiceAuthError(
            "service_auth_configuration_error",
            "Internal service authentication is not configured correctly.",
            503,
        )
    return mode


def _fallback_enabled() -> bool:
    value = os.getenv("PESAGUARD_PIPELINE_SERVICE_JWT_ALLOW_HMAC_FALLBACK", "0")
    if value not in {"0", "1"}:
        raise ServiceAuthError(
            "service_auth_configuration_error",
            "Internal service authentication is not configured correctly.",
            503,
        )
    return value == "1"


def _hmac_authenticate(method: str, raw_target: bytes, raw_body: bytes, *, operation: str) -> None:
    secret = os.getenv("PESAGUARD_PIPELINE_KEY_SYNC_SECRET", "")
    unavailable_code = {
        "sync": "key_sync_unavailable",
        "resolve": "tenant_resolution_unavailable",
        "key_revoke": "key_lifecycle_unavailable",
        "key_suspend": "key_lifecycle_unavailable",
    }.get(operation, "service_auth_unavailable")
    unavailable_message = {
        "sync": "Developer key synchronization is not configured.",
        "resolve": "Internal tenant resolution is not configured.",
        "key_revoke": "Developer key lifecycle operations are not configured.",
        "key_suspend": "Developer key lifecycle operations are not configured.",
    }.get(operation, "Internal service authentication is not configured.")
    if len(secret.encode("utf-8")) < 32:
        raise ServiceAuthError(unavailable_code, unavailable_message, 503)

    from flask import request

    timestamp = request.headers.get("X-PesaGuard-Timestamp", "")
    supplied_signature = request.headers.get("X-PesaGuard-Signature", "")
    if not timestamp.isascii() or not timestamp.isdigit():
        raise ServiceAuthError(
            "invalid_signature", "A valid signed timestamp is required.", 401
        )
    try:
        timestamp_value = int(timestamp)
    except (TypeError, ValueError):
        raise ServiceAuthError(
            "invalid_signature", "A valid signed timestamp is required.", 401
        ) from None
    if abs(int(time.time()) - timestamp_value) > 300:
        message = (
            "The synchronization signature has expired."
            if operation == "sync"
            else "The tenant resolution signature has expired."
            if operation == "resolve"
            else "The key lifecycle signature has expired."
        )
        raise ServiceAuthError("expired_signature", message, 401)

    canonical = b"\n".join((
        timestamp.encode("ascii"),
        method.encode("ascii"),
        raw_target,
        raw_body,
    ))
    expected_signature = hmac.new(
        secret.encode("utf-8"), canonical, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, supplied_signature):
        message = (
            "The synchronization signature is invalid."
            if operation == "sync"
            else "The tenant resolution signature is invalid."
            if operation == "resolve"
            else "The key lifecycle signature is invalid."
        )
        raise ServiceAuthError("invalid_signature", message, 401)


def _base64url_uint(value: Any) -> int:
    if not isinstance(value, str) or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Invalid JWK integer.")
    encoded = value.encode("ascii")
    encoded += b"=" * (-len(encoded) % 4)
    decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
    return int.from_bytes(decoded, "big")


def _jwks_url() -> str:
    value = os.getenv("PESAGUARD_PIPELINE_SERVICE_JWT_JWKS_URL", "").strip()
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.netloc
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
    ):
        raise ServiceAuthError(
            "service_auth_configuration_error",
            "Internal service authentication is not configured correctly.",
            503,
        )
    return value


def _parse_jwks(response: requests.Response) -> Dict[str, rsa.RSAPublicKey]:
    content = response.content
    if not isinstance(content, bytes) or len(content) > SERVICE_JWT_MAX_JWKS_BYTES:
        raise ValueError("Invalid JWKS response size.")
    document = json.loads(content.decode("utf-8"))
    keys = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(keys, list) or not keys or len(keys) > SERVICE_JWT_MAX_JWKS_KEYS:
        raise ValueError("Invalid JWKS key set.")

    parsed: Dict[str, rsa.RSAPublicKey] = {}
    for jwk_data in keys:
        if not isinstance(jwk_data, dict):
            raise ValueError("Invalid JWKS key.")
        kid = jwk_data.get("kid")
        if not isinstance(kid, str) or not _KID_PATTERN.fullmatch(kid) or kid in parsed:
            raise ValueError("Invalid JWKS key ID.")
        if _PRIVATE_JWK_FIELDS.intersection(jwk_data):
            raise ValueError("JWKS contains private key material.")
        if (
            jwk_data.get("kty") != "RSA"
            or jwk_data.get("use", "sig") != "sig"
            or jwk_data.get("alg", "RS256") != "RS256"
            or (
                "key_ops" in jwk_data
                and (
                    not isinstance(jwk_data["key_ops"], list)
                    or "verify" not in jwk_data["key_ops"]
                )
            )
        ):
            raise ValueError("JWKS contains an unsupported key.")
        modulus = _base64url_uint(jwk_data.get("n"))
        exponent = _base64url_uint(jwk_data.get("e"))
        if not 2048 <= modulus.bit_length() <= 8192 or exponent < 3 or exponent % 2 == 0:
            raise ValueError("JWKS contains an invalid RSA key.")
        parsed[kid] = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    return parsed


def _fetch_jwks(url: str) -> Dict[str, rsa.RSAPublicKey]:
    try:
        response = requests.get(url, timeout=(1.5, 2.0), allow_redirects=False)
        response.raise_for_status()
        keys = _parse_jwks(response)
    except ServiceAuthError:
        raise
    except Exception as exc:
        raise ServiceAuthError(
            "service_auth_unavailable",
            "Internal service authentication is temporarily unavailable.",
            503,
        ) from exc
    with _jwks_cache_lock:
        _jwks_cache.update(
            url=url,
            keys=keys,
            expires_at=time.monotonic() + SERVICE_JWT_JWKS_CACHE_SECONDS,
        )
    return keys


def _get_jwks(*, force_refresh: bool = False) -> Dict[str, rsa.RSAPublicKey]:
    global _unknown_kid_refresh_at

    url = _jwks_url()
    with _jwks_cache_lock:
        cache_valid = (
            _jwks_cache.get("url") == url
            and _jwks_cache.get("expires_at", 0.0) > time.monotonic()
        )
        if cache_valid:
            if not force_refresh:
                return dict(_jwks_cache["keys"])
            now = time.monotonic()
            if now - _unknown_kid_refresh_at < 5:
                return dict(_jwks_cache["keys"])
            _unknown_kid_refresh_at = now
    return _fetch_jwks(url)


def _parse_service_token(token: str, required_scope: str) -> tuple[Dict[str, Any], int]:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise ServiceAuthError(
            "invalid_service_token", "The internal service token is invalid.", 401
        ) from exc
    kid = header.get("kid")
    if (
        header.get("alg") != "RS256"
        or not isinstance(kid, str)
        or not _KID_PATTERN.fullmatch(kid)
        or header.get("typ", "JWT") != "JWT"
    ):
        raise ServiceAuthError(
            "invalid_service_token", "The internal service token is invalid.", 401
        )

    keys = _get_jwks()
    key = keys.get(kid)
    if key is None:
        keys = _get_jwks(force_refresh=True)
        key = keys.get(kid)
    if key is None:
        raise ServiceAuthError(
            "invalid_service_token", "The internal service token is invalid.", 401
        )

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=SERVICE_JWT_ISSUER,
            audience=SERVICE_JWT_AUDIENCE,
            leeway=SERVICE_JWT_CLOCK_SKEW_SECONDS,
            options={
                "require": ["iss", "aud", "sub", "iat", "exp", "jti", "scope"],
                "verify_iat": False,
            },
        )
    except jwt.InvalidTokenError as exc:
        raise ServiceAuthError(
            "invalid_service_token", "The internal service token is invalid.", 401
        ) from exc

    issued_at, expires_at = claims.get("iat"), claims.get("exp")
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
    ):
        raise ServiceAuthError(
            "invalid_service_token", "The internal service token is invalid.", 401
        )
    now = int(time.time())
    lifetime = expires_at - issued_at
    if (
        issued_at > now + SERVICE_JWT_CLOCK_SKEW_SECONDS
        or expires_at <= now - SERVICE_JWT_CLOCK_SKEW_SECONDS
        or lifetime < SERVICE_JWT_MIN_LIFETIME_SECONDS
        or lifetime > SERVICE_JWT_MAX_LIFETIME_SECONDS
    ):
        raise ServiceAuthError(
            "invalid_service_token", "The internal service token is invalid.", 401
        )
    if claims.get("iss") != SERVICE_JWT_ISSUER or claims.get("aud") != SERVICE_JWT_AUDIENCE:
        raise ServiceAuthError(
            "invalid_service_token", "The internal service token is invalid.", 401
        )
    if claims.get("sub") != SERVICE_JWT_SUBJECT:
        raise ServiceAuthError(
            "invalid_service_token", "The internal service token is invalid.", 401
        )
    token_id = claims.get("jti")
    try:
        if not isinstance(token_id, str) or str(uuid.UUID(token_id)) != token_id:
            raise ValueError("Invalid token ID.")
    except (TypeError, ValueError):
        raise ServiceAuthError(
            "invalid_service_token", "The internal service token is invalid.", 401
        ) from None
    scopes = claims.get("scope")
    if (
        not isinstance(scopes, list)
        or not scopes
        or not all(
            isinstance(scope, str) and scope in SERVICE_JWT_ALLOWED_SCOPES
            for scope in scopes
        )
        or len(scopes) != 1
        or scopes[0] != required_scope
    ):
        raise ServiceAuthError(
            "insufficient_service_scope",
            "The internal service token does not authorize this operation.",
            403,
        )
    return claims, lifetime


def authenticate_internal_request(
    *,
    method: str,
    raw_target: bytes,
    raw_body: bytes,
    required_scope: str,
    operation: str,
) -> Optional[Dict[str, Any]]:
    """Apply the configured HMAC/JWT mode to one private bridge request."""
    mode = _service_jwt_mode()
    if mode == "HMAC_ONLY":
        _hmac_authenticate(method, raw_target, raw_body, operation=operation)
        return None

    from flask import request

    authorization_present = "Authorization" in request.headers
    authorization = request.headers.get("Authorization", "")
    claims: Optional[Dict[str, Any]] = None
    lifetime: Optional[int] = None
    if authorization_present:
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise ServiceAuthError(
                "invalid_service_token",
                "The internal service token is invalid.",
                401,
            )
        claims, lifetime = _parse_service_token(parts[1], required_scope)
    elif mode == "DUAL_REQUIRED":
        raise ServiceAuthError(
            "missing_service_token",
            "A valid internal service token is required.",
            401,
        )
    elif not _fallback_enabled():
        raise ServiceAuthError(
            "missing_service_token",
            "A valid internal service token is required.",
            401,
        )

    if mode == "DUAL_REQUIRED":
        _hmac_authenticate(method, raw_target, raw_body, operation=operation)
    elif claims is None:
        # Emergency compatibility is intentionally limited to JWT_PRIMARY and
        # only applies when Authorization is wholly absent.
        if mode != "JWT_PRIMARY" or authorization_present or not _fallback_enabled():
            raise ServiceAuthError(
                "missing_service_token",
                "A valid internal service token is required.",
                401,
            )
        _hmac_authenticate(method, raw_target, raw_body, operation=operation)

    if claims is not None and operation in {"sync", "key_revoke", "key_suspend"}:
        claims["_verified_lifetime_seconds"] = lifetime
    return claims


def consume_service_jwt_replay(claims: Optional[Dict[str, Any]]) -> None:
    """Atomically mark a mutating service JWT as consumed in shared Redis."""
    if claims is None:
        return
    redis_url = os.getenv("REDIS_URL", "").strip()
    if not redis_url:
        raise ServiceAuthError(
            "service_replay_protection_unavailable",
            "Internal service replay protection is temporarily unavailable.",
            503,
        )
    try:
        import redis

        with _redis_client_lock:
            client = _redis_clients.get(redis_url)
            if client is None:
                client = redis.from_url(
                    redis_url,
                    socket_connect_timeout=1,
                    socket_timeout=1,
                    decode_responses=True,
                )
                _redis_clients[redis_url] = client
        lifetime = int(claims["_verified_lifetime_seconds"])
        ttl = max(1, min(lifetime + 30, int(claims["exp"]) - int(time.time()) + 30))
        if not client.set(
            f"pesaguard:service-jwt:replay:{claims['jti']}",
            "1",
            nx=True,
            ex=ttl,
        ):
            raise ServiceAuthError(
                "service_token_replayed",
                "The internal service token has already been used.",
                401,
            )
    except ServiceAuthError:
        raise
    except Exception as exc:
        raise ServiceAuthError(
            "service_replay_protection_unavailable",
            "Internal service replay protection is temporarily unavailable.",
            503,
        ) from exc


def reset_internal_service_auth_caches() -> None:
    """Reset process-local caches; exposed for deterministic tests."""
    global _unknown_kid_refresh_at

    with _jwks_cache_lock:
        _jwks_cache.clear()
        _jwks_cache.update(expires_at=0.0, keys={})
        _unknown_kid_refresh_at = 0.0
    with _redis_client_lock:
        _redis_clients.clear()
