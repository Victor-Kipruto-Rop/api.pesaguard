"""Health-check helpers shared by the web services."""

from __future__ import annotations

from environment import required_env

import logging
import os
import threading
import time
from typing import Any, Dict, Optional

import requests
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import StaticPool

logger = logging.getLogger("pesaguard.health")

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DEFAULT_DATABASE_URL = required_env("DATABASE_URL")

_environment = os.getenv("PESAGUARD_ENVIRONMENT", os.getenv("ENVIRONMENT", "development")).lower()
KAFKA_REQUIRED_FOR_OK = os.getenv(
    "PESAGUARD_HEALTH_REQUIRE_KAFKA",
    "1" if _environment == "production" else "0",
) == "1"
REDIS_REQUIRED_FOR_OK = os.getenv(
    "PESAGUARD_HEALTH_REQUIRE_REDIS",
    "1" if _environment == "production" else "0",
) == "1"

DARAJA_OAUTH_URL = os.getenv(
    "DARAJA_OAUTH_URL",
    "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
)
DARAJA_CHECK_CACHE_SECONDS = int(os.getenv("PESAGUARD_DARAJA_HEALTH_CACHE_SECONDS", "180"))


def _database_connect_args(database_url: str, timeout: int) -> Dict[str, Any]:
    if database_url.startswith("sqlite"):
        return {"check_same_thread": False}
    if database_url.startswith("postgresql"):
        return {"connect_timeout": timeout}
    return {}


_db_engines: Dict[str, Any] = {}
_db_engine_lock = threading.Lock()


def _get_or_create_engine(database_url: str, timeout: int):
    cache_key = f"{database_url}::{timeout}"
    with _db_engine_lock:
        engine = _db_engines.get(cache_key)
        if engine is None:
            engine_kwargs = {
                "pool_pre_ping": True,
                "connect_args": _database_connect_args(database_url, timeout),
            }
            if database_url.startswith("sqlite"):
                if database_url in {"sqlite://", "sqlite:///:memory:"}:
                    engine_kwargs["poolclass"] = StaticPool
            else:
                engine_kwargs.update({"pool_size": 2, "max_overflow": 0})
            engine = create_engine(database_url, **engine_kwargs)
            try:
                from metrics import instrument_engine_query_timing
                instrument_engine_query_timing(engine)
            except Exception:
                logger.debug("Health engine query timing instrumentation skipped.", exc_info=True)
            _db_engines[cache_key] = engine
        return engine


def check_database_connection(database_url: Optional[str] = None, timeout: int = 5) -> Dict[str, Any]:
    url = database_url or DEFAULT_DATABASE_URL
    try:
        engine = _get_or_create_engine(url, timeout)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "ok", "database": {"status": "ok", "type": "sql"}}
    except SQLAlchemyError as exc:
        logger.warning("Database health check failed: %s", exc)
        return {"status": "failed", "database": {"status": "failed", "error": str(exc)}}
    except Exception as exc:
        logger.exception("Unexpected error during database health check: %s", exc)
        return {"status": "failed", "database": {"status": "failed", "error": str(exc)}}


def check_kafka_connectivity(timeout: int = 5) -> Dict[str, Any]:
    try:
        from kafka import KafkaProducer
    except ImportError:
        return {"status": "failed", "kafka": {"status": "failed", "error": "kafka-python not installed"}}

    producer = None
    try:
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            request_timeout_ms=timeout * 1000,
            api_version_auto_timeout_ms=timeout * 1000,
        )
        if not producer.bootstrap_connected():
            return {"status": "failed", "kafka": {"status": "failed", "error": "unable to connect to Kafka brokers"}}
        return {"status": "ok", "kafka": {"status": "ok"}}
    except Exception as exc:
        return {"status": "failed", "kafka": {"status": "failed", "error": str(exc)}}
    finally:
        if producer is not None:
            try:
                producer.close(timeout=timeout)
            except Exception as close_exc:
                logger.debug("Error closing Kafka health-check producer: %s", close_exc)


_redis_client_cache: Dict[str, Any] = {}
_redis_client_lock = threading.Lock()


def _get_or_create_redis_client(redis_url: str, timeout: int):
    cache_key = f"{redis_url}::{timeout}"
    with _redis_client_lock:
        client = _redis_client_cache.get(cache_key)
        if client is None:
            import redis
            client = redis.from_url(redis_url, socket_connect_timeout=timeout, socket_timeout=timeout)
            _redis_client_cache[cache_key] = client
        return client


def check_redis_connectivity(timeout: int = 5) -> Dict[str, Any]:
    try:
        import redis  # noqa: F401
    except ImportError:
        return {"status": "failed", "redis": {"status": "failed", "error": "redis package not installed"}}

    try:
        _get_or_create_redis_client(REDIS_URL, timeout).ping()
        return {"status": "ok", "redis": {"status": "ok"}}
    except Exception as exc:
        with _redis_client_lock:
            _redis_client_cache.pop(f"{REDIS_URL}::{timeout}", None)
        return {"status": "failed", "redis": {"status": "failed", "error": str(exc)}}


_daraja_check_lock = threading.Lock()
_daraja_check_cache: Dict[str, Any] = {"result": None, "checked_at": 0.0}


def check_daraja_connectivity(timeout: int = 5) -> Dict[str, Any]:
    consumer_key = os.getenv("DARAJA_CONSUMER_KEY", "")
    consumer_secret = os.getenv("DARAJA_CONSUMER_SECRET", "")
    if not consumer_key or not consumer_secret:
        return {"status": "degraded", "daraja": {"status": "degraded", "reason": "credentials_not_configured"}}

    now = time.time()
    with _daraja_check_lock:
        cached = _daraja_check_cache["result"]
        if cached is not None and (now - _daraja_check_cache["checked_at"]) < DARAJA_CHECK_CACHE_SECONDS:
            return cached
        try:
            response = requests.get(DARAJA_OAUTH_URL, auth=(consumer_key, consumer_secret), timeout=timeout)
            if response.status_code == 200 and "access_token" in response.json():
                result = {"status": "ok", "daraja": {"status": "ok"}}
            else:
                result = {"status": "failed", "daraja": {"status": "failed", "error": f"unexpected response (status {response.status_code})"}}
        except Exception as exc:
            result = {"status": "failed", "daraja": {"status": "failed", "error": str(exc)}}
        _daraja_check_cache["result"] = result
        _daraja_check_cache["checked_at"] = now
        return result


def build_health_payload() -> Dict[str, Any]:
    db_result = check_database_connection()
    kafka_result = check_kafka_connectivity()
    redis_result = check_redis_connectivity()
    daraja_result = check_daraja_connectivity()

    db_ok = db_result["database"]["status"] == "ok"
    kafka_ok = kafka_result["kafka"]["status"] == "ok"
    redis_ok = redis_result["redis"]["status"] == "ok"
    daraja_ok = daraja_result["daraja"]["status"] == "ok"

    if not db_ok:
        overall_status = "failed"
    elif (kafka_ok or not KAFKA_REQUIRED_FOR_OK) and (redis_ok or not REDIS_REQUIRED_FOR_OK) and daraja_ok:
        overall_status = "ok"
    else:
        overall_status = "degraded"

    return {
        "status": overall_status,
        "service": "pesaguard",
        "checks": {
            "database": db_result["database"],
            "kafka": kafka_result["kafka"],
            "redis": redis_result["redis"],
            "daraja": daraja_result["daraja"],
        },
    }
