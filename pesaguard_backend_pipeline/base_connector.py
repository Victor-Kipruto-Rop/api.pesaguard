"""
Enterprise-grade base interface and connectors for internal ledger/order systems.

Supports multi-tenant Postgres databases, REST API ledgers, and Google Sheets integrations
with automatic retry backoff, SQL identifier sanitization, and normalized schema parsing.
"""

from __future__ import annotations

import json
import logging
import os
import re
from decimal import Decimal
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from sqlalchemy import create_engine, text

logger = logging.getLogger("pesaguard.connectors")

# Defense-in-depth SQL identifier allowlist validation
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_identifier(name: str, kind: str) -> str:
    """Validate database object identifiers to prevent SQL injection during interpolation."""
    if not name or not _SAFE_IDENTIFIER.match(name):
        raise ValueError(
            f"Unsafe {kind} identifier rejected: {name!r}. Must contain only ASCII letters, "
            f"digits, and underscores, and must not start with a digit."
        )
    return name


class BaseConnector(ABC):
    """
    Abstract Base Class for all internal order/ledger connectors.
    
    All connectors must yield records matching the normalized PesaGuard ledger shape:
    {
        "internal_ref": str,        # Order/Invoice ID in the customer's ledger system
        "amount": float,            # Expected monetary amount
        "phone_number": str,        # Payer phone number
        "timestamp": str,           # ISO8601 UTC timestamp
        "status": str,              # Status (e.g. "pending", "paid", "failed")
    }
    """

    @abstractmethod
    def fetch_recent_records(self, since_minutes: int = 15) -> Iterable[Dict[str, Any]]:
        """Return internal records created or modified within the last N minutes."""
        raise NotImplementedError

    def fetch_candidate_records(
        self,
        since_minutes: int = 15,
        amount: Optional[Decimal] = None,
        phone_number: Optional[str] = None,
        tolerance: Optional[Decimal] = None,
        limit: int = 500,
    ) -> Iterable[Dict[str, Any]]:
        """Return a bounded candidate set; non-SQL connectors use a capped fallback."""
        return list(self.fetch_recent_records(since_minutes=since_minutes))[:max(1, min(limit, 5000))]


# Default field mapping for internal ledger columns
_DEFAULT_MAPPING: Dict[str, str] = {
    "internal_ref": "internal_ref",
    "amount": "amount",
    "phone_number": "phone_number",
    "timestamp": "created_at",
    "status": "status",
}


def _merge_mapping(defaults: Dict[str, str], override: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Merge custom column mappings safely over default field keys."""
    merged = dict(defaults)
    if override:
        merged.update(override)
    return merged


class PostgresConnector(BaseConnector):
    """Connector for pilot customers whose internal orders live in PostgreSQL."""

    def __init__(self, connection_string: str, table_name: str = "orders", mapping: Optional[Dict[str, str]] = None):
        self.connection_string = connection_string
        self.table_name = table_name
        self.mapping = _merge_mapping(_DEFAULT_MAPPING, mapping)
        self._engine = None

    def _get_engine(self):
        """Lazy-initialize a single connection pool per connector instance."""
        if self._engine is None:
            if not self.connection_string:
                raise ValueError("PostgresConnector requires a valid database connection string.")
            self._engine = create_engine(
                self.connection_string,
                pool_pre_ping=True,
                pool_size=int(os.getenv("CONNECTOR_DB_POOL_SIZE", "5")),
                max_overflow=int(os.getenv("CONNECTOR_DB_MAX_OVERFLOW", "10")),
            )
        return self._engine

    def fetch_recent_records(self, since_minutes: int = 15) -> List[Dict[str, Any]]:
        """Query recent internal transactions from Postgres safely."""
        if not self.connection_string:
            logger.warning("PostgresConnector execution skipped: Connection string is empty.")
            return []

    def fetch_candidate_records(
        self,
        since_minutes: int = 15,
        amount: Optional[Decimal] = None,
        phone_number: Optional[str] = None,
        tolerance: Optional[Decimal] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Push bounded candidate filtering into PostgreSQL before Python scoring."""
        if not self.connection_string:
            return []
        try:
            safe_table = _validate_identifier(self.table_name, "table")
            safe_columns = {k: _validate_identifier(v, f"column mapping for '{k}'") for k, v in self.mapping.items()}
            engine = self._get_engine()
            since_dt = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
            conditions = [f"{safe_columns['timestamp']} >= :since"]
            params: Dict[str, Any] = {"since": since_dt, "limit": max(1, min(limit, 5000))}
            if amount is not None and tolerance is not None:
                conditions.append(f"{safe_columns['amount']} BETWEEN :lower_amount AND :upper_amount")
                params["lower_amount"] = max(Decimal("0"), amount - tolerance)
                params["upper_amount"] = amount + tolerance
            if phone_number:
                conditions.append(f"{safe_columns['phone_number']} = :phone_number")
                params["phone_number"] = phone_number
            query = text(
                f"SELECT {safe_columns['internal_ref']}, {safe_columns['amount']}, {safe_columns['phone_number']}, "  # nosec B608: all identifiers pass _validate_identifier; values are bound below.
                f"{safe_columns['timestamp']}, {safe_columns['status']} FROM {safe_table} "
                f"WHERE {' AND '.join(conditions)} ORDER BY {safe_columns['timestamp']} DESC LIMIT :limit"
            )
            with engine.connect() as connection:
                rows = connection.execute(query, params).fetchall()
            return [{
                "internal_ref": str(row[0]),
                "amount": row[1],
                "phone_number": str(row[2] or ""),
                "timestamp": row[3].isoformat() if hasattr(row[3], "isoformat") else str(row[3]),
                "status": str(row[4] or "pending"),
            } for row in rows]
        except Exception as exc:
            logger.exception("Failed fetching bounded ledger candidates: %s", exc)
            return []

        try:
            safe_table = _validate_identifier(self.table_name, "table")
            safe_columns = {k: _validate_identifier(v, f"column mapping for '{k}'") for k, v in self.mapping.items()}
        except ValueError as exc:
            logger.error("PostgresConnector query aborted due to invalid identifier: %s", exc)
            return []

        try:
            engine = self._get_engine()
            since_time = datetime.now(timezone.utc).timestamp() - (since_minutes * 60)
            since_dt = datetime.fromtimestamp(since_time, tz=timezone.utc)

            query = text(
                f"SELECT {safe_columns['internal_ref']}, {safe_columns['amount']}, {safe_columns['phone_number']}, "  # nosec B608: all identifiers pass _validate_identifier; values are bound below.
                f"{safe_columns['timestamp']}, {safe_columns['status']} "
                f"FROM {safe_table} WHERE {safe_columns['timestamp']} >= :since"
            )

            with engine.connect() as connection:
                rows = connection.execute(query, {"since": since_dt}).fetchall()

            records = []
            for row in rows:
                raw_ts = row[3]
                formatted_ts = raw_ts.isoformat() if hasattr(raw_ts, "isoformat") else str(raw_ts)
                records.append({
                    "internal_ref": str(row[0]),
                    "amount": float(row[1]) if row[1] is not None else 0.0,
                    "phone_number": str(row[2] or ""),
                    "timestamp": formatted_ts,
                    "status": str(row[4] or "pending"),
                })
            
            logger.info("Fetched %d internal records from Postgres table '%s'", len(records), safe_table)
            return records

        except Exception as exc:
            logger.exception("Failed fetching records from Postgres connector: %s", exc)
            return []


class GoogleSheetsConnector(BaseConnector):
    """Production-ready Google Sheets ledger connector using Service Account Auth."""

    def __init__(
        self,
        sheet_id: str,
        worksheet_name: str = "Orders",
        credentials_json: Optional[str] = None,
        mapping: Optional[Dict[str, str]] = None,
    ):
        self.sheet_id = sheet_id
        self.worksheet_name = worksheet_name
        self.credentials_json = credentials_json or os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", "")
        self.mapping = _merge_mapping(_DEFAULT_MAPPING, mapping)
        self._client = None

    def _get_client(self):
        """Initialize gspread client with Service Account credentials."""
        if self._client is not None:
            return self._client

        if not self.credentials_json:
            raise ValueError("GoogleSheetsConnector requires Service Account JSON credentials.")

        try:
            import gspread
            from google.oauth2.service_account import Credentials

            scopes = ["https://www.googleapis.com/auth/spreadsheets.readonly"]
            if self.credentials_json.startswith("{"):
                cred_dict = json.loads(self.credentials_json)
                creds = Credentials.from_service_account_info(cred_dict, scopes=scopes)
            else:
                creds = Credentials.from_service_account_file(self.credentials_json, scopes=scopes)

            self._client = gspread.authorize(creds)
            return self._client
        except ImportError:
            logger.error("gspread or google-auth package is not installed.")
            raise RuntimeError("Missing required dependencies: 'gspread' and 'google-auth'.")

    def fetch_recent_records(self, since_minutes: int = 15) -> List[Dict[str, Any]]:
        """Fetch and parse records from the designated Google Sheet worksheet."""
        if not self.sheet_id:
            logger.warning("GoogleSheetsConnector skipped: sheet_id is empty.")
            return []

        try:
            client = self._get_client()
            sheet = client.open_by_key(self.sheet_id)
            worksheet = sheet.worksheet(self.worksheet_name)
            rows = worksheet.get_all_records()

            records = []
            now_ts = datetime.now(timezone.utc).timestamp()
            cutoff_ts = now_ts - (since_minutes * 60)

            ref_col = self.mapping["internal_ref"]
            amount_col = self.mapping["amount"]
            phone_col = self.mapping["phone_number"]
            time_col = self.mapping["timestamp"]
            status_col = self.mapping["status"]

            for row in rows:
                raw_time = str(row.get(time_col, "")).strip()
                record_dt = None

                # Parse timestamp formats safely
                if raw_time:
                    try:
                        record_dt = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                    except ValueError:
                        pass

                if record_dt and record_dt.timestamp() < cutoff_ts:
                    continue

                records.append({
                    "internal_ref": str(row.get(ref_col, "")),
                    "amount": float(row.get(amount_col, 0) or 0),
                    "phone_number": str(row.get(phone_col, "")),
                    "timestamp": record_dt.isoformat() if record_dt else raw_time,
                    "status": str(row.get(status_col, "pending")),
                })

            logger.info("Fetched %d internal records from Google Sheet '%s'", len(records), self.sheet_id)
            return records

        except Exception as exc:
            logger.exception("Failed to fetch Google Sheets records: %s", exc)
            return []


class RestConnector(BaseConnector):
    """Robust REST API ledger connector with exponential retries and error handling."""

    def __init__(
        self,
        endpoint: str,
        auth_type: str = "api_key",
        auth_value: str = "",
        mapping: Optional[Dict[str, str]] = None,
        timeout_seconds: int = 10,
    ):
        self.endpoint = endpoint
        self.auth_type = auth_type
        self.auth_value = auth_value
        self.timeout_seconds = timeout_seconds
        self.mapping = _merge_mapping(
            {"internal_ref": "id", "amount": "amount", "phone_number": "phone", "timestamp": "created_at", "status": "status"},
            mapping,
        )
        self._session = self._build_http_session()

    def _build_http_session(self) -> requests.Session:
        """Construct an HTTP session with automated retry logic on transient errors."""
        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def fetch_recent_records(self, since_minutes: int = 15) -> List[Dict[str, Any]]:
        """Execute REST query to retrieve recent order payload."""
        if not self.endpoint:
            logger.warning("REST connector execution skipped: Endpoint URL is empty.")
            return []

        headers = {"Accept": "application/json"}
        if self.auth_type == "bearer" and self.auth_value:
            headers["Authorization"] = f"Bearer {self.auth_value}"
        elif self.auth_type == "api_key" and self.auth_value:
            headers["X-API-Key"] = self.auth_value

        params = {"since_minutes": since_minutes}

        try:
            response = self._session.get(
                self.endpoint,
                headers=headers,
                params=params,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()

            payload = response.json()
            items = payload.get("items", payload) if isinstance(payload, dict) else payload

            if not isinstance(items, list):
                logger.error("REST connector expected list payload, got: %s", type(items))
                return []

            records = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                records.append({
                    "internal_ref": str(item.get(self.mapping["internal_ref"], "")),
                    "amount": float(item.get(self.mapping["amount"], 0) or 0),
                    "phone_number": str(item.get(self.mapping["phone_number"], "")),
                    "timestamp": str(item.get(self.mapping["timestamp"], "")),
                    "status": str(item.get(self.mapping["status"], "pending")),
                })

            logger.info("Fetched %d internal records via REST connector from %s", len(records), self.endpoint)
            return records

        except requests.RequestException as exc:
            logger.error("REST connector HTTP request failed for %s: %s", self.endpoint, exc)
            return []
        except Exception as exc:
            logger.exception("Unexpected error processing REST connector response: %s", exc)
            return []


class ConnectorRegistry:
    """Multi-tenant connector registry supporting dynamic per-tenant configuration."""

    def __init__(self, connectors: Optional[Dict[str, BaseConnector]] = None):
        self.connectors: Dict[str, BaseConnector] = connectors or {}

    @classmethod
    def from_env(cls) -> "ConnectorRegistry":
        """Build connector registry initialized from active environment configuration."""
        connector_type = os.getenv("CONNECTOR_TYPE", "postgres").lower()
        tenant_id = os.getenv("TENANT_ID", "default")

        connector: Optional[BaseConnector] = None

        if connector_type == "postgres":
            connector = PostgresConnector(
                connection_string=os.getenv("DATABASE_URL", ""),
                table_name=os.getenv("INTERNAL_RECORDS_TABLE", "orders"),
                mapping=json.loads(os.getenv("POSTGRES_MAPPING", "{}")) if os.getenv("POSTGRES_MAPPING") else None,
            )
        elif connector_type == "google_sheets":
            connector = GoogleSheetsConnector(
                sheet_id=os.getenv("GOOGLE_SHEET_ID", ""),
                worksheet_name=os.getenv("GOOGLE_SHEET_WORKSHEET", "Orders"),
                credentials_json=os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", ""),
            )
        elif connector_type == "rest":
            connector = RestConnector(
                endpoint=os.getenv("REST_CONNECTOR_ENDPOINT", ""),
                auth_type=os.getenv("REST_CONNECTOR_AUTH_TYPE", "api_key"),
                auth_value=os.getenv("REST_CONNECTOR_AUTH_VALUE", ""),
                mapping=json.loads(os.getenv("REST_MAPPING", "{}")) if os.getenv("REST_MAPPING") else None,
            )

        return cls({tenant_id: connector}) if connector else cls({})

    def get_connector(self, tenant_id: str) -> Optional[BaseConnector]:
        """Retrieve the configured connector instance for a tenant."""
        return self.connectors.get(tenant_id)
