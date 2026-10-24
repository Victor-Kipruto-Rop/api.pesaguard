"""Tenant-scoped, read-only endpoints for registry evidence lookup."""
from __future__ import annotations

import logging
import uuid
from typing import Any, Callable

from flask import Blueprint, g, jsonify, request
from sqlalchemy import select

from auth_rbac import get_current_user, require_auth
from models import Organization
from pesaguard_backend_pipeline.registry_datasource_client import (
    DatasourceContractError,
    DatasourceNotConfigured,
    DatasourceUnavailable,
    RegistryDatasourceClient,
)

logger = logging.getLogger("pesaguard.registry_datasource")


def create_registry_datasource_blueprint(session_factory: Callable[[], Any]) -> Blueprint:
    bp = Blueprint("registry_datasource", __name__)

    @bp.post("/api/v1/organizations/<organization_id>/registry-lookup")
    @require_auth("read:settings")
    def lookup_registry_evidence(organization_id: str):
        user = get_current_user()
        tenant_id = str(getattr(user, "tenant_id", "") or "").strip()
        if not tenant_id:
            return jsonify({"error": "tenant_context_required"}), 403

        correlation_id = (
            request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )[:100]
        g.correlation_id = correlation_id

        with session_factory() as session:
            organization = session.scalar(
                select(Organization).where(
                    Organization.id == organization_id,
                    Organization.tenant_id == tenant_id,
                )
            )
        if organization is None:
            return jsonify({"error": "organization_not_found", "correlation_id": correlation_id}), 404

        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"error": "invalid_request", "message": "A JSON object is required.",
                            "correlation_id": correlation_id}), 400
        registration_number = body.get("registration_number")
        tax_pin = body.get("tax_pin")
        if registration_number is not None and not isinstance(registration_number, str):
            return jsonify({"error": "invalid_request", "message": "registration_number must be a string.",
                            "correlation_id": correlation_id}), 400
        if tax_pin is not None and not isinstance(tax_pin, str):
            return jsonify({"error": "invalid_request", "message": "tax_pin must be a string.",
                            "correlation_id": correlation_id}), 400
        if bool((registration_number or "").strip()) == bool((tax_pin or "").strip()):
            return jsonify({"error": "invalid_request",
                            "message": "Provide exactly one registration_number or tax_pin.",
                            "correlation_id": correlation_id}), 422

        try:
            result = RegistryDatasourceClient().lookup(
                registration_number=registration_number,
                tax_pin=tax_pin,
                correlation_id=correlation_id,
            )
        except DatasourceNotConfigured:
            logger.warning("registry_datasource_not_configured correlation_id=%s", correlation_id)
            return jsonify({"error": "registry_datasource_not_configured",
                            "message": "Registry lookup is not configured for this environment.",
                            "correlation_id": correlation_id}), 503
        except DatasourceUnavailable:
            logger.warning("registry_datasource_unavailable correlation_id=%s", correlation_id)
            return jsonify({"error": "registry_datasource_unavailable",
                            "message": "Registry lookup is temporarily unavailable.",
                            "correlation_id": correlation_id}), 503
        except DatasourceContractError:
            logger.error("registry_datasource_contract_error correlation_id=%s", correlation_id)
            return jsonify({"error": "registry_datasource_invalid_response",
                            "message": "Registry lookup returned an invalid response.",
                            "correlation_id": correlation_id}), 502

        record = result.get("organization")
        if isinstance(record, dict):
            # Do not return tax PINs or unbounded raw provider payloads to browsers.
            record = {key: value for key, value in record.items() if key not in {"tax_pin", "registry_payload"}}
        return jsonify({
            "organization_id": organization_id,
            "correlation_id": correlation_id,
            "found": result["found"],
            "match_type": result.get("match_type"),
            "source": result.get("source", "internal_registry"),
            "last_imported_at": result.get("last_imported_at"),
            "organization": record,
            "evidence_only": True,
            "verification_note": "This lookup does not verify, approve, reject, or activate the organization.",
        }), 200

    return bp
