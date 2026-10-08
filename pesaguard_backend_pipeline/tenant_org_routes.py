from __future__ import annotations

from typing import Any, Dict, Optional

from flask import Blueprint, g, jsonify, request
from auth_rbac import AuthRBAC, get_current_user, require_auth
from tenant_organization_service import (
    OrganizationOwnerNotFound,
    TenantOrganizationService,
)
from models import Organization, OrganizationApproval, OrganizationMembership, Department, Team

bp = Blueprint("tenant_org_routes", __name__, url_prefix="/api/v1")
service = None


def _resolve_session_factory():
    """Resolve the active session factory lazily to avoid import-order and circular dependency issues."""
    try:
        import app_2  # local import to avoid import cycles during app bootstrap
        session_factory = getattr(app_2, "SessionLocal", None)
    except ImportError as exc:
        raise RuntimeError("The application session factory is unavailable") from exc
    if session_factory is None:
        raise RuntimeError("The application session factory is unavailable")
    return session_factory


def _get_service() -> TenantOrganizationService:
    global service
    if service is None:
        service = TenantOrganizationService(session_factory=_resolve_session_factory())
    return service


def _tenant_scope() -> Optional[str]:
    user = get_current_user()
    if user and getattr(user, "tenant_id", None):
        return str(user.tenant_id)
    raise PermissionError("authenticated tenant context is required")


@bp.route("/organizations", methods=["GET"])
@require_auth("read:settings")
def list_organizations():
    tenant_id = _tenant_scope()
    session = _resolve_session_factory()()
    try:
        rows = session.query(Organization).filter_by(tenant_id=tenant_id).all()
        return jsonify({"items": [{
            "id": row.id,
            "tenant_id": row.tenant_id,
            "name": row.name,
            "slug": row.slug,
            "owner_user_id": row.owner_user_id,
            "status": row.status,
            "settings": row.settings,
        } for row in rows]}), 200
    finally:
        session.close()


@bp.route("/organizations", methods=["POST"])
@require_auth("manage:organizations")
def create_organization():
    payload = request.get_json(silent=True) or {}
    tenant_id = _tenant_scope()
    owner_user_id = payload.get("owner_user_id")
    if owner_user_id is None:
        owner_user_id = str(get_current_user().user_id)
    elif not isinstance(owner_user_id, str) or not owner_user_id.strip():
        return jsonify({"error": "invalid_owner"}), 400
    try:
        org = _get_service().create_organization(
            name=payload.get("name"),
            tenant_id=tenant_id,
            owner_user_id=owner_user_id.strip(),
            settings=payload.get("settings") or {},
        )
    except OrganizationOwnerNotFound:
        return jsonify({"error": "owner_not_found"}), 404
    return jsonify({"status": "created", "organization": org}), 201


@bp.route("/organizations/<organization_id>", methods=["GET", "PATCH"])
@require_auth("read:settings")
def organization_detail(organization_id: str):
    session = _resolve_session_factory()()
    try:
        org = session.query(Organization).filter_by(id=organization_id, tenant_id=_tenant_scope()).first()
        if org is None:
            return jsonify({"error": "not_found"}), 404
        if request.method == "PATCH":
            payload = request.get_json(silent=True) or {}
            if "name" in payload:
                org.name = payload["name"]
            if "settings" in payload:
                org.settings = payload["settings"]
            if "status" in payload:
                org.status = payload["status"]
            session.commit()
            return jsonify({"status": "updated", "organization": {
                "id": org.id,
                "tenant_id": org.tenant_id,
                "name": org.name,
                "slug": org.slug,
                "settings": org.settings,
                "status": org.status,
            }}), 200
        return jsonify({
            "id": org.id,
            "tenant_id": org.tenant_id,
            "name": org.name,
            "slug": org.slug,
            "settings": org.settings,
            "status": org.status,
        }), 200
    finally:
        session.close()


@bp.route("/organizations/<organization_id>/teams", methods=["GET", "POST"])
@require_auth("manage:teams")
def organization_teams(organization_id: str):
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        team = _get_service().create_team(organization_id, payload.get("name"), tenant_id=_tenant_scope())
        return jsonify({"status": "created", "team": team}), 201

    session = _resolve_session_factory()()
    try:
        rows = session.query(Team).filter_by(organization_id=organization_id, tenant_id=_tenant_scope()).all()
        return jsonify({"items": [{
            "id": row.id,
            "tenant_id": row.tenant_id,
            "organization_id": row.organization_id,
            "name": row.name,
            "slug": row.slug,
        } for row in rows]}), 200
    finally:
        session.close()


@bp.route("/organizations/<organization_id>/departments", methods=["GET", "POST"])
@require_auth("manage:departments")
def organization_departments(organization_id: str):
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        department = _get_service().create_department(
            organization_id,
            payload.get("name"),
            team_id=payload.get("team_id"),
            tenant_id=_tenant_scope(),
        )
        return jsonify({"status": "created", "department": department}), 201

    session = _resolve_session_factory()()
    try:
        rows = session.query(Department).filter_by(organization_id=organization_id, tenant_id=_tenant_scope()).all()
        return jsonify({"items": [{
            "id": row.id,
            "tenant_id": row.tenant_id,
            "organization_id": row.organization_id,
            "team_id": row.team_id,
            "name": row.name,
            "slug": row.slug,
        } for row in rows]}), 200
    finally:
        session.close()


@bp.route("/organizations/<organization_id>/members", methods=["POST"])
@require_auth("manage:organizations")
def add_member(organization_id: str):
    payload = request.get_json(silent=True) or {}
    membership = _get_service().add_user_to_organization(
        user_id=payload.get("user_id"),
        tenant_id=_tenant_scope(),
        organization_id=organization_id,
        team_id=payload.get("team_id"),
        department_id=payload.get("department_id"),
        role=payload.get("role", "member"),
    )
    return jsonify({"status": "added", "membership": membership}), 201


@bp.route("/organizations/<organization_id>/usage", methods=["GET"])
@require_auth("read:usage")
def usage_summary(organization_id: str):
    tenant_id = _tenant_scope()
    return jsonify(_get_service().get_usage_summary(tenant_id, organization_id)), 200


@bp.route("/organizations/<organization_id>/approvals", methods=["POST"])
@require_auth("manage:organizations")
def create_approval(organization_id: str):
    payload = request.get_json(silent=True) or {}
    session = _resolve_session_factory()()
    try:
        tenant_id = _tenant_scope()
        organization = session.query(Organization).filter_by(
            id=organization_id,
            tenant_id=tenant_id,
        ).first()
        if organization is None:
            return jsonify({"error": "not_found"}), 404

        approval = OrganizationApproval(
            id=f"approval_{__import__('uuid').uuid4().hex[:12]}",
            tenant_id=tenant_id,
            organization_id=organization_id,
            request_type=payload.get("request_type", "create"),
            requested_by=str(get_current_user().user_id),
            reason=payload.get("reason"),
            approval_metadata=payload.get("metadata") or payload.get("approval_metadata") or {},
            status="pending",
        )
        session.add(approval)
        session.commit()
        session.refresh(approval)
        return jsonify({"status": "pending", "approval": {
            "id": approval.id,
            "tenant_id": approval.tenant_id,
            "organization_id": approval.organization_id,
            "status": approval.status,
        }}), 201
    finally:
        session.close()


@bp.route("/organizations/<organization_id>/approvals/<approval_id>/review", methods=["POST"])
@require_auth("manage:organizations")
def review_approval(organization_id: str, approval_id: str):
    payload = request.get_json(silent=True) or {}
    session = _resolve_session_factory()()
    try:
        approval = session.query(OrganizationApproval).filter_by(
            id=approval_id, organization_id=organization_id, tenant_id=_tenant_scope()
        ).first()
        if approval is None:
            return jsonify({"error": "not_found"}), 404
        approval.status = payload.get("status", "approved")
        approval.approver_id = str(get_current_user().user_id)
        approval.reason = payload.get("reason") or approval.reason
        approval.reviewed_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        session.commit()
        return jsonify({"status": approval.status, "approval": {"id": approval.id, "status": approval.status}}), 200
    finally:
        session.close()
