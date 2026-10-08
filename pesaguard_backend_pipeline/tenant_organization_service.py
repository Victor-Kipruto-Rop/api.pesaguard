from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session, sessionmaker

from models import (
    Department,
    Organization,
    OrganizationMembership,
    Team,
    TenantConfiguration,
    TenantLimit,
    TenantUsage,
    UserAccount,
)


class OrganizationOwnerNotFound(ValueError):
    """Raised when an organization owner is not active in its tenant."""


class TenantOrganizationService:
    """Multi-tenant organization service for SaaS composition, limits, and usage tracking."""

    def __init__(self, session_factory: Optional[sessionmaker] = None):
        self.session_factory = session_factory

    def _session(self) -> Session:
        if self.session_factory is None:
            raise RuntimeError("TenantOrganizationService requires a SQLAlchemy session factory.")
        return self.session_factory()

    @staticmethod
    def _slugify(value: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower())
        slug = slug.strip("-")
        return slug or "organization"

    @staticmethod
    def _serialize(obj: Any) -> Dict[str, Any]:
        if obj is None:
            return {}
        payload = {}
        for key in getattr(obj, "__mapper__", obj.__class__).c.keys():
            value = getattr(obj, key, None)
            payload[key] = value
        return payload

    def create_organization(
        self,
        name: str,
        tenant_id: str,
        owner_user_id: Optional[str] = None,
        settings: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        tenant_id = str(tenant_id or "default")
        slug = self._slugify(name)
        session = self._session()
        try:
            if owner_user_id is not None:
                owner = session.query(UserAccount).filter_by(
                    id=str(owner_user_id),
                    tenant_id=tenant_id,
                    status="active",
                ).first()
                if owner is None:
                    raise OrganizationOwnerNotFound(
                        "Organization owner not found for tenant"
                    )

            base_slug = slug
            suffix = 1
            while True:
                existing = session.query(Organization).filter_by(tenant_id=tenant_id, slug=slug).first()
                if existing is None:
                    break
                slug = f"{base_slug}-{suffix}"
                suffix += 1

            org = Organization(
                id=f"org_{uuid.uuid4().hex[:12]}",
                tenant_id=tenant_id,
                name=str(name),
                slug=slug,
                owner_user_id=owner_user_id,
                settings=settings or {},
                status="active",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(org)
            session.commit()
            session.refresh(org)
            return self._serialize(org)
        finally:
            session.close()

    def get_organization_by_slug(self, tenant_id: str, slug: str) -> Optional[Dict[str, Any]]:
        session = self._session()
        try:
            record = session.query(Organization).filter_by(tenant_id=str(tenant_id or "default"), slug=self._slugify(slug)).first()
            return None if record is None else self._serialize(record)
        finally:
            session.close()

    def create_team(self, organization_id: str, name: str, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        session = self._session()
        try:
            requested_tenant_id = str(tenant_id or "")
            org_query = session.query(Organization).filter_by(id=organization_id)
            if requested_tenant_id:
                org_query = org_query.filter_by(tenant_id=requested_tenant_id)
            org = org_query.first()
            if org is None:
                raise ValueError(f"Organization {organization_id} not found")
            resolved_tenant_id = org.tenant_id
            slug = self._slugify(name)
            team = Team(
                id=f"team_{uuid.uuid4().hex[:12]}",
                tenant_id=resolved_tenant_id,
                organization_id=organization_id,
                name=str(name),
                slug=slug,
                created_at=datetime.now(timezone.utc),
            )
            session.add(team)
            session.commit()
            session.refresh(team)
            return self._serialize(team)
        finally:
            session.close()

    def create_department(
        self,
        organization_id: str,
        name: str,
        team_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        session = self._session()
        try:
            requested_tenant_id = str(tenant_id or "")
            org_query = session.query(Organization).filter_by(id=organization_id)
            if requested_tenant_id:
                org_query = org_query.filter_by(tenant_id=requested_tenant_id)
            org = org_query.first()
            if org is None:
                raise ValueError(f"Organization {organization_id} not found")
            resolved_tenant_id = org.tenant_id
            if team_id:
                team = session.query(Team).filter_by(id=team_id, organization_id=organization_id, tenant_id=resolved_tenant_id).first()
                if team is None:
                    raise ValueError(f"Team {team_id} not found for organization {organization_id}")
            dep = Department(
                id=f"dept_{uuid.uuid4().hex[:12]}",
                tenant_id=resolved_tenant_id,
                organization_id=organization_id,
                team_id=team_id,
                name=str(name),
                slug=self._slugify(name),
                created_at=datetime.now(timezone.utc),
            )
            session.add(dep)
            session.commit()
            session.refresh(dep)
            return self._serialize(dep)
        finally:
            session.close()

    def add_user_to_organization(
        self,
        user_id: str,
        tenant_id: str,
        organization_id: str,
        team_id: Optional[str] = None,
        department_id: Optional[str] = None,
        role: str = "member",
    ) -> Dict[str, Any]:
        session = self._session()
        try:
            org = session.query(Organization).filter_by(id=organization_id, tenant_id=str(tenant_id or "default")).first()
            if org is None:
                raise ValueError(f"Organization {organization_id} not found for tenant {tenant_id}")
            user = session.query(UserAccount).filter_by(id=str(user_id), tenant_id=str(tenant_id or "default"), status="active").first()
            if user is None:
                raise ValueError(f"User {user_id} not found for tenant {tenant_id}")
            if team_id:
                team = session.query(Team).filter_by(id=team_id, organization_id=organization_id, tenant_id=str(tenant_id or "default")).first()
                if team is None:
                    raise ValueError(f"Team {team_id} not found for organization {organization_id}")
            if department_id:
                department = session.query(Department).filter_by(id=department_id, organization_id=organization_id, tenant_id=str(tenant_id or "default")).first()
                if department is None:
                    raise ValueError(f"Department {department_id} not found for organization {organization_id}")

            membership = OrganizationMembership(
                id=f"member_{uuid.uuid4().hex[:12]}",
                tenant_id=str(tenant_id or "default"),
                user_id=str(user_id),
                organization_id=organization_id,
                team_id=team_id,
                department_id=department_id,
                role=str(role),
                active=True,
                created_at=datetime.now(timezone.utc),
            )
            session.add(membership)
            session.commit()
            session.refresh(membership)
            return self._serialize(membership)
        finally:
            session.close()

    def upsert_tenant_configuration(self, tenant_id: str, config_patch: Dict[str, Any]) -> Dict[str, Any]:
        tenant_id = str(tenant_id or "default")
        session = self._session()
        try:
            config_row = session.query(TenantConfiguration).filter_by(tenant_id=tenant_id).first()
            if config_row is None:
                config_row = TenantConfiguration(
                    id=f"cfg_{uuid.uuid4().hex[:12]}",
                    tenant_id=tenant_id,
                    organization_id=None,
                    config={},
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                session.add(config_row)

            merged = dict(config_row.config or {})
            merged.update(config_patch or {})
            config_row.config = merged
            config_row.updated_at = datetime.now(timezone.utc)
            session.commit()
            session.refresh(config_row)
            return self._serialize(config_row)
        finally:
            session.close()

    def set_limit(self, tenant_id: str, organization_id: str, metric_name: str, limit_value: float, period: str = "monthly") -> Dict[str, Any]:
        session = self._session()
        try:
            row = session.query(TenantLimit).filter_by(
                tenant_id=str(tenant_id or "default"),
                organization_id=str(organization_id),
                metric_name=str(metric_name),
                period=str(period),
            ).first()
            if row is None:
                row = TenantLimit(
                    id=f"limit_{uuid.uuid4().hex[:12]}",
                    tenant_id=str(tenant_id or "default"),
                    organization_id=str(organization_id),
                    metric_name=str(metric_name),
                    limit_value=float(limit_value),
                    period=str(period),
                    created_at=datetime.now(timezone.utc),
                )
                session.add(row)
            else:
                row.limit_value = float(limit_value)
            session.commit()
            session.refresh(row)
            return self._serialize(row)
        finally:
            session.close()

    def record_usage(self, tenant_id: str, organization_id: str, metric_name: str, delta: float, period: str = "monthly") -> Dict[str, Any]:
        session = self._session()
        try:
            row = session.query(TenantUsage).filter_by(
                tenant_id=str(tenant_id or "default"),
                organization_id=str(organization_id),
                metric_name=str(metric_name),
                period=str(period),
            ).first()
            if row is None:
                row = TenantUsage(
                    id=f"usage_{uuid.uuid4().hex[:12]}",
                    tenant_id=str(tenant_id or "default"),
                    organization_id=str(organization_id),
                    metric_name=str(metric_name),
                    period=str(period),
                    current_usage=0.0,
                    updated_at=datetime.now(timezone.utc),
                )
                session.add(row)

            row.current_usage = float(row.current_usage or 0.0) + float(delta or 0.0)
            row.updated_at = datetime.now(timezone.utc)
            session.commit()
            session.refresh(row)
            return self._serialize(row)
        finally:
            session.close()

    def check_limit(self, tenant_id: str, organization_id: str, metric_name: str, requested_value: float = 0.0, period: str = "monthly") -> bool:
        session = self._session()
        try:
            limit_row = session.query(TenantLimit).filter_by(
                tenant_id=str(tenant_id or "default"),
                organization_id=str(organization_id),
                metric_name=str(metric_name),
                period=str(period),
            ).first()
            if limit_row is None:
                return True

            usage_row = session.query(TenantUsage).filter_by(
                tenant_id=str(tenant_id or "default"),
                organization_id=str(organization_id),
                metric_name=str(metric_name),
                period=str(period),
            ).first()
            current_usage = float((usage_row.current_usage if usage_row else 0.0) or 0.0)
            return (current_usage + float(requested_value or 0.0)) <= float(limit_row.limit_value)
        finally:
            session.close()

    def get_usage_summary(self, tenant_id: str, organization_id: str) -> Dict[str, Any]:
        session = self._session()
        try:
            config_row = session.query(TenantConfiguration).filter_by(tenant_id=str(tenant_id or "default")).first()
            usage_rows = session.query(TenantUsage).filter_by(
                tenant_id=str(tenant_id or "default"),
                organization_id=str(organization_id),
            ).all()
            limit_rows = session.query(TenantLimit).filter_by(
                tenant_id=str(tenant_id or "default"),
                organization_id=str(organization_id),
            ).all()

            usage_payload = {
                row.metric_name: {
                    "metric_name": row.metric_name,
                    "current_usage": float(row.current_usage or 0.0),
                    "period": row.period,
                    "updated_at": row.updated_at.isoformat() if row.updated_at else None,
                }
                for row in usage_rows
            }
            limits_payload = {
                row.metric_name: {
                    "metric_name": row.metric_name,
                    "limit_value": float(row.limit_value),
                    "period": row.period,
                }
                for row in limit_rows
            }
            return {
                "tenant_id": str(tenant_id or "default"),
                "organization_id": str(organization_id),
                "config": (config_row.config if config_row else {}),
                "limits": limits_payload,
                "usage": usage_payload,
            }
        finally:
            session.close()
