from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, UserAccount
from tenant_organization_service import TenantOrganizationService


def _build_service():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return TenantOrganizationService(session_factory=sessionmaker(bind=engine, expire_on_commit=False))


def test_organization_service_supports_tenant_scoped_orgs_and_teams():
    service = _build_service()
    with service._session() as session:
        session.add(UserAccount(
            id="user-1",
            username="user-1",
            tenant_id="tenant-a",
            roles=["owner"],
            permissions=[],
            status="active",
        ))
        session.add(UserAccount(
            id="user-2",
            username="user-2",
            tenant_id="tenant-a",
            roles=["operator"],
            permissions=[],
            status="active",
        ))
        session.commit()

    org = service.create_organization(
        name="Acme Finance",
        tenant_id="tenant-a",
        owner_user_id="user-1",
        settings={"region": "eu-west-1"},
    )
    team = service.create_team(org["id"], "Finance", tenant_id="tenant-a")
    department = service.create_department(org["id"], "Treasury", team_id=team["id"], tenant_id="tenant-a")

    membership = service.add_user_to_organization(
        user_id="user-2",
        tenant_id="tenant-a",
        organization_id=org["id"],
        team_id=team["id"],
        department_id=department["id"],
        role="manager",
    )

    assert org["tenant_id"] == "tenant-a"
    assert team["tenant_id"] == "tenant-a"
    assert department["tenant_id"] == "tenant-a"
    assert membership["tenant_id"] == "tenant-a"
    assert membership["role"] == "manager"
    assert service.get_organization_by_slug("tenant-a", "acme-finance") is not None
    assert service.get_organization_by_slug("tenant-b", "acme-finance") is None


def test_organization_service_tracks_configuration_limits_and_usage():
    service = _build_service()
    org = service.create_organization("Northwind", tenant_id="tenant-a")

    service.upsert_tenant_configuration("tenant-a", {"data_residency": "eu", "feature_flags": {"alerting": True}})
    service.set_limit("tenant-a", org["id"], "api_requests", 3, "monthly")

    assert service.record_usage("tenant-a", org["id"], "api_requests", 1)["current_usage"] == 1
    assert service.check_limit("tenant-a", org["id"], "api_requests", 2) is True

    service.record_usage("tenant-a", org["id"], "api_requests", 2)
    assert service.check_limit("tenant-a", org["id"], "api_requests", 1) is False

    summary = service.get_usage_summary("tenant-a", org["id"])
    assert summary["usage"]["api_requests"]["current_usage"] == 3
    assert summary["config"]["data_residency"] == "eu"


def test_organization_owner_must_belong_to_the_same_tenant():
    service = _build_service()
    with service._session() as session:
        session.add(UserAccount(
            id="user-b",
            username="user-b",
            tenant_id="tenant-b",
            roles=["owner"],
            permissions=[],
            status="active",
        ))
        session.commit()

    try:
        service.create_organization(
            "Cross Tenant Owner",
            tenant_id="tenant-a",
            owner_user_id="user-b",
        )
    except ValueError as error:
        assert str(error) == "Organization owner not found for tenant"
    else:
        raise AssertionError("cross-tenant organization owner was accepted")
