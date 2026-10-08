"""Add canonical platform, tenant, service, client, external identity, and RBAC tables."""

from alembic import op
import sqlalchemy as sa


revision = "20260925_add_iam_foundation"
down_revision = "20260923_add_transaction_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "iam_platforms",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("slug", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("attributes", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("slug", name="uq_iam_platform_slug"),
        sa.CheckConstraint("status IN ('active', 'suspended', 'decommissioned')", name="ck_iam_platform_status"),
    )
    op.create_table(
        "iam_tenants",
        sa.Column("tenant_id", sa.String(), primary_key=True),
        sa.Column("platform_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("slug", sa.String(length=128), nullable=False),
        sa.Column("owner_user_id", sa.String(), nullable=True),
        sa.Column("residency_region", sa.String(length=64), nullable=False, server_default="ke-central"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="provisioning"),
        sa.Column("attributes", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("platform_id", "slug", name="uq_iam_tenant_platform_slug"),
        sa.CheckConstraint("status IN ('provisioning', 'active', 'suspended', 'deleting', 'deleted')", name="ck_iam_tenant_status"),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_iam_tenant_identity_nonempty"),
    )
    op.create_index("ix_iam_tenants_platform_status", "iam_tenants", ["platform_id", "status"])
    op.create_table(
        "iam_service_identities",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("identity_type", sa.String(length=32), nullable=False, server_default="service"),
        sa.Column("owner_user_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("scopes", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("attributes", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("authorization_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "name", name="uq_iam_service_identity_tenant_name"),
        sa.CheckConstraint("status IN ('active', 'suspended', 'revoked', 'decommissioned')", name="ck_iam_service_identity_status"),
        sa.CheckConstraint("identity_type IN ('service', 'workload', 'machine')", name="ck_iam_service_identity_type"),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_iam_service_identity_tenant_nonempty"),
    )
    op.create_index("ix_iam_service_identity_scope_status", "iam_service_identities", ["tenant_id", "status"])
    op.create_table(
        "iam_api_clients",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("client_identifier", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("client_type", sa.String(length=32), nullable=False, server_default="confidential"),
        sa.Column("service_identity_id", sa.String(), nullable=True),
        sa.Column("owner_user_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("scopes", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("redirect_uris", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("attributes", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "client_identifier", name="uq_iam_api_client_identifier"),
        sa.CheckConstraint("status IN ('active', 'suspended', 'revoked', 'expired')", name="ck_iam_api_client_status"),
        sa.CheckConstraint("client_type IN ('confidential', 'public', 'service')", name="ck_iam_api_client_type"),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_iam_api_client_tenant_nonempty"),
    )
    op.create_index("ix_iam_api_client_tenant_status", "iam_api_clients", ["tenant_id", "status"])
    op.create_table(
        "iam_external_identities",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("provider_id", sa.String(), nullable=True),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("subject", sa.String(length=512), nullable=False),
        sa.Column("email", sa.String(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("claims", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "issuer", "subject", name="uq_iam_external_identity_subject"),
        sa.CheckConstraint("status IN ('active', 'disabled', 'unlinked')", name="ck_iam_external_identity_status"),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_iam_external_identity_tenant_nonempty"),
    )
    op.create_index("ix_iam_external_identity_user", "iam_external_identities", ["tenant_id", "user_id"])
    op.create_table(
        "iam_roles",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("managed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "name", name="uq_iam_role_tenant_name"),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_iam_role_tenant_nonempty"),
    )
    op.create_table(
        "iam_permissions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("resource", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("name", name="uq_iam_permission_name"),
    )
    op.create_table(
        "iam_role_permissions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("role_id", sa.String(), nullable=False),
        sa.Column("permission_id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("role_id", "permission_id", name="uq_iam_role_permission"),
    )
    op.create_table(
        "iam_role_bindings",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("subject_type", sa.String(length=32), nullable=False),
        sa.Column("subject_id", sa.String(), nullable=False),
        sa.Column("role_id", sa.String(), nullable=False),
        sa.Column("scope_type", sa.String(length=32), nullable=False, server_default="tenant"),
        sa.Column("scope_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("granted_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "subject_type", "subject_id", "role_id", "scope_type", "scope_id", name="uq_iam_role_binding"),
        sa.CheckConstraint("subject_type IN ('user', 'service', 'api_client')", name="ck_iam_role_binding_subject_type"),
        sa.CheckConstraint("scope_type IN ('tenant', 'organization', 'team', 'resource')", name="ck_iam_role_binding_scope_type"),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_iam_role_binding_tenant_nonempty"),
    )
    op.create_index("ix_iam_role_binding_subject", "iam_role_bindings", ["tenant_id", "subject_type", "subject_id"])


def downgrade() -> None:
    op.drop_index("ix_iam_role_binding_subject", table_name="iam_role_bindings")
    op.drop_table("iam_role_bindings")
    op.drop_table("iam_role_permissions")
    op.drop_table("iam_permissions")
    op.drop_table("iam_roles")
    op.drop_index("ix_iam_external_identity_user", table_name="iam_external_identities")
    op.drop_table("iam_external_identities")
    op.drop_index("ix_iam_api_client_tenant_status", table_name="iam_api_clients")
    op.drop_table("iam_api_clients")
    op.drop_index("ix_iam_service_identity_scope_status", table_name="iam_service_identities")
    op.drop_table("iam_service_identities")
    op.drop_index("ix_iam_tenants_platform_status", table_name="iam_tenants")
    op.drop_table("iam_tenants")
    op.drop_table("iam_platforms")
