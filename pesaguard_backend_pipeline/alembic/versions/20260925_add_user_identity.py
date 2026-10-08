"""Add the canonical human identity model separate from credentials."""

from alembic import op
import sqlalchemy as sa


revision = "20260925_add_user_identity"
down_revision = "20260925_add_iam_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "iam_user_identities",
        sa.Column("user_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(), nullable=True),
        sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("phone", sa.String(length=64), nullable=True),
        sa.Column("phone_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("phone_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_name", sa.String(length=128), nullable=True),
        sa.Column("last_name", sa.String(length=128), nullable=True),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING_VERIFICATION"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "external_id", name="uq_iam_user_identity_external_id"),
        sa.UniqueConstraint("tenant_id", "email", name="uq_iam_user_identity_email"),
        sa.CheckConstraint("status IN ('INVITED', 'PENDING_VERIFICATION', 'ACTIVE', 'SUSPENDED', 'LOCKED', 'DEACTIVATED', 'DELETED')", name="ck_iam_user_identity_status"),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_iam_user_identity_tenant_nonempty"),
    )
    op.create_index("ix_iam_user_identity_tenant_status", "iam_user_identities", ["tenant_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_iam_user_identity_tenant_status", table_name="iam_user_identities")
    op.drop_table("iam_user_identities")
