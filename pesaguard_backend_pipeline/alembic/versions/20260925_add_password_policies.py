"""Add scoped password expiration policies."""

from alembic import op
import sqlalchemy as sa


revision = "20260925_add_password_policies"
down_revision = "20260925_add_password_credentials"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "iam_password_policies",
        sa.Column("policy_id", sa.String(), primary_key=True),
        sa.Column("scope_type", sa.String(length=32), nullable=False),
        sa.Column("scope_id", sa.String(length=255), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("max_age_days", sa.Integer(), nullable=True),
        sa.Column("privileged_max_age_days", sa.Integer(), nullable=True),
        sa.Column("notify_before_days", sa.Integer(), nullable=False, server_default="14"),
        sa.Column("force_change", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("emergency_rotation_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("scope_type", "scope_id", name="uq_iam_password_policy_scope"),
        sa.CheckConstraint("scope_type IN ('platform', 'organization', 'tenant')", name="ck_iam_password_policy_scope_type"),
        sa.CheckConstraint("max_age_days IS NULL OR max_age_days >= 0", name="ck_iam_password_policy_max_age"),
        sa.CheckConstraint("privileged_max_age_days IS NULL OR privileged_max_age_days >= 0", name="ck_iam_password_policy_privileged_age"),
        sa.CheckConstraint("notify_before_days >= 0", name="ck_iam_password_policy_notify_before"),
    )


def downgrade() -> None:
    op.drop_table("iam_password_policies")
