"""Add versioned Argon2id password credentials, history, and reset state."""

from alembic import op
import sqlalchemy as sa


revision = "20260925_add_password_credentials"
down_revision = "20260925_add_user_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "iam_password_credentials",
        sa.Column("credential_id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("algorithm", sa.String(length=32), nullable=False, server_default="argon2id"),
        sa.Column("parameters", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(length=255), nullable=True),
        sa.CheckConstraint("status IN ('ACTIVE', 'REVOKED', 'EXPIRED', 'COMPROMISED')", name="ck_iam_password_credential_status"),
        sa.CheckConstraint("algorithm = 'argon2id'", name="ck_iam_password_credential_algorithm"),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_iam_password_credential_tenant_nonempty"),
    )
    op.create_index("ix_iam_password_credential_user_status", "iam_password_credentials", ["tenant_id", "user_id", "status"])
    op.create_table(
        "iam_password_history",
        sa.Column("history_id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("algorithm", sa.String(length=32), nullable=False, server_default="argon2id"),
        sa.Column("parameters", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("algorithm = 'argon2id'", name="ck_iam_password_history_algorithm"),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_iam_password_history_tenant_nonempty"),
    )
    op.create_index("ix_iam_password_history_user_created", "iam_password_history", ["tenant_id", "user_id", "created_at"])
    op.create_table(
        "iam_password_reset_states",
        sa.Column("reset_id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False, unique=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.CheckConstraint("status IN ('PENDING', 'USED', 'EXPIRED', 'REVOKED')", name="ck_iam_password_reset_status"),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_iam_password_reset_tenant_nonempty"),
    )
    op.create_index("ix_iam_password_reset_user_status", "iam_password_reset_states", ["tenant_id", "user_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_iam_password_reset_user_status", table_name="iam_password_reset_states")
    op.drop_table("iam_password_reset_states")
    op.drop_index("ix_iam_password_history_user_created", table_name="iam_password_history")
    op.drop_table("iam_password_history")
    op.drop_index("ix_iam_password_credential_user_status", table_name="iam_password_credentials")
    op.drop_table("iam_password_credentials")
