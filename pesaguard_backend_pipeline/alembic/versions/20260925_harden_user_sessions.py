"""Harden user sessions with lifecycle, activity, and expiry state."""

from alembic import op
import sqlalchemy as sa


revision = "20260925_harden_user_sessions"
down_revision = "20260925_add_password_policies"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("user_sessions") as batch:
        batch.add_column(sa.Column("organization_id", sa.String(), nullable=True))
        batch.add_column(sa.Column("location_info", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("state", sa.String(length=16), nullable=False, server_default="ACTIVE"))
        batch.add_column(sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("authentication_method", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("mfa_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")))
        batch.create_check_constraint(
            "ck_user_sessions_state",
            "state IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'SUSPENDED')",
        )
    op.execute(sa.text("UPDATE user_sessions SET last_activity_at = issued_at WHERE last_activity_at IS NULL"))


def downgrade() -> None:
    with op.batch_alter_table("user_sessions") as batch:
        batch.drop_constraint("ck_user_sessions_state", type_="check")
        batch.drop_column("mfa_verified")
        batch.drop_column("authentication_method")
        batch.drop_column("absolute_expires_at")
        batch.drop_column("expires_at")
        batch.drop_column("last_activity_at")
        batch.drop_column("state")
        batch.drop_column("location_info")
        batch.drop_column("organization_id")
