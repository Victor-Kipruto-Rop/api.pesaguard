"""Add public status email subscriptions."""

from alembic import op
import sqlalchemy as sa


revision = "20261003_add_public_status_subscriptions"
down_revision = "20260928_add_discrepancy_filter_presets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "public_status_subscriptions",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("email_hash", sa.String(length=64), nullable=False),
        sa.Column("confirmation_token_hash", sa.String(length=64), nullable=True),
        sa.Column("confirmation_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confirmed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("last_status_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email_hash", name="uq_public_status_subscription_email_hash"),
    )
    op.create_index(
        "ix_public_status_subscription_confirmed",
        "public_status_subscriptions",
        ["confirmed"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_public_status_subscription_confirmed",
        table_name="public_status_subscriptions",
    )
    op.drop_table("public_status_subscriptions")
