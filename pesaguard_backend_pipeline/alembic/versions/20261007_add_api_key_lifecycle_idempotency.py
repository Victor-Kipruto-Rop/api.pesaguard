"""Add short-lived idempotency storage for internal API-key lifecycle calls."""

from alembic import op
import sqlalchemy as sa


revision = "20261007_api_key_lifecycle_idem"
down_revision = "20261004_sync_developer_api_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_key_lifecycle_idempotency_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("service_subject", sa.String(length=128), nullable=False),
        sa.Column("operation", sa.String(length=16), nullable=False),
        sa.Column("key_id", sa.String(length=255), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("response", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "operation IN ('revoke', 'suspend')",
            name="ck_api_key_lifecycle_idempotency_operation",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "service_subject",
            "operation",
            "key_id",
            "idempotency_key",
            name="uq_api_key_lifecycle_idempotency",
        ),
    )
    op.create_index(
        "ix_api_key_lifecycle_idempotency_expiry",
        "api_key_lifecycle_idempotency_records",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_api_key_lifecycle_idempotency_expiry",
        table_name="api_key_lifecycle_idempotency_records",
    )
    op.drop_table("api_key_lifecycle_idempotency_records")
