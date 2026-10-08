"""Track Developer Platform API-key synchronization versions."""

from alembic import op
import sqlalchemy as sa


revision = "20261004_sync_developer_api_keys"
down_revision = "20261003_merge_auth_public_status_heads"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "api_key_records",
        sa.Column("source_version", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("api_key_records", "source_version")
