"""Add persisted discrepancy filter presets.

incidents/filters/presets (api/dashboard_app.py) rebuilt its preset dict from
scratch on every request -- POST returned 201 as if it had saved something,
but nothing survived past that one response. This table gives it somewhere
real to write to, mirroring communication_saved_filters' shape.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260928_add_discrepancy_filter_presets"
down_revision = "20260923_add_transaction_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "discrepancy_filter_presets",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("owner_user_id", sa.String(length=128), nullable=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("filters", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("tenant_id", "name", name="uq_discrepancy_filter_preset_name"),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_discrepancy_filter_preset_tenant_id_nonempty"),
    )


def downgrade() -> None:
    op.drop_table("discrepancy_filter_presets")
