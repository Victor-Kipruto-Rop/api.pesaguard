"""Create tenant workflow records for dashboard workflow APIs."""
from alembic import op
import sqlalchemy as sa

revision = "20261018_tenant_workflows"
down_revision = "20261007_api_key_lifecycle_idem"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "tenant_workflow_records",
        sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("domain", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("updated_by", sa.String(length=128), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("tenant_id <> ''", name="ck_workflow_tenant_nonempty"),
        sa.CheckConstraint(
            "domain IN ('reconciliation_run','matching_rule','data_quality_finding','scheduled_reconciliation','settlement_review','refund_reversal_request','report_definition','report_run','fraud_investigation','privacy_request','support_case')",
            name="ck_workflow_domain",
        ),
        sa.CheckConstraint(
            "status IN ('draft','requested','queued','running','completed','failed','open','triage','in_progress','pending_review','approved','rejected','resolved','closed','disabled','scheduled','cancelled','needs_information')",
            name="ck_workflow_status",
        ),
        sa.CheckConstraint("version >= 1", name="ck_workflow_version_positive"),
    )
    op.create_index(
        "ix_workflow_tenant_domain_status_created",
        "tenant_workflow_records",
        ["tenant_id", "domain", "status", "created_at"],
    )
    op.create_index(
        "ix_workflow_tenant_domain_updated",
        "tenant_workflow_records",
        ["tenant_id", "domain", "updated_at"],
    )


def downgrade():
    op.drop_index("ix_workflow_tenant_domain_updated", table_name="tenant_workflow_records")
    op.drop_index("ix_workflow_tenant_domain_status_created", table_name="tenant_workflow_records")
    op.drop_table("tenant_workflow_records")
