"""Allow internal API-key synchronization replay records."""

from alembic import op
import sqlalchemy as sa


revision = "20261007_api_key_sync_idem"
down_revision = "20261007_api_key_lifecycle_idem"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("api_key_lifecycle_idempotency_records") as batch_op:
        batch_op.drop_constraint(
            "ck_api_key_lifecycle_idempotency_operation",
            type_="check",
        )
        batch_op.create_check_constraint(
            "ck_api_key_lifecycle_idempotency_operation",
            "operation IN ('sync', 'revoke', 'suspend')",
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text(
        "SELECT 1 FROM api_key_lifecycle_idempotency_records "
        "WHERE operation = 'sync' LIMIT 1"
    )).first():
        raise RuntimeError(
            "Cannot remove sync idempotency support while sync replay records exist."
        )
    with op.batch_alter_table("api_key_lifecycle_idempotency_records") as batch_op:
        batch_op.drop_constraint(
            "ck_api_key_lifecycle_idempotency_operation",
            type_="check",
        )
        batch_op.create_check_constraint(
            "ck_api_key_lifecycle_idempotency_operation",
            "operation IN ('revoke', 'suspend')",
        )
