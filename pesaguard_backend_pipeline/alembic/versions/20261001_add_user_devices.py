"""Add durable tenant-scoped user device identities."""

from alembic import op
import sqlalchemy as sa
import uuid


revision = "20261001_add_user_devices"
down_revision = "20260925_harden_user_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_devices",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("device_id", sa.String(length=255), nullable=False),
        sa.Column("device_name", sa.String(length=128), nullable=False, server_default="Unknown device"),
        sa.Column("browser", sa.String(length=128), nullable=True),
        sa.Column("operating_system", sa.String(length=128), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_ip_address", sa.String(length=64), nullable=True),
        sa.Column("session_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("trusted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("risk_metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_user_devices_tenant_id_nonempty"),
        sa.CheckConstraint("session_count >= 0", name="ck_user_devices_session_count_nonnegative"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "user_id", "device_id", name="uq_user_devices_owner_device"),
    )
    op.create_index("ix_user_devices_owner_last_seen", "user_devices", ["tenant_id", "user_id", "last_seen_at"])
    op.create_index("ix_user_sessions_owner_activity", "user_sessions", ["tenant_id", "user_id", "last_activity_at"])

    bind = op.get_bind()
    sessions = sa.Table("user_sessions", sa.MetaData(), autoload_with=bind)
    devices = sa.Table("user_devices", sa.MetaData(), autoload_with=bind)
    eligible_sessions = sa.select(
        sessions.c.tenant_id,
        sessions.c.user_id,
        sessions.c.device_id,
        sessions.c.user_agent,
        sessions.c.ip_address,
        sessions.c.issued_at,
        sessions.c.last_activity_at,
        sessions.c.id,
    ).where(
        sessions.c.tenant_id.is_not(None),
        sessions.c.tenant_id != "",
        sessions.c.user_id.is_not(None),
        sessions.c.device_id.is_not(None),
        sessions.c.device_id != "",
    ).cte("eligible_sessions")
    latest_sessions = sa.select(
        eligible_sessions,
        sa.func.row_number().over(
            partition_by=(
                eligible_sessions.c.tenant_id,
                eligible_sessions.c.user_id,
                eligible_sessions.c.device_id,
            ),
            order_by=(
                sa.func.coalesce(eligible_sessions.c.last_activity_at, eligible_sessions.c.issued_at).desc(),
                eligible_sessions.c.issued_at.desc(),
                eligible_sessions.c.id.desc(),
            ),
        ).label("session_rank"),
    ).cte("latest_sessions")
    device_stats = sa.select(
        eligible_sessions.c.tenant_id,
        eligible_sessions.c.user_id,
        eligible_sessions.c.device_id,
        sa.func.min(eligible_sessions.c.issued_at).label("first_seen_at"),
        sa.func.max(sa.func.coalesce(eligible_sessions.c.last_activity_at, eligible_sessions.c.issued_at)).label("last_seen_at"),
        sa.func.count().label("session_count"),
    ).group_by(
        eligible_sessions.c.tenant_id,
        eligible_sessions.c.user_id,
        eligible_sessions.c.device_id,
    ).cte("device_stats")
    backfill = sa.select(
        device_stats.c.tenant_id,
        device_stats.c.user_id,
        device_stats.c.device_id,
        latest_sessions.c.user_agent,
        latest_sessions.c.ip_address,
        device_stats.c.first_seen_at,
        device_stats.c.last_seen_at,
        device_stats.c.session_count,
    ).join(
        latest_sessions,
        sa.and_(
            latest_sessions.c.tenant_id == device_stats.c.tenant_id,
            latest_sessions.c.user_id == device_stats.c.user_id,
            latest_sessions.c.device_id == device_stats.c.device_id,
        ),
    ).where(latest_sessions.c.session_rank == 1).execution_options(stream_results=True)

    batch = []
    for row in bind.execute(backfill).mappings():
        batch.append({
            "id": f"dev_{uuid.uuid4().hex}",
            "tenant_id": row["tenant_id"],
            "user_id": row["user_id"],
            "device_id": row["device_id"],
            "device_name": "Unknown device",
            "browser": None,
            "operating_system": None,
            "user_agent": row["user_agent"],
            "first_seen_at": row["first_seen_at"],
            "last_seen_at": row["last_seen_at"],
            "last_ip_address": row["ip_address"],
            "session_count": row["session_count"],
            "trusted": False,
            "revoked_at": None,
            "risk_metadata": {},
        })
        if len(batch) == 1000:
            bind.execute(sa.insert(devices), batch)
            batch.clear()
    if batch:
        bind.execute(sa.insert(devices), batch)


def downgrade() -> None:
    op.drop_index("ix_user_sessions_owner_activity", table_name="user_sessions")
    op.drop_index("ix_user_devices_owner_last_seen", table_name="user_devices")
    op.drop_table("user_devices")