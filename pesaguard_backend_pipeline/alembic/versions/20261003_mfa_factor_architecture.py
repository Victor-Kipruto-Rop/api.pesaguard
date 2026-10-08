"""Add factor-based MFA storage and migrate account-embedded TOTP material."""

from __future__ import annotations

import os
import uuid

from alembic import context, op
import sqlalchemy as sa

from pesaguard_backend_pipeline.data_protection import encrypt_value


revision = "20261003_mfa_factor_architecture"
down_revision = "20261002_encrypt_oidc_client_secrets"
branch_labels = None
depends_on = None


def _create_tables() -> None:
    op.create_table(
        "mfa_factors",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("factor_type", sa.String(32), nullable=False),
        sa.Column("factor_kind", sa.String(32), nullable=False, server_default="totp"),
        sa.Column("display_name", sa.String(128), nullable=False, server_default="Authenticator"),
        sa.Column("secret_encrypted", sa.Text(), nullable=True),
        sa.Column("credential_id", sa.String(1024), nullable=True),
        sa.Column("credential_public_key", sa.Text(), nullable=True),
        sa.Column("sign_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_used_counter", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("factor_type IN ('totp', 'webauthn')", name="ck_mfa_factors_type"),
        sa.CheckConstraint("status IN ('pending', 'active', 'revoked', 'locked')", name="ck_mfa_factors_status"),
        sa.CheckConstraint("failed_attempts >= 0", name="ck_mfa_factors_failed_attempts"),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_mfa_factors_tenant_id_nonempty"),
        sa.UniqueConstraint("credential_id", name="uq_mfa_factors_credential_id"),
    )
    op.create_index("ix_mfa_factors_owner_state", "mfa_factors", ["tenant_id", "user_id", "status"])

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_mfa_recovery_tenant_id_nonempty"),
        sa.UniqueConstraint("code_hash", name="uq_mfa_recovery_code_hash"),
    )
    op.create_index("ix_mfa_recovery_owner_unused", "mfa_recovery_codes", ["tenant_id", "user_id", "used_at"])

    op.create_table(
        "mfa_policies",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("policy", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_mfa_policies_tenant_id_nonempty"),
        sa.UniqueConstraint("tenant_id", name="uq_mfa_policies_tenant"),
    )

    op.create_table(
        "mfa_events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("factor_id", sa.String(), nullable=True),
        sa.Column("challenge_id", sa.String(), nullable=True),
        sa.Column("event_type", sa.String(96), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("tenant_id IS NOT NULL AND tenant_id <> ''", name="ck_mfa_events_tenant_id_nonempty"),
    )
    op.create_index("ix_mfa_events_owner_time", "mfa_events", ["tenant_id", "user_id", "created_at"])


def upgrade() -> None:
    _create_tables()
    op.add_column(
        "mfa_challenges",
        sa.Column("challenge_type", sa.String(64), nullable=False, server_default="email_verification"),
    )
    op.add_column("mfa_challenges", sa.Column("factor_id", sa.String(), nullable=True))
    op.add_column(
        "mfa_challenges",
        sa.Column("challenge_data", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.create_index("ix_mfa_challenges_owner_status", "mfa_challenges", ["tenant_id", "user_id", "status"])

    if context.is_offline_mode():
        return

    bind = op.get_bind()
    accounts = sa.table(
        "user_accounts",
        sa.column("id", sa.String()),
        sa.column("tenant_id", sa.String()),
        sa.column("attributes", sa.JSON()),
        sa.column("mfa_enabled", sa.Boolean()),
    )
    factors = sa.table(
        "mfa_factors",
        sa.column("id", sa.String()),
        sa.column("tenant_id", sa.String()),
        sa.column("user_id", sa.String()),
        sa.column("factor_type", sa.String()),
        sa.column("factor_kind", sa.String()),
        sa.column("display_name", sa.String()),
        sa.column("secret_encrypted", sa.Text()),
        sa.column("status", sa.String()),
        sa.column("metadata_json", sa.JSON()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("confirmed_at", sa.DateTime(timezone=True)),
        sa.column("expires_at", sa.DateTime(timezone=True)),
    )
    recovery = sa.table(
        "mfa_recovery_codes",
        sa.column("id", sa.String()),
        sa.column("tenant_id", sa.String()),
        sa.column("user_id", sa.String()),
        sa.column("code_hash", sa.String()),
    )

    rows = bind.execute(sa.select(
        accounts.c.id,
        accounts.c.tenant_id,
        accounts.c.attributes,
        accounts.c.mfa_enabled,
    )).mappings()
    now = sa.func.now()
    for row in rows:
        attributes = dict(row["attributes"] or {})
        encrypted_secret = attributes.get("mfa_totp_secret")
        pending_secret = attributes.get("mfa_pending_secret")
        active_secret = encrypted_secret if row["mfa_enabled"] and encrypted_secret else None
        legacy_secret = active_secret or pending_secret
        if legacy_secret:
            protected_secret = (
                legacy_secret if str(legacy_secret).startswith("enc:v1:")
                else encrypt_value(str(legacy_secret))
            )
            factor_id = f"mfa_factor_{uuid.uuid4().hex}"
            is_active = active_secret is not None
            enrollment_started = attributes.get("mfa_enrollment_started_at")
            expires_at = None
            if not is_active and enrollment_started:
                try:
                    from datetime import datetime, timedelta
                    expires_at = datetime.fromisoformat(str(enrollment_started)) + timedelta(minutes=15)
                except ValueError:
                    expires_at = None
            metadata = {}
            pending_hashes = attributes.get("mfa_pending_recovery_code_hashes")
            if isinstance(pending_hashes, list):
                metadata["pending_recovery_code_hashes"] = [str(value) for value in pending_hashes if value]
            bind.execute(factors.insert().values(
                id=factor_id,
                tenant_id=row["tenant_id"] or "default",
                user_id=row["id"],
                factor_type="totp",
                factor_kind="totp",
                display_name="Authenticator",
                secret_encrypted=protected_secret,
                status="active" if is_active else "pending",
                metadata_json=metadata,
                created_at=now,
                confirmed_at=now if is_active else None,
                expires_at=expires_at,
            ))

        hashes = attributes.get("mfa_recovery_code_hashes")
        if isinstance(hashes, list):
            for code_hash in hashes:
                if not isinstance(code_hash, str) or len(code_hash) != 64:
                    continue
                bind.execute(recovery.insert().values(
                    id=f"mfa_recovery_{uuid.uuid4().hex}",
                    tenant_id=row["tenant_id"] or "default",
                    user_id=row["id"],
                    code_hash=code_hash,
                ))

        changed = False
        for key in (
            "mfa_totp_secret",
            "mfa_pending_secret",
            "mfa_recovery_code_hashes",
            "mfa_pending_recovery_code_hashes",
            "mfa_enrollment_started_at",
        ):
            if key in attributes:
                attributes.pop(key)
                changed = True
        if changed:
            bind.execute(accounts.update().where(accounts.c.id == row["id"]).values(
                attributes=attributes,
                mfa_enabled=bool(active_secret),
            ))


def downgrade() -> None:
    if not context.is_offline_mode():
        bind = op.get_bind()
        factors = sa.table(
            "mfa_factors",
            sa.column("tenant_id", sa.String()),
            sa.column("user_id", sa.String()),
            sa.column("factor_type", sa.String()),
            sa.column("secret_encrypted", sa.Text()),
            sa.column("status", sa.String()),
        )
        if bind.execute(sa.select(factors.c.user_id).where(factors.c.factor_type == "webauthn").limit(1)).first():
            raise RuntimeError("Cannot downgrade MFA storage while WebAuthn factors are registered")

    op.drop_index("ix_mfa_challenges_owner_status", table_name="mfa_challenges")
    op.drop_column("mfa_challenges", "challenge_data")
    op.drop_column("mfa_challenges", "factor_id")
    op.drop_column("mfa_challenges", "challenge_type")
    op.drop_index("ix_mfa_events_owner_time", table_name="mfa_events")
    op.drop_table("mfa_events")
    op.drop_table("mfa_policies")
    op.drop_index("ix_mfa_recovery_owner_unused", table_name="mfa_recovery_codes")
    op.drop_table("mfa_recovery_codes")
    op.drop_index("ix_mfa_factors_owner_state", table_name="mfa_factors")
    op.drop_table("mfa_factors")
