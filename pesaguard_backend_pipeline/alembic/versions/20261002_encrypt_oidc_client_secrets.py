"""Encrypt existing OIDC provider client secrets."""

from __future__ import annotations

import base64
import hashlib
import json
import os

from alembic import context, op
import sqlalchemy as sa
from cryptography.fernet import Fernet


revision = "20261002_encrypt_oidc_client_secrets"
down_revision = "20261001_add_user_devices"
branch_labels = None
depends_on = None


def _cipher() -> Fernet:
    secret = os.getenv("PESAGUARD_PAYLOAD_ENCRYPTION_KEY") or os.getenv("PROVIDER_ENCRYPTION_KEY")
    if not secret:
        if os.getenv("PESAGUARD_ENVIRONMENT", "development").lower() in {"production", "prod"}:
            raise RuntimeError("PESAGUARD_PAYLOAD_ENCRYPTION_KEY must be configured to migrate OIDC client secrets")
        secret = os.getenv("JWT_SECRET_KEY", "development-payload-key")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


def upgrade() -> None:
    if context.is_offline_mode():
        return
    bind = op.get_bind()
    providers = sa.table(
        "oidc_providers",
        sa.column("id", sa.String()),
        sa.column("client_secret", sa.String()),
    )
    rows = bind.execute(sa.select(providers.c.id, providers.c.client_secret)).mappings().all()
    plaintext_rows = [
        row for row in rows
        if row["client_secret"] and not row["client_secret"].startswith("enc:v1:")
    ]
    if not plaintext_rows:
        return
    cipher = _cipher()
    for row in plaintext_rows:
        plaintext = json.dumps(row["client_secret"], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        encrypted = "enc:v1:" + cipher.encrypt(plaintext).decode("ascii")
        bind.execute(
            providers.update().where(providers.c.id == row["id"]).values(client_secret=encrypted)
        )


def downgrade() -> None:
    raise RuntimeError("Encrypted OIDC client secrets cannot be safely downgraded")
