"""Merge the MFA and public-status migration branches."""

revision = "20261003_merge_auth_public_status_heads"
down_revision = (
    "20261003_mfa_factor_architecture",
    "20261003_add_public_status_subscriptions",
)
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
