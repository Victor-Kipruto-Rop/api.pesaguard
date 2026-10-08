"""Re-encrypt persisted IAM and provider secrets after configuring new and previous keys."""

from __future__ import annotations

from pesaguard_backend_pipeline.app_4_advanced_features import SessionLocal
from pesaguard_backend_pipeline.data_protection import encrypt_value, rotate_encrypted_value, rotate_encrypted_values
from pesaguard_backend_pipeline.models import OIDCProvider, PaymentProvider, UserAccount
from pesaguard_backend_pipeline.provider_management_service import ProviderManagementService


def rotate_encryption_keys() -> dict[str, int]:
    """Rewrap user attributes and provider configuration with active encryption keys."""
    rotated_users = 0
    session = SessionLocal()
    try:
        for account in session.query(UserAccount).yield_per(100):
            attributes = account.attributes or {}
            rotated = rotate_encrypted_values(attributes)
            if rotated != attributes:
                account.attributes = rotated
                rotated_users += 1
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    provider_session = SessionLocal()
    try:
        provider_ids = provider_session.query(PaymentProvider.tenant_id, PaymentProvider.id).all()
    finally:
        provider_session.close()

    provider_service = ProviderManagementService(SessionLocal)
    rotated_providers = sum(
        provider_service.rotate_provider_configuration(tenant_id, provider_id)
        for tenant_id, provider_id in provider_ids
    )

    oidc_session = SessionLocal()
    rotated_oidc_providers = 0
    try:
        for provider in oidc_session.query(OIDCProvider).yield_per(100):
            secret = provider.client_secret
            if not secret:
                continue
            rotated_secret = (
                rotate_encrypted_value(secret)
                if secret.startswith("enc:v1:")
                else encrypt_value(secret)
            )
            if rotated_secret != secret:
                provider.client_secret = rotated_secret
                rotated_oidc_providers += 1
        oidc_session.commit()
    except Exception:
        oidc_session.rollback()
        raise
    finally:
        oidc_session.close()

    return {
        "users": rotated_users,
        "providers": rotated_providers,
        "oidc_providers": rotated_oidc_providers,
    }


if __name__ == "__main__":
    result = rotate_encryption_keys()
    print(
        f"Re-encrypted {result['users']} user records, {result['providers']} payment providers, "
        f"and {result['oidc_providers']} OIDC providers."
    )
