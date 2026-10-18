# Webhook Signing Secret Encryption Rollout

New webhook signing secrets and sensitive leaf fields in webhook delivery audit
payloads are stored as authenticated ciphertext using
`PESAGUARD_PAYLOAD_ENCRYPTION_KEY`. The API returns the plaintext signing
secret only in the successful registration response. Existing legacy plaintext
secrets and historical delivery payloads remain readable temporarily for
compatibility; migrate them before calling the rollout complete.

## Required environment

- `PESAGUARD_PAYLOAD_ENCRYPTION_KEY`: independently generated high-entropy key
  stored only in the deployment secret store.
- `PESAGUARD_PAYLOAD_ENCRYPTION_KEY_PREVIOUS`: optional previous key during a
  controlled key-rotation window.
- `DATABASE_URL`: connection string for the target environment.

Staging and production now fail closed if neither
`PESAGUARD_PAYLOAD_ENCRYPTION_KEY` nor the documented provider-key alias is
configured. Do not use `JWT_SECRET_KEY` as an encryption-key substitute in
staging or production.

## Migration procedure

1. Schedule a change window and take a database backup.
2. Verify the backup is restorable and preserve the current encryption key in an
   approved recovery store.
3. Set `PESAGUARD_PAYLOAD_ENCRYPTION_KEY` directly in the protected deployment
   environment. Never paste it into a pull request or chat.
4. Run a dry-run from the repository root. This reports legacy plaintext signing
   secrets and delivery payloads that still contain sensitive plaintext fields:

   ```bash
   PYTHONPATH=pesaguard_backend_pipeline python pesaguard_backend_pipeline/scripts/encrypt_webhook_signing_secrets.py
   ```

5. Review only the counts. If the counts are plausible, apply the migration:

   ```bash
   PYTHONPATH=pesaguard_backend_pipeline python pesaguard_backend_pipeline/scripts/encrypt_webhook_signing_secrets.py --apply
   ```

6. Restart workers/API processes as required. Run a controlled webhook delivery
   to confirm the recipient validates the signature.
7. Verify migrated signing secrets and sensitive delivery-payload fields use the
   `enc:v1:` prefix without printing ciphertext or plaintext values. Check errors
   and delivery status.
8. Preserve the previous key if any other encrypted records still depend on it.
   Remove it only after all retained data is re-encrypted and recovery is tested.

## Rollback

Do not roll back by writing plaintext secrets back into the database. If
verification fails, restore the previous key configuration (including the
previous-key variable where appropriate), keep the encrypted values, and
investigate. Restore a database backup only under the approved recovery process.

## Remaining limitation

The current outbound HTTP implementation re-resolves hostnames when connecting
after URL validation. URL checks are repeated at delivery time and redirects are
disabled, but DNS rebinding is not fully eliminated by validation alone. Before
high-risk production use, route webhook egress through a controlled egress proxy
or implement and test an IP-pinned TLS transport that preserves hostname/SNI
verification.
