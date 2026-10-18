# Production Secret Rotation Runbook

This runbook applies to PesaGuard API, workers, scheduled jobs, and monitoring
integrations. Do not paste production credentials into issues, pull requests,
chat messages, shell history, or logs. Use the deployment provider's protected
environment-variable interface or an approved secret manager.

## Rules

- Assign an owner and purpose to every production secret.
- Keep separate credentials for development, staging, and production.
- Rotate immediately after suspected disclosure, staff departure with access,
  unexpected use, or a provider/security advisory.
- Prefer overlap rotation when a provider supports two active keys. Verify the
  new credential before revoking the old one.
- If overlap is impossible, schedule a controlled change window and document
  expected interruption and rollback.
- Never replace an encryption key until every artifact encrypted with the old
  key has a tested recovery/migration plan.
- Record secret identifier, owner, rotation date, verification evidence, and
  revocation date; never record the secret value itself.

## Rotation procedure

1. Identify every consumer of the credential: API, worker, scheduler, CI, backup
   job, monitoring receiver, and provider configuration.
2. Review the provider's current rotation procedure and generate/create a new
   credential through the provider's trusted console or CLI.
3. Store the new value directly in the approved secret store or protected
   deployment environment. Do not commit it to the repository.
4. Deploy or restart the relevant consumers using the new value. Confirm
   initialization logs do not reveal credentials.
5. Run a non-destructive verification for the specific integration and check
   error rates, audit events, and delivery/connection metrics.
6. Revoke the previous credential after verification, unless an immediate
   emergency revocation is required.
7. Verify the old credential is rejected and the new credential continues to
   work. Remove stale copies from local files, CI variables, and operator notes.
8. Record the outcome and follow-up actions without recording secret material.

## Credential-specific notes

### Application signing and encryption keys

- JWT/session signing keys: identify token lifetime and key-rotation support
  before rotating. If immediate revocation is needed, invalidate existing
  sessions/tokens through the supported revocation mechanism.
- Payload/provider encryption keys: preserve access to old keys until stored
  values have been re-encrypted or their retention period ends. Maintain an
  independently protected recovery copy.
- Backup encryption keys: retain the key needed for each retained backup and
  test restore from an encrypted backup before changing the process.

### Redis and PostgreSQL

- Prefer provider-supported credential rotation. Update every API/worker/cron
  consumer and verify connections before revoking the old credential.
- Keep database roles least-privileged. Rotate application credentials without
  using a database superuser for routine application access.
- Do not put connection URLs in command-line arguments or diagnostic output.

### Daraja and other provider credentials

- Rotate in the provider console. Update the protected runtime configuration
  and test a sandbox or approved non-financial operation where possible.
- Verify callback authentication and webhook source restrictions after change.
- Do not log callback signatures, shared secrets, access tokens, or full
  provider authorization headers.

### Sentry and OpenTelemetry

- Sentry DSNs are ingestion credentials, not administrative API tokens. If
  exposed, rotate or replace the project key through Sentry and update the
  protected runtime configuration.
- Use a separate, minimally scoped Sentry auth token only for automation that
  requires the Sentry API. Never use an account password as an integration key.
- Keep collector credentials separate from Sentry credentials and verify that
  telemetry still arrives after rotation.

### Alertmanager and outbound webhooks

- Generate high-entropy secrets independently per receiver/tenant where
  supported. Update the sender and receiver as a coordinated change.
- Require HTTPS and compare secrets safely. Do not place the secret in the URL.
- Send a test alert, verify successful delivery, then verify an invalid secret
  is rejected.

### GitHub and deployment credentials

- Use short-lived or narrowly scoped tokens where supported.
- Store CI credentials as protected repository/environment secrets.
- Review workflow permissions and environment approvals after rotating.
- Revoke the old token and verify the workflow uses the new one.

## Emergency response

If a credential may be exposed:

1. Restrict or revoke it immediately when safe to do so.
2. Preserve sanitized logs and relevant audit events.
3. Rotate dependent credentials if the exposed credential could reveal or access
   them.
4. Assess access to transaction records, customer data, backups, and production
   infrastructure.
5. Follow PesaGuard's incident response and applicable customer/regulatory
   notification procedures.
6. Document the incident and add regression tests or preventive controls.

## Completion record

For each rotation, record:

- Secret identifier/purpose (never the value)
- Owner and approving person
- Systems updated
- Rotation and revocation timestamps
- Verification test and result
- Any interruption, incident, or follow-up action
