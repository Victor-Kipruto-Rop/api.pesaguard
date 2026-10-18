# Secrets management and rotation

## Current control status

Production credentials must be stored in an organization-approved secret manager
or deployment platform's encrypted secret store. The application and repository
do not currently provide a centralized secret manager or automated credential
rotation. Git ignore rules and deployment environment variables do not replace
access control, audit, expiry, or rotation policy.

Before production, assign an owner for every credential class, choose an
organization-approved rotation cadence based on provider policy and risk, and
record the approved store, access group, expiry, rotation evidence, and recovery
owner. Do not invent a universal interval where provider or regulatory
requirements differ.

## Rotation procedure

1. Inventory the credential, its consumers, provider/account, owner, expiry, and
   rollback method. Limit access to the operator performing the change.
2. Create a replacement credential in the provider or host secret manager. Keep
   its value out of source control, issue text, command arguments, logs, and test
   reports.
3. Update the deployment secret store and roll the affected service. Where the
   provider supports overlap, leave the previous value active only for the
   approved verification window.
4. Verify authenticated health and the expected non-production integration. For
   payment credentials, use the provider sandbox before scheduling a production
   change with the payment owner.
5. Revoke the previous credential, verify it no longer authenticates, and record
   the credential identifier, owner, timestamps, affected release, and outcome;
   never record secret values.
6. Confirm alerts, backups, recovery keys, and dependent jobs use the new
   credential. Update the inventory and expiry reminder.

If a credential is exposed, revoke or disable it immediately, issue a
replacement, inspect provider and application audit logs for use, and record the
incident. Do not wait for the normal cadence or rely on deleting the exposed
copy.

## Local development

Use the ignored repository-root `.env` with local-only credentials. Start from
`.env.example`, replace placeholders, and restrict file permissions. Never copy
production secrets into a developer environment or commit `.env`, even when it
is ignored by Git.
