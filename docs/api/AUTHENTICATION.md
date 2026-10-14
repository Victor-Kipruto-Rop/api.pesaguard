# Authentication and identity routes

## Status and source of truth

The canonical FastAPI app mounts the authentication Flask application at both `/auth` and `/api/v1/auth`. Therefore the code exposes unversioned and versioned aliases for the authentication routes below; the aliases do not imply different permissions or behavior.

**Important documentation gap:** the checked-in `docs/api/openapi.implemented.json` was generated before recent authentication and lifecycle changes and currently omits these mounted routes. The docs repository's route/OpenAPI generator is being updated to enumerate the FastAPI app and its WSGI mounts. Until regeneration succeeds, do not treat the current generated OpenAPI snapshot as a complete route inventory. Confirm exact request schemas, response codes, security requirements, and permissions in the deployed `/openapi.json` before production use.

## Credential schemes

The checked-in contract defines bearer JWT authentication and an API-key scheme through `X-API-Key`. The backend verifier accepts tenant API-key prefixes `pk_` and `pgk_`; a prefix does not establish validity, environment, tenant binding, or permissions.

Use the scheme documented for each operation. Do not send bearer and API-key credentials together. The backend explicitly rejects the compatibility case where a `pgk_` value is sent as a bearer token while `X-API-Key` is also present; do not rely on mixed-credential behavior for other combinations.

## Registered route inventory

The following paths are registered in the authentication Flask application. Unless a deployment explicitly disables a mount, each path is exposed both as written and with the `/api/v1` prefix prepended (for example, `POST /auth/login` and `POST /api/v1/auth/login`). This is a code-level route inventory, not a guarantee that a production deployment has the same revision or configuration.

### Login, credentials, and sessions

| Method | Route |
|---|---|
| POST | `/auth/register` |
| POST | `/auth/login` |
| POST | `/auth/refresh` |
| POST | `/auth/logout` |
| POST | `/auth/logout-all` |
| GET | `/auth/verify` |
| POST | `/auth/revoke` |
| POST | `/auth/revoke/refresh` |
| POST | `/auth/revoke/device` |
| POST | `/auth/revoke/user` |
| POST | `/auth/security/global-revoke` |
| POST | `/auth/client-token` |
| GET | `/auth/sessions` |
| POST | `/auth/sessions/{session_id}/renew` |
| POST | `/auth/sessions/{session_id}/revoke` |
| POST | `/auth/password/change` |
| POST | `/auth/password-reset/request` |
| POST | `/auth/password-reset/confirm` |
| POST | `/auth/passwordless/challenge` |
| POST | `/auth/passwordless/verify` |
| POST | `/auth/verify-email` |
| POST | `/auth/verify-email/resend` |

### API keys, devices, and administrative controls

| Method | Route |
|---|---|
| POST | `/auth/api-keys` |
| POST | `/auth/api-keys/{key_id}/revoke` |
| POST | `/auth/api-keys/{key_id}/rotate` |
| GET | `/auth/devices` |
| POST | `/auth/devices/{device_id}/logout` |
| POST | `/auth/devices/{device_id}/rename` |
| POST | `/auth/devices/{device_id}/revoke` |
| POST | `/auth/devices/{device_id}/trust` |
| GET | `/auth/users` |
| GET | `/auth/account/lockouts` |
| POST | `/auth/account/unlock` |
| POST | `/auth/admin/users/{user_id}/password-reset` |
| POST | `/auth/admin/users/{user_id}/emergency-credential-rotation` |
| POST | `/auth/service-credentials/{credential_id}/revoke` |

### Multi-factor authentication and WebAuthn

| Method | Route |
|---|---|
| POST | `/auth/mfa/challenge` |
| POST | `/auth/mfa/email/request` |
| POST | `/auth/mfa/email/verify` |
| POST | `/auth/mfa/enroll` |
| POST | `/auth/mfa/enroll/verify` |
| GET | `/auth/mfa/factors` |
| POST | `/auth/mfa/factors/{factor_id}/revoke` |
| GET | `/auth/mfa/policy` |
| PUT | `/auth/mfa/policy` |
| POST | `/auth/mfa/recovery-codes/regenerate` |
| POST | `/auth/mfa/reset/request` |
| POST | `/auth/mfa/reset/confirm` |
| POST | `/auth/mfa/verify` |
| POST | `/auth/mfa/webauthn/enroll/options` |
| POST | `/auth/mfa/webauthn/enroll/verify` |
| POST | `/auth/mfa/webauthn/login/verify` |
| POST | `/auth/mfa/webauthn/step-up/options` |
| POST | `/auth/mfa/webauthn/step-up/verify` |

### Single sign-on and OIDC

| Method | Route |
|---|---|
| GET | `/auth/sso/oidc/authorize` |
| GET, POST | `/auth/sso/oidc/callback` |
| GET | `/auth/sso/oidc/config` |
| POST | `/auth/sso/oidc/token` |
| POST | `/auth/sso/oidc/validate` |
| GET, POST | `/auth/sso/policy` |
| POST | `/auth/sso/policy/review` |
| GET, POST | `/auth/sso/providers` |

## Do not infer request or response schemas

This list is derived from route decorators in the current backend source. It intentionally does not invent request fields, success payloads, status codes, or permission names. Those details must be taken from the regenerated OpenAPI contract and verified against the deployed revision. In particular, use the actual paths `/auth/password-reset/request`, `/auth/password-reset/confirm`, `/auth/password/change`, and `/auth/sessions`; older drafts used incorrect singular or hyphenated paths.

## Credential handling

- Obtain credentials only through the authorized provisioning and identity workflow.
- Store secrets in a managed secret store or protected runtime configuration.
- Never expose credentials in browser bundles, URLs, source control, logs, screenshots, or telemetry.
- Rotate or revoke credentials through the supported endpoint or operator workflow.
- Confirm token expiry, key status, tenant binding, and operation-specific permissions before troubleshooting an authorization failure.
