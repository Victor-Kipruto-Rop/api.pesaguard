# Authentication and API-key behavior

## Status and source of truth

This page describes the authentication mechanisms present in the checked-in route-derived contract and backend code. It is not a login API reference. The current `docs/api/openapi.implemented.json` does not define public `/api/v1/auth/login`, `/api/v1/auth/logout`, `/api/v1/auth/refresh`, or `/api/v1/auth/session` operations. Older examples for those endpoints are not valid integration instructions.

Before making a request, inspect the operation in the deployed `/openapi.json` and follow its exact security requirement. The checked-in implementation snapshot defines:

- `bearerAuth`: HTTP Bearer credentials formatted as JWTs.
- `apiKeyAuth`: an API key supplied in the `X-API-Key` header.
- Tenant API-key prefixes accepted by the backend verifier: `pk_` and `pgk_`.

The API-key verifier's accepted prefix is not proof that a key is valid, active, correctly scoped, or authorized for a given tenant. Do not infer permissions or environment from the prefix.

## Request examples

For an operation whose OpenAPI security requirement includes `bearerAuth`:

```http
GET /tenant/current
Authorization: Bearer <provisioned-jwt>
Accept: application/json
```

For an operation whose security requirement includes `apiKeyAuth`:

```http
GET /tenant/current
X-API-Key: <provisioned-tenant-api-key>
Accept: application/json
```

These examples are conditional on the credential having the permission required by the selected operation. In the checked-in contract, `GET /tenant/current` declares `read:settings`. Do not send both bearer and API-key credentials in one request. The backend explicitly rejects the compatibility case where a `pgk_` value is sent as a bearer token while `X-API-Key` is also present; do not rely on mixed-credential behavior for other combinations.

## Authorization and tenant isolation

Authentication establishes an identity; it does not grant unrestricted access. The current route-derived contract includes operation-specific permission identifiers such as `read:settings`, `read:discrepancies`, and `manage:organizations`. Some handlers perform additional permission checks, so inspect the operation description and backend implementation when a route has more than one authorization condition.

Requests must use a tenant context authorized for the credential. A caller-supplied tenant identifier is not proof of access. Treat `401` as an authentication failure and `403` as an authorization or tenant-scope denial only where the operation documents those responses; check the actual response schema for other cases.

## Credential handling

- Obtain credentials only through the deployment's authorized provisioning process.
- Store them in a managed secret store or protected runtime configuration.
- Never expose credentials in browser bundles, URLs, source control, logs, screenshots, or telemetry.
- Rotate or revoke credentials through the supported operator workflow.
- Confirm token expiry, key status, tenant binding, and permissions before troubleshooting an authorization failure.

## What this page does not claim

This page does not claim that self-service login, refresh, logout, API-key creation, production-key approval, or a particular key expiry policy is enabled for every deployment. Those workflows must be documented from their actual registered routes and verified deployment configuration before they are advertised as available.
