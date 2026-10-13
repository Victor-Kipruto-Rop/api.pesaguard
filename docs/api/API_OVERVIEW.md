# PesaGuard API: implemented routes and target contract

## Purpose and source of truth

PesaGuard has two different OpenAPI artifacts; they must not be confused:

- **Implemented route snapshot:** [`openapi.implemented.json`](openapi.implemented.json) is generated from the Flask application's registered route map. It is the repository's implementation snapshot, not proof that the same revision is currently deployed.
- **Target contract:** [`openapi.json`](openapi.json) is a hand-maintained design contract for planned tenant-scoped transaction, reconciliation, fraud, and authentication operations. A route appearing only there must not be presented as implemented.
- **Deployed contract:** the running service's `/openapi.json` is authoritative for the deployed revision. Compare it with the checked-in generated snapshot before relying on any endpoint.

The repository's current README states that M-Pesa/Daraja is the active payment scope. Airtel Money and bank integration documents are design references unless a working adapter, tests, configuration, and deployment evidence demonstrate otherwise.

## Runtime and URL conventions

The backend is a Flask/SQLAlchemy service behind a FastAPI control plane. The canonical public API origin configured in the repository is `https://api.pesaguard.co.ke`. Do not assume every endpoint uses the same prefix: the route-derived snapshot includes paths with and without `/api/v1`, so use the exact path and server definition in the deployed OpenAPI document.

## Authentication

The checked-in route-derived contract defines bearer JWT authentication and an API-key scheme using `X-API-Key`. The backend API-key verifier accepts `pk_` and `pgk_` prefixes. A key prefix does not prove environment, tenant, permissions, or provisioning status. Credentials are tenant-scoped and must be provisioned through the authorized workflow.

The current route-derived OpenAPI snapshot does **not** define the `/api/v1/auth/login`, `/api/v1/auth/logout`, `/api/v1/auth/refresh`, or `/api/v1/auth/session` routes described in older drafts. Do not integrate against those paths unless they appear in the deployed contract.

## Permission identifiers

The route-derived snapshot contains these `x-required-permission` values:

- `bulk:operations`
- `export:communications`
- `manage:communications`
- `manage:organizations`
- `manage:providers`
- `read:analytics`
- `read:communications`
- `read:discrepancies`
- `read:metrics`
- `read:providers`
- `read:settings`
- `read:usage`
- `resolve:discrepancies`
- `send:communications`
- `write:discrepancies`
- `write:settings`

This is the set present in the checked-in snapshot, not a promise that every credential has any of these permissions. Some handlers apply additional conditional permission checks; read the operation description and backend handler before assuming a single permission is sufficient.

## Examples of routes in the checked-in implementation snapshot

The following paths are present in the checked-in route-derived contract. They still need to be checked against the live deployed specification before production use:

- `GET /tenant/current` — current tenant context; documented with `read:settings`.
- `GET /api/v1/customers/{tenant_id}/transactions` — tenant transaction listing; documented with `read:discrepancies`.
- `GET /api/v1/customers/{tenant_id}/transactions/{trans_id}` — transaction detail; documented with `read:discrepancies`.
- `GET /incidents/filters/presets` — built-in and tenant-persisted discrepancy filter presets.
- `POST /incidents/filters/presets` — persists a named filter preset; the handler applies both the route-level read permission and a conditional write-permission check when API authentication is required.

Use the operation's request schema, responses, parameters, and security requirements rather than assuming examples are complete.

## Errors, pagination, and idempotency

Do not assume a universal error envelope, pagination shape, or idempotency behavior unless the specific operation documents it. The hand-maintained target contract includes proposed examples; the route-derived and deployed contracts take precedence for implemented behavior.

## Release and verification

Before calling the API production-ready, verify:

1. The backend CI workflow passes tests, migrations, and the breaking-contract gate.
2. The route-derived OpenAPI and route snapshot are regenerated from the current backend commit.
3. The documentation CI checks strict drift between HTML guides, OpenAPI, and registered routes.
4. The deployed `/openapi.json`, health/readiness endpoints, authentication, tenant isolation, and critical reconciliation flows pass staging smoke tests.
5. The live integration status for each payment rail is explicitly confirmed.

A repository file or successful documentation build alone is not evidence of a successful production deployment.
