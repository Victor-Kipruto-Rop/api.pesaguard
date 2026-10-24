# Local PesaGuard datasource integration

This integration is a server-to-server, read-only lookup into the datasource's imported registry dataset. It does not connect to BRS/KRA by itself and must not be treated as business verification.

## Backend configuration

Set these values in the PesaGuard backend environment only:

```dotenv
PESAGUARD_DATASOURCE_BASE_URL=http://host.docker.internal:8000
PESAGUARD_DATASOURCE_API_KEY=<same local-only REGISTRY_API_KEYS value>
PESAGUARD_DATASOURCE_CONNECT_TIMEOUT_SECONDS=2
PESAGUARD_DATASOURCE_READ_TIMEOUT_SECONDS=5
```

Use `http://127.0.0.1:8000` when PesaGuard runs directly on the Windows host. If both services share a Docker network, use the datasource service DNS name and port. Local HTTP is accepted only in development/test environments and only for recognized local hosts; non-local environments require HTTPS.

The key must never be put in frontend/Vite variables, browser storage, a response, source control, or logs. Use separate keys for local, staging, and production.

## Endpoint

`POST /api/v1/organizations/{organization_id}/registry-lookup`

Requires a PesaGuard bearer token with `read:settings` permission. The organization is resolved from the authenticated user's tenant; a client-supplied tenant ID is never trusted.

Send exactly one of:

```json
{"registration_number":"CPR/2024/12345"}
```

or

```json
{"tax_pin":"A123456789"}
```

The response returns a sanitized organization record, source and import timestamp where available, a correlation ID, and `evidence_only: true`. Sensitive tax PIN and raw registry payload fields are not returned to the browser. Not found is a valid result, not proof the business does not exist.

## Failure behavior

- Missing configuration, rejected credentials, or upstream unavailability returns a generic 503.
- Invalid upstream JSON/schema returns 502.
- Missing or cross-tenant organization returns 404.
- Malformed request returns 400/422.
- Logs contain only safe error categories and correlation IDs, not registry identifiers, tax PINs, API keys, or response bodies.

The lookup endpoint does not write verification status or mark an organization verified/rejected. A separate approved verification workflow must preserve provider provenance, timestamps, and manual-review requirements.

## Validation

Run focused tests from the repository root:

```powershell
$env:PYTHONPATH = "."
pytest -q pesaguard_backend_pipeline/tests/test_registry_datasource_client.py
python -m compileall -q pesaguard_backend_pipeline
```

Then run the datasource's local smoke test and make a request using a test organization in the local PesaGuard database. Do not use production credentials or data for local validation.
