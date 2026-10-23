# PesaGuard Datasource registry integration

This integration lets authenticated PesaGuard backend users request a registry lookup through the PesaGuard API. The PesaGuard server calls the Datasource API; browser code never receives the Datasource credential.

## Local sandbox configuration

Create the Datasource local stack from the `pesaguard-datasource` repository first. Generate a managed key with only `registry:read` using `scripts/create-sandbox-key.ps1`, and copy it directly into the ignored local PesaGuard `.env`.

Set:

```dotenv
PESAGUARD_DATASOURCE_BASE_URL=http://127.0.0.1:8000
PESAGUARD_DATASOURCE_API_KEY=<pg_sandbox_key>
PESAGUARD_DATASOURCE_ENVIRONMENT=sandbox
```

If the PesaGuard backend itself runs inside Docker Desktop on Windows and Datasource publishes port 8000 on the host, use `http://host.docker.internal:8000`. `127.0.0.1` inside a container points to that container, not to Windows. If both services share a Docker network, use the Datasource service DNS name.

Never put this API key in `VITE_*` variables, React, mobile clients, public settings, or API responses. The client refuses mismatched key prefixes and refuses non-HTTPS production base URLs.

## PesaGuard route

`POST /api/v1/registry/datasource/lookup`

Requires an authenticated PesaGuard user with `manage:organizations` permission and an authenticated tenant context. The request body accepts exactly one identifier:

```json
{ "registration_number": "<test-registration-number>" }
```

or

```json
{ "tax_pin": "<test-tax-pin>" }
```

The route never accepts a tenant ID or Datasource credential from the body. It forwards the request to `GET /api/v1/registry/lookup` with `X-API-Key`, a caller-service label, and the incoming `X-Correlation-ID` if supplied.

Error responses distinguish local configuration problems (`datasource_not_configured`), upstream timeout/unavailability, `API_KEY_ENVIRONMENT_MISMATCH`, and `API_KEY_SCOPE_DENIED`. No raw credential or upstream response body is logged.

## Test

From the repository root with the development dependencies installed:

```powershell
$env:PYTEST_TEST_DB_URL = 'sqlite:///./pesaguard-datasource-test.db'
python -m pytest pesaguard_backend_pipeline/tests/test_registry_datasource_client.py -q
```

Then start both services locally, sign in to PesaGuard with a user who has `manage:organizations`, and call the route through the PesaGuard API (for example via its authenticated API client). A `record_found` result means only that the internal imported registry dataset contains a matching record. It is not an authoritative BRS/KRA check and must not automatically mark an organization verified.

## Production boundary

Do not point a production PesaGuard deployment at localhost. Configure a separately deployed Datasource sandbox with `DATASOURCE_ENVIRONMENT=sandbox`, an isolated database, the reviewed migration, and an operator-managed sandbox key. Production integration should be a separately approved change using a live key and HTTPS.
