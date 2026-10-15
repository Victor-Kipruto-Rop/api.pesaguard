# PesaGuard backend environment configuration

In development, the backend can load `.env` from the backend checkout root using
the existing `python-dotenv` dependency. The default path is resolved from the
installed backend source, not the shell's current directory. Package startup
loads it before legacy compatibility imports; database consumers also import the
shared loader. Docker services receive explicitly configured values through
Compose `env_file`, never through an image layer.

## Precedence and required values

- Process environment values take precedence, even when explicitly empty.
- Set `PESAGUARD_ENV_FILE` to an absolute path to choose another deployment file.
  A missing explicitly selected file fails with a value-free error.
- Set `PYTHON_DOTENV_DISABLED=1` for environment-only deployment or testing.
- Production and staging do not load the implicit checkout `.env`; inject their
  values from the approved deployment secret store. The API image defaults to
  `PESAGUARD_ENVIRONMENT=production`, which makes Redis and Kafka readiness gates
  required unless an explicit environment override is supplied.
- An absent default file is permitted when configuration is injected externally.
- Values are literal: `${NAME}` interpolation is disabled. Write complete URLs.
- `DATABASE_URL` must be supplied; backend modules no longer embed database
  username/password defaults. `PESAGUARD_API_URL` is required by RuntimeConfig.
- Existing JWT validation remains in place. Do not use example secrets in service.
- The test conftest disables deployment-file loading. Do not run tests from a
  shell containing production credentials or production connection URLs.

Use `c:\Users\kipru\pesaguard\.env.example` as the configuration template.
Keep real secrets only in the ignored local file or your deployment secret store.
Do not copy credentials into Python, frontend code, Compose YAML, or documentation.
`.gitignore` protects environment files from Git and `.dockerignore` excludes them
from Docker build contexts. Shell workers no longer print Redis connection URLs.

## Docker validation

From PowerShell, validate without starting services or displaying resolved secrets:

```powershell
docker compose --env-file 'c:\Users\kipru\pesaguard\.env' -f 'c:\Users\kipru\pesaguard\infra\docker\docker-compose.yml' config --quiet
```

Compose interpolation needs `--env-file` as well as the service-level `env_file`.
Supply `DATABASE_URL_DOCKER` for the intended container-accessible database;
Compose no longer supplies embedded database credentials. Do not assume local
Postgres is the same database as an external managed instance. Match the selected
URL, user, database, TLS settings, and deployed service ports before starting.
Backup scripts now depend on the shared backend environment module and its dotenv
dependency; deploy them with the backend, not as a copied standalone Python file.

## Important limits

Loading a key does not implement its feature. Settings for integrations that have
no backend consumer remain unused; this change does not add AWS Secrets Manager,
new payment adapters, or change financial matching, retention, or authentication
rules. Existing non-secret local-service defaults and provider protocol constants
remain where not specifically changed.

The local deployment file still requires operator review: replace unresolved
placeholders, remove duplicate keys, confirm Redis/S3 formats, confirm CORS origins
and listening ports, and reconcile declared data-residency regions with actual
hosting. No production connections, migrations, payments, backups, or service
startup are needed to validate dotenv parsing.

Credentials exposed in tool output must be treated as compromised. Revoke/rotate
through the approved operational process and audit their use. Encryption-key
rotation needs a recovery/migration plan; do not discard keys needed to decrypt
existing financial records. This code change does not rotate credentials or
remove them from existing logs or previously built images.

## Transactional and alert email

`EmailService` uses Python's SMTP transport, not an email-provider HTTP API.
Configure these keys in the ignored deployment file:

```dotenv
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM_EMAIL=
SMTP_FROM_NAME=PesaGuard
SMTP_USE_TLS=true
SMTP_USE_SSL=false
```

Supply the real host, authorized sender, and credentials from your SMTP provider.
For implicit TLS (usually port 465), set `SMTP_USE_TLS=false` and
`SMTP_USE_SSL=true`. Certificate and hostname verification are enabled in both
modes. Plaintext delivery is rejected. Both credential fields must be supplied
for authenticated SMTP; an unauthenticated TLS relay may leave both empty.
Missing host/sender fails delivery without opening a connection. Invalid ports,
boolean values, or conflicting TLS modes fail service initialization.

Explicit constructor arguments take precedence, then canonical `SMTP_*` keys,
then legacy `EMAIL_*` keys (`EMAIL_FROM` for the sender). `SMTP_SERVER` is the
last host fallback. Explicitly empty values do not fall back. Remove duplicate
aliases when migrating: a canonical key in the deployment file takes precedence
over a differently named legacy key, even in the process environment.
SMTP credentials are never embedded in source. `EMAIL_PROVIDER` is not a selector.

### Manual checks

The manual utility loads the same configuration as `EmailService`. Importing it
or collecting it with pytest does not load credentials or connect to SMTP.

```powershell
python 'c:\Users\kipru\pesaguard\pesaguard_backend_pipeline\tests\test_smtp.py' --check-only
python 'c:\Users\kipru\pesaguard\pesaguard_backend_pipeline\tests\test_smtp.py' --send --to 'kiprutovictor39@gmail.com'
```

`--check-only` validates configuration without networking. Sending requires an
explicit recipient and makes one attempt, with no automatic retry. Failure exits
nonzero. Success means SMTP acceptance, not confirmed inbox delivery. Diagnostics
report the stage and exception type, never credentials or raw provider responses.

On 2026-09-17 the Windows TCP check to `smtp.gmail.com:587` resolved DNS but failed
to connect. Local configuration validation passed; live SMTP authentication and
delivery remain unverified. Check outbound network policy with your administrator;
do not disable TLS or firewall protections to work around this blocker.

The report, daily-summary, account-security, and public status subscription
messages use an inline-styled, table-based PesaGuard email layout with a
plain-text alternative. Discrepancy alert messages use the same brand palette
and escape provider-supplied values before rendering HTML. The layout uses an
in-message wordmark and requires no externally hosted images. Email-client
rendering still needs a real inbox/client review before production sign-off.

This configures transactional mail in the feature applications. The separate
discrepancy alert notifier still uses `ALERT_SMTP_HOST`,
`ALERT_SMTP_PORT`, `ALERT_SMTP_USER`, `ALERT_SMTP_PASS`, `ALERT_EMAIL_FROM`, and
`ALERT_EMAIL_RECIPIENTS`. The communications gateway abstraction is separate and
is not wired to this SMTP service by this change. Mock transport tests do not
verify live delivery, provider configuration, or recipient inbox placement.
