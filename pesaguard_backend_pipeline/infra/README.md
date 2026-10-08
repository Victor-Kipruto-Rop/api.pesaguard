# Infrastructure environment configuration

Use the ignored repository-root `.env` as the deployment configuration. Do not
copy it into images or commit it. Start from the root `.env.example` for new
installations; merge new keys into existing deployments without replacing secrets.
The launcher uses the project's existing `python-dotenv` dependency.

## Docker Compose

Compose has **no top-level `env_file`**. `--env-file` supplies YAML interpolation;
service-level `env_file` supplies backend container variables. The launcher sets
both to the same absolute file, even when invoked from another working directory.
Monitoring, database, broker and proxy containers do not receive the complete
backend env file. Shell values override explicitly interpolated Compose settings;
service `environment` entries override service `env_file` values.

Validate without displaying resolved credentials or starting services:

```powershell
python 'C:\Users\kipru\pesaguard\infra\configure.py' compose -- -f infra/docker/docker-compose.yml config --quiet
python 'C:\Users\kipru\pesaguard\infra\configure.py' compose -- -f infra/docker/docker-compose.yml -f infra/docker/docker-compose.aws.yml config --quiet
python 'C:\Users\kipru\pesaguard\infra\configure.py' compose -- -f infra/docker/docker-compose.yml -f infra/docker/docker-compose.tunnel.yml config --quiet
python 'C:\Users\kipru\pesaguard\infra\configure.py' --env-file 'C:\Users\kipru\pesaguard\.env.staging' compose -- -f infra/docker/docker-compose.staging.yml config --quiet
```

Use `up -d --build` instead of `config --quiet` only after reviewing deployment
settings. Plain `config`, `config --environment` and container inspection can expose
secrets. Direct Compose usage remains supported: pass `--env-file` and, when not
using the root `.env`, set `PESAGUARD_COMPOSE_ENV_FILE` to the same absolute path.

Required settings by variant:

- Base: `POSTGRES_USER`, `POSTGRES_DB`, `POSTGRES_PASSWORD`, `DATABASE_URL_DOCKER`,
  `PESAGUARD_API_URL`, `JWT_SECRET_KEY`, `KAFKA_BOOTSTRAP_SERVERS_DOCKER`,
  `REDIS_URL_DOCKER`, `PESAGUARD_BIND_HOST_DOCKER`.
- Full: database/API/JWT settings above plus `KAFKA_BOOTSTRAP_SERVERS_FULL` and
  `KAFKA_ADVERTISED_LISTENERS_FULL`. This variant uses Kafka, not Redpanda.
- Staging: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `STAGING_POSTGRES_DB`,
  `STAGING_KAFKA_ADVERTISED_LISTENERS`.
- AWS/tunnel overlays: `API_SERVER_NAME` (one hostname, not a URL).
  Tunnel additionally requires `CLOUDFLARE_TUNNEL_TOKEN`.

Write complete connection URLs; URL-encode credentials as appropriate. Do not
construct URLs using `${...}` references in `.env`: the backend treats them
literally. Compose does interpolate unquoted/double-quoted values, so single-quote
values containing literal dollar signs. Keep database identity and URLs consistent.
Changing initialization variables does **not** rename existing databases or rotate
passwords in existing Postgres volumes. No migration or credential rotation is
performed here. Use container-reachable Redis/Kafka URLs, not host localhost URLs.

Non-secret protocol constants, container paths, service DNS topology, published
ports, image versions, timer schedules and existing operational defaults remain
in infrastructure files. This change does not certify their production suitability.
In particular, the AWS overlay's existing `ports: []` does not necessarily remove
base-file published ports during Compose merging; review actual exposure before
deployment. No network/security controls are changed by this configuration work.

## Nginx

Docker overlays mount the template into the official image's template directory.
Its entrypoint substitutes only `API_SERVER_NAME`; `$host`, `$remote_addr`, and
other Nginx variables are preserved. Do not mount the template as a ready-to-use
`nginx.conf` or copy it directly into host Nginx.

For host Nginx, render using the deployment's Python environment, then validate
and install the result under your approved deployment procedure:

```bash
python3 /opt/pesaguard/infra/configure.py --env-file /etc/pesaguard/.env render-nginx > /tmp/pesaguard-api.conf
```

The output contains a hostname, not secrets. Validate the installed candidate with
`nginx -t` before reload. Existing TLS/proxy behavior is unchanged.

## Linux systemd

Both services require `/etc/pesaguard/.env`. Provision this root-owned deployment
file with restrictive permissions; systemd reads it before dropping service
privileges. The backup unit also accepts `/etc/pesaguard/backup.env` as optional,
last-wins backup-specific overrides for backwards compatibility. Prefer scoped
service files via `EnvironmentFile` drop-ins where least privilege requires them.
Never source these files as shell scripts. Use simple literal `KEY=value` entries
without `export`, command substitution or variable expansion for systemd.

Set `PYTHONUNBUFFERED`, `LOG_LEVEL`, `PESAGUARD_BACKUP_DIR`,
`PESAGUARD_BACKUP_RETENTION_DAYS`, `PESAGUARD_BACKUP_STATUS_FILE`,
`PESAGUARD_ENVIRONMENT`, and backup encryption/upload commands in the deployment
file. The former `PESAGUARD_BACKUP_ENCRYPT_COMMAND_REQUIRED` unit setting had no
consumer; the actual encryption enforcement uses `PESAGUARD_ENVIRONMENT=production`.
Do not weaken that setting. Existing script defaults apply to omitted optional
backup settings. Unit installation paths, users and timer schedules are unchanged;
review them for your host (scheduled reports currently uses a desktop install path).
Systemd does not expand environment variables in `User` or `WorkingDirectory`.
Validate units on Linux with `systemd-analyze verify` before enabling timers.

No production services, payments, backups or database changes are needed for
configuration validation. Protect `.env` with filesystem ACLs; Git ignore rules
are not an access-control mechanism.
