# Deployment verification for Redis and observability

This checklist is for the deployed API service (for example, Render). Do not put credentials in source control, issue comments, or screenshots.

## Required deployment configuration

- `PESAGUARD_ENVIRONMENT=production`
- `REDIS_URL`: the managed Redis service's private/internal connection URL when available. Use the scheme and TLS mode supplied by the provider (`redis://` or `rediss://`).
- `PESAGUARD_SHARED_METRICS=1` to enable shared multi-worker telemetry.
- `SENTRY_DSN`: optional. If configured, use the complete DSN from the Sentry project. If Sentry is not being used, remove the variable rather than setting a placeholder or whitespace.
- `PORT`: let the hosting platform provide this value unless the service's port configuration explicitly requires a fixed value.

Never paste the values of these variables into logs or support messages.

## Redis validation

1. Confirm the Redis service is running and not out of connections or memory.
2. Confirm the API service uses the matching Redis instance and correct internal URL, credentials, TLS scheme, and network.
3. Redeploy or restart the API after changing variables.
4. Confirm the API no longer logs Redis connection timeouts.
5. Exercise a protected endpoint. In production, if Redis is unavailable, distributed rate limiting must fail closed with HTTP 503 rather than silently using a per-process memory bucket.
6. Restore Redis and repeat the check. Metrics now retry after transient Redis startup/network failures rather than permanently disabling the shared backend after the first failed attempt.

## Health checks and ports

- Use `/livez` for liveness; it should not fail solely because a dependency is down.
- Use `/health` for readiness; it should return a failing status when the database readiness check fails.
- The container listens on `0.0.0.0:$PORT`. A platform-injected port such as 8000 overrides the image's default. Ensure the service's configured health check and port agree with the actual listener.
- `GET /` is informational only and reports `status: running`; it does not prove dependencies are ready. Use `/livez` for liveness and `/health` for dependency readiness. Never use the root response as the deployment readiness gate.

## Sentry and logs

- Invalid Sentry DSNs are rejected before SDK initialization and are not echoed to logs.
- If Sentry is intentionally disabled, leave `SENTRY_DSN` unset.
- Logs may use process-local metrics while Redis is unavailable, but shared metrics must be verified after Redis recovers.
- Treat a successful platform “live” message as process startup evidence only; it does not prove that Redis, the database, tenant isolation, or reconciliation workflows are healthy.

## Release gate

Do not label the deployment production-ready until Redis recovery, distributed rate limiting, health checks, database readiness, tenant-isolation tests, and a representative reconciliation flow have all been verified in the deployed environment.
