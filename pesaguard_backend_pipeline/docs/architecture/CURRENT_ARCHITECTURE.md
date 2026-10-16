# Current architecture

## Runtime flow

The Flask API is assembled in `api/dashboard_app.py`. `canonical_app.py` is the
ASGI entry point; the older `app.py`, `app_1.py`, `app_2.py`, and
`app_4_advanced_features.py` modules remain compatibility and service modules
used by existing deployments and tests.

Daraja callbacks enter through the webhook application, are validated and
normalized, then pass through the event store and reconciliation pipeline.
Reconciliation results and operational changes are persisted through SQLAlchemy
models. The outbox and event-processing components publish work to Kafka so
database commits and event delivery can be retried independently.

## Dependencies and operations

- PostgreSQL is the production relational database. SQLite is used by local and
  unit tests. Schema changes are maintained with Alembic migrations.
- Kafka carries asynchronous transaction and reconciliation events. Redis
  supports distributed coordination and rate limiting where configured.
- Daraja is the payment callback/provider boundary. Email and notification
  delivery are handled by the communication services and configured providers.
- Prometheus scrapes application metrics. Alert rules and Alertmanager routing
  are defined in `monitoring/`.
- Health and readiness responses report database, Kafka, Redis, and Daraja
  dependency state. The public status endpoint intentionally exposes a reduced
  view and omits private dependency error details.

## Security boundaries

Customer API authentication and permissions are defined in
`authorization_policy.py`. Internal service endpoints use the internal service
authentication layer and scoped credentials. Candidate ledger records must be
tenant-scoped by the query that retrieves them; reconciliation also rejects
explicit tenant, provider, account, or currency conflicts.

Production deployments should use the deployment configuration in `infra/`,
provide secrets through protected files or the deployment secret manager, and
run the migrations and release checks before routing production traffic.
