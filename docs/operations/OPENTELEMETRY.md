# PesaGuard OpenTelemetry deployment

PesaGuard uses OpenTelemetry for distributed tracing and W3C Trace Context propagation. Prometheus remains the primary metrics system for existing application counters; structured JSON logs remain available as the operational log stream. Sentry is optional error reporting and is not a replacement for tracing.

## Local Docker Compose

The Compose stack runs:
- PesaGuard services with the OpenTelemetry SDK and supported framework/client instrumentation.
- OpenTelemetry Collector accepting OTLP/gRPC on 4317 and OTLP/HTTP on 4318.
- Jaeger as the trace store and UI.
- Prometheus scraping collector self-metrics and any OTLP metrics emitted by configured applications. Existing PesaGuard application counters continue to use the Prometheus endpoint.

Start the stack using the repository's normal Compose setup. Open the Jaeger UI at `http://localhost:16686`; search for service names such as `pesaguard` or the service-specific name configured by `OTEL_SERVICE_NAME`. The UI is bound to loopback by Compose and should not be exposed publicly without authentication and network controls.

## Required application configuration

Set these values in the deployment environment (never commit collector credentials or tokens):

- `OTEL_SERVICE_NAME`: unique service name, e.g. `pesaguard-api`.
- `OTEL_SERVICE_VERSION`: release or build version.
- `OTEL_DEPLOYMENT_ENVIRONMENT`: `production`, `staging`, or `development`.
- `OTEL_EXPORTER_OTLP_ENDPOINT`: reachable OTLP endpoint. Leave blank to avoid attempted network export and use structured trace fallback only.
- `OTEL_EXPORTER_OTLP_PROTOCOL`: `grpc` or `http/protobuf`, matching the collector endpoint.
- `OTEL_EXPORTER_OTLP_TIMEOUT`: export timeout in seconds.
- `OTEL_TRACES_SAMPLER`: defaults to `parentbased_traceidratio`.
- `OTEL_TRACES_SAMPLER_ARG`: sampling ratio between `0.0` and `1.0`; start around `0.10` and tune to traffic and cost.

For local Compose, the internal collector endpoint is `http://otel_collector:4317`. For Render or another hosted platform, configure an actual reachable collector or managed OTLP backend. Do not point a hosted service at `localhost` or the Compose-only hostname `otel_collector`. Use the provider's TLS/authentication requirements and store any auth headers as secrets.

## What is instrumented

The bootstrap instruments FastAPI requests, Flask requests where used, SQLAlchemy, Redis, HTTPX, Requests, and Kafka/RQ where compatible instrumentors are installed. W3C `traceparent` is used to continue trace context across service boundaries when propagation headers are passed through. Add explicit `trace_span(...)` spans around business-critical stages such as callback validation, ledger persistence, reconciliation matching, discrepancy creation, and report generation when those stages need deeper visibility.

## Verification checklist

1. Confirm the deployment installs the pinned OTel packages from `pesaguard_backend_pipeline/requirements.txt`.
2. Confirm startup logs say the SDK is initialized and `exporter_attached=true` when an endpoint is configured.
3. Send a request through the API and search for its trace in Jaeger or the configured backend.
4. Verify trace context crosses a downstream request or queued job, not just the inbound API span.
5. Temporarily make the collector unavailable in staging and confirm API processing remains available while export failures are logged and bounded.
6. Verify traces do not contain access tokens, payment credentials, full callback payloads, or unnecessary personal/financial data.
7. Treat a configured exporter as configuration, not proof of network reachability. Verify actual traces arrive in the backend.

The runtime `otel_status()` helper reports safe configuration state only. It deliberately does not expose the collector URL or credentials and does not claim that a configured endpoint is reachable.
