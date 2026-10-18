# Security Checklist

PesaGuard processes financial transaction and reconciliation data. This checklist
describes the controls required before a production deployment.

## Reporting A Vulnerability

Do not open a public issue for a suspected vulnerability. Use a private GitHub
security advisory or contact the repository maintainer through GitHub with:

- impact and affected component
- reproduction steps and evidence
- proposed mitigation, if known

Reports should receive an acknowledgement within 48 hours and a remediation
timeline within five business days.

## Deployment Controls

- Keep API authentication enabled in production.
- Configure Daraja shared-secret or source allowlist controls; do not enable
  unrestricted webhook sources in production.
- Configure payload encryption and rotate provider credentials outside source
  control.
- Apply Alembic migrations before starting application and worker processes.
- Configure encrypted off-site backups and verify restore procedures.
- Protect Prometheus metrics at the network or scrape layer.
- Confirm tenant-scoped queries, audit outbox delivery, and dead-letter replay
  controls in the release validation suite.

## Operational Review

- Record the deployment owner and rollback plan.
- Review dependency and secret rotation status using [the production secret rotation runbook](../operations/SECRETS_ROTATION.md).
- Confirm monitoring, alert routing, retention, and incident contacts.
- Track implementation and evidence for every control in [the security implementation tracker](IMPLEMENTATION_TRACKER.md).
