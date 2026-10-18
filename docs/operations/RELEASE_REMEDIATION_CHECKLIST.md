# Core API Release Remediation Checklist

This checklist records release evidence required before enabling live financial traffic. A code change or a green unit-test run alone is not production certification.

## Changes in this branch

- CI no longer treats frontend test failures as non-blocking when a frontend package manifest exists.
- The restore-drill job installs the same backend development manifest used by the test suite instead of falling back to an unrelated root requirements file or minimal ad-hoc packages.
- The dependency scan explicitly audits the backend development manifest, which includes backend production requirements, rather than potentially scanning only a root manifest.
- The dependency scan workflow declares read-only repository permissions.

## Required verification before merge

- [ ] CI passes on this branch, including the complete backend test suite and restore drill.
- [ ] Dependency and security scans pass; triage and remediate findings rather than suppressing them.
- [ ] OpenAPI compatibility gate is confirmed to run against the correct base revision.
- [ ] Container build and image vulnerability scan pass for the exact image intended for deployment.
- [ ] Database migrations succeed against both a clean database and a representative prior-version database.
- [ ] Concurrent duplicate and conflicting provider transaction submissions are tested against PostgreSQL constraints.
- [ ] Cross-tenant authorization tests cover API reads/writes, exports, background jobs, and reports.
- [ ] Outbox/event delivery, retries, dead-letter recovery, and worker restarts are tested for duplicate side effects.
- [ ] Reconciliation is evaluated against reviewed ground truth; ambiguous records fail closed to review.
- [ ] Backup and restore are validated against a production-like application schema and reconciled financial totals.
- [ ] Staging smoke tests verify authenticated Daraja callbacks, callback retries, readiness, CORS, and API-key authorization.
- [ ] Rollback and incident-response procedures are exercised.

## External actions requiring repository/deployment-owner access

### Public status monitor

The scheduled workflow failed on 2026-10-18. Its code exits immediately if the `PESAGUARD_STATUS_MONITOR_TOKEN` Actions secret is absent; otherwise, it calls `https://api.pesaguard.co.ke/public/status/monitor`. Inspect the failed run logs to determine which condition occurred. Ensure the same newly generated random token (at least 32 characters) is configured as a GitHub Actions repository secret and as the production backend runtime setting. Do not put the token in this repository or in issue comments. Then manually dispatch the workflow and verify a successful run.

### Production environment

Confirm deployment secrets and protected-environment approvals are configured. Run staging acceptance checks before enabling live traffic. Production deployment, DNS/TLS, runtime secrets, live provider credentials, and a real restore drill cannot be completed safely from repository file edits alone.

## Scope and safety

PesaGuard's currently supported integration must be described as M-Pesa/Daraja unless another provider has passed its own end-to-end certification. Airtel Money and bank integrations must remain explicitly labelled as planned or in development until that evidence exists.

Do not claim production-ready status until all required checks above have evidence attached to the release.
