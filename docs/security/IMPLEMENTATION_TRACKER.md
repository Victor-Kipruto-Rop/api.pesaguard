# Security Implementation Tracker

This is a living engineering tracker for `Victor-Kipruto-Rop/api.pesaguard`.
A control is complete only when implementation, regression tests, and required
environment verification are recorded. Existing code or documentation alone is
not proof of a working production control.

## Release rule

**Production security remains NOT VERIFIED** until required CI checks pass,
staging verification is complete, infrastructure controls are confirmed, and
engineering/security/finance owners approve the release. Do not enable live
financial traffic on the basis of this tracker.

## Phase 1 — Immediate correctness and operational foundations

- [x] Identify and fix Redis key-type collision between token-bucket hashes and
  distinct-attempt sets by assigning separate namespaces.
- [x] Ensure a rate-limit reset clears both the token bucket and distinct-attempt
  state.
- [x] Add focused regression tests for key separation and reset behavior.
- [x] Add a production secret-rotation runbook covering signing, encryption,
  backup, provider, database, Redis, monitoring, and CI credentials.
- [ ] Run focused tests and the full CI suite on the branch.
- [ ] Verify the Redis-backed integration test against a real Redis service.
- [ ] Merge only after review and passing checks.

## Phase 2 — Identity, authentication, and authorization

- [ ] Inventory every public, tenant, internal, and administrative route.
- [ ] Verify password hashing, email verification, reset-token expiry, single use,
  and account-enumeration resistance.
- [ ] Verify MFA enrollment, challenge, recovery, lockout, and replay protections.
- [ ] Verify access-token expiry, refresh rotation/reuse detection, session
  revocation, logout, and privilege-change session rotation.
- [x] Change session lifecycle reads to fail closed in production/staging rather than falling back to an active-only legacy query; regression test added (execution pending).
- [ ] Verify every route's role/permission and object-level authorization.
- [ ] Add cross-tenant regression tests for all tenant-owned resources.
- [ ] Verify PostgreSQL RLS/constraints where supported and prove tenant context
  cannot be forged by request input.
- [ ] Verify support/admin access is least-privileged, time-bounded, and audited.

## Phase 3 — API, callbacks, and transaction integrity

- [ ] Verify API-key entropy, one-time display, hashing, scopes, expiry, rotation,
  and revocation.
- [ ] Verify per-tenant/per-key rate limits and production fail-closed behavior.
- [ ] Verify request schema/size limits, safe error responses, and resource caps.
- [ ] Verify Daraja callback authentication, constant-time secret comparison,
  source allowlisting, replay handling, idempotency, and conflict quarantine.
- [ ] Verify transaction writes, audit records, and outbox operations are atomic
  where required.
- [ ] Test concurrent duplicate/conflicting callbacks against PostgreSQL.
- [ ] Verify webhook signatures, timestamp/replay protection, retries, and SSRF
  protections for outbound integrations.

## Phase 4 — Data, cryptography, and secrets

- [ ] Verify TLS on every public and private service link.
- [ ] Verify encryption-at-rest requirements for database, disks, artifacts, and
  backups against provider guarantees.
- [ ] Verify payload/provider encryption key loading and failure behavior.
- [ ] Establish an approved production secret store and named secret owners.
- [ ] Rotate credentials shared outside the approved store.
- [ ] Verify key rotation and recovery for payloads, signing tokens, and backups.
- [ ] Verify data minimization, retention, deletion, and privacy-request workflows.
- [ ] Verify logs, Sentry, traces, CSVs, and exports redact sensitive fields.

## Phase 5 — Infrastructure and supply chain

- [ ] Verify production network exposure, TLS, CORS, security headers, and debug
  mode settings.
- [ ] Verify PostgreSQL and Redis are not publicly exposed unnecessarily.
- [ ] Verify container non-root execution, resource limits, patching, and image
  scanning.
- [ ] Verify dependency, SAST, secret, and container scans are blocking for
  actionable high-severity findings.
- [ ] Verify branch protection, required checks, protected deployment environment,
  least-privilege workflow permissions, and deployment approval.
- [ ] Verify no credentials or sensitive local artifacts remain in repository
  history; rotate any exposed secrets.

## Phase 6 — Monitoring, backups, and response

- [ ] Verify Sentry receives a controlled test event and release/environment tags.
- [ ] Verify OpenTelemetry traces reach the configured collector/backend.
- [ ] Verify Redis, PostgreSQL, queue, callback, backup, and scheduler alerts.
- [ ] Verify Alertmanager receiver authentication and rejected-secret behavior.
- [ ] Verify encrypted backup creation and successful isolated restore.
- [ ] Record measured recovery point/time objectives and test disaster recovery.
- [ ] Complete incident-response, credential-compromise, and vulnerability
  disclosure procedures.
- [ ] Verify audit logs are access-controlled and tamper-evident as required.

## Phase 7 — Independent verification and release decision

- [ ] Run the full backend suite and integration tests with PostgreSQL, Redis,
  and Kafka/Redpanda.
- [ ] Run tenant-isolation, concurrency, API security, and production-shaped load
  tests in staging.
- [ ] Run an external security assessment/penetration test before expanding live
  financial traffic.
- [ ] Preserve CI, scan, restore, staging-smoke, and alert-delivery evidence.
- [ ] Obtain engineering, security, and finance/data-owner sign-off.

## Current evidence and blockers

- Repository's existing production certification document reports production
  status as NOT VERIFIED and lists CI billing, staging configuration, secret
  management, and integration/recovery verification as gates.
- This branch adds the Redis key-type fix, focused tests, and a rotation runbook.
- Focused tests were added for Redis key separation/reset and production/staging
  session-lifecycle fail-closed behavior. They have not yet been executed by this
  tool session; a passing result must not be inferred from test code alone.
- Render currently has no provisioned managed Redis service; provisioning was
  blocked by Render billing requirements. Sentry initialization was previously
  blocked by a malformed `SENTRY_DSN`.
- A production release requires resolving those environment blockers and running
  the required deployment and integration checks.
