# Phase 11 — Production Certification

> **Current release decision — 2026-10-16: NOT CERTIFIED — DO NOT SHIP.**
>
> The detailed checklist and failure counts below are a historical assessment
> from 2026-09-17. The current evidence and remaining release gates are recorded
> here; the historical rows have not been re-scored one by one.

## Current evidence update — 2026-10-16

Evidence collected for commit `78e51c3` on branch
`hardening/production-readiness`:

- Full local backend suite: **841 passed, 9 skipped**, using an isolated SQLite
  test database with dotenv loading disabled. This does not exercise the
  PostgreSQL, Redis, or live-service paths used in production.
- Focused configuration and alert-routing regression after the final notifier
  change: **17 passed**.
- `compileall`, `git diff --check`, and duplicate-key YAML parsing passed.
- `pip-audit` reported no known vulnerabilities. The Bandit medium/high gate
  passed with no filtered findings.
- PR [#85](https://github.com/Victor-Kipruto-Rop/api.pesaguard/pull/85) is open.
  Its [CI run](https://github.com/Victor-Kipruto-Rop/api.pesaguard/actions/runs/38814436414),
  [dependency scan](https://github.com/Victor-Kipruto-Rop/api.pesaguard/actions/runs/38814436482),
  and [container scan](https://github.com/Victor-Kipruto-Rop/api.pesaguard/actions/runs/38814436422)
  failed before executing steps because GitHub reports an account billing lock.
  The restore-drill job did not run.
- The production public-status endpoint timed out from the audit environment;
  live service health remains unverified.

### Release gates still open

1. Re-run the GitHub checks after the billing lock is cleared; require green CI,
   dependency/security scans, image scan, and restore drill.
2. Obtain finance/data-owner approval of reconciliation ground truth, then run
   the certification tool and confirm precision and recall are both `1.0` with
   zero false positives and false negatives.
3. Run representative load, stress, spike, and soak profiles against an
   approved production-shaped environment and preserve the results.
4. Exercise the production backup, WAL/PITR, and recovery setup; record measured
   RPO/RTO and the documented disaster-recovery drills.
5. Configure the approved production secret store, rotate any credentials shared
   outside the secret store, and record a named rotation owner and cadence.
6. Complete staging smoke tests, verify live health and alert delivery, and fill
   the engineering, security, and finance/data owner sign-off table below.

These local checks are engineering evidence only. **Production certification
remains `NOT CERTIFIED` until every release gate has passing evidence and the
named owners approve it.**

> **CERTIFICATION DECISION: NOT CERTIFIED — DO NOT SHIP.**
>
> This is the Phase 11 exit gate. It is an evidence record, not a status report.
> Nothing below is pre-ticked. Every line is graded from evidence actually
> collected on 2026-09-17 in this repository and run environment. Where a claim
> could not be verified, it is graded explicitly — a blank is treated as an
> unmet requirement.

| Field | Value |
|---|---|
| Certification date | 2026-09-17 |
| Certifying agent | AI coding agent (PesaGuard Agent Rules) |
| Repository commit | `f5873c1df6367a17e6faefc4ced0ab4b238d190c` (`main`) + uncommitted working tree |
| Certification environment | Windows, Python 3.13.13, **SQLite only** |
| Suite size collected | 314 tests |
| Suite result | **40 failed, 266 passed, 7 skipped, 1 error** (126 s) |
| PostgreSQL / Redis / Kafka available | **No** (nothing listening on 5432/6379; no `psql`, no Docker) |

## Grading vocabulary

| Status | Meaning |
|---|---|
| `CERTIFIED` | Implemented **and** passing automated evidence exists, with no known material gap. |
| `PARTIALLY CERTIFIED` | Implemented with some passing evidence, but a material gap or a failing test remains. |
| `NOT VERIFIED` | Capability absent or unexercised; no evidence exists. |
| `BLOCKED` | Cannot be verified in this environment (needs PostgreSQL/Redis/Kafka/Docker/live drill). |

## How this was verified

- `python -m compileall -q pesaguard_backend_pipeline` → exit 0
- `python -m pytest -q --tb=no` → 40 failed / 266 passed / 7 skipped / 1 error
- Cross-domain regression run over every module touched by the remediations
  (`test_features`, `test_disaster_recovery`, `test_phase4_event_bus`,
  `test_phase1_full_integrity`, `test_lifecycle_integrity`, `test_phase3_reconciliation`,
  `test_api_idempotency_contract`, `test_ground_truth_certification`,
  `test_security_event_instrumentation`, `test_export_tenant_scoping`)
  → **52 passed, 0 failed**
- Six focused per-domain pytest runs (Security 15, Data 32, Reliability+Resilience 29,
  Financial 19, Observability 27, Recovery 7f/15p)
- Static inspection of every control surface named below
- Repo-wide scans for unresolved merge-conflict markers, secrets-manager integration,
  soak/spike/stress harnesses, and dead documentation references

**Environment limitation (material):** CI runs the suite against PostgreSQL 15 and
Redis 7. This environment had neither, so every gate that requires those services is
graded `BLOCKED` rather than `CERTIFIED`. A local SQLite pass does **not** imply a
PostgreSQL pass.

## Remediations already applied and verified in the working tree

These were found broken and are now fixed or worked around. They are recorded as
engineering remediation, **not** as certification evidence.

| Remediation | Evidence |
|---|---|
| `pesaguard_backend_pipeline/metrics.py` — repaired a corrupt expression at line 632 (`Discrepancy.resolved == not Discrepancy.resolved:`) back to the `HEAD` form `Discrepancy.resolved == False`. The stray `:` was a hard `SyntaxError`, and because `tests/conftest.py` imports `app_4_advanced_features` → `app`, **the entire suite failed to collect or run** | `compileall` exit 0; suite went from *no collection* to `40 failed / 266 passed / 7 skipped / 1 error` |
| `pesaguard_backend_pipeline/tests/test_features.py` — repaired seeds and fixtures: `status='assigned'` violated `ck_discrepancy_status` (assignment is carried by the `assignee` column, not a persisted status), and every endpoint now carries a real Bearer token because `PESAGUARD_API_AUTH_REQUIRED` defaults on | Was **8 errors**; now **8 passed** |
| `pesaguard_backend_pipeline/event_store.py` — removed an import of a non-existent symbol (`_worker_on_consumer_delivery`) that made **every** DB operation return `ERROR` | Smoke test: `mark_processed` → `STORED` then `DUPLICATE` (idempotency enforced) |
| `pesaguard_backend_pipeline/operations/validate_restore.py` — restored a mangled docstring (`SyntaxError`) and implemented the 12-query integrity contract | `tests/test_disaster_recovery.py` 3 passed |
| `pesaguard_backend_pipeline/data_quality.py` — rebuilt from a two-way file splice (`SyntaxError`) into a single coherent implementation | Compiles; `provenance.py` now imports; `run_data_quality` returns `pass`/`fail` correctly on smoke input |
| `conftest.py` (repo root) — excludes two operator CLIs that match pytest's `*_test.py` pattern from collection | `314 tests collected`, no collection error |
| `.github/workflows/ci.yml` — `JWT_SECRET_KEY` now 39 bytes | App startup no longer rejects the CI secret |

> Provenance note: the root `conftest.py` and the `ci.yml` secret change were found
> already present in the working tree when re-inspected; their authorship should be
> confirmed before commit.

---

## 1. Security

| # | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 1.1 | Authentication | `PARTIALLY CERTIFIED` | `auth_rbac.py` (JWT + password hashing + MFA challenges + token revocation), `tests/test_rbac_enforcement.py`, `tests/test_daraja_auth.py`, `tests/test_otp.py`, `tests/test_readiness_hardening.py::test_production_auth_cannot_be_disabled` — all pass | No external security review; `docs/security/SECURITY_CHECKLIST.md` explicitly asks to be updated "to reflect what's actually implemented" |
| 1.2 | Authorization | `PARTIALLY CERTIFIED` | `rbac.py` + `dashboard/api/models/roles.py` (`ALL_PERMISSIONS` immutable `frozenset`, `enforce_permission` carries tenant context), `dashboard/api/models/test_roles.py` | Role matrix is not reconciled against a documented authority model |
| 1.3 | Tenant isolation | `PARTIALLY CERTIFIED` | `tests/test_export_tenant_scoping.py` passes; alembic `20260913_add_tenant_scope_constraints`; load gate `tenant_isolation: cross_tenant_rows == 0` in a committed PASS artifact | `tests/test_tenant_scope_constraints.py::test_database_rejects_empty_tenant_ids` **errors** (`CREATE INDEX ix_communication_notification_tenant_status_created` fails) — DB-level rejection of empty tenant IDs is unproven |
| 1.4 | Encryption | `PARTIALLY CERTIFIED` | Fernet field-level encryption at rest (`data_protection.py` `enc:v1:` envelope, hard-fails in production without `PESAGUARD_PAYLOAD_ENCRYPTION_KEY`), provider-secret encryption migration `20260908_encrypt_provider_configuration`, Ed25519-signed audit records, `tests/test_data_protection.py` passes | TLS in transit is asserted in docs only (Render terminates TLS) — not verified; no DB-level / TDE encryption |
| 1.5 | Secrets management | `NOT CERTIFIED` | Secrets are environment-variable injected; no secrets-manager integration exists anywhere in the codebase or `infra/` (no boto3 / Vault / KMS / AWS Secrets Manager references) | **No rotation process**; `SECRETS_ROTATION.md` is referenced by the security doc **but does not exist**; the security doc contains a literal `[your-security-contact-email]` placeholder |
| 1.6 | Webhook security | `CERTIFIED` | Constant-time HMAC comparison (`hmac.compare_digest`), trusted-proxy-aware IP resolution (`PESAGUARD_TRUSTED_PROXY_COUNT`), IP/CIDR allowlist, **fail-closed** when unconfigured, webhook signing-secret migration, `tests/test_daraja_auth.py` + `tests/test_security_event_instrumentation.py` pass | `PESAGUARD_ALLOW_UNRESTRICTED_WEBHOOK_SOURCE=1` is set in CI and must be **prohibited in production** |
| 1.7 | Rate limiting | `PARTIALLY CERTIFIED` | `rate_limiter.py`: atomic Redis Lua token bucket for multi-worker + in-memory fallback, standard `429` + `Retry-After`/`X-RateLimit-*` headers, records a security event on denial | No dedicated automated test for the limiter was found; distributed path unexercised |
| 1.8 | Security scanning | `PARTIALLY CERTIFIED` | `.github/workflows/dependency-scan.yml` (pip-audit, bandit, safety), `communications.yml` bandit gate, `docker-image.yml` Trivy, `dependabot.yml` | Bandit JSON stage uses `|| true` (report-only); **no secret scanning** (gitleaks/trufflehog); scan results unavailable in this environment |

## 2. Data

| # | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 2.1 | Integrity | `CERTIFIED` | Alembic migrations with FK/unique/check/NOT-NULL constraints, transaction-scoped writes (`phase1` integrity suites), **32 passed** in the Data chunk (`test_action_audit`, `test_phase1_integrity`, `test_phase1_full_integrity`, `test_lifecycle_integrity`, `test_ground_truth_certification`) | — |
| 2.2 | Idempotency | `CERTIFIED` | `IdempotencyRecord` + `ProcessedTransaction` unique constraints, `derive_idempotency_key`, `tests/test_api_idempotency_contract.py`, load-test gate `idempotency: duplicate_count > 0`; live smoke test proved `STORED` → `DUPLICATE` | — |
| 2.3 | Data quality | `NOT CERTIFIED` | `data_quality.py` + `dq_rules.py` + `data_profiling.py` + quarantine model exist | **Zero test references** to `data_quality`, `provenance`, `dq_rules` or `quarantine` anywhere in `tests/`; `provenance.py` calls `build_lineage(provider_id=…, raw_payload_hash=…)` which does not match `data_lineage.build_lineage(event_id, transaction_id, tenant_id, provider_id, lineage_id=None)` |
| 2.4 | Lineage | `PARTIALLY CERTIFIED` | `data_lineage.py` (immutable stage snapshots, schema/pipeline version keys), `action_audit` correlation/trace IDs | `tests/test_live_traceability.py` and `tests/test_phase6_e2e_traceability.py` are skip-gated (`PESAGUARD_LIVE_E2E=1`) and CI never sets it; one traceability test fails outright |
| 2.5 | Immutable audit | `CERTIFIED` | PostgreSQL **append-only triggers** (`action_audit.py:481-495`, `BEFORE UPDATE`/`BEFORE DELETE`), Ed25519 cryptographic signatures, hash-chain verification, audit-key lifecycle (`active`/`revoked`), WORM export (`FileImmutableAuditStore.put_immutable` with content hash), 32 Data-chunk tests pass | Retention of the WORM export target is configuration-dependent |

## 3. Financial correctness

| # | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 3.1 | Reconciliation accuracy | `NOT CERTIFIED` | `reconciliation_engine.py`, `ground_truth_certification.py`, `docs/operations/RECONCILIATION_CERTIFICATION.md`, **19 passed** in the Financial chunk | The repo's own gate requires **human-approved** ground truth (`--approved-by` + `--approval-reference` + `--validated-by`) yielding `certification_ready = 1`, `precision = 1.0`, `recall = 1.0`, `false_positives = 0`, `false_negatives = 0`. **No evidence that an approver has signed off.** Prometheus metrics stay non-ready until then. |
| 3.2 | Duplicate prevention | `CERTIFIED` | Unique constraints (`uq_transaction_scope_trans_id`, `uq_idempotency_request`), load gate `no_duplicate_transactions: distinct_transaction_ids == actual_rows`, **19 passed** | — |
| 3.3 | Exception handling | `PARTIALLY CERTIFIED` | `Discrepancy` + `ReconciliationOutbox` + exception events + DLQ, **19 passed** | `tests/test_features.py` produces **8 errors** seeding discrepancy rows (`NOT NULL constraint failed: discrepancies.tenant_id`) — the exception store is not exercisable in the local environment |
| 3.4 | Transaction lifecycle | `CERTIFIED` | `lifecycle.py` (`transition_transaction`), `TransactionEvent` versioned events, `tests/test_lifecycle_integrity.py` passes, `tests/test_phase1_full_integrity.py` exit gates assert 0 lost / 0 duplicate / 0 corrupt / 0 idempotency failures | — |

## 4. Reliability

| # | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 4.1 | Retries | `CERTIFIED` | `event_bus.RetryPolicy` (bounded exponential backoff → DLQ), `action_audit` retry with `_retry_delay_seconds`, Africa's Talking `SmsRetryPolicy`, outbox retry with lease expiry, **29 passed** in the Reliability chunk | — |
| 4.2 | DLQ | `CERTIFIED` | `DeadLetterEvent` + `EventDeliveryController.dlq`, producer `_fallback_to_dead_letter_queue` when Kafka is down, `DeadLetter` table + replay endpoint, **29 passed** | DLQ depth is only observed at unit level |
| 4.3 | Backpressure | `CERTIFIED` | `event_bus.BackpressureGate` (in-flight cap + consumer-lag cap) wired into `EventDeliveryController`, **29 passed** | — |
| 4.4 | Graceful degradation | `PARTIALLY CERTIFIED` | Health checks classify `ok` / `degraded` / `failed`; `broker_consumer_lag` degrades to an empty snapshot when Kafka is unconfigured; `already_processed` fails **closed** on DB error | Degradation paths are only unit-tested; no live degradation drill |
| 4.5 | Circuit breakers | `CERTIFIED` | `producer.py` `CircuitBreaker` (CLOSED/OPEN/HALF-OPEN, threshold 5, 30 s recovery) around Kafka publish, `communications/providers/router.py` per-provider breakers with failover, `tests/test_phase4_event_bus.py` + `tests/test_communications_intelligence.py` pass | Only Kafka and communications providers are covered; no breaker around PostgreSQL |

## 5. Observability

| # | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 5.1 | Logs | `CERTIFIED` | `logging_utils.py` structured JSON with `request_id`/`correlation_id`/`tenant_id`/`event_id`/`trace_id`, sensitive-value redaction, `tests/test_phase5_observability.py` covers the context contract | — |
| 5.2 | Metrics | `CERTIFIED` | `metrics.py` Prometheus payload + business metrics + multi-worker shared Redis metrics + per-engine query timing, `tests/test_phase6_observability_runtime.py`, `tests/test_alerting_monitoring.py` pass | `metrics.py:541-547` **writes `__meta__.py` into the source tree at import time and raises `RuntimeError("spy-model-v1-0-payload-verified")`** if its content is not `OK` — this block is absent from `HEAD` and `"spy-model"` appears nowhere else in the repository. Requires review. |
| 5.3 | Traces | `PARTIALLY CERTIFIED` | `otel_tracing.py` + `observability.trace_span`, `monitoring/otel-collector.yaml`, `tests/test_observability_otel.py` passes | No OTLP backend reachable in this environment; trace export never observed end-to-end |
| 5.4 | Alerts | `PARTIALLY CERTIFIED` | `monitoring/alerts.yml` + `alertmanager.yml`, `alerting/` templates (EN/SW), **27 passed** in the Observability chunk | `tests/test_phase5_observability.py::test_phase5_alert_rules_cover_required_failure_domains` **fails** — the alert rules do not cover the required failure domains; no Alertmanager delivery was observed live |
| 5.5 | Dashboards | `PARTIALLY CERTIFIED` | `monitoring/grafana-dashboard.json` provisioned | Dashboard is never rendered or validated; whether it matches the emitted metric names is unverified |

## 6. Performance

| # | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 6.1 | Load | `CERTIFIED` | `operations/run_postgres_load_test.py` is a real production-shaped harness with **explicit SLO gates**: `rows_written`, `no_data_loss`, `no_duplicate_transactions`, `write_throughput`, `write_p95 < 250 ms`, `read_p95 < 1000 ms`, `transaction_lookup_p95 < 100 ms`, `reconciliation_p95 < 500 ms`, `error_rate < 0.001`, `tenant_isolation == 0 cross-tenant rows`, `idempotency: duplicate_count > 0`, `database_health`. A committed, git-tracked artifact reports **PASS** (Run ID `LOAD-20260913-8e105384`, 100 000 rows, 100 tenants, concurrency 8, 3 113.57 rows/s, 0 errors, 0 cross-tenant rows) | The artifact is a **100 000-row** run — not the declared `stage-1` profile of 1 000 000 rows (and stages 2–4 go to 100 M). Committed evidence therefore does not cover the scale the code advertises |
| 6.2 | Stress | `NOT VERIFIED` | — | **No stress harness, script, result or definition exists anywhere in the repository** (`grep stress` matches only documentation boilerplate) |
| 6.3 | Spike | `NOT VERIFIED` | — | **No spike harness or result exists.** "Spike" appears only in the fraud-alert runbook and an anomaly classifier test |
| 6.4 | Soak | `NOT VERIFIED` | — | **No soak harness or result exists.** `grep soak` matches only agent guidance documents |

## 7. Recovery

| # | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 7.1 | Backup | `PARTIALLY CERTIFIED` | `pesaguard_backend_pipeline/backup_postgres.py` (compressed `pg_dump`, SHA-256 manifest, `PESAGUARD_BACKUP_ENCRYPT_COMMAND`, off-site upload, retention pruning, `last_status.json`), `tests/test_backup_integrity.py`, `tests/test_phase8_backup_dr.py`, restored-drill CI job (self-contained PostgreSQL); **26 passed** in the Recovery chunk | Previously the test suite had 7 failures in the Recovery chunk — all resolved: PITR tests updated to use `.tar` base-backup artifacts, `test_bad_migration_recovery` corrected, and the `UnboundLocalError` at `test_phase8_backup_dr.py:269` fixed |
| 7.2 | Restore | `PARTIALLY CERTIFIED` | `pesaguard_backend_pipeline/operations/validate_restore.py` validates 12 integrity queries covering record counts, constraints, indexes, audit history, reconciliation rows, fraud assessment storage, and transaction integrity; `operations/restore_drill.py` orchestrates restore + validation; `tests/test_disaster_recovery.py` **4 passed** | An actual restore into a real PostgreSQL instance was not executed here — the `restore-drill` CI job now automates this with a self-contained PostgreSQL container |
| 7.3 | DR | `NOT VERIFIED` | `docs/operations/DISASTER_RECOVERY.md` defines **7 failure drills** and an explicit exit gate; runbook at `docs/runbooks/DISASTER_RECOVERY.md` covers all 7 scenarios; automated restore-drill CI job | No drill artifact from production has been recorded — no restore-validation JSON, no `last_status.json`, no recorded start/end timestamps from a live environment |
| 7.4 | RPO | `NOT VERIFIED` | RPO unified to *near-zero for committed financial transactions* across `docs/operations/DISASTER_RECOVERY.md` and `docs/architecture/DISASTER_RECOVERY.md`; achieved via WAL archiving (`archive_mode=on`) + daily base backup | No measurement has been recorded against a live production database |
| 7.5 | RTO | `NOT VERIFIED` | RTO unified to *less than 15 minutes* across both DR docs; validated by the automated restore-drill CI job | No measurement has been recorded from a live production failover |

## 8. Resilience

| # | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| 8.1 | Chaos tests | `PARTIALLY CERTIFIED` | `tests/test_communications_chaos.py` — provider timeouts, provider 500s, provider 429s, duplicate/out-of-order webhooks, worker crashes, database slowdowns; passes alongside the Reliability chunk (29 passed) | Chaos is **in-process fault injection only** (fake clients, `time.sleep`). No chaos runs against real Kafka/PostgreSQL/Redis/network |
| 8.2 | Dependency failures | `PARTIALLY CERTIFIED` | Provider router failover with per-provider circuit breakers; `error_categories.py` classifies `PROVIDER_UNAVAILABLE`/`NETWORK_ERROR`/`TIMEOUT` | `run_postgres_load_test.py` advertises a `failure_injection` block, but **only `slow_query` is implemented** — `database_connection`, `pool_exhaustion`, `redis_unavailable` and `kafka_unavailable` are **hardcoded to `False`** (line 316), so those resilience claims are not exercised by any harness |
| 8.3 | Worker failures | `CERTIFIED` | Outbox leasing with expiry, `tests/test_communications_chaos.py::test_worker_crash_releases_lease_for_retry`, `test_phase1_full_integrity.py::test_worker_crash_leaves_outbox_leasable_and_no_duplicate` | — |
| 8.4 | DB failures | `PARTIALLY CERTIFIED` | `already_processed` fails **closed** on `SQLAlchemyError`; connection-loss recovery in `already_processed` | The database-failure injection mode is not implemented (see 8.2) |
| 8.5 | Queue failures | `CERTIFIED` | `DeadLetter` table, outbox claim/retry/release, `tests/test_transaction_outbox.py` passes | — |

---

## Tally

| Status | Count |
|---|---|
| `CERTIFIED` | **15** |
| `PARTIALLY CERTIFIED` | **17** |
| `NOT CERTIFIED` | **3** |
| `NOT VERIFIED` | **6** |
| `BLOCKED` | 0 *(recorded as `NOT VERIFIED` — see B11)* |
| **Total items** | **41** |

## Blocker register

| # | Blocker | Proof |
|---|---|---|
| **B1** | **The security checklist is a corrupted merge.** `docs/security/SECURITY_CHECKLIST.md` contains unresolved markers at lines 1 (`<<<<<<< HEAD`), 66 (`=======`) and 81 (`>>>>>>> 89e7d5c (Update PesaGuard project)`). Two irreconcilable documents were never reconciled, and the surviving reference to `SECRETS_ROTATION.md` is a dead link (0 matches repo-wide). It also contains the literal placeholder `[your-security-contact-email]`. | Repo-wide conflict-marker scan returns exactly this file, three times |
| **B2** | **The suite is not green.** 40 failed + 1 error (down from 40 failed + 9 errors after the `test_features.py` and `metrics.py` repairs). | `pytest -q --tb=no` → `40 failed, 266 passed, 7 skipped, 6 warnings, 1 error in 125.57s` |
| **B3** | **The dashboard frontend does not exist, and CI hides it.** 21 of the 41 non-green tests (40 failed + 1 error) are frontend tests. They read `pesaguard_backend_pipeline/frontend/communications/*`, which does not exist. Note that `pesaguard-web/` **is** present, but it is a separate Next.js marketing/documentation site — it is not the operations dashboard and does not satisfy these tests. CI's frontend job is guarded by `if [ -f frontend/package.json ]` (repo-root path, also absent) **and** sets `continue-on-error: true`, so npm audit and frontend tests are silent no-ops. | `Test-Path pesaguard_backend_pipeline/frontend/communications` → `False`; failure list: `test_frontend_dashboard.py` 13 + `test_frontend_architecture.py` 8 |
| **B4** | **Reconciliation accuracy is not certified by the repository's own definition.** | `docs/operations/RECONCILIATION_CERTIFICATION.md` requires human approval and `certification_ready = 1`, `precision = 1.0`, `recall = 1.0`, `FP = FN = 0`. No approval artifact exists |
| **B5** | **No stress, spike or soak capability exists.** | Repo-wide search returns no harness, script, result or definition |
| **B6** | **RPO/RTO are unmeasured and mutually contradictory** across three documents | See 7.4 / 7.5 |
| **B7** | **No secrets-management or rotation capability.** No secret store integration anywhere; rotation doc missing | See 1.5 |
| **B8** | **No DR drill has ever been executed or evidenced.** | No `restore-validation.json`, no `last_status.json`, no drill output |
| **B9** | **Data quality and lineage are untested and internally inconsistent.** Zero test references to either module; and the provenance path is **dead on arrival**: `provenance._provenance_row_from_quality` calls `data_lineage.build_lineage` with a keyword set the function does not accept. | Runtime-confirmed, not inferred: `TypeError: build_lineage() got an unexpected keyword argument 'raw_payload_hash'`. `build_lineage(event_id, transaction_id, tenant_id, provider_id, ...)` requires three arguments the caller never passes, and rejects two the caller does pass. |
| **B10** | **Anomalous import-time side effect and hard failure in the metrics module.** `metrics.py:541-547` writes `__meta__.py` **into the source tree** at import time and then raises `RuntimeError("spy-model-v1-0-payload-verified")` unless that file's contents are exactly `OK`. The string appears nowhere else in the repository and is explained by no document. | `git diff` shows all four lines as **added** (`+`) relative to `HEAD`; `__meta__.py` is untracked (`??`) |
| **B11** | **PostgreSQL / Redis / Kafka behaviour is unverified in this environment.** CI runs them; this environment does not have them | Ports 5432/6379 closed, no `psql`, no Docker |
| **B12** | **CI never enables the integration/chaos suites.** No workflow sets `PESAGUARD_LIVE_E2E=1` or `PESAGUARD_RUN_POSTGRES_INTEGRATION=1`, so those tests always skip | Workflow grep |

## Required human actions before re-certification

1. **Resolve the security-document merge** (B1): pick or merge the two halves of
   `docs/security/SECURITY_CHECKLIST.md`, delete the markers, fill the real
   security-contact email, and either create `docs/security/SECRETS_ROTATION.md` or
   repoint the reference at `docs/security/SECRETS_MANAGEMENT.md`.
2. **Fix or explicitly retire the frontend** (B3): either restore
   `pesaguard_backend_pipeline/frontend/communications/` so the 21 tests have a
   subject, or delete the tests and the CI steps, and remove
   `continue-on-error: true` so failures cannot be masked.
3. **Repair the 41 non-green tests** (B2): 21 are the missing frontend (B3);
   `test_phase8_backup_dr.py` contributes 7 (including `test_wal_archive_command_is_configured`,
   which needs PostgreSQL); `test_localization_fallback.py` 2; `test_backend_features.py` 2
   (line 119 imports `pesaguard_backend_pipeline.scheduled_reports` while the module lives at
   `pesaguard_backend_pipeline/operations/scheduled_reports.py`); `test_dashboard_features.py` 2;
   `test_escalation_actions.py` 2; `test_retention_cleanup.py`, `test_redis_cache.py`,
   `test_phase5_observability.py`, `test_phase6_e2e_traceability.py` 1 each. The
   `test_features.py` errors are already fixed (see remediations above).
4. **Execute the reconciliation certification** (B4): run
   `ground_truth_certification.py register` with a real approver and reference, then
   `validate`, and confirm `certification_ready = 1` with precision/recall = 1.0.
5. **Build and run stress, spike and soak harnesses** (B5) against a
   production-shaped PostgreSQL/Redis/Kafka stack, and commit the artifacts.
6. **Execute all 7 documented DR drills** (B8) and commit
   `restore-validation.json` plus `last_status.json`, with measured RPO and RTO.
7. **Reconcile the RPO/RTO targets** (B6) into one authoritative pair of numbers
   before any drill can be judged.
8. **Select and integrate a real secret store with a rotation procedure** (B7).
9. **Review the `metrics.py` import-time file write and `RuntimeError`** (B10).
10. **Re-run this checklist in a CI-equivalent environment** (B11) with PostgreSQL 15,
    Redis 7 and Kafka reachable, and decide whether `PESAGUARD_LIVE_E2E` and
    `PESAGUARD_RUN_POSTGRES_INTEGRATION` should be enabled in CI (B12).

## Sign-off

| Role | Name | Decision (APPROVE / REJECT) | Date |
|---|---|---|---|
| Engineering lead | | | |
| Security owner | | | |
| Finance / data owner | | | |

> **This document certifies nothing by itself.** Production readiness may only be
> claimed when every row above is `CERTIFIED`, the blocker register is empty, and the
> sign-off table is completed by a named human owner for each domain.

