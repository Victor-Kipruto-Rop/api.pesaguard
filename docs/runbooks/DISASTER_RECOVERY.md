# PesaGuard Runbook

> Deployment note: this repository's current release workflow uses a configured Render deployment hook. Kubernetes commands below apply only if the target environment is actually deployed to Kubernetes; do not run them against a Render or Docker Compose deployment. Confirm the deployment provider before executing provider-specific recovery steps.

## Service health checks
1. Verify the webhook receiver and dashboard API health endpoints at http://127.0.0.1:5000/health and http://127.0.0.1:5001/health.
2. Check the Prometheus-compatible metrics endpoints for throughput, latency, and open discrepancy counts.
3. If the services are healthy but alerts are missing, review the alerting service logs and recent delivery failures.

## Kafka lag growth
1. Check the consumer lag metric and compare with recent throughput.
2. Inspect the reconciliation service logs for backpressure or database issues.
3. If lag persists for more than 10 minutes, page the operator and pause non-critical alert traffic.

## Connector authentication failure
1. Confirm the tenant credentials and token expiry state.
2. Re-run the connector sync manually and verify a successful response.
3. If failures continue, disable live alerts for that tenant and route the incident to the operator.

## Daraja callback spike
1. Validate the webhook receiver health and confirm the request volume.
2. Check for duplicate or malformed payloads that could be retried.
3. Scale the webhook receiver or rate-limit the source if the backlog continues to grow.


---

## Disaster Recovery — Failure Scenarios

> **Primary objectives:** RPO near-zero for committed financial transactions; RTO < 15 minutes.
> Every procedure below assumes the incident has been acknowledged and an operator
> is executing under an active incident bridge. Record start/end timestamps,
> the backup artifact used, and the WAL position for every drill.

### DR-1 — PostgreSQL service failure / data directory loss

**Symptoms:** `pg_isready` returns false; database connections time out;
pod liveness/readiness probes are failing.

**Recovery steps:**
1. Confirm the failure is not a network or DNS issue by testing connectivity
   from the application pods to the Postgres service endpoint.
2. If a standby is available (multi-AZ replica), promote it:
   ```bash
   pg_ctl promote -D /var/lib/postgresql/data
   ```
3. If no standby is available, provision a fresh PostgreSQL instance.
4. Restore the latest base backup:
   ```bash
   python pesaguard_backend_pipeline/backup_postgres.py --restore /var/backups/pesaguard/pesaguard_LATEST.sql.gz.enc
   ```
5. Configure WAL replay in `postgresql.auto.conf` and restart:
   ```conf
   recovery_target_timeline = 'latest'
   restore_command = 'cp /var/lib/postgresql/wal_archive/%f %p'
   recovery_target_time = 'YYYY-MM-DD HH:MM:SS'
   ```
6. Run the integrity validator:
   ```powershell
   py -3.13 pesaguard_backend_pipeline/operations/validate_restore.py --database-url $env:RESTORE_DATABASE_URL --output restore-validation.json
   ```
7. Verify application health: `curl -sf http://localhost:8000/health`
8. Re-enable Kafka consumers and outbox workers.

**Exit gate:** Backup restore succeeded, integrity validation `passed`,
application health check returns 200, webhook acceptance confirmed.

### DR-2 — Non-production table corruption or accidental DELETE

**Symptoms:** A table (e.g. staging data, temporary reconciliation cache)
has been dropped or corrupted.

**Recovery steps:**
1. Determine whether the affected table is production (tenant data) or
   non-production (staging/temp).
2. For non-production tables: restore only the affected table from the
   latest base backup using `pg_restore --table=<name>`:
   ```bash
   pg_restore -h localhost -U pesaguard -d pesaguard \
     --table=<corrupted_table> /var/backups/pesaguard/pesaguard_LATEST.sql.gz
   ```
3. For production tables: escalate to DR-5 (region failure) or DR-1
   (full restore + WAL replay).
4. Verify the restored table:
   ```sql
   SELECT count(*) FROM <table>;
   ```

**Exit gate:** Row count matches expected; application queries succeed.

### DR-3 — Bad migration in production

**Symptoms:** A newly deployed migration causes application errors, data
integrity violations, or performance regression.

**Recovery steps:**
1. Immediately halt the migration rollout (block further deployments).
2. **Do not** roll forward — investigate the root cause.
3. If the migration has not been applied to all tenants, roll back the
   deployment to the previous pinned image.
4. If the migration was applied:
   a. Identify the pre-migration timestamp from deployment logs.
   b. Create a base backup of the current (post-migration) state for
      forensic analysis.
   c. Restore the database to the pre-migration point using PITR:
      ```bash
      python pesaguard_backend_pipeline/backup_postgres.py \
        --pitr-restore /var/backups/pesaguard/pesaguard_BASEBACKUP.tar \
        --target-time 'YYYY-MM-DD HH:MM:SS'
      ```
   d. Verify the restored database passes the integrity validator.
   e. Re-run the migration with the fix.
5. Document the incident and add a regression test.

**Exit gate:** PITR restore to pre-migration timestamp succeeds; integrity
validation `passed`; corrected migration applies cleanly.

### DR-4 — Application server failure / container crash

**Symptoms:** API returns 502/503; pods are CrashLooping;
dashboard unavailable but database is healthy.

**Recovery steps:**
1. Check pod status: `kubectl get pods -n pesaguard`
2. Inspect logs: `kubectl logs -n pesaguard deployment/pesaguard-api --tail=100`
3. If the issue is isolated to the pod, restart it:
   ```bash
   kubectl rollout restart deployment/pesaguard-api
   ```
4. If the issue is image-level, redeploy from the pinned image:
   ```bash
   kubectl set image deployment/pesaguard-api pesaguard-api=ghcr.io/pesaguard/api:v1.4.2
   ```
5. Verify health:
   ```bash
   kubectl rollout status deployment/pesaguard-api
   curl -sf https://api.pesaguard.co.ke/health
   ```

**Exit gate:** All pods healthy; health endpoint returns 200; Kafka
consumers resume processing.

### DR-5 — Local backup volume failure / off-site recovery

**Symptoms:** Backup directory is missing, corrupted, or the primary host
is destroyed.

**Recovery steps:**
1. Identify the off-site backup location from the deployment configuration
   (`PESAGUARD_BACKUP_UPLOAD_COMMAND` target).
2. Download the latest backup artifact and manifest from off-site storage:
   ```bash
   aws s3 cp s3://pesaguard-backups/latest/ /tmp/restore/ --recursive
   ```
3. If the backup is encrypted, decrypt using the managed key manager:
   ```bash
   PESAGUARD_BACKUP_DECRYPT_COMMAND /tmp/restore/artifact.enc > /tmp/restore/artifact
   ```
4. Verify the manifest (SHA-256 + file size).
5. Restore into a fresh database instance:
   ```bash
   python pesaguard_backend_pipeline/backup_postgres.py --restore /tmp/restore/artifact
   ```
6. Replay WAL archives to minimize RPO:
   ```conf
   restore_command = 'cp /var/lib/postgresql/wal_archive/%f %p'
   recovery_target_timeline = 'latest'
   recovery_target_time = 'YYYY-MM-DD HH:MM:SS UTC'
   ```
7. Run integrity validation and application health check.

**Exit gate:** Restore succeeds; integrity validation `passed`;
measured RPO within target (typically seconds with WAL replay).

### DR-6 — Credential compromise / secret rotation

**Symptoms:** A database credential, API token, or encryption key has been
exposed, leaked, or suspected of compromise.

**Recovery steps:**
1. **Immediate:** Revoke all exposed credentials in the relevant IAM/system:
   - AWS: Delete the compromised access key pair in IAM.
   - PostgreSQL: Rotate the database master password in RDS.
   - Application: Rotate JWT secret, encryption keys, webhook secret keys
     via the secret manager.
2. **Verify encrypted backups remain secure:**
   - Encrypted backups (`.enc` files) must NOT be decryptable with the old key.
   - The `PESAGUARD_BACKUP_ENCRYPT_COMMAND` uses an external key manager;
     only the new key should be active.
3. **Restore with the replacement secret:**
   ```bash
   DATABASE_URL="postgresql://postgres:NEW_PASSWORD@host:5432/db" \
   python pesaguard_backend_pipeline/backup_postgres.py --restore /var/backups/pesaguard/LATEST.sql.gz.enc
   ```
4. Deploy the new credentials to the running application.
5. Verify all integrations (Kafka, Redis, payment providers) reconnect
   successfully.
6. Audit all access logs for unauthorized activity in the 72-hour window
   before detection.

**Exit gate:** All compromised credentials revoked and replaced; application
operating with new secrets; no unauthorized access detected in audit logs.

### DR-7 — Region failure / multi-region failover

**Symptoms:** Primary region (e.g., `us-east-1`) is unreachable due to
outage, network partition, or large-scale incident.

**Recovery steps:**
1. Declare region failure and activate the recovery region (e.g., `eu-west-1`).
2. Restore the latest off-site base backup in the recovery region:
   ```bash
   aws s3 cp s3://pesaguard-backups/latest/ /tmp/restore/ --recursive
   python pesaguard_backend_pipeline/backup_postgres.py --restore /tmp/restore/artifact
   ```
3. Restore WAL archives from the recovery region's archived bucket:
   ```conf
   archive_command = 'aws s3 cp %p s3://pesaguard-backups-wal-recovery/%f'
   restore_command = 'aws s3 cp s3://pesaguard-backups-wal-recovery/%f %p'
   recovery_target_timeline = 'latest'
   ```
4. Start PostgreSQL in recovery mode and let it replay WAL to the latest
   point.
5. Verify data integrity with `validate_restore.py`.
6. Update DNS / load balancer to point traffic to the recovery region.
7. Monitor for tenant isolation: ensure data-residency rules are respected.

**Exit gate:** Recovery region database restored and validated; traffic
routed to recovery region; tenant data-residency compliance verified.

---

## Exit Gate (applies to all scenarios)

Every recovery is considered complete only when **all** of the following hold:

1. Backup artifact integrity verified (SHA-256 manifest matches).
2. Restore succeeded (exit code 0 from `backup_postgres.py --restore`).
3. Integrity validation `passed` from `validate_restore.py`.
4. Measured RPO is within target (near-zero for committed transactions).
5. Measured RTO is below 15 minutes.
6. Application health check returns 200.
7. Webhook acceptance and outbox publication confirmed (idempotent test).
