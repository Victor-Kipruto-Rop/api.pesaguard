# PesaGuard Disaster Recovery

## Recovery objectives

- These are service targets, not measured capabilities. Certification requires a
  timed restore/failover exercise against the production topology.
- **RPO:** near-zero for committed financial transactions. Every accepted webhook must be present in PostgreSQL and its transaction outbox before a successful response.
- **RTO:** less than 15 minutes for restoration of the database and gateway processing path.

The objectives are measured from the incident timestamp to the first successful health check, database query, webhook acceptance, and outbox publication after restoration.

## Backup controls

`backup_postgres.py --backup` performs a compressed `pg_dump`, writes a SHA-256 manifest, optionally encrypts the artifact using `PESAGUARD_BACKUP_ENCRYPT_COMMAND`, uploads the artifact and manifest through `PESAGUARD_BACKUP_UPLOAD_COMMAND`, and prunes artifacts older than `PESAGUARD_BACKUP_RETENTION_DAYS`.

Production must set:

- `PESAGUARD_BACKUP_ENCRYPT_COMMAND`
- `PESAGUARD_BACKUP_DECRYPT_COMMAND`
- `PESAGUARD_BACKUP_UPLOAD_COMMAND`
- `PESAGUARD_BACKUP_RETENTION_DAYS`
- `PESAGUARD_BACKUP_STATUS_FILE`

The systemd service and timer run the backup daily. Backup status is written to `last_status.json`; monitoring must alert when the status is not `succeeded` or the newest artifact exceeds the RPO window.

## Point-in-time recovery

Base backups alone do not provide near-zero RPO. Production PostgreSQL must enable WAL archiving to encrypted, off-site storage, for example with `archive_mode=on`, `archive_timeout` bounded to the RPO, and an archive command that writes immutable, encrypted WAL objects. Validate WAL replay by restoring the latest base backup and replaying WAL through the target recovery timestamp.

## Replication and regional failure

WAL archiving is not a live replica. Production must additionally use a managed PostgreSQL standby or streaming replica in an independent failure domain, with monitored replication lag, automated or operator-approved promotion, and tenant/data-residency controls. The application must be able to point to the promoted endpoint through deployment configuration. The repository's Docker Compose stack enables local WAL archiving for development and drills; it does not provision regional replication or claim automatic failover.

## Restore validation

Restore into an isolated PostgreSQL instance. Do not restore over production in place. Run:

```powershell
py -3.13 pesaguard_backend_pipeline/operations/validate_restore.py `
  --database-url $env:RESTORE_DATABASE_URL `
  --output restore-validation.json
```

The validator checks record counts, constraints, indexes, audit history, reconciliation rows, fraud assessment storage, and database query functionality. Follow it with an application health check and a synthetic idempotent webhook/outbox test.

For a repeatable restore drill, run the repository command against a disposable PostgreSQL target:

```powershell
py -3.13 pesaguard_backend_pipeline/operations/restore_drill.py `
  --backup-file $env:BACKUP_FILE `
  --database-url $env:RESTORE_DATABASE_URL `
  --output restore-drill.json
```

The command restores the artifact, runs the integrity validator, records duration and validation output, and exits non-zero unless both restore and validation succeed. The target URL must point to an isolated database, never the production database.

## Failure drills

Run each drill in an isolated environment and record start/end timestamps, backup artifact, WAL position, restored counts, and validation output:

1. Stop PostgreSQL and restore the latest base backup.
2. Delete or corrupt a non-production table and restore it from the backup.
3. Apply a bad migration in an isolated clone and restore the prior database snapshot.
4. Destroy the application server and redeploy from the pinned image.
5. Remove the local backup volume and restore from the off-site copy.
6. Rotate compromised database credentials and verify encrypted backups remain unreadable without the recovery key, then restore with the replacement secret.
7. Simulate region loss by restoring the off-site backup and WAL archive in the recovery region.

The exit gate is met only when backup succeeds, restore succeeds, integrity validation passes, the measured RPO is within target, and the measured RTO is below 15 minutes.
