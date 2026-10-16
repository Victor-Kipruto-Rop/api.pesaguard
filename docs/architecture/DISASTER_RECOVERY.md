# PesaGuard Disaster Recovery

## Overview
This document describes the daily backup process, offsite storage, and restore procedure for the PesaGuard Postgres database and Kafka replay capability.

## Backup Policy
- Frequency: daily backup of Postgres data using `pg_dump`.
  - Retention: keep daily base backups for 30 days, weekly archive snapshots for 6 months, and WAL archives for 30 days for point-in-time recovery.
  - Encryption: encrypt artifacts with an externally managed key before off-site upload. Base backups use pg_basebackup format; WAL archives are written to encrypted, off-site storage with archive_mode=on and archive_timeout bounded to the RPO.
- Evidence: each artifact has a SHA-256 manifest and must pass full-stream integrity verification before being considered fresh.
- Recovery targets (not yet measured in production): near-zero RPO for committed financial transactions; RTO < 15 minutes. The automated restore-drill CI job checks restore behavior in its disposable topology; it does not prove production meets either target. Record measured RPO/RTO from representative recovery drills before certification.
  - Storage: copy backup files off the primary host to separate object storage or backup storage. Replication via streaming replica or managed standby provides live failover within the primary region.
  - Recovery target: restore from the most recent base backup within the retention window, replaying WAL archives to the target timestamp for point-in-time recovery.

## Backup Commands
### Create a Postgres dump
```bash
export PGPASSWORD="${POSTGRES_PASSWORD:-pesaguard}"
pg_dump -h ${POSTGRES_HOST:-localhost} -p ${POSTGRES_PORT:-5432} -U ${POSTGRES_USER:-pesaguard} -F c -b -v -f "pesaguard-backup-$(date +%F).dump" ${POSTGRES_DB:-pesaguard}
```

### Verify the backup file
```bash
pg_restore -l pesaguard-backup-$(date +%F).dump | head -n 20
```

### Copy backup off-host
```bash
aws s3 cp pesaguard-backup-$(date +%F).dump s3://pesaguard-backups/$(date +%F)/pesaguard-backup.dump
```

## Kafka Retention
Kafka should be configured with deliberate retention settings so replay is possible after an incident.
For the local Docker Compose setup, metrics are configured in `docker/docker-compose.yml`:
- `KAFKA_LOG_RETENTION_HOURS: 168` (7 days)
- `KAFKA_LOG_RETENTION_BYTES: 10737418240` (10 GiB)

## Restore Procedure
### 1. Prepare a recovery environment
1. Provision a recovery VM or container with Postgres installed.
2. Create a fresh database if needed:
   ```bash
dropdb --if-exists pesaguard
createdb -h localhost -U ${POSTGRES_USER:-pesaguard} ${POSTGRES_DB:-pesaguard}
```

### 2. Restore from backup
```bash
export PGPASSWORD="${POSTGRES_PASSWORD:-pesaguard}"
pg_restore -h ${POSTGRES_HOST:-localhost} -p ${POSTGRES_PORT:-5432} -U ${POSTGRES_USER:-pesaguard} -d ${POSTGRES_DB:-pesaguard} -v "pesaguard-backup-YYYY-MM-DD.dump"
```

### 3. Verify restore success
```bash
psql -h ${POSTGRES_HOST:-localhost} -U ${POSTGRES_USER:-pesaguard} -d ${POSTGRES_DB:-pesaguard} -c "SELECT count(*) FROM discrepancy;"
```

### 4. Verify application startup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python pesaguard_backend_pipeline/app_2.py
```

  - Restore drill: quarterly isolated restore drill, plus an automated CI job that restores a base backup into a disposable PostgreSQL instance and runs the 12-query integrity gate from `validate_restore.py`.

## Notes
- The listed retention periods are placeholders and should be adjusted according to contractual and compliance requirements.
- Store backup files in a separate storage location from the production VM.
