# Pilot Readiness: 6 Critical Features — Verification Checklist

## Overview

This document is a verification checklist for six reliability controls relevant to a PesaGuard pilot. It describes intended behavior and verification steps; it is not proof that every control is implemented, enabled in the target environment, or production-validated. Confirm code evidence, passing tests, migration state, configuration, and staging results for each item before declaring it complete.

---

## 1. Webhook Idempotency

### Problem Solved
- Daraja may retry webhook deliveries on timeout/network errors
- Without idempotency, duplicate transactions could be processed multiple times
- Leads to duplicate reconciliation, incorrect reporting, and customer confusion

### Solution
**Unique constraint + duplicate check in 3 layers:**

1. **Database Layer** (`models.py`): 
   - `Transaction.trans_id` has `UniqueConstraint('trans_id')`
   - Database enforces atomicity: duplicate INSERT fails cleanly

2. **Event Store** (`event_store.py`):
   - `already_processed(trans_id)` checks DB before accepting webhook
   - Conservative on errors: assumes already processed to prevent duplicates
   - `mark_processed()` uses unique constraint to prevent duplicates at insert

3. **Application Layer** (`app.py`):
   - Fast path: check `event_store.already_processed()` first
   - If true: return 200 OK without processing (idempotent)
   - If false: process and record atomically

### Deployment
```bash
# 1. Apply migration
cd /opt/pesaguard
alembic upgrade head

# 2. Verify constraint
psql -c "\\d transactions" | grep uq_transaction
# Output: uq_transaction_trans_id UNIQUE CONSTRAINT

# 3. Test: Send same webhook twice
curl -X POST https://api.pesaguard.co.ke/webhook/mpesa/confirmation \
  -H "Content-Type: application/json" \
  -d '{"TransID": "test123", "TransAmount": 100, "MSISDN": "254712345678", ...}'

# Second request should return 200 OK (idempotent)
```

### Verification
```bash
# Check for duplicate transactions in DB
psql -c "SELECT trans_id, COUNT(*) FROM transactions GROUP BY trans_id HAVING COUNT(*) > 1;"
# Should return empty (no duplicates)
```

---

## 2. Fast 200 Response to Daraja

### Problem Solved
- Daraja expects HTTP 200 response within 10-15 seconds
- Slow operations (Kafka publishing, notifications, reconciliation) cause timeouts
- Timeouts trigger Daraja retries, causing load spikes

### Solution
**Async processing with immediate acknowledgment:**

1. **Webhook Endpoint** (`app.py:/webhook/mpesa/confirmation`):
   - Validate payload (< 2ms)
   - Check idempotency (< 5ms)
   - **Return 200 OK immediately** (< 10ms total)

2. **Background Processing** (all async):
   - Enqueue to RQ/Redis (optional, if available)
   - Fallback to direct Kafka publish (sync)
   - Never blocks HTTP response

3. **Failure Handling**:
   - Log errors for manual replay
   - Never return error to Daraja (would trigger retries)

### Code Changes
- `enqueue_transaction_event()` tries RQ first, falls back to sync Kafka
- `app.py` webhook endpoint: all slow work moved after 200 response
- Correlation IDs trace async tasks back to original requests

### Deployment
```bash
# Optional: Set up Redis for background job queue
export REDIS_URL="redis://localhost:6379/0"

# If Redis unavailable, sync Kafka fallback is automatic
# Monitor logs for "queued to background job" vs "sync fallback" messages
```

### Verification
```bash
# 1. Measure response time
time curl -X POST https://api.pesaguard.co.ke/webhook/mpesa/confirmation \
  -H "Content-Type: application/json" \
  -d '{...}'
# Should be < 50ms

# 2. Check logs for async queue status
tail -f /var/log/pesaguard/app.log | grep "Transaction event"
# Should see either "queued to background job" or "published to Kafka (sync fallback)"
```

---

## 3. Webhook Signature & IP Validation

### Problem Solved
- Attackers could send fake webhooks impersonating Daraja
- Without validation, could trigger false reconciliation alerts
- Could be used for DDoS by spamming webhook endpoint

### Solution
**Multi-layer validation:**

1. **IP Allowlist** (`security_helpers.py`):
   - Whitelist Daraja IP ranges (regional)
   - Support X-Forwarded-For for proxied requests
   - Reject early (before parsing JSON)

2. **Signature Verification** (`app.py:_verify_daraja_signature()`):
   - Daraja includes `X-Daraja-Signature` header (HMAC-SHA256)
   - Verify: `HMAC-SHA256(consumer_secret, request_body) == signature`
   - Optional: only validate if header present (backward compatible)

3. **Rate Limiting** (`rate_limiter.py`):
   - Per-IP rate limit (30 req/min by default)
   - Returns 429 with Retry-After header
   - Prevents credential brute-force

### Deployment
```bash
# 1. Set Daraja credentials in environment
export DARAJA_CONSUMER_KEY="xxxxx"
export DARAJA_CONSUMER_SECRET="xxxxx"

# 2. Verify signature validation in logs
tail /var/log/pesaguard/app.log | grep "signature\|source\|rate"

# 3. Test: Send invalid signature
curl -X POST https://api.pesaguard.co.ke/webhook/mpesa/confirmation \
  -H "X-Daraja-Signature: invalid" \
  -d '...'
# Should return 403 Forbidden
```

### Configuration
```bash
# Optional: Configure IP allowlist
export DARAJA_ALLOWED_IPS="196.201.214.0/23,196.201.215.0/24"

# Optional: Configure rate limit
export PESAGUARD_WEBHOOK_RATE_LIMIT_PER_MINUTE=30
```

---

## 4. Automated PostgreSQL Backups

### Problem Solved
- Data loss from storage failures, accidental deletes, or ransomware
- No automated restoration testing = backups don't work when needed
- Manual backups = human error

### Solution
**Daily automated backups with restoration testing:**

1. **Backup Script** (`backup_postgres.py`):
   - `pg_dump | gzip` for compression
   - Timestamps: `pesaguard_20260722_020000.sql.gz`
   - Default: `/var/backups/pesaguard/`

2. **Systemd Timer** (`pesaguard-backup.timer`):
   - Runs daily at 02:00 UTC (low traffic)
   - Automatic retry on failure
   - Persistent: runs missed triggers on startup

3. **Retention Policy**:
   - Keep 30 days of backups
   - Auto-cleanup old files
   - Configurable via `PESAGUARD_BACKUP_RETENTION_DAYS`

4. **Integrity Testing**:
   - Quick validation after backup (first 1000 bytes)
   - Confirms valid SQL and non-empty

### Deployment
```bash
# 1. Create backup directory
sudo mkdir -p /var/backups/pesaguard
sudo chown postgres:postgres /var/backups/pesaguard
sudo chmod 700 /var/backups/pesaguard

# 2. Copy backup script
sudo cp pesaguard_backend_pipeline/backup_postgres.py /usr/local/bin/pesaguard-backup.py
sudo chmod +x /usr/local/bin/pesaguard-backup.py

# 3. Install systemd units
sudo cp infra/pesaguard-backup.service /etc/systemd/system/
sudo cp infra/pesaguard-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable pesaguard-backup.timer

# 4. Start backup service
sudo systemctl start pesaguard-backup.timer

# 5. Verify (run manual backup)
sudo /usr/bin/python3 /opt/pesaguard/pesaguard_backend_pipeline/backup_postgres.py --backup
```

### Verification
```bash
# List recent backups
python3 backup_postgres.py --list

# Test integrity
python3 backup_postgres.py --test

# Full restoration test (on staging only!)
python3 backup_postgres.py --restore /var/backups/pesaguard/pesaguard_20260722_020000.sql.gz

# Verify data after restore
psql -c "SELECT COUNT(*) FROM transactions;"
```

### Configuration
```bash
# Optional: Change backup directory
export PESAGUARD_BACKUP_DIR="/mnt/backup-storage/pesaguard"

# Optional: Change retention
export PESAGUARD_BACKUP_RETENTION_DAYS=60
```

---

## 5. Extended Health Check Endpoint

### Problem Solved
- Kubernetes/load balancers can't determine service degradation
- External monitoring doesn't know if Kafka/Redis are down
- Can't distinguish between "critical failure" and "degraded but operational"

### Solution
**Comprehensive health checks with graduated status:**

1. **Status Levels**:
   - `ok`: All critical services running (DB + most optionals)
   - `degraded`: Database OK but Kafka/Redis/Daraja config issues
   - `failed`: Database down (data unavailable)

2. **Checks Performed** (`health.py`):
   - **Database**: SQL query on main connection pool
   - **Kafka**: Broker bootstrap connectivity
   - **Redis**: PING test (optional)
   - **Daraja**: Credential format check (optional, no external API call)

3. **Endpoint**: `GET /health`
   - Response: JSON with individual check statuses
   - HTTP code: 200 (ok), 503 (degraded/failed)
   - Use in container orchestration for readiness/liveness probes

### Deployment
```bash
# 1. Kubernetes readiness probe
# In pod spec:
readinessProbe:
  httpGet:
    path: /health
    port: 5000
  initialDelaySeconds: 5
  periodSeconds: 10

# 2. Kubernetes liveness probe
livenessProbe:
  httpGet:
    path: /health
    port: 5000
  initialDelaySeconds: 30
  periodSeconds: 30

# 3. Nginx upstream health check
upstream pesaguard {
   server api.pesaguard.co.ke;
  check interval=3000 rise=2 fall=5 timeout=1000 type=http;
  check_http_send "GET /health HTTP/1.0\\r\\n\\r\\n";
  check_http_expect_alive http_2xx;
}
```

### Verification
```bash
# Test health endpoint
curl https://api.pesaguard.co.ke/health

# Output (ok):
{
  "status": "ok",
  "service": "pesaguard",
  "checks": {
    "database": {"status": "ok"},
    "kafka": {"status": "ok"},
    "redis": {"status": "ok"},
    "daraja": {"status": "ok"}
  }
}

# Output (degraded, missing Kafka):
{
  "status": "degraded",
  "service": "pesaguard",
  "checks": {
    "database": {"status": "ok"},
    "kafka": {"status": "failed", "error": "unable to connect"},
    "redis": {"status": "ok"},
    "daraja": {"status": "ok"}
  }
}

# Check HTTP code
curl -o /dev/null -w "%{http_code}" https://api.pesaguard.co.ke/health
# 200 if ok, 503 if degraded/failed
```

---

## 6. Structured Logging with Correlation IDs

### Problem Solved
- Debugging distributed issues: which logs belong to same transaction?
- Tracing webhook -> Kafka -> reconciliation pipeline is tedious
- Correlating errors across services requires manual log grepping

### Solution
**Correlation IDs for end-to-end request tracing:**

1. **Per-Request Correlation ID**:
   - Generated on webhook arrival or extracted from `X-Correlation-ID` header
   - Propagated through all logs for that request
   - Returned in response headers for client reference

2. **Structured JSON Logs** (`logging_utils.py`):
   - All logs include: `correlation_id`, `trans_id`, `tenant_id`, `timestamp`
   - Easily parsed by ELK/Splunk/CloudWatch
   - Sample:
     ```json
     {
       "ts": "2026-07-22T07:30:45.123Z",
       "level": "INFO",
       "logger": "pesaguard.webhook",
       "correlation_id": "a1b2c3d4",
       "trans_id": "TX123456",
       "message": "Transaction accepted",
       "tenant_id": "default"
     }
     ```

3. **Context Propagation** (`contextvars`):
   - Async-safe: works with background jobs and concurrency
   - Automatic: set once on request, available in all logs

### Deployment
```bash
# 1. All logs automatically structured (no code changes needed)

# 2. Observe logs with correlation ID
tail -f /var/log/pesaguard/app.log | jq 'select(.correlation_id == "a1b2c3d4")'

# 3. Client can request correlation ID from response
curl -i https://api.pesaguard.co.ke/webhook/mpesa/confirmation
# Headers include: X-Correlation-ID: a1b2c3d4

# 4. Client can pass correlation ID for tracing
curl -H "X-Correlation-ID: my-request-123" \
   https://api.pesaguard.co.ke/webhook/mpesa/confirmation

# 5. Configure ELK/Splunk to parse JSON
# Example Filebeat config:
processors:
  - decode_json_fields:
      fields: ["message"]
      target: ""
      overwrite_keys: true
```

### Verification
```bash
# 1. Send test webhook and capture correlation ID
RESPONSE=$(curl -i https://api.pesaguard.co.ke/webhook/mpesa/confirmation -d '...')
CORR_ID=$(echo "$RESPONSE" | grep X-Correlation-ID | cut -d' ' -f2)

# 2. Grep all logs for that correlation ID
grep "$CORR_ID" /var/log/pesaguard/*.log
# Should see: webhook receive -> idempotency check -> Kafka queue -> reconciliation

# 3. Verify JSON structure
tail -1 /var/log/pesaguard/app.log | jq '.correlation_id, .trans_id, .tenant_id'
# Should output correlation_id, trans_id, tenant_id
```

---

## Testing Checklist

- [ ] **Idempotency**: Send duplicate webhook, verify no double-processing
- [ ] **Fast 200**: Measure webhook response time < 50ms
- [ ] **Signature validation**: Send webhook with invalid signature, verify 403
- [ ] **IP allowlist**: Send from unauthorized IP, verify 403
- [ ] **Backup**: Run manual backup, verify file exists and is non-empty
- [ ] **Restore**: Restore backup on staging, verify data integrity
- [ ] **Health check**: GET /health returns 200 with all checks ok
- [ ] **Health degraded**: Stop Kafka, GET /health returns 503 with degraded status
- [ ] **Correlation ID**: Send webhook, grep logs by correlation ID, verify tracing works

---

## Configuration Reference

### Environment Variables

```bash
# Database
DATABASE_URL="postgresql://pesaguard:pesaguard@localhost:5432/pesaguard"

# Webhook security
DARAJA_CONSUMER_KEY="xxxxx"
DARAJA_CONSUMER_SECRET="xxxxx"
DARAJA_ALLOWED_IPS="196.201.214.0/23,196.201.215.0/24"
PESAGUARD_WEBHOOK_RATE_LIMIT_PER_MINUTE=30
PESAGUARD_WEBHOOK_MAX_BODY_BYTES=1048576

# Background jobs
REDIS_URL="redis://localhost:6379/0"
RQ_QUEUE_NAME="transaction_events"

# Backups
PESAGUARD_BACKUP_DIR="/var/backups/pesaguard"
PESAGUARD_BACKUP_RETENTION_DAYS=30

# Logging
LOG_LEVEL="INFO"

# Kafka
KAFKA_BOOTSTRAP_SERVERS="localhost:9092"
KAFKA_TOPIC_TRANSACTIONS="mpesa.transactions.raw"
```

---

## Troubleshooting

### Webhook timeouts still occurring
```bash
# Check if background job queue is working
redis-cli INFO stats | grep "total_commands_processed"

# If Redis down, check logs for "sync fallback"
tail -f /var/log/pesaguard/app.log | grep "sync fallback"

# Measure actual response time
for i in {1..10}; do time curl -o /dev/null -s https://api.pesaguard.co.ke/webhook/...; done
```

### Backups not running
```bash
# Check systemd timer status
sudo systemctl status pesaguard-backup.timer
sudo systemctl list-timers pesaguard-backup.timer

# Check service logs
sudo journalctl -u pesaguard-backup.service -n 50

# Manual test
sudo python3 /opt/pesaguard/pesaguard_backend_pipeline/backup_postgres.py --backup
```

### Health check returning failed
```bash
# Check individual service connectivity
sudo systemctl status postgresql
redis-cli PING
kafka-console-producer --bootstrap-servers localhost:9092 --topic test

# Test health endpoint directly
curl https://api.pesaguard.co.ke/health | jq '.checks'
```

### Duplicate transactions detected
```bash
# Check if idempotency check is working
psql -c "SELECT trans_id, COUNT(*) FROM transactions GROUP BY trans_id HAVING COUNT(*) > 1;"

# Check event_store logs
grep "already_processed\|mark_processed" /var/log/pesaguard/app.log

# Review webhook retry pattern in Daraja dashboard
```

---

## Monitoring & Alerting

### Key Metrics to Monitor

```prometheus
# Webhook response time (should be < 50ms)
histogram_quantile(0.95, rate(pesaguard_webhook_duration_seconds_bucket[5m]))

# Duplicate transactions rejected (should be low)
rate(pesaguard_webhook_duplicates_total[5m])

# Async job queue depth (should stay < 1000)
pesaguard_background_job_queue_depth

# Health check failures (should be 0)
rate(pesaguard_health_check_failed_total[5m])

# Backup failures (should be 0)
rate(pesaguard_backup_failed_total[1d])
```

### Alert Rules
```yaml
- alert: WebhookHighLatency
  expr: histogram_quantile(0.95, rate(pesaguard_webhook_duration_seconds_bucket[5m])) > 0.05
  for: 5m

- alert: DatabaseHealthCheckFailed
  expr: pesaguard_health_check_database_failed > 0
  for: 1m

- alert: BackupMissing
  expr: time() - pesaguard_last_backup_timestamp_seconds > 86400
  for: 30m
```

---

## Summary

| Control to verify | Required evidence before marking complete | Deployment dependency to verify |
|---|---|---|
| Webhook idempotency | Duplicate callback tests and database uniqueness evidence; retries must not create duplicate financial effects | Current schema migration applied and database constraints verified |
| Fast callback acknowledgement | Integration test proving acknowledgement timing and durable handoff semantics under dependency failure | Worker/queue configuration and provider callback timeout behavior verified |
| Signature and source validation | Positive and negative signature tests plus source-validation configuration evidence | Correct provider secret and trusted source configuration supplied securely |
| Automated backups | Successful scheduled backup plus a tested restore with recorded result | Backup timer/scheduler enabled, storage reachable, retention and alerting configured |
| Extended health checks | Tests proving readiness reflects required dependencies, not only process liveness | Deployment health probe targets the intended readiness endpoint |
| Correlation IDs | Tests showing an incoming/request-generated ID is propagated into structured logs and responses | Log collection preserves the field and redacts sensitive data |

Do not mark any control as complete based on this table alone. Record the test run, environment, timestamp, responsible operator, and result for each item. Pilot readiness requires the relevant checks to pass in staging; production readiness also requires the release gates in the repository README.
