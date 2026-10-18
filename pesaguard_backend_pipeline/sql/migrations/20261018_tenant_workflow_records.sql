-- Additive migration for tenant-scoped dashboard workflow records.
-- Apply through the deployment's approved migration runner; do not use create_all in production.
CREATE TABLE IF NOT EXISTS tenant_workflow_records (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL CHECK (tenant_id <> ''),
    domain VARCHAR(40) NOT NULL CHECK (domain IN (
        'reconciliation_run','matching_rule','data_quality_finding',
        'scheduled_reconciliation','settlement_review','refund_reversal_request',
        'report_definition','report_run','fraud_investigation','privacy_request','support_case'
    )),
    status VARCHAR(32) NOT NULL CHECK (status IN (
        'draft','requested','queued','running','completed','failed','open','triage',
        'in_progress','pending_review','approved','rejected','resolved','closed',
        'disabled','scheduled','cancelled','needs_information'
    )),
    title VARCHAR(200) NOT NULL,
    description TEXT NULL,
    payload JSON NOT NULL DEFAULT '{}',
    created_by VARCHAR(128) NOT NULL,
    updated_by VARCHAR(128) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_workflow_tenant_domain_status_created
    ON tenant_workflow_records (tenant_id, domain, status, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_workflow_tenant_domain_updated
    ON tenant_workflow_records (tenant_id, domain, updated_at DESC);
