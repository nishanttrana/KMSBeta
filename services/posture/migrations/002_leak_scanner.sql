CREATE TABLE IF NOT EXISTS leak_scan_targets (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL, -- git_repo, container_image, log_stream, s3_bucket, env_file
    uri TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_scanned_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    scan_count INT NOT NULL DEFAULT 0,
    open_findings INT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS leak_scan_jobs (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_name TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    findings_count INT NOT NULL DEFAULT 0,
    error TEXT,
    progress_pct INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS leak_findings (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_name TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    type TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    context_preview TEXT NOT NULL DEFAULT '',
    entropy DOUBLE PRECISION NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'open',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMPTZ,
    resolved_by TEXT,
    notes TEXT,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_leak_findings_target ON leak_findings(tenant_id, target_id, status);
CREATE INDEX IF NOT EXISTS idx_leak_scan_jobs_target ON leak_scan_jobs(tenant_id, target_id, created_at DESC);
