CREATE TABLE IF NOT EXISTS reporting_alerts (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    audit_event_id TEXT NOT NULL DEFAULT '',
    audit_action TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    service TEXT NOT NULL DEFAULT '',
    actor_id TEXT NOT NULL DEFAULT '',
    actor_type TEXT NOT NULL DEFAULT '',
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'new',
    acknowledged_by TEXT NOT NULL DEFAULT '',
    acknowledged_at TIMESTAMP,
    resolved_by TEXT NOT NULL DEFAULT '',
    resolved_at TIMESTAMP,
    resolution_note TEXT NOT NULL DEFAULT '',
    incident_id TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '',
    is_escalated BOOLEAN NOT NULL DEFAULT FALSE,
    escalated_from TEXT NOT NULL DEFAULT '',
    dedup_count INTEGER NOT NULL DEFAULT 1,
    channels_sent_json TEXT NOT NULL DEFAULT '[]',
    channel_status_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_reporting_alerts_severity ON reporting_alerts (tenant_id, severity, status);
CREATE INDEX IF NOT EXISTS idx_reporting_alerts_status ON reporting_alerts (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_reporting_alerts_target ON reporting_alerts (tenant_id, target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_reporting_alerts_incident ON reporting_alerts (tenant_id, incident_id);
CREATE INDEX IF NOT EXISTS idx_reporting_alerts_audit ON reporting_alerts (tenant_id, audit_event_id);
CREATE INDEX IF NOT EXISTS idx_reporting_alerts_created_at ON reporting_alerts (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS reporting_incidents (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    alert_count INTEGER NOT NULL DEFAULT 0,
    first_alert_at TIMESTAMP,
    last_alert_at TIMESTAMP,
    assigned_to TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_reporting_incidents_status ON reporting_incidents (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_reporting_incidents_last_alert ON reporting_incidents (tenant_id, last_alert_at DESC);

CREATE TABLE IF NOT EXISTS reporting_alert_rules (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    condition TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'warning',
    event_pattern TEXT NOT NULL DEFAULT '',
    threshold INTEGER NOT NULL DEFAULT 0,
    window_seconds INTEGER NOT NULL DEFAULT 0,
    channels_json TEXT NOT NULL DEFAULT '[]',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS reporting_severity_overrides (
    tenant_id TEXT NOT NULL,
    audit_action TEXT NOT NULL,
    severity TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, audit_action)
);

CREATE TABLE IF NOT EXISTS reporting_notification_channels (
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    config_json TEXT NOT NULL DEFAULT '{}',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS reporting_report_jobs (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    format TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    filters_json TEXT NOT NULL DEFAULT '{}',
    result_content TEXT NOT NULL DEFAULT '',
    result_content_type TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_reporting_report_jobs_status ON reporting_report_jobs (tenant_id, status);

CREATE TABLE IF NOT EXISTS reporting_scheduled_reports (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    template_id TEXT NOT NULL,
    format TEXT NOT NULL,
    schedule TEXT NOT NULL,
    filters_json TEXT NOT NULL DEFAULT '{}',
    recipients_json TEXT NOT NULL DEFAULT '[]',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_reporting_scheduled_reports_due ON reporting_scheduled_reports (enabled, next_run_at);
