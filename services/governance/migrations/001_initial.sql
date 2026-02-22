CREATE TABLE IF NOT EXISTS approval_policies (
    id                    TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL,
    name                  TEXT NOT NULL,
    description           TEXT,
    scope                 TEXT NOT NULL,
    trigger_actions       JSONB NOT NULL,
    required_approvals    INTEGER NOT NULL,
    total_approvers       INTEGER NOT NULL,
    approver_roles        JSONB NOT NULL,
    approver_users        JSONB,
    timeout_hours         INTEGER DEFAULT 48,
    escalation_hours      INTEGER,
    escalation_to         JSONB,
    retention_days        INTEGER DEFAULT 90,
    notification_channels JSONB NOT NULL DEFAULT '["email"]'::jsonb,
    status                TEXT NOT NULL DEFAULT 'active',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS approval_requests (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    policy_id          TEXT NOT NULL REFERENCES approval_policies(id),
    action             TEXT NOT NULL,
    target_type        TEXT NOT NULL,
    target_id          TEXT NOT NULL,
    target_details     JSONB NOT NULL,
    requester_id       TEXT NOT NULL,
    requester_email    TEXT,
    requester_ip       INET,
    status             TEXT NOT NULL DEFAULT 'pending',
    required_approvals INTEGER NOT NULL,
    current_approvals  INTEGER NOT NULL DEFAULT 0,
    current_denials    INTEGER NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ NOT NULL,
    resolved_at        TIMESTAMPTZ,
    retain_until       TIMESTAMPTZ,
    callback_service   TEXT NOT NULL,
    callback_action    TEXT NOT NULL,
    callback_payload   JSONB
);

CREATE TABLE IF NOT EXISTS approval_votes (
    id             TEXT PRIMARY KEY,
    request_id     TEXT NOT NULL REFERENCES approval_requests(id),
    tenant_id      TEXT NOT NULL,
    approver_id    TEXT NOT NULL,
    approver_email TEXT NOT NULL,
    vote           TEXT NOT NULL,
    vote_method    TEXT NOT NULL,
    comment        TEXT,
    token_hash     BYTEA,
    voted_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address     INET
);

CREATE TABLE IF NOT EXISTS approval_tokens (
    id             TEXT PRIMARY KEY,
    request_id     TEXT NOT NULL REFERENCES approval_requests(id),
    approver_email TEXT NOT NULL,
    token_hash     BYTEA NOT NULL,
    action         TEXT NOT NULL,
    used           BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS governance_settings (
    tenant_id                     TEXT PRIMARY KEY,
    approval_expiry_minutes       INTEGER NOT NULL DEFAULT 60,
    expiry_check_interval_seconds INTEGER NOT NULL DEFAULT 60,
    smtp_host                     TEXT,
    smtp_port                     TEXT,
    smtp_username                 TEXT,
    smtp_password                 TEXT,
    smtp_from                     TEXT,
    smtp_starttls                 BOOLEAN NOT NULL DEFAULT TRUE,
    notify_dashboard              BOOLEAN NOT NULL DEFAULT TRUE,
    notify_email                  BOOLEAN NOT NULL DEFAULT TRUE,
    challenge_response_enabled    BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by                    TEXT,
    updated_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_approval_pending ON approval_requests(tenant_id, status) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_approval_target ON approval_requests(tenant_id, target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_approval_expiry ON approval_requests(expires_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_approval_votes_req ON approval_votes(tenant_id, request_id, approver_email);
CREATE INDEX IF NOT EXISTS idx_approval_tokens_lookup ON approval_tokens(request_id, token_hash, action);
