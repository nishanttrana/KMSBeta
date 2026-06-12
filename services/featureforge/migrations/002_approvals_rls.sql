-- Second-principal approvals, request-id correlation on the event trail, and
-- tenant row-level security (same pattern as services/keycore/migrations/012).
BEGIN;

CREATE TABLE IF NOT EXISTS ff_approvals (
    intent_id  TEXT NOT NULL,
    tenant_id  TEXT NOT NULL,
    approver   TEXT NOT NULL,
    comment    TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (intent_id, approver)
);
CREATE INDEX IF NOT EXISTS idx_ff_approvals_tenant ON ff_approvals(tenant_id, created_at);

ALTER TABLE ff_events ADD COLUMN IF NOT EXISTS request_id TEXT NOT NULL DEFAULT '';

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'ff_intents' AND policyname = 'tenant_isolation_ff_intents'
    ) THEN
        ALTER TABLE ff_intents ENABLE ROW LEVEL SECURITY;
        EXECUTE 'CREATE POLICY tenant_isolation_ff_intents ON ff_intents USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'ff_events' AND policyname = 'tenant_isolation_ff_events'
    ) THEN
        ALTER TABLE ff_events ENABLE ROW LEVEL SECURITY;
        EXECUTE 'CREATE POLICY tenant_isolation_ff_events ON ff_events USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'ff_approvals' AND policyname = 'tenant_isolation_ff_approvals'
    ) THEN
        ALTER TABLE ff_approvals ENABLE ROW LEVEL SECURITY;
        EXECUTE 'CREATE POLICY tenant_isolation_ff_approvals ON ff_approvals USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

COMMIT;
