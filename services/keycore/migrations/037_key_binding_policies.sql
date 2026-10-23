-- 037: key binding policies (13.51.0-beta, docs/KEYS.md "Binding
-- policies"). A binding policy says how a key may be reached: through which
-- channel (a direct caller, "rest", or a platform service such as
-- kms-kmip), from which networks and as which workload identities. Every
-- active policy that applies to a key must pass for any operation on it;
-- keycore checks them in its key access decision. The old
-- key_binding_configs table (migration 012) was never enforced and was
-- dropped in 016. Replicated (pkg/clustercatalog, keycore).
CREATE TABLE IF NOT EXISTS key_binding_policies (
    tenant_id           TEXT NOT NULL,
    id                  TEXT NOT NULL,
    name                TEXT NOT NULL,
    all_keys            BOOLEAN NOT NULL DEFAULT FALSE,
    key_ids             TEXT NOT NULL DEFAULT '[]',
    label_selector      TEXT NOT NULL DEFAULT '{}',
    channels            TEXT NOT NULL DEFAULT '[]',
    source_networks     TEXT NOT NULL DEFAULT '[]',
    workload_identities TEXT NOT NULL DEFAULT '[]',
    status              TEXT NOT NULL DEFAULT 'active',
    created_by          TEXT NOT NULL DEFAULT '',
    updated_by          TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS key_binding_policies_name ON key_binding_policies (tenant_id, name);
