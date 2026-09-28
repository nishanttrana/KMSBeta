-- Crypto agility: the customer's migration policy. Each rule says which
-- algorithms it covers, what happens to keys that use them from a date the
-- customer picks (deprecated, decrypt/verify only, disallowed), and an
-- optional target algorithm. Keycore enforces it on every key operation.
CREATE TABLE IF NOT EXISTS agility_policy_rules (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    match_kind TEXT NOT NULL,
    match_value TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    effective_date TIMESTAMPTZ NOT NULL,
    target_algorithm TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);
