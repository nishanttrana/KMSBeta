-- Dynamic database credentials (13.34.0-beta, dbengine.go). A role says
-- how to create and drop a short-lived login on a customer database whose
-- admin credential lives in Playbooks -> Credentials; a lease is one login
-- handed out. No password is stored: it is returned once.
CREATE TABLE IF NOT EXISTS secret_db_roles (
    tenant_id              TEXT NOT NULL,
    name                   TEXT NOT NULL,
    connection_id          TEXT NOT NULL,
    engine                 TEXT NOT NULL DEFAULT 'postgres',
    creation_statements    TEXT NOT NULL,
    revocation_statements  TEXT NOT NULL,
    default_ttl_seconds    INTEGER NOT NULL,
    max_ttl_seconds        INTEGER NOT NULL,
    created_by             TEXT NOT NULL DEFAULT '',
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS secret_db_leases (
    tenant_id       TEXT NOT NULL,
    id              TEXT NOT NULL,
    role_name       TEXT NOT NULL,
    username        TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'active',
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP NOT NULL,
    max_expires_at  TIMESTAMP NOT NULL,
    ended_at        TIMESTAMP,
    last_error      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_secret_db_leases_due ON secret_db_leases (state, expires_at);
CREATE INDEX IF NOT EXISTS idx_secret_db_leases_role ON secret_db_leases (tenant_id, role_name, created_at DESC);
