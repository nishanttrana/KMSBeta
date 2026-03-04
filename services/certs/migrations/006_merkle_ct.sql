-- Certificate Transparency Merkle tree tables

CREATE TABLE IF NOT EXISTS cert_merkle_epochs (
  id          TEXT      NOT NULL,
  tenant_id   TEXT      NOT NULL,
  epoch_number INTEGER  NOT NULL,
  leaf_count  INTEGER   NOT NULL DEFAULT 0,
  tree_root   TEXT      NOT NULL DEFAULT '',
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, epoch_number)
);

CREATE TABLE IF NOT EXISTS cert_merkle_leaves (
  epoch_id      TEXT      NOT NULL,
  tenant_id     TEXT      NOT NULL,
  leaf_index    INTEGER   NOT NULL,
  cert_id       TEXT      NOT NULL,
  serial_number TEXT      NOT NULL DEFAULT '',
  subject_cn    TEXT      NOT NULL DEFAULT '',
  leaf_hash     TEXT      NOT NULL,
  logged_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (epoch_id, tenant_id, leaf_index)
);

CREATE INDEX IF NOT EXISTS idx_cert_merkle_leaves_cert
  ON cert_merkle_leaves (tenant_id, cert_id);
