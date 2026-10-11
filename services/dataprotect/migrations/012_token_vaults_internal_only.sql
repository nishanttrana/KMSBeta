-- The external database token vault is removed (9.0.0-beta). It stored a
-- database's address and a password reference and labelled the vault
-- "external", but nothing ever connected to that database: the tokens of
-- every vault have always been in token_vault_records here. The label and
-- the unused settings are cleared so a vault says where its tokens are.
-- The columns stay (an older node of a cluster may still select them).

UPDATE token_vaults
SET storage_type = 'internal', external_provider = '', external_config_json = '{}', external_schema_version = ''
WHERE storage_type <> 'internal' OR external_provider <> '' OR external_config_json <> '{}' OR external_schema_version <> '';
