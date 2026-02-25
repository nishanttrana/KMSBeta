ALTER TABLE data_protection_policy
    ADD COLUMN tokenization_mode_policy_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE data_protection_policy
    ADD COLUMN token_format_policy_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE data_protection_policy
    ADD COLUMN allow_token_renewal BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN max_token_renewals INTEGER NOT NULL DEFAULT 3;

ALTER TABLE data_protection_policy
    ADD COLUMN allow_one_time_tokens BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN detokenize_allowed_purposes_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN detokenize_allowed_workflows_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN require_detokenize_justification BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN allow_bulk_tokenize BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN allow_bulk_detokenize BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN allowed_redaction_detectors_json TEXT NOT NULL DEFAULT '["EMAIL","PHONE","SSN","PAN","IBAN","NAME","CUSTOM"]';

ALTER TABLE data_protection_policy
    ADD COLUMN allowed_redaction_actions_json TEXT NOT NULL DEFAULT '["replace_placeholder","remove","hash"]';

ALTER TABLE data_protection_policy
    ADD COLUMN max_custom_regex_length INTEGER NOT NULL DEFAULT 512;

ALTER TABLE data_protection_policy
    ADD COLUMN max_custom_regex_groups INTEGER NOT NULL DEFAULT 16;

ALTER TABLE data_protection_policy
    ADD COLUMN max_detokenize_batch INTEGER NOT NULL DEFAULT 10000;

ALTER TABLE data_protection_policy
    ADD COLUMN require_token_context_tags BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN required_token_context_keys_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN masking_role_policy_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE data_protection_policy
    ADD COLUMN token_metadata_retention_days INTEGER NOT NULL DEFAULT 365;

ALTER TABLE data_protection_policy
    ADD COLUMN redaction_event_retention_days INTEGER NOT NULL DEFAULT 365;

ALTER TABLE tokens
    ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE tokens
    ADD COLUMN use_limit INTEGER NOT NULL DEFAULT 0;

ALTER TABLE tokens
    ADD COLUMN renew_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE tokens
    ADD COLUMN metadata_tags_json TEXT NOT NULL DEFAULT '{}';
