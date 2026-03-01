ALTER TABLE governance_system_state
    ADD COLUMN IF NOT EXISTS posture_force_quorum_destructive_ops BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS posture_require_step_up_auth BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS posture_pause_connector_sync BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS posture_guardrail_policy_required BOOLEAN NOT NULL DEFAULT FALSE;
