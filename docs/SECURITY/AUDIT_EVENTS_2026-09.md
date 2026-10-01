# Audit events added in the 2026-09 security refresh

Every event goes through the unified audit pipeline (`pkg/audit` / service
publisher → `AUDIT` stream). On top of these, every HTTP request, including
every refusal (4xx), is audited by `pkg/auditmw`. The events below add
security meaning where a generic request record isn't enough.

Every row names the test that fails if its event stops being emitted (or
is emitted with the wrong `result` or `reason`). Naming the code that emits
an event is not proof; a new row is added only with its test (1.36.0-beta).

| Event | Emitted by | When | Severity | Test |
|---|---|---|---|---|
| `audit.auth.service_key_revoked` | auth (startup) | a service API key derived from the old public default secret is deleted | critical | `TestBootstrapRevokesKeysDerivedFromPublicDefaultSecret` |
| `audit.auth.service_key_retired` | auth (startup) | service keys from a previous `INTERNAL_SERVICE_BOOTSTRAP_SECRET` are deleted after rotation | warning | `TestBootstrapRetiresServiceKeysFromRotatedSecret` |
| `audit.governance.fips_mode_changed` | governance | an admin changes the platform FIPS mode (from, to, actor, reason, stopped features, restarts) | critical for a downgrade, else warning | `TestFIPSModeChangeImpactAndRollout` |
| `audit.governance.fips_mode_applied` | governance | a service instance starts and reports its FIPS mode (once per start) | info; warning if it differs from the platform mode | `TestFIPSRolloutIsAuditedOncePerStartAndOnCompletion` |
| `audit.governance.fips_mode_rollout_completed` | governance | every service runs the requested mode (once per change) | info | `TestFIPSRolloutIsAuditedOncePerStartAndOnCompletion` |
| `audit.cluster.publication_changed` | cluster-manager | a replication publication is created or its table set changes (which data this node offers members) | info | `TestSecureJoinEndToEnd` (two nodes: `scripts/test-cluster-replication.sh`) |
| `audit.cluster.member_joined` | cluster-manager (primary) | a node consumed a join token and received the master key and a replication role for its components | warning | `TestSecureJoinEndToEnd` |
| `audit.cluster.joined_cluster` | cluster-manager (member) | this node joined a cluster: master key replaced, components subscribed | warning | `TestSecureJoinEndToEnd` |
| `audit.auth.cluster_token_minted` | auth (primary) | a primary-signed 5-minute token is minted for a write a member forwarded (user, member node) | info; warning if the source is a service principal | `TestClusterMintOnlyForClusterManager` |
| `audit.auth.cluster_mint_refused` | auth (primary) | a forwarded-token mint was refused: caller isn't cluster-manager, malformed request, or the user must change their password (`reason`, `result: refused`) | warning | `TestClusterMintOnlyForClusterManager` |
| `audit.cluster.write_forwarded` | cluster-manager (primary) | a member's forwarded write was proxied to a service (member, service, method, path, actor, status) | info | `TestSecureJoinEndToEnd` |
| `audit.cluster.forward_refused` | cluster-manager (primary) | a forwarded write was refused: bad member credential (including a removed member), not forwardable, bad claims, identity refused | warning | `TestSecureJoinEndToEnd` |
| `audit.<service>.cluster_write_forwarded` | every service (member) | this member sent a lifecycle write to the primary (actor, method, path, primary, status) | info | `TestClusterForwarding` (pkg/config) |
| `audit.<service>.cluster_write_refused` | every service (member) | a write was refused on the member: `invalid_token`, `primary_unreachable` (down or TLS pin mismatch), `primary_write_required` | warning | `TestClusterForwarding` (pkg/config) |
| `audit.key.cluster_join_key_created` | keycore (member) | a one-time ML-KEM join key was created for a master-key transfer | info | `TestClusterMEKTransfer` |
| `audit.key.cluster_mek_exported` | keycore (primary) | the master key was sealed to a joining member (member, context, fingerprint) | critical | `TestClusterMEKTransfer` |
| `audit.key.cluster_mek_imported` | keycore (member) | a cluster master key was installed; keycore restarts on it | critical | `TestClusterMEKTransfer` |
| `audit.key.service_derive` | keycore | an internal service derives a purpose-bound working key | info | `TestServiceDeriveAudited` |
| `audit.key.service_derive_refused` | keycore | a service derive was refused (`result: refused`, `reason`: `service_identity_required`, `not_found`, `policy_denied`, `fips_mode_violation`, `access_denied` or `service_derive_failed`; with `key_id`, `purpose`, the calling `service`) | warning | `TestServiceDeriveAudited` |
| `audit.key.derive_refused` | keycore | a generic derive tries to use the reserved service-derive context | critical | `TestGenericDeriveCannotReproduceServiceSubkey` |
| `audit.cert.ocsp_refused` | certs | an OCSP request with a SHA-1 CertID in FIPS strict mode (`result: refused`, `reason: sha1_certid_fips_strict`) | warning | `TestOCSPStrictModeRefusesSHA1CertID` (strict mode) |
| `audit.dataprotect.request_refused` | dataprotect | a request without a verified platform token (or without a wrapper token on a wrapper runtime route) was refused before any handler ran (7.2.0-beta; `result: refused`, `reason: unauthenticated \| invalid_token`, `path`, `method`) | warning | `TestUnauthenticatedRequestsAreRefusedAndAudited` |
| `audit.dataprotect.fpe_refused` | dataprotect | FPE request for FF3-1, legacy encrypt or an unknown algorithm (`reason`, `result: refused`) | warning | `TestFPERefusalsAudited` |
| `audit.dataprotect.fpe_legacy_decrypted` | dataprotect | pre-1.26.0 ciphertext decrypted for migration (`LEGACY-FF1`/`LEGACY-FF3-1`) | warning | `TestFPELegacyDecryptMigrationPath` |
| `audit.key.create_refused` | keycore | key creation for an algorithm keycore does not generate (`reason`, `result: refused`) | warning | `TestCreateKeyRefusesAlgorithmsItCannotGenerate` |
| `audit.key.algorithm_label_corrected` | keycore (primary, startup) | a key record named material it didn't hold is relabelled to the real algorithm or `INVALID-MATERIAL` (recorded vs actual) | warning | `TestCorrectKeyAlgorithmLabels` (and `...Postgres`) |
| `audit.crypto.random_refused` | keycore | random bytes requested from a source that is unavailable (QKD, QRNG, no tenant HSM) | warning | `TestRandomNeverSubstitutesASource` |
| `audit.hsm.random_generated` | hsm-connector (kernel) | random bytes drawn from a tenant HSM with `C_GenerateRandom` (refusals included) | info | `TestRandomFromToken` (SoftHSM2) |
| `audit.key.kdf_refused` | keycore | scrypt or Argon2id KDF refused in FIPS strict mode | warning | `TestKDFStrictRefusalAudited` |
| `audit.pqc.migration_step_executed` | pqc | one migration step changed a key in keycore (`outcome`: `successor_created` with `successor_key_id`, or `rotated`) | info | `TestPQCServiceReadinessPlanExecuteRollback` |
| `audit.dataprotect.kdf_legacy_used` | dataprotect | identifier-derived (v1) working keys are used (at most every 5 min per key, with a count) | warning | `TestLegacyKeyStaysReadableAndIsAudited` |
| `audit.dataprotect.kdf_refused` | dataprotect | a derivation is refused: v1 after migration, v2 before it, or v1 in strict mode (at most once a minute per key and reason, with a count) | critical for v1 after migration, else warning | `TestKDFMigrationDualReadThenCutover` |
| `audit.dataprotect.kdf_migration_started` / `_vault_reprotected` / `_migration_completed` / `_migration_aborted` | dataprotect | per-key migration steps (actor, pinned version, counts; forced completion noted) | info; warning when forced or rows failed | `TestKDFMigrationDualReadThenCutover` (started, completed), `TestVaultReprotectKeepsTokens`, `TestKDFMigrationAbortAudited` |

## Key access (keycore)

| Event | When | Severity | Test |
|---|---|---|---|
| `audit.key.access_refused` | a key operation was denied by key access control (`result: refused`, `reason`: `authentication_required` (no verified token; there is no anonymous key use), `not_assigned_to_caller`, `deny_by_default`, `no_matching_grant`, `authentication_required`, `interface_policy`, `workload_not_authenticated`, `workload_operation_not_permitted`, `workload_key_not_bound`, or `not_visible` with `operation: read` for a read of a key the caller can't see (5.0.0-beta; tests `TestHiddenKeyReadsLookMissingAndAreAudited`, `TestKeyVisibilityPostgres`); with `key_id`, `operation`, the verified `actor`, `authenticated`, and `unverified_actor_headers` if any were sent) | warning | `TestActorHeadersCannotGrantAccess`, `TestActorGroupsHeaderDoesNotMatchGrants` |
| `audit.key.actor_headers_ignored` | a request carried `X-Actor-*` / `X-KMS-Subject` / `X-KMS-Interface` identity headers; they were ignored (`result: refused`, `reason: unverified_identity_headers`, `claimed` values, `verified_actor`) | warning | `TestActorHeadersCannotGrantAccess` |
| `audit.key.delegation_refused` | a service's request to use a key for a user was refused before any handler (6.0.0-beta; `result: refused`, `reason`: `delegation_by_non_service`, `delegation_usage_invalid`, `delegation_unverifiable`, `delegation_token_invalid`, `delegation_token_is_service` or `delegation_tenant_mismatch`; `caller`, `usage`, `path`). A delegated request that passes is decided as the user: `audit.key.access_refused` then carries `via` and `usage` (and `reason: delegation_tenant_mismatch` if the key is in another tenant, `reason: delegation_usage_mismatch` for a delegated `read` on a key operation, 6.18.0-beta), and every keycore event for it carries `on_behalf_of`, `via`, `usage` | warning | `TestDelegationRefusals`, `TestDelegatedUseDecidesWithUserGrant`, `TestDelegatedTenantMustOwnTheKey`, `TestDelegatedReadCannotPerformAKeyOperation`, `TestDelegatedPublicKeyReadUsesTheUsersView` |
| `audit.auth.service_identity_retired` | at startup, auth deleted the API keys and revoked the registration of a removed internal service (`retiredServiceClients`; 7.0.0-beta: `kms-payment`), with `keys_deleted`, `registration_revoked`; emitted only when something was revoked | warning | `TestBootstrapRetiresRemovedServiceIdentities` |
| `audit.key.request_refused` | a keycore request without a verified token was refused before any handler ran (4.0.0-beta; `result: refused`, `reason: unauthenticated`, `path`, `method`, `source_ip`, `unverified_actor_headers`). Only the three internal-token reconciler routes are exempt | warning | `TestTokenlessManagementRequestsAreRefused`, `TestActorHeadersWithoutTokenAreNotAnIdentity`, `TestAnonymousKeyUseIsRefused` |
| `audit.key.access_policy_updated` | kernel event for `PUT /keys/{id}/access-policy` (4.0.0-beta; was emitted by the service with a body-supplied `updated_by`). Actor from the token; details `grant_count`, `grants`. Refused with `unauthenticated`, `permission_denied` (no `key.access.manage`), `tenant_mismatch` or `not_key_owner` (caller neither created the key nor is a tenant admin) | warning | `TestKeyGrantsChangeOnlyByCreatorOrAdmin`, `TestAccessRoutesRefusalsAudited` |
| `audit.key.access_policy_read`, `access_groups_listed`, `access_group_created`, `access_group_deleted`, `access_group_members_updated`, `access_settings_read`, `access_settings_updated`, `interface_policies_listed`, `interface_policy_upserted`, `interface_policy_deleted` | kernel events for keycore's access-management routes (4.0.0-beta; the write subjects keep their pre-4.0 names). The `interface_tls_config_*` and `interface_port*` subjects went with their routes in 6.8.0-beta (`TestInterfacePortRoutesRemoved`). Permissions `key.access.read` / `key.access.admin`; refusals audited under the same subject | info (reads), warning (writes) | `TestAccessRoutesRefusalsAudited`, `TestReadonlyUserCannotManageKeys` |
| `audit.key.<action>_requested` for `create`, `import`, `form`, `bulk_import`, `bulk_rotate`, `bulk_delete`, `update`, `rotate`, `activate`, `deactivate`, `disable`, `destroy`, `export_policy_update`, `version_activate`, `version_deactivate`, `version_delete`, `usage_limit_update`, `usage_reset`, `approval_update`, `iv_mode_update`, `tag_upsert`, `tag_delete` | kernel request events for keycore's key-management writes (4.0.0-beta), including refusals (`unauthenticated`, `permission_denied`, `tenant_mismatch`) and failures. The domain events (`audit.key.rotate`, `audit.key.export_policy_updated`, ...) are still emitted by the service when the change happens | info; warning or critical for rotate, disable, destroy, export policy, approval | `TestKeyAdminRoutesRefusalsAudited`, `TestReadonlyUserCannotManageKeys`, `TestCreateKeyRefusesAnotherTenantInBody` |
| `audit.key.inventory_keys_read`, `inventory_orphans_read`, `inventory_duplicates_read`, `inventory_dependencies_read`, `rotation_analytics_read`, `rotation_overdue_read`, `enterprise_summary_read`, `health_summary_read`, `compromise_events_read`, `analytics_usage_read`, `analytics_hotspots_read`, `analytics_trends_read`, `dspm_findings_read`, `dspm_events_read`, `compliance_dashboard_read`, `cost_optimization_read` | kernel events for keycore's tenant-wide views (5.0.0-beta), permission `key.inventory.read`; refusals under the same subject | info | `TestInventoryRoutesRefusalsAudited`, `TestInventoryViewsNeedInventoryPermission` |
| `audit.key.ceremony_*` (`guardians_listed`, `guardian_created`, `guardian_deleted`, `ceremonies_listed`, `ceremony_read`, `ceremony_created`, `ceremony_share_submitted`, `ceremony_completed`, `ceremony_aborted`), `usage_meter_requested`, `rotation_metric_recorded`, `health_recalculated`, `inventory_synced`, `inventory_dependency_upserted`, `compromise_reported`, `compromise_status_updated`, `compromise_advisories_ingested`, `analytics_metric_recorded`, `enterprise_controls_listed`, `enterprise_control_read`, `enterprise_control_upserted`, `enterprise_anomaly_scan`, `dspm_finding_upserted`, `enterprise_kdf_derive`, `fingerprint_verified`, `search_token_created`, `enterprise_<category>_upserted`, `orchestration_run_requested`, `scheduling_job_*` (`jobs_listed`, `job_created`, `job_updated`, `job_deleted`), `attest_requested`, `verify_material_requested`, `fips_self_test_requested` | kernel events for keycore's remaining non-crypto routes (5.0.0-beta), refusals included (`unauthenticated`, `permission_denied`, `tenant_mismatch`); permissions in API_REFERENCE.md | info; warning or critical for compromise reports, ceremony completion, orchestration runs | `TestKeyOpsRoutesRefusalsAudited`, `TestKeyOpsNeedTheirPermission`, `TestFingerprintCheckRespectsVisibility` |
| `audit.key.destruction_checked` | kernel event for `POST /keys/{id}/destruction-check` (6.5.0-beta; replaces `zeroize_verify_requested`): details `result` (`removed`, `material_remains`, `incomplete`), `version_rows`, `hsm`, `hsm_objects`; refused with `reason: key_not_destroyed` for a live key, and `unauthenticated`, `permission_denied`, `tenant_mismatch` by the kernel | info; critical when material remains; warning when refused | `TestDestructionCheckFindsRemainingMaterial`, `TestDestructionCheckFindsHSMObjects` (SoftHSM2), `TestDestructionCheckPostgres`, `TestKeyOpsRoutesRefusalsAudited`, `TestKeyOpsNeedTheirPermission` |

| `audit.key.encrypt`, `decrypt`, `wrap`, `unwrap`, `sign`, `verify`, `mac`, `derive`, `kem_encapsulate`, `kem_decapsulate` | every key operation, named after the operation that ran (a wrap is never `encrypt`): `result` `success`, `refused` (`reason`: `ops_limit_reached`, `policy_denied`, `fips_mode_violation`, key-access or HSM reasons), `failure` (`error_message`) or `pending_approval`; with `key_id`, `operation` and measured `duration_ms`. The audit service builds the Operations metrics from these (2.1.0-beta) | info; warning for refusals | `TestCryptoOpsAuditedWithOutcomeAndDuration`, `TestOpsMetricsBuiltFromIngestedKeyOpEvents` (audit) |

Identity comes only from the verified token (CLAUDE.md rule 4). Proven by
`TestActorHeadersCannotGrantAccess`, `TestActorHeadersWithoutTokenAreNotAnIdentity`,
`TestActorGroupsHeaderDoesNotMatchGrants` and `TestActorBuiltFromVerifiedClaimsOnly`.

## System administration (governance)

| Event | When | Severity | Test |
|---|---|---|---|
| `audit.governance.system_admin_refused` | a system-administration route (settings, backups, restore, backup key, system state, FIPS mode, posture controls, network, FDE, SNMP, integrity) was refused (`result: refused`; `reason`: `authentication_required`, `tenant_required`, `tenant_mismatch`, `not_root_tenant`, `token_tenant_not_root` or `insufficient_privileges`; with `route`, `status`, `actor`, `authenticated`) | warning | `TestSystemAdminRoutesRequireVerifiedToken`, `TestSystemAdminRefusalReasons` |
| `audit.governance.builtin_policy_created` | the first approval request for an action with no active policy created the built-in policy covering it (today `posture.escalate_remediation`: approvers are tenant admins other than the requester), once per tenant (`policy_id`, `name`, `trigger_actions`, `approver_roles`, `trigger`). Deleting it is refused (`approval_refused`, `reason: builtin_policy_delete`); disabling or narrowing the required playbook policy is refused (`reason: builtin_policy_required`) | warning | `TestBuiltinPostureEscalationPolicy`, `TestBuiltinPlaybookPolicyRequired` |
| `audit.governance.builtin_policy_restored` | a required built-in policy (Playbook actions) found disabled, by 2.5.0-beta, was switched back on at the next approval request (`policy_id`, `name`, `trigger`) | warning | `TestBuiltinPlaybookPolicyRequired` |
| `audit.governance.authentication_refused` | a governance request carried a token that doesn't verify (`result: refused`, `reason: invalid_token`, `route`) | warning | `TestSystemAdminRoutesRequireVerifiedToken` |

Only a verified root administrator passes, plus the platform services listed
per route in `systemAdminServiceCallers` (keycore and policy read
`GET /governance/system/state`; posture writes
`PUT /governance/system/posture-controls`). Governance refuses to start
without its token-verification key (see below). Proven by
`TestSystemAdminRoutesRequireVerifiedToken`, `TestSystemAdminRefusalReasons`,
`TestSystemAdminServiceCallersAreRouteBound` and `TestMissingJWTKeyRefusesStart`.

## HSM integration (hsm-connector, keycore)

| Event | When | Severity | Test |
|---|---|---|---|
| `audit.hsm.<action>` | every hsm-connector request (kernel): `key_generated` (details `hsm_serial`, `hsm_token`), `tenant_key_ensured`, `encrypt`, `decrypt`, `sign`, `verify`, `key_destroyed`, `status_read`, `key_inspected`, `objects_listed`; refusals carry `result: refused` and `reason` (`caller_not_allowed`, `foreign_label`, `hsm_not_configured`, `library_not_allowed`, `pin_not_provided`, `integrity_check_failed`, `tenant_key_protected`, `algorithm_not_supported`, and the kernel's own) | info; warning for destroy and refusals | `TestAESKeyLivesInHSMAndEncrypts`, `TestRefusalsAudited` (pkg/hsmconnector, SoftHSM2) |
| `audit.key.hsm_settings_updated` | a tenant's "tenant key in HSM" / "HSM keys" switches changed (before and after) | warning | `TestHSMResidentKeyLifecycle` |
| `audit.key.hsm_refused` | keycore refused an HSM operation (`reason`: `hsm_keys_disabled`, `hsm_not_configured`, `hsm_not_connected`, `hsm_unavailable`, `algorithm_not_supported`, `hsm_import_not_supported`, `iv_mode_not_supported`, `material_in_hsm`, `hsm_key_not_found`: the key's object is not on the HSM the tenant's profile points at, message names the recorded serial) | warning | `TestHSMResidentKeyLifecycle`, `TestHSMKeyProvenance` |
| `audit.key.hsm_objects_destroyed` / `audit.key.hsm_destroy_failed` | a destroyed HSM key's objects were removed from the HSM, or some couldn't be (`labels`, `result: failure`, `reason`: `hsm_unreachable`, or `hsm_not_configured` when the platform runs no HSM connector, 6.7.0-beta) | info / critical | `TestHSMResidentKeyLifecycle`, `TestHSMDeviceChangeAndDestroyFailureAudited`, `TestDestroyWithoutHSMConnectorIsAudited` |
| `audit.key.hsm_status_read`, `audit.key.hsm_settings_update` | kernel events for keycore `GET`/`PUT /hsm/settings` | info / warning | `TestHSMRoutesAudited`, `TestHSMRoutesRefusalsAudited` |
| `audit.key.hsm_device_changed` | an HSM key was rotated onto a different HSM (serial) than its previous version (`previous_serial`, `serial`) | warning | `TestHSMDeviceChangeAndDestroyFailureAudited` |
| `audit.key.hsm_objects_listed`, `audit.key.hsm_key_inspected` | kernel events for keycore `GET /hsm/objects` (partition listing) and `GET /keys/{id}/hsm` ("Verify in HSM") | info | `TestHSMRoutesAudited`, `TestHSMRoutesRefusalsAudited` |
| `audit.key.create` | for HSM keys also carries `hsm_serial`, `hsm_token`, `hsm_model`, `hsm_manufacturer` of the device that generated it | info | `TestHSMKeyProvenance` |
| `audit.cert.crl_generation_failed` | a CA couldn't sign its CRL (for an HSM CA: the HSM or keycore refused); no unsigned CRL is published | critical | `TestHSMCACRLFailureAudited` (SoftHSM2) |

The connector refusing to start (no database, no JWT key) shows as a
`refusing to start` / `boot failed` log line. A missing PIN or a library
outside the allowed roots is a per-request refusal and is audited. Proven by
the tests listed in [HSM_INTEGRATION.md](HSM_INTEGRATION.md).

## Service master keys (pkg/mek)

The secrets, certs, cloud and ekm services emit these under their own
namespace (`audit.secrets.*`, `audit.cert.*`, `audit.cloud.*`,
`audit.ekm.*`); below, `<svc>` stands for that namespace. Migration events
are per tenant, with actor type `service`, and carry `item_type`, `count`
(rows), `item_count` and `item_ids` (sorted, the first 500).
[SERVICE_MASTER_KEYS.md](SERVICE_MASTER_KEYS.md) explains the flow.

| Event | When | Severity | Test |
|---|---|---|---|
| `audit.<svc>.dev_mek_rewrapped` | rows under a public development key were re-wrapped onto the keycore-held key; the items entered the exposure register | warning | `TestMEKLifecycleSQLite`, `TestMEKLifecyclePostgres` |
| `audit.<svc>.mek_rewrapped` | rows under an old environment key (`from: env_mek`) or the previous keycore version (`from: previous_version`) were re-wrapped | info | `TestMEKLifecycleSQLite`, `TestMEKLifecyclePostgres` |
| `audit.<svc>.dev_mek_rewrap_refused` / `mek_rewrap_refused` | a row a legacy key opens couldn't be rewritten (`result: refused`, `reason: rewrap_failed`); start refused, retried next start | critical | `TestRewrapFailureRefusesStart` |
| `audit.<svc>.mek_unreadable` | rows no known key opens (`result: failure`); emitted when the count changes | warning | `TestMEKLifecycleSQLite`, `TestMEKLifecyclePostgres` |
| `audit.<svc>.mek_check_refused` | keycore derives a different key than the stored data is recorded under (`result: refused`, `reason: mek_mismatch`); start refused | critical | `TestMEKLifecycleSQLite`, `TestMEKLifecyclePostgres` |
| `audit.<svc>.mek_exposure_remediated` | an exposure entry closed: material rotated, deleted or re-keyed, or acknowledged with a reason | info; warning when acknowledged | `TestMEKLifecycleSQLite`, `TestExposureAndRewrapRoutes` |
| `audit.<svc>.mek_exposure_listed` / `mek_exposure_acknowledged` | kernel events for `GET /mek/exposure` and the acknowledge route (refusals included) | info / warning | `TestExposureAndRewrapRoutes` |
| `audit.<svc>.mek_backup_rewrap` | governance re-wrapped backup contents through the service (counts; `result: refused` for any other caller) | warning | `TestExposureAndRewrapRoutes` |
| `audit.key.data_key_generated` | keycore `POST /keys/{id}/generate-data-key` (kernel event; details `key_bytes`, `include_plaintext`, `version`; refusals `result: refused` with `reason`: `ops_limit_reached`, `policy_denied`, `fips_mode_violation`, access refusals, HSM refusals, `permission_denied`) | info; warning for refusals | `TestGenerateDataKeyRoundTripsThroughUnwrap` |
| `audit.key.algorithm_changed` | a rotation moved the key to a new algorithm under the same key ID (`from_algorithm`, `to_algorithm`, `version`, `result: success`) | warning | `TestRotationChangesAlgorithmUnderSameKeyID` |
| `audit.key.algorithm_change_refused` | a rotation's `target_algorithm` refused (`result: refused`, `reason`: unknown or weak target, an operation the key serves that the target can't, HSM-resident key) | warning | `TestRotationChangesAlgorithmUnderSameKeyID` |
| `audit.key.ciphertext_rewrapped` | kernel event for `POST /keys/{id}/rewrap` (details `from_version`, `version`); refusals `version_refused`, `policy_denied`, `fips_mode_violation`, `access_denied`, plus the kernel's `unauthenticated`, `permission_denied`, `tenant_mismatch`. The inner decrypt and encrypt emit their own `audit.key.decrypt` / `audit.key.encrypt` | info; warning for refusals | `TestRotationChangesAlgorithmUnderSameKeyID`, `TestAgilityRoutesRefusalsAudited` |
| `audit.key.agility_posture_read`, `agility_inventory_read`, `agility_keys_by_algorithm_read` | kernel events for keycore's crypto-agility reads; the posture read carries `total_keys`, `quantum_vulnerable_keys`, `not_assessed_keys` (refusals `result: refused`: `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`). `agility_score_read` was removed with the invented score in 3.2.0-beta | info; warning for refusals | `TestAgilityFiguresComeFromKeys`, `TestAgilityRoutesRefusalsAudited`, `TestAgilityRuleTenantSmugglingRefused` |
| `audit.key.agility_migration_plans_listed`, `agility_migration_plan_created`, `agility_migration_plan_updated` | removed in 7.3.0-beta with the record-only keycore migration plans; migrations run in the pqc service (`audit.pqc.migration_step_executed`) | — | `TestAgilityFiguresComeFromKeys` (route answers 404) |
| `audit.key.canary_keys_listed`, `canary_key_created` (`name`), `canary_trips_listed`, `canary_key_deactivated` | kernel events for keycore canary keys (refusals `result: refused`: `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`) | info; `canary_key_deactivated` and refusals warning | `TestCanaryRoutesAudited`, `TestCanaryRoutesRefusalsAudited` |
| `audit.keycore.canary_tripped` | a canary key ID was referenced through the key API; the caller gets `404` (`canary_id`, `actor_id`, `actor_ip`, `source: key_api_probe`); a deactivated canary never trips | critical | `TestCanaryProbeThroughKeyAPITrips`, `TestDeactivatedCanaryDoesNotTrip` |
| `audit.keycore.threat_signal_raised` | the every-minute sweep of this node's key usage trail found `new_actor`, `volume_spike` or `dormant_key_activity`, or a canary tripped (`signal_id`, `signal_type`, `key_id`, `actor_id`, `severity`, `description`); raised once per condition and window, under the tenant whose traffic it was | the signal's: critical, high or medium | `TestThreatDetectsNewActor`, `TestThreatDetectsVolumeSpike`, `TestThreatDetectsDormantActivity`, `TestThreatSignalDedupe`, `TestThreatSweepCoversEveryTenantSeparately`, `TestCanaryProbeThroughKeyAPITrips` |
| `audit.posture.threat_finding_raised` | posture raised a finding for a synced threat signal (`finding_id`, `signal_id`, `signal_type`, `key_id`, `actor_id`, `severity`); once per signal, never reopened after it is resolved | info | `TestThreatSignalBecomesFindingOnce` |
| `audit.auth.tenant_ids_listed` | reporting listed active tenant IDs from auth for the scheduled alert sync (`count`); any caller but `kms-reporting` is refused (`reason: service_identity_required`) | info; warning for refusals | `TestTenantIDsOnlyForReporting`, `TestTenantIDsRoutesRefusalsAudited` |
| `audit.reporting.alert_created` for a threat signal | the scheduled alert sync (primary only, every minute, every active tenant from auth plus root and tenants reporting holds rows for) raised a critical or high threat signal as an alert; medium stays a posture finding | info | `TestThreatSignalsBecomeAlertsOnScheduledSync`, `TestThreatAlertForTenantOnlyAuthKnows`, `TestListAlertsDoesNotSyncOnMember` |
| `audit.key.rotation_policy_*`, `rotation_policies_listed`, `rotation_runs_listed`, `rotation_upcoming_listed` | kernel events for keycore rotation policies: created, updated, deleted, triggered (details `matched`, `rotated`, `failed`) and listed; refusals `result: refused` | info; warning for delete, trigger and refusals | `TestRotationTriggerRotatesMatchingKeys`, `TestRotationRoutesRefusalsAudited` |
| `audit.key.rotation_policy_run` | a scheduled policy run on the primary (actor `kms-keycore-rotation-scheduler`; details `matched`, `rotated`, `failed`, `error`); each rotated key also emits `audit.key.rotate` | info; warning when a key failed | `TestRotationSchedulerRunsDuePoliciesOnPrimaryOnly` |
| `audit.audit.webhook_*` (`webhooks_listed`, `webhook_created`, `webhook_updated`, `webhook_deleted`, `webhook_tested`, `webhook_deliveries_listed`) | kernel events for event-stream management; a connection that can't carry a stream is `result: refused`, `reason: connection_not_streamable` (2.10.0-beta) | info; warning for changes | `TestWebhookManagementAudited`, `TestStreamAPIRequiresConnection` (refused), `TestWebhookRoutesRefusalsAudited` |
| `audit.audit.webhook_delivered` | one audit event delivered (or test) through one stream's connection: `event_id`, `event_action`, `http_status`, `attempts`, `latency_ms`, `format` (connection type), `connection_id`; never itself delivered | info; warning on failure | `TestStreamDeliversThroughSIEMConnection` |
| `audit.audit.webhook_migrated` | the primary moved legacy streams' own credentials into compliance connections (`count`, `webhook_ids`); open exposure entries move with them (2.10.0-beta) | info | `TestLegacyStreamsMigrateIntoConnections` |
| `audit.audit.webhook_migration_refused` | a legacy stream's credentials don't map onto a connection type (`reason`: `no_splunk_token_header`, `no_datadog_api_key_header`, `unmapped_headers`, `unknown_format`); it keeps delivering and is reported once per process | warning | `TestLegacyStreamsMigrateIntoConnections` |
| `audit.audit.webhook_credentials_sealed` | the primary sealed webhook credentials an earlier release stored in plaintext (`count`, `webhook_ids`); each is also in the exposure register | warning | `TestPlaintextWebhooksAreSealedAndRegistered` |
| `audit.audit.webhook_credentials_seal_refused` | plaintext webhook credentials could not be sealed (`webhook_ids`, `reason: seal_failed`) | critical | `TestPlaintextWebhookSealRefusalAudited` |
| `audit.audit.target_integrity_verified` | kernel event for `GET /audit/targets/{target_id}/integrity` (1.38.0-beta): one target's audit trail recomputed and checked (details `verdict` `intact`/`tampered`/`no_events`, `events_checked`, `failed`); refusals `result: refused` | info; warning for refusals | `TestTargetIntegrityRouteAudited`, `TestTargetIntegrityRouteRefusalsAudited` |
| `audit.audit.chain_broken` | a chain verification found a break: the whole tenant chain (`GET /audit/chain/verify`, details `scope: chain`, `breaks` with reasons `previous_hash_mismatch`, `chain_hash_mismatch`, `hmac_mismatch`, `hmac_key_unknown`, `checkpoint_key_unknown`, `checkpoint_signature_invalid`, `checkpoint_head_mismatch`), one target's trail (`scope: target`, `target_id`, each event's failures: `content_altered`, `link_broken`, `link_predecessor_missing`, `hmac_mismatch`, `hmac_key_unknown`, `checkpoint_key_unknown`, `checkpoint_signature_invalid`, `checkpoint_head_mismatch`) or listed checkpoints (`scope: checkpoints`); `break_count`; `result: failure`. Published on the `AUDIT` stream and recorded by ingest (directly if the publish fails) | critical | `TestTargetIntegrityRouteAudited` (target), `TestTargetIntegrityRejectsTampering` (each target reason), `TestVerifyChainCatchesRewriteWithHMACKey`, `TestVerifyChainChecksCheckpoints` (chain), `TestCheckpointsRouteAudited` (checkpoints), `TestChainBrokenPublishedToStream`, `TestChainBrokenRecordedWhenStreamDown` |
| `audit.audit.activity_stats_read` | kernel event for `GET /audit/activity/stats` (7.17.0-beta): the Audit Log Activity charts' counts over a window (details `from`, `to`, `total`); refusals `result: refused`, including `reason` `bad_window` for a malformed window | info; warning for refusals | `TestActivityStatsRouteAudited`, `TestActivityStatsRouteRefusalsAudited` |
| `audit.audit.checkpoints_listed` | kernel event for `GET /audit/checkpoints` (3.0.0-beta): the tenant's newest signed checkpoints, each re-verified (details `checkpoints`, `failed`); refusals `result: refused` | info; warning for refusals | `TestCheckpointsRouteAudited`, `TestTargetIntegrityRouteRefusalsAudited` (same router) |
| `audit.audit.checkpoint_signed` | a node signed the head of one tenant chain it writes (3.0.0-beta; every 10 minutes, only if the chain moved): details `format`, `chain_node`, `sequence`, `chain_hash`, `signed_at`, `key_id`, `algorithm` (`ECDSA-P384`), `signature` (base64 DER) | low | `TestSignCheckpointsSignsMovedChainsOnly`, `TestCheckpointVerifiesOutsideTheService` |
| `audit.audit.checkpoint_key_created` | the audit service generated its in-memory checkpoint signing key (root tenant; `target_id` = key ID, details `algorithm`, `public_key_pem`, `chain_node`); the private key is never stored | medium | `TestSignCheckpointsSignsMovedChainsOnly`, `TestCheckpointKeyTrustedOnlyThroughRegistration` |
| `audit.audit.checkpoint_refused` | a checkpoint key could not be generated or a head could not be signed (`result: refused`, details `reason` `key_generation_failed`/`signing_failed`, `error`); nothing is recorded as signed | high | `TestCheckpointRefusalAudited` |
| `audit.audit.event_hmac_key_installed` | the event HMAC key was derived (HKDF-SHA256) from the audit master key when the keyring opened (root tenant; `target_id` = HMAC key ID, details `mek_key_id`, `mek_version`, and `unavailable_mek_versions` when an earlier version's key could not be derived, so its events will report `hmac_key_unknown`) | medium | `TestEventHMACKeyFromMasterKeySurvivesRestart`, `TestEventHMACKeyCoversEarlierMasterKeyVersions` |
| `audit.key.public_key_read` | kernel event for keycore `GET /keys/{id}/public-key` (6.18.0-beta; details `algorithm`, `version`); refused `result: refused` with `reason` `not_asymmetric`, `key_deleted`, `spki_unavailable`, or the kernel's `unauthenticated`/`tenant_mismatch`; a hidden key is `404` with `audit.key.access_refused` `not_visible` | info; warning for refusals | `TestPublicKeyReadReturnsTheKeysSPKI`, `TestPublicKeyReadRefusals`, `TestPublicKeyRouteRefusalsAudited`, `TestPublicKeyReadOfAHiddenKeyIsRefused` |
| `audit.key.key_consumers_read` | kernel event for keycore `GET /keys/{id}/consumers` (1.38.0-beta; detail `consumers`); unknown key `result: failure`; refusals `result: refused` | info; warning for refusals | `TestKeyConsumersFromUsageTrail`, `TestKeyConsumersRefusalsAudited` |
| `audit.<svc>.mek_exposure_recorded` | an item entered the exposure register for a reason other than a public key, e.g. `source: plaintext_storage` (`mek.Keyring.RecordExposure`) | warning | `TestExposureAndRewrapRoutes` |
| `audit.posture.*` engine kernel events (`health_read`, `dashboard_viewed`, `risk_read`, `risk_history_read`, `scan_run`, `events_ingested`, `audit_synced`, `findings_listed`, `finding_status_updated`, `actions_listed`, `action_executed`) | every posture engine request (1.32.0-beta), including refusals `result: refused` with `reason` `unauthenticated` (no or forged token), `permission_denied`, `tenant_mismatch` (query, header, body or batch item names another tenant; `requested_tenant`), `tenant_conflict`, `tenant_wildcard` (`*`/`all`). `action_executed` carries the verified executor as actor and what the executor changed (`severity_from`, `severity_to`, `escalated_finding_id`, `approval_request_id`); it is refused with `approval_pending`, `approval_invalid` (an approval ID not bound to this action and caller), `approval_unavailable` (fail closed) or `not_executable` (1.34.0-beta); a re-run (`already_executed`) or a source finding no longer open (`finding_not_open`) is `result: failure` | info; warning for `action_executed` and refusals | `TestPostureEngineRoutesAudited`, `TestPostureRoutesRefusalsAudited`, `TestPostureCrossTenantRefused`, `TestEscalationRunsOnlyOnBoundApproval` |
| `audit.posture.baseline_ready` | a tenant's posture baseline reached 14 complete days, so its risk score is assessed from now on (`baseline_days`, `required_days`, `baseline_from`); emitted once, on the first assessed scan (7.19.0-beta) | info | `TestScanAssessedOnceBaselineReady`; not emitted while building: `TestScanNotAssessedWhileBaselineBuilds` |
| `audit.posture.baseline_read` | kernel event for `GET /posture/baseline` (`ready`, `days`); refusals `result: refused` (7.19.0-beta) | info; warning for refusals | `TestBaselineRouteAndGlobalRisk`, `TestPostureRoutesRefusalsAudited` |
| `audit.posture.actions_corrected` | the primary corrected action rows written before 1.34.0-beta, when "execute" only published an event nothing consumed: `reset_to_suggested` (escalations to run for real), `not_performed` (other types marked executed), `withdrawn` (open actions of types posture cannot execute) | warning | `TestLegacyActionsCorrected` |
| `audit.posture.events_ingested` (scheduled) | the engine scheduler synced audit events into posture (`inserted`, `source: scheduled_audit_sync`), under the synced tenant | info | `TestScheduledAuditSyncAudited` |
| `audit.key.system_key_ensure` | a service asked for its system key (kernel event; `refused` for a non-service caller) | info | `TestSystemKeyRouteIsServiceOnlyAndAudited` |
| `audit.key.system_key_created` | keycore created a service's system key | info | `TestEnsureSystemKeyIsIdempotentAndServiceBound` |
| `audit.key.status_transition_refused` | an operator key status change (activate, disable, deactivate, suspend, compromise) the lifecycle state table doesn't allow was refused, for example compromised to active (`from`, `to`, `reason`, `result: refused`) | high | `TestSetKeyStatusEnforcesLifecycleTable` |
| `audit.key.system_key_change_refused` | destroy, disable, version delete or export of a system key was refused (`operation`, `reason: system_key_protected`) | critical | `TestSystemKeyIsProtectedFromDestruction` |
| `audit.governance.backup_create_refused` | a backup wasn't taken (`reason`, for example a service couldn't re-wrap a row under a public key, or `BACKUP_HSM_WRAP_SECRET` is missing or short) | warning | `TestBackupReprotectPostgres`, `TestSplitBackupKeyRestorePostgres` |
| `audit.governance.backup_key_downloaded` | an HSM-bound backup's wrapped key file was downloaded again | warning | `TestHSMBoundBackupPostgres` |
| `audit.governance.backup_key_download_refused` | a key download was refused (`reason: key_not_retained`: software mode, or a key removed by migration 013) | warning | `TestSoftwareBackupKeyNotRetainedPostgres` |

**If NATS is down at startup,** migration events can't be published. The
counts stay in `<svc>_mek_state` and the items in `<svc>_mek_exposure`, and
the service log has a `MEK scan: …` line. A refused start shows as a
`refusing to start:` line.

## Internal mTLS (certs, docs/SECURITY/INTERNAL_TLS.md)

| Event | When | Severity | Test |
|---|---|---|---|
| `audit.cert.internal_subca_created` | the internal-services Sub CA is created under the runtime root (first start) | info | `TestInternalSubCAIsCreatedOnceUnderTheRoot` |
| `audit.certs.internal_enroll` | every enrolment request on `POST /v1/enroll` (route kernel); refusals carry `result: refused` and `reason`: `invalid_request`, `invalid_csr`, `proof_rejected` (wrong identity, wrong secret, expired, unknown identity), `issuance_refused` | warning | `TestEnrollmentIssuesRegistrySANsFromTheSubCA`, `TestEnrollmentRefusals` |
| `audit.cert.internal_pki_bootstrapped` | the certs service loaded its internal PKI before the database and recorded the CAs and the certificates it issued before connecting (`created`, `issued_before_database`) | info | `TestReconcileRecordsBootstrapStateAndSwitchesToTheDatabase` |
| `audit.cert.internal_enrolled` | a certificate was issued from a CSR: identity, serial, key algorithm, expiry, how many previous certificates were superseded | info | `TestEnrollmentIssuesRegistrySANsFromTheSubCA` |

Proven by `TestEnrollmentIssuesRegistrySANsFromTheSubCA` and
`TestEnrollmentRefusals` (services/certs), and `TestEnrollmentProof`
(pkg/svctls).

## HSM library uploads and CLI/SSH access (hsm-connector, auth)

| Event | When | Severity | Test |
|---|---|---|---|
| `audit.hsm.provider_library_inventory` | connector start: each tenant's provider files with SHA-256 | info | `TestLibraryWatcherAuditsUploads` |
| `audit.hsm.provider_library_added` / `_changed` / `_removed` | a file uploaded, replaced or deleted over SSH/SFTP | warning | `TestLibraryWatcherAuditsUploads` |
| `audit.auth.cli_session_refused` | CLI session refused, `result: refused`, `reason` `invalid_credentials` or `public_default_password` | warning | `TestCLISessionRefusesThePublicPasswordAndAuditsRefusals` |
| `audit.auth.cli_ssh_password_synced` | auth set the SSH password on hsm-integration (`result` success/failure) | info | `TestCLISSHPasswordSyncKeepsThePasswordOffTheCommandLine` |
| `audit.auth.cli_password_revoked` | a CLI user on the retired public password got a random one; SSH copy locked | critical | `TestRevokeRetiredCLIPasswords` |

Proven by `TestLibraryWatcherAuditsUploads` (pkg/hsmconnector),
`TestCLISessionRefusesThePublicPasswordAndAuditsRefusals`,
`TestRevokeRetiredCLIPasswords` and
`TestCLISSHPasswordSyncKeepsThePasswordOffTheCommandLine` (services/auth).
SSH logins themselves are in the hsm-integration container log (sshd,
`LogLevel VERBOSE`, with key fingerprints), not the audit trail.

## Service mTLS (certs, docs/SECURITY/INTERNAL_TLS.md)

| Event | When | Severity | Test |
|---|---|---|---|
| `audit.certs.internal_mtls_inventory_read` | the Service mTLS page was read (root only) | info | `TestMTLSRoutesRootOnlyAndAudited` |
| `audit.certs.internal_mtls_policy_updated` | an identity's certificate key or key-exchange profile changed; previous and new values, generation, certificates revoked | warning | `TestMTLSRoutesRootOnlyAndAudited`, `TestMTLSRoutesRefusalsAudited` |
| `audit.certs.internal_mtls_rotated` | an identity's certificate was revoked and replaced; `restart_mode` graceful or force | warning | `TestMTLSRoutesRootOnlyAndAudited` |
| `audit.certs.internal_mtls_rotated_all` | every internal certificate was rotated, with staggered restarts | critical | `TestMTLSRoutesRootOnlyAndAudited` |
| `audit.certs.internal_mtls_applied` | every reporting instance runs the new generation (from their reports, not the request); serials | info | `TestMTLSAppliedOnlyWhenReportedAndAuditedOnce` |
| `audit.certs.edge_tls_read` | the external edge key exchange was read (root only) | info | `TestEdgeTLSRoutesPublishAndAudit` |
| `audit.certs.edge_tls_policy_updated` | the external listeners' key-exchange profile changed; previous and new profile, generation, Envoy's groups. Refused with `not_root_tenant`, `invalid_policy`, `unchanged` | warning | `TestEdgeTLSRoutesPublishAndAudit` |
| `audit.certs.edge_tls_applied` | every external listener was measured by handshake accepting exactly the new groups; the groups and negotiated group per listener. Never from the request | info | `TestEdgeTLSAppliedOnlyWhenMeasured`, `TestEdgeProfileAppliedByRealEnvoy` |
| `audit.certs.edge_tls_certificate_source_updated` | a listener's certificate source changed (`listener` `https` or `kmip`; `runtime`, `ca` with `ca_id` and key algorithm, `external`); previous source and the serial installed on this node. Refused with `not_root_tenant`, `invalid_listener`, `invalid_source`, `unknown_ca`, `ca_not_active`, `hsm_ca_not_supported`, `internal_services_ca`, `invalid_key_algorithm`, `unchanged` | warning | `TestEdgeCertificateRoutesAudited`, `TestEdgeCertificateFromPKICA`, `TestKMIPCertificateSource` |
| `audit.certs.edge_tls_csr_created` | this node generated its edge key and a CSR for an external CA (`node`, subject, SANs, key algorithm; never the key). Refused with `source_not_external`, `invalid_request`, `invalid_key_algorithm` | warning | `TestEdgeCertificateRoutesAudited`, `TestEdgeExternalCertificateFlow` |
| `audit.certs.edge_tls_certificate_installed` | an external CA's certificate was installed on this node (`node`, serial, subject, issuer, `not_after`). Refused with `source_not_external`, `no_pending_key`, `invalid_certificate`, `key_mismatch`, `not_valid_now`, `not_server_certificate`, `bad_chain`, `chain_required` | warning | `TestEdgeCertificateRoutesAudited`, `TestEdgeExternalCertificateFlow`, `TestEdgeProfileAppliedByRealEnvoy` |
| `audit.certs.edge_tls_certificate_restored` | after a restart, certs copied this node's kept external certificate and key back into the tmpfs runtime volume (`listener`, serial, subject, issuer, `not_after`; never the key). Not emitted when the kept copy is expired, isn't the installed external certificate, or was discarded by leaving the `external` source: the listener then serves a runtime-root certificate | info | `TestEdgeExternalCertificateSurvivesRestart` |
| `audit.cert.revoked` (reason `superseded`) for an edge or KMIP certificate (7.22.0-beta) | certs revoked the certificate it had issued for a listener once the listener stopped serving it: after a restart, a change of source, or an external install. The served certificate is never revoked | warning | `TestEdgeCertificateReplacedIsRevoked` |
| `audit.certs.edge_tls_measurement_read` | the external listeners' measured groups were read (any verified caller; the pqc inventory) | info | `TestEdgeCertificateRoutesAudited` |
| `audit.certs.certificate_key_label_corrected` | a certificate or CA record named a key its certificate doesn't carry, and was corrected (`recorded_algorithm`, `recorded_class`, `actual_algorithm`, `reason`: `key_size_mismatch` or `pqc_label_removed`) | warning | `TestCorrectKeyLabels`, `TestCorrectKeyLabelsPostgres` |
| `audit.certs.pqc_profile_removed` | a certificate profile with a PQC or hybrid algorithm was deleted (PQC certificates removed, 1.19.0-beta) | warning | `TestCorrectKeyLabelsPostgres` |
| `audit.cert.pqc_issuance_refused` | a PQC or hybrid certificate, CA or profile was requested and refused (`kind`, `algorithm`, `class`, `result: refused`, `reason: pqc_certificates_removed`); replaces `audit.cert.pqc_cert_issued`, `pqc_cert_validated` and `pqc_migration_executed` | warning | `TestPQCCertificatesRefusedAndAudited` |

Refusals carry `result: refused` and a `reason`: `not_root_tenant`,
`unchanged`, `invalid_policy`, `unknown_identity`,
`kx_profile_not_applicable`, `force_not_available`,
`confirmation_required`, and the kernel's own. Proven by
`TestMTLSRoutesRefusalsAudited`, `TestMTLSRoutesRootOnlyAndAudited`,
`TestMTLSAppliedOnlyWhenReportedAndAuditedOnce`, `TestCorrectKeyLabels` (and
`TestCorrectKeyLabelsPostgres` on real Postgres) and
`TestPQCCertificatesRefusedAndAudited` (services/certs).

**How a restart shows:** a service restarting for a policy change logs
`mTLS policy for <identity> changed (...): graceful|force restart`. Its
next report shows the new generation.

## Certs root wrapping key (certs, docs/SECURITY/SECRET_ROTATION.md)

| Event | When | Severity | Test |
|---|---|---|---|
| `audit.certs.crwk_rotated` | the CRWK was re-keyed after a passphrase rotation. Details: `from_version`, `to_version`, `ca_signers_rewrapped`, and `reason`: `passphrase_rotation`, or `public_default_passphrase` (migration off the retired public passphrase; carries an `exposure` note). A failed rewrap has `result: failure`, `reason: rewrap_failed`, `rotation_reason`, and the error; it is retried on the next start | warning | `TestCRWKMigratesOffThePublicDefault` (and `...Postgres`), `TestCRWKRotationResumesAndAuditsFailure` |

Proven by `TestCRWKMigratesOffThePublicDefault` (SQLite and
`...Postgres`) and `TestCRWKRotationResumesAndAuditsFailure`
(services/certs).

## Kernel-emitted events (pkg/route)

Services migrated to the `pkg/route` kernel emit one specific event per
request, and the kernel guarantees it for refusals too. The kernel's own
refusals are listed below. Handlers add their own (for example
`feature_preview` or a FIPS refusal) with `c.Refuse`.

| Event | When | Severity | Test |
|---|---|---|---|
| `audit.<service>.<action>`, `result: refused`, `reason: unauthenticated` | no verified token on a non-public route (401) | warning | `TestEveryRouteRefusesAndAudits` (pkg/route); `routetest.RefusalsAudited` per service |
| `audit.<service>.<action>`, `result: refused`, `reason: permission_denied` | the token lacks the route's permission (403) | warning | `TestEveryRouteRefusesAndAudits`; `routetest.RefusalsAudited` per service |
| `audit.<service>.<action>`, `result: refused`, `reason: tenant_mismatch` | the request names a tenant other than the token's (403), including in the JSON body | warning | `TestBodyTenantCannotCrossTenants`; `routetest.RefusalsAudited` per service |
| `audit.<service>.<action>`, `result: refused`, `reason: tenant_conflict` | query, header and body name different tenants (403) | warning | `TestConflictingTenantSourcesRefused` |
| `audit.<service>.<action>`, `result: failure` | the handler returned an error (`error_code` in details) | the route's severity | `TestFailureAndHandlerRefusalAreAudited` |
| `audit.secrets.*` | every secrets route; see the table in `docs/API_REFERENCE.md` (Service 25) | info; `value_read` and `deleted` are warning | `TestSecretsRoutesRefuseAndAudit`, `TestCreateSecretRefusesCrossTenantBody` |
| `audit.secrets.<action>`, `result: refused`, `reason: not_in_access_rule` or `access_rule_denied` | an access rule on the secret's path does not allow the caller the capability the route needs (7.29.0-beta, docs/SECURITY/SECRET_ACCESS.md); details carry `path` and `capability`. Every secrets route, Vault KV included | warning | `TestAccessRulesAreEnforcedOnEveryRoute`, `TestDecide` |
| `audit.secrets.access_rule_created`, `access_rule_deleted`, `access_rules_listed`, `access_read` | access rule management (7.29.0-beta); created and deleted carry `path`, `subject`, `capabilities`, `effect`. Playbook trigger `secret_access_rule_changed` | warning for created and deleted; info | `TestAccessRuleValidation`, `TestTriggerSubjectsAreEmitted` |
| `audit.secrets.<action>`, `result: refused`, `reason: no_access_rule` or `access_groups_unavailable` | 7.30.0-beta: the tenant denies by default and no allow rule covers the path (403); or a group rule covers the path and the caller's group membership could not be read (503, fail closed) | warning | `TestDefaultDeny`, `TestGroupRules` |
| `audit.secrets.settings_read`, `settings_updated` | vault settings (7.30.0-beta); `settings_updated` carries `default_deny`, `max_versions`, `deleted_retention_days` and `previous`. Playbook trigger `secret_access_rule_changed` | warning for updated; info | `TestDefaultDeny`, `TestTriggerSubjectsAreEmitted` |
| `audit.secrets.retention_purged` | the hourly sweep on the primary destroyed a deleted secret whose retention period passed (7.30.0-beta); actor `system:retention`, details `path`, `deleted_at`, `deleted_by`, `retention_days`, `versions_destroyed`; `result: failure` if it could not. Not emitted through a route. Playbook trigger `secret_destroyed` | warning | `TestRetention` (member mode included) |
| `audit.key.access_user_groups_read` | keycore returned a user's access group IDs (7.30.0-beta), to the secrets service or a caller with `key.access.read` | info | `TestListUserAccessGroups`, `TestAccessRoutesRefusalsAudited` |
| `audit.secrets.version_caps_listed`, `version_cap_set`, `version_cap_deleted` | version caps by path (7.31.0-beta), with `path` and `max_versions`. Playbook trigger `secret_access_rule_changed` | warning for set and deleted; info | `TestPathCaps`, `TestTriggerSubjectsAreEmitted` |
| `audit.secrets.access_rule_created`, `result: refused`, `reason: unknown_subject` or `subject_check_unavailable` | 7.31.0-beta: the rule's subject does not exist in the tenant (400), or the service that owns it could not be asked (503); nothing is stored. `access_rules_listed` carries `subjects_missing` when stored rules name subjects that have gone | warning | `TestSubjects` |
| `audit.auth.subjects_checked` | auth answered whether users, roles or clients exist in a tenant (7.31.0-beta), to the secrets service only; another caller is refused with `service_identity_required` | info; refusal warning | `TestSubjectsCheck`, `TestSubjectsRoutesRefusalsAudited` |
| `audit.secrets.restored`, `destroyed`, `version_destroyed`, `rolled_back` | version operations (7.29.0-beta): `rolled_back` carries `from_version` and `new_version`; `destroyed` carries `versions_destroyed`. Refusals: `secret_deleted`, `secret_not_deleted`, `version_conflict`, `version_is_current`, `already_current`, `name_held_by_deleted_secret`. `destroyed` is the playbook trigger `secret_destroyed` | warning for destroyed, version_destroyed, rolled_back; info | `TestSoftDeleteRestoreDestroy`, `TestVersionReadRollbackDestroyAndConditionalWrite` |
| `audit.pqc.<action>` | every pqc route (5.2.0-beta; list in `docs/API_REFERENCE.md`, Service 11); refusals `result: refused` (`unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`). 6.3.0-beta removed `policy_read`, `policy_update_requested`, `audit.pqc.policy_viewed` and `audit.pqc.policy_updated` with the policy routes; `audit.pqc.inventory_viewed` and `scan_completed` carry counts, not a score | info; warning for execute, rollback and refusals | `TestPQCRoutesRefusalsAudited`, `TestPQCActorAndTenantComeFromTheToken`, `TestPQCPolicyRemovedAndNoInventedScores` |
| `audit.workload.<action>` | every workload-identity route (6.9.0-beta; list in `docs/API_REFERENCE.md`, Audit Action Subject Reference): `settings_viewed`, `settings_updated`, `signing_keys_rotated` (6.11.0-beta; `trust_domain`, `jwt_signer_key_id`), `summary_viewed`, `registrations_viewed`, `registration_upserted`, `registration_deleted`, `federation_viewed`, `federation_bundle_upserted`, `federation_bundle_deleted`, `svid_issued` (`private_key_returned`), `issuance_history_viewed`, `graph_viewed`, `key_usage_viewed`, `token_exchanged`. Refusals `result: refused` with `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`. The service no longer publishes its own request events | info; warning for settings, federation, deletes, issuance, exchange and refusals | `TestWorkloadRefusalsAudited`, `TestIssueNeedsIssuePermission`, `TestRotateSigningKeys` |
| `audit.workload.token_exchanged` | the SVID exchange (6.9.0-beta; no bearer token, the SVID is the credential). Actor is the verified SPIFFE ID (`actor_type: workload`) with `spiffe_id`, `trust_domain`, `svid_type`, `document_hash`, `serial_or_key_id`, `allowed_permissions`, `allowed_key_ids`. Refused (`result: refused`) with `svid_invalid`, `audience_not_allowed`, `svid_proof_required`, `svid_proof_invalid`, `svid_proof_expired`, `svid_proof_replayed`, `registration_not_found`, `svid_registration_mismatch`, `registration_disabled`, `interface_not_allowed`, `permissions_not_allowed`, `keys_not_allowed`, `workload_identity_disabled`, `token_exchange_disabled`, or `tenant_mismatch` when a bearer token names another tenant | warning | `TestExchangeWithJWTSVID`, `TestExchangeRefusals`, `TestExchangeWithX509SVIDNeedsProofOfPossession`, `TestFederatedSVIDNeedsFederationEnabled` |
| `audit.workload.mek_signing_keys_sealed` | the workload primary sealed a tenant's root CA and JWT-SVID signer private keys that an earlier release stored as plaintext PEM, and emptied the plaintext columns (6.11.0-beta; per tenant, `target_type: workload_signing_keys`, `exposure` names the remedy). `audit.workload.mek_exposure_recorded` (`source: plaintext_storage`) precedes it | warning | `TestSigningKeysSealedAtRestSQLite`, `TestSigningKeysSealedAtRestPostgres` |
| `audit.workload.mek_signing_keys_seal_refused` | a plaintext row couldn't be sealed (`result: refused`, `reason: seal_failed`); the row is left as it was, and a failure on the startup pass stops the start | critical | `TestSigningKeysSealedAtRestSQLite`, `TestSigningKeysSealedAtRestPostgres` |
| `audit.keyaccess.<action>` | every key-access route (6.9.0-beta): `settings_viewed`, `settings_updated`, `summary_viewed`, `codes_viewed`, `code_upserted`, `code_deleted`, `decisions_viewed`, `decision_evaluated`. Kernel refusals as above. `audit.keyaccess.approval_required` is no longer a separate event: `decision_evaluated` carries `approval_required` and `approval_request_id` | info; warning for settings, code deletes, evaluations and refusals | `TestKeyAccessRefusalsAudited`, `TestEvaluateDeniesUnjustifiedRequest` |
| `audit.keyaccess.decision_evaluated`, `result: refused` | `POST /key-access/evaluate` from anyone but the `kms-ekm`, `kms-cloud` and `kms-hyok-proxy` service identities (`reason: evaluator_identity_required`), or an evaluator naming another service (`reason: service_mismatch`) | warning | `TestEvaluateRestrictedToEvaluatorIdentities` |
| `audit.confidential.<action>` | the confidential routes that were on the legacy mux (6.9.0-beta): `policy_viewed`, `policy_updated`, `summary_viewed`, `key_release_evaluated` (actor and `requester` from the token, never the body), `releases_viewed`, `release_viewed`. Kernel refusals as above | info; warning for `policy_updated` and refusals | `TestConfidentialRefusalsAudited`, `TestEvaluateRecordsVerifiedCaller`, `TestPolicyUpdateAuditedAndNeedsWrite` |
| `audit.sbom.*` | every sbom/cbom route (1.33.0-beta); list in `docs/API_REFERENCE.md` (Audit Action Subject Reference) | info | `TestSBOMRoutesRefusalsAudited`, `TestCBOMGenerateCrossTenantRefusedAndAudited`; the removed advisory and vulnerability routes (2.19.0-beta): `TestSBOMVulnerabilityRoutesRemoved` |
| `audit.sbom.<action>`, `result: refused`, `reason: platform_tenant_required` | a tenant other than the platform tenant tries to generate the platform SBOM (403) | warning | `TestSBOMPlatformWritesRefusedOutsidePlatformTenant` |
| `audit.watchdog.heartbeats_listed`, `audit.watchdog.incidents_listed`, `audit.reconciler.status_read` | a platform health read (1.39.0-beta), permission `health.read`; refusals `unauthenticated`, `permission_denied` | info | `TestWatchdogReadsAudited`, `TestWatchdogRoutesRefusalsAudited`, `TestReconcilerStatusReadAudited`, `TestReconcilerRoutesRefusalsAudited` |
| `audit.<service>.<action>`, `result: refused`, `reason: unauthenticated` or `invalid_token` | a request with no bearer token, or one that fails verification, to a routed path on a service served by `pkg/jwtauth.MustWrapRouter` (7.10.0-beta; bad tokens on Public routes too) | warning | `TestKernelWrapperAuditsTokenRefusals` |
| `audit.<service>.request_refused`, `result: refused`, `reason: unauthenticated` or `invalid_token` | a request with no bearer token, or one that fails verification, to a service still on a raw mux behind `pkg/jwtauth.MustWrap` (7.12.0-beta: audit, backup, compliance, policy, signing, non-kernel `platform.Boot` services) | warning | `TestLegacyWrapperAuditsTokenRefusals` |
| `audit.discovery.<action>` | every discovery route (7.9.0-beta, route kernel): `scan_start`, `scans_list`, `scan_read`, `assets_list`, `asset_read`, `asset_review`, `summary_read`, (7.11.0-beta) `targets_list`, `target_add`, `target_remove`, and (7.18.0-beta) `sources_read`, `upload_scan`, `asset_remove`, refusals included (`unauthenticated`, `permission_denied`, `tenant_mismatch`, `classification_is_catalogue`, `invalid_target`, `platform_target`, `target_exists`, `target_limit`, and 7.18.0-beta `scan_running`, `invalid_upload`, `upload_too_large`). `upload_scan` details carry the file name, size and finding count, never the content | info; refusals warning | `TestDiscoveryRoutesRefusalsAudited`, `TestDiscoveryWritesNeedPermissionAndOwnTenant`, `TestDiscoveryRelabelRefusedAndAudited`, `TestTargetRoutesAudited`, `TestTargetRangesAndProtocol`, `TestScanRunsInBackgroundOneAtATime`, `TestUploadInventoriesWithoutStoringSecrets`, `TestSourcesReportSetupAndLastScan`, `TestRemoveAssetAudited` |
| `audit.discovery.<action>` (7.20.0-beta) | git repositories and the scan schedule: `repositories_list`, `repository_add`, `repository_remove`, `repository_test`, `schedule_read`, `schedule_update`, refusals included (`permission_denied`, `invalid_repository`, `platform_target`, `repository_exists`, `repository_limit`, `connection_unfit`, `invalid_schedule`, `user_required`). A URL that carries a credential is refused and not copied into the event; a failed repository test is a failure, never a success | info; refusals warning | `TestRepositoryRoutesAudited`, `TestRepositoryTestReadsTheArchive`, `TestScheduleRoutesAudited`, `TestDiscoveryRoutesRefusalsAudited` |
| `audit.discovery.scheduled_scan` | discovery's scheduler, for every due schedule (7.20.0-beta): `success` with the scan it started, or `refused` with `reason: authority_revoked` (the authorizing user is inactive or lost `discovery.write`; the schedule pauses) or `authority_unknown` (auth did not answer; the run is postponed). Details name `authorized_by`, the sources and the interval | info; refusals warning | `TestScheduleRunsOnCheckedAuthority`, `TestScheduleSkippedOnClusterMember` |
| `audit.compliance.connection_resolved` / `connection_tested` / `connection_deleted` for `git` connections (7.20.0-beta) | compliance opens a `git` connection for `kms-discovery` only (`use: repository`); the audit service and governance are refused (`connection_use_unsupported`); a test is refused with `connection_test_elsewhere`; a delete while a repository uses it is refused with `connection_in_use`, or `connection_usage_unverified` when discovery can't answer | info; refusals warning | `TestGitConnectionIsDiscoverysAlone`, `TestPlatformUsageFindsRepositories` |
| `audit.auth.delegated_authority_checked` by discovery (7.20.0-beta) | auth answers `kms-discovery` as well as `kms-compliance` about a user's standing; any other caller is refused (`service_identity_required`), and discovery is refused every other delegated route | info; refusals warning | `TestAuthorityCheckForDiscoveryOnly` |
| `audit.discovery.secret_exposed` | discovery, the first time a private key, keystore or cloud access key is found in code or an upload (7.18.0-beta; a long hex string is listed as exposed but raises no event, since it is often a hash); target is the asset, details name the type, source, location and fingerprint prefix, never the secret; not repeated when the same secret is found again. Playbook trigger `secret_exposed` | high (audit event catalogue), risk 80 | `TestUploadInventoriesWithoutStoringSecrets`, `TestTriggerSubjectsAreEmitted`, `TestSecretExposedIsHighSeverity` |
| `audit.dataprotect.<action>` | every dataprotect route (7.4.0-beta, route kernel), refusals included (`permission_denied`, `unauthenticated`, tenant) | info; deletes and decrypt/detokenize are warning | `TestDataProtectRoutesRefusalsAudited`, `TestDataProtectRoutesNeedTheirPermission` |
| `audit.reporting.*` | every reporting route (1.33.0-beta); the actor is the verified caller, never a body field, `actor` query or `X-Actor-ID` | info; `rule_deleted` and `report_deleted` are warning | `TestReportingRoutesRefusalsAudited`, `TestGenerateReportRequesterIsVerifiedCaller`, `TestAlertOperationActorIsVerifiedCaller` |
| `audit.compliance.playbook_*`, `connection_*` (routes) | every playbook, run and connection route (2.5.0-beta; list in `docs/API_REFERENCE.md`); the tenant comes from the token, never the body | info; changes, runs, cancels and retries are warning | `TestPlaybookRoutesRefusalsAudited`, `TestPlaybookCreateTakesTenantFromToken` |
| `audit.compliance.playbook_created` / `playbook_updated` / `playbook_run_requested` / `playbook_run_cancelled` / `playbook_run_retried`, `result: refused`, `reason: action_permission_denied` or `user_required` | saving an enabled playbook, or starting, cancelling or retrying a run, without every permission its actions use (`missing_permissions`), or enabling one as an API client (403) | warning | `TestPlaybookSaveRequiresActionPermissions`, `TestPlaybookRunRequiresActionPermissionsAndAuditsEachAction`, `TestPlaybookCancelAndRetry` |
| `audit.compliance.connection_created`, `result: refused`, `reason: url_blocked` | a connection names a non-https URL, a platform service host, or a private, loopback or metadata address (400) | warning | `TestPlaybookOutboundCannotReachPlatformOrPrivateHosts` |
| `audit.compliance.connection_deleted`, `result: refused`, `reason: connection_in_use`; `connection_tested` | deleting a connection a playbook uses (409); a real test call through a connection | warning; info | `TestPlaybookConnectionsSealedAndNeverReturned` |
| `audit.compliance.playbook_run_requested`, `result: refused`, `reason: playbook_invalid` | a manual run of a stored playbook that names a removed action or still holds inline credentials (409) | warning | `TestPlaybookRemovedActionsRefused`, `TestPlaybookInlineSecretsMigrated` |
| `audit.compliance.playbook_run_cancelled` / `playbook_run_retried`, `result: refused`, `reason: run_not_cancellable` / `run_not_retryable` | a run in a state that can't be cancelled or retried (409) | warning | `TestPlaybookCancelAndRetry` |
| `audit.compliance.playbook_dry_run` | a dry run: steps resolved, targets read, nothing changed | info | `TestPlaybookDryRun` |
| `audit.compliance.playbook_triggered` | a trigger (catalogue or custom subject, filters, threshold) matched an enabled playbook: `success` with `run_id`, or `refused` with `reason` `playbook_not_authorized`, `authority_revoked`, `authority_unverified`, `cooldown`, `cooldown_unavailable`, `stale_event` or `threshold_unavailable` | info; refused is warning | `TestPlaybookTriggerListener`, `TestPlaybookThresholdSurvivesFailover`, `TestPlaybookThresholdUnavailableRefused`, `TestPlaybookFiresOnChainBroken`, `TestPlaybookCooldownSurvivesFailover`, `TestPlaybookCooldownUnavailableRefused` |
| `audit.compliance.playbook_action_executed` | each step of each run: `success`, `pending` (a platform approval, or paused for governance), `skipped` (condition), `failure` (including a template that resolved empty), or `refused` (`action_removed`, `approval_mismatch`, `approval_unverified`, `definition_changed`, `authority_revoked`) | warning for key, certificate, access and reporting actions and failures, else info | `TestPlaybookRunRequiresActionPermissionsAndAuditsEachAction`, `TestPlaybookPendingApprovalIsNotSuccess`, `TestPlaybookTemplatesAndConditions`, `TestPlaybookApprovalGate`, `TestPlaybookRemovedActionsRefused` |
| `audit.compliance.playbook_approval_requested` / `playbook_approval_granted` | a step paused for a governance approval; a verified approval resumed it | warning; info | `TestPlaybookApprovalGate` |
| `audit.compliance.connection_resolved` | compliance opened a connection for the audit service (event stream) or governance (approval notice): `caller`, `use`, `type`, never a field; any other caller is `refused`, `reason: service_identity_required`, and a type the caller can't use is `refused`, `reason: connection_use_unsupported` (2.10.0-beta) | info; warning when refused | `TestConnectionResolveRestrictedToAuditAndGovernance` |
| `audit.compliance.connection_imported` | a service moved credentials it held into a connection (`source_id`, `type`, `exposure_recorded`; `already_imported` on a retry); other callers `refused`, `service_identity_required` | warning | `TestConnectionImportIdempotentWithExposure` |
| `audit.compliance.connection_deleted`, `result: refused`, `reason: connection_in_use` / `connection_usage_unverified` | deleting a connection an event stream or governance uses (409), or when the audit service or governance can't say (503) (2.10.0-beta) | warning | `TestConnectionDeleteChecksStreamsAndGovernance` |
| `audit.governance.notify_connections_migrated` | the primary moved plaintext Slack/Teams approval-notice URLs into compliance connections, recorded there as exposed (`connection_ids`) (2.10.0-beta) | warning | `TestGovernanceNotifyURLsMigrateToConnections` |
| `audit.governance.webhook_tested`, `result: refused`, `reason: ad_hoc_url_refused` | a notice test named a URL instead of using the saved connection | warning | `TestGovernanceWebhookTestRefusesAdHocURL` |
| `audit.compliance.playbook_connections_migrated` | credentials an earlier release kept inline in actions were sealed into connections and recorded in the exposure register (`refused`, `seal_failed`, if any could not be) | warning; critical when refused | `TestPlaybookInlineSecretsMigrated` |
| `audit.compliance.playbook_run_completed` | a run finished: completed, pending approval, failed, cancelled, approval denied or expired (`refused` for the last three) | info; warning unless completed | `TestPlaybookRunRequiresActionPermissionsAndAuditsEachAction`, `TestPlaybookApprovalGate`, `TestPlaybookCancelAndRetry` |
| `audit.auth.delegated_*` | auth performed a playbook step on a person's behalf, or refused (`service_identity_required`, `delegator_unknown`, `delegator_inactive`, `delegator_lacks_permission`, `self_target`, `last_administrator`, `service_identity_protected`); `delegated_authority_checked` for the pre-run check | warning; info for the check | `TestDelegatedRoutesRefusalsAudited`, `TestDelegationOnlyForComplianceService`, `TestDelegationChecksTheDelegatorNow`, `TestDelegatedDisableUser`, `TestDelegatedRevokeKeysAndClients` |
| `audit.governance.notification_email_sent` | a playbook's email sent to tenant users; refused for any caller but `kms-compliance` or a recipient outside the tenant | info; refused is warning | `TestNotifyRoutesRefusalsAudited`, `TestNotifyEmailOnlyToTenantUsers` |
| `audit.reporting.rule_tested` | an alert rule was checked without saving (validity, one event, replay of recent audit events); details `valid`, `replay_hours`, `replay_matched`, `replay_fired` (2.13.0-beta) | info | `TestRuleTestRouteAudited` |
| `audit.reporting.incident_opened`, `audit.reporting.alert_created` | a new incident (once), a new alert (with its source); playbook triggers | info | `TestIncidentOpenedEmittedOnce`, `TestAlertCreatedNamesAlertAndSource` |
| `audit.reporting.incident_status_updated` / `incident_assigned`, `result: failure` | an unknown status (400) or an incident that doesn't exist (404); both answered 200 before 2.5.0-beta | info | `TestIncidentUpdatesValidated` |

Proven by `routetest.RefusalsAudited` for every route, and by the
`pkg/route`, `services/secrets`, `services/sbom` and `services/reporting`
tests (`handler_tenancy_test.go`: cross-tenant refusals audited, identity from
the token).

## Metered cryptographic operations (2.2.0-beta)

An event whose details carry `metered_op` (`pkg/audit.MeteredOp`), with
`duration_ms` and `result`, is one cryptographic operation. The audit
service builds the Operations metrics from these events alone
(docs/DECISIONS.md, 2.2.0-beta). Each operation is metered once, by the
service that does the cryptography.

| Event | When | Severity | Test |
|---|---|---|---|
| `audit.key.<op>` (see Key access) and `audit.key.attested_release` (kernel, `Spec.Metered`) | keycore key operations and attested release | info; warning for refusals | `TestCryptoOpsAuditedWithOutcomeAndDuration`, `TestAttestedReleaseSealsToRecipientOnlyForConfidentialService` |
| any kernel event of a route with `route.Spec.Metered` | every call, refusals included, carries `metered_op` | per route | `TestMeteredRouteMarksEveryEvent` (pkg/route) |
| `audit.dataprotect.tokenized`, `detokenized`, `fpe_encrypted`, `fpe_decrypted`, `fpe_legacy_decrypted`, `field_encrypted`, `field_decrypted`, `envelope_encrypted`, `envelope_decrypted`, `searchable_encrypted`, `searchable_decrypted` | the operation completed; now metered | info | `TestDataProtectOperationsMetered` |
| `audit.dataprotect.<op>_refused` / `audit.dataprotect.<op>_failed` | the operation was refused (401/403/409/429, `reason` = error code) or failed (`error`); `fpe_refused` stays the event for a withdrawn FPE algorithm and is metered | warning / info | `TestDataProtectOperationsMetered` |
| `audit.cert.issued`, `audit.cert.ocsp_query` (wire) | metered when the CA key is local (`cert_issue`, `ocsp_sign`); an HSM/keycore CA is metered by keycore | info | `TestLocalCertificateSigningMetered` |
| `audit.cert.cert_issue_failed` / `audit.cert.ocsp_sign_failed` | the CA could not produce the signature (`error`) | warning | `TestCertSigningFailureAuditedAndMetered` |

## What can't be audited, and how it shows instead

A service that **refuses to start** has no audit pipeline yet, because it exits
before connecting. That covers placeholder secrets, weak database passwords,
an invalid or mismatched FIPS mode, a missing certified module, a public or
weak certs CRWK passphrase (`TestCRWKPassphraseRefusesPublicAndWeakValues`), a
retired public `AUTH_BOOTSTRAP_CLI_PASSWORD` (`TestCLIBootstrapPasswordRefusesThePublicDefault`), and a missing
or malformed token-verification key (keycore; governance, which looks for
`GOVERNANCE_JWT_PUBLIC_KEY_PEM`/`_B64`, then the shared
`JWT_PUBLIC_KEY_PEM`/`_B64`, then `KEYCORE_JWT_PUBLIC_KEY_*`, then
`JWT_PUBLIC_KEY_PATH`). These refusals appear as:
- a `refusing to start: …` line on the container's stderr;
- the service missing or restarting in health checks;
- during a FIPS rollout, the service never reaching the target mode in System
  Administration → Runtime Crypto (and no `fips_mode_applied` event for it).

A service that can't **enrol for its internal mTLS certificate** doesn't serve
at all: it logs `internal mTLS enrolment for kms-<name> failed (attempt N)`
and retries until the certs service answers. The certs side audits each
refusal (`audit.certs.internal_enroll`, `result: refused`). A TLS handshake a
server refuses (no client certificate, wrong CA, plain HTTP) is logged by the
server as `http: TLS handshake error`; nothing reaches the application, so
there is no request to audit.

Tests that prove emission: `TestBootstrapRevokesKeysDerivedFromPublicDefaultSecret`,
`TestBootstrapRetiresServiceKeysFromRotatedSecret` (auth);
`TestFIPSModeChangeImpactAndRollout`,
`TestFIPSRolloutIsAuditedOncePerStartAndOnCompletion` (governance);
`TestGenericDeriveCannotReproduceServiceSubkey` (keycore);
`TestLegacyKeyStaysReadableAndIsAudited`, `TestKDFMigrationDualReadThenCutover`
(dataprotect).

## Authentication and approval refusals (1.27.0-beta)

| Event | When | Test |
|---|---|---|
| `audit.auth.sso_login_refused` | A SAML or OIDC callback is refused: bad or missing signature, wrong issuer, audience, recipient or request, replayed assertion, bad state | `TestSAMLRefusesForgedAndMisdirectedAssertions` (parser); handler emits on every refusal path |
| `audit.auth.client_activation_refused` | Client activation without an approved governance request, or for another tenant | `TestHandlerRegisterActivateFlow` |
| `audit.governance.approval_refused` | An approval-API call without a token, from another tenant, a policy change by a non-administrator, a vote by a service or a user with no email | `TestApprovalAPIRequiresAuthenticatedTenantCaller` |
| `audit.governance.link_refused` | The email-link approval page opened with an invalid or used token | `TestApprovalPageNeedsAValidToken` |
| `audit.hyok.dke_refused` | A Microsoft DKE call refused: no or invalid token, an Entra token whose issuer, audience, tenant or user the endpoint does not allow, an anonymous key fetch on another host, a non-current key version | `TestMicrosoftDKERefusesBadEntraTokens`, `TestMicrosoftDKEPublicKeyWithoutToken` |
| `audit.governance.approval_refused` (`reason: vote_refused`) | A vote refused: not an approver of the request (including a user without the policy's approver role), the requester, a wrong challenge code | `TestApproverRolesDecideWhoMayVote` |
| `audit.hyok.admin_refused` | HYOK endpoint administration without a valid token, cross-tenant, or by a non-administrator | `TestHYOKAdminRoutesRequireTenantAdmin` |
| `audit.hyok.approval_refused` | A retry whose approval is not approved, is for another key, operation or payload, or was already used | `TestHYOKGovernanceApprovalReleasesOperationOnce` |
| `audit.hyok.request_denied` (`reason: key_access_unavailable`, `result: refused`) | Key access is deployed (or the deployment's profiles are unknown) and gives no decision: `424` (6.10.0-beta) | `TestHYOKKeyAccessFailsClosed`; the not-deployed allow (`key_access_reason: key_access_not_deployed` on the request event) by `TestHYOKKeyAccessNotDeployedAllows` |
| `audit.hyok.request_denied` (`reason: policy_unavailable`, `result: refused`) | The policy service can't be reached: `424 policy_unavailable`; there is no fail-open setting (6.20.0-beta) | `TestHYOKPolicyUnavailableFailsClosed` |
| `audit.ekm.key_access_denied` (`result: refused`) | A TDE `wrap`, `unwrap` or `rotate` refused by key access: a deny decision (its `reason`), or `reason: key_access_unavailable` when deployed and unreachable (6.10.0-beta; unwrap and rotate denials were not audited before) | `TestEKMKeyAccessUnavailableRefuses`, `TestEKMKeyAccessDenyAudited`; not-deployed allow by `TestEKMKeyAccessNotDeployedAllows` |
| `audit.ekm.tde_key_accessed` (`operation: public`, `result: refused`, `reason: public_key_unavailable`) | `GET /ekm/tde/keys/{id}/public` when keycore gives no public key for the key: `424`. Before 6.12.0-beta an invented `EKM-PUBLIC-` value was returned and audited as a success, which now carries `result: success` and `key_version` | `TestTDEPublicKeyUnavailableRefuses`, `TestTDEPublicKeyUnavailableHTTP424`; success by `TestTDEPublicKeyFromKeycore`, `TestTDEPublicKeyFollowsRotation` |
| `audit.ekm.tde_key_accessed` (`operation: public`, `result: refused`, `reason` = keycore's) | keycore refused the user ekm acts for (6.18.0-beta): `403` (e.g. `delegation_refused`) or `404 not_found` for a key the user can't see, passed on with the same status and reason | `TestTDEPublicKeyKeycoreRefusalPassedOn` |
| `audit.cloud.key_access_denied` (`result: refused`) | A BYOK `import`, `rotate` or `sync` refused by key access: a deny decision, or `reason: key_access_unavailable` when deployed and unreachable (6.10.0-beta) | `TestCloudKeyAccessUnavailableRefuses`; not-deployed allow by `TestCloudKeyAccessNotDeployedAllows` |
| `audit.signing.sign_refused` | A sign request refused for identity, token or policy (4xx; `code`, `reason`, `identity_mode`, `result: refused`) | `TestSignRefusalAuditedPostgres` (disabled signing, forged OIDC token, then a valid sign that isn't counted as refused); `TestSignArtifactPolicyGatesPostgres` covers each service code |
| `audit.signing.request_refused` | A sign or verify request naming another tenant (`reason: tenant_mismatch`, `route`) | `TestTenantMismatchRefusedAndAudited` (blob, git and verify) |

| `audit.ekm.request_refused` | An EKM call without a verified token for its tenant, or a BitLocker agent call without a bitlocker-role JWT | `TestHandlerEKMRequiresVerifiedTenantToken` |

## Attested key release (1.30.0-beta)

| Event | When | Test |
|---|---|---|
| `audit.confidential.key_released` | Keycore sealed the key to the recipient key the verified evidence commits to | `TestReleaseSealsKeyToAttestedEnclaveKey` |
| `audit.confidential.key_release_refused` | No binding, verdict not allow, or keycore refused | `TestReleaseRefusedWithoutBindingAllowOrKeycore` |
| `audit.confidential.key_release` | Kernel event for `POST /confidential/release` (refused when nothing is released) | `TestConfidentialRefusalsAudited` (kernel refusals) |
| `audit.key.attested_release` | Keycore kernel event; refused for any caller but `kms-confidential`, non-exportable or inactive keys | `TestAttestedReleaseSealsToRecipientOnlyForConfidentialService` |

## Crypto policy floor (3.2.0-beta, docs/SECURITY/ALGORITHM_TRANSITIONS.md)

| Event | When | Test |
|---|---|---|
| `audit.policy.floor_refused` | A policy create or update refused because `spec.minAlgorithmTier` is not a floor (`result: refused`, `reason: invalid_min_algorithm_tier`, `policy_name`, `min_algorithm_tier`). Before 3.2.0-beta such a policy was stored and its floor enforced nothing | `TestUnknownFloorRefusedAndAudited` |
| `audit.policy.violated` | A request a policy denies, including by the `crypto-floor` rule: now `result: refused` (was `success`), with `algorithm` and the denying `rules` | `TestCryptoFloorDenialAudited` |
| `audit.policy.crypto_floor_violation` | A request denied by a policy's `minAlgorithmTier` (`result: refused`, `reason: below_min_algorithm_tier`, `policy_id`, `algorithm`, its `tier`, `message`); HIGH in the audit catalogue. Catalogued and documented for alerting before 3.2.0-beta but never emitted | `TestCryptoFloorDenialAudited` |

## Customer migration policy (5.1.0-beta, docs/SECURITY/ALGORITHM_TRANSITIONS.md)

| Event | When | Test |
|---|---|---|
| `audit.key.crypto_policy_refused` | A key operation refused by the tenant's migration policy (`reason` `crypto_policy_decrypt_only` or `crypto_policy_disallowed`, with `rule_id`, `rule_name`, `rule_action`); `result: refused`, `operation`, `algorithm`, `key_id`. The operation's own `audit.key.<op>` carries the same `reason`. Playbooks trigger `crypto_policy_refused` | `TestCryptoPolicyEnforcedOnKeyOperations`, `TestQuantumVulnerableRuleActsAsPQCFloor` |
| `audit.key.agility_policy_rules_listed`, `agility_policy_rule_created`, `agility_policy_rule_updated`, `agility_policy_rule_deleted` | Kernel events for migration rules (details `name`, `match_kind`, `match_value`, `action`, `effective_date`, `target_algorithm`; refusals `result: refused`). Changes are Playbooks trigger `crypto_policy_changed` | `TestAgilityPolicyRulesValidatedAndAudited`, `TestAgilityRoutesRefusalsAudited` |
| `audit.key.caraf_assessment_read`, `caraf_threats_listed`, `caraf_threat_created`, `caraf_threat_updated`, `caraf_threat_deleted`, `caraf_assets_listed`, `caraf_asset_created`, `caraf_asset_updated`, `caraf_asset_deleted` | Kernel events for the risk assessment (details: threat `years_to_threat` and match; asset X, Y, cost, ownership, sensitivity, linked key count; refusals `result: refused`) | `TestCarafRoutesValidatedAndAudited`, `TestAgilityRoutesRefusalsAudited` |
| `audit.key.caraf_decision_recorded` | A risk decision recorded or cleared (warning; `decision`, `owner`, `status`, `due`, `review_by`; the verified caller is `decided_by`). Playbooks trigger `crypto_risk_decision_recorded` | `TestCarafRoutesValidatedAndAudited` |
| `audit.key.agility_drill_run` | An algorithm-swap drill run (`from_algorithm`, `to_algorithm`, `iterations`, `drill_result` passed/failed, `drill_error`); refused with `fips_mode_violation`, `crypto_policy_disallowed` or `crypto_policy_decrypt_only` (`result: refused`, `rule_id`) | `TestAgilityDrillRouteValidatedAndAudited`, `TestAgilityDrillStrictRefusesNonModuleAlgorithm` |
| `audit.key.agility_drills_listed` | Drill history read (refusals `result: refused`) | `TestAgilityDrillRouteValidatedAndAudited`, `TestAgilityRoutesRefusalsAudited` |

## Automation signals (5.3.0-beta, docs/AUTOMATION_ALKM_PQC.md)

| Event | When | Test |
|---|---|---|
| `audit.security.sustained_risk_detected` | Audit saw 3 events scoring ≥80 on one target (key, other target, or tenant) within 5 minutes; once per window, `result: warning`, `target_type` / `target_id` set so the `sustained_risk_detected` playbook trigger can act on `{{event.target_id}}`. It changes nothing itself | `TestSustainedRiskPublishedOnceWithTarget` |

No longer emitted, because the work they named never happened:
`audit.security.auto_quarantined` (renamed to the row above; nothing was
quarantined), `audit.security.hndl_pattern_detected` (raw encrypt volume, not
a harvest-now-decrypt-later measurement), `audit.tenant.onboarded` (keycore's
`/tenants/onboard` provisioned nothing, yet was audited every 30 s),
`audit.key.archive_requested` (nothing was queued), and
`audit.kmip.client_dormant` / `audit.kmip.client_revoked` from the KMIP
auto-decommission, which measured time since a client was created, not its
traffic. The catalogue entries for events no code ever emitted
(`audit.key.wake_kat_failed`, `hbs_exhausted`, `dependency_blocked_destroy`,
`predictive_rotation_scheduled`, `lifecycle_auto_transition`,
`zeroization_verified`, `archive_completed`, `audit.pqc.attestation_recorded`)
are gone too.

## Tenant cryptoperiods (2026-09-30, docs/AUTOMATION_ALKM_PQC.md)

| Event | When | Test |
|---|---|---|
| `audit.key.cryptoperiods_listed`, `audit.key.cryptoperiod_set`, `audit.key.cryptoperiod_reset` | Kernel events for the tenant's cryptoperiods (`days`, `default_days`); refusals `invalid_days`, `unknown_category`, `not_custom` with `result: refused` | `TestTenantCryptoperiodDrivesRotation`, `TestRotationRoutesRefusalsAudited` |

## REST client credentials (7.16.0-beta, docs/CI_CD_AUTOMATION.md)

Rotation, revocation and API-key deletion moved onto the route kernel, so
each call and each refusal is its own event.

| Event | When | Test |
|---|---|---|
| `audit.auth.client_key_rotated` | An approved client's API key was replaced; the old key row is deleted in the same transaction (`api_key_prefix`). Refused (`result: refused`): `client_state` (not approved), `service_identity_protected` (a `kms-*` identity) | `TestRotatedClientKeyWorksAndOldKeyStops`, `TestRevokedClientKeyStops`, `TestPendingClientKeyRotationRefused`, `TestServiceIdentityClientProtected` |
| `audit.auth.client_revoked` | A client was revoked and its API keys deleted. Refused: `service_identity_protected` | `TestRevokedClientKeyStops`, `TestServiceIdentityClientProtected` |
| `audit.auth.api_key_revoked` | One API key was deleted. Refused: `service_identity_protected` (a platform service key) | `TestServiceIdentityClientProtected` |
| `audit.auth.client_activation_refused` (`code: client_state` or `not_found`) | Activation of a client that is no longer pending (it would have minted a second key) or doesn't exist | `TestActivationOfApprovedClientRefusedAndAudited` |
| `audit.auth.unbound_api_keys_retired` | Auth startup deleted API keys bound to no client, which only the removed `POST /auth/api-keys` created (`keys_deleted`, `reason: endpoint_removed`) | `TestUnboundAPIKeysRemovedAndRetired`, `TestClientKeyLifecyclePostgres` |
| (all of the above, unauthenticated / wrong tenant / missing permission) | Kernel refusals | `TestClientAdminRefusalsAudited` |
