# Audit events added in the 2026-09 security refresh

Every event goes through the unified audit pipeline (`pkg/audit` / service
publisher → `AUDIT` stream). On top of these, every HTTP request, including
every refusal (4xx), is audited by `pkg/auditmw`. The events below add
security meaning where a generic request record isn't enough.

| Event | Emitted by | When | Severity |
|---|---|---|---|
| `audit.auth.service_key_revoked` | auth (startup) | a service API key derived from the old public default secret is deleted | critical |
| `audit.auth.service_key_retired` | auth (startup) | service keys from a previous `INTERNAL_SERVICE_BOOTSTRAP_SECRET` are deleted after rotation | warning |
| `audit.governance.fips_mode_changed` | governance | an admin changes the platform FIPS mode (from, to, actor, reason, stopped features, restarts) | critical for a downgrade, else warning |
| `audit.governance.fips_mode_applied` | governance | a service instance starts and reports its FIPS mode (once per start) | info; warning if it differs from the platform mode |
| `audit.governance.fips_mode_rollout_completed` | governance | every service runs the requested mode (once per change) | info |
| `audit.cluster.publication_changed` | cluster-manager | a replication publication is created or its table set changes (which data this node offers members) | info |
| `audit.cluster.member_joined` | cluster-manager (primary) | a node consumed a join token and received the master key and a replication role for its components | warning |
| `audit.cluster.joined_cluster` | cluster-manager (member) | this node joined a cluster: master key replaced, components subscribed | warning |
| `audit.auth.cluster_token_minted` | auth (primary) | a primary-signed 5-minute token is minted for a write a member forwarded (user, member node) | info; warning if the source is a service principal |
| `audit.auth.cluster_mint_refused` | auth (primary) | a forwarded-token mint was refused: caller isn't cluster-manager, malformed request, or the user must change their password (`reason`, `result: refused`) | warning |
| `audit.cluster.write_forwarded` | cluster-manager (primary) | a member's forwarded write was proxied to a service (member, service, method, path, actor, status) | info |
| `audit.cluster.forward_refused` | cluster-manager (primary) | a forwarded write was refused: bad member credential (including a removed member), not forwardable, bad claims, identity refused | warning |
| `audit.<service>.cluster_write_forwarded` | every service (member) | this member sent a lifecycle write to the primary (actor, method, path, primary, status) | info |
| `audit.<service>.cluster_write_refused` | every service (member) | a write was refused on the member: `invalid_token`, `primary_unreachable` (down or TLS pin mismatch), `primary_write_required` | warning |
| `audit.key.cluster_join_key_created` | keycore (member) | a one-time ML-KEM join key was created for a master-key transfer | info |
| `audit.key.cluster_mek_exported` | keycore (primary) | the master key was sealed to a joining member (member, context, fingerprint) | critical |
| `audit.key.cluster_mek_imported` | keycore (member) | a cluster master key was installed; keycore restarts on it | critical |
| `audit.key.service_derive` | keycore | an internal service derives a purpose-bound working key | info |
| `audit.key.derive_refused` | keycore | a generic derive tries to use the reserved service-derive context | critical |
| `audit.cert.ocsp_refused` | certs | an OCSP request with a SHA-1 CertID in FIPS strict mode | warning |
| `audit.dataprotect.fpe_refused` | dataprotect | FPE request for FF3-1, legacy encrypt or an unknown algorithm (`reason`, `result: refused`) | warning |
| `audit.dataprotect.fpe_legacy_decrypted` | dataprotect | pre-1.26.0 ciphertext decrypted for migration (`LEGACY-FF1`/`LEGACY-FF3-1`) | warning |
| `audit.key.create_refused` | keycore | key creation for an algorithm keycore does not generate (`reason`, `result: refused`) | warning |
| `audit.key.algorithm_label_corrected` | keycore (primary, startup) | a key record named material it didn't hold is relabelled to the real algorithm or `INVALID-MATERIAL` (recorded vs actual) | warning |
| `audit.crypto.random_refused` | keycore | random bytes requested from a source that is unavailable (QKD, QRNG, no tenant HSM) | warning |
| `audit.hsm.random_generated` | hsm-connector (kernel) | random bytes drawn from a tenant HSM with `C_GenerateRandom` (refusals included) | info |
| `audit.key.kdf_refused` | keycore | scrypt or Argon2id KDF refused in FIPS strict mode | warning |
| `audit.pqc.migration_step_executed` | pqc | one migration step changed a key in keycore (`outcome`: `successor_created` with `successor_key_id`, or `rotated`) | info |
| `audit.dataprotect.kdf_legacy_used` | dataprotect | identifier-derived (v1) working keys are used (at most every 5 min per key, with a count) | warning |
| `audit.dataprotect.kdf_refused` | dataprotect | a derivation is refused: v1 after migration, v2 before it, or v1 in strict mode (at most once a minute per key and reason, with a count) | critical for v1 after migration, else warning |
| `audit.dataprotect.kdf_migration_started` / `_vault_reprotected` / `_migration_completed` / `_migration_aborted` | dataprotect | per-key migration steps (actor, pinned version, counts; forced completion noted) | info; warning when forced or rows failed |

## Key access (keycore)

| Event | When | Severity |
|---|---|---|
| `audit.key.access_refused` | a key operation was denied by key access control (`result: refused`, `reason`: `authentication_required` (no verified token; there is no anonymous key use), `not_assigned_to_caller`, `deny_by_default`, `no_matching_grant`, `authentication_required`, `interface_policy`, `workload_not_authenticated`, `workload_operation_not_permitted` or `workload_key_not_bound`; with `key_id`, `operation`, the verified `actor`, `authenticated`, and `unverified_actor_headers` if any were sent) | warning |
| `audit.key.actor_headers_ignored` | a request carried `X-Actor-*` / `X-KMS-Subject` / `X-KMS-Interface` identity headers; they were ignored (`result: refused`, `reason: unverified_identity_headers`, `claimed` values, `verified_actor`) | warning |

Identity comes only from the verified token (CLAUDE.md rule 4). Proven by
`TestActorHeadersCannotGrantAccess`, `TestActorHeadersWithoutTokenAreNotAnIdentity`,
`TestActorGroupsHeaderDoesNotMatchGrants` and `TestActorBuiltFromVerifiedClaimsOnly`.

## System administration (governance)

| Event | When | Severity |
|---|---|---|
| `audit.governance.system_admin_refused` | a system-administration route (settings, backups, restore, backup key, system state, FIPS mode, posture controls, network, FDE, SNMP, integrity) was refused (`result: refused`; `reason`: `authentication_required`, `tenant_required`, `tenant_mismatch`, `not_root_tenant`, `token_tenant_not_root` or `insufficient_privileges`; with `route`, `status`, `actor`, `authenticated`) | warning |
| `audit.governance.authentication_refused` | a governance request carried a token that doesn't verify (`result: refused`, `reason: invalid_token`, `route`) | warning |

Only a verified root administrator passes, plus the platform services listed
per route in `systemAdminServiceCallers` (keycore and policy read
`GET /governance/system/state`; posture writes
`PUT /governance/system/posture-controls`). Governance refuses to start
without its token-verification key (see below). Proven by
`TestSystemAdminRoutesRequireVerifiedToken`, `TestSystemAdminRefusalReasons`,
`TestSystemAdminServiceCallersAreRouteBound` and `TestMissingJWTKeyRefusesStart`.

## HSM integration (hsm-connector, keycore)

| Event | When | Severity |
|---|---|---|
| `audit.hsm.<action>` | every hsm-connector request (kernel): `key_generated` (details `hsm_serial`, `hsm_token`), `tenant_key_ensured`, `encrypt`, `decrypt`, `sign`, `verify`, `key_destroyed`, `status_read`, `key_inspected`, `objects_listed`; refusals carry `result: refused` and `reason` (`caller_not_allowed`, `foreign_label`, `hsm_not_configured`, `library_not_allowed`, `pin_not_provided`, `integrity_check_failed`, `tenant_key_protected`, `algorithm_not_supported`, and the kernel's own) | info; warning for destroy and refusals |
| `audit.key.hsm_settings_updated` | a tenant's "tenant key in HSM" / "HSM keys" switches changed (before and after) | warning |
| `audit.key.hsm_refused` | keycore refused an HSM operation (`reason`: `hsm_keys_disabled`, `hsm_not_configured`, `hsm_not_connected`, `hsm_unavailable`, `algorithm_not_supported`, `hsm_import_not_supported`, `iv_mode_not_supported`, `material_in_hsm`, `hsm_key_not_found`: the key's object is not on the HSM the tenant's profile points at, message names the recorded serial) | warning |
| `audit.key.hsm_objects_destroyed` / `audit.key.hsm_destroy_failed` | a destroyed HSM key's objects were removed from the HSM, or some couldn't be (`labels`, `result: failure`) | info / critical |
| `audit.key.hsm_status_read`, `audit.key.hsm_settings_update` | kernel events for keycore `GET`/`PUT /hsm/settings` | info / warning |
| `audit.key.hsm_device_changed` | an HSM key was rotated onto a different HSM (serial) than its previous version (`previous_serial`, `serial`) | warning |
| `audit.key.hsm_objects_listed`, `audit.key.hsm_key_inspected` | kernel events for keycore `GET /hsm/objects` (partition listing) and `GET /keys/{id}/hsm` ("Verify in HSM") | info |
| `audit.key.create` | for HSM keys also carries `hsm_serial`, `hsm_token`, `hsm_model`, `hsm_manufacturer` of the device that generated it | info |
| `audit.cert.crl_generation_failed` | a CA couldn't sign its CRL (for an HSM CA: the HSM or keycore refused); no unsigned CRL is published | critical |

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

| Event | When | Severity |
|---|---|---|
| `audit.<svc>.dev_mek_rewrapped` | rows under a public development key were re-wrapped onto the keycore-held key; the items entered the exposure register | warning |
| `audit.<svc>.mek_rewrapped` | rows under an old environment key (`from: env_mek`) or the previous keycore version (`from: previous_version`) were re-wrapped | info |
| `audit.<svc>.dev_mek_rewrap_refused` / `mek_rewrap_refused` | a row a legacy key opens couldn't be rewritten (`result: refused`, `reason: rewrap_failed`); start refused, retried next start | critical |
| `audit.<svc>.mek_unreadable` | rows no known key opens (`result: failure`); emitted when the count changes | warning |
| `audit.<svc>.mek_check_refused` | keycore derives a different key than the stored data is recorded under (`result: refused`, `reason: mek_mismatch`); start refused | critical |
| `audit.<svc>.mek_exposure_remediated` | an exposure entry closed: material rotated, deleted or re-keyed, or acknowledged with a reason | info; warning when acknowledged |
| `audit.<svc>.mek_exposure_listed` / `mek_exposure_acknowledged` | kernel events for `GET /mek/exposure` and the acknowledge route (refusals included) | info / warning |
| `audit.<svc>.mek_backup_rewrap` | governance re-wrapped backup contents through the service (counts; `result: refused` for any other caller) | warning |
| `audit.key.data_key_generated` | keycore `POST /keys/{id}/generate-data-key` (kernel event; details `key_bytes`, `include_plaintext`, `version`; refusals `result: refused` with `reason`: `ops_limit_reached`, `policy_denied`, `fips_mode_violation`, access refusals, HSM refusals, `permission_denied`) | info; warning for refusals |
| `audit.key.agility_score_read`, `agility_inventory_read`, `agility_keys_by_algorithm_read`, `agility_migration_plans_listed` | kernel events for keycore's crypto-agility reads (refusals `result: refused`: `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`) | info; warning for refusals |
| `audit.key.agility_migration_plan_created` / `agility_migration_plan_updated` | kernel events for creating a migration plan (details `from_algorithm`, `to_algorithm`, server-counted `affected_keys`) and changing its status (detail `status`); refusals as above | info; warning for refusals |
| `audit.key.rotation_policy_*`, `rotation_runs_listed`, `rotation_upcoming_listed` | kernel events for keycore rotation policies: created, updated, deleted, triggered (details `matched`, `rotated`, `failed`) and listed; refusals `result: refused` | info; warning for delete, trigger and refusals |
| `audit.key.rotation_policy_run` | a scheduled policy run on the primary (actor `kms-keycore-rotation-scheduler`; details `matched`, `rotated`, `failed`, `error`); each rotated key also emits `audit.key.rotate` | info; warning when a key failed |
| `audit.audit.webhook_*` (`webhooks_listed`, `webhook_created`, `webhook_updated`, `webhook_deleted`, `webhook_tested`, `webhook_deliveries_listed`) | kernel events for webhook management; a blocked URL is `result: refused`, `reason: url_blocked` | info; warning for changes |
| `audit.audit.webhook_delivered` | one audit event delivered (or test) to one webhook: `event_id`, `event_action`, `http_status`, `attempts`, `latency_ms`; never itself delivered | info; warning on failure |
| `audit.audit.webhook_credentials_sealed` | the primary sealed webhook credentials an earlier release stored in plaintext (`count`, `webhook_ids`); each is also in the exposure register | warning |
| `audit.audit.webhook_credentials_seal_refused` | plaintext webhook credentials could not be sealed (`webhook_ids`, `reason: seal_failed`) | critical |
| `audit.<svc>.mek_exposure_recorded` | an item entered the exposure register for a reason other than a public key, e.g. `source: plaintext_storage` (`mek.Keyring.RecordExposure`) | warning |
| `audit.posture.leak_*` (`leak_targets_listed`, `leak_target_created`, `leak_target_deleted`, `leak_scan_started`, `leak_jobs_listed`, `leak_findings_listed`, `leak_finding_updated`) | kernel events for the leak scanner; a scan of a disabled target is refused (`target_disabled`) | info |
| `audit.posture.leak_scan_completed` | a scan finished or failed: `status`, `findings`, `job_id`, error | info; warning with findings or on failure |
| `audit.posture.*` engine kernel events (`health_read`, `dashboard_viewed`, `risk_read`, `risk_history_read`, `scan_run`, `events_ingested`, `audit_synced`, `findings_listed`, `finding_status_updated`, `actions_listed`, `action_executed`) | every posture engine request (1.32.0-beta), including refusals `result: refused` with `reason` `unauthenticated` (no or forged token), `permission_denied`, `tenant_mismatch` (query, header, body or batch item names another tenant; `requested_tenant`), `tenant_conflict`, `tenant_wildcard` (`*`/`all`). `action_executed` carries the verified executor as actor and what the executor changed (`severity_from`, `severity_to`, `escalated_finding_id`, `approval_request_id`); it is refused with `approval_pending`, `approval_invalid` (an approval ID not bound to this action and caller), `approval_unavailable` (fail closed) or `not_executable` (1.34.0-beta); a re-run (`already_executed`) or a source finding no longer open (`finding_not_open`) is `result: failure` | info; warning for `action_executed` and refusals |
| `audit.posture.actions_corrected` | the primary corrected action rows written before 1.34.0-beta, when "execute" only published an event nothing consumed: `reset_to_suggested` (escalations to run for real), `not_performed` (other types marked executed), `withdrawn` (open actions of types posture cannot execute) | warning |
| `audit.posture.events_ingested` (scheduled) | the engine scheduler synced audit events into posture (`inserted`, `source: scheduled_audit_sync`), under the synced tenant | info |
| `audit.key.system_key_ensure` | a service asked for its system key (kernel event; `refused` for a non-service caller) | info |
| `audit.key.system_key_created` | keycore created a service's system key | info |
| `audit.key.system_key_change_refused` | destroy, disable, version delete or export of a system key was refused (`operation`, `reason: system_key_protected`) | critical |
| `audit.governance.backup_create_refused` | a backup wasn't taken (`reason`, for example a service couldn't re-wrap a row under a public key, or `BACKUP_HSM_WRAP_SECRET` is missing or short) | warning |
| `audit.governance.backup_key_downloaded` | an HSM-bound backup's wrapped key file was downloaded again | warning |
| `audit.governance.backup_key_download_refused` | a key download was refused (`reason: key_not_retained`: software mode, or a key removed by migration 013) | warning |

**If NATS is down at startup,** migration events can't be published. The
counts stay in `<svc>_mek_state` and the items in `<svc>_mek_exposure`, and
the service log has a `MEK scan: …` line. A refused start shows as a
`refusing to start:` line.

## Internal mTLS (certs, docs/SECURITY/INTERNAL_TLS.md)

| Event | When | Severity |
|---|---|---|
| `audit.cert.internal_subca_created` | the internal-services Sub CA is created under the runtime root (first start) | info |
| `audit.certs.internal_enroll` | every enrolment request on `POST /v1/enroll` (route kernel); refusals carry `result: refused` and `reason`: `invalid_request`, `invalid_csr`, `proof_rejected` (wrong identity, wrong secret, expired, unknown identity), `issuance_refused` | warning |
| `audit.cert.internal_pki_bootstrapped` | the certs service loaded its internal PKI before the database and recorded the CAs and the certificates it issued before connecting (`created`, `issued_before_database`) | info |
| `audit.cert.internal_enrolled` | a certificate was issued from a CSR: identity, serial, key algorithm, expiry, how many previous certificates were superseded | info |

Proven by `TestEnrollmentIssuesRegistrySANsFromTheSubCA` and
`TestEnrollmentRefusals` (services/certs), and `TestEnrollmentProof`
(pkg/svctls).

## HSM library uploads and CLI/SSH access (hsm-connector, auth)

| Event | When | Severity |
|---|---|---|
| `audit.hsm.provider_library_inventory` | connector start: each tenant's provider files with SHA-256 | info |
| `audit.hsm.provider_library_added` / `_changed` / `_removed` | a file uploaded, replaced or deleted over SSH/SFTP | warning |
| `audit.auth.cli_session_refused` | CLI session refused, `result: refused`, `reason` `invalid_credentials` or `public_default_password` | warning |
| `audit.auth.cli_ssh_password_synced` | auth set the SSH password on hsm-integration (`result` success/failure) | info |
| `audit.auth.cli_password_revoked` | a CLI user on the retired public password got a random one; SSH copy locked | critical |

Proven by `TestLibraryWatcherAuditsUploads` (pkg/hsmconnector),
`TestCLISessionRefusesThePublicPasswordAndAuditsRefusals`,
`TestRevokeRetiredCLIPasswords` and
`TestCLISSHPasswordSyncKeepsThePasswordOffTheCommandLine` (services/auth).
SSH logins themselves are in the hsm-integration container log (sshd,
`LogLevel VERBOSE`, with key fingerprints), not the audit trail.

## Service mTLS (certs, docs/SECURITY/INTERNAL_TLS.md)

| Event | When | Severity |
|---|---|---|
| `audit.certs.internal_mtls_inventory_read` | the Service mTLS page was read (root only) | info |
| `audit.certs.internal_mtls_policy_updated` | an identity's certificate key or key-exchange profile changed; previous and new values, generation, certificates revoked | warning |
| `audit.certs.internal_mtls_rotated` | an identity's certificate was revoked and replaced; `restart_mode` graceful or force | warning |
| `audit.certs.internal_mtls_rotated_all` | every internal certificate was rotated, with staggered restarts | critical |
| `audit.certs.internal_mtls_applied` | every reporting instance runs the new generation (from their reports, not the request); serials | info |
| `audit.certs.certificate_key_label_corrected` | a certificate or CA record named a key its certificate doesn't carry, and was corrected (`recorded_algorithm`, `recorded_class`, `actual_algorithm`, `reason`: `key_size_mismatch` or `pqc_label_removed`) | warning |
| `audit.certs.pqc_profile_removed` | a certificate profile with a PQC or hybrid algorithm was deleted (PQC certificates removed, 1.19.0-beta) | warning |
| `audit.cert.pqc_issuance_refused` | a PQC or hybrid certificate, CA or profile was requested and refused (`kind`, `algorithm`, `class`, `result: refused`, `reason: pqc_certificates_removed`); replaces `audit.cert.pqc_cert_issued`, `pqc_cert_validated` and `pqc_migration_executed` | warning |

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

| Event | When | Severity |
|---|---|---|
| `audit.certs.crwk_rotated` | the CRWK was re-keyed after a passphrase rotation. Details: `from_version`, `to_version`, `ca_signers_rewrapped`, and `reason`: `passphrase_rotation`, or `public_default_passphrase` (migration off the retired public passphrase; carries an `exposure` note). A failed rewrap has `result: failure`, `reason: rewrap_failed`, `rotation_reason`, and the error; it is retried on the next start | warning |

Proven by `TestCRWKMigratesOffThePublicDefault` (SQLite and
`...Postgres`) and `TestCRWKRotationResumesAndAuditsFailure`
(services/certs).

## Kernel-emitted events (pkg/route)

Services migrated to the `pkg/route` kernel emit one specific event per
request, and the kernel guarantees it for refusals too. The kernel's own
refusals are listed below. Handlers add their own (for example
`feature_preview` or a FIPS refusal) with `c.Refuse`.

| Event | When | Severity |
|---|---|---|
| `audit.<service>.<action>`, `result: refused`, `reason: unauthenticated` | no verified token on a non-public route (401) | warning |
| `audit.<service>.<action>`, `result: refused`, `reason: permission_denied` | the token lacks the route's permission (403) | warning |
| `audit.<service>.<action>`, `result: refused`, `reason: tenant_mismatch` | the request names a tenant other than the token's (403), including in the JSON body | warning |
| `audit.<service>.<action>`, `result: refused`, `reason: tenant_conflict` | query, header and body name different tenants (403) | warning |
| `audit.<service>.<action>`, `result: failure` | the handler returned an error (`error_code` in details) | the route's severity |
| `audit.secrets.*` | every secrets route; see the table in `docs/API_REFERENCE.md` (Service 25) | info; `value_read` and `deleted` are warning |
| `audit.sbom.*` | every sbom/cbom route (1.33.0-beta); list in `docs/API_REFERENCE.md` (Audit Action Subject Reference) | info; `sbom_advisory_deleted` is warning |
| `audit.sbom.<action>`, `result: refused`, `reason: platform_tenant_required` | a tenant other than the platform tenant tries to generate the platform SBOM or save/delete an advisory (403) | warning |
| `audit.reporting.*` | every reporting route (1.33.0-beta); the actor is the verified caller, never a body field, `actor` query or `X-Actor-ID` | info; `rule_deleted` and `report_deleted` are warning |

Proven by `routetest.RefusalsAudited` for every route, and by the
`pkg/route`, `services/secrets`, `services/sbom` and `services/reporting`
tests (`handler_tenancy_test.go`: cross-tenant refusals audited, identity from
the token).

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
| `audit.hyok.request_denied` (`reason: key_access_unavailable`) | The key-access service is unreachable and the proxy fails closed | `TestHYOKKeyAccessFailsClosed` |
| `audit.signing.sign_refused` | A sign request refused for identity, token or policy (4xx; `code`, `reason`, `identity_mode`, `result: refused`) | `TestSignRefusalAuditedPostgres` (disabled signing, forged OIDC token, then a valid sign that isn't counted as refused); `TestSignArtifactPolicyGatesPostgres` covers each service code |
| `audit.signing.request_refused` | A sign or verify request naming another tenant (`reason: tenant_mismatch`, `route`) | `TestTenantMismatchRefusedAndAudited` (blob, git and verify) |

| `audit.ekm.request_refused` | An EKM call without a verified token for its tenant, or a BitLocker agent call without a bitlocker-role JWT | `TestHandlerEKMRequiresVerifiedTenantToken` |

## Attested key release (1.30.0-beta)

| Event | When | Test |
|---|---|---|
| `audit.confidential.key_released` | Keycore sealed the key to the recipient key the verified evidence commits to | `TestReleaseSealsKeyToAttestedEnclaveKey` |
| `audit.confidential.key_release_refused` | No binding, verdict not allow, or keycore refused | `TestReleaseRefusedWithoutBindingAllowOrKeycore` |
| `audit.confidential.key_release` | Kernel event for `POST /confidential/release` (refused when nothing is released) | kernel (`pkg/route`) |
| `audit.key.attested_release` | Keycore kernel event; refused for any caller but `kms-confidential`, non-exportable or inactive keys | `TestAttestedReleaseSealsToRecipientOnlyForConfidentialService` |
