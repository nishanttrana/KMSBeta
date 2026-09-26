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
| `audit.dataprotect.kdf_legacy_used` | dataprotect | identifier-derived (v1) working keys are used (at most every 5 min per key, with a count) | warning |
| `audit.dataprotect.kdf_refused` | dataprotect | a derivation is refused: v1 after migration, v2 before it, or v1 in strict mode (at most once a minute per key and reason, with a count) | critical for v1 after migration, else warning |
| `audit.dataprotect.kdf_migration_started` / `_vault_reprotected` / `_migration_completed` / `_migration_aborted` | dataprotect | per-key migration steps (actor, pinned version, counts; forced completion noted) | info; warning when forced or rows failed |

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

Proven by `routetest.RefusalsAudited` for every route, and by the
`pkg/route` and `services/secrets` tests.

## What can't be audited, and how it shows instead

A service that **refuses to start** has no audit pipeline yet, because it exits
before connecting. That covers placeholder secrets, weak database passwords,
an invalid or mismatched FIPS mode, and a missing certified module. These
refusals appear as:
- a `refusing to start: …` line on the container's stderr;
- the service missing or restarting in health checks;
- during a FIPS rollout, the service never reaching the target mode in System
  Administration → Runtime Crypto (and no `fips_mode_applied` event for it).

Tests that prove emission: `TestBootstrapRevokesKeysDerivedFromPublicDefaultSecret`,
`TestBootstrapRetiresServiceKeysFromRotatedSecret` (auth);
`TestFIPSModeChangeImpactAndRollout`,
`TestFIPSRolloutIsAuditedOncePerStartAndOnCompletion` (governance);
`TestGenericDeriveCannotReproduceServiceSubkey` (keycore);
`TestLegacyKeyStaysReadableAndIsAudited`, `TestKDFMigrationDualReadThenCutover`
(dataprotect).
