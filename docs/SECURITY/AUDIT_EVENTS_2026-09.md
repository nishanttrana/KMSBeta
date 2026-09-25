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
| `audit.key.service_derive` | keycore | an internal service derives a purpose-bound working key | info |
| `audit.key.derive_refused` | keycore | a generic derive tries to use the reserved service-derive context | critical |
| `audit.cert.ocsp_refused` | certs | an OCSP request with a SHA-1 CertID in FIPS strict mode | warning |
| `audit.dataprotect.kdf_legacy_used` | dataprotect | identifier-derived (v1) working keys are used (at most every 5 min per key, with a count) | warning |
| `audit.dataprotect.kdf_refused` | dataprotect | a derivation is refused: v1 after migration, v2 before it, or v1 in strict mode (at most once a minute per key and reason, with a count) | critical for v1 after migration, else warning |
| `audit.dataprotect.kdf_migration_started` / `_vault_reprotected` / `_migration_completed` / `_migration_aborted` | dataprotect | per-key migration steps (actor, pinned version, counts; forced completion noted) | info; warning when forced or rows failed |

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
