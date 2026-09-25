# Data Protection Working-Key Derivation

**Standing rule.** A dataprotect working key (tokenization, FPE, masking, field
encryption, envelope, searchable encryption) is always derived from **secret
key material held by keycore**, never from identifiers. Data protected the old
way stays readable until its key is migrated. Nothing breaks silently.

## What was wrong (found 2026-09-25)

keycore's `GET /keys/{id}` returns metadata only. It includes the **KCV** (hex)
but never `material_b64`. dataprotect then fell back to
`firstString(material, wrapped_material, kcv, id)`, and failing that to
`tenant|key|purpose`, and ran the result through HMAC-SHA256 (`keyFromHash`).

**In production the working key was `HMAC(KCV, …)`.** The KCV is public: it
appears in the key list, the API and the dashboard. So anyone who could read
key metadata could recompute every tokenization, FPE and field-protection key,
reverse FPE ciphertexts, brute-force vault lookup hashes of low-entropy values
such as card numbers, and forge searchable-encryption tokens.

## The fix

**keycore: `POST /keys/{id}/service-derive`**
([service_derive.go](../../services/keycore/service_derive.go))

- **Caller:** internal services only (a verified service JWT, `kms-*` client).
  Any other caller gets 403 `service_identity_required`.
- **Derivation:** `HKDF-SHA256(key material of version N, salt="vecta-service-derive", info="vecta/service-derive/v1|<client>|<tenant>|<key>|<purpose>|vN")`,
  using the FIPS-module `crypto/hkdf`.
- **Binding:** the client ID comes from the verified JWT, so only
  kms-dataprotect can obtain dataprotect's subkeys.
- **Can't be reproduced:** `POST /keys/{id}/derive` refuses info that starts
  with the reserved prefix.
- **Stable across rotation:** the version is pinned, so rotating the keycore
  key doesn't silently change a working key.
- **Audit:** every call emits `audit.key.service_derive` (key, version,
  purpose, calling service) and records key usage.

**dataprotect: versioned derivation** ([kdf.go](../../services/dataprotect/kdf.go))

| Version | Working key |
|---|---|
| `v1` (legacy) | the old identifier-derived key. Kept **only** so existing data stays readable |
| `v2` | keycore service-derive, pinned to a key version |

Each key has a state in `dataprotect_key_kdf`:

```
legacy ──start-migration──▶ migrating ──complete──▶ v2
              ▲                  │
              └──────abort───────┘
```

| State | Default | Per-request `X-Vecta-KDF-Version` | Stored vault tokens |
|---|---|---|---|
| `legacy` | v1 | `v2` → 409 `kdf_migration_not_started` | written v1 |
| `migrating` | v1 (unchanged clients keep working) | `v1` or `v2` (dual-read / dual-write) | written **v2**; each row read with its own version |
| `v2` | v2 | `v1` → 409 `legacy_kdf_retired` | v2 only; any leftover v1 row → 409 |

- **New keys:** keys created **after** the v2 cutoff (recorded by migration
  011 when this release first starts; on a fresh install, before any key) are
  `v2` from birth and can never use v1.
- **Existing keys:** keys created before the cutoff, or whose creation time is
  unknown, start as `legacy`. The service never guesses v2 for a key that may
  already protect v1 data.
- **FIPS strict mode** (`VECTA_FIPS_MODE=only`): v1 is refused in every state
  (409 `key_material_unavailable`).
- **Every v1 derivation is counted.** `legacy_uses` and `last_legacy_use_at`
  are stored, and `audit.dataprotect.kdf_legacy_used` (severity `warning`) is
  emitted at most every 5 minutes per key, so ongoing legacy use is always
  visible.

## Migration runbook (per key)

1. **See what's legacy:** `GET /kdf/keys?tenant_id=…`, or Data Protection →
   Working-Key Derivation in the dashboard. Each row shows its state, legacy
   use count and remaining v1 vault tokens.
2. **Start:** `POST /kdf/keys/{key_id}/start-migration`. This pins the
   keycore version v2 will use.
3. **Re-protect data you hold** (FPE ciphertexts, field-encrypted records,
   envelopes, searchable indexes, vaultless tokens): for each value, call the
   decrypt or detokenize endpoint with `X-Vecta-KDF-Version: v1` and the
   encrypt or tokenize endpoint with `X-Vecta-KDF-Version: v2`, then store the
   result. Unchanged clients keep reading v1 throughout.
4. **Re-protect stored vault tokens:** run
   `POST /kdf/keys/{key_id}/reprotect-vault` (`{"limit": 1000}`) until
   `remaining` is 0.
   - Token strings don't change, so tokens your systems hold stay valid.
   - Each original is re-encrypted and its lookup hash recomputed, so the same
     input still returns the same token.
   - Irreversible tokens have no stored original; their v1 lookup hash (an
     HMAC under the predictable key) is dropped.
   - `failed_token_ids` lists rows the v1 key couldn't decrypt (see the
     limitations below).
5. **Complete:** `POST /kdf/keys/{key_id}/complete`. It's refused while v1
   vault tokens remain (409 `legacy_tokens_remaining`).
   `{"force": true}` abandons unreadable leftovers and is audited as a
   warning. From now on v1 is refused for this key in every mode.
6. **If you need to back out:** `POST /kdf/keys/{key_id}/abort` returns a
   migrating key to legacy. Rows already re-protected stay v2 and readable.

Audit events: `kdf_migration_started`, `kdf_vault_reprotected`,
`kdf_migration_completed`, `kdf_migration_aborted` (all
`audit.dataprotect.*`), plus keycore's `audit.key.service_derive`.

## Known limitations

- **Vault rows unreadable before the migration:** under v1 the key followed
  the *current* KCV, so rotating a keycore key already broke older vault rows.
  The re-protect job reports them in `failed_token_ids`; they can only be
  abandoned (`force`).
- **Re-pinning after rotation:** rotating the keycore key doesn't re-key v2
  data (the version is pinned). Moving v2 data to a newer key version is a
  follow-up that will reuse this state machine.
- **Latency:** dataprotect calls keycore once per operation per key to derive.
  Caching derived working keys is a possible optimisation.

## Tests

- **keycore:**
  - `TestServiceDeriveBindsCallerPurposeAndVersion`
  - `TestServiceDeriveRequiresServiceIdentity`
  - `TestGenericDeriveCannotReproduceServiceSubkey`
- **dataprotect:**
  - `TestNewKeyUsesKeycoreDerivationOnly`
  - `TestLegacyKeyStaysReadableAndIsAudited`
  - `TestKDFMigrationDualReadThenCutover`
  - `TestVaultReprotectKeepsTokens`
  - `TestIdentifierKeysRejectedAfterMigrationEveryMode`
  - `TestStrictModeRefusesIdentifierDerivedKeys`
  - `TestKDFHandlerRoutesAndHeader`
- **Mode coverage:** all run under FIPS modes off / on / only (`make
  test-fips-modes`, CI `fips-modes`).
- **Migration SQL:** 011 was dry-run against Postgres in a rolled-back
  transaction.
