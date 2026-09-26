# HSM integration (PKCS#11)

**Standing rules.**
- The KMS talks to a customer HSM only through the vendor's own PKCS#11
  library, loaded by one service, `hsm-connector`. Nothing is simulated:
  there is no "Vecta HSM" and no software stand-in. (The unused
  `software-vault` service moved to the KMSExtension repo as a seed.)
- Every HSM object the KMS creates is labelled `vecta:<tenant>:...`, and the
  connector refuses a label outside the caller's tenant.
- Only the `kms-keycore` and `kms-governance` identities may use HSM keys.
  Every operation and refusal is audited.

## Architecture

```
dashboard ──► keycore ──┐                    ┌──► vendor PKCS#11 library ──► HSM
                        ├─► hsm-connector ───┤    (Securosys Primus, Thales Luna,
dashboard ──► governance┘   (cgo, glibc)     │     Entrust nShield, Utimaco,
                                             │     AWS CloudHSM, ...)
                           reads the tenant's HSM profile (auth_hsm_provider_configs)
```

- **hsm-connector** (`services/hsm-connector`, core in `pkg/hsmconnector`)
  is built with cgo on Debian, because vendor PKCS#11 libraries are glibc
  builds. Keycore stays a static, cgo-free binary. The connector is the only
  process that loads a library and holds a PIN. A crashing vendor library
  takes down the connector, not keycore.
- **Tenant profile.** The tenant administrator saves it in the HSM tab: the
  library path, a slot ID or token label, and the name of the PIN variable.
  The connector reads it and never writes the database.
- **Library confinement.** A library is native code loaded into the
  connector, so it may only come from `HSM_LIBRARY_ROOTS`. By default that is
  the provider workspace `/var/lib/vecta/hsm/providers`, which the
  `hsm-integration` container writes and the connector mounts read-only.
  Paths are resolved through symlinks before the check.
- **PIN.** The PIN is in the connector's environment under the profile's
  `pin_env_var` (upper case, containing `PIN`, e.g. `SECUROSYS_HSM_PIN`), or
  in the file named by `<var>_FILE`. Operators put it in
  `hsm-connector.env`. The PIN is never stored in the database or sent to
  the dashboard.
- **Sessions.** Each library is initialised once. Per slot, one session
  stays open after `C_Login` (a token logs out when its last session
  closes). Each request opens its own short session.

## The two switches (HSM tab → KMS integration, per tenant)

Both switches need a configured, connected HSM. Keycore asks the connector
for status before accepting either.

### 1. Tenant key in HSM (applies to new keys only)

- On first use, the connector generates `vecta:<tenant>:tenant-key`, an
  AES-256 key inside the HSM (`CKA_SENSITIVE`, not extractable, no
  wrap/unwrap).
- Each **new** key version gets a fresh 256-bit data key. Keycore encrypts
  the material with it (AES-256-GCM, AAD = tenant | key | version ID). The
  HSM then encrypts that data key with the tenant key (`CKM_AES_GCM`, the IV
  from the HSM's `C_GenerateRandom`, the same AAD).
- The version is stored with `protection = tenant_hsm` and the tenant key's
  label. Every use of the material has the HSM decrypt the data key first,
  so with the HSM unreachable those keys stop working.
- Key versions created before the switch keep `protection = mek`: the owner
  chose "new keys only" (2026-09-26). Turning the switch off affects only
  keys created afterwards.
- The key API refuses to destroy the tenant key
  (`409 tenant_key_protected`): that would crypto-shred every key it
  protects.

### 2. HSM keys (per key: "Create in HSM")

When this is on, the create-key form offers **Create in HSM**, and the API
takes `"hsm": true` on `POST /keys`.

| Algorithm | Generated with | Operations in the HSM |
|---|---|---|
| AES-128/192/256 | `CKM_AES_KEY_GEN` | encrypt/decrypt, `CKM_AES_GCM`, 96-bit IV from the HSM, 128-bit tag |
| RSA-2048/3072/4096 | `CKM_RSA_PKCS_KEY_PAIR_GEN` (e = 65537) | sign/verify, `CKM_RSA_PKCS_PSS` (SHA-256/384/512, MGF1, salt = hash length) |
| ECDSA P-256 / P-384 | `CKM_EC_KEY_PAIR_GEN` | sign/verify, `CKM_ECDSA` (keycore hashes; the signature is returned as ASN.1 DER) |

- **Key objects.** Keys are token objects with `CKA_SENSITIVE=true` and
  `CKA_EXTRACTABLE=false`. The label is `vecta:<tenant>:key:<key_id>:v<n>`.
  Keycore stores the public key (asymmetric) and a KCV, and holds **no
  material** (`protection = hsm_resident`).
- **KCV.** For AES, the KCV is E(K, 0¹²⁸)[:3], computed in the HSM. It is
  left empty if the HSM refuses ECB. For asymmetric keys it is
  SHA-256(SPKI)[:3].
- **Rotation** generates the next version in the HSM.
- **Destroy** (immediate or scheduled) destroys every version's objects in
  the HSM. If the HSM can't be reached, `audit.key.hsm_destroy_failed`
  (critical) lists the labels left behind.
- **Refused operations.** Anything that needs the material is refused with
  `409 hsm_operation_unsupported` and audited: export, wrap, derive, MAC,
  KEM and material verification. Also refused: an external or deterministic
  IV (`iv_mode_not_supported`), importing outside material into the HSM
  (`hsm_import_not_supported`), and other algorithms
  (`algorithm_not_supported`).

## Governance backups

An HSM-bound backup has its backup key wrapped with AES-256-GCM inside the
tenant's HSM, under the same tenant key. See
[BACKUP_KEYS.md](BACKUP_KEYS.md). The `BACKUP_HSM_WRAP_SECRET` derivation is
gone.

## Audit events

| Event | When |
|---|---|
| `audit.hsm.<action>` (connector kernel): `key_generated`, `tenant_key_ensured`, `encrypt`, `decrypt`, `sign`, `verify`, `key_destroyed`, `status_read` | Every connector request. Refusals carry `result: refused` and a `reason`: `unauthenticated`, `permission_denied`, `tenant_mismatch`, `caller_not_allowed`, `foreign_label`, `hsm_not_configured`, `library_not_allowed`, `pin_not_provided`, `integrity_check_failed`, `tenant_key_protected`, `algorithm_not_supported` |
| `audit.key.hsm_settings_updated` | A tenant's switches changed (before and after values) |
| `audit.key.hsm_refused` | Keycore refused an HSM operation (`reason`: `hsm_keys_disabled`, `hsm_not_configured`, `hsm_not_connected`, `hsm_unavailable`, `algorithm_not_supported`, `hsm_import_not_supported`, `iv_mode_not_supported`, `material_in_hsm`) |
| `audit.key.hsm_objects_destroyed` / `audit.key.hsm_destroy_failed` | A destroyed key's HSM objects were removed, or some couldn't be |
| `audit.key.hsm_status_read`, `audit.key.hsm_settings_update` | Kernel events for keycore's `GET` and `PUT /hsm/settings` |
| `audit.key.create` | Carries `hsm: true`, `hsm_label` and `algorithm` for an HSM key |

## FIPS 140-3

Operations on HSM keys run in **the HSM's** cryptographic module, not the Go
module. The mechanisms are all on the approved list (AES-GCM, RSA-PSS,
ECDSA P-256/P-384, SHA-2), and they behave the same in `on`, `only` and
`off`. The KMS doesn't claim the HSM is validated: the status shows only
what the library reports (manufacturer, model, firmware). Its validation
certificate is the customer's to check. Keycore still runs the tenant-key
envelope (AES-256-GCM on the material) in the Go module.

## Clustering

The connector runs on every node and writes nothing replicated
(`pkg/clusterroute.NeverForward`). Key creation is forwarded to the primary,
so the primary's connector creates objects. Members use them for
operations. Every node needs the same library, profile and PIN, and must
reach the same HSM. With a network HSM (Primus, Luna, CloudHSM) that's the
normal setup. A node-local HSM would not see objects made on the primary.

## Tests

- **SoftHSM2** (a real PKCS#11 library; CI installs it). Tests of the
  connector (`pkg/hsmconnector`):
  - `TestAESKeyLivesInHSMAndEncrypts`: GCM round trip, tamper and AAD
    refusal, value not readable (`C_GetAttributeValue` on `CKA_VALUE`
    fails), destroy.
  - `TestSignVerifyInHSM`: RSA-PSS and ECDSA signatures verified by Go's
    own implementation against the exported public key.
  - `TestTenantIsolationAndCallers` and `TestTenantKey`.
  - `TestLibraryAndPINAreConfined` and `routetest.RefusalsAudited`.
- **Keycore** against a real connector (`pkg/hsmconnector/softhsmtest`):
  `TestHSMResidentKeyLifecycle`, `TestHSMResidentSigningKeys`,
  `TestTenantHSMKeyProtectsNewKeys`, `TestHSMSettingsNeedAConfiguredHSM`,
  `TestHSMRoutesRefusalsAudited`, and `TestHSMStoragePostgres` (real
  Postgres).
- **Governance:** `TestHSMBoundBackupKeyWrappedByHSM`,
  `TestRetiredHSMBoundFormatsAreRefused`, `TestHSMBoundBackupPostgres`.
- All of it runs in FIPS modes off, on and only.

## Not yet validated or not covered

- **Tested only against SoftHSM2.** Vendor HSMs (Securosys Primus, Thales
  Luna, Entrust nShield, Utimaco, AWS CloudHSM) have not been tested from
  this repository. Their libraries implement the same PKCS#11 calls, but
  vendor quirks (GCM IV handling, error codes, required attributes) must be
  checked on the customer's HSM with **Test connection** and a test key
  before production. Three known variations are handled:
  - an HSM that substitutes its own GCM IV (the IV actually used is
    returned);
  - GCM tag failure reported as `CKR_GENERAL_ERROR`, `CKR_FUNCTION_FAILED`,
    `CKR_ENCRYPTED_DATA_INVALID` or `CKR_AEAD_DECRYPT_FAILED`;
  - an HSM that refuses ECB (the AES KCV is left empty).
- **Algorithms not in the HSM:** RSA encryption, Ed25519, ML-DSA/ML-KEM,
  HMAC and non-GCM AES modes can't be HSM-resident.
- **No existing-key migration** into the tenant key (new keys only), and no
  import of outside material into the HSM.
- **Traffic between services.** With the tenant key on, the data key crosses
  the internal network from connector to keycore on each use, like every
  internal call today. The HSM PIN sits in the connector's environment or
  file.
