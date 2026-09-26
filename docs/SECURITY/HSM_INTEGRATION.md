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

### Creating a key or CA when an HSM is available

With **HSM keys** on, the create-key dialog opens with an alert naming the
HSM (manufacturer, model, token, serial). **Create in HSM** is already
checked when the algorithm can live in the HSM. If the operator unchecks it,
or picks an algorithm the HSM can't hold, the alert says the key will be
created in the KMS instead. With only the tenant key on, the dialog says the
material will be encrypted by the tenant's HSM key.

The CA dialog in the Certificates tab does the same. The key storage option
**In the tenant's HSM** makes the CA key an HSM-resident keycore key
(ECDSA P-256/P-384). Every certificate, CRL and OCSP response is signed in
the HSM, certs → keycore (prehashed sign) → HSM, and certs stores no private
key for it. RSA can't be an HSM CA key: the HSM signs RSA only with PSS, and
OCSP responses (`x/crypto/ocsp`) can't be PSS-signed.

The old key storage option labelled "HSM-backed (external HSM - FIPS
boundary)" (`key_backend: keycore`) actually signed certificates with a
software key in certs and only added a keycore side signature. It has been
removed from the dialog. CAs created with it are labelled "Software key,
keycore co-signed", and `key_backend: "hsm"` is no longer folded into it.

## One HSM per tenant

A tenant (domain) has **one** HSM profile: one library and one slot or
token. That is where its tenant key and all its HSM keys are generated, so
there is never a choice to make at key creation. For availability, use the
vendor's own HA behind that one profile (Luna HA group, a Primus cluster,
CloudHSM cluster). The library presents it as one slot, and the objects are
replicated by the HSM. Different tenants can use different HSMs, even from
different vendors.

- **Recorded device.** Each HSM key records the device it was generated on
  (manufacturer, model, serial, token label) in its labels. `audit.key.create`
  carries them too.
- **Profile changes.** If the tenant's profile is later pointed at another
  device, operations on keys whose objects aren't there are refused with
  `409 hsm_key_not_found`, naming the device the key was created on. They
  are never silently re-created.
- **Rotation onto another device.** A rotation that lands on a different
  serial emits `audit.key.hsm_device_changed`.

## Proving a key is in the HSM

**Verify in HSM** (key details) calls `GET /keys/{id}/hsm`. Keycore reads
every version's objects back from the HSM (`C_GetAttributeValue`; never
`CKA_VALUE` of a key) and shows:

- the label and ID;
- `CKA_LOCAL`: generated on the token;
- `CKA_SENSITIVE`, `CKA_EXTRACTABLE=false`, `CKA_ALWAYS_SENSITIVE`,
  `CKA_NEVER_EXTRACTABLE`;
- the usages, key type and size;
- whether the HSM configured now is the device the key was created on.

For a key under the tenant key, it shows the tenant key's object.
`TestGeneratedKeysHaveHSMAttributes` asserts all of this for AES, RSA and EC
keys, as SoftHSM2 reports it.

## Keys and certificates already in the partition

The Keys and Certificates tabs have **Show HSM partition**.
`GET /hsm/objects` lists every key and certificate the tenant's HSM login
can see: type, size or curve, generated-on-token, sensitive and
extractable, and for certificates the subject, issuer, serial and expiry.
Objects the KMS created for the tenant are linked to their KMS key; the rest
are marked "found in HSM". Other tenants' KMS objects on a shared partition
are left out. The listing is read-only: objects found in the HSM can't yet
be used through the KMS (see "Not yet validated or not covered").

## HSM activity

Every connector call and every keycore HSM decision is audited (table
below). The HSM tab's **HSM activity** panel lists them from the audit log.
It queries `GET /audit/events` with `action_prefix=audit.hsm.` and
`action_prefix=audit.key.hsm_`, and the Audit Log tab can filter on service
`hsm`.

## Governance backups

An HSM-bound backup has its backup key wrapped with AES-256-GCM inside the
tenant's HSM, under the same tenant key. See
[BACKUP_KEYS.md](BACKUP_KEYS.md). The `BACKUP_HSM_WRAP_SECRET` derivation is
gone.

## Audit events

| Event | When |
|---|---|
| `audit.hsm.<action>` (connector kernel): `key_generated` (with the HSM serial and token), `tenant_key_ensured`, `encrypt`, `decrypt`, `sign`, `verify`, `key_destroyed`, `key_inspected`, `objects_listed`, `status_read` | Every connector request. Refusals carry `result: refused` and a `reason`: `unauthenticated`, `permission_denied`, `tenant_mismatch`, `caller_not_allowed`, `foreign_label`, `hsm_not_configured`, `library_not_allowed`, `pin_not_provided`, `integrity_check_failed`, `tenant_key_protected`, `algorithm_not_supported` |
| `audit.key.hsm_settings_updated` | A tenant's switches changed (before and after values) |
| `audit.key.hsm_refused` | Keycore refused an HSM operation (`reason`: `hsm_key_not_found`, `hsm_keys_disabled`, `hsm_not_configured`, `hsm_not_connected`, `hsm_unavailable`, `algorithm_not_supported`, `hsm_import_not_supported`, `iv_mode_not_supported`, `material_in_hsm`) |
| `audit.key.hsm_objects_destroyed` / `audit.key.hsm_destroy_failed` | A destroyed key's HSM objects were removed, or some couldn't be |
| `audit.key.hsm_status_read`, `audit.key.hsm_settings_update`, `audit.key.hsm_objects_listed`, `audit.key.hsm_key_inspected` | Kernel events for keycore's HSM routes |
| `audit.hsm.key_inspected`, `audit.hsm.objects_listed` | The connector read a key's attributes, or listed the partition |
| `audit.key.hsm_device_changed` | A rotated version was generated on a different HSM serial than the key's first |
| `audit.cert.crl_generation_failed` | A CRL couldn't be signed (for example, the HSM was unreachable). No CRL is published: this used to emit a JSON note wrapped in `X509 CRL` PEM |
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
  - `TestGeneratedKeysHaveHSMAttributes`: label, ID, `CKA_LOCAL`,
    sensitive, never extractable and usages, read back from the HSM.
  - `TestPartitionListing`: a key and a certificate created outside the KMS
    are listed; another tenant's KMS key is not.
- **Keycore** against a real connector (`pkg/hsmconnector/softhsmtest`):
  `TestHSMResidentKeyLifecycle`, `TestHSMResidentSigningKeys`,
  `TestTenantHSMKeyProtectsNewKeys`, `TestHSMSettingsNeedAConfiguredHSM`,
  `TestHSMRoutesRefusalsAudited`, `TestHSMKeyProvenance` (recorded device,
  verify, partition links, prehashed signing, the missing-object refusal),
  and `TestHSMStoragePostgres` (real Postgres).
- **Certs:** `TestHSMCAKeysSignInTheHSM`: an HSM root (P-384) and
  intermediate (P-256); a leaf verified through the chain; the CRL and OCSP
  response signed in the HSM; RSA and no-keycore refused.
- **Audit:** `TestQueryEventsByActionPrefix` (`_` is literal).
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
  import of outside material into the HSM (the owner accepts this, FIPS mode
  included).
- **Objects already in the partition are listed, not used.** Using a key the
  KMS didn't create would need an explicit "adopt" step. It would have to
  bind the object to one tenant, because its label doesn't carry the
  tenant, and that step doesn't exist yet.
- **HSM CA keys are ECDSA only** (see above).
- **Traffic between services.** With the tenant key on, the data key crosses
  the internal network from connector to keycore on each use, like every
  internal call today. The HSM PIN sits in the connector's environment or
  file.
