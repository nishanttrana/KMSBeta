# Key Management

> **Version:** Beta — Last updated 2026-03-22
> **Audience:** Application Developers, Security Engineers, Platform Engineers, Compliance Officers

---

## Table of Contents

1. [Overview](#1-overview)
2. [Key Algorithms Reference Table](#2-key-algorithms-reference-table)
3. [Key Lifecycle States](#3-key-lifecycle-states)
4. [Key Versioning](#4-key-versioning)
5. [Creating Keys](#5-creating-keys)
6. [Importing Existing Keys](#6-importing-existing-keys)
7. [Cryptographic Operations](#7-cryptographic-operations)
8. [Key Rotation](#8-key-rotation)
9. [Key Access Policy](#9-key-access-policy)
10. [Key Tags and Labels](#10-key-tags-and-labels)
11. [Rate Limiting](#11-rate-limiting)
12. [Export Policy](#12-export-policy)
13. [HSM-Backed Keys](#13-hsm-backed-keys)
14. [Security Considerations](#14-security-considerations)
15. [Use Cases](#15-use-cases)
16. [API Reference](#16-api-reference)

---

## 1. Overview

### 1.1 What Are Keys?

A **cryptographic key** is a piece of data that controls a cryptographic algorithm. Keys determine the output of encryption (making data unreadable without the key), signing (producing unforgeable attestations of data origin), and key derivation (producing child keys from a parent). Without the key, properly encrypted data is computationally infeasible to recover.

Vecta KMS is the **authoritative system of record** for all cryptographic keys in your organization. Instead of applications generating and storing their own keys in config files, environment variables, or databases, Vecta KMS:

- Generates keys using validated, properly seeded cryptographic sources
- Stores keys encrypted at rest using a key-encrypting-key (KEK) hierarchy
- Enforces lifecycle rules (activation, expiry, rotation, destruction)
- Logs every key operation to a tamper-evident audit chain
- Controls access via fine-grained grants, not broad API permissions
- Separates key ownership (who can manage the key) from key usage (who can encrypt/decrypt with it)

### 1.2 Why Centralized Key Management Matters

Decentralized key management — the default in most organizations — creates serious operational and security problems:

| Problem | Impact | Vecta KMS Solution |
|---|---|---|
| Keys in environment variables or config files | Any process or developer can read the key | Keys never leave the KMS; apps get ciphertext/plaintext, not key material |
| No rotation schedule | Old, potentially compromised keys used indefinitely | Automated rotation schedules, event-driven rotation APIs |
| No audit trail | Cannot prove who used a key when | Every operation logged in tamper-evident audit chain |
| Siloed key inventories | Cannot find all keys during incident response | Centralized inventory across all tenants and environments |
| Inconsistent algorithm choices | Weak algorithms in use without detection | Algorithm policy enforcement; FIPS mode blocks unapproved algorithms |
| Manual destruction | Keys never actually destroyed | Cryptographically guaranteed destruction with audit proof |

### 1.3 NIST SP 800-57 Key Types

Vecta KMS supports all key types defined in NIST SP 800-57 Part 1 Rev. 5:

| NIST Key Type | Description | Vecta KMS Purpose Value |
|---|---|---|
| Data Encryption Key (DEK) | Encrypts application data | `encrypt` |
| Key Encrypting Key (KEK) | Wraps other keys | `wrap` |
| Message Authentication Code Key | Produces MACs/HMACs | `mac` |
| Authentication Key | Used for entity authentication | `authenticate` |
| Private Signature Key | Signs data; kept secret | `sign` |
| Public Signature Verification Key | Verifies signatures; public | `sign` (public half) |
| Symmetric Content Encryption Key | Encrypts bulk data | `encrypt` |
| Key Agreement Key | Used in DH/ECDH protocols | `derive` |
| Key Transport Key | Wraps keys for transport | `wrap` |
| Key Derivation Key | Derives child keys via KDF | `derive` |
| Random Number Generation Key | Seeds DRBG | Internal — not directly exposed |
| Post-Quantum KEM Key | Quantum-safe key encapsulation | `kem` |

---

## 2. Key Algorithms Reference Table

The following table covers all algorithms supported by Vecta KMS. The **FIPS Approved** column reflects FIPS 140-3 validation status. The **Post-Quantum** column marks algorithms providing security against quantum adversaries.

### 2.1 Symmetric Algorithms

| Algorithm | Type | Key Size | Purpose(s) | FIPS 140-3 | Post-Quantum | Recommended Use Case |
|---|---|---|---|---|---|---|
| `AES-128` | Symmetric block cipher | 128-bit | encrypt, wrap | Yes | No (128-bit symmetric is considered borderline) | Legacy systems requiring AES-128; prefer AES-256 for new deployments |
| `AES-192` | Symmetric block cipher | 192-bit | encrypt, wrap | Yes | No | Rarely used; AES-256 preferred |
| `AES-256` | Symmetric block cipher | 256-bit | encrypt, wrap | Yes | Yes (256-bit symmetric provides ~128-bit post-quantum security) | **Default choice** for data encryption and key wrapping |
| `HMAC-SHA256` | Symmetric MAC | 256-bit | mac, authenticate | Yes | No | Message authentication, API request signing (symmetric), token validation |
| `HMAC-SHA384` | Symmetric MAC | 384-bit | mac, authenticate | Yes | No | Higher-assurance MACs; TLS 1.3 PRF |
| `HMAC-SHA512` | Symmetric MAC | 512-bit | mac, authenticate | Yes | No | Highest-assurance MACs; HKDF extract step |
| `ChaCha20` | Stream cipher | 256-bit | encrypt | No | No | Fast encryption on platforms without AES hardware acceleration |
| `ChaCha20-Poly1305` | AEAD stream cipher | 256-bit | encrypt | No | No | Fast AEAD on mobile/embedded without AES-NI; not for FIPS environments |

### 2.2 Asymmetric Algorithms

| Algorithm | Type | Key Size | Purpose(s) | FIPS 140-3 | Post-Quantum | Recommended Use Case |
|---|---|---|---|---|---|---|
| `RSA-2048` | Asymmetric RSA | 2048-bit | sign, wrap | Yes | No | **Legacy only** — minimum size for new keys; prefer RSA-3072+ or EC |
| `RSA-3072` | Asymmetric RSA | 3072-bit | sign, wrap | Yes | No | RSA signing where EC cannot be used; roughly equivalent to AES-128 |
| `RSA-4096` | Asymmetric RSA | 4096-bit | sign, wrap | Yes | No | Highest-assurance RSA; use for long-lived root CAs; slow |
| `EC-P256` | Asymmetric EC | 256-bit (P-256 curve) | sign, derive | Yes | No | General-purpose EC signing and ECDH; widely compatible |
| `EC-P384` | Asymmetric EC | 384-bit (P-384 curve) | sign, derive | Yes | No | **Recommended** for new EC keys; required for NSA Suite B Top Secret |
| `EC-P521` | Asymmetric EC | 521-bit (P-521 curve) | sign, derive | Yes | No | Highest-assurance EC; use for long-lived CA keys |
| `Ed25519` | Asymmetric EdDSA | 255-bit (Curve25519) | sign | No (not yet) | No | Fast, modern signing; no hash-and-sign weakness; widely adopted |
| `Ed448` | Asymmetric EdDSA | 448-bit (Curve448) | sign | No (not yet) | No | Higher-security EdDSA; less common than Ed25519 |
| `X25519` | Asymmetric ECDH | 255-bit (Curve25519) | derive | No (not yet) | No | Modern key agreement; TLS 1.3 key exchange |
| `X448` | Asymmetric ECDH | 448-bit (Curve448) | derive | No (not yet) | No | Higher-security ECDH key agreement |

### 2.3 Post-Quantum Algorithms (NIST PQC Standards)

| Algorithm | Type | Key Size (public/private) | Purpose(s) | FIPS Standard | Security Level | Recommended Use Case |
|---|---|---|---|---|---|---|
| `ML-KEM-512` | Lattice-based KEM | 800 / 1632 bytes | kem | FIPS 203 | Level 1 (~AES-128) | Post-quantum key encapsulation; fastest; hybrid TLS |
| `ML-KEM-768` | Lattice-based KEM | 1184 / 2400 bytes | kem | FIPS 203 | Level 3 (~AES-192) | **Recommended** ML-KEM level; balanced performance/security |
| `ML-KEM-1024` | Lattice-based KEM | 1568 / 3168 bytes | kem | FIPS 203 | Level 5 (~AES-256) | Highest-security KEM; use for long-term key exchange |
| `ML-DSA-44` | Lattice-based signature | 1312 / 2528 bytes | sign | FIPS 204 | Level 2 (~AES-128) | Post-quantum signing; smaller signatures |
| `ML-DSA-65` | Lattice-based signature | 1952 / 4000 bytes | sign | FIPS 204 | Level 3 (~AES-192) | **Recommended** ML-DSA level; balanced |
| `ML-DSA-87` | Lattice-based signature | 2592 / 4864 bytes | sign | FIPS 204 | Level 5 (~AES-256) | Highest-security PQC signing |
| `SLH-DSA-SHA2-128s` | Hash-based signature | 32 / 64 bytes | sign | FIPS 205 | Level 1 | Stateless hash-based; small keys; slow signing; long-lived use |
| `SLH-DSA-SHAKE-128s` | Hash-based signature | 32 / 64 bytes | sign | FIPS 205 | Level 1 | SHAKE-based variant; same security as SHA2 variant |
| `SLH-DSA-SHA2-192s` | Hash-based signature | 48 / 96 bytes | sign | FIPS 205 | Level 3 | Higher-security hash-based signing |
| `SLH-DSA-SHA2-256s` | Hash-based signature | 64 / 128 bytes | sign | FIPS 205 | Level 5 | Highest-security stateless hash-based signing |

### 2.4 Algorithm Selection Guidance

```
New application data encryption?
  → AES-256 (symmetric) or ML-KEM-768 (post-quantum hybrid)

Signing API requests or documents?
  → Ed25519 (fast, modern) or EC-P384 (FIPS environments)

Post-quantum migration (key exchange)?
  → ML-KEM-768 in hybrid with X25519

Post-quantum migration (signatures)?
  → ML-DSA-65 or SLH-DSA-SHA2-128s

Certificate authority key?
  → EC-P384 (root: EC-P521) or RSA-4096

Code signing (must support air-gapped verification)?
  → Ed25519 or EC-P256 (wide tooling support)

Payment / PCI-DSS environment (FIPS required)?
  → AES-256, HMAC-SHA256, EC-P384, RSA-3072+

Long-term archive encryption (20+ years)?
  → AES-256 + ML-KEM-1024 hybrid
```

---

## 3. Key Lifecycle States

### 3.1 State Diagram

```
                    ┌──────────────┐
                    │   PreActive  │
                    │              │
                    │ Created but  │
                    │ not yet usable│
                    └──────┬───────┘
                           │ activate
                           │ (automatic on activation_date,
                           │  or manual API call)
                           ▼
  ┌──────────┐    ┌──────────────┐    ┌─────────────────┐
  │ Suspended│◄───│    Active    │───►│   Deactivated   │
  │          │    │              │    │                 │
  │ Temporarily    │ Normal       │    │ Past expiry;    │
  │ disabled │    │ operational  │    │ decrypt only    │
  └────┬─────┘    └──────┬───────┘    └────────┬────────┘
       │ reinstate        │                     │
       │ ◄────────────────┘ compromise          │ compromise
       │                  │                     │
       │                  ▼                     ▼
       │           ┌──────────────┐    ┌─────────────────┐
       │           │  Compromised │    │   Compromised   │
       │           │              │    │  (from Deact.)  │
       │           │ Key material │    │                 │
       │           │ may be known │    │                 │
       │           └──────┬───────┘    └────────┬────────┘
       │                  │ destroy              │ destroy
       │                  ▼                     ▼
       │           ┌──────────────────────────────────────┐
       └──────────►│              Destroyed               │
          destroy  │                                      │
                   │  Key material cryptographically       │
                   │  erased. Metadata retained.          │
                   └──────────────────────────────────────┘
```

### 3.2 State Definitions and Allowed Operations

| State | Description | Allowed Operations | Prohibited Operations |
|---|---|---|---|
| **PreActive** | Key created but not yet in service. Activation date in future, or manually held. | Get key metadata, set policy, rotate (creates new version in PreActive) | encrypt, decrypt, sign, verify, wrap, unwrap, derive, export |
| **Active** | Normal operational state. All configured operations permitted. | All operations the key's purpose allows (encrypt, decrypt, sign, verify, wrap, unwrap, derive, kem, mac) | None (subject to access policy) |
| **Suspended** | Temporarily disabled. No crypto operations. Can be reinstated to Active. | Get key metadata | All crypto operations |
| **Deactivated** | Past expiry or manually deactivated. Decrypt/verify still allowed for data decryption; new encryptions blocked. | decrypt, verify, unwrap (for decryption of old data) | encrypt, sign, wrap, derive (new operations) |
| **Compromised** | Key material may be known to unauthorized parties. Strictly limited. | decrypt (if absolutely required for data recovery), get metadata | encrypt, sign, wrap, derive |
| **Destroyed** | Key material cryptographically erased. Cannot be recovered. | Get metadata (tombstone) | All crypto operations |

### 3.3 State Transition API

```bash
# Activate a PreActive key
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/activate?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN"

# Deactivate an Active key
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/deactivate?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN"

# Mark key as Compromised (triggers governance alert)
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/compromise?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Key material found in leaked repository",
    "incident_id": "INC-2026-0042"
  }'

# Destroy a key
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/destroy?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "confirm_name": "my-first-key",
    "reason": "End of retention period"
  }'
```

### 3.4 NIST SP 800-57 Alignment

Vecta KMS lifecycle states map directly to NIST SP 800-57 Part 1 Rev. 5 Section 5.3:

| NIST State | Vecta KMS State | Notes |
|---|---|---|
| Pre-activation | PreActive | |
| Active | Active | |
| Suspended | Suspended | NIST calls this "on hold" |
| Deactivated | Deactivated | |
| Compromised | Compromised | |
| Destroyed | Destroyed | |
| Destroyed Compromised | Compromised → Destroyed | Vecta tracks the compromise reason even after destruction |

---

## 4. Key Versioning

### 4.1 How Versions Work

Every key in Vecta KMS has a **version counter** starting at 1. Each rotation increments the version. The current version is always used for new cryptographic operations (encrypt, sign, wrap). Older versions are retained for decryption of existing ciphertext.

```
Key: "payments-dek"
│
├── Version 1 (created 2025-01-01, rotated out 2025-07-01) → status: Deactivated
├── Version 2 (created 2025-07-01, rotated out 2026-01-01) → status: Deactivated
└── Version 3 (created 2026-01-01, current)               → status: Active
```

When you call `encrypt`, the response includes `"key_version": 3`. Store this version number alongside the ciphertext. When you later call `decrypt`, pass the same `key_version: 3` to ensure the correct version's key material is used.

If you do not specify `key_version` in a decrypt call, Vecta KMS attempts decryption with the current active version. If you have old ciphertext from version 1, you must specify `key_version: 1`.

### 4.2 Version Retention

Version retention is controlled by the `old_version_action` field in the rotation request:

| `old_version_action` | Effect |
|---|---|
| `retain` | Old version stays Active; both versions can decrypt and encrypt |
| `deactivate` | Old version moves to Deactivated; can still decrypt, but not encrypt |
| `destroy` | Old version immediately destroyed; old ciphertext irrecoverable |

Recommended policy: use `deactivate` during normal rotation to allow data re-encryption, then `destroy` once all data has been re-encrypted.

### 4.3 Version-Specific Operations

```bash
# Decrypt with a specific key version
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/decrypt?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext_b64": "...",
    "iv_b64": "...",
    "tag_b64": "...",
    "key_version": 2
  }'

# List all versions of a key
curl "http://localhost:5173/svc/keycore/keys/{KEY_ID}/versions?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN"

# Response:
{
  "versions": [
    {
      "version": 1,
      "status": "deactivated",
      "created_at": "2025-01-01T00:00:00Z",
      "deactivated_at": "2025-07-01T00:00:00Z",
      "kcv": "A3F2E1"
    },
    {
      "version": 2,
      "status": "deactivated",
      "created_at": "2025-07-01T00:00:00Z",
      "deactivated_at": "2026-01-01T00:00:00Z",
      "kcv": "B7C4D9"
    },
    {
      "version": 3,
      "status": "active",
      "created_at": "2026-01-01T00:00:00Z",
      "deactivated_at": null,
      "kcv": "E2F8A1"
    }
  ],
  "current_version": 3
}
```

### 4.4 Key Check Value (KCV)

A **Key Check Value (KCV)** is a short fingerprint derived from symmetric key material. Vecta KMS computes KCV as the first 3 bytes (6 hex characters) of AES-ECB encryption of a zero block under the key.

KCVs are used to:
- Verify that a key import succeeded without error
- Confirm that two parties hold the same key material (compare KCVs out-of-band)
- Satisfy PCI-DSS key verification requirements

KCVs are returned in key creation, import, and rotation responses. They are safe to log (3 bytes do not reveal the 32-byte key).

---

## 5. Creating Keys

### 5.1 Via Dashboard — Step by Step

1. Navigate to **CORE → Keys** in the left sidebar.
2. Click the **Create Key** button (top right, blue).
3. Complete the **Key Details** form:

   **Name** (required)
   - Human-readable identifier for the key.
   - Maximum 255 characters.
   - No leading or trailing spaces.
   - Allowed characters: letters, digits, hyphens, underscores, periods.
   - Convention: `{app}-{environment}-{purpose}` (e.g., `payments-prod-dek`, `api-gateway-staging-signing-key`).

   **Algorithm** (required)
   - Select from dropdown. Groups: Symmetric, RSA, Elliptic Curve, EdDSA, Post-Quantum.
   - Selecting an algorithm auto-populates the **Purpose** field with compatible values.

   **Purpose** (required)
   - `encrypt` — Key used for symmetric or asymmetric encryption/decryption.
   - `sign` — Key used for digital signatures and verification.
   - `wrap` — Key used to wrap (encrypt) other keys.
   - `derive` — Key used as input to a KDF to produce child keys.
   - `mac` — Key used for HMAC / MAC computation.
   - `kem` — Key used for key encapsulation mechanisms (ML-KEM).
   - `authenticate` — Key used for authentication (HMAC-based session tokens).

   **Key Backend** (required)
   - `software` — Key generated and stored in software (encrypted at rest using platform KEK).
   - `hsm` — Key generated and stored inside HSM hardware. Never exposed in software memory.

4. Expand **Lifecycle Settings** (optional):
   - **Activation Date:** ISO-8601 date/time. Key is created in `PreActive` state and automatically transitions to `Active` at this time.
   - **Expiry Date:** Key automatically transitions to `Deactivated` at this time.
   - **Destruction Date:** Key is automatically destroyed at this time (requires governance approval if configured).

5. Expand **Labels** (optional):
   - Click **Add Label** to add key-value pairs.
   - Example: `env=production`, `team=platform`, `data-class=confidential`.

6. Expand **Tags** (optional):
   - Click **Add Tag** to add string tags.
   - Example: `pci-scope`, `critical`, `high-availability`.

7. Expand **Access Policy** (optional):
   - Toggle **Deny by Default** ON for production keys.
   - Click **Add Grant** to configure initial access grants.

8. Click **Create Key**.
9. The key detail page opens. Note the **Key ID** — you will need it for API calls.

### 5.2 Via API — Full Field Reference

```bash
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "payments-prod-dek",
    "algorithm": "AES-256",
    "purpose": "encrypt",
    "key_backend": "hsm",
    "export_allowed": false,
    "iv_mode": "auto",
    "activation_date": "2026-04-01T00:00:00Z",
    "expires_at": "2027-04-01T00:00:00Z",
    "destroy_date": "2028-04-01T00:00:00Z",
    "labels": {
      "env": "production",
      "team": "payments",
      "data-class": "pci",
      "app": "payment-gateway"
    },
    "tags": ["pci-scope", "critical", "hsm-backed"],
    "ops_limit": 1000000,
    "ops_limit_window": "day",
    "access_policy": {
      "deny_by_default": true,
      "require_approval_for_policy_change": true,
      "grants": [
        {
          "subject": "svc-payment-gateway",
          "subject_type": "user",
          "operations": ["encrypt", "decrypt"],
          "expires_at": "2027-04-01T00:00:00Z"
        }
      ]
    }
  }'
```

### 5.3 Field-by-Field Documentation

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | Yes | — | Human-readable key name. Max 255 chars. No leading/trailing spaces. Must be unique within tenant. |
| `algorithm` | string | Yes | — | Cryptographic algorithm. See Section 2 for all valid values. |
| `purpose` | string | Yes | — | Intended use: `encrypt`, `sign`, `wrap`, `derive`, `mac`, `kem`, `authenticate`. Must be compatible with the algorithm. |
| `key_backend` | string | No | `software` | Storage backend: `software` (encrypted at rest) or `hsm` (hardware-resident). |
| `export_allowed` | boolean | No | `false` | Whether key material can be exported. Strongly recommended to leave `false`. |
| `iv_mode` | string | No | `auto` | IV/nonce handling for symmetric encryption: `auto` (server generates), `caller` (caller must provide IV in encrypt request). |
| `activation_date` | string (ISO-8601) | No | null (immediately active) | Key created in `PreActive` state, auto-activates at this timestamp. |
| `expires_at` | string (ISO-8601) | No | null | Key auto-deactivates at this timestamp. |
| `destroy_date` | string (ISO-8601) | No | null | Key auto-destroyed at this timestamp. |
| `labels` | object | No | {} | Key-value metadata map. Keys: max 63 chars, lowercase alphanumeric + hyphens. Values: max 255 chars. Max 100 labels per key. |
| `tags` | array of strings | No | [] | String tags for grouping. Max 50 tags. Max 63 chars each. |
| `ops_limit` | integer | No | null (unlimited) | Maximum operations allowed per `ops_limit_window`. |
| `ops_limit_window` | string | No | `day` | Rate limit window: `hour`, `day`, `week`, `month`. |
| `ops_total` | integer | No | null (unlimited) | Lifetime operation count limit. |
| `access_policy` | object | No | default policy | Access policy configuration. See Section 9. |

### 5.4 Full Response — All Fields

```json
{
  "id": "key_01J3XVQB5M9N4KPFGHWCZ8D",
  "name": "payments-prod-dek",
  "algorithm": "AES-256",
  "purpose": "encrypt",
  "status": "preactive",
  "version": 1,
  "key_backend": "hsm",
  "export_allowed": false,
  "iv_mode": "auto",
  "tenant_id": "acme-corp",
  "labels": {
    "env": "production",
    "team": "payments",
    "data-class": "pci",
    "app": "payment-gateway"
  },
  "tags": ["pci-scope", "critical", "hsm-backed"],
  "kcv": "A3F2E1",
  "ops_limit": 1000000,
  "ops_limit_window": "day",
  "ops_total": null,
  "ops_count": 0,
  "activation_date": "2026-04-01T00:00:00Z",
  "expires_at": "2027-04-01T00:00:00Z",
  "destroy_date": "2028-04-01T00:00:00Z",
  "created_at": "2026-03-22T14:00:00Z",
  "updated_at": "2026-03-22T14:00:00Z",
  "created_by": "admin",
  "hsm_key_id": "hsm:slot0:key:a3f2e1b8c4d9",
  "public_key_pem": null
}
```

> For asymmetric keys (`RSA-*`, `EC-*`, `Ed25519`, `ML-KEM-*`, `ML-DSA-*`, etc.), `public_key_pem` contains the PEM-encoded public key. The private key never appears in any API response.

---

## 6. Importing Existing Keys

### 6.1 Why Import Keys?

You may need to import key material into Vecta KMS when:
- **Migrating from another KMS:** Bring existing DEKs into Vecta KMS without re-encrypting all data.
- **Hardware-generated keys:** A key was generated on an HSM offline and must be loaded into Vecta KMS's HSM partition.
- **Legacy application keys:** An application hard-coded a key; centralize it in Vecta KMS while maintaining backward compatibility.
- **Key ceremony keys:** A key generated during a formal key ceremony (multiple parties, audited) must be imported into the platform.
- **Cloud KMS migration:** Moving from AWS KMS to Vecta KMS — existing encrypted data needs the original key material.

> **Security consideration:** Importing key material means the key existed outside of Vecta KMS at some point. The import history is logged. For highest assurance, prefer generating keys inside Vecta KMS (or inside an HSM) rather than importing.

### 6.2 Import Formats

| Format | Description | Use Case |
|---|---|---|
| `raw` | Raw binary key material, base64-encoded | Symmetric keys (AES, HMAC) |
| `pkcs8` | PKCS#8 DER-encoded private key, base64-encoded | RSA, EC, EdDSA private keys |
| `spki` | SubjectPublicKeyInfo DER, base64-encoded | Public key import (for verify-only keys) |
| `jwk` | JSON Web Key format | Keys from JWKS-based systems |

### 6.3 Wrapping the Key Before Import (Required)

Key material **must be wrapped (encrypted) before sending** to the import API. This prevents exposure in transit (even though TLS is used — defense in depth).

Import wrapping process:

```bash
# Step 1: Get the import wrapping public key from Vecta KMS
curl "http://localhost:5173/svc/keycore/keys/import-wrapping-key?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN"

# Response:
{
  "wrapping_key_id": "wk_01J3XVQB5M9N4KPFGHWCZ8D",
  "wrapping_algorithm": "RSA-OAEP-SHA256",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki...\n-----END PUBLIC KEY-----",
  "expires_at": "2026-03-22T15:00:00Z"
}

# Step 2: Wrap your key material using the wrapping public key (offline)
# Example using openssl:
echo -n "your-32-byte-aes-key-hex" | xxd -r -p > /tmp/plainkey.bin
openssl rsautl -encrypt -oaep \
  -pubin -inkey /tmp/wrapping_public.pem \
  -in /tmp/plainkey.bin \
  -out /tmp/wrapped_key.bin
WRAPPED_KEY_B64=$(base64 -w0 /tmp/wrapped_key.bin)

# Step 3: Submit the import request
curl -X POST "http://localhost:5173/svc/keycore/keys/import?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"imported-legacy-dek\",
    \"algorithm\": \"AES-256\",
    \"purpose\": \"encrypt\",
    \"import_format\": \"raw\",
    \"wrapped_key_material_b64\": \"$WRAPPED_KEY_B64\",
    \"wrapping_key_id\": \"wk_01J3XVQB5M9N4KPFGHWCZ8D\",
    \"wrapping_algorithm\": \"RSA-OAEP-SHA256\",
    \"labels\": {\"source\": \"legacy-app\", \"env\": \"production\"}
  }"
```

### 6.4 Verifying the Import

Always verify the import immediately with a known test vector:

```bash
# Encrypt a known plaintext with the original key (before import, using your own tool)
# Store the ciphertext

# After import, decrypt with Vecta KMS
# If plaintext matches → import successful
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{NEW_KEY_ID}/decrypt?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext_b64": "<your-test-ciphertext>",
    "iv_b64": "<your-test-iv>",
    "tag_b64": "<your-test-tag>",
    "key_version": 1
  }'

# Compare the returned plaintext_b64 with your known plaintext
# Also verify the KCV in the import response matches the KCV you computed locally
```

---

## 7. Cryptographic Operations

### 7.1 Encrypt / Decrypt

#### AES-GCM (Recommended)

AES-GCM (Galois/Counter Mode) is an **authenticated encryption with associated data (AEAD)** mode. It provides both confidentiality and integrity. If anyone tampers with the ciphertext, decryption fails with an authentication error. This is the recommended mode for all new applications.

**When to use:** Any application data encryption where you want confidentiality + integrity in one operation.

**Request — Encrypt:**

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/encrypt?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext_b64": "U2Vuc2l0aXZlIHBheW1lbnQgZGF0YQ==",
    "aad_b64": "dXNlcl9pZDoxMjM0NTY=",
    "mode": "AES-GCM"
  }'
```

**Response:**

```json
{
  "ciphertext_b64": "XK9mR3pL2wQ7nB4vZ1yC8sA5jT0uE6oF",
  "iv_b64": "dGhpcyBpcyBhIG5v",
  "tag_b64": "aGVsbG8gd29ybGQh",
  "key_id": "key_01J3XVQB5M9N4KPFGHWCZ8D",
  "key_version": 3,
  "algorithm": "AES-256-GCM"
}
```

**Request — Decrypt:**

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/decrypt?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext_b64": "XK9mR3pL2wQ7nB4vZ1yC8sA5jT0uE6oF",
    "iv_b64": "dGhpcyBpcyBhIG5v",
    "tag_b64": "aGVsbG8gd29ybGQh",
    "aad_b64": "dXNlcl9pZDoxMjM0NTY=",
    "key_version": 3,
    "mode": "AES-GCM"
  }'
```

**Response:**

```json
{
  "plaintext_b64": "U2Vuc2l0aXZlIHBheW1lbnQgZGF0YQ==",
  "key_id": "key_01J3XVQB5M9N4KPFGHWCZ8D",
  "key_version": 3
}
```

**AES-GCM notes:**
- IV is 12 bytes (96 bits), auto-generated by server when `iv_mode: "auto"`.
- Authentication tag is 16 bytes (128 bits) — do not truncate.
- GCM tag verification failures return `422` with `AUTHENTICATION_FAILED` error code.
- AAD is not encrypted but is authenticated — include any context that should be bound to this ciphertext (user ID, record ID, table name, etc.).
- **Never reuse an IV with the same key.** Vecta KMS prevents this in `auto` mode by using a DRBG.

#### AES-CBC (Legacy Compatibility)

AES-CBC provides confidentiality only — no integrity check. Use only when integrating with legacy systems that cannot use GCM.

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/encrypt?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext_b64": "TGVnYWN5IGRhdGE=",
    "mode": "AES-CBC"
  }'
```

**AES-CBC notes:**
- Plaintext is PKCS#7 padded automatically.
- Response includes `iv_b64` but no `tag_b64` (no authentication tag).
- Without a MAC, you cannot detect tampering. Add a separate HMAC if integrity is required.
- Not recommended for new applications.

#### RSA-OAEP (Asymmetric Key Transport)

Use RSA-OAEP to encrypt small amounts of data (typically a DEK) for transport to a party holding the RSA private key.

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{RSA_KEY_ID}/encrypt?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext_b64": "REVLX01BVEVSSUFMX0hFUkU=",
    "mode": "RSA-OAEP-SHA256"
  }'
```

**RSA-OAEP notes:**
- Maximum plaintext size = (key_size_bytes) - 2 - (2 × hash_size_bytes). For RSA-4096 with SHA-256: 512 - 2 - 64 = 446 bytes max.
- Do not use RSA-OAEP to encrypt bulk data — use AES-GCM for the data, RSA-OAEP to wrap the AES key.

#### ChaCha20-Poly1305

Fast AEAD on platforms without AES hardware acceleration (e.g., some ARM IoT devices).

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/encrypt?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext_b64": "TW9iaWxlIGRldmljZSBkYXRh",
    "mode": "ChaCha20-Poly1305"
  }'
```

**ChaCha20-Poly1305 notes:**
- Not available in FIPS mode.
- 12-byte nonce, 16-byte Poly1305 authentication tag.
- Equivalent security to AES-256-GCM; prefer AES-256-GCM in FIPS environments.

#### AAD Best Practices

Additional Authenticated Data binds the ciphertext to a specific context without encrypting the context. The AAD is authenticated but not confidential. Include as AAD:

- Record ID / primary key
- Table or collection name
- User ID (data owner)
- Data classification label
- Application name and version

Example AAD construction: `"table=payments&record_id=12345&user_id=alice&app=payment-gateway"`

This ensures ciphertext cannot be transplanted from record 12345 to record 99999 without detection.

---

### 7.2 Sign / Verify

Digital signatures provide **non-repudiation** and **integrity** — proving that a specific entity signed specific data, and that the data has not been altered since signing.

#### ECDSA (EC-P256, EC-P384, EC-P521)

```bash
# Sign
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{EC_KEY_ID}/sign?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data_b64": "eyJwYXlsb2FkIjoiY3JpdGljYWwifQ==",
    "algorithm": "ECDSA-SHA256"
  }'

# Response:
{
  "signature_b64": "MEYCIQDx...",
  "key_id": "key_01J...",
  "key_version": 1,
  "algorithm": "ECDSA-SHA256",
  "signing_time": "2026-03-22T14:00:00Z"
}
```

```bash
# Verify
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{EC_KEY_ID}/verify?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data_b64": "eyJwYXlsb2FkIjoiY3JpdGljYWwifQ==",
    "signature_b64": "MEYCIQDx...",
    "algorithm": "ECDSA-SHA256"
  }'

# Response:
{
  "valid": true,
  "key_id": "key_01J...",
  "key_version": 1,
  "algorithm": "ECDSA-SHA256"
}
```

**ECDSA algorithm options:**
- `ECDSA-SHA256` — Use with EC-P256. Standard choice.
- `ECDSA-SHA384` — Use with EC-P384. Required for NSA Suite B.
- `ECDSA-SHA512` — Use with EC-P521.
- Vecta KMS uses **deterministic ECDSA (RFC 6979)** by default — the signature for the same data + key is always the same, eliminating the random-nonce vulnerability that compromised early Bitcoin wallets.

**Important:** `data_b64` should be the raw data to sign (Vecta KMS applies the hash internally). Do not pre-hash unless you are sending a digest and set `prehashed: true`.

#### EdDSA — Ed25519

```bash
# Sign with Ed25519
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{ED25519_KEY_ID}/sign?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data_b64": "SGVsbG8gd29ybGQ=",
    "algorithm": "Ed25519"
  }'
```

**Ed25519 notes:**
- Deterministic: same data + key = same signature, always. No nonce vulnerability.
- Fast: ~100,000 signatures/second on modern hardware.
- 64-byte signature (compact vs ECDSA's DER-encoded variable-length output).
- No hash selection — Ed25519 uses SHA-512 internally (you cannot change this).
- Widely supported in modern software (TLS 1.3, SSH, signal protocol).
- Not FIPS approved yet (as of 2026), but support is expected in upcoming FIPS updates.

#### RSA-PSS (Modern RSA Signatures)

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{RSA_KEY_ID}/sign?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data_b64": "RG9jdW1lbnQgdG8gc2lnbg==",
    "algorithm": "RSA-PSS-SHA256",
    "salt_length": 32
  }'
```

**RSA-PSS notes:**
- More secure than PKCS#1v1.5 — use for all new RSA signatures.
- `salt_length`: recommend `32` for SHA-256, `48` for SHA-384, `64` for SHA-512.
- Probabilistic: each signature of the same data is different (due to random salt). This is expected and correct.

#### RSA-PKCS1v1.5 (Legacy Only)

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{RSA_KEY_ID}/sign?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data_b64": "TGVnYWN5IGRvY3VtZW50",
    "algorithm": "RSA-PKCS1v1.5-SHA256"
  }'
```

Use only for compatibility with systems that cannot support RSA-PSS.

#### ML-DSA (Post-Quantum Signatures)

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{MLDSA_KEY_ID}/sign?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data_b64": "UG9zdC1xdWFudHVtIHNpZ25lZCBkYXRh",
    "algorithm": "ML-DSA-65"
  }'
```

---

### 7.3 Wrap / Unwrap

Key wrapping is the process of **encrypting one key under another**. The encrypting key is the KEK (Key Encrypting Key); the encrypted key is the DEK (Data Encrypting Key).

**KEK/DEK pattern:**
```
Application generates or requests DEK from Vecta KMS
Vecta KMS wraps DEK under KEK (stored in HSM)
Application stores wrapped DEK in database
Application sends wrapped DEK to Vecta KMS for unwrapping when needed
Application uses unwrapped DEK for encryption
Application discards DEK after use (never persists plaintext DEK)
```

#### AES-KW (AES Key Wrap, RFC 3394)

FIPS-approved key wrapping algorithm. Specifically designed for wrapping symmetric keys.

```bash
# Wrap a DEK under a KEK
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEK_ID}/wrap?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_to_wrap_b64": "REVLX01BVEVSSUFMX0hFUkVfMzJfQllURVM=",
    "wrap_algorithm": "AES-KW"
  }'

# Response:
{
  "wrapped_key_b64": "W3jGhN4mK9pQ2rT8vX1wY5zA7bC0dE6f...",
  "kek_id": "key_KEK_01J...",
  "kek_version": 2,
  "wrap_algorithm": "AES-KW"
}
```

```bash
# Unwrap
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEK_ID}/unwrap?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "wrapped_key_b64": "W3jGhN4mK9pQ2rT8vX1wY5zA7bC0dE6f...",
    "wrap_algorithm": "AES-KW",
    "kek_version": 2
  }'

# Response:
{
  "key_b64": "REVLX01BVEVSSUFMX0hFUkVfMzJfQllURVM=",
  "kek_id": "key_KEK_01J...",
  "kek_version": 2
}
```

#### AES-GCM Wrap

Provides AEAD properties during wrapping (integrity check on the wrapped key).

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEK_ID}/wrap?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_to_wrap_b64": "REVLX01BVEVSSUFMX0hFUkVfMzJfQllURVM=",
    "wrap_algorithm": "AES-GCM",
    "aad_b64": "a2V5LXdyYXAtY29udGV4dA=="
  }'
```

#### RSA-OAEP Key Wrap (Asymmetric)

Use for transporting a DEK to a party who has the RSA private key (e.g., cloud KMS BYOK import).

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{RSA_KEK_ID}/wrap?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_to_wrap_b64": "REVLX01BVEVSSUFMX0hFUkVfMzJfQllURVM=",
    "wrap_algorithm": "RSA-OAEP-SHA256"
  }'
```

---

### 7.4 Derive

Key derivation produces child keys from a parent key using a Key Derivation Function (KDF). The derived key is deterministic — the same inputs always produce the same output.

#### HKDF-SHA256 (RFC 5869)

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{PARENT_KEY_ID}/derive?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "kdf": "HKDF-SHA256",
    "info_b64": "c2Vzc2lvbi1rZXktMjAyNi0wMy0yMg==",
    "salt_b64": "cmFuZG9tLXNhbHQtdmFsdWU=",
    "derived_key_length": 32,
    "derived_key_purpose": "encrypt",
    "derived_key_algorithm": "AES-256"
  }'

# Response includes the derived key ID (new key registered in Vecta KMS)
{
  "derived_key_id": "key_DRV_01J...",
  "kdf": "HKDF-SHA256",
  "parent_key_id": "key_01J...",
  "parent_key_version": 1,
  "info_b64": "c2Vzc2lvbi1rZXktMjAyNi0wMy0yMg==",
  "derived_key_length": 32
}
```

**HKDF notes:**
- `info_b64`: domain separation string — encode context (session ID, user ID, purpose). Different info values produce different, independent derived keys.
- `salt_b64`: optional; if omitted, HKDF uses a zero-length salt.
- Common pattern: derive per-session keys from a long-lived master key, using the session ID as the `info` value.

#### SP800-108-CTR (NIST KDF in Counter Mode)

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{PARENT_KEY_ID}/derive?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "kdf": "SP800-108-CTR",
    "label_b64": "ZW5jcnlwdGlvbi1rZXk=",
    "context_b64": "c2Vzc2lvbi0xMjM0NTY=",
    "derived_key_length": 32,
    "derived_key_algorithm": "AES-256"
  }'
```

Use SP800-108-CTR for FIPS-compliant key derivation in regulated environments.

---

### 7.5 KEM (Key Encapsulation Mechanism)

KEM is a post-quantum-safe mechanism for establishing a shared secret between two parties. Unlike DH/ECDH, ML-KEM is believed to be secure against quantum computers.

**Encapsulate (sender, uses recipient's public key):**

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{MLKEM_PUBLIC_KEY_ID}/kem/encapsulate?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "ML-KEM-768"
  }'

# Response:
{
  "encapsulated_key_b64": "3kR9mN4pL...",
  "shared_secret_b64": "7XvB2wQ5nT...",
  "algorithm": "ML-KEM-768"
}
# Send encapsulated_key_b64 to the recipient
# Use shared_secret_b64 as key material (or derive from it with HKDF)
# NEVER send shared_secret_b64
```

**Decapsulate (recipient, uses their ML-KEM private key):**

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{MLKEM_PRIVATE_KEY_ID}/kem/decapsulate?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "encapsulated_key_b64": "3kR9mN4pL...",
    "algorithm": "ML-KEM-768"
  }'

# Response:
{
  "shared_secret_b64": "7XvB2wQ5nT...",
  "algorithm": "ML-KEM-768"
}
# shared_secret_b64 will match what the sender got — shared secret established
```

**Hybrid KEM (post-quantum + classical):**

For highest security during PQC transition, combine ML-KEM with X25519:

```bash
# Both parties do X25519 key exchange AND ML-KEM key encapsulation
# Combine both shared secrets: combined = HKDF(X25519_shared || ML-KEM_shared, "hybrid-kem")
# Even if one algorithm is broken, the other provides security
```

---

### 7.6 Hash

Vecta KMS provides a hash computation API backed by its HSM or software crypto layer.

```bash
# SHA-256
curl -X POST \
  "http://localhost:5173/svc/keycore/hash?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data_b64": "SGVsbG8gV2VjdGEgS01T",
    "algorithm": "SHA-256"
  }'

# Response:
{
  "digest_b64": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
  "algorithm": "SHA-256"
}
```

**Supported hash algorithms:**

| Algorithm | Standard | Output Size | Notes |
|---|---|---|---|
| `SHA-256` | NIST FIPS 180-4 | 256 bits | General purpose; most common |
| `SHA-384` | NIST FIPS 180-4 | 384 bits | Required for some compliance regimes |
| `SHA-512` | NIST FIPS 180-4 | 512 bits | Higher collision resistance |
| `SHA3-256` | NIST FIPS 202 (Keccak) | 256 bits | Sponge construction; different from SHA-2 |
| `SHA3-384` | NIST FIPS 202 | 384 bits | |
| `SHA3-512` | NIST FIPS 202 | 512 bits | |
| `BLAKE2b-256` | RFC 7693 | 256 bits | Fast; keyed hashing supported; not FIPS |
| `BLAKE2b-512` | RFC 7693 | 512 bits | Fast; keyed hashing supported; not FIPS |

> **Important:** A plain hash is not a MAC. Hashing data does not prove who created it and is vulnerable to length extension attacks (SHA-256). Use HMAC (Section 7.1 with `purpose: mac`) for message authentication.

---

### 7.7 Random Bytes

Vecta KMS provides cryptographically strong random byte generation from multiple entropy sources.

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/random?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "length": 32,
    "source": "software"
  }'

# Response:
{
  "random_b64": "3kR9mN4pL7wQ2nT8vX1yC5zA0bD6eF...",
  "length": 32,
  "source": "software"
}
```

**Entropy sources:**

| Source | Description | FIPS | Use Case |
|---|---|---|---|
| `software` | AES-CTR-DRBG (NIST SP 800-90A) seeded from OS entropy | Yes | General purpose; IV generation; salt generation |
| `hsm` | HSM hardware RNG (NIST SP 800-90B compliant) | Yes | Key material seeding; high-assurance randomness |
| `qrng` | Quantum Random Number Generator (via QRNG service) | No (pending) | Highest-assurance entropy; future-proof |

---

## 8. Key Rotation

### 8.1 Why Rotate Keys?

Key rotation limits the **cryptoperiod** — the time span during which a key is authorized for use. Limiting the cryptoperiod limits:

- The amount of data protected by any single key version
- The window of exposure if a key is compromised
- Compliance violations (PCI-DSS, NIST SP 800-57 mandate rotation schedules)

### 8.2 NIST SP 800-57 Recommended Cryptoperiods

| Algorithm | Key Type | Recommended Cryptoperiod |
|---|---|---|
| AES-256 (originator) | Symmetric encryption | 2 years |
| AES-256 (recipient) | Symmetric encryption | 2 years |
| HMAC-SHA256 | MAC | 2 years |
| RSA-4096 | Signature | 1 year (private), 3 years (public verification) |
| EC-P384 | Signature | 2 years (private), 5 years (public verification) |
| Ed25519 | Signature | 2 years |
| ML-DSA-65 | Signature | TBD (NIST guidance pending) |
| ML-KEM-768 | KEM | 2 years |

### 8.3 Manual Rotation

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/rotate?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "old_version_action": "deactivate",
    "reason": "Scheduled quarterly rotation"
  }'

# Response:
{
  "key_id": "key_01J...",
  "new_version": 4,
  "old_version": 3,
  "old_version_action": "deactivate",
  "new_kcv": "F1E2D3",
  "rotated_at": "2026-03-22T14:00:00Z"
}
```

`old_version_action` values:

| Value | Effect on Old Version |
|---|---|
| `retain` | Old version remains Active. Both versions can encrypt. |
| `deactivate` | Old version moves to Deactivated. Can decrypt existing ciphertext; cannot create new ciphertext. (Recommended for most rotations) |
| `destroy` | Old version immediately destroyed. Existing ciphertext encrypted with old version is irrecoverable. (Only if you are certain all data has been re-encrypted) |

### 8.4 Re-Encrypting Data After Rotation

After rotation, existing ciphertext encrypted with the old version is still decryptable (if you used `retain` or `deactivate`). To fully benefit from rotation, re-encrypt data with the new version:

```bash
# For each record encrypted with old version:
# 1. Decrypt with old version
PLAINTEXT=$(curl -X POST ".../decrypt" -d '{"key_version": 3, ...}' | jq -r '.plaintext_b64')

# 2. Re-encrypt with new version (omit key_version → uses current active version = 4)
NEW_CIPHERTEXT=$(curl -X POST ".../encrypt" -d "{\"plaintext_b64\": \"$PLAINTEXT\"}" | jq)

# 3. Update database record with new ciphertext
# 4. After all records are re-encrypted, destroy old version
curl -X POST ".../keys/{KEY_ID}/versions/3/destroy" ...
```

### 8.5 Automated Rotation via Lifecycle Dates

Set `expires_at` on key creation to schedule automatic deactivation (which can trigger a rotation event to your systems via webhook):

```bash
# Create key that expires in 1 year
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "auto-rotating-dek",
    "algorithm": "AES-256",
    "purpose": "encrypt",
    "expires_at": "2027-03-22T00:00:00Z",
    "destroy_date": "2028-03-22T00:00:00Z"
  }'

# Configure a webhook (Admin → Settings → Webhooks) to receive:
# {"event": "key.expiring", "key_id": "...", "days_until_expiry": 30}
# Use this webhook to trigger your rotation workflow
```

---

## 9. Key Access Policy

### 9.1 The Grants Model

Access to key operations is controlled by **grants** — explicit permissions linking a subject (user or group) to specific operations on a specific key or key ring.

```
Grant:
  subject:       "svc-payment-gateway"    ← who
  subject_type:  "user"                   ← user or group
  operations:    ["encrypt", "decrypt"]   ← what
  not_before:    "2026-01-01T00:00:00Z"   ← optional: earliest valid time
  expires_at:    "2027-01-01T00:00:00Z"   ← optional: latest valid time
  justification: "Payment processing"     ← optional: audit note
  ticket_id:     "TICKET-1234"            ← optional: links to change management
```

### 9.2 Operations

| Operation | Description |
|---|---|
| `encrypt` | Encrypt plaintext data |
| `decrypt` | Decrypt ciphertext to plaintext |
| `sign` | Create a digital signature |
| `verify` | Verify a digital signature |
| `wrap` | Wrap (encrypt) another key |
| `unwrap` | Unwrap (decrypt) a wrapped key |
| `derive` | Derive child keys via KDF |
| `export` | Export raw key material (requires `export_allowed: true`) |
| `rotate` | Trigger key rotation |
| `admin` | Full control: modify policy, lifecycle, labels |

### 9.3 Adding Grants — Via API

```bash
# Add a grant
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/access-policy/grants?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "svc-analytics",
    "subject_type": "user",
    "operations": ["encrypt"],
    "expires_at": "2027-01-01T00:00:00Z",
    "justification": "Read-only analytics pipeline — encrypt only for field masking"
  }'

# Response:
{
  "grant_id": "grant_01J...",
  "subject": "svc-analytics",
  "operations": ["encrypt"],
  "expires_at": "2027-01-01T00:00:00Z",
  "created_at": "2026-03-22T14:00:00Z",
  "created_by": "admin"
}
```

```bash
# List grants on a key
curl \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/access-policy/grants?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN"

# Delete a grant
curl -X DELETE \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/access-policy/grants/{GRANT_ID}?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN"
```

### 9.4 Deny-by-Default

Enable `deny_by_default` to ensure all access is explicitly granted:

```bash
curl -X PATCH \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/access-policy?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "deny_by_default": true
  }'
```

Once enabled: any principal without an explicit matching grant receives `403 Forbidden` with error code `ACCESS_DENIED_NO_GRANT`.

### 9.5 Global Access Policy Settings

```bash
curl -X PATCH \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/access-policy?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "deny_by_default": true,
    "require_approval_for_policy_change": true,
    "grant_default_ttl_minutes": 10080,
    "grant_max_ttl_minutes": 525600,
    "enforce_signed_requests": false,
    "replay_window_seconds": 300,
    "nonce_ttl_seconds": 600,
    "require_interface_policies": false
  }'
```

**Settings reference:**

| Setting | Type | Default | Description |
|---|---|---|---|
| `deny_by_default` | boolean | `false` | All operations require explicit grant when true |
| `require_approval_for_policy_change` | boolean | `false` | Policy edits require governance N-of-M approval |
| `grant_default_ttl_minutes` | integer | null | Auto-expiry for new grants if no `expires_at` specified |
| `grant_max_ttl_minutes` | integer | null | Maximum allowed grant TTL (rejects grants with longer `expires_at`) |
| `enforce_signed_requests` | boolean | `false` | Require HTTP Message Signatures (RFC 9421) on all requests |
| `replay_window_seconds` | integer | `300` | How long nonces are remembered to prevent replay attacks |
| `nonce_ttl_seconds` | integer | `600` | Maximum age of a nonce in signed requests |
| `require_interface_policies` | boolean | `false` | All access must pass interface-level allow-list checks |

### 9.6 Interface Policies

Interface policies restrict which **network interface or protocol** a principal can use to access a key. This prevents, for example, a KMIP client from accessing a key that should only be reachable via REST.

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/access-policy/interface-policies?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "interface": "kmip",
    "allowed_subjects": ["kmip-client-storage-array-1", "kmip-client-backup-system"],
    "denied_subjects": []
  }'
```

**Supported interfaces:**

| Interface | Description |
|---|---|
| `rest` | Standard REST API via `/svc/keycore/` |
| `kmip` | KMIP protocol on port 5696 |
| `hyok` | Hold-Your-Own-Key cloud interface |
| `payment` | Payment crypto TR-31 interface |
| `ekm` | External Key Manager database TDE interface |

---

## 10. Key Tags and Labels

### 10.1 Tags

Tags are **simple string labels** for grouping and filtering keys. Max 50 per key, max 63 characters each.

```bash
# Add tags to a key
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/tags?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tags": ["pci-scope", "critical", "hsm-backed", "quarterly-rotation"]}'

# Remove a tag
curl -X DELETE \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/tags/pci-scope?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN"

# Filter keys by tag
curl "http://localhost:5173/svc/keycore/keys?tenant_id=acme-corp&tag=pci-scope" \
  -H "Authorization: Bearer $TOKEN"
```

### 10.2 Labels

Labels are **key-value metadata** for rich filtering, automation, and policy integration. Max 100 per key. Keys: lowercase alphanumeric + hyphens, max 63 chars. Values: max 255 chars.

```bash
# Update labels (merge, not replace)
curl -X PATCH \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/labels?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "labels": {
      "env": "production",
      "team": "platform",
      "data-class": "restricted",
      "rotation-schedule": "quarterly",
      "app": "api-gateway",
      "cost-center": "eng-security"
    }
  }'

# Filter keys by label
curl "http://localhost:5173/svc/keycore/keys?tenant_id=acme-corp&label=env%3Dproduction&label=team%3Dplatform" \
  -H "Authorization: Bearer $TOKEN"
```

### 10.3 Label Use Cases

**Autokey templates:** Autokey governance templates use label selectors to target keys. For example: "All keys with `data-class=restricted` must have `deny_by_default` enabled."

**Compliance policies:** Compliance frameworks can query keys by label. "List all keys with `env=production` and `rotation-schedule!=quarterly` — these are non-compliant."

**Cost allocation:** Label with `cost-center` to attribute key operation costs to teams.

**Incident response:** Label with `app=payment-gateway` to instantly find all keys used by a compromised application.

---

## 11. Rate Limiting

Rate limiting prevents runaway applications from exhausting key usage quotas and provides cost control.

### 11.1 Configuring Rate Limits

```bash
curl -X PATCH \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ops_limit": 100000,
    "ops_limit_window": "day",
    "ops_total": 10000000
  }'
```

### 11.2 Rate Limit Fields

| Field | Type | Description |
|---|---|---|
| `ops_limit` | integer | Maximum operations per `ops_limit_window`. Null = unlimited. |
| `ops_limit_window` | string | Window for `ops_limit`: `hour`, `day`, `week`, `month`. |
| `ops_total` | integer | Lifetime operation count limit. Once reached, all operations return 429. Null = unlimited. |

### 11.3 Rate Limit Behavior

When a rate limit is exceeded, the API returns:

```
HTTP 429 Too Many Requests
Retry-After: 3600

{
  "error": "RATE_LIMIT_EXCEEDED",
  "message": "Key ops_limit of 100000 per day reached",
  "retry_after_seconds": 3600,
  "key_id": "key_01J...",
  "ops_count": 100000,
  "ops_limit": 100000,
  "ops_limit_window": "day",
  "window_resets_at": "2026-03-23T00:00:00Z"
}
```

### 11.4 Monitoring Usage

```bash
# Get current operation count
curl "http://localhost:5173/svc/keycore/keys/{KEY_ID}?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '{ops_count, ops_limit, ops_limit_window, ops_total}'
```

---

## 12. Export Policy

### 12.1 Default: Export Disabled

By default, `export_allowed: false`. Key material **never leaves the Vecta KMS platform** in plaintext. Applications receive ciphertext/plaintext results of operations, not the raw key bytes.

This is the recommended setting for all production keys. The key material stays within Vecta KMS's custody chain (including the HSM if key_backend is `hsm`).

### 12.2 Enabling Export

```bash
# Warning: this is an elevated privilege operation and may require governance approval
curl -X PATCH \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"export_allowed": true}'
```

If `require_approval_for_policy_change` is enabled on the key, this request creates a governance approval request instead of immediately applying the change.

### 12.3 Exporting Key Material

Once export is allowed and the caller has the `export` grant:

```bash
# Export raw symmetric key
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/export?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "raw",
    "wrapping_key_id": "wrapping-rsa-key-id",
    "wrap_algorithm": "RSA-OAEP-SHA256"
  }'

# Response:
{
  "format": "raw",
  "wrapped_key_material_b64": "...",
  "wrapping_key_id": "wrapping-rsa-key-id",
  "wrap_algorithm": "RSA-OAEP-SHA256",
  "key_version": 3,
  "exported_at": "2026-03-22T14:00:00Z"
}
```

### 12.4 Export Formats

| Format | Description | Use Case |
|---|---|---|
| `raw` | Raw key bytes, base64 | Symmetric keys; simple import into other systems |
| `pkcs8` | PKCS#8 DER, base64 | RSA/EC private key export |
| `spki` | SubjectPublicKeyInfo DER, base64 | Public key export (always allowed regardless of export_allowed) |
| `jwk` | JSON Web Key | JWKS-based systems, OIDC providers |

All formats except `spki` are wrapped (encrypted) before export. Sending raw key material over an API — even over TLS — is against best practice without wrapping.

---

## 13. HSM-Backed Keys

### 13.1 What HSM-Backed Means

When `key_backend: "hsm"` is set:

1. The key is **generated inside the HSM hardware** — true hardware entropy, never touches software memory.
2. The key material **never leaves the HSM** — all cryptographic operations (encrypt, sign, wrap) execute inside the HSM.
3. The Vecta KMS application processes only inputs and outputs — never the key itself.
4. The HSM provides **FIPS 140-3 Level 3** (or higher) custody, including tamper evidence and response.

### 13.2 Creating an HSM-Backed Key

```bash
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "root-ca-key",
    "algorithm": "EC-P384",
    "purpose": "sign",
    "key_backend": "hsm",
    "export_allowed": false,
    "labels": {
      "role": "root-ca",
      "env": "production"
    }
  }'
```

### 13.3 HSM Key Identifier

HSM-backed keys include an `hsm_key_id` in the response — the HSM's internal handle for this key. This is logged in audit events and can be cross-referenced with the HSM's own audit log (if the HSM provides one).

### 13.4 Supported HSM Providers

| Provider | Connection Method | Notes |
|---|---|---|
| Thales Luna 7 | PKCS#11 via Luna Client | FIPS 140-3 Level 3; network-attached |
| Entrust nShield 5c | PKCS#11 via nCore | FIPS 140-3 Level 3; PCIe or network |
| Utimaco SecurityServer | PKCS#11 | FIPS 140-3 Level 3 |
| Securosys Primus X | REST API + PKCS#11 | FIPS 140-3 Level 3; CloudHSM option |
| AWS CloudHSM | PKCS#11 via CloudHSM client | FIPS 140-3 Level 3; managed |
| Azure Managed HSM | REST API (MHSM) | FIPS 140-3 Level 3; managed |

### 13.5 HSM Key Operations Performance

HSM operations are slower than software operations due to hardware communication overhead. Typical throughput:

| Algorithm | Software (ops/sec) | HSM (ops/sec) |
|---|---|---|
| AES-256-GCM encrypt | ~500,000 | ~5,000 - 20,000 |
| EC-P384 sign | ~20,000 | ~500 - 2,000 |
| RSA-4096 sign | ~1,000 | ~50 - 200 |

For high-throughput applications, consider: generate a short-lived DEK in the HSM, use software crypto for bulk data operations, re-wrap the DEK under the HSM-backed KEK for storage.

---

## 14. Security Considerations

### 14.1 Algorithm Selection Guidance

**Avoid for new keys:**
- RSA-2048 (acceptable minimum, but RSA-3072+ preferred)
- AES-128 (prefer AES-256; marginal cost difference)
- ChaCha20 without Poly1305 (use ChaCha20-Poly1305 for AEAD)
- RSA-PKCS1v1.5 signatures (use RSA-PSS)
- SHA-1 for any new signature or MAC (deprecated)
- Ed25519 in FIPS-mandated environments (not yet FIPS-approved)

**Prefer for new keys:**
- AES-256-GCM for symmetric encryption
- EC-P384 for signing and ECDH
- Ed25519 for signing in non-FIPS environments
- ML-KEM-768 for post-quantum key exchange (hybrid with X25519 during transition)
- ML-DSA-65 for post-quantum signing

### 14.2 Key Naming

Never embed:
- Passwords or API keys in key names
- Personally identifiable information (PII) in key names
- Classification levels that reveal sensitive context

Key names appear in audit logs, reports, and dashboards visible to admins. A key named `patient-ssn-aes256-key` leaks that you process SSNs; prefer `patient-data-dek`.

### 14.3 Least Privilege

- Grant only the specific operations needed (do not grant `admin` when `encrypt` suffices)
- Use time-bounded grants (`expires_at`) for temporary access
- Grant access to specific service accounts, not groups of humans for production crypto
- Review grants quarterly; remove unused grants
- Enable `deny_by_default` on all production key rings

### 14.4 Rotation Schedule Recommendations

| Data Sensitivity | Algorithm | Max Cryptoperiod |
|---|---|---|
| High (PCI, PHI, PII) | AES-256 | 90 days |
| High (PCI, PHI, PII) | EC-P384 signing | 1 year |
| Medium (internal sensitive) | AES-256 | 1 year |
| Low (non-sensitive) | AES-256 | 2 years |
| Root CA key | EC-P521 / RSA-4096 | 5 years |
| Code signing | Ed25519 / EC-P256 | 1 year |

### 14.5 Compromise Response Runbook

If you suspect a key has been compromised:

```bash
# Step 1: Immediately mark as Compromised (blocks new encrypt/sign operations)
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/compromise?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Key material found in leaked repo", "incident_id": "INC-2026-0042"}'

# Step 2: Identify all data encrypted under this key
curl "http://localhost:5173/svc/audit/events?tenant_id=acme-corp&key_id={KEY_ID}&event_type=key.encrypt" \
  -H "Authorization: Bearer $TOKEN"

# Step 3: Generate a new replacement key
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "payments-prod-dek-v2", "algorithm": "AES-256", "purpose": "encrypt"}'

# Step 4: Re-encrypt all data with the new key
# (Application-level re-encryption pipeline)

# Step 5: Destroy the compromised key once re-encryption is confirmed
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/{KEY_ID}/destroy?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"confirm_name": "payments-prod-dek", "reason": "Key compromised — data re-encrypted"}'

# Step 6: Notify security team and initiate incident response
# Step 7: Export and preserve the audit chain for forensic evidence
```

### 14.6 Export Policy

- Leave `export_allowed: false` for all production keys unless migration is specifically needed.
- When export is needed: wrap the exported material immediately; never transport raw key material without wrapping.
- Log and review all export events in the audit trail.
- Consider requiring governance approval for export policy changes.

---

## 15. Use Cases

### Use Case 1: Application Data Encryption (KEK/DEK Pattern)

**Scenario:** A payment processing API needs to encrypt card data at rest in a database. You want key separation: the DEK is stored in the database (wrapped), but the KEK never leaves Vecta KMS.

```bash
# Step 1: Create a KEK (Key Encrypting Key) in Vecta KMS HSM
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=payments-tenant" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "payments-kek",
    "algorithm": "AES-256",
    "purpose": "wrap",
    "key_backend": "hsm",
    "export_allowed": false
  }'
# → key_id: "key_KEK_01J..."

# Step 2: Application creates a random DEK for each payment record (or per customer)
# DEK generated by application (or via Vecta random bytes)
curl -X POST "http://localhost:5173/svc/keycore/random?tenant_id=payments-tenant" \
  -H "Authorization: Bearer $APP_TOKEN" \
  -d '{"length": 32}' | jq -r '.random_b64'
# → DEK_MATERIAL_B64 (32 bytes AES-256 key)

# Step 3: Wrap the DEK under the KEK
curl -X POST "http://localhost:5173/svc/keycore/keys/key_KEK_01J.../wrap?tenant_id=payments-tenant" \
  -H "Authorization: Bearer $APP_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"key_to_wrap_b64\": \"$DEK_MATERIAL_B64\", \"wrap_algorithm\": \"AES-KW\"}"
# → wrapped_dek_b64

# Step 4: Encrypt card data with the DEK (application-side, using standard library)
# Store: wrapped_dek_b64, ciphertext, iv, tag alongside the record in database

# Step 5: To decrypt — retrieve wrapped_dek, unwrap it, decrypt record
curl -X POST "http://localhost:5173/svc/keycore/keys/key_KEK_01J.../unwrap?tenant_id=payments-tenant" \
  -H "Authorization: Bearer $APP_TOKEN" \
  -d "{\"wrapped_key_b64\": \"$WRAPPED_DEK_B64\", \"wrap_algorithm\": \"AES-KW\"}"
# → dek_material_b64 (use to decrypt record, then immediately discard from memory)
```

---

### Use Case 2: API Request Signing (ECDSA or Ed25519)

**Scenario:** A microservice needs to sign API requests so the receiving service can verify the request came from an authorized caller and was not tampered with.

```bash
# Step 1: Create signing key for the service
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=platform" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "name": "svc-order-manager-signing-key",
    "algorithm": "Ed25519",
    "purpose": "sign",
    "labels": {"service": "order-manager", "env": "production"}
  }'
# → key_id: "key_SIGN_01J..."
# → public_key_pem: "-----BEGIN PUBLIC KEY-----\n..."

# Step 2: Distribute public key to receiving service (publish to internal JWKS endpoint)
# The private key never leaves Vecta KMS

# Step 3: Sign each request payload (hash of request body)
PAYLOAD_HASH_B64=$(echo -n '{"order_id": "ORD-123", "amount": 9900}' | sha256sum | cut -d' ' -f1 | xxd -r -p | base64)

curl -X POST "http://localhost:5173/svc/keycore/keys/key_SIGN_01J.../sign?tenant_id=platform" \
  -H "Authorization: Bearer $SVC_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"data_b64\": \"$PAYLOAD_HASH_B64\", \"algorithm\": \"Ed25519\", \"prehashed\": true}"
# → signature_b64: "..."
# Add to request as header: X-Signature: <signature_b64>

# Step 4: Receiving service verifies
curl -X POST "http://localhost:5173/svc/keycore/keys/key_SIGN_01J.../verify?tenant_id=platform" \
  -H "Authorization: Bearer $SVC_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"data_b64\": \"$PAYLOAD_HASH_B64\",
    \"signature_b64\": \"$REQUEST_SIGNATURE\",
    \"algorithm\": \"Ed25519\",
    \"prehashed\": true
  }"
# → {"valid": true, ...}
```

---

### Use Case 3: Payment Key Wrapping (TR-31)

**Scenario:** PCI-DSS environment. Wrapping Zone Master Keys (ZMK) and PIN Encryption Keys (PEK) for transport and storage in TR-31 key blocks.

```bash
# Step 1: Create an LMK (Local Master Key) — HSM-backed, never exported
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=payment-prod" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "name": "payment-lmk",
    "algorithm": "AES-256",
    "purpose": "wrap",
    "key_backend": "hsm",
    "export_allowed": false,
    "tags": ["pci-scope", "lmk"]
  }'

# Step 2: Import PEK from HSM ceremony (wrapped under LMK)
curl -X POST "http://localhost:5173/svc/payment/key-blocks?tenant_id=payment-prod" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "block_format": "TR-31",
    "key_usage": "P0",
    "algorithm": "AES-256",
    "mode_of_use": "E",
    "key_version_number": "00",
    "exportability": "S",
    "kbpk_id": "key_LMK_01J...",
    "key_material_b64": "<wrapped-pek-from-ceremony>"
  }'
```

---

### Use Case 4: Certificate Private Key Storage (HSM-Backed, EC-P384)

**Scenario:** An intermediate CA private key must be stored in HSM with strict access controls.

```bash
# Step 1: Generate CA key inside HSM
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=pki" \
  -H "Authorization: Bearer $PKI_ADMIN_TOKEN" \
  -d '{
    "name": "intermediate-ca-key-2026",
    "algorithm": "EC-P384",
    "purpose": "sign",
    "key_backend": "hsm",
    "export_allowed": false,
    "access_policy": {
      "deny_by_default": true,
      "require_approval_for_policy_change": true,
      "grants": [
        {
          "subject": "svc-ca-signer",
          "operations": ["sign"],
          "expires_at": "2028-01-01T00:00:00Z"
        }
      ]
    }
  }'
# Returns: public_key_pem for use in CSR

# Step 2: Pass public_key_pem to certs service to create CSR
curl -X POST "http://localhost:5173/svc/certs/signing-requests?tenant_id=pki" \
  -H "Authorization: Bearer $PKI_ADMIN_TOKEN" \
  -d '{
    "key_id": "key_CA_01J...",
    "subject": "CN=Vecta Intermediate CA 2026,O=Acme Corp,C=US",
    "key_usages": ["cert_sign", "crl_sign"]
  }'
```

---

### Use Case 5: Post-Quantum Key Exchange (ML-KEM-768 for TLS Replacement)

**Scenario:** Two backend services need to establish a shared secret that is secure against future quantum adversaries.

```bash
# Recipient: create ML-KEM-768 keypair
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=platform" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "svc-data-processor-kem-key",
    "algorithm": "ML-KEM-768",
    "purpose": "kem"
  }'
# Returns: key_id, public_key_pem (publish this)

# Sender: encapsulate against recipient public key
curl -X POST "http://localhost:5173/svc/keycore/keys/{KEM_KEY_ID}/kem/encapsulate?tenant_id=platform" \
  -H "Authorization: Bearer $SENDER_TOKEN" \
  -d '{"algorithm": "ML-KEM-768"}'
# Returns: encapsulated_key_b64 (send to recipient), shared_secret_b64 (use locally)

# Recipient: decapsulate to recover shared secret
curl -X POST "http://localhost:5173/svc/keycore/keys/{KEM_KEY_ID}/kem/decapsulate?tenant_id=platform" \
  -H "Authorization: Bearer $RECIPIENT_TOKEN" \
  -d '{"encapsulated_key_b64": "...", "algorithm": "ML-KEM-768"}'
# Returns: shared_secret_b64 (matches sender's shared_secret_b64)

# Both parties: derive session key from shared secret using HKDF
# Use the shared_secret as HKDF IKM → 32-byte session AES-256 key
```

---

### Use Case 6: Microservice-to-Microservice Encryption (HKDF-Derived Per-Session Keys)

**Scenario:** Microservice A encrypts data for Microservice B. Each request uses a unique derived key to prevent any single key from being over-used.

```bash
# Create a long-lived master key shared between the two services
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=platform" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"name": "svc-a-to-svc-b-master-key", "algorithm": "AES-256", "purpose": "derive"}'

# Per request: derive a session key using the request ID as context
REQUEST_ID="req-2026-03-22-abc123"
INFO_B64=$(echo -n "svc-a-to-svc-b:$REQUEST_ID:encrypt" | base64)

curl -X POST "http://localhost:5173/svc/keycore/keys/{MASTER_KEY_ID}/derive?tenant_id=platform" \
  -H "Authorization: Bearer $SVC_A_TOKEN" \
  -d "{
    \"kdf\": \"HKDF-SHA256\",
    \"info_b64\": \"$INFO_B64\",
    \"derived_key_length\": 32,
    \"derived_key_algorithm\": \"AES-256\",
    \"derived_key_purpose\": \"encrypt\"
  }"
# → derived_key_id: temporary key for this request's data

# Service A encrypts with derived key, sends ciphertext + request_id to Service B
# Service B derives the same key using the same request_id → decrypts
```

---

### Use Case 7: Database Field Encryption (AES-256-GCM Per-Field)

**Scenario:** Encrypt individual fields (SSN, DOB, credit card number) in a database table. Each field gets its own AAD to prevent data transposition attacks.

```bash
# One key per table (or per data classification)
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=data-platform" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "patients-pii-field-dek",
    "algorithm": "AES-256",
    "purpose": "encrypt",
    "labels": {"table": "patients", "data-class": "phi"}
  }'

# Encrypt SSN with per-record, per-field AAD
RECORD_ID="patient-uuid-12345"
FIELD_NAME="ssn"
AAD_B64=$(echo -n "table=patients&record=${RECORD_ID}&field=${FIELD_NAME}" | base64)

curl -X POST "http://localhost:5173/svc/keycore/keys/{KEY_ID}/encrypt?tenant_id=data-platform" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"plaintext_b64\": \"$(echo -n '123-45-6789' | base64)\",
    \"aad_b64\": \"$AAD_B64\"
  }"
# Store: ciphertext_b64, iv_b64, tag_b64, aad_b64 in database (or reconstruct AAD from known fields)

# Decrypt — must provide exact same AAD
curl -X POST "http://localhost:5173/svc/keycore/keys/{KEY_ID}/decrypt?tenant_id=data-platform" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"ciphertext_b64\": \"...\",
    \"iv_b64\": \"...\",
    \"tag_b64\": \"...\",
    \"aad_b64\": \"$AAD_B64\"
  }"
```

---

### Use Case 8: Code Signing Pipeline (Ed25519, Transparency Log)

**Scenario:** CI/CD pipeline signs container images and artifacts. Signatures are published to a transparency log. Deployment systems verify before running.

```bash
# Step 1: Create code signing key (restricted to CI/CD service account)
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=platform" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "name": "container-image-signing-key-2026",
    "algorithm": "Ed25519",
    "purpose": "sign",
    "access_policy": {
      "deny_by_default": true,
      "grants": [
        {"subject": "svc-cicd-pipeline", "operations": ["sign"], "expires_at": "2027-01-01T00:00:00Z"},
        {"subject": "svc-deployment", "operations": ["verify"], "expires_at": "2027-01-01T00:00:00Z"}
      ]
    }
  }'

# Step 2: CI/CD signs image digest
IMAGE_DIGEST_B64=$(docker inspect myimage:latest --format='{{index .RepoDigests 0}}' | sha256sum | cut -d' ' -f1 | xxd -r -p | base64)

curl -X POST "http://localhost:5173/svc/keycore/keys/{SIGN_KEY_ID}/sign?tenant_id=platform" \
  -H "Authorization: Bearer $CICD_TOKEN" \
  -d "{\"data_b64\": \"$IMAGE_DIGEST_B64\", \"algorithm\": \"Ed25519\", \"prehashed\": true}"
# → signature_b64

# Step 3: Submit to signing service / transparency log
curl -X POST "http://localhost:5173/svc/signing/entries?tenant_id=platform" \
  -H "Authorization: Bearer $CICD_TOKEN" \
  -d "{
    \"artifact_digest_b64\": \"$IMAGE_DIGEST_B64\",
    \"signature_b64\": \"$SIGNATURE_B64\",
    \"key_id\": \"$SIGN_KEY_ID\",
    \"artifact_type\": \"container-image\",
    \"artifact_ref\": \"registry.example.com/myimage:v1.2.3@sha256:...\"
  }"
# → transparency_log_entry_id (include in image attestation)

# Step 4: Deployment verifies before running
curl -X POST "http://localhost:5173/svc/keycore/keys/{SIGN_KEY_ID}/verify?tenant_id=platform" \
  -H "Authorization: Bearer $DEPLOY_TOKEN" \
  -d "{
    \"data_b64\": \"$IMAGE_DIGEST_B64\",
    \"signature_b64\": \"$SIGNATURE_FROM_ATTESTATION\",
    \"algorithm\": \"Ed25519\",
    \"prehashed\": true
  }"
# → {"valid": true} — allow deployment
# → {"valid": false} — block deployment, alert security team
```

---

## 16. API Reference

### 16.1 Key CRUD Endpoints

#### List Keys

```
GET /svc/keycore/keys?tenant_id={tenant_id}
```

Query parameters:

| Parameter | Type | Description |
|---|---|---|
| `tenant_id` | string | Required. Tenant context. |
| `status` | string | Filter: `active`, `preactive`, `deactivated`, `compromised`, `destroyed`, `suspended`. |
| `algorithm` | string | Filter by algorithm (e.g., `AES-256`). |
| `purpose` | string | Filter by purpose (e.g., `encrypt`). |
| `key_backend` | string | Filter: `software` or `hsm`. |
| `tag` | string | Filter by tag (can be repeated for AND). |
| `label` | string | Filter by label (format: `key=value`, can be repeated). |
| `page` | integer | Page number (default: 1). |
| `page_size` | integer | Results per page (default: 50, max: 500). |
| `sort` | string | Sort field: `name`, `created_at`, `expires_at`. |
| `order` | string | Sort order: `asc`, `desc`. |

```bash
curl "http://localhost:5173/svc/keycore/keys?tenant_id=acme-corp&status=active&algorithm=AES-256&label=env%3Dproduction&page=1&page_size=50" \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "keys": [ /* array of key objects */ ],
  "total": 142,
  "page": 1,
  "page_size": 50,
  "total_pages": 3
}
```

#### Get Key

```
GET /svc/keycore/keys/{key_id}?tenant_id={tenant_id}
```

```bash
curl "http://localhost:5173/svc/keycore/keys/key_01J3XVQB5M9N4KPFGHWCZ8D?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN"
```

#### Create Key

```
POST /svc/keycore/keys?tenant_id={tenant_id}
```

See Section 5.3 for full field reference. Returns HTTP 201 on success.

#### Update Key (Metadata Only)

```
PATCH /svc/keycore/keys/{key_id}?tenant_id={tenant_id}
```

Updatable fields: `name`, `labels`, `tags`, `ops_limit`, `ops_limit_window`, `ops_total`, `export_allowed`, `expires_at`, `destroy_date`.

```bash
curl -X PATCH "http://localhost:5173/svc/keycore/keys/key_01J...?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "labels": {"env": "production", "rotated-on": "2026-03-22"},
    "ops_limit": 500000
  }'
```

#### Delete Key (Soft Delete — moves to Destroyed)

```
DELETE /svc/keycore/keys/{key_id}?tenant_id={tenant_id}
```

```bash
curl -X DELETE "http://localhost:5173/svc/keycore/keys/key_01J...?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"confirm_name": "my-key-name"}'
```

### 16.2 Lifecycle Endpoints

```bash
# Activate
POST /svc/keycore/keys/{key_id}/activate?tenant_id={tenant_id}

# Deactivate
POST /svc/keycore/keys/{key_id}/deactivate?tenant_id={tenant_id}

# Suspend
POST /svc/keycore/keys/{key_id}/suspend?tenant_id={tenant_id}
Body: {"reason": "string"}

# Reinstate (Suspended → Active)
POST /svc/keycore/keys/{key_id}/reinstate?tenant_id={tenant_id}

# Compromise
POST /svc/keycore/keys/{key_id}/compromise?tenant_id={tenant_id}
Body: {"reason": "string", "incident_id": "string (optional)"}

# Destroy
POST /svc/keycore/keys/{key_id}/destroy?tenant_id={tenant_id}
Body: {"confirm_name": "string", "reason": "string"}

# Rotate
POST /svc/keycore/keys/{key_id}/rotate?tenant_id={tenant_id}
Body: {"old_version_action": "retain|deactivate|destroy", "reason": "string"}
```

### 16.3 Cryptographic Operation Endpoints

```bash
# Encrypt
POST /svc/keycore/keys/{key_id}/encrypt?tenant_id={tenant_id}
Body: {"plaintext_b64": "...", "aad_b64": "...(opt)", "mode": "...(opt)", "key_version": N (opt)}

# Decrypt
POST /svc/keycore/keys/{key_id}/decrypt?tenant_id={tenant_id}
Body: {"ciphertext_b64": "...", "iv_b64": "...", "tag_b64": "...", "aad_b64": "...(opt)", "key_version": N}

# Sign
POST /svc/keycore/keys/{key_id}/sign?tenant_id={tenant_id}
Body: {"data_b64": "...", "algorithm": "...", "prehashed": false}

# Verify
POST /svc/keycore/keys/{key_id}/verify?tenant_id={tenant_id}
Body: {"data_b64": "...", "signature_b64": "...", "algorithm": "...", "prehashed": false}

# Wrap
POST /svc/keycore/keys/{key_id}/wrap?tenant_id={tenant_id}
Body: {"key_to_wrap_b64": "...", "wrap_algorithm": "...", "aad_b64": "...(opt)"}

# Unwrap
POST /svc/keycore/keys/{key_id}/unwrap?tenant_id={tenant_id}
Body: {"wrapped_key_b64": "...", "wrap_algorithm": "...", "kek_version": N, "aad_b64": "...(opt)"}

# Derive
POST /svc/keycore/keys/{key_id}/derive?tenant_id={tenant_id}
Body: {"kdf": "HKDF-SHA256|SP800-108-CTR", "info_b64": "...", "salt_b64": "...(opt)", "derived_key_length": 32, "derived_key_algorithm": "AES-256", "derived_key_purpose": "encrypt"}

# KEM Encapsulate
POST /svc/keycore/keys/{key_id}/kem/encapsulate?tenant_id={tenant_id}
Body: {"algorithm": "ML-KEM-768"}

# KEM Decapsulate
POST /svc/keycore/keys/{key_id}/kem/decapsulate?tenant_id={tenant_id}
Body: {"encapsulated_key_b64": "...", "algorithm": "ML-KEM-768"}

# Hash
POST /svc/keycore/hash?tenant_id={tenant_id}
Body: {"data_b64": "...", "algorithm": "SHA-256|SHA-384|SHA-512|SHA3-256|SHA3-384|SHA3-512|BLAKE2b-256|BLAKE2b-512"}

# Random Bytes
POST /svc/keycore/random?tenant_id={tenant_id}
Body: {"length": 32, "source": "software|hsm|qrng"}

# Export
POST /svc/keycore/keys/{key_id}/export?tenant_id={tenant_id}
Body: {"format": "raw|pkcs8|spki|jwk", "wrapping_key_id": "...(opt)", "wrap_algorithm": "...(opt)"}

# Import (get wrapping key)
GET /svc/keycore/keys/import-wrapping-key?tenant_id={tenant_id}

# Import (submit)
POST /svc/keycore/keys/import?tenant_id={tenant_id}
Body: {"name": "...", "algorithm": "...", "purpose": "...", "import_format": "raw|pkcs8|spki|jwk", "wrapped_key_material_b64": "...", "wrapping_key_id": "...", "wrapping_algorithm": "..."}
```

### 16.4 Key Version Endpoints

```bash
# List versions
GET /svc/keycore/keys/{key_id}/versions?tenant_id={tenant_id}

# Get specific version metadata
GET /svc/keycore/keys/{key_id}/versions/{version}?tenant_id={tenant_id}

# Destroy a specific old version
POST /svc/keycore/keys/{key_id}/versions/{version}/destroy?tenant_id={tenant_id}
Body: {"reason": "string"}
```

### 16.5 Access Policy Endpoints

```bash
# Get access policy
GET /svc/keycore/keys/{key_id}/access-policy?tenant_id={tenant_id}

# Update access policy settings
PATCH /svc/keycore/keys/{key_id}/access-policy?tenant_id={tenant_id}
Body: {"deny_by_default": bool, "require_approval_for_policy_change": bool, ...}

# List grants
GET /svc/keycore/keys/{key_id}/access-policy/grants?tenant_id={tenant_id}

# Add grant
POST /svc/keycore/keys/{key_id}/access-policy/grants?tenant_id={tenant_id}
Body: {"subject": "...", "subject_type": "user|group", "operations": [...], "expires_at": "...", "not_before": "...", "justification": "...", "ticket_id": "..."}

# Update grant
PATCH /svc/keycore/keys/{key_id}/access-policy/grants/{grant_id}?tenant_id={tenant_id}
Body: {"operations": [...], "expires_at": "...", "justification": "..."}

# Delete grant
DELETE /svc/keycore/keys/{key_id}/access-policy/grants/{grant_id}?tenant_id={tenant_id}

# List interface policies
GET /svc/keycore/keys/{key_id}/access-policy/interface-policies?tenant_id={tenant_id}

# Set interface policy
POST /svc/keycore/keys/{key_id}/access-policy/interface-policies?tenant_id={tenant_id}
Body: {"interface": "rest|kmip|hyok|payment|ekm", "allowed_subjects": [...], "denied_subjects": [...]}

# Delete interface policy
DELETE /svc/keycore/keys/{key_id}/access-policy/interface-policies/{interface}?tenant_id={tenant_id}
```

### 16.6 Tag Management Endpoints

```bash
# Get tags
GET /svc/keycore/keys/{key_id}/tags?tenant_id={tenant_id}

# Add tags
POST /svc/keycore/keys/{key_id}/tags?tenant_id={tenant_id}
Body: {"tags": ["tag1", "tag2"]}

# Remove a tag
DELETE /svc/keycore/keys/{key_id}/tags/{tag}?tenant_id={tenant_id}

# Replace all tags
PUT /svc/keycore/keys/{key_id}/tags?tenant_id={tenant_id}
Body: {"tags": ["tag1", "tag2", "tag3"]}
```

### 16.7 Label Management Endpoints

```bash
# Get labels
GET /svc/keycore/keys/{key_id}/labels?tenant_id={tenant_id}

# Merge labels (add/update without removing existing)
PATCH /svc/keycore/keys/{key_id}/labels?tenant_id={tenant_id}
Body: {"labels": {"key": "value"}}

# Replace all labels
PUT /svc/keycore/keys/{key_id}/labels?tenant_id={tenant_id}
Body: {"labels": {"key": "value"}}

# Delete a label
DELETE /svc/keycore/keys/{key_id}/labels/{label_key}?tenant_id={tenant_id}
```

### 16.8 Audit Endpoint for Keys

```bash
# Get audit events for a specific key
GET /svc/audit/events?tenant_id={tenant_id}&key_id={key_id}

Query parameters:
  event_type: key.encrypt|key.decrypt|key.sign|key.verify|key.rotate|key.activate|key.deactivate|key.compromise|key.destroy|key.policy_change
  from: ISO-8601 timestamp
  to: ISO-8601 timestamp
  principal: filter by who performed the action
  result: success|failure
  page, page_size
```

### 16.9 Common Error Codes

| HTTP Status | Error Code | Description |
|---|---|---|
| 400 | `INVALID_REQUEST` | Malformed request body or missing required field |
| 400 | `ALGORITHM_PURPOSE_MISMATCH` | Algorithm does not support the requested purpose |
| 401 | `UNAUTHORIZED` | Missing or invalid token |
| 401 | `TOKEN_EXPIRED` | JWT has expired |
| 401 | `TOKEN_TENANT_MISMATCH` | Token's tenant binding does not match request tenant |
| 403 | `ACCESS_DENIED_NO_GRANT` | No matching grant for this principal + operation |
| 403 | `ACCESS_DENIED_INTERFACE` | Interface policy does not allow this principal |
| 403 | `MUST_CHANGE_PASSWORD` | Admin account requires password change |
| 404 | `KEY_NOT_FOUND` | Key ID does not exist in this tenant |
| 404 | `KEY_VERSION_NOT_FOUND` | Specific key version not found |
| 409 | `KEY_NAME_CONFLICT` | A key with this name already exists in this tenant |
| 409 | `INVALID_STATE_TRANSITION` | Operation not allowed in current key lifecycle state |
| 422 | `FIPS_VIOLATION` | Algorithm not permitted in FIPS mode |
| 422 | `AUTHENTICATION_FAILED` | GCM/Poly1305 tag verification failed (tampered ciphertext) |
| 422 | `EXPORT_NOT_ALLOWED` | Key export is disabled (export_allowed: false) |
| 422 | `KEY_DESTROYED` | Key has been destroyed — operation impossible |
| 429 | `RATE_LIMIT_EXCEEDED` | Key operation rate limit reached |
| 500 | `HSM_ERROR` | HSM communication or operation failure |
| 503 | `SERVICE_UNAVAILABLE` | Service temporarily unavailable (cluster leader election, etc.) |

---

*Vecta KMS — Key Management Documentation — Version Beta — 2026-03-22*
