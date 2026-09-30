# Vecta KMS — Data Protection

## Table of Contents

1. [Overview](#1-overview)
2. [Format-Preserving Tokenization](#2-format-preserving-tokenization)
   - [What FPE Is](#21-what-fpe-is)
   - [PAN Tokenization](#22-pan-tokenization)
   - [SSN Tokenization](#23-ssn-tokenization)
   - [Vault Tokenization (Non-FPE)](#24-vault-tokenization-non-fpe)
   - [Tokenization Scheme Configuration](#25-tokenization-scheme-configuration)
   - [API Endpoints — Tokenization](#26-api-endpoints--tokenization)
3. [Data Masking and Redaction](#3-data-masking-and-redaction)
   - [Masking Modes](#31-masking-modes)
   - [Masking Policy Configuration](#32-masking-policy-configuration)
   - [Field Encryption](#33-field-encryption)
   - [API Endpoints — Masking and Field Encryption](#34-api-endpoints--masking-and-field-encryption)
5. [PKCS#11 Provider](#5-pkcs11-provider)
6. [JCA/JCE Provider](#6-jcajce-provider)
7. [Autokey — Automatic Key Provisioning](#7-autokey--automatic-key-provisioning)
   - [What Autokey Is](#71-what-autokey-is)
   - [Template Configuration](#72-template-configuration)
   - [Handle Request Workflow](#73-handle-request-workflow)
   - [API Endpoints — Autokey](#74-api-endpoints--autokey)
8. [Secrets Vault](#8-secrets-vault)
   - [Overview](#81-overview)
   - [Secret Object Schema](#82-secret-object-schema)
   - [API Endpoints — Secrets](#83-api-endpoints--secrets)
9. [Use Cases](#9-use-cases)
   - [PCI DSS: End-to-End PAN Tokenization at Checkout](#91-pci-dss-end-to-end-pan-tokenization-at-checkout)
   - [HIPAA: PHI Field Encryption Per Patient](#92-hipaa-phi-field-encryption-per-patient)
   - [Data Warehouse Dynamic Masking](#93-data-warehouse-dynamic-masking)
   - [Java Microservice Using JCA — Zero Code Change](#94-java-microservice-using-jca--zero-code-change)
   - [Autokey for Microservice Fleet — Self-Service](#95-autokey-for-microservice-fleet--self-service)

---

## 1. Overview

Vecta KMS separates two concerns that are often conflated:

- **Key management** governs the lifecycle of cryptographic keys — generation, rotation, distribution, destruction, and access policy. The core KMS services handle this.
- **Data protection** uses those keys to transform sensitive data at the application layer — tokenizing PANs, masking PII fields, encrypting database columns.

All data-protection endpoints are hosted under the `/svc/dataprotect/` base path and run inside the `dataprotect` service behind the Envoy edge. It authenticates via the standard `Authorization: Bearer <jwt>` header and require `X-Tenant-ID` for multi-tenant deployments.

### 1.1 Decision Matrix: Tokenization vs Encryption vs Masking

Choose the right protection technique based on format requirements, reversibility, and the use case:

| Requirement | Tokenization (FPE) | Tokenization (Vault) | Encryption (AES-GCM) | Masking |
|---|---|---|---|---|
| Output preserves original format and length | Yes | No (opaque token) | No | Configurable |
| Reversible by authorized callers | Yes | Yes | Yes | No (one-way) |
| Original data stored anywhere | No | Yes (in vault) | No (encrypted) | No |
| Suitable for PCI DSS PAN in legacy systems | Yes (Luhn-valid) | Limited | No | No |
| Suitable for display-only (logs, UI) | Partial (preservePrefix/Suffix) | Partial | No | Yes |
| Supports exact-match search without decryption | Yes (FPE is deterministic) | Yes (vault lookup) | Only in deterministic mode | N/A |
| Key rotation | Re-tokenize | Re-tokenize or update mapping | Re-encrypt | N/A |
| Best for high-cardinality PII (SSNs, PANs) | Yes | Yes | Yes | Display/logging |
| Best for database column encryption | No | No | Yes | No |
| Best for CHD in payment flows | Yes | Limited | No | No |

### 1.2 Compliance Context

**PCI DSS:**
- Requirement 3.3 mandates that PANs not be stored in cleartext. FPE tokenization with Luhn preservation satisfies this while keeping downstream systems functional.
- Requirement 3.5 mandates cryptographic protection of stored keys. All tokenization keys are managed under Vecta KMS key policy with full audit trails.
- Requirement 3.6 covers key management procedures — Vecta's key lifecycle, rotation scheduling, and destruction workflows satisfy 3.6.1 through 3.6.1.4.

**HIPAA:**
- The Security Rule (45 CFR 164.312(a)(2)(iv) and 164.312(e)(2)(ii)) requires encryption of PHI at rest and in transit. Field encryption with AES-256-GCM satisfies the at-rest requirement.
- De-identification under 45 CFR 164.514(b) can be achieved through redaction or format-preserving tokenization where the original cannot be reverse-engineered without the key.

### 1.3 API Base Paths

| Service | Base path (dashboard proxy) | Edge path |
|---|---|---|
| Data Protection | `/svc/dataprotect/` | `/api/dataprotect/` |
| Secrets Vault | `/svc/secrets/` | `/api/secrets/` |
| Autokey | `/svc/autokey/` | `/api/autokey/` |

All examples in this document use the dashboard proxy base path.

---

## 2. Format-Preserving Tokenization

### 2.1 What FPE Is

Format-Preserving Encryption (FPE) is a class of symmetric encryption where the ciphertext occupies the same format domain as the plaintext. For a numeric 16-digit credit card number, the FPE output is also a 16-digit numeric string. For a 9-digit SSN, the output is a 9-digit numeric string.

Vecta KMS implements **FF1** from **NIST SP 800-38G** (`pkg/crypto.FF1Encrypt`),
verified against NIST's nine published FF1 sample vectors.

**FF1 (NIST SP 800-38G, Section 5.1):**
- AES Feistel network (10 rounds) with a CBC-MAC PRF; variable radix and length
- Alphabet here: `0-9a-z` (radix 2 to 36), letter case preserved
- Minimum domain: radix^length >= 1,000,000 (for example, at least 6 decimal digits); maximum length 4096
- Tweak: the request's `tweak` string as bytes, up to 256 bytes
- Key: the AES-256 working key keycore derives for the `fpe` purpose

**FF3-1 is not offered.** NIST's SP 800-38G Rev. 1 draft withdraws it after
published attacks. Requests for `FF3`/`FF3-1` are refused and audited
(`audit.dataprotect.fpe_refused`).

**Ciphertext from before 1.26.0-beta.** Until 1.26.0-beta both names ran an
additive keystream, not FF1: its round keys never depended on the data, so one
known plaintext/ciphertext pair revealed every other value of the same length
under the same key and tweak. Treat that ciphertext as weakly protected and
migrate it:

1. Decrypt with `POST /fpe/decrypt` and `algorithm: "LEGACY-FF1"` (or
   `"LEGACY-FF3-1"` for values encrypted as FF3/FF3-1), with the same key,
   tweak and radix. This is decrypt-only and audited as
   `audit.dataprotect.fpe_legacy_decrypted`.
2. Re-encrypt with `POST /fpe/encrypt` (`algorithm: "FF1"`).
3. Replace the stored value. Legacy encrypt is refused.

**How FPE works conceptually:**
1. The plaintext string is split into a left half `A` and right half `B`.
2. Multiple rounds of AES-based pseudo-random function are applied, mixing the halves.
3. Each round output is reduced to the target alphabet using modular arithmetic.
4. The result is a ciphertext of identical length and alphabet as the input.
5. The process is fully reversible given the same key and tweak.

**Tweak values:**
The tweak is a domain-specific additional input that differentiates tokenization across contexts. Unlike a key, the tweak is not secret — it functions like an initialization vector. Examples:
- Merchant ID: `tweak = hex("MERCHANT-9001")` — tokens for the same PAN differ per merchant
- Tenant ID: isolates tokenization namespaces across tenants
- Static tweak: a constant 16-byte value fixed at scheme creation (simplest, most common)
- Field-level tweak: derived from a field name or record identifier at tokenization time

> **Security Note:** The tweak does not substitute for key secrecy. Two callers with the same key and tweak will produce identical tokens for the same input — this is intentional for lookup use cases. If token collisions across contexts are a risk, use different keys per context rather than different tweaks alone.

**Alphabet configuration:**
- Numeric: `0123456789` (10 symbols, radix 10) — for PANs, SSNs, account numbers
- Alphanumeric: `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` (62 symbols) — for codes, license plates
- Custom charset: any ordered set of unique printable characters, e.g. hex `0123456789abcdef`

### 2.2 PAN Tokenization

A Primary Account Number (PAN) is the 13–19 digit number embossed on a payment card. PCI DSS Requirement 3.3 prohibits storing the full PAN in cleartext.

**Luhn-valid token output:**
Many legacy payment systems validate incoming card numbers using the Luhn algorithm before processing. If a tokenized PAN fails the Luhn check, these systems reject the transaction. Vecta FPE supports `luhnPreserve: true`, which adjusts the final digit of the FPE output to ensure the result passes the Luhn check. This costs one digit of entropy (the last digit is forced) but maintains compatibility with any Luhn-validating system.

**Partial visibility (preservePrefix / preserveSuffix):**
For display purposes, card schemes define that the first 6 digits (BIN/IIN) and last 4 digits may be shown in cleartext. Vecta implements this via:
- `preservePrefix: 6` — the first 6 characters of the input are copied unchanged to the output
- `preserveSuffix: 4` — the last 4 characters are copied unchanged to the output
- Only the middle digits (positions 7–12 for a 16-digit PAN) are FPE-encrypted

**Example:**
```
Input PAN:    4532015112830366
After FPE:    4532874359820366
              ^^^^            ^^^^
              BIN (preserved) last-4 (preserved)
              Middle digits are FPE ciphertext
```

> **Note:** When `preservePrefix` and `preserveSuffix` overlap (input shorter than prefix+suffix), the entire string is treated as visible and FPE is skipped. Minimum FPE length is 2 characters after subtracting preserved regions.

### 2.3 SSN Tokenization

US Social Security Numbers have the format `XXX-XX-XXXX` (9 digits with dashes). Tokenization operates on the numeric content only:

1. Strip dashes: `123-45-6789` → `123456789` (9 digits)
2. Apply FF1 FPE with numeric alphabet, length 9
3. Re-apply dash format mask: result `987654321` → `987-65-4321`

The scheme `inputAlphabet` is `0123456789` and `minLength`/`maxLength` are both `9`. The dash insertion is handled by a format mask in the scheme configuration (`formatMask: "###-##-####"` where `#` represents a digit from the tokenized output).

> **Security Note:** SSNs have low entropy (only 9 digits, ~30 bits). FPE does not increase entropy — it permutes the space. For SSN storage, combine tokenization with access control and audit logging. Do not use SSN tokens as primary identifiers in publicly accessible systems.

### 2.4 Vault Tokenization (Non-FPE)

Vault mode generates a random opaque token and stores the mapping (token → original value) in a secure encrypted vault within Vecta KMS. Unlike FPE, the token has no mathematical relationship to the original value.

**Token formats:**
- `uuid`: Standard UUID v4 — `f47ac10b-58cc-4372-a567-0e02b2c3d479`
- `random_alphanumeric`: Configurable-length random string — `Xk9mP3qR7wL2`
- `custom_prefix`: Prefix + random suffix — `TKN-a8f2c9d1e4b3`

**Vault search:**
Because there is no mathematical relationship between token and original, retrieval requires a vault lookup:
- Look up by token: given `TKN-a8f2c9d1e4b3`, retrieve original value
- Look up by original: given original value, retrieve all tokens (useful for de-duplication)

**Trade-offs vs FPE:**
| | FPE | Vault |
|---|---|---|
| Format preserved | Yes | No |
| Lookup without vault | Yes (compute token directly) | No |
| Token reveals nothing about original | Depends on key security | Yes (random) |
| Storage required | No | Yes (token↔original mapping) |
| Suitable for PANs in legacy systems | Yes | Limited |
| Suitable for arbitrary strings | Yes | Yes |

### 2.5 Tokenization Scheme Configuration

A tokenization scheme encapsulates all parameters needed to tokenize and detokenize a class of values. Schemes are created once and referenced by ID at tokenization time.

**Full scheme object:**

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "pan-tokenizer",
  "description": "PCI DSS PAN tokenization using FF1 with Luhn preservation",
  "mode": "fpe",
  "algorithm": "FF1",
  "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "inputAlphabet": "0123456789",
  "outputAlphabet": "0123456789",
  "minLength": 13,
  "maxLength": 19,
  "tweakSource": "static",
  "staticTweak": "0123456789abcdef0123456789abcdef",
  "preservePrefix": 6,
  "preserveSuffix": 4,
  "luhnPreserve": true,
  "nullHandling": "passthrough",
  "createdAt": "2026-01-15T08:00:00Z",
  "updatedAt": "2026-01-15T08:00:00Z",
  "createdBy": "admin@example.com"
}
```

**Field-by-field reference:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | Yes | — | Unique human-readable identifier for the scheme within the tenant. Must match `^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$`. |
| `description` | string | No | `""` | Free-text description for documentation and audit purposes. |
| `mode` | string | Yes | — | Tokenization mode. One of: `fpe` (format-preserving encryption via FF1), `vault` (random token with vault storage), `format_preserving` (alias for `fpe`). |
| `algorithm` | string | Required if `mode=fpe` | — | FPE algorithm: `FF1` (FF3-1 is refused since 1.26.0-beta). Ignored for `mode=vault`. |
| `keyId` | string (UUID) | Yes | — | ID of the AES key in Vecta KMS to use for encryption. Key must have purpose `tokenize` or `encrypt`. Must be in `ACTIVE` state. |
| `inputAlphabet` | string | No | `"0123456789"` | Ordered set of unique characters that appear in the input. All input characters must belong to this set. Minimum 2 characters, maximum 95. |
| `outputAlphabet` | string | No | Same as `inputAlphabet` | Ordered set of unique characters for the output token. Must have same length as `inputAlphabet` (bijective mapping). Leave unset to use same alphabet as input. |
| `minLength` | int | No | `2` | Minimum input length (in characters). Inputs shorter than this are rejected. |
| `maxLength` | int | No | `256` | Maximum input length. Inputs longer than this are rejected. |
| `tweakSource` | string | No | `"static"` | How the FPE tweak is derived. One of: `static` (use `staticTweak` for every call), `field` (caller provides tweak per request), `random` (random tweak per call, stored in token). |
| `staticTweak` | string (hex) | Required if `tweakSource=static` | — | Exactly 32 hex characters (16 bytes) for FF1. |
| `preservePrefix` | int | No | `0` | Number of leading characters to copy unchanged from input to output. These characters are not encrypted. |
| `preserveSuffix` | int | No | `0` | Number of trailing characters to copy unchanged from input to output. These characters are not encrypted. |
| `luhnPreserve` | boolean | No | `false` | When `true`, the FPE output's final digit is adjusted to make the result pass the Luhn check. Only valid for numeric alphabet. |
| `nullHandling` | string | No | `"passthrough"` | Behavior when input is `null` or empty string. `passthrough`: return null/empty unchanged. `error`: return HTTP 422. `tokenize`: treat empty string as valid input. |
| `formatMask` | string | No | `null` | Optional display mask applied after tokenization. Use `#` as digit placeholder. Example: `"###-##-####"` for SSNs. |
| `vaultTokenFormat` | string | No | `"uuid"` | For `mode=vault` only. One of: `uuid`, `random_alphanumeric`, `custom_prefix`. |
| `vaultTokenLength` | int | No | `16` | For `mode=vault` with `random_alphanumeric`. Length of the random portion. |
| `vaultTokenPrefix` | string | No | `"TKN-"` | For `mode=vault` with `custom_prefix`. Prefix string. |

### 2.6 API Endpoints — Tokenization

All endpoints require `Authorization: Bearer $TOKEN` and `X-Tenant-ID: root` headers.

---

#### Create a Tokenization Scheme

Tokenization settings live in a token vault: `POST /svc/dataprotect/token-vaults`.

#### List Tokenization Schemes

`GET /svc/dataprotect/token-vaults`

#### Get a Scheme

`GET /svc/dataprotect/token-vaults/{id}`

#### Delete a Scheme

`DELETE /svc/dataprotect/token-vaults/{id}`

#### Tokenize a Single Value

`POST /svc/dataprotect/tokenize`

```bash
curl -X POST https://localhost/svc/dataprotect/tokenize \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "schemeId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "value": "4532015112830366"
  }'
```

**Response `200 OK`:**

```json
{
  "token": "4532874359820366",
  "schemeId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "preservedPrefix": "453201",
  "preservedSuffix": "0366",
  "luhnValid": true,
  "request_id": "req_dp_010"
}
```

---

#### Batch Tokenize

`POST /svc/dataprotect/tokenize/batch`

Up to 1000 values per request.

```bash
curl -X POST https://localhost/svc/dataprotect/tokenize/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "schemeId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "values": [
      "4532015112830366",
      "5425233430109903",
      "4916338506082832"
    ]
  }'
```

**Response `200 OK`:**

```json
{
  "items": [
    {"index": 0, "value": "4532015112830366", "token": "4532874359820366", "luhnValid": true, "error": null},
    {"index": 1, "value": "5425233430109903", "token": "5425711896340903", "luhnValid": true, "error": null},
    {"index": 2, "value": "4916338506082832", "token": "4916592047312832", "luhnValid": true, "error": null}
  ],
  "successCount": 3,
  "errorCount": 0,
  "request_id": "req_dp_011"
}
```

---

#### Detokenize a Single Value

`POST /svc/dataprotect/detokenize`

```bash
curl -X POST https://localhost/svc/dataprotect/detokenize \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "schemeId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "token": "4532874359820366"
  }'
```

**Response `200 OK`:**

```json
{
  "value": "4532015112830366",
  "schemeId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "request_id": "req_dp_020"
}
```

> **Security Note:** Every detokenize call is logged to the audit trail with the caller identity, scheme ID, and timestamp. Unauthorized bulk detokenization attempts trigger posture findings.

---

#### Batch Detokenize

`POST /svc/dataprotect/detokenize/batch`

```bash
curl -X POST https://localhost/svc/dataprotect/detokenize/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "schemeId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "tokens": ["4532874359820366", "5425711896340903"]
  }'
```

**Response `200 OK`:**

```json
{
  "items": [
    {"index": 0, "token": "4532874359820366", "value": "4532015112830366", "error": null},
    {"index": 1, "token": "5425711896340903", "value": "5425233430109903", "error": null}
  ],
  "successCount": 2,
  "errorCount": 0,
  "request_id": "req_dp_021"
}
```

---

## 3. Data Masking and Redaction

Data masking transforms sensitive values into representations that conceal the original while preserving enough structure for the intended audience. Unlike tokenization, masking is typically one-way: the original cannot be recovered from the masked output.

### 3.1 Masking Modes

Vecta KMS supports four masking modes:

**1. Static Masking**
A fixed masking pattern applied identically to all callers.

```
Input:   4532015112830366
Output:  XXXXXXXXXXXX0366   (visibleSuffix=4, maskChar='X')
```

Static masking is deterministic: the same input always produces the same masked output.

**2. Dynamic Masking**
The masking policy varies by the caller's assigned role(s).

```
Caller role: dba              → 4532015112830366    (full, no masking — roleExemption)
Caller role: analyst          → XXXXXXXXXXXX0366    (last 4 visible)
Caller role: support          → ************0366    (last 4, asterisk)
Caller role: auditor          → XXXXXXXXXXXXXXXX    (fully masked)
```

Dynamic masking requires the caller to present a JWT with role claims that the masking service evaluates against the policy's `dynamicRules`.

**3. Redaction**
The value is replaced entirely with `null` or an empty string `""`.

```
Input:   4532015112830366
Output:  null
```

Redaction is the correct choice for API responses to untrusted callers, log sanitization, and de-identification under HIPAA's Safe Harbor method.

**4. Format-Preserving Masking**
Original characters are replaced with random characters from the same alphabet, preserving length and character class. The output is not reversible.

```
Input:   4532015112830366   (all numeric, 16 chars)
Output:  7819302847561243   (random numeric, 16 chars, Luhn invalid)
```

> **Warning:** Format-preserving masking output is **not** Luhn-valid unless explicitly set. Systems that validate Luhn will reject these values. Use FPE tokenization (Section 2) when Luhn validity is required.

### 3.2 Masking Policy Configuration

**Full policy object:**

```json
{
  "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "name": "credit-card-masking",
  "description": "Dynamic masking by caller role for PAN fields",
  "fieldPattern": "pan|credit_card|card_number",
  "maskMode": "dynamic",
  "maskChar": "X",
  "visiblePrefix": 0,
  "visibleSuffix": 4,
  "formatPreserve": false,
  "redactToNull": false,
  "roleExemptions": ["dba", "payment-processor"],
  "dynamicRules": [
    {"roles": ["analyst"], "visiblePrefix": 0, "visibleSuffix": 4, "maskChar": "X"},
    {"roles": ["support"], "visiblePrefix": 0, "visibleSuffix": 4, "maskChar": "*"},
    {"roles": ["auditor"], "visiblePrefix": 0, "visibleSuffix": 0, "maskChar": "X"}
  ],
  "createdAt": "2026-03-23T10:00:00Z",
  "updatedAt": "2026-03-23T10:00:00Z",
  "createdBy": "admin@example.com"
}
```

**Field-by-field reference:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | Yes | — | Unique policy name within the tenant. |
| `description` | string | No | `""` | Documentation description. |
| `fieldPattern` | string | Yes | — | Regex or pipe-separated list of field name patterns this policy applies to. Matched against the `field` parameter in mask requests. |
| `maskMode` | string | Yes | — | One of: `static`, `dynamic`, `redact`, `format_preserving`. |
| `maskChar` | string (1 char) | No | `"X"` | Character used to replace masked digits/characters. Common values: `X`, `*`, `#`. Used in `static` and `dynamic` modes. |
| `visiblePrefix` | int | No | `0` | Number of leading characters to show unmasked. |
| `visibleSuffix` | int | No | `4` | Number of trailing characters to show unmasked. |
| `formatPreserve` | boolean | No | `false` | When `true` in `format_preserving` mode, output characters are drawn from the same character class as input. |
| `redactToNull` | boolean | No | `false` | When `true` in `redact` mode, return JSON `null` instead of empty string `""`. |
| `roleExemptions` | string[] | No | `[]` | Roles that bypass masking entirely and receive the original value. |
| `dynamicRules` | object[] | Required if `maskMode=dynamic` | `[]` | Ordered list of per-role masking rules. First matching rule wins. |
| `dynamicRules[].roles` | string[] | Yes | — | Role names this rule applies to. |
| `dynamicRules[].visiblePrefix` | int | Yes | — | Characters to show at start for this role. |
| `dynamicRules[].visibleSuffix` | int | Yes | — | Characters to show at end for this role. |
| `dynamicRules[].maskChar` | string | No | Parent `maskChar` | Override mask character for this role. |

---

#### Create a Masking Policy

`POST /svc/dataprotect/masking-policies`; list with `GET`, change with `PUT /svc/dataprotect/masking-policies/{id}`, delete with `DELETE /svc/dataprotect/masking-policies/{id}`.

#### Apply Masking to a Record

`POST /svc/dataprotect/mask`

```bash
curl -X POST https://localhost/svc/dataprotect/mask \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "policyId": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "callerRoles": ["analyst"],
    "record": {
      "customer_id": "C-10045",
      "card_number": "4532015112830366",
      "billing_zip": "94107",
      "cvv": "372"
    }
  }'
```

**Response `200 OK`:**

```json
{
  "maskedRecord": {
    "customer_id": "C-10045",
    "card_number": "XXXXXXXXXXXX0366",
    "billing_zip": "94107",
    "cvv": "372"
  },
  "appliedRules": {
    "card_number": {"policy": "credit-card-masking", "rule": "analyst", "visibleSuffix": 4}
  },
  "request_id": "req_dp_041"
}
```

---

### 3.3 Field Encryption

Field encryption encrypts individual fields with AES-256-GCM, supporting per-field associated data for integrity binding.

**Associated Data (AD):**
AES-GCM supports Additional Authenticated Data (AAD) that is authenticated but not encrypted. Standard associated data format used by Vecta:
```
AD = "{fieldName}:{recordId}:{tenantId}"
```
If any component changes (record moved, field renamed), decryption fails with an authentication error.

**Deterministic Encryption Mode:**
By default, AES-GCM uses a random 96-bit IV, producing different ciphertext each call. Deterministic mode derives the IV from:
```
IV = HMAC-SHA256(deterministicKey, plaintext || fieldName)[0:12]
```
This enables equality-search queries (`WHERE encrypted_ssn = ?`) without decrypting.

> **Security Note:** Deterministic encryption reveals when two records share the same plaintext value. For low-cardinality fields (boolean flags, status codes with few values) this leaks significant information. Use only for equality search on fields with adequate entropy.

**Key Rotation — Re-encrypt Endpoint:**
The re-encrypt endpoint accepts old ciphertext, decrypts with the current key version, and returns new ciphertext encrypted under the latest key version.

---

#### Encrypt a Field

`POST /svc/dataprotect/app/encrypt-fields` encrypts the named fields of a JSON document.

#### Decrypt a Field

`POST /svc/dataprotect/app/decrypt-fields` reverses `encrypt-fields`.

### 3.4 API Endpoints — Masking and Field Encryption

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/dataprotect/mask` | Apply masking to a single record |

---

## 5. PKCS#11 Provider

Vecta does not ship a PKCS#11 module. The earlier `services/pkcs11-provider`
exported no `C_GetFunctionList` (so OpenSSL, Java SunPKCS11, pkcs11-tool and
database TDE could not load it), ignored the requested mechanism and PIN, and
always signed as `SHA256withRSA`. It was removed in 1.27.0-beta; see
[REAL_CAPABILITY.md](SECURITY/REAL_CAPABILITY.md). Applications reach Vecta keys
through the REST API, the KMIP server (port 5696, mTLS), or the JCA provider
below. HSMs are integrated the other way round: Vecta loads the customer's own
PKCS#11 library in `hsm-connector` ([HSM_INTEGRATION.md](SECURITY/HSM_INTEGRATION.md)).

## 6. JCA/JCE Provider

The JCA provider is source in `services/jca-provider` (also downloadable as a
zip from the dashboard's Java SDK view, built from the same files). It
registers one service, `Cipher.VectaKeyWrap`, which wraps and unwraps keys
under a Vecta KMS TDE key through the ekm API; the Vecta key never leaves the
KMS. There is no local cipher, signature, key store or `SecureRandom`.

```java
Security.addProvider(new com.vecta.kms.VectaKMSProvider());
Cipher c = Cipher.getInstance("VectaKeyWrap", "VectaKMS");
c.init(Cipher.WRAP_MODE, new VectaKMSKey("tde_key_123"));
byte[] wrapped = c.wrap(dataKey);   // keep c.getIV() with it
```

Configuration: `VECTA_BASE_URL` (https only), `VECTA_TENANT_ID`,
`VECTA_AUTH_TOKEN`, optional `VECTA_CA_CERT`; TLS 1.3. It runs on OpenJDK
builds; Oracle JDK loads a `Cipher` provider only from a jar signed with an
Oracle JCE code-signing certificate. See `services/jca-provider/README.md`.

## 7. Autokey — Automatic Key Provisioning

### 7.1 What Autokey Is

Autokey gives application teams a self-service path to request cryptographic key handles without involving a KMS administrator for every request. Platform teams define **templates** that encode approved algorithms, purposes, naming conventions, and rotation schedules. Developers request a handle that conforms to a template; the system either provisions the key immediately or routes it through a governance approval flow for exceptional cases.

Key properties of Autokey:

- **Templates encode standards.** Algorithm choice, key size, rotation period, purpose, and required tags are all captured in the template. Developers cannot deviate from them without admin involvement.
- **Handles are stable references.** A handle is a logical identifier bound to a KMS key. Application code references the handle name rather than a raw key ID, so key rotation is transparent.
- **Approval is optional per template.** Templates can be marked `requiresApproval: false` for common low-risk keys (e.g., per-service AES-256 DEKs) and `requiresApproval: true` for sensitive ones (e.g., CA signing keys, cross-tenant KEKs).
- **Governance engine integration.** Approval-required requests enter the existing Vecta governance approval queue; no separate approval system is needed.

Autokey is surfaced in the dashboard under **Autokey** and its state feeds **Posture** and **Compliance** cards.

API prefix (dashboard proxy): `/svc/autokey/autokey/`

### 7.2 Template Configuration

A template defines the properties that all keys provisioned under it must have.

**Full template object:**

```json
{
  "id": "e5f6a7b8-c9d0-1234-efab-567890123456",
  "name": "service-data-encryption-key",
  "description": "Standard AES-256-GCM DEK for application services",
  "keyAlgorithm": "AES",
  "keySize": 256,
  "keyPurposes": ["encrypt", "decrypt"],
  "rotationPeriodDays": 90,
  "requiresApproval": false,
  "handleNamePattern": "{service}-dek-{env}",
  "requiredTags": {
    "managed-by": "autokey",
    "template": "service-data-encryption-key"
  },
  "allowedRequestorRoles": ["developer", "service-account"],
  "maxHandlesPerRequestor": 5,
  "keyExpiryDays": 0,
  "createdAt": "2026-01-10T08:00:00Z",
  "updatedAt": "2026-01-10T08:00:00Z",
  "createdBy": "platform-admin@example.com"
}
```

**Field-by-field reference:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | Yes | — | Unique template name. Used in handle name patterns and audit trails. |
| `description` | string | No | `""` | Human-readable purpose of this template. |
| `keyAlgorithm` | string | Yes | — | Key algorithm. One of: `AES`, `RSA`, `EC`, `Ed25519`, `HMAC`. |
| `keySize` | int | Yes for AES/RSA | — | Key size in bits. AES: 128/192/256. RSA: 2048/3072/4096. EC: use `keyCurve` instead. |
| `keyCurve` | string | Yes for EC | — | EC named curve. One of: `P-256`, `P-384`, `P-521`, `Ed25519`. |
| `keyPurposes` | string[] | Yes | — | Allowed purposes. Valid values: `encrypt`, `decrypt`, `sign`, `verify`, `wrap`, `unwrap`, `derive`, `tokenize`. |
| `rotationPeriodDays` | int | No | `365` | Days between automatic key rotations. Set `0` to disable automatic rotation. |
| `requiresApproval` | boolean | No | `false` | When `true`, handle requests enter the governance approval queue before provisioning. |
| `handleNamePattern` | string | No | `"{template}-{uuid}"` | Pattern for auto-generated handle names. Variables: `{service}`, `{env}`, `{uuid}`, `{template}`. |
| `requiredTags` | map[string]string | No | `{}` | Tags automatically applied to every key provisioned under this template. |
| `allowedRequestorRoles` | string[] | No | `["developer"]` | KMS roles permitted to create handle requests using this template. |
| `maxHandlesPerRequestor` | int | No | `10` | Maximum active handles any single requestor identity may hold under this template. |
| `keyExpiryDays` | int | No | `0` | Days until the provisioned key expires automatically. `0` = no expiry. |
| `justificationRequired` | boolean | No | `false` | Whether the requestor must supply a free-text business justification when creating a handle request. |

---

#### Create a Template (Admin)

`POST /svc/autokey/autokey/templates`

```bash
curl -X POST https://localhost/svc/autokey/autokey/templates \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "service-data-encryption-key",
    "description": "Standard AES-256-GCM DEK for application services",
    "keyAlgorithm": "AES",
    "keySize": 256,
    "keyPurposes": ["encrypt", "decrypt"],
    "rotationPeriodDays": 90,
    "requiresApproval": false,
    "handleNamePattern": "{service}-dek-{env}",
    "requiredTags": {
      "managed-by": "autokey",
      "template": "service-data-encryption-key"
    },
    "allowedRequestorRoles": ["developer", "service-account"],
    "maxHandlesPerRequestor": 5
  }'
```

**Response `201 Created`:**

```json
{
  "item": {
    "id": "e5f6a7b8-c9d0-1234-efab-567890123456",
    "name": "service-data-encryption-key",
    "keyAlgorithm": "AES",
    "keySize": 256,
    "keyPurposes": ["encrypt", "decrypt"],
    "rotationPeriodDays": 90,
    "requiresApproval": false,
    "handleNamePattern": "{service}-dek-{env}",
    "allowedRequestorRoles": ["developer", "service-account"],
    "maxHandlesPerRequestor": 5,
    "createdAt": "2026-03-23T11:00:00Z",
    "createdBy": "platform-admin@example.com"
  },
  "request_id": "req_ak_001"
}
```

---

#### List Templates

`GET /svc/autokey/autokey/templates`

```bash
curl "https://localhost/svc/autokey/autokey/templates?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `200 OK`:**

```json
{
  "items": [
    {
      "id": "e5f6a7b8-c9d0-1234-efab-567890123456",
      "name": "service-data-encryption-key",
      "keyAlgorithm": "AES",
      "keySize": 256,
      "requiresApproval": false,
      "createdAt": "2026-03-23T11:00:00Z"
    },
    {
      "id": "f6a7b8c9-d0e1-2345-fabc-678901234567",
      "name": "ca-signing-key",
      "keyAlgorithm": "EC",
      "keyCurve": "P-384",
      "requiresApproval": true,
      "createdAt": "2026-03-23T11:05:00Z"
    }
  ],
  "totalCount": 2,
  "request_id": "req_ak_002"
}
```

### 7.3 Handle Request Workflow

The complete lifecycle of a handle request from developer to provisioned key:

**Step 1 — Developer requests a handle**

**Response `202 Accepted`** (immediate provisioning since `requiresApproval: false`):

```json
{
  "item": {
    "id": "g7b8c9d0-e1f2-3456-gabc-789012345678",
    "handleName": "payments-service-dek-prod",
    "templateId": "e5f6a7b8-c9d0-1234-efab-567890123456",
    "status": "provisioning",
    "requestedBy": "dev-user@example.com",
    "requestedAt": "2026-03-23T11:10:00Z",
    "keyId": null,
    "approvalRequired": false
  },
  "request_id": "req_ak_010"
}
```

**Step 2 — Poll handle status** (for async provisioning)

**Response `200 OK`** (provisioning complete):

```json
{
  "item": {
    "id": "g7b8c9d0-e1f2-3456-gabc-789012345678",
    "handleName": "payments-service-dek-prod",
    "templateId": "e5f6a7b8-c9d0-1234-efab-567890123456",
    "status": "active",
    "requestedBy": "dev-user@example.com",
    "requestedAt": "2026-03-23T11:10:00Z",
    "provisionedAt": "2026-03-23T11:10:02Z",
    "keyId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "keyAlgorithm": "AES",
    "keySize": 256,
    "rotationPeriodDays": 90,
    "nextRotationAt": "2026-06-21T11:10:02Z",
    "tags": {
      "managed-by": "autokey",
      "template": "service-data-encryption-key",
      "service": "payments-service",
      "env": "prod"
    },
    "approvalRequired": false
  },
  "request_id": "req_ak_011"
}
```

**Step 3 — Application uses handle name to resolve key ID** (for approval-required templates, this step comes after admin approval)

The application resolves the handle name to a KMS key ID at startup, then uses the key ID for cryptographic operations:

```bash
# Resolve handle name to key ID
curl "https://localhost/svc/autokey/autokey/handles?handleName=payments-service-dek-prod" \
  -H "Authorization: Bearer $SVC_TOKEN" \
  -H "X-Tenant-ID: root"
```

**Step 4 — Admin approves an approval-required request** (for templates with `requiresApproval: true`)

**Response `200 OK`:**

```json
{
  "item": {
    "id": "h8c9d0e1-f2a3-4567-habc-890123456789",
    "status": "provisioning",
    "approvedBy": "platform-admin@example.com",
    "approvedAt": "2026-03-23T11:30:00Z",
    "comment": "Approved for production CA signing key — reviewed CSR and key purpose"
  },
  "request_id": "req_ak_020"
}
```

**Step 5 — Admin rejects a request**

**Response `200 OK`:**

```json
{
  "item": {
    "id": "h8c9d0e1-f2a3-4567-habc-890123456789",
    "status": "rejected",
    "rejectedBy": "platform-admin@example.com",
    "rejectedAt": "2026-03-23T11:35:00Z",
    "reason": "CA signing keys require a separate governance ceremony."
  },
  "request_id": "req_ak_021"
}
```

### 7.4 API Endpoints — Autokey

| Method | Path | Description | Role |
|---|---|---|---|
| `GET` | `/svc/autokey/autokey/templates` | List templates | Admin |
| `POST` | `/svc/autokey/autokey/templates` | Create template | Admin |
| `DELETE` | `/svc/autokey/autokey/templates/{id}` | Delete template | Admin |
| `GET` | `/svc/autokey/autokey/handles` | List handles (filter by status, template) | Developer/Admin |

---

## 8. Secrets Vault

### 8.1 Overview

The Secrets Vault stores arbitrary key-value secrets with full versioning, hierarchical namespacing, and fine-grained access policy. It is distinct from the cryptographic key store: the Secrets Vault holds strings and blobs (passwords, API keys, connection strings, certificates as PEM), while the key store holds cryptographic key material.

Key properties:

- **Hierarchical path namespace.** Secrets are addressed by a path such as `/apps/payments/prod/db-password`. Access policies are assigned per path prefix, so a service account can be granted access to `/apps/payments/prod/*` without accessing `/apps/billing/`.
- **Full versioning.** Every `PUT` to an existing path creates a new version. The previous version is retained until explicitly destroyed. Reads default to the latest version; specific versions can be retrieved.
- **Encrypted at rest.** Secret values are encrypted with an AES-256-GCM key managed by Vecta KMS. The encryption key itself is subject to full KMS key lifecycle controls.
- **Soft delete and hard delete.** Soft delete (`DELETE`) marks a secret inactive but retains all versions for recovery. Hard delete (`destroy`) permanently removes a specific version with no recovery.
- **Expiry.** Secrets can carry an `expiresAt` timestamp. Expired secrets are not returned by default and trigger posture findings if not rotated.

API prefix (dashboard proxy): `/svc/secrets/`

### 8.2 Secret Object Schema

**Full secret object:**

```json
{
  "path": "/apps/payments/prod/db-password",
  "value": "s3cur3-db-pa$$w0rd-2026",
  "version": 3,
  "metadata": {
    "owner": "payments-team",
    "rotation-schedule": "90d",
    "jira-ticket": "INFRA-4421"
  },
  "expiresAt": "2026-06-23T00:00:00Z",
  "createdAt": "2026-03-23T09:00:00Z",
  "createdBy": "platform-admin@example.com",
  "updatedAt": "2026-03-23T09:00:00Z",
  "updatedBy": "platform-admin@example.com",
  "active": true
}
```

**Field-by-field reference:**

| Field | Type | Description |
|---|---|---|
| `path` | string | Hierarchical path. Must start with `/`. Segments separated by `/`. Max 512 characters. Path is the primary identifier. |
| `value` | string | The secret value. Stored encrypted at rest. Max 65,536 bytes. Binary values should be base64-encoded before storage. |
| `version` | int | Auto-incremented version number. Version 1 is the initial creation; every `PUT` increments by 1. |
| `metadata` | map[string]string | Arbitrary key-value metadata stored with the secret. Not encrypted — do not store sensitive data in metadata. |
| `expiresAt` | string (ISO 8601) | Optional expiry timestamp. After this time, the secret is excluded from default list/get responses and triggers a posture finding. Null = no expiry. |
| `createdAt` | string (ISO 8601) | Timestamp of initial secret creation (version 1). |
| `createdBy` | string | Identity that created the secret (version 1). |
| `updatedAt` | string (ISO 8601) | Timestamp of the latest version creation. |
| `updatedBy` | string | Identity that created the latest version. |
| `active` | boolean | `false` after soft delete. Soft-deleted secrets are excluded from list results by default. |

### 8.3 API Endpoints — Secrets

#### List Secrets by Prefix

`GET /svc/secrets/secrets`

Query parameters: `prefix` (string, path prefix filter), `pageSize` (int), `pageToken` (string), `includeExpired` (boolean, default false), `includeDeleted` (boolean, default false).

```bash
curl "https://localhost/svc/secrets/secrets?prefix=/apps/payments/prod/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `200 OK`:**

```json
{
  "items": [
    {
      "path": "/apps/payments/prod/db-password",
      "version": 3,
      "expiresAt": "2026-06-23T00:00:00Z",
      "updatedAt": "2026-03-23T09:00:00Z",
      "active": true
    },
    {
      "path": "/apps/payments/prod/stripe-api-key",
      "version": 1,
      "expiresAt": null,
      "updatedAt": "2026-01-15T08:00:00Z",
      "active": true
    }
  ],
  "nextPageToken": null,
  "totalCount": 2,
  "request_id": "req_sec_001"
}
```

> **Note:** Values are not returned in list responses. Fetch individual secrets by path to retrieve the value.

---

#### Create a Secret

`POST /svc/secrets/secrets`

```bash
curl -X POST https://localhost/svc/secrets/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/apps/payments/prod/db-password",
    "value": "s3cur3-db-pa$$w0rd-2026",
    "metadata": {
      "owner": "payments-team",
      "rotation-schedule": "90d",
      "jira-ticket": "INFRA-4421"
    },
    "expiresAt": "2026-06-23T00:00:00Z"
  }'
```

**Response `201 Created`:**

```json
{
  "item": {
    "path": "/apps/payments/prod/db-password",
    "version": 1,
    "metadata": {
      "owner": "payments-team",
      "rotation-schedule": "90d",
      "jira-ticket": "INFRA-4421"
    },
    "expiresAt": "2026-06-23T00:00:00Z",
    "createdAt": "2026-03-23T09:00:00Z",
    "createdBy": "platform-admin@example.com",
    "active": true
  },
  "request_id": "req_sec_002"
}
```

---

#### Get Latest Secret Version

`GET /svc/secrets/secrets/{path}`

The `{path}` parameter is URL-encoded. Use `%2F` for `/`.

```bash
curl "https://localhost/svc/secrets/secrets/%2Fapps%2Fpayments%2Fprod%2Fdb-password" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `200 OK`:**

```json
{
  "item": {
    "path": "/apps/payments/prod/db-password",
    "value": "s3cur3-db-pa$$w0rd-2026",
    "version": 3,
    "metadata": {"owner": "payments-team", "rotation-schedule": "90d"},
    "expiresAt": "2026-06-23T00:00:00Z",
    "createdAt": "2026-03-23T09:00:00Z",
    "updatedAt": "2026-03-23T09:00:00Z",
    "active": true
  },
  "request_id": "req_sec_003"
}
```

---

#### Create New Version (Update)

`PUT /svc/secrets/secrets/{path}`

```bash
curl -X PUT \
  "https://localhost/svc/secrets/secrets/%2Fapps%2Fpayments%2Fprod%2Fdb-password" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "value": "n3w-s3cur3-db-pa$$w0rd-Q2-2026",
    "metadata": {
      "owner": "payments-team",
      "rotation-schedule": "90d",
      "rotated-by": "ci-pipeline"
    },
    "expiresAt": "2026-09-23T00:00:00Z"
  }'
```

**Response `200 OK`:**

```json
{
  "item": {
    "path": "/apps/payments/prod/db-password",
    "version": 4,
    "updatedAt": "2026-03-23T12:00:00Z",
    "updatedBy": "ci-pipeline@example.com",
    "active": true
  },
  "request_id": "req_sec_004"
}
```

---

#### Soft Delete a Secret

`DELETE /svc/secrets/secrets/{path}`

Marks the secret inactive. All versions are retained and recoverable. The secret no longer appears in list results by default.

```bash
curl -X DELETE \
  "https://localhost/svc/secrets/secrets/%2Fapps%2Fpayments%2Fprod%2Fdb-password" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `204 No Content`**

---

#### List Versions

`GET /svc/secrets/secrets/{path}/versions`

```bash
curl "https://localhost/svc/secrets/secrets/%2Fapps%2Fpayments%2Fprod%2Fdb-password/versions" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `200 OK`:**

```json
{
  "items": [
    {"version": 4, "createdAt": "2026-03-23T12:00:00Z", "createdBy": "ci-pipeline@example.com", "active": true, "destroyed": false},
    {"version": 3, "createdAt": "2026-03-01T09:00:00Z", "createdBy": "platform-admin@example.com", "active": true, "destroyed": false},
    {"version": 2, "createdAt": "2026-01-15T08:00:00Z", "createdBy": "platform-admin@example.com", "active": false, "destroyed": true},
    {"version": 1, "createdAt": "2026-01-01T08:00:00Z", "createdBy": "platform-admin@example.com", "active": false, "destroyed": false}
  ],
  "path": "/apps/payments/prod/db-password",
  "request_id": "req_sec_011"
}
```

---

## 9. Use Cases

### 9.1 PCI DSS: End-to-End PAN Tokenization at Checkout

**Context:** An e-commerce platform processes card-present and card-not-present transactions. The checkout service must not store raw PANs. The order management service needs to display the last 4 digits. The fraud service needs to compare PANs across sessions without decrypting.

**Compliance notes:** PCI DSS Requirements 3.3, 3.5, 3.6, 12.3.3.

**Prerequisites:**
- AES-256 key created in Vecta KMS with purpose `tokenize`, tagged `env=prod, use=pan-tokenization`
- FPE tokenization scheme `pan-tokenizer` created (see Section 2.6)
- Checkout service holds `dataprotect:tokenize` permission
- Order/fraud services hold `dataprotect:tokenize` but NOT `dataprotect:detokenize`
- Only the settlement service holds `dataprotect:detokenize`

**Step 1 — Checkout receives raw PAN from card terminal/browser:**

```bash
# Checkout service tokenizes PAN at the point of receipt
curl -X POST https://localhost/svc/dataprotect/tokenize \
  -H "Authorization: Bearer $CHECKOUT_TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "schemeId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "value": "4532015112830366"
  }'
# Response: token = "4532874359820366"
# Raw PAN is immediately discarded. Only the token is stored.
```

**Step 2 — Order management displays card to customer:**

The token `4532874359820366` has `preservePrefix=6` and `preserveSuffix=4`, so the order display shows `453201XXXXXX0366` — computed from the visible portions of the token without any API call.

**Step 3 — Fraud service compares PANs across sessions:**

Because FF1 FPE is deterministic (same key + tweak + input → same output), the fraud service can compare token values directly: if two sessions produce the same token, they used the same PAN. No decryption required.

**Step 4 — Settlement service detokenizes for network submission:**

```bash
curl -X POST https://localhost/svc/dataprotect/detokenize \
  -H "Authorization: Bearer $SETTLEMENT_TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "schemeId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "token": "4532874359820366"
  }'
# Returns original PAN 4532015112830366 for network authorization
# This call is logged to the audit trail
```

**Compliance outcome:** Raw PAN never stored in the checkout, order, or fraud databases. Settlement is the only system with `detokenize` permission, creating a narrow, auditable decryption surface.

---

### 9.2 HIPAA: PHI Field Encryption Per Patient

**Context:** A health information system stores patient records in PostgreSQL. The `ssn`, `dob`, `diagnosis_codes`, and `medication_list` columns contain PHI that must be encrypted at rest per the HIPAA Security Rule.

**Compliance notes:** 45 CFR 164.312(a)(2)(iv), 164.312(e)(2)(ii), 164.514(b).

**Prerequisites:**
- AES-256 key `phi-encryption-key` in Vecta KMS, purpose `encrypt`, tagged `data-class=phi`
- Application service account holds `dataprotect:encrypt` and `dataprotect:decrypt`
- Compliance team holds `dataprotect:reencrypt` for key rotation

**Step 1 — Encrypt SSN on record creation:**

```bash
# Store ciphertext "AQIDAHjK..." in the ssn column
```

**Step 2 — Encrypt SSN with deterministic mode for equality search:**

If the application needs `SELECT * FROM patients WHERE ssn = ?`:

```bash
# Same SSN always produces same ciphertext — allows index-based search
# Security trade-off: reveals that two patients have the same SSN
```

**Step 3 — Key rotation (annual or on incident):**

```bash
# Update DB: SET ssn = newCiphertext WHERE patient_id = 'patient-00192'
```

**Compliance outcome:** PHI columns contain only AES-256-GCM ciphertext. Key rotation is fully auditable. Associated data binding ensures ciphertext cannot be silently relocated to a different patient record.

---

### 9.3 Data Warehouse Dynamic Masking

**Context:** A data analytics platform exposes a read-only API over the data warehouse. Data scientists, support engineers, and external auditors all query the same API with different data access needs.

**Prerequisites:**
- Masking policy `credit-card-masking` created (see Section 3.2)
- Masking policy `phi-masking` created for PHI fields
- Each caller JWT contains a `roles` claim: `["analyst"]`, `["support"]`, or `["auditor"]`

**Step 1 — Analyst queries customer records:**

The API gateway extracts the caller's roles from the JWT and passes them to the masking service:

**Response — analyst sees:**

```json
{
  "items": [
    {
      "maskedRecord": {
        "customer_id": "C-10045",
        "card_number": "XXXXXXXXXXXX0366",
        "ssn": "XXX-XX-6789",
        "full_name": "Jane Smith",
        "transaction_amount": 142.50
      }
    }
  ]
}
```

**Step 2 — Auditor queries same records (fully masked):**

Pass `"callerRoles": ["auditor"]` — the auditor dynamic rule specifies `visibleSuffix: 0`, so both `card_number` and `ssn` are fully replaced with `X`.

**Step 3 — DBA queries for debugging (role exemption):**

Pass `"callerRoles": ["dba"]` — the `roleExemptions` list includes `dba`, so the original values are returned unmasked.

**Compliance outcome:** A single masking policy definition controls data visibility for all consumer roles. Policy changes take effect immediately without application code changes. All mask calls are audited with caller role and policy ID.

---

### 9.4 Java Microservice Using JCA — Zero Code Change

**Context:** A Java service encrypts records with AES-GCM data keys and
wants those data keys protected by a Vecta KMS key (envelope encryption).

The service keeps its own `AES/GCM/NoPadding` cipher (the JVM's provider) for
the data, and uses the Vecta provider only to wrap and unwrap each data key:

```java
Security.addProvider(new VectaKMSProvider());
KeyGenerator gen = KeyGenerator.getInstance("AES");
gen.init(256);
SecretKey dataKey = gen.generateKey();

Cipher kek = Cipher.getInstance("VectaKeyWrap", "VectaKMS");
kek.init(Cipher.WRAP_MODE, new VectaKMSKey("tde_key_123"));
byte[] wrappedDataKey = kek.wrap(dataKey);
byte[] wrapIV = kek.getIV();          // store both with the ciphertext

Cipher data = Cipher.getInstance("AES/GCM/NoPadding");   // JVM provider
data.init(Cipher.ENCRYPT_MODE, dataKey);
byte[] ciphertext = data.doFinal(plaintext);
```

To read, unwrap the data key with `UNWRAP_MODE` and
`new IvParameterSpec(wrapIV)`, then decrypt locally. Every wrap and unwrap is
a KMS call, checked against the key's access policy and audited
(`audit.ekm.tde_key_accessed`).

### 9.5 Autokey for Microservice Fleet — Self-Service

**Context:** A platform engineering team manages 40+ microservices. Each service needs its own AES-256 DEK for encrypting data at rest. Previously, developers opened tickets and waited 3–5 days for a KMS admin to provision keys manually.

**Prerequisites:**
- Autokey template `service-data-encryption-key` created (see Section 7.2)
- Platform team has assigned `allowedRequestorRoles: ["developer", "service-account"]`
- CI/CD pipeline service account holds the `developer` KMS role

**Step 1 — Developer requests a handle during service onboarding:**

**Response:** Handle provisioned immediately (no approval required for this template). `keyId` returned within 2 seconds.

**Step 2 — Service reads its key ID from the handle at startup:**

```bash
# Startup script resolves handle → key ID
KEY_ID=$(curl -s \
  "https://localhost/svc/autokey/autokey/handles?handleName=inventory-service-dek-prod" \
  -H "Authorization: Bearer $SVC_TOKEN" \
  -H "X-Tenant-ID: root" \
  | jq -r '.items[0].keyId')

export VECTA_DEK_KEY_ID=$KEY_ID
```

**Step 3 — Service uses the key ID for field encryption at runtime:**

```bash
    \"keyId\": \"$VECTA_DEK_KEY_ID\",
    \"fieldName\": \"product_cost\",
    \"recordId\": \"SKU-00912\",
    \"plaintext\": \"47.99\"
  }"
```

**Step 4 — Key rotation is automatic.**

The template specifies `rotationPeriodDays: 90`. Vecta KMS automatically rotates the key at the scheduled interval. The handle name (`inventory-service-dek-prod`) remains stable; the `keyId` behind it is updated. The service resolves the key ID at each startup, so it always uses the current key version without any code change.

**Step 5 — Platform admin monitors Autokey usage:**

```bash
# Summary of all handle requests across the fleet
curl "https://localhost/svc/autokey/autokey/summary?tenant_id=root" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response:**

```json
{
  "summary": {
    "templateCount": 4,
    "servicePolicyCount": 12,
    "handleCount": 47,
    "pendingApprovals": 2,
    "provisionedLast24h": 3,
    "deniedOrFailed": 0,
    "policyMatchedCount": 47,
    "policyMismatchCount": 0
  },
  "request_id": "req_ak_100"
}
```

**Compliance outcome:** Every key provisioned under Autokey carries the `managed-by: autokey` and `template: service-data-encryption-key` tags, making the fleet inventory auditable. Platform teams can prove that all 47 service DEKs conform to the approved AES-256 standard without reviewing individual key records. Autokey state feeds the Compliance and Posture dashboards directly.
