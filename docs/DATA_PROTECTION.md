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
4. [Payment Cryptography](#4-payment-cryptography)
   - [TR-31 Key Blocks](#41-tr-31-key-blocks)
   - [PIN Block Formats](#42-pin-block-formats)
   - [ISO 20022 Signing](#43-iso-20022-signing)
   - [API Endpoints — Payment](#44-api-endpoints--payment)
5. [PKCS#11 Provider](#5-pkcs11-provider)
   - [What PKCS#11 Is](#51-what-pkcs11-is)
   - [Installation](#52-installation)
   - [Configuration](#53-configuration)
   - [Supported Mechanisms](#54-supported-mechanisms)
   - [Integration Examples](#55-integration-examples)
6. [JCA/JCE Provider](#6-jcajce-provider)
   - [Dependency and Setup](#61-dependency-and-setup)
   - [Supported Algorithms](#62-supported-algorithms)
   - [Java Code Examples](#63-java-code-examples)
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
   - [TR-31 Key Injection into POS Terminals](#93-tr-31-key-injection-into-pos-terminals)
   - [ATM PIN Change Flow](#94-atm-pin-change-flow)
   - [Data Warehouse Dynamic Masking](#95-data-warehouse-dynamic-masking)
   - [Java Microservice Using JCA — Zero Code Change](#96-java-microservice-using-jca--zero-code-change)
   - [PostgreSQL Column Encryption via PKCS#11](#97-postgresql-column-encryption-via-pkcs11)
   - [Autokey for Microservice Fleet — Self-Service](#98-autokey-for-microservice-fleet--self-service)

---

## 1. Overview

Vecta KMS separates two concerns that are often conflated:

- **Key management** governs the lifecycle of cryptographic keys — generation, rotation, distribution, destruction, and access policy. The core KMS services handle this.
- **Data protection** uses those keys to transform sensitive data at the application layer — tokenizing PANs, masking PII fields, encrypting database columns, or participating in payment-industry protocols such as TR-31 and PIN block translation.

All data-protection endpoints are hosted under the `/svc/dataprotect/` base path and run inside the `dataprotect` service behind the Envoy edge. Payment-specific endpoints use `/svc/payment/`. Both services authenticate via the standard `Authorization: Bearer <jwt>` header and require `X-Tenant-ID` for multi-tenant deployments.

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
| Payment Crypto | `/svc/payment/` | `/api/payment/` |
| Secrets Vault | `/svc/secrets/` | `/api/secrets/` |
| Autokey | `/svc/autokey/` | `/api/autokey/` |

All examples in this document use the dashboard proxy base path.

---

## 2. Format-Preserving Tokenization

### 2.1 What FPE Is

Format-Preserving Encryption (FPE) is a class of symmetric encryption where the ciphertext occupies the same format domain as the plaintext. For a numeric 16-digit credit card number, the FPE output is also a 16-digit numeric string. For a 9-digit SSN, the output is a 9-digit numeric string.

Vecta KMS implements the two NIST-standardized FPE modes from **NIST SP 800-38G**:

**FF1 (NIST SP 800-38G, Section 5.1):**
- Based on AES in Feistel network mode with variable radix and length
- Supports tweaks up to 2^32 bytes (practically unlimited)
- Requires minimum plaintext length of 2 characters in the specified alphabet
- Best choice for general-purpose FPE; PCI DSS and HIPAA use cases
- Underlying key: AES-128, AES-192, or AES-256

**FF3-1 (NIST SP 800-38G, Section 5.2, Revised):**
- Also AES-based Feistel; tweak is exactly 7 bytes (56 bits)
- Faster than FF1 for short strings (credit card numbers, SSNs)
- Note: FF3 (original) had a known attack reducing security margin; FF3-1 fixes the tweak construction. Vecta implements FF3-1 only.

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
| `mode` | string | Yes | — | Tokenization mode. One of: `fpe` (format-preserving encryption via FF1/FF3-1), `vault` (random token with vault storage), `format_preserving` (alias for `fpe`). |
| `algorithm` | string | Required if `mode=fpe` | — | FPE algorithm. One of: `FF1`, `FF3-1`. Ignored for `mode=vault`. |
| `keyId` | string (UUID) | Yes | — | ID of the AES key in Vecta KMS to use for encryption. Key must have purpose `tokenize` or `encrypt`. Must be in `ACTIVE` state. |
| `inputAlphabet` | string | No | `"0123456789"` | Ordered set of unique characters that appear in the input. All input characters must belong to this set. Minimum 2 characters, maximum 95. |
| `outputAlphabet` | string | No | Same as `inputAlphabet` | Ordered set of unique characters for the output token. Must have same length as `inputAlphabet` (bijective mapping). Leave unset to use same alphabet as input. |
| `minLength` | int | No | `2` | Minimum input length (in characters). Inputs shorter than this are rejected. |
| `maxLength` | int | No | `256` | Maximum input length. Inputs longer than this are rejected. |
| `tweakSource` | string | No | `"static"` | How the FPE tweak is derived. One of: `static` (use `staticTweak` for every call), `field` (caller provides tweak per request), `random` (random tweak per call, stored in token). |
| `staticTweak` | string (hex) | Required if `tweakSource=static` | — | Exactly 32 hex characters (16 bytes) for FF1; exactly 14 hex characters (7 bytes) for FF3-1. |
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

`POST /svc/dataprotect/schemes`

```bash
curl -X POST http://localhost:5173/svc/dataprotect/schemes \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "pan-tokenizer",
    "description": "PCI DSS compliant PAN tokenization using FF1",
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
    "nullHandling": "passthrough"
  }'
```

**Response `201 Created`:**

```json
{
  "item": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "pan-tokenizer",
    "description": "PCI DSS compliant PAN tokenization using FF1",
    "mode": "fpe",
    "algorithm": "FF1",
    "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "inputAlphabet": "0123456789",
    "outputAlphabet": "0123456789",
    "minLength": 13,
    "maxLength": 19,
    "tweakSource": "static",
    "preservePrefix": 6,
    "preserveSuffix": 4,
    "luhnPreserve": true,
    "nullHandling": "passthrough",
    "createdAt": "2026-03-23T10:00:00Z",
    "updatedAt": "2026-03-23T10:00:00Z",
    "createdBy": "admin@example.com"
  },
  "request_id": "req_dp_001"
}
```

> **Note:** The `staticTweak` is stored internally but never returned in read responses to minimize exposure. Store it separately if you need to audit the tweak value.

---

#### List Tokenization Schemes

`GET /svc/dataprotect/schemes`

Query parameters: `pageSize` (int, default 20), `pageToken` (string, for pagination), `mode` (filter by mode: `fpe`, `vault`).

```bash
curl "http://localhost:5173/svc/dataprotect/schemes?pageSize=10&mode=fpe" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `200 OK`:**

```json
{
  "items": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "name": "pan-tokenizer",
      "mode": "fpe",
      "algorithm": "FF1",
      "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "createdAt": "2026-03-23T10:00:00Z"
    },
    {
      "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "name": "ssn-tokenizer",
      "mode": "fpe",
      "algorithm": "FF1",
      "keyId": "4ab96g75-6828-5673-c4gd-3d074g77bgb7",
      "createdAt": "2026-03-23T10:05:00Z"
    }
  ],
  "nextPageToken": null,
  "totalCount": 2,
  "request_id": "req_dp_002"
}
```

---

#### Get a Scheme

`GET /svc/dataprotect/schemes/{id}`

```bash
curl "http://localhost:5173/svc/dataprotect/schemes/a1b2c3d4-e5f6-7890-abcd-ef1234567890" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `200 OK`:** Returns the full scheme object (same shape as create response, minus `staticTweak`).

---

#### Update a Scheme

`PATCH /svc/dataprotect/schemes/{id}`

Only `name`, `description`, and `nullHandling` are mutable after creation. Algorithm and key changes require creating a new scheme.

```bash
curl -X PATCH \
  "http://localhost:5173/svc/dataprotect/schemes/a1b2c3d4-e5f6-7890-abcd-ef1234567890" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated: PCI DSS PAN tokenization — production",
    "nullHandling": "error"
  }'
```

**Response `200 OK`:** Returns updated scheme object.

---

#### Delete a Scheme

`DELETE /svc/dataprotect/schemes/{id}`

Fails with `409 Conflict` if any active tokenized records reference this scheme. Deactivate all dependent systems before deleting.

```bash
curl -X DELETE \
  "http://localhost:5173/svc/dataprotect/schemes/a1b2c3d4-e5f6-7890-abcd-ef1234567890" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `204 No Content`** on success.

---

#### Tokenize a Single Value

`POST /svc/dataprotect/tokenize`

```bash
curl -X POST http://localhost:5173/svc/dataprotect/tokenize \
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
curl -X POST http://localhost:5173/svc/dataprotect/tokenize/batch \
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
curl -X POST http://localhost:5173/svc/dataprotect/detokenize \
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
curl -X POST http://localhost:5173/svc/dataprotect/detokenize/batch \
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

#### Vault Search

`GET /svc/dataprotect/vault/search`

For vault-mode schemes only. Query parameters: `schemeId` (required), `token` (optional), `original` (optional).

```bash
curl "http://localhost:5173/svc/dataprotect/vault/search?schemeId=b2c3d4e5-f6a7-8901-bcde-f12345678901&token=TKN-a8f2c9d1e4b3" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `200 OK`:**

```json
{
  "items": [
    {
      "token": "TKN-a8f2c9d1e4b3",
      "createdAt": "2026-03-10T14:22:00Z",
      "schemeId": "b2c3d4e5-f6a7-8901-bcde-f12345678901"
    }
  ],
  "originalValue": "4532015112830366",
  "request_id": "req_dp_030"
}
```

**Summary of Tokenization Endpoints:**

| Method | Path | Description |
|---|---|---|
| `GET` | `/svc/dataprotect/schemes` | List schemes (pagination, mode filter) |
| `POST` | `/svc/dataprotect/schemes` | Create scheme |
| `GET` | `/svc/dataprotect/schemes/{id}` | Get scheme |
| `PATCH` | `/svc/dataprotect/schemes/{id}` | Update (name, description, nullHandling) |
| `DELETE` | `/svc/dataprotect/schemes/{id}` | Delete (fails if scheme in use) |
| `POST` | `/svc/dataprotect/tokenize` | Tokenize single value |
| `POST` | `/svc/dataprotect/tokenize/batch` | Tokenize up to 1000 values |
| `POST` | `/svc/dataprotect/detokenize` | Detokenize single token |
| `POST` | `/svc/dataprotect/detokenize/batch` | Detokenize up to 1000 tokens |
| `GET` | `/svc/dataprotect/vault/search` | Search vault by token or original value |

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

`POST /svc/dataprotect/masking/policies`

```bash
curl -X POST http://localhost:5173/svc/dataprotect/masking/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "credit-card-masking",
    "description": "Dynamic masking by caller role for PAN fields",
    "fieldPattern": "pan|credit_card|card_number",
    "maskMode": "dynamic",
    "maskChar": "X",
    "visiblePrefix": 0,
    "visibleSuffix": 4,
    "roleExemptions": ["dba", "payment-processor"],
    "dynamicRules": [
      {"roles": ["analyst"], "visiblePrefix": 0, "visibleSuffix": 4, "maskChar": "X"},
      {"roles": ["support"], "visiblePrefix": 0, "visibleSuffix": 4, "maskChar": "*"},
      {"roles": ["auditor"], "visiblePrefix": 0, "visibleSuffix": 0, "maskChar": "X"}
    ]
  }'
```

**Response `201 Created`:**

```json
{
  "item": {
    "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "name": "credit-card-masking",
    "fieldPattern": "pan|credit_card|card_number",
    "maskMode": "dynamic",
    "maskChar": "X",
    "visiblePrefix": 0,
    "visibleSuffix": 4,
    "roleExemptions": ["dba", "payment-processor"],
    "dynamicRules": [
      {"roles": ["analyst"], "visiblePrefix": 0, "visibleSuffix": 4, "maskChar": "X"},
      {"roles": ["support"], "visiblePrefix": 0, "visibleSuffix": 4, "maskChar": "*"},
      {"roles": ["auditor"], "visiblePrefix": 0, "visibleSuffix": 0, "maskChar": "X"}
    ],
    "createdAt": "2026-03-23T10:10:00Z",
    "createdBy": "admin@example.com"
  },
  "request_id": "req_dp_040"
}
```

---

#### Apply Masking to a Record

`POST /svc/dataprotect/mask`

```bash
curl -X POST http://localhost:5173/svc/dataprotect/mask \
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

#### Batch Mask

`POST /svc/dataprotect/mask/batch`

Up to 1000 records per request.

```bash
curl -X POST http://localhost:5173/svc/dataprotect/mask/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "policyId": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "callerRoles": ["support"],
    "records": [
      {"id": "r1", "card_number": "4532015112830366"},
      {"id": "r2", "card_number": "5425233430109903"}
    ]
  }'
```

**Response `200 OK`:**

```json
{
  "items": [
    {"index": 0, "maskedRecord": {"id": "r1", "card_number": "************0366"}, "error": null},
    {"index": 1, "maskedRecord": {"id": "r2", "card_number": "************9903"}, "error": null}
  ],
  "successCount": 2,
  "errorCount": 0,
  "request_id": "req_dp_042"
}
```

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

`POST /svc/dataprotect/encrypt/field`

```bash
curl -X POST http://localhost:5173/svc/dataprotect/encrypt/field \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "fieldName": "ssn",
    "recordId": "patient-00192",
    "plaintext": "123-45-6789",
    "deterministic": false
  }'
```

**Response `200 OK`:**

```json
{
  "ciphertext": "AQIDAHjK9mP3qR7wL2Xk9mP3qR7wL2Xk9mP3qR7wL2VGhTkL9mP3==",
  "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "keyVersion": 1,
  "algorithm": "AES-256-GCM",
  "deterministic": false,
  "fieldName": "ssn",
  "recordId": "patient-00192",
  "request_id": "req_dp_050"
}
```

The `ciphertext` is base64-encoded: key version prefix (4 bytes) + IV (12 bytes) + GCM tag (16 bytes) + encrypted content.

---

#### Decrypt a Field

`POST /svc/dataprotect/decrypt/field`

```bash
curl -X POST http://localhost:5173/svc/dataprotect/decrypt/field \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "fieldName": "ssn",
    "recordId": "patient-00192",
    "ciphertext": "AQIDAHjK9mP3qR7wL2Xk9mP3qR7wL2Xk9mP3qR7wL2VGhTkL9mP3=="
  }'
```

**Response `200 OK`:**

```json
{
  "plaintext": "123-45-6789",
  "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "keyVersion": 1,
  "request_id": "req_dp_051"
}
```

---

#### Re-encrypt a Field (Key Rotation)

`POST /svc/dataprotect/reencrypt/field`

```bash
curl -X POST http://localhost:5173/svc/dataprotect/reencrypt/field \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "fieldName": "ssn",
    "recordId": "patient-00192",
    "oldCiphertext": "AQIDAHjK9mP3qR7wL2Xk9mP3qR7wL2Xk9mP3qR7wL2VGhTkL9mP3=="
  }'
```

**Response `200 OK`:**

```json
{
  "oldCiphertext": "AQIDAHjK9mP3qR7wL2Xk9mP3qR7wL2Xk9mP3qR7wL2VGhTkL9mP3==",
  "newCiphertext": "AQIEBHkL9mQ4rS8xM3Yl9mQ4rS8xM3Yl9mQ4rS8xM3WIiUlM9mQ4==",
  "oldKeyVersion": 1,
  "newKeyVersion": 2,
  "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "request_id": "req_dp_052"
}
```

### 3.4 API Endpoints — Masking and Field Encryption

| Method | Path | Description |
|---|---|---|
| `GET` | `/svc/dataprotect/masking/policies` | List masking policies |
| `POST` | `/svc/dataprotect/masking/policies` | Create masking policy |
| `GET` | `/svc/dataprotect/masking/policies/{id}` | Get policy |
| `PATCH` | `/svc/dataprotect/masking/policies/{id}` | Update policy |
| `DELETE` | `/svc/dataprotect/masking/policies/{id}` | Delete policy |
| `POST` | `/svc/dataprotect/mask` | Apply masking to a single record |
| `POST` | `/svc/dataprotect/mask/batch` | Apply masking to up to 1000 records |
| `POST` | `/svc/dataprotect/encrypt/field` | Encrypt a single field value |
| `POST` | `/svc/dataprotect/decrypt/field` | Decrypt a single field value |
| `POST` | `/svc/dataprotect/reencrypt/field` | Re-encrypt during key rotation |

---

## 4. Payment Cryptography

Payment cryptography covers the regulated protocols used in card-present payment networks: TR-31 key blocks, PIN block generation and translation, PIN verification (PVV and IBM offset), and ISO 20022 message signing.

> **Security Note:** All payment cryptography operations require the caller to hold the `payment:operate` permission in addition to standard authentication. Operations are logged with payment-specific audit subjects.

### 4.1 TR-31 Key Blocks

**Background — PCI PIN Security Requirement 18-3:**
The PCI PIN Security standard (Requirement 18-3) mandates that symmetric key material exchanged between payment participants must be transported inside authenticated, integrity-protected key blocks. The TR-31 (ANSI X9.143) standard defines the key block format used industry-wide.

**TR-31 Block Header Format:**

The first 16 characters are the header, encoding key metadata authenticated by the appended MAC:

```
Position  Length  Field              Example  Description
0         1       VersionId          D        Block format version (D=current AES-based)
1         4       BlockLength        0096     Total block length in ASCII decimal characters
5         2       KeyUsage           P0       Key usage code (see table below)
7         1       Algorithm          A        Key algorithm (A=AES, D=DEA, T=2TDEA, Y=AES-256)
8         1       ModeOfUse         N        Permitted mode of use (see table below)
9         2       KeyVersionNumber   00       Vendor-defined version counter
11        1       Exportability      S        S=Sensitive, E=Exportable, N=Non-Exportable
12        2       NumOptionalBlocks  00       Count of optional header blocks
14        2       Reserved           00       Must be "00"
Total: 16 characters
```

**Key Usage Codes (TR-31):**

| Code | Usage | Description |
|---|---|---|
| `B0` | BDK | Base Derivation Key for DUKPT |
| `B1` | Initial DUKPT Key | Initial Key loaded into device |
| `B2` | BDK (DUKPT AES) | AES-based BDK |
| `C0` | CVK | Card Verification Key (Visa CVV, Mastercard CVC) |
| `D0` | Data Encryption | Generic symmetric data encryption key |
| `D1` | Data Encryption (asymmetric public) | DEK public component |
| `E0` | EMV Issuer MK — Application Cryptogram | ICC master key |
| `E1` | EMV Issuer MK — Secure Messaging Confidentiality | |
| `E2` | EMV Issuer MK — Secure Messaging Integrity | |
| `E3` | EMV Issuer MK — Data Authentication | DAC |
| `E4` | EMV Issuer MK — Dynamic Numbers | UN generation |
| `E5` | EMV Issuer MK — Card Personalization | |
| `E6` | EMV Issuer MK — Other | Vendor-specific |
| `I0` | Initialization Vector | IV for use with another key |
| `K0` | Key Encryption / Key Wrapping | KEK |
| `K1` | TR-31 Key Block Protection Key | KBPK |
| `K2` | TR-34 Asymmetric Transport Key | RSA key transport |
| `M0` | ISO 16609 MAC Algorithm 1 | Retail MAC |
| `M1` | ISO 9797-1 MAC Algorithm 1 | CBC-MAC |
| `M3` | ISO 9797-1 MAC Algorithm 3 | ANSI Retail MAC |
| `M5` | ISO 9797-1 MAC Algorithm 5 | CMAC |
| `M7` | HMAC | HMAC-SHA family |
| `P0` | PIN Encryption Key | ZPK / PEK |
| `S0` | Asymmetric Key Pair for Digital Signature | |
| `S1` | Asymmetric Key Pair — CA Signing | |
| `S2` | Asymmetric Key Pair — Non-X9.24 | |
| `V0` | PIN Verification — KPV | |
| `V2` | PIN Verification — Visa PVV | |
| `V3` | PIN Verification — IBM 3624 | Offset method |
| `V4` | PIN Verification — Other | |

**Algorithm Codes:**

| Code | Algorithm |
|---|---|
| `A` | AES-128 |
| `D` | Single DES (DEA) — legacy, avoid in new designs |
| `R` | RSA |
| `T` | 2-key Triple DES (2TDEA) |
| `U` | AES-192 |
| `Y` | AES-256 |

**Mode of Use Codes:**

| Code | Mode | Description |
|---|---|---|
| `B` | Both Encrypt/Decrypt | Key may encrypt and decrypt |
| `C` | MAC Generation/Verification | MAC both directions |
| `D` | Decrypt Only | Key may not encrypt |
| `E` | Encrypt Only | Key may not decrypt |
| `G` | MAC Generation Only | Cannot verify |
| `N` | No Restriction | Any use permitted by key usage |
| `S` | Sign Only | Signature generation only |
| `T` | Both Sign and Decrypt | Asymmetric dual use |
| `V` | Verify Only | Signature verification only |
| `W` | Wrap Only | Key wrapping only |
| `X` | Key Derivation | Key derivation function input |

**Exportability Codes:**

| Code | Description |
|---|---|
| `E` | Exportable — may be exported under any KEK |
| `N` | Non-Exportable — cannot be exported |
| `S` | Sensitive — may be exported only under certain conditions |

---

#### Wrap a Key in a TR-31 Block

`POST /svc/payment/tr31/wrap`

```bash
curl -X POST http://localhost:5173/svc/payment/tr31/wrap \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "workingKeyId": "5bc96h86-7939-6784-d5he-4e185h88chc8",
    "kbpkId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "keyUsage": "P0",
    "algorithm": "A",
    "modeOfUse": "N",
    "exportability": "S",
    "keyVersionNumber": "01",
    "optionalBlocks": {}
  }'
```

**Response `200 OK`:**

```json
{
  "keyBlock": "D0096P0AN01S0000F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4",
  "header": {
    "versionId": "D",
    "blockLength": 96,
    "keyUsage": "P0",
    "algorithm": "A",
    "modeOfUse": "N",
    "keyVersionNumber": "01",
    "exportability": "S",
    "numOptionalBlocks": 0
  },
  "kbpkId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "workingKeyId": "5bc96h86-7939-6784-d5he-4e185h88chc8",
  "request_id": "req_pay_001"
}
```

---

#### Unwrap a TR-31 Key Block

`POST /svc/payment/tr31/unwrap`

```bash
curl -X POST http://localhost:5173/svc/payment/tr31/unwrap \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "keyBlock": "D0096P0AN01S0000F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4",
    "kbpkId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "importedKeyName": "zpk-zone-a-2026"
  }'
```

**Response `200 OK`:**

```json
{
  "importedKeyId": "d4e5f6a7-b8c9-0123-def0-123456789abc",
  "importedKeyName": "zpk-zone-a-2026",
  "keyUsage": "P0",
  "algorithm": "A",
  "modeOfUse": "N",
  "exportability": "S",
  "keyVersionNumber": "01",
  "request_id": "req_pay_002"
}
```

---

#### Translate a TR-31 Key Block

`POST /svc/payment/tr31/translate`

Re-wraps a key block from one KBPK to another without exposing the working key in plaintext.

```bash
curl -X POST http://localhost:5173/svc/payment/tr31/translate \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "keyBlock": "D0096P0AN01S0000...",
    "incomingKbpkId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "outgoingKbpkId": "7de29b53-8164-4e19-c712-5f48a22bf093"
  }'
```

**Response `200 OK`:**

```json
{
  "keyBlock": "D0096P0AN01S0000A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4",
  "outgoingKbpkId": "7de29b53-8164-4e19-c712-5f48a22bf093",
  "request_id": "req_pay_003"
}
```

### 4.2 PIN Block Formats

A PIN block encodes a cardholder's PIN in a standardized binary structure. Vecta KMS supports all four primary ISO 9564-1 formats.

**ISO 9564-1 Format 0 (most common):**

Format 0 XORs a PIN-encoded block with a PAN-derived block:

```
PIN Block construction:
  Nibble 0    : Format = 0
  Nibble 1    : PIN length (4–12)
  Nibbles 2–13: PIN digits, padded with 0xF

PAN Block construction:
  Nibbles 0–3 : 0000
  Nibbles 4–15: Rightmost 12 PAN digits, excluding check digit

Final = PIN Block XOR PAN Block

Example: PIN=1234, PAN=4532015112830366
  Check digit of PAN = 6 (last digit), exclude it
  Rightmost 12 excl. check: 5 3 2 0 1 5 1 1 2 8 3 0

  PIN Block (hex): 04 12 34 FF FF FF FF FF
  PAN Block (hex): 00 00 53 20 15 11 28 30
  XOR result:      04 12 67 DF EA EE D7 CF

Encrypted PIN block transmitted = DES/AES-encrypt(04 12 67 DF EA EE D7 CF, ZPK)
```

**ISO 9564-1 Format 1:**
- Random padding (11 nibbles) instead of PAN XOR
- Each PIN entry produces a unique block — good for systems where PAN is unavailable at the PIN device

**ISO 9564-1 Format 3:**
- Like Format 0, but fill nibbles are random decimal digits (0–9) instead of 0xF
- Slightly better entropy than Format 0

**ISO 9564-1 Format 4 (AES-native, 128-bit):**
- 16-byte block — does not XOR with PAN
- `Format=4`, PIN length, PIN digits, then random padding to 128 bits
- Recommended for all new AES-based designs; avoids the XOR-with-PAN vulnerability

---

#### Generate a PIN Block

`POST /svc/payment/pin/generate-block`

```bash
curl -X POST http://localhost:5173/svc/payment/pin/generate-block \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "pin": "1234",
    "pan": "4532015112830366",
    "format": 0,
    "zpkId": "5bc96h86-7939-6784-d5he-4e185h88chc8"
  }'
```

**Response `200 OK`:**

```json
{
  "encryptedPinBlock": "A3F7E29D4B1C8F62",
  "format": 0,
  "zpkId": "5bc96h86-7939-6784-d5he-4e185h88chc8",
  "request_id": "req_pay_010"
}
```

---

#### Translate a PIN Block

`POST /svc/payment/pin/translate`

Translates a PIN block from one ZPK to another without exposing the PIN in plaintext.

```bash
curl -X POST http://localhost:5173/svc/payment/pin/translate \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "encryptedPinBlock": "A3F7E29D4B1C8F62",
    "pan": "4532015112830366",
    "incomingFormat": 0,
    "incomingZpkId": "5bc96h86-7939-6784-d5he-4e185h88chc8",
    "outgoingFormat": 0,
    "outgoingZpkId": "6cd07i97-8a4a-7895-e6if-5f296i99didi"
  }'
```

**Response `200 OK`:**

```json
{
  "encryptedPinBlock": "C8B2F14A7E3D9521",
  "incomingZpkId": "5bc96h86-7939-6784-d5he-4e185h88chc8",
  "outgoingZpkId": "6cd07i97-8a4a-7895-e6if-5f296i99didi",
  "outgoingFormat": 0,
  "request_id": "req_pay_011"
}
```

---

#### Verify PIN — Visa PVV Method

`POST /svc/payment/pin/verify/pvv`

**PVV Algorithm:**
1. Input: `PVKI (1) || PAN_RIGHT_12 (12 excl. check) || PIN_length (1)` = 14 digits
2. Encrypt under PVK
3. Scan result left-to-right, extract first 4 decimal nibbles → 4-digit PVV
4. Stored on card Track 2. At verification: re-derive and compare.

```bash
curl -X POST http://localhost:5173/svc/payment/pin/verify/pvv \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "encryptedPinBlock": "A3F7E29D4B1C8F62",
    "pan": "4532015112830366",
    "pinBlockFormat": 0,
    "zpkId": "5bc96h86-7939-6784-d5he-4e185h88chc8",
    "pvk1Id": "7de29b53-8164-4e19-c712-5f48a22bf093",
    "pvki": "1",
    "pvv": "8421"
  }'
```

**Response `200 OK`:**

```json
{
  "verified": true,
  "pan": "4532015112830366",
  "pvki": "1",
  "request_id": "req_pay_020"
}
```

---

#### Verify PIN — IBM 3624 Offset Method

`POST /svc/payment/pin/verify/offset`

**IBM 3624 Algorithm:**
1. PVK encrypts rightmost 12 PAN digits (excl. check digit)
2. Extract leftmost 4 nibbles, reduce to decimal → "Natural PIN"
3. Customer PIN Offset = `(Customer PIN digit - Natural PIN digit) mod 10` per digit
4. Stored on card. At verification: re-derive Natural PIN, apply offset, compare to entered PIN.

```bash
curl -X POST http://localhost:5173/svc/payment/pin/verify/offset \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "encryptedPinBlock": "A3F7E29D4B1C8F62",
    "pan": "4532015112830366",
    "pinBlockFormat": 0,
    "zpkId": "5bc96h86-7939-6784-d5he-4e185h88chc8",
    "pvkId": "7de29b53-8164-4e19-c712-5f48a22bf093",
    "pinOffset": "3829"
  }'
```

**Response `200 OK`:**

```json
{
  "verified": true,
  "pan": "4532015112830366",
  "request_id": "req_pay_021"
}
```

---

#### Generate a PIN (Initial Card Issuance)

`POST /svc/payment/pin/generate`

Generates a cryptographically random PIN and returns it encrypted in a PIN block. The cleartext PIN is never returned.

```bash
curl -X POST http://localhost:5173/svc/payment/pin/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "pan": "4532015112830366",
    "pinLength": 4,
    "format": 0,
    "zpkId": "5bc96h86-7939-6784-d5he-4e185h88chc8",
    "pvk1Id": "7de29b53-8164-4e19-c712-5f48a22bf093",
    "pvki": "1"
  }'
```

**Response `200 OK`:**

```json
{
  "encryptedPinBlock": "B7C4D82E3A91F056",
  "pvv": "6193",
  "format": 0,
  "zpkId": "5bc96h86-7939-6784-d5he-4e185h88chc8",
  "request_id": "req_pay_030"
}
```

### 4.3 ISO 20022 Signing

ISO 20022 is the international standard for electronic data interchange between financial institutions, used by SWIFT, SEPA, FedNow, and other modern payment rails. Vecta KMS supports signing and verification of ISO 20022 messages via XMLDSig (for XML messages) and JWS (for JSON messages).

---

#### Sign an ISO 20022 Message

`POST /svc/payment/iso20022/sign`

```bash
curl -X POST http://localhost:5173/svc/payment/iso20022/sign \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "keyId": "9ef30c64-6828-5784-d5ef-4e296f99bgc9",
    "messageFormat": "xml",
    "signatureFormat": "xmldsig",
    "messageBase64": "PD94bWwgdmVyc2lvbj0iMS4wIj8+PERvY3VtZW50Pjwvc2VuZGVyPjwvRG9jdW1lbnQ+",
    "canonicalizationAlgorithm": "http://www.w3.org/2001/10/xml-exc-c14n#",
    "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "includeKeyInfo": true
  }'
```

**Response `200 OK`:**

```json
{
  "signedMessageBase64": "PD94bWwgdmVyc2lvbj0iMS4wIj8+PERvY3VtZW50PjxTaWduYXR1cmU+...",
  "signatureBase64": "MEUCIQCkL7v9K+2j8mP3qR7wL2Xk9mP3qR7wL2Xk9mP3qR7w==",
  "keyId": "9ef30c64-6828-5784-d5ef-4e296f99bgc9",
  "algorithm": "rsa-sha256",
  "canonicalization": "exc-c14n",
  "request_id": "req_pay_040"
}
```

---

#### Verify an ISO 20022 Signature

`POST /svc/payment/iso20022/verify`

```bash
curl -X POST http://localhost:5173/svc/payment/iso20022/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "keyId": "9ef30c64-6828-5784-d5ef-4e296f99bgc9",
    "signedMessageBase64": "PD94bWwgdmVyc2lvbj0iMS4wIj8+PERvY3VtZW50PjxTaWduYXR1cmU+...",
    "signatureFormat": "xmldsig"
  }'
```

**Response `200 OK`:**

```json
{
  "verified": true,
  "keyId": "9ef30c64-6828-5784-d5ef-4e296f99bgc9",
  "signerKeyInfo": {
    "algorithm": "RSA",
    "keySize": 2048,
    "subjectDN": "CN=FI-Sending-Bank,O=Example Bank,C=US"
  },
  "request_id": "req_pay_041"
}
```

### 4.4 API Endpoints — Payment

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/payment/tr31/wrap` | Wrap working key in TR-31 block under KBPK |
| `POST` | `/svc/payment/tr31/unwrap` | Unwrap TR-31 block and import to KMS |
| `POST` | `/svc/payment/tr31/translate` | Translate TR-31 block from one KBPK to another |
| `POST` | `/svc/payment/pin/generate-block` | Generate encrypted PIN block |
| `POST` | `/svc/payment/pin/translate` | Translate PIN block between ZPKs/formats |
| `POST` | `/svc/payment/pin/verify/pvv` | Verify PIN using Visa PVV method |
| `POST` | `/svc/payment/pin/verify/offset` | Verify PIN using IBM 3624 offset method |
| `POST` | `/svc/payment/pin/generate` | Generate random PIN, return encrypted block |
| `POST` | `/svc/payment/iso20022/sign` | Sign ISO 20022 message (XMLDSig or JWS) |
| `POST` | `/svc/payment/iso20022/verify` | Verify ISO 20022 message signature |

---

## 5. PKCS#11 Provider

### 5.1 What PKCS#11 Is

PKCS#11 (also known as Cryptoki) is the OASIS-standard API for hardware security modules (HSMs) and cryptographic tokens. It defines a C-based interface that applications use to perform cryptographic operations without managing key material directly — the key stays inside the HSM or token.

Vecta provides a **software PKCS#11 library** — a shared library (`.so`, `.dylib`, or `.dll`) that implements the PKCS#11 v2.40 interface and proxies all cryptographic operations to Vecta KMS over HTTPS. From the application's perspective, Vecta KMS behaves exactly like an HSM:

- Keys are created and stored in KMS, never exported to the application
- All cryptographic operations (sign, decrypt, wrap, derive) execute on the KMS server
- The library handles authentication, session management, and retry logic
- The application interacts through standard PKCS#11 API calls — no Vecta-specific code required

This allows any PKCS#11-aware application (nginx, Apache, Java SunPKCS11, OpenSSL, OpenVPN, EJBCA, etc.) to use Vecta KMS as its cryptographic backend with zero application code changes.

### 5.2 Installation

**Download the library from the Vecta KMS admin console or package repository.**

**Linux (x86-64 / ARM64):**
```
/usr/lib/vecta/pkcs11/libvecta-pkcs11.so
```

Install via package:
```bash
# RPM-based (RHEL, CentOS, Fedora)
rpm -ivh vecta-pkcs11-1.5.0-1.x86_64.rpm

# DEB-based (Ubuntu, Debian)
dpkg -i vecta-pkcs11_1.5.0_amd64.deb

# Verify installation
ls -la /usr/lib/vecta/pkcs11/libvecta-pkcs11.so
pkcs11-tool --module /usr/lib/vecta/pkcs11/libvecta-pkcs11.so --show-info
```

**macOS (Apple Silicon / Intel):**
```
/usr/local/lib/vecta/pkcs11/libvecta-pkcs11.dylib
```

Install via Homebrew tap or direct download:
```bash
brew install vecta/tap/vecta-pkcs11
# or manual:
sudo cp libvecta-pkcs11.dylib /usr/local/lib/vecta/pkcs11/
sudo chmod 644 /usr/local/lib/vecta/pkcs11/libvecta-pkcs11.dylib
```

**Windows (x64):**
```
C:\Program Files\Vecta\pkcs11\vecta-pkcs11.dll
```

Install via MSI installer. The DLL is registered in the Windows service registry automatically.

### 5.3 Configuration

The library reads its configuration from a file whose path is set via the environment variable `VECTA_PKCS11_CONF`, or defaults to:
- Linux/macOS: `/etc/vecta/pkcs11.conf`
- Windows: `C:\ProgramData\Vecta\pkcs11.conf`

**Complete configuration file (`vecta-pkcs11.conf`):**

```ini
[global]
# Base URL of the Vecta KMS server
server_url = https://kms.example.com

# Tenant ID to use for all operations
tenant_id = root

# Log level: trace, debug, info, warn, error
log_level = info

# Log file path (omit to log to stderr)
log_file = /var/log/vecta-pkcs11.log

# Connection timeout in milliseconds
connection_timeout_ms = 5000

# Read/operation timeout in milliseconds
read_timeout_ms = 30000

# Maximum number of retry attempts on transient errors
max_retries = 3

# Retry backoff: initial_ms, max_ms
retry_initial_ms = 100
retry_max_ms = 5000

[auth]
# Authentication method: client_credentials, mtls, workload_identity
method = client_credentials

# For client_credentials:
client_id = pkcs11-service
# Path to file containing client secret (preferred over inline value)
client_secret_file = /etc/vecta/pkcs11-secret
# Token cache TTL in seconds (refresh before expiry)
token_ttl_buffer_seconds = 60

# For mTLS (comment out client_credentials fields above):
# method = mtls
# cert_file = /etc/vecta/client.crt
# key_file = /etc/vecta/client.key
# ca_bundle = /etc/vecta/ca-bundle.pem

# For workload identity (SPIFFE SVID):
# method = workload_identity
# spiffe_socket = unix:///run/spire/agent.sock

[slot_0]
# PKCS#11 slot label (shown in C_GetTokenInfo)
label = VectaKMS-Production

# Security Officer PIN (used for administrative operations)
so_pin = change-this-so-pin

# User PIN (used for normal cryptographic operations)
user_pin = change-this-user-pin

# Key filter: only expose keys with this tag to this slot
# Format: tag:<key>=<value>
key_filter = tag:pkcs11-slot=prod

# Optional: restrict slot to specific key IDs (comma-separated UUIDs)
# key_ids = 3fa85f64-5717-4562-b3fc-2c963f66afa6,7de29b53-8164-4e19-c712-5f48a22bf093

# Optional: restrict to keys with specific purpose
# key_purpose = sign,decrypt

[slot_1]
# Second slot for staging keys
label = VectaKMS-Staging
so_pin = change-this-so-pin
user_pin = change-this-user-pin
key_filter = tag:pkcs11-slot=staging

[performance]
# Size of the session pool (concurrent PKCS#11 sessions)
session_pool_size = 10

# Per-operation timeout in milliseconds
operation_timeout_ms = 10000

# Cache public key material locally (reduces round-trips for verify operations)
cache_public_keys = true

# TTL for cached public keys in seconds
cache_ttl_seconds = 300

# Whether to perform operations asynchronously (experimental)
async_operations = false

# Maximum pending async operations
async_queue_depth = 100

[tls]
# Minimum TLS version for KMS server connection: TLSv1.2, TLSv1.3
min_tls_version = TLSv1.2

# Custom CA bundle for server certificate verification
# ca_bundle = /etc/vecta/server-ca.pem

# Disable server certificate verification (NOT for production)
insecure_skip_verify = false
```

> **Security Note:** Store the `user_pin` and `so_pin` in a secrets management system (such as Vecta's Secrets Vault, Section 8) rather than in the configuration file with world-readable permissions. Set configuration file permissions to `0600` owned by the service account running the PKCS#11-consuming application.

> **Warning:** The `insecure_skip_verify = true` option disables server certificate verification, making the connection vulnerable to man-in-the-middle attacks. Never set this in production environments.

### 5.4 Supported Mechanisms

The following PKCS#11 mechanisms are supported by the Vecta library. The `CKM_` constants correspond to the standard PKCS#11 mechanism identifiers.

| CKM Constant | Hex Value | Operations | Key Types | Notes |
|---|---|---|---|---|
| `CKM_RSA_PKCS` | `0x00000001` | Encrypt, Decrypt, Sign, Verify | RSA | PKCS#1 v1.5 padding |
| `CKM_RSA_PKCS_OAEP` | `0x00000009` | Encrypt, Decrypt | RSA | OAEP with configurable hash |
| `CKM_RSA_PKCS_PSS` | `0x0000000D` | Sign, Verify | RSA | PSS with configurable salt/hash |
| `CKM_SHA1_RSA_PKCS` | `0x00000006` | Sign, Verify | RSA | SHA-1 + PKCS#1 v1.5 |
| `CKM_SHA256_RSA_PKCS` | `0x00000040` | Sign, Verify | RSA | SHA-256 + PKCS#1 v1.5 |
| `CKM_SHA384_RSA_PKCS` | `0x00000041` | Sign, Verify | RSA | SHA-384 + PKCS#1 v1.5 |
| `CKM_SHA512_RSA_PKCS` | `0x00000042` | Sign, Verify | RSA | SHA-512 + PKCS#1 v1.5 |
| `CKM_SHA256_RSA_PKCS_PSS` | `0x00000043` | Sign, Verify | RSA | SHA-256 + PSS |
| `CKM_SHA512_RSA_PKCS_PSS` | `0x00000045` | Sign, Verify | RSA | SHA-512 + PSS |
| `CKM_ECDSA` | `0x00001041` | Sign, Verify | EC | Raw ECDSA (caller provides hash) |
| `CKM_ECDSA_SHA256` | `0x00001044` | Sign, Verify | EC | ECDSA with SHA-256 |
| `CKM_ECDSA_SHA384` | `0x00001045` | Sign, Verify | EC | ECDSA with SHA-384 |
| `CKM_ECDSA_SHA512` | `0x00001046` | Sign, Verify | EC | ECDSA with SHA-512 |
| `CKM_EC_KEY_PAIR_GEN` | `0x00001040` | GenerateKeyPair | EC | Curves: P-256, P-384, P-521 |
| `CKM_RSA_PKCS_KEY_PAIR_GEN` | `0x00000000` | GenerateKeyPair | RSA | Key sizes: 2048, 3072, 4096 |
| `CKM_AES_KEY_GEN` | `0x00001080` | GenerateKey | AES | 128, 192, 256-bit |
| `CKM_AES_ECB` | `0x00001081` | Encrypt, Decrypt | AES | Not recommended for new designs |
| `CKM_AES_CBC` | `0x00001082` | Encrypt, Decrypt | AES | Requires 16-byte IV |
| `CKM_AES_CBC_PAD` | `0x00001085` | Encrypt, Decrypt | AES | CBC with PKCS#7 padding |
| `CKM_AES_GCM` | `0x00001087` | Encrypt, Decrypt | AES | 96-bit IV, 128-bit tag recommended |
| `CKM_AES_CTR` | `0x00001086` | Encrypt, Decrypt | AES | Counter mode |
| `CKM_AES_CMAC` | `0x0000108A` | Sign, Verify | AES | AES-CMAC MAC |
| `CKM_SHA_1` | `0x00000220` | Digest | — | Software-only |
| `CKM_SHA256` | `0x00000250` | Digest | — | Software-only |
| `CKM_SHA384` | `0x00000260` | Digest | — | Software-only |
| `CKM_SHA512` | `0x00000270` | Digest | — | Software-only |
| `CKM_ECDH1_DERIVE` | `0x00001050` | Derive | EC | ECDH key agreement |
| `CKM_AES_KEY_WRAP` | `0x00002109` | Wrap, Unwrap | AES | AES Key Wrap (RFC 3394) |
| `CKM_RSA_PKCS_KEY_WRAP` | `0x00000001` | Wrap, Unwrap | RSA | RSA-OAEP key wrap |

> **Tip:** Digest operations (`CKM_SHA_*`) are performed locally in the library without a KMS round-trip, as they do not involve key material. All other operations are forwarded to the KMS server.

### 5.5 Integration Examples

#### nginx TLS Private Key Offload

Keep the nginx TLS private key in Vecta KMS. nginx uses the OpenSSL PKCS#11 engine to perform TLS handshakes without the private key ever being loaded into nginx memory.

**Prerequisites:** Install `libp11` (OpenSSL PKCS#11 engine) and the Vecta PKCS#11 library.

```bash
# Install libp11
apt-get install libengine-pkcs11-openssl   # Debian/Ubuntu
yum install openssl-pkcs11                  # RHEL/CentOS
```

**OpenSSL engine configuration (`/etc/ssl/openssl-vecta.cnf`):**

```ini
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so
MODULE_PATH = /usr/lib/vecta/pkcs11/libvecta-pkcs11.so
init = 0
```

**nginx configuration (`/etc/nginx/nginx.conf` excerpt):**

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate     /etc/nginx/certs/api-example-com.crt;
    ssl_certificate_key "engine:pkcs11:pkcs11:token=VectaKMS-Production;object=nginx-tls-key;type=private";

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    location / {
        proxy_pass http://backend;
    }
}
```

Set the environment variable before starting nginx:
```bash
export OPENSSL_CONF=/etc/ssl/openssl-vecta.cnf
export VECTA_PKCS11_CONF=/etc/vecta/pkcs11.conf
nginx
```

> **Tip:** The key object name `nginx-tls-key` corresponds to the `CKA_LABEL` attribute of the key in the PKCS#11 slot. Tag the key in Vecta KMS with `tag:pkcs11-slot=prod` so it appears in the correct slot.

---

#### List Objects with pkcs11-tool

```bash
# List all private keys in the production slot
pkcs11-tool \
  --module /usr/lib/vecta/pkcs11/libvecta-pkcs11.so \
  --token-label VectaKMS-Production \
  --login --pin change-this-user-pin \
  --list-objects --type privkey

# Expected output:
# Private Key Object; EC
#   label:      nginx-tls-key
#   ID:         3fa85f645717
#   Usage:      sign, decrypt
#   Access:     sensitive, always sensitive, never extractable, local

# Sign a file
echo "test payload" > /tmp/test.txt
pkcs11-tool \
  --module /usr/lib/vecta/pkcs11/libvecta-pkcs11.so \
  --token-label VectaKMS-Production \
  --login --pin change-this-user-pin \
  --sign --mechanism SHA256-RSA-PKCS \
  --id 3fa85f645717 \
  --input-file /tmp/test.txt \
  --output-file /tmp/test.sig
```

---

#### Java SunPKCS11 Provider

The JDK's built-in `SunPKCS11` provider can load the Vecta library for Java applications that use JCA/JCE without modifying application code.

```java
import java.security.*;
import javax.crypto.*;
import java.io.ByteArrayInputStream;

public class VectaPKCS11Example {

    public static void main(String[] args) throws Exception {
        // Configuration string for SunPKCS11
        String configStr =
            "--name VectaKMS\n" +
            "library /usr/lib/vecta/pkcs11/libvecta-pkcs11.so\n" +
            "slot 0\n" +
            "description Vecta KMS PKCS#11\n";

        // Load and configure the provider
        Provider sunPKCS11 = Security.getProvider("SunPKCS11");
        Provider vectaProvider = sunPKCS11.configure(
            new ByteArrayInputStream(configStr.getBytes())
        );
        Security.addProvider(vectaProvider);

        // Load the KMS keystore (PKCS#11 token)
        KeyStore ks = KeyStore.getInstance("PKCS11", vectaProvider);
        ks.load(null, "change-this-user-pin".toCharArray());

        // Retrieve a private key by label
        PrivateKey signingKey = (PrivateKey) ks.getKey("my-signing-key", null);

        // Sign data using the key from KMS — private key never leaves the server
        Signature sig = Signature.getInstance("SHA256withECDSA", vectaProvider);
        sig.initSign(signingKey);
        sig.update("Hello, Vecta KMS!".getBytes());
        byte[] signature = sig.sign();

        System.out.println("Signature length: " + signature.length + " bytes");
        System.out.println("Signing complete — private key remained in KMS");
    }
}
```

---

#### EJBCA Certificate Authority Integration

EJBCA (open-source CA) can use Vecta as its CA signing key backend:

1. In EJBCA's `cesecore.properties`:
   ```properties
   cryptotoken.p11.lib.255.name=VectaKMS
   cryptotoken.p11.lib.255.file=/usr/lib/vecta/pkcs11/libvecta-pkcs11.so
   ```

2. Create a CryptoToken in EJBCA Admin UI → System Functions → Crypto Tokens → Create:
   - Type: PKCS#11
   - Library: VectaKMS
   - Slot: 0 (or by label: VectaKMS-Production)
   - Auth code: `change-this-user-pin`

3. Generate or use existing CA signing key:
   - Key alias: `caSignKey0001`
   - Algorithm: RSA 4096 or EC P-384

4. The CA private key is generated in Vecta KMS and all signing operations execute server-side. EJBCA never holds the private key material.

---

## 6. JCA/JCE Provider

### 6.1 Dependency and Setup

The Vecta JCA/JCE provider is a Java library that registers Vecta KMS as a standard `java.security.Provider`. Once registered, standard JCA/JCE API calls transparently route cryptographic operations to Vecta KMS.

**Maven dependency:**

```xml
<dependency>
  <groupId>io.vecta</groupId>
  <artifactId>vecta-jca-provider</artifactId>
  <version>1.5.0</version>
</dependency>
```

**Gradle dependency:**

```groovy
implementation 'io.vecta:vecta-jca-provider:1.5.0'
```

**Provider configuration and registration:**

```java
import io.vecta.jca.VectaProvider;
import io.vecta.jca.VectaProviderConfig;
import java.security.Security;

// Build configuration
VectaProviderConfig config = VectaProviderConfig.builder()
    .serverUrl("https://kms.example.com")
    .tenantId("root")
    .clientId("jca-service")
    .clientSecret(System.getenv("VECTA_CLIENT_SECRET"))
    // Optional: mTLS instead of client credentials
    // .clientCertPath("/etc/service/client.crt")
    // .clientKeyPath("/etc/service/client.key")
    .connectionTimeoutMs(5000)
    .readTimeoutMs(30000)
    .cachePublicKeys(true)
    .cachePublicKeysTtlSeconds(300)
    .build();

// Register the provider (insert at position 1 = highest priority)
Security.insertProviderAt(new VectaProvider(config), 1);

// Or append (lowest priority — only used when other providers don't support the algorithm)
Security.addProvider(new VectaProvider(config));
```

**Spring Boot auto-configuration:**

If using the Spring Boot starter, add to `application.yml`:

```yaml
vecta:
  kms:
    server-url: https://kms.example.com
    tenant-id: root
    client-id: jca-service
    client-secret: ${VECTA_CLIENT_SECRET}
    jca:
      enabled: true
      provider-priority: 1
      cache-public-keys: true
```

### 6.2 Supported Algorithms

**JCA Service: KeyGenerator**

| Algorithm | Key Sizes | Notes |
|---|---|---|
| `AES` | 128, 192, 256 | Generates AES key in KMS |
| `HmacSHA256` | 256 | HMAC-SHA256 key |
| `HmacSHA384` | 384 | HMAC-SHA384 key |
| `HmacSHA512` | 512 | HMAC-SHA512 key |

**JCA Service: KeyPairGenerator**

| Algorithm | Key Sizes / Curves | Notes |
|---|---|---|
| `RSA` | 2048, 3072, 4096 | Generates RSA key pair in KMS |
| `EC` | P-256, P-384, P-521 | Generates EC key pair in KMS |
| `Ed25519` | 256 | Edwards curve signing key pair |
| `Ed448` | 448 | Edwards curve signing key pair |

**JCA Service: Cipher**

| Algorithm String | Mode | Notes |
|---|---|---|
| `AES/GCM/NoPadding` | Encrypt, Decrypt | Recommended for authenticated encryption |
| `AES/CBC/PKCS5Padding` | Encrypt, Decrypt | CBC with PKCS#7 padding |
| `AES/ECB/NoPadding` | Encrypt, Decrypt | Not recommended; no IV |
| `AES/CTR/NoPadding` | Encrypt, Decrypt | Counter mode |
| `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` | Encrypt, Decrypt | RSA-OAEP |
| `RSA/ECB/PKCS1Padding` | Encrypt, Decrypt | RSA PKCS#1 v1.5 |

**JCA Service: Signature**

| Algorithm String | Key Type | Notes |
|---|---|---|
| `SHA256withRSA` | RSA | PKCS#1 v1.5 |
| `SHA384withRSA` | RSA | PKCS#1 v1.5 |
| `SHA512withRSA` | RSA | PKCS#1 v1.5 |
| `SHA256withRSAandMGF1` | RSA | RSA-PSS |
| `SHA512withRSAandMGF1` | RSA | RSA-PSS |
| `SHA256withECDSA` | EC | ECDSA with SHA-256 |
| `SHA384withECDSA` | EC | ECDSA with SHA-384 |
| `SHA512withECDSA` | EC | ECDSA with SHA-512 |
| `Ed25519` | Ed25519 | Pure EdDSA |
| `Ed448` | Ed448 | Pure EdDSA |

**JCA Service: MessageDigest**

All digest operations are performed locally without KMS round-trips:

| Algorithm | Notes |
|---|---|
| `SHA-256` | Local computation |
| `SHA-384` | Local computation |
| `SHA-512` | Local computation |
| `SHA-1` | Local computation (legacy) |

**JCA Service: Mac**

| Algorithm | Notes |
|---|---|
| `HmacSHA256` | Key stored in KMS |
| `HmacSHA384` | Key stored in KMS |
| `HmacSHA512` | Key stored in KMS |
| `AESCMAC` | AES-CMAC; key stored in KMS |

**JCA Service: KeyStore**

`VectaKMS` keystore type — loads keys from KMS by alias (key name or tag).

**JCA Service: KeyAgreement**

| Algorithm | Notes |
|---|---|
| `ECDH` | Key agreement using EC keys in KMS |
| `X25519` | Key agreement using X25519 keys in KMS |

### 6.3 Java Code Examples

#### Generate an AES Key in Vecta via JCA

```java
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;

// Assumes VectaProvider is already registered (see Section 6.1)

// Generate AES-256 key — stored in Vecta KMS, not in JVM memory
KeyGenerator keyGen = KeyGenerator.getInstance("AES", "VectaKMS");
keyGen.init(256);
SecretKey aesKey = keyGen.generateKey();

// aesKey.getEncoded() returns null — the key material never leaves KMS
System.out.println("Key ID: " + ((io.vecta.jca.VectaSecretKey) aesKey).getKeyId());
```

---

#### Encrypt Data with AES/GCM/NoPadding

```java
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

// Load existing key from KMS by ID or retrieve generated key
SecretKey aesKey = loadVectaKey("3fa85f64-5717-4562-b3fc-2c963f66afa6");

// Encrypt
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "VectaKMS");
GCMParameterSpec paramSpec = new GCMParameterSpec(128, new byte[12]); // KMS generates IV
cipher.init(Cipher.ENCRYPT_MODE, aesKey, paramSpec);
cipher.updateAAD("fieldName:recordId:tenantId".getBytes()); // associated data
byte[] ciphertext = cipher.doFinal("sensitive data".getBytes());

// Decrypt
cipher.init(Cipher.DECRYPT_MODE, aesKey, paramSpec);
cipher.updateAAD("fieldName:recordId:tenantId".getBytes());
byte[] plaintext = cipher.doFinal(ciphertext);
System.out.println(new String(plaintext)); // "sensitive data"
```

---

#### Sign with SHA256withECDSA

```java
import java.security.*;

// Load EC key pair from Vecta KMS
KeyStore ks = KeyStore.getInstance("VectaKMS");
ks.load(null, null); // KMS uses token/OAuth — no PIN required here
PrivateKey ecPrivateKey = (PrivateKey) ks.getKey("my-ecdsa-key", null);
PublicKey ecPublicKey = ks.getCertificate("my-ecdsa-key").getPublicKey();

// Sign — the private key operation executes on the KMS server
Signature signer = Signature.getInstance("SHA256withECDSA", "VectaKMS");
signer.initSign(ecPrivateKey);
signer.update("data to sign".getBytes());
byte[] signature = signer.sign();

// Verify — can use any provider (public key is cached)
Signature verifier = Signature.getInstance("SHA256withECDSA");
verifier.initVerify(ecPublicKey);
verifier.update("data to sign".getBytes());
boolean valid = verifier.verify(signature);
System.out.println("Signature valid: " + valid); // true
```

---

#### Use VectaKMS KeyStore to Load a Key by Alias

```java
import java.security.*;
import java.security.cert.Certificate;
import javax.crypto.SecretKey;

KeyStore ks = KeyStore.getInstance("VectaKMS");

// Initialization loads the key catalog from KMS
// The Properties object maps alias names to KMS key IDs or tags
java.util.Properties props = new java.util.Properties();
props.setProperty("vecta.keystore.tagFilter", "env=prod");
ks.load(
    new java.io.ByteArrayInputStream(props.toString().getBytes()),
    null
);

// Enumerate key aliases
java.util.Enumeration<String> aliases = ks.aliases();
while (aliases.hasMoreElements()) {
    String alias = aliases.nextElement();
    System.out.println("Key: " + alias + " | Type: " +
        (ks.isKeyEntry(alias) ? "key" : "cert"));
}

// Get a symmetric key by alias
SecretKey dataKey = (SecretKey) ks.getKey("prod-data-encryption-key", null);

// Get a private key by alias
PrivateKey sigKey = (PrivateKey) ks.getKey("prod-signing-key", null);
```

---

#### Generate RSA Key Pair and Self-Signed Certificate

```java
import java.security.*;
import java.security.cert.*;
import javax.security.auth.x500.X500Principal;

// Generate RSA-4096 key pair in KMS
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "VectaKMS");
kpg.initialize(4096);
KeyPair keyPair = kpg.generateKeyPair();

// The private key is a handle — not exportable
System.out.println("Private key class: " + keyPair.getPrivate().getClass().getName());

// Use the key pair to create a certificate signing request
// (use Bouncy Castle or similar for CSR generation)
// The CSR signing uses the KMS key transparently
```

---

#### HMAC Computation

```java
import javax.crypto.Mac;
import javax.crypto.SecretKey;

SecretKey hmacKey = loadVectaHmacKey("prod-hmac-key");

Mac mac = Mac.getInstance("HmacSHA256", "VectaKMS");
mac.init(hmacKey);
byte[] hmacResult = mac.doFinal("message to authenticate".getBytes());

// Convert to hex
StringBuilder sb = new StringBuilder();
for (byte b : hmacResult) sb.append(String.format("%02x", b));
System.out.println("HMAC-SHA256: " + sb.toString());
```

---

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
curl -X POST http://localhost:5173/svc/autokey/autokey/templates \
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
curl "http://localhost:5173/svc/autokey/autokey/templates?tenant_id=root" \
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

```bash
curl -X POST http://localhost:5173/svc/autokey/autokey/handles \
  -H "Authorization: Bearer $DEV_TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "templateId": "e5f6a7b8-c9d0-1234-efab-567890123456",
    "handleName": "payments-service-dek-prod",
    "serviceId": "payments-service",
    "environment": "prod",
    "justification": "Production DEK for PAN field encryption in the payments microservice"
  }'
```

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

```bash
curl "http://localhost:5173/svc/autokey/autokey/handles/g7b8c9d0-e1f2-3456-gabc-789012345678" \
  -H "Authorization: Bearer $DEV_TOKEN" \
  -H "X-Tenant-ID: root"
```

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
curl "http://localhost:5173/svc/autokey/autokey/handles?handleName=payments-service-dek-prod" \
  -H "Authorization: Bearer $SVC_TOKEN" \
  -H "X-Tenant-ID: root"
```

**Step 4 — Admin approves an approval-required request** (for templates with `requiresApproval: true`)

```bash
curl -X POST \
  "http://localhost:5173/svc/autokey/autokey/handles/h8c9d0e1-f2a3-4567-habc-890123456789/approve" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "comment": "Approved for production CA signing key — reviewed CSR and key purpose"
  }'
```

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

```bash
curl -X POST \
  "http://localhost:5173/svc/autokey/autokey/handles/h8c9d0e1-f2a3-4567-habc-890123456789/reject" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "CA signing keys require a separate governance ceremony. Please open a ticket with the platform team."
  }'
```

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
| `GET` | `/svc/autokey/autokey/templates/{id}` | Get template | Admin |
| `PATCH` | `/svc/autokey/autokey/templates/{id}` | Update template | Admin |
| `DELETE` | `/svc/autokey/autokey/templates/{id}` | Delete template | Admin |
| `POST` | `/svc/autokey/autokey/handles` | Request a key handle | Developer |
| `GET` | `/svc/autokey/autokey/handles` | List handles (filter by status, template) | Developer/Admin |
| `GET` | `/svc/autokey/autokey/handles/{id}` | Get handle status | Developer/Admin |
| `POST` | `/svc/autokey/autokey/handles/{id}/approve` | Approve pending handle | Admin |
| `POST` | `/svc/autokey/autokey/handles/{id}/reject` | Reject pending handle | Admin |

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
curl "http://localhost:5173/svc/secrets/secrets?prefix=/apps/payments/prod/" \
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
curl -X POST http://localhost:5173/svc/secrets/secrets \
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
curl "http://localhost:5173/svc/secrets/secrets/%2Fapps%2Fpayments%2Fprod%2Fdb-password" \
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
  "http://localhost:5173/svc/secrets/secrets/%2Fapps%2Fpayments%2Fprod%2Fdb-password" \
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
  "http://localhost:5173/svc/secrets/secrets/%2Fapps%2Fpayments%2Fprod%2Fdb-password" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `204 No Content`**

---

#### Hard Delete (Destroy) a Specific Version

`POST /svc/secrets/secrets/{path}/destroy/{version}`

Permanently and irreversibly removes a specific version's value. Use when a secret value has been compromised and must not be recoverable.

```bash
curl -X POST \
  "http://localhost:5173/svc/secrets/secrets/%2Fapps%2Fpayments%2Fprod%2Fdb-password/destroy/2" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `200 OK`:**

```json
{
  "path": "/apps/payments/prod/db-password",
  "version": 2,
  "destroyed": true,
  "destroyedAt": "2026-03-23T12:05:00Z",
  "destroyedBy": "security-admin@example.com",
  "request_id": "req_sec_010"
}
```

> **Warning:** Destroy is permanent. The version record is retained (metadata only, no value) to maintain audit continuity, but the secret value cannot be recovered.

---

#### List Versions

`GET /svc/secrets/secrets/{path}/versions`

```bash
curl "http://localhost:5173/svc/secrets/secrets/%2Fapps%2Fpayments%2Fprod%2Fdb-password/versions" \
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

#### Get Specific Version

`GET /svc/secrets/secrets/{path}/versions/{version}`

```bash
curl "http://localhost:5173/svc/secrets/secrets/%2Fapps%2Fpayments%2Fprod%2Fdb-password/versions/3" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `200 OK`:** Returns the full secret object for version 3, including value.

---

#### Rollback to a Previous Version

`POST /svc/secrets/secrets/{path}/rollback/{version}`

Creates a new version whose value is copied from the specified historical version. Does not restore destroyed versions.

```bash
curl -X POST \
  "http://localhost:5173/svc/secrets/secrets/%2Fapps%2Fpayments%2Fprod%2Fdb-password/rollback/3" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root"
```

**Response `200 OK`:**

```json
{
  "item": {
    "path": "/apps/payments/prod/db-password",
    "version": 5,
    "rolledBackFrom": 3,
    "createdAt": "2026-03-23T12:10:00Z",
    "createdBy": "platform-admin@example.com"
  },
  "request_id": "req_sec_015"
}
```

**Summary of Secrets Endpoints:**

| Method | Path | Description |
|---|---|---|
| `GET` | `/svc/secrets/secrets` | List secrets by prefix |
| `POST` | `/svc/secrets/secrets` | Create secret (version 1) |
| `GET` | `/svc/secrets/secrets/{path}` | Get latest version (with value) |
| `PUT` | `/svc/secrets/secrets/{path}` | Create new version |
| `DELETE` | `/svc/secrets/secrets/{path}` | Soft delete |
| `POST` | `/svc/secrets/secrets/{path}/destroy/{version}` | Hard delete specific version |
| `GET` | `/svc/secrets/secrets/{path}/versions` | List all versions |
| `GET` | `/svc/secrets/secrets/{path}/versions/{version}` | Get specific version with value |
| `POST` | `/svc/secrets/secrets/{path}/rollback/{version}` | Rollback to historical version |

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
curl -X POST http://localhost:5173/svc/dataprotect/tokenize \
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
curl -X POST http://localhost:5173/svc/dataprotect/detokenize \
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
curl -X POST http://localhost:5173/svc/dataprotect/encrypt/field \
  -H "Authorization: Bearer $APP_TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "fieldName": "ssn",
    "recordId": "patient-00192",
    "plaintext": "123-45-6789",
    "deterministic": false
  }'
# Store ciphertext "AQIDAHjK..." in the ssn column
```

**Step 2 — Encrypt SSN with deterministic mode for equality search:**

If the application needs `SELECT * FROM patients WHERE ssn = ?`:

```bash
curl -X POST http://localhost:5173/svc/dataprotect/encrypt/field \
  -H "Authorization: Bearer $APP_TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "fieldName": "ssn",
    "recordId": "search-context",
    "plaintext": "123-45-6789",
    "deterministic": true
  }'
# Same SSN always produces same ciphertext — allows index-based search
# Security trade-off: reveals that two patients have the same SSN
```

**Step 3 — Key rotation (annual or on incident):**

```bash
# Re-encrypt all SSN ciphertexts to new key version
# Call this for every patient record during the maintenance window:
curl -X POST http://localhost:5173/svc/dataprotect/reencrypt/field \
  -H "Authorization: Bearer $ROTATION_TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "fieldName": "ssn",
    "recordId": "patient-00192",
    "oldCiphertext": "AQIDAHjK9mP3qR7wL2Xk9mP3qR7wL2Xk9mP3qR7wL2VGhTkL9mP3=="
  }'
# Update DB: SET ssn = newCiphertext WHERE patient_id = 'patient-00192'
```

**Compliance outcome:** PHI columns contain only AES-256-GCM ciphertext. Key rotation is fully auditable. Associated data binding ensures ciphertext cannot be silently relocated to a different patient record.

---

### 9.3 TR-31 Key Injection into POS Terminals

**Context:** A payment processor injects Zone PIN Keys (ZPKs) into POS terminals during personalization. Keys must be transported in TR-31 key blocks per PCI PIN Security Requirement 18-3.

**Prerequisites:**
- KBPK (K1) stored in Vecta KMS, tagged `role=kbpk, zone=zone-a`
- ZPK (P0) stored in Vecta KMS, tagged `role=zpk, zone=zone-a, terminal=POS-00142`
- Caller holds `payment:operate` permission

**Step 1 — Wrap ZPK for transport to the POS terminal's key injection device:**

```bash
curl -X POST http://localhost:5173/svc/payment/tr31/wrap \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "workingKeyId": "5bc96h86-7939-6784-d5he-4e185h88chc8",
    "kbpkId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "keyUsage": "P0",
    "algorithm": "A",
    "modeOfUse": "N",
    "exportability": "S",
    "keyVersionNumber": "01"
  }'
# Returns TR-31 key block: "D0096P0AN01S0000..."
```

**Step 2 — Transmit key block to the key injection facility (KIF).**

The KIF's own KBPK may differ from the KMS KBPK. Use `translate` to re-wrap for the KIF's KBPK without exposing the ZPK:

```bash
curl -X POST http://localhost:5173/svc/payment/tr31/translate \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "keyBlock": "D0096P0AN01S0000...",
    "incomingKbpkId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "outgoingKbpkId": "7de29b53-8164-4e19-c712-5f48a22bf093"
  }'
```

**Step 3 — KIF injects translated key block into terminal.** Terminal unwraps using its local KBPK.

**Compliance outcome:** ZPK never appears in plaintext outside a TR-31 block. Full PCI PIN Security Requirement 18-3 compliance. Audit trail covers every wrap and translate operation.

---

### 9.4 ATM PIN Change Flow

**Context:** A bank allows customers to change their PIN at an ATM. The ATM captures the old PIN and new PIN as encrypted PIN blocks under the ATM's ZPK. The host must verify the old PIN and store a new PIN verification value.

**Prerequisites:**
- ATM ZPK stored in Vecta KMS
- PVK stored in Vecta KMS (for Visa PVV verification)

**Step 1 — Verify old PIN (PVV method):**

```bash
curl -X POST http://localhost:5173/svc/payment/pin/verify/pvv \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "encryptedPinBlock": "A3F7E29D4B1C8F62",
    "pan": "4532015112830366",
    "pinBlockFormat": 0,
    "zpkId": "5bc96h86-7939-6784-d5he-4e185h88chc8",
    "pvk1Id": "7de29b53-8164-4e19-c712-5f48a22bf093",
    "pvki": "1",
    "pvv": "8421"
  }'
# Response: {"verified": true}
```

**Step 2 — Translate new PIN block from ATM ZPK to host ZPK:**

```bash
curl -X POST http://localhost:5173/svc/payment/pin/translate \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "encryptedPinBlock": "F1E2D3C4B5A69788",
    "pan": "4532015112830366",
    "incomingFormat": 0,
    "incomingZpkId": "5bc96h86-7939-6784-d5he-4e185h88chc8",
    "outgoingFormat": 0,
    "outgoingZpkId": "6cd07i97-8a4a-7895-e6if-5f296i99didi"
  }'
```

**Step 3 — Compute new PVV and store on the card (for re-issuance) or in the host database:**

The new PVV is derived during the `translate` or a separate `generate` call, then stored on Track 2.

**Compliance outcome:** Old and new PINs never appear in plaintext on the host. Every PIN operation is logged to the audit trail with ATM terminal ID, PAN (masked), and operation type.

---

### 9.5 Data Warehouse Dynamic Masking

**Context:** A data analytics platform exposes a read-only API over the data warehouse. Data scientists, support engineers, and external auditors all query the same API with different data access needs.

**Prerequisites:**
- Masking policy `credit-card-masking` created (see Section 3.2)
- Masking policy `phi-masking` created for PHI fields
- Each caller JWT contains a `roles` claim: `["analyst"]`, `["support"]`, or `["auditor"]`

**Step 1 — Analyst queries customer records:**

The API gateway extracts the caller's roles from the JWT and passes them to the masking service:

```bash
curl -X POST http://localhost:5173/svc/dataprotect/mask/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "policyId": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "callerRoles": ["analyst"],
    "records": [
      {
        "customer_id": "C-10045",
        "card_number": "4532015112830366",
        "ssn": "123-45-6789",
        "full_name": "Jane Smith",
        "transaction_amount": 142.50
      }
    ]
  }'
```

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

### 9.6 Java Microservice Using JCA — Zero Code Change

**Context:** An existing Java microservice uses `javax.crypto.Cipher` with a locally-managed AES key. The security team wants to migrate the key into Vecta KMS without modifying the microservice's business logic.

**Prerequisites:**
- Vecta JCA provider dependency added to the service's `pom.xml`
- Vecta provider registered at application startup (see Section 6.1)
- Existing key migrated into Vecta KMS and accessible as alias `data-encryption-key`

**Before (local key management):**

```java
// Old code — key loaded from a local keystore file
KeyStore ks = KeyStore.getInstance("PKCS12");
ks.load(new FileInputStream("/etc/service/keystore.p12"), "changeit".toCharArray());
SecretKey key = (SecretKey) ks.getKey("data-encryption-key", "changeit".toCharArray());

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key);
byte[] ciphertext = cipher.doFinal(plaintext);
```

**After (Vecta KMS, same code structure):**

```java
// Only change: register VectaProvider at startup (in main() or @Configuration)
Security.insertProviderAt(new VectaProvider(vectaConfig), 1);

// Business logic code unchanged:
KeyStore ks = KeyStore.getInstance("VectaKMS"); // <- only this string changes
ks.load(null, null);
SecretKey key = (SecretKey) ks.getKey("data-encryption-key", null);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // unchanged
cipher.init(Cipher.ENCRYPT_MODE, key);                    // unchanged
byte[] ciphertext = cipher.doFinal(plaintext);            // unchanged
```

The `KeyStore.getInstance("VectaKMS")` call is the only change in the business logic layer. All subsequent JCA calls — `Cipher.getInstance`, `cipher.init`, `cipher.doFinal` — are identical. The JCA provider intercepts these calls and routes them to Vecta KMS.

**Compliance outcome:** Private key material removed from the filesystem. Key rotation, access policy, and audit logging managed centrally in Vecta KMS. Zero changes to the service's business logic or test suite.

---

### 9.7 PostgreSQL Column Encryption via PKCS#11

**Context:** A PostgreSQL 16 cluster needs to encrypt specific columns (SSNs, account numbers) using server-side transparent column encryption backed by Vecta KMS keys.

**Prerequisites:**
- Vecta PKCS#11 library installed at `/usr/lib/vecta/pkcs11/libvecta-pkcs11.so`
- PostgreSQL `pgcrypto` extension or a custom C extension that can call PKCS#11
- Encryption key `pg-column-encryption-key` in Vecta KMS, purpose `encrypt`/`decrypt`, tagged `pkcs11-slot=prod`

**Step 1 — Configure the PKCS#11 library:**

Create `/etc/vecta/pkcs11.conf` with `key_filter = tag:pkcs11-slot=prod` so only the column encryption key appears in the slot (see Section 5.3).

**Step 2 — Create a PostgreSQL wrapper function that calls PKCS#11:**

```sql
-- Create extension that wraps PKCS#11 encrypt/decrypt
-- (requires a custom C extension or pg_pkcs11 contrib module)
CREATE EXTENSION IF NOT EXISTS pg_vecta_pkcs11;

-- Configure the module to use the Vecta library
SELECT pg_vecta_pkcs11.configure(
    '/usr/lib/vecta/pkcs11/libvecta-pkcs11.so',
    'VectaKMS-Production',
    'pg-column-encryption-key'
);

-- Encrypt/decrypt helper functions
CREATE OR REPLACE FUNCTION encrypt_field(plaintext TEXT) RETURNS BYTEA
  LANGUAGE SQL AS $$
    SELECT pg_vecta_pkcs11.encrypt(plaintext::BYTEA, 'pg-column-encryption-key', 'AES/GCM');
  $$;

CREATE OR REPLACE FUNCTION decrypt_field(ciphertext BYTEA) RETURNS TEXT
  LANGUAGE SQL SECURITY DEFINER AS $$
    SELECT convert_from(
        pg_vecta_pkcs11.decrypt(ciphertext, 'pg-column-encryption-key', 'AES/GCM'),
        'UTF8'
    );
  $$;
```

**Step 3 — Encrypt sensitive column on insert:**

```sql
CREATE TABLE patients (
    patient_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    full_name   TEXT NOT NULL,
    ssn_enc     BYTEA,          -- stores encrypted SSN
    dob         DATE
);

-- Insert with encryption
INSERT INTO patients (full_name, ssn_enc, dob)
VALUES (
    'Jane Smith',
    encrypt_field('123-45-6789'),
    '1985-04-12'
);
```

**Step 4 — Decrypt on read (authorized roles only):**

```sql
-- Grant decrypt_field only to authorized roles
GRANT EXECUTE ON FUNCTION decrypt_field(BYTEA) TO phi_reader_role;
REVOKE EXECUTE ON FUNCTION decrypt_field(BYTEA) FROM PUBLIC;

-- Authorized read
SELECT patient_id, full_name, decrypt_field(ssn_enc) AS ssn
FROM patients
WHERE patient_id = '...';

-- Unauthorized read sees only ciphertext
SELECT patient_id, full_name, ssn_enc FROM patients;
```

**Compliance outcome:** SSN values stored as ciphertext in PostgreSQL. Encryption key lives in Vecta KMS and never touches PostgreSQL disk or memory in plaintext. Column decryption restricted to explicitly authorized database roles.

---

### 9.8 Autokey for Microservice Fleet — Self-Service

**Context:** A platform engineering team manages 40+ microservices. Each service needs its own AES-256 DEK for encrypting data at rest. Previously, developers opened tickets and waited 3–5 days for a KMS admin to provision keys manually.

**Prerequisites:**
- Autokey template `service-data-encryption-key` created (see Section 7.2)
- Platform team has assigned `allowedRequestorRoles: ["developer", "service-account"]`
- CI/CD pipeline service account holds the `developer` KMS role

**Step 1 — Developer requests a handle during service onboarding:**

```bash
# Run by the CI/CD pipeline during `make provision-keys`
curl -X POST http://localhost:5173/svc/autokey/autokey/handles \
  -H "Authorization: Bearer $CI_TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d '{
    "templateId": "e5f6a7b8-c9d0-1234-efab-567890123456",
    "handleName": "inventory-service-dek-prod",
    "serviceId": "inventory-service",
    "environment": "prod",
    "justification": "DEK for product catalog field encryption in inventory-service prod"
  }'
```

**Response:** Handle provisioned immediately (no approval required for this template). `keyId` returned within 2 seconds.

**Step 2 — Service reads its key ID from the handle at startup:**

```bash
# Startup script resolves handle → key ID
KEY_ID=$(curl -s \
  "http://localhost:5173/svc/autokey/autokey/handles?handleName=inventory-service-dek-prod" \
  -H "Authorization: Bearer $SVC_TOKEN" \
  -H "X-Tenant-ID: root" \
  | jq -r '.items[0].keyId')

export VECTA_DEK_KEY_ID=$KEY_ID
```

**Step 3 — Service uses the key ID for field encryption at runtime:**

```bash
curl -X POST http://localhost:5173/svc/dataprotect/encrypt/field \
  -H "Authorization: Bearer $SVC_TOKEN" \
  -H "X-Tenant-ID: root" \
  -H "Content-Type: application/json" \
  -d "{
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
curl "http://localhost:5173/svc/autokey/autokey/summary?tenant_id=root" \
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
