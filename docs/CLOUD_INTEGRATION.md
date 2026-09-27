# Cloud & Integration

Vecta KMS connects to the cloud provider ecosystem through four integration patterns: **BYOK** (Bring Your Own Key — you generate and control the key material imported into a cloud provider's KMS), **HYOK** (Hold Your Own Key — every encrypt/decrypt operation passes through your proxy, cloud sees neither plaintext nor key), **EKM** (External Key Manager — database and endpoint encryption controlled by Vecta), and **KMIP** (Key Management Interoperability Protocol — OASIS standard for storage, virtualization, and HSM integration). A fifth pillar, **Artifact Signing**, provides supply-chain security for binaries, containers, and Git commits.

---

## Table of Contents

1. [BYOK (Bring Your Own Key)](#1-byok-bring-your-own-key)
2. [HYOK (Hold Your Own Key)](#2-hyok-hold-your-own-key)
3. [EKM (External Key Manager)](#3-ekm-external-key-manager)
4. [KMIP (Key Management Interoperability Protocol)](#4-kmip-key-management-interoperability-protocol)
5. [Artifact Signing](#5-artifact-signing)
6. [Use Cases](#6-use-cases)
7. [API Reference](#7-api-reference)

---

## 1. BYOK (Bring Your Own Key)

### 1.1 What BYOK Solves

Cloud providers encrypt your data at rest by default, using keys they generate and manage. This is convenient but creates a key custody problem: the cloud provider generates, stores, and controls your encryption keys. If the provider is legally compelled to produce your data, or if their key management is compromised, your data is exposed.

BYOK shifts key custody back to you:

| Property | Provider-managed Keys | BYOK (Vecta + Cloud CMK) |
|---|---|---|
| Who generates the key | Cloud provider | You (Vecta KMS / HSM) |
| Who stores the key | Cloud HSM (opaque to you) | Cloud HSM, but you uploaded the material |
| Who can rotate the key | Cloud provider (on their schedule) | You (on your schedule) |
| Who can destroy the key | Cloud provider | You (triggers data inaccessibility) |
| Audit trail | Cloud provider's logs | Vecta immutable audit + cloud logs |
| Regulatory compliance | Shared responsibility | You satisfy "control your keys" clauses |

BYOK satisfies the "customer-managed keys" requirement in:
- GDPR Article 32 (appropriate technical measures)
- HIPAA § 164.312(a)(2)(iv) (encryption and decryption controls)
- PCI DSS Requirement 3.5 (cryptographic key management)
- FedRAMP FIPS 140-2 key management controls
- ISO 27001 Annex A.10 (cryptography)

**What BYOK does NOT provide:** The cloud provider still performs key operations (encrypt, decrypt) on your behalf. The key material lives in the cloud provider's HSM. If you need to prevent the cloud provider from performing operations under legal compulsion, see HYOK (Section 2).

### 1.2 BYOK Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Vecta KMS                                   │
│                                                                     │
│  1. Generate AES-256 key                                            │
│  2. Wrap key material with cloud provider's RSA wrapping key        │
│     (RSA-OAEP, cloud public key obtained from import parameters)    │
│  3. Export wrapped ciphertext (plaintext never leaves Vecta/HSM)    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Wrapped key ciphertext (HTTPS)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Cloud Provider KMS                             │
│                                                                     │
│  4. Receive wrapped key material                                    │
│  5. Unwrap inside cloud HSM using cloud's private RSA key           │
│  6. Store AES-256 key as Customer Managed Key (CMK)                 │
│  7. Use CMK for S3/Blob/GCS encryption, database encryption, etc.  │
│                                                                     │
│  Plaintext key material NEVER transits the network in any step.    │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.3 AWS KMS BYOK

AWS KMS external key import (BYOK) uses a two-step process: you get an RSA wrapping key from AWS, use Vecta to wrap your key material with it, and upload the wrapped material to AWS.

#### Step-by-Step: AWS KMS BYOK

**Step 1 — Create the key in Vecta**

```bash
curl -X POST "https://localhost/svc/keycore/keys?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-aws-s3-cmk",
    "algorithm": "AES-256",
    "purpose": "encrypt_decrypt",
    "key_backend": "hsm",
    "metadata": {
      "target": "aws",
      "service": "s3",
      "environment": "production"
    }
  }'
# Note the returned key ID: VECTA_KEY_ID
```

**Step 2 — Create an AWS External Key**

```bash
aws kms create-key \
  --origin EXTERNAL \
  --description "Vecta BYOK - S3 Production CMK" \
  --region us-east-1 \
  --tags '[{"TagKey":"managed-by","TagValue":"vecta-kms"}]'
# Note the returned KeyId: AWS_KEY_ID
```

**Step 3 — Get AWS Import Parameters**

```bash
aws kms get-parameters-for-import \
  --key-id $AWS_KEY_ID \
  --wrapping-algorithm RSAES_OAEP_SHA_256 \
  --wrapping-key-spec RSA_2048 \
  --region us-east-1 \
  --query '{PublicKey:PublicKey,ImportToken:ImportToken,ParametersValidTo:ParametersValidTo}'
```

This returns a base64-encoded RSA-2048 public key and an import token (valid for 24 hours).

**Step 4 — Wrap key material in Vecta**

```bash
curl -X POST "https://localhost/svc/keycore/keys/{VECTA_KEY_ID}/export?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "aws_byok",
    "wrapping_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----",
    "wrapping_algorithm": "RSAES_OAEP_SHA_256"
  }'
# Returns: {"wrapped_key_material": "base64-encoded-ciphertext"}
```

**Step 5 — Import to AWS**

```bash
# Decode wrapped material to binary
echo -n "$WRAPPED_KEY_MATERIAL" | base64 -d > wrapped-key.bin
echo -n "$IMPORT_TOKEN"         | base64 -d > import-token.bin

aws kms import-key-material \
  --key-id $AWS_KEY_ID \
  --encrypted-key-material fileb://wrapped-key.bin \
  --import-token fileb://import-token.bin \
  --expiration-model KEY_MATERIAL_EXPIRES \
  --valid-to 2027-03-22T00:00:00Z \
  --region us-east-1
```

**Step 6 — Register BYOK sync config in Vecta**

**Step 7 — Enable the CMK and verify**

```bash
# Enable the CMK (imported keys start in PendingImport/Disabled state)
aws kms enable-key --key-id $AWS_KEY_ID --region us-east-1

# Verify CMK is enabled
aws kms describe-key --key-id $AWS_KEY_ID --region us-east-1 \
  --query 'KeyMetadata.{State:KeyState,Origin:Origin,ValidTo:ValidTo}'

# Test encrypt/decrypt
PLAINTEXT_B64=$(echo -n "hello world" | base64)
CIPHERTEXT=$(aws kms encrypt \
  --key-id $AWS_KEY_ID \
  --plaintext $PLAINTEXT_B64 \
  --region us-east-1 \
  --query CiphertextBlob --output text)

aws kms decrypt \
  --ciphertext-blob fileb://<(echo "$CIPHERTEXT" | base64 -d) \
  --region us-east-1 \
  --query Plaintext --output text | base64 -d
# Output: hello world
```

#### AWS S3 Server-Side Encryption with CMK

```bash
# Configure S3 bucket to use the Vecta-managed CMK
aws s3api put-bucket-encryption \
  --bucket acme-prod-data \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"
      },
      "BucketKeyEnabled": true
    }]
  }'
```

#### AWS RDS Encryption with CMK

```bash
# Create RDS instance with Vecta-managed CMK
aws rds create-db-instance \
  --db-instance-identifier prod-payments-db \
  --db-instance-class db.r6g.xlarge \
  --engine postgres \
  --engine-version 15.4 \
  --storage-encrypted \
  --kms-key-id "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123" \
  --allocated-storage 500 \
  --region us-east-1
```

#### AWS BYOK Key Rotation

When the BYOK key approaches its expiry date (or you rotate per policy):

```bash
# Trigger rotation sync (Vecta rotates the Vecta key and re-imports to AWS)
curl -X POST "https://localhost/svc/cloud/cloud/sync?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "config_id": "BYOK_CONFIG_ID",
    "rotate": true,
    "reason": "scheduled_annual_rotation"
  }'
```

After rotation, AWS automatically re-encrypts data keys (but not data) under the new key material. Data encrypted under the old key material remains decryptable during the transition period.

---

### 1.4 Azure Key Vault BYOK

Azure BYOK imports key material to Azure Key Vault as an HSM-protected key. Azure requires the key material to be wrapped using Azure's Key Exchange Key (KEK).

#### Azure BYOK Step-by-Step

**Step 1 — Prepare Azure Key Vault**

```bash
# Create resource group and Key Vault
az group create --name rg-pki --location eastus

az keyvault create \
  --name acme-prod-kv \
  --resource-group rg-pki \
  --location eastus \
  --sku Premium \
  --enable-soft-delete true \
  --enable-purge-protection true \
  --retention-days 90

# Enable BYOK (Managed HSM is required for HSM-backed keys)
az keyvault update \
  --name acme-prod-kv \
  --resource-group rg-pki \
  --enable-rbac-authorization true
```

**Step 2 — Create Key Exchange Key (KEK) in Azure**

```bash
az keyvault key create \
  --vault-name acme-prod-kv \
  --name vecta-byok-kek \
  --kty RSA-HSM \
  --size 4096 \
  --ops import

# Get KEK public key
az keyvault key download \
  --vault-name acme-prod-kv \
  --name vecta-byok-kek \
  --file kek-public.pem \
  --encoding PEM
```

**Step 3 — Register Azure BYOK config in Vecta**

**Step 4 — Generate wrapped key material in Vecta**

**Step 5 — Import to Azure Key Vault**

```bash
BYOK_BLOB=$(cat vecta-byok.blob)

az keyvault key import \
  --vault-name acme-prod-kv \
  --name payments-cmk \
  --byok-string "$BYOK_BLOB" \
  --kty RSA-HSM \
  --ops encrypt decrypt wrapKey unwrapKey
```

**Step 6 — Assign key to Azure services**

```bash
# Azure Storage Account with Customer Managed Key
az storage account update \
  --name acmeprodsa \
  --resource-group rg-pki \
  --encryption-key-source Microsoft.Keyvault \
  --encryption-key-vault https://acme-prod-kv.vault.azure.net \
  --encryption-key-name payments-cmk \
  --encryption-key-version ""  # Use latest version

# Azure SQL Database with CMK
az sql db tde set \
  --database mydb \
  --resource-group rg-pki \
  --server myserver \
  --status Enabled

az sql server tde-key set \
  --resource-group rg-pki \
  --server myserver \
  --server-key-type AzureKeyVault \
  --kid "https://acme-prod-kv.vault.azure.net/keys/payments-cmk"
```

---

### 1.5 Google Cloud KMS BYOK

Google Cloud KMS BYOK uses Import Jobs. You create an import job which provides a wrapping key, then import your key material wrapped with that key.

#### Google Cloud BYOK Step-by-Step

**Step 1 — Create key ring and placeholder key**

```bash
# Create key ring
gcloud kms keyrings create vecta-managed \
  --location us-east1 \
  --project acme-prod

# Create a key with EXTERNAL origin (placeholder for imported material)
gcloud kms keys create payments-cmk \
  --keyring vecta-managed \
  --location us-east1 \
  --purpose encryption \
  --import-only \
  --project acme-prod
```

**Step 2 — Create an import job**

```bash
gcloud kms import-jobs create vecta-byok-job-001 \
  --keyring vecta-managed \
  --location us-east1 \
  --import-method rsa-oaep-4096-sha256-aes-256 \
  --protection-level hsm \
  --project acme-prod

# Get the wrapping key public key
gcloud kms import-jobs describe vecta-byok-job-001 \
  --keyring vecta-managed \
  --location us-east1 \
  --project acme-prod \
  --format "get(publicKey.pem)" > gcp-wrapping-key.pem
```

**Step 3 — Wrap and import via Vecta**

```bash

# Trigger Vecta to wrap and import
curl -X POST "https://localhost/svc/cloud/cloud/sync?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"config_id": "GCP_BYOK_CONFIG_ID"}'
```

**Step 4 — Verify import**

```bash
gcloud kms keys versions list \
  --key payments-cmk \
  --keyring vecta-managed \
  --location us-east1 \
  --project acme-prod

# Test encrypt
echo -n "hello world" | gcloud kms encrypt \
  --key payments-cmk \
  --keyring vecta-managed \
  --location us-east1 \
  --project acme-prod \
  --plaintext-file - \
  --ciphertext-file output.enc

gcloud kms decrypt \
  --key payments-cmk \
  --keyring vecta-managed \
  --location us-east1 \
  --project acme-prod \
  --ciphertext-file output.enc \
  --plaintext-file -
```

**Step 5 — Use CMK with GCS**

```bash
# Set default encryption on GCS bucket
gsutil kms authorize -p acme-prod -k \
  "projects/acme-prod/locations/us-east1/keyRings/vecta-managed/cryptoKeys/payments-cmk"

gsutil defstorageclass set REGIONAL gs://acme-prod-data
gsutil kms set \
  "projects/acme-prod/locations/us-east1/keyRings/vecta-managed/cryptoKeys/payments-cmk" \
  gs://acme-prod-data
```

---

### 1.6 BYOK Rotation and Lifecycle

#### Key Rotation

Key rotation in BYOK contexts has two distinct meanings:

1. **Vecta key rotation** — A new key version is created in Vecta. The old key material is superseded. New key material must be imported to the cloud provider.
2. **Cloud CMK version rotation** — The cloud provider creates a new CMK version. Data previously encrypted under the old version remains decryptable (cloud providers maintain multiple versions). New data uses the new version.

After rotation:
- AWS: old key material remains importable via key version. Data keys encrypted with old CMK version continue working until you explicitly delete the old key version.
- Azure: old key version kept accessible for decryption. New operations use new version.
- GCP: old import job and key version remain. Create a new import job and new key version for rotation.

#### Destruction

Destroying the Vecta key does not automatically destroy the cloud CMK. Both must be destroyed explicitly:

```bash

# Step 2: Delete cloud CMK (varies by provider)
# AWS:
aws kms schedule-key-deletion --key-id $AWS_KEY_ID --pending-window-in-days 30

# Azure:
az keyvault key delete --vault-name acme-prod-kv --name payments-cmk

# GCP:
gcloud kms keys versions destroy 1 \
  --key payments-cmk \
  --keyring vecta-managed \
  --location us-east1 \
  --project acme-prod
```

> **Warning:** Destroying the encryption key makes all data encrypted with it permanently inaccessible. Ensure complete backups exist before key destruction, or that the data is intentionally being rendered inaccessible (crypto-shredding / GDPR right to erasure).

---

### 1.7 BYOK Monitoring and Alerts

**Response:**

```json
{
  "config_id": "byok_01HXYZ...",
  "provider": "aws",
  "status": "synced",
  "last_sync_at": "2026-03-22T10:00:00Z",
  "key_material_valid_to": "2027-03-22T00:00:00Z",
  "days_until_expiry": 365,
  "rotation_due": false,
  "cloud_key_status": "Enabled",
  "cloud_key_arn": "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"
}
```

---

## 2. HYOK (Hold Your Own Key)

### 2.1 What HYOK Solves

BYOK keeps key material under your control before it reaches the cloud, but once imported, the cloud provider holds the key and can perform encryption and decryption operations on your behalf — or under legal compulsion without your knowledge.

HYOK (Hold Your Own Key) eliminates this residual exposure. With HYOK, the cloud provider **never receives the key material at all**. Every encryption and decryption operation the cloud service needs to perform must call through a proxy endpoint that you control. You can inspect, approve, deny, time-restrict, and audit every individual key operation.

| Property | BYOK | HYOK |
|---|---|---|
| You generate key material | Yes | Yes |
| Cloud provider holds key material | Yes (in their HSM) | No — never |
| Cloud can operate key without you | Yes | No — requires your proxy |
| Legal compulsion risk | Reduced (you control rotation) | Minimal (no key, no operation) |
| Data access if your proxy is offline | Normal (cloud has key) | Blocked (cloud cannot decrypt) |
| Latency overhead | None (after import) | Low (proxy round-trip per operation) |
| Audit of every key operation | No | Yes — every call logged |

### 2.2 HYOK Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Cloud Service (Microsoft 365 / Google Workspace)                       │
│                                                                         │
│  User opens encrypted document:                                         │
│  1. Cloud service calls → HYOK proxy (your endpoint)                   │
│     with: encrypted DEK, user identity JWT, tenant, operation           │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ HTTPS mutual TLS
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Vecta HYOK Proxy  (running inside your perimeter)                     │
│                                                                         │
│  2. Validate caller JWT (signature, expiry, issuer, audience)           │
│  3. Check HYOK policy:                                                  │
│     - Is the caller in allowed_callers[]?                               │
│     - Is it within the time_restrictions window?                        │
│     - Does the governance policy allow this operation?                  │
│     - Is a justification / ticket required?                             │
│  4. If approved → call Vecta keycore (HSM-backed decrypt/encrypt)      │
│  5. Return result to cloud service                                      │
│  6. Log every step to immutable audit trail                             │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ mTLS (internal)
                                     ▼
                         ┌───────────────────────┐
                         │   Vecta Keycore (HSM) │
                         │   AES-256 / EC-P384   │
                         └───────────────────────┘
```

### 2.3 Microsoft Double Key Encryption (DKE)

Microsoft 365 Double Key Encryption protects documents and emails with two independent keys. Microsoft manages one key; you manage the other via a DKE-compatible key service. Both keys are required to decrypt. Microsoft cannot decrypt without your key; you cannot decrypt without Microsoft's key.

**Supported workloads:**
- Microsoft Word, Excel, PowerPoint (protected documents)
- Outlook (protected emails)
- Teams (protected messages)
- SharePoint / OneDrive (protected files at rest)

#### How DKE Encryption Works

```
Encryption:
1. M365 generates a random symmetric Content Encryption Key (CEK)
2. Encrypts CEK with Microsoft's key (RSA-OAEP) → M-CEK
3. Calls your DKE endpoint to encrypt CEK with your key → D-CEK
4. Stores both M-CEK and D-CEK alongside the ciphertext

Decryption (when a user opens the document):
1. M365 unwraps M-CEK using Microsoft's key
2. Calls the key's kid + "/decrypt" → POST /svc/hyok/api/v1/keys/{key}/{version}/decrypt
   - Body: {"alg": "RSA-OAEP-256", "value": <wrapped CEK, base64>}; Authorization: the user's Entra ID token
3. Your endpoint validates the user's identity and decrypts D-CEK → CEK
4. M365 uses CEK to decrypt the document content
```

#### Vecta DKE Endpoints

The DKE key URL you put in the sensitivity label is
`https://<kms-host>/svc/hyok/api/v1/keys/<keycore key id>`.

| Method | Path | Auth |
|---|---|---|
| `GET` | `/svc/hyok/api/v1/keys/{id}` | none, only on the endpoint's `key_uri_hostname` (Office fetches it anonymously) |
| `POST` | `/svc/hyok/api/v1/keys/{id}/{version}/decrypt` | the user's Entra ID token (or a Vecta token) |

#### DKE Public Key Endpoint

**Response (the format Office reads):**

```json
{
  "key": {
    "kty": "RSA",
    "n": "<modulus, base64url>",
    "e": 65537,
    "alg": "RSA-OAEP-256",
    "kid": "<the key URL>/<version>"
  },
  "cache": {"exp": "<RFC 3339, 24 h ahead>"}
}
```

Office posts decrypt requests to `kid` + `/decrypt`.

#### DKE Decrypt Endpoint

**Request:** `{"alg": "RSA-OAEP-256", "value": "<wrapped CEK, base64>"}`
**Response:** `{"value": "<CEK, base64>"}`

Only the key's current version decrypts; a `kid` naming another version gets
`409 key_version_not_current`. Every refusal is audited as
`audit.hyok.dke_refused`.

#### DKE Azure AD Configuration

```
1. Entra admin center → App registrations → New registration ("Vecta DKE").
   Expose an API: its Application ID URI (e.g. api://dke.acme.com) is the
   token audience; put it in the endpoint's jwt_audiences.
   Optionally define an app role (e.g. DKE.Decrypt) and assign it to users.
2. Microsoft Purview → Information protection → Sensitivity labels:
   create a label with Double Key Encryption and the DKE key URL above.
3. Publish the label policy to the users who need it.
```

#### DKE Vecta Configuration

```bash
# RSA key for DKE
curl -X POST "https://localhost/svc/keycore/keys?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "m365-dke-key", "algorithm": "RSA-4096", "purpose": "encrypt_decrypt"}'

# DKE endpoint: which Entra tokens and users are accepted
curl -X PUT "https://localhost/svc/hyok/hyok/v1/endpoints/dke?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"enabled": true, "auth_mode": "jwt", "metadata_json": "{\"valid_issuers\":[\"https://login.microsoftonline.com/<entra-tenant-id>/v2.0\"],\"jwt_audiences\":[\"api://dke.acme.com\"],\"authorized_roles\":[\"DKE.Decrypt\"],\"key_uri_hostname\":\"kms.acme.com\"}"}'
```

The same fields are in the dashboard under HYOK → DKE. An Entra token is
accepted only when its issuer is in `valid_issuers`, its audience in
`jwt_audiences`, and the user is in `authorized_emails` or holds one of
`authorized_roles`.

### 2.4 Google Client-Side Encryption (CSE)

Google Workspace Client-Side Encryption ensures that Google never receives plaintext data or encryption keys. The encryption happens in the browser or client before data is sent to Google.

**Supported Workloads:**
- Google Drive (Docs, Sheets, Slides, files)
- Gmail (encrypted messages and attachments)
- Google Meet (video call recordings)
- Google Calendar (event details)

#### How Google CSE Works

```
Upload (Encryption):
1. Browser generates a random DEKS (Data Encryption Key Symmetric)
2. Calls Vecta CSE endpoint to wrap DEKS → wrapped DEKS
3. Uploads ciphertext + wrapped DEKS to Google

Download (Decryption):
1. Google sends wrapped DEKS + user identity to your CSE endpoint
2. Vecta validates the identity and unwraps DEKS
3. Browser uses DEKS to decrypt the content
4. Google never saw DEKS in plaintext
```

#### Vecta Google CSE Endpoints

Google calls the KACLS endpoints on the ekm service:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/svc/ekm/ekm/kacls/status` | KACLS status |
| `POST` | `/svc/ekm/ekm/kacls/wrap` | Wrap a DEK |
| `POST` | `/svc/ekm/ekm/kacls/unwrap` | Unwrap a DEK |
| `POST` | `/svc/ekm/ekm/kacls/privilegedunwrap` | Privileged unwrap (admin/legal) |

The authorization token must be signed by a Google CSE token issuer for
audience `cse-authorization`. The authentication token must be a Google ID
token whose audience is one of the config's `authentication_client_ids`
(the OAuth client ID of your CSE identity provider) and whose hosted domain
is in `allowed_domains`. Configs are managed at `/svc/ekm/ekm/google-cse/configs`.

#### Google Workspace Admin Setup

```
1. Google Admin Console → Apps → Google Workspace → Drive and Docs → Client-side encryption
2. Configure key access control list service:
   - Issuer: accounts.google.com
3. Enable CSE for specific organizational units
4. Configure CSE labels for document classification
```

---

### 2.5 HYOK Policies

There is no separate HYOK policy object. A protocol endpoint
(`PUT /svc/hyok/hyok/v1/endpoints/{protocol}`) links a `policy_id` evaluated
by the policy service, can require governance approval
(`governance_required`), and for DKE carries the identity rules above. Every
request is logged (`GET /svc/hyok/hyok/v1/requests`) and audited.

## 3. EKM (External Key Manager)

### 3.1 Database Transparent Data Encryption (TDE)

Transparent Data Encryption encrypts database files, log files, and backups at rest without requiring application changes. The database engine transparently encrypts data as it writes to disk and decrypts it as it reads.

**TDE Key Hierarchy:**

```
                ┌──────────────────────────┐
                │      Vecta KMS           │
                │   Master Key (HSM)       │
                │   (never leaves Vecta)   │
                └────────────┬─────────────┘
                             │ wraps
                             ▼
                ┌──────────────────────────┐
                │  Database Master Key      │
                │  (stored in DB, wrapped)  │
                └────────────┬─────────────┘
                             │ wraps
                             ▼
                ┌──────────────────────────┐
                │  Database Encryption Key  │
                │  (DEK — wraps pages)      │
                └────────────┬─────────────┘
                             │ encrypts
                             ▼
                ┌──────────────────────────┐
                │  Database files, logs,   │
                │  backups on disk          │
                └──────────────────────────┘
```

**Benefits of External Key Management for TDE:**

| Benefit | Description |
|---|---|
| Key separation | Database administrators cannot access the master key |
| Centralized rotation | Rotate keys in Vecta; all databases pick up the new version |
| Hardware custody | Master key in HSM, not in a database server file |
| Audit trail | Every key operation logged centrally |
| Compliance | Satisfies PCI DSS Req 3.6 (key custodian separation), HIPAA, SOC 2 |

### 3.2 EKM Agent

The Vecta EKM Agent is a lightweight process that runs on the database server. It presents a local interface (PKCS#11, MSSQL EKM provider DLL, or Oracle PKCS#11 library) to the database engine and proxies all key operations to Vecta KMS over mutual TLS.

```
Database Engine
     │
     │ Local interface (DLL / PKCS#11)
     ▼
Vecta EKM Agent (localhost)
     │
     │ mTLS (port 8443)
     ▼
Vecta KMS API
     │
     │ HSM operation
     ▼
Hardware Security Module
```

**Agent heartbeat:** Every 30 seconds, the agent sends a heartbeat to Vecta. If the agent fails to heartbeat for > 90 seconds, an alert is generated and the database server appears as `unreachable` in the EKM dashboard.

#### Install EKM Agent

```bash
# Download agent installer
curl -o vecta-ekm-agent-installer.sh \
  "https://kms.internal.acme.com/downloads/ekm-agent/latest/linux-amd64/install.sh"

chmod +x vecta-ekm-agent-installer.sh

# Install with configuration
sudo ./vecta-ekm-agent-installer.sh \
  --kms-url "https://kms.internal.acme.com" \
  --tenant-id "root" \
  --agent-token "ekm-agent-token-here" \
  --cert-file "/etc/vecta-ekm/agent.pem" \
  --key-file  "/etc/vecta-ekm/agent.key" \
  --ca-file   "/etc/vecta-ekm/ca-chain.pem"

# Start agent
sudo systemctl enable --now vecta-ekm-agent
sudo systemctl status vecta-ekm-agent
```

### 3.3 Which databases can keep their TDE key in Vecta

Vecta holds a TDE master key only through its KMIP server (TTLV over mTLS,
port 5696). Register a KMIP client in the KMIP tab first; it issues the client
certificate and key, and the CA to trust is the Vecta internal CA. The EKM
agent reports TDE state; it is not in the database's key path.

| Engine | Vecta integration | How |
|---|---|---|
| MySQL Enterprise | Yes | `keyring_okv` plugin: `okvclient.ora` with `SERVER=<kms-host>:5696` and an `ssl/` directory holding `CA.pem`, `cert.pem`, `key.pem` |
| PostgreSQL (Percona pg_tde) | Yes | pg_tde KMIP key provider pointing at `<kms-host>:5696` |
| Db2 native encryption | Yes | `KEYSTORE_TYPE KMIP` with a KMIP configuration file |
| Microsoft SQL Server | No | needs an EKM provider DLL implementing SQL Server's EKM interface; Vecta ships none |
| Oracle | No | needs a software keystore, Oracle Key Vault, or a PKCS#11 HSM library; Vecta ships none |
| MariaDB | No | its key management plugins do not speak KMIP |

These earlier sections described a `vecta-ekm.dll` SQL Server provider and a
`vecta-pkcs11.so` Oracle library. Neither exists; the text was removed in
1.27.0-beta ([REAL_CAPABILITY.md](SECURITY/REAL_CAPABILITY.md)).

### 3.4 BitLocker Endpoint Encryption

The EKM agent on a Windows host (`services/ekm-agent`) registers as a
BitLocker client, sends heartbeats with the host's BitLocker state, and runs
jobs the KMS queues for it; recovery material it reports is stored under the
ekm master key.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/svc/ekm/ekm/bitlocker/clients/register` | Register a Windows host |
| `GET` | `/svc/ekm/ekm/bitlocker/clients` | Hosts and their reported BitLocker state |
| `GET` | `/svc/ekm/ekm/bitlocker/clients/{id}/deploy` | Agent deployment package for a host |
| `POST` | `/svc/ekm/ekm/bitlocker/clients/{id}/operations` | Queue an operation (for example enable or rotate) |
| `GET` | `/svc/ekm/ekm/bitlocker/clients/{id}/jobs` | Jobs and their results |
| `GET` | `/svc/ekm/ekm/bitlocker/recovery` | Recovery keys (audited on every read) |

The agent itself calls `.../clients/{id}/heartbeat`, `.../jobs/next` and
`.../jobs/{job_id}/result` over TLS with its agent credential.

---

## 4. KMIP (Key Management Interoperability Protocol)

### 4.1 Protocol Overview

KMIP is an OASIS standard protocol (current version: 2.1, published 2019) that defines a common interface for key management servers. Storage arrays, virtualization platforms, tape libraries, databases, and HSMs that speak KMIP can interoperate with any KMIP-compliant KMS — including Vecta.

**Transport:** TLS 1.3 on port 5696 (default KMIP port). Mutual authentication — both client and server present X.509 certificates.

**Encoding:** TTLV (Tag-Type-Length-Value) binary encoding by default; XML encoding available. Vecta supports both.

**KMIP Versions:** Vecta implements KMIP 1.4 and 2.0. The protocol version is negotiated at connection time using the `Discover Versions` operation.

#### Object Types

| Object Type | Description |
|---|---|
| Symmetric Key | AES, 3DES, etc. — the most common KMIP object type |
| Asymmetric Key Pair | RSA, EC key pairs (public + private) |
| Certificate | X.509 certificates |
| Secret Data | Passwords, tokens, arbitrary binary secrets |
| Opaque Object | Vendor-specific data objects |

#### Object States (KMIP lifecycle)

```
Pre-Active → Active → Deactivated → Compromised → Destroyed
```

| State | Description |
|---|---|
| Pre-Active | Key created but not yet approved for use |
| Active | Key in normal operational use |
| Deactivated | Key no longer used for new operations; may still decrypt old data |
| Compromised | Key known or suspected compromised; avoid use |
| Destroyed | Key material permanently deleted |
| Destroyed Compromised | Key was compromised and then destroyed |

### 4.2 Supported Operations

| Operation | KMIP 1.4 | KMIP 2.0 | Notes |
|---|---|---|---|
| `Create` | ✓ | ✓ | Create symmetric key |
| `Create Key Pair` | ✓ | ✓ | Create asymmetric key pair |
| `Register` | ✓ | ✓ | Import existing key/object |
| `Get` | ✓ | ✓ | Retrieve managed object (key material) |
| `Get Attributes` | ✓ | ✓ | Get object metadata |
| `Set Attributes` | ✓ | ✓ | Update object metadata |
| `Add Attributes` | ✓ | ✓ | Add metadata attributes |
| `Delete Attributes` | ✓ | ✓ | Remove metadata attributes |
| `Locate` | ✓ | ✓ | Search objects by attributes |
| `Destroy` | ✓ | ✓ | Delete managed object |
| `Activate` | ✓ | ✓ | Transition key to Active state |
| `Revoke` | ✓ | ✓ | Transition to Compromised/Deactivated |
| `Obtain Lease` | ✓ | ✓ | Time-limited access to key |
| `Locate` | ✓ | ✓ | Search by attributes |
| `Encrypt` | ✗ | ✓ | Encrypt data using server-side key |
| `Decrypt` | ✗ | ✓ | Decrypt data using server-side key |
| `Sign` | ✗ | ✓ | Sign data |
| `Signature Verify` | ✗ | ✓ | Verify signature |
| `MAC` | ✗ | ✓ | Generate MAC |
| `MAC Verify` | ✗ | ✓ | Verify MAC |
| `RNG Retrieve` | ✓ | ✓ | Retrieve random bytes |
| `Query` | ✓ | ✓ | Query server capabilities |
| `Discover Versions` | ✓ | ✓ | Negotiate protocol version |
| `Check` | ✓ | ✓ | Check key meets constraints |
| `Get Usage Allocation` | ✓ | ✓ | Get remaining key usage |

### 4.3 KMIP Connection Setup

#### Create KMIP Client Profile

A client profile defines which operations a specific KMIP client is authorized to perform and which key groups it can access.

```bash
curl -X POST "https://localhost/svc/kmip/kmip/profiles?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "netapp-storage-cluster-01",
    "description": "NetApp ONTAP 9.12 cluster — volume encryption keys",
    "client_certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIBxDCCAW...\n-----END CERTIFICATE-----",
    "allowed_operations": [
      "create", "get", "destroy", "activate", "revoke",
      "locate", "get_attributes", "set_attributes"
    ],
    "object_groups": ["storage-keys", "volume-keys"],
    "allowed_algorithms": ["AES-256"],
    "allowed_key_states": ["Pre-Active", "Active", "Deactivated"],
    "max_keys_per_session": 10000,
    "require_attribute_name_on_create": true
  }'
```

#### Issue KMIP Client Certificate

```bash
# Issue client certificate for the KMIP client
curl -X POST "https://localhost/svc/certs/certs?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "ca_id": "CLIENT_ISSUING_CA_ID",
    "profile_id": "client-mtls-365d",
    "subject_cn": "netapp-cluster-01",
    "sans": [{"type": "dns", "value": "netapp01.storage.internal.acme.com"}],
    "cert_type": "client",
    "validity_days": 365,
    "algorithm": "EC-P256"
  }'
```

### 4.4 KMIP Integration Examples

#### NetApp ONTAP Volume Encryption

```
# NetApp ONTAP 9.x — KMIP key server configuration
# Run in ONTAP CLI as admin

# Add Vecta as key manager
security key-manager external add-servers \
  -vserver svm-prod \
  -key-servers kms.internal.acme.com:5696 \
  -client-cert netapp-cluster-01 \
  -server-ca-certs vecta-internal-ca

# Verify connectivity
security key-manager external show
security key-manager external check

# Enable volume-level encryption
volume create \
  -vserver svm-prod \
  -volume vol_payments \
  -size 10TB \
  -encrypt true \
  -encryption-type volume
```

#### VMware vSphere VM Disk Encryption

VMware vCenter uses KMIP to manage keys for VM Encryption (vSphere VM Encryption encrypts VM disk files using keys from an external KMS).

```
# vCenter → Security → Key Providers → Add Standard Key Provider
Name: Vecta KMS
Protocol: KMIP
Address: kms.internal.acme.com
Port: 5696
Proxy: (leave blank for direct connection)

# Upload certificates
Server certificate: (Vecta's KMIP server cert)
Client certificate: (cert issued by Vecta PKI for vCenter)
Client private key: (private key for client cert)

# Test connection
vCenter → Security → Key Providers → Test Connection

# Create storage policy using KMS
VM Storage Policies → Create Policy → Enable encryption → Select Vecta KMS provider

# Encrypt a VM
VM → Actions → Encrypt → Select encryption storage policy
```

**vSphere API (PowerCLI):**

```powershell
# Connect to vCenter
Connect-VIServer -Server vcenter.internal.acme.com

# Get KMS cluster
$kmsCluster = Get-KmsCluster -Name "Vecta KMS"

# Encrypt VM disks
$vm = Get-VM "payments-vm-01"
$storagePolicy = Get-SpbmStoragePolicy "Vecta Encrypted"

Set-SpbmEntityConfiguration -StoragePolicy $storagePolicy -Entity $vm.ExtensionData.Config.Hardware.Device |
  Where-Object {$_ -is [VMware.Vim.VirtualDisk]}
```

#### Pure Storage FlashArray

```
# Pure Storage FlashArray — KMIP key management
# Access Array Management Interface → Protection → Encryption

purestorage.setkmip(
    address="kms.internal.acme.com",
    port=5696,
    ca_cert=open("vecta-ca-chain.pem").read(),
    client_cert=open("pure-client.pem").read(),
    client_key=open("pure-client.key").read()
)

# Verify connectivity
purestorage.getkmipstatus()
```

#### IBM Spectrum Protect (Tivoli Storage Manager)

```
# TSM key management via KMIP
# Edit tsm.opt
KMIP_HOST kms.internal.acme.com
KMIP_PORT 5696
KMIP_CERTFILE /opt/tsmekm/certs/vecta-ca.pem
KMIP_CLIENTCERT /opt/tsmekm/certs/tsm-client.pem
KMIP_CLIENTKEY /opt/tsmekm/certs/tsm-client.key
KMIP_PROTOCOL TLSV13
```

#### Brocade / HPE SAN Switch

```
# Brocade switch KMIP configuration
# Via switch CLI:
cryptocfg --set -kmipserver kms.internal.acme.com 5696
cryptocfg --set -kmip_ca /etc/security/vecta-ca.pem
cryptocfg --set -kmip_cert /etc/security/brocade-client.pem
cryptocfg --set -kmip_key /etc/security/brocade-client.key
cryptocfg --export kmip
```

---

### 4.5 KMIP Object Management via API

While KMIP clients communicate over the KMIP binary protocol, Vecta also exposes a REST interface for managing KMIP objects.

```bash

# List KMIP client profiles
curl "https://localhost/svc/kmip/kmip/profiles?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

```

### 4.6 mTLS Setup for KMIP Clients

All KMIP clients must authenticate with a client certificate. The steps are:

1. Issue a client certificate from Vecta PKI (cert_type: `client`).
2. Create a KMIP client profile referencing the client certificate's CN or fingerprint.
3. Configure the KMIP client with: client cert PEM, client key PEM, Vecta CA chain PEM, server hostname, port 5696.
4. Test the connection using the KMIP client's built-in connectivity test.

```bash
# Complete mTLS setup script for a new KMIP client
CLIENT_NAME="new-storage-array"
TENANT="root"

# Step 1: Issue client cert
CERT_RESPONSE=$(curl -sk -X POST "https://localhost/svc/certs/certs?tenant_id=${TENANT}" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"ca_id\": \"CLIENT_ISSUING_CA_ID\",
    \"profile_id\": \"client-mtls-365d\",
    \"subject_cn\": \"${CLIENT_NAME}\",
    \"cert_type\": \"client\",
    \"validity_days\": 365,
    \"algorithm\": \"EC-P256\"
  }")

CERT_ID=$(echo $CERT_RESPONSE | jq -r '.id')
CERT_PEM=$(echo $CERT_RESPONSE | jq -r '.certificate_pem')
KEY_PEM=$(echo $CERT_RESPONSE | jq -r '.private_key_pem')

echo "$CERT_PEM" > "${CLIENT_NAME}-client.pem"
echo "$KEY_PEM"  > "${CLIENT_NAME}-client.key"

# Step 2: Create KMIP profile
curl -X POST "https://localhost/svc/kmip/kmip/profiles?tenant_id=${TENANT}" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"name\": \"${CLIENT_NAME}\",
    \"client_certificate_pem\": $(jq -Rs . <<< "$CERT_PEM"),
    \"allowed_operations\": [\"create\", \"get\", \"destroy\", \"activate\", \"locate\"],
    \"object_groups\": [\"storage-keys\"]
  }"

echo "Client cert: ${CLIENT_NAME}-client.pem"
echo "Client key:  ${CLIENT_NAME}-client.key"
echo "CA chain:    vecta-ca-chain.pem"
echo "KMIP server: kms.internal.acme.com:5696"
```

---

## 5. Artifact Signing

### 5.1 What Artifact Signing Provides

Software supply chain attacks have become one of the most impactful attack vectors. An attacker who can inject malicious code into a build pipeline or replace a published artifact can compromise every system that deploys that artifact.

Artifact signing addresses this by providing:

| Guarantee | Mechanism |
|---|---|
| **Integrity** | Signature is invalid if artifact is modified after signing |
| **Attribution** | Signature is tied to a specific key / identity (the signer) |
| **Non-repudiation** | Signer cannot deny having signed; the KMS keeps a signing record |
| **Timeliness** | The signing record carries the time and a per-tenant sequence number |
| **Verifiability** | Any party with the public key can verify, without trusting the signer |

### 5.2 Supported Artifact Types

| `artifact_type` | Description | Verification |
|---|---|---|
| `artifact` | General file (SHA-256 hash signing) | `sha256sum` + Vecta verify API |
| `blob` | Binary blob (inline data signing) | Vecta verify API |
| `git` | Git commit / tag signing | `git verify-commit`, `git verify-tag` |
| `container` | OCI container image (cosign-compatible) | `cosign verify` |
| `sbom` | Software Bill of Materials (SPDX, CycloneDX) | Vecta verify API |

### 5.3 Signing Profiles

A signing profile (`/svc/signing/signing/profiles`) fixes the artifact type,
the keycore signing key and algorithm, who may sign (`identity_mode`: allowed
workload patterns, OIDC issuers and subject patterns, repositories) and a
content `policy` (`required_branch_patterns`, `required_artifact_tags`,
`allowed_digests`, CI-only signing).

### 5.4 Signing an Artifact

```bash
# Sign a container image by digest (also: artifact_type "artifact", "sbom", ...)
curl -X POST "https://kms.acme.com/svc/signing/signing/blob?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"profile_id\": \"$PROFILE_ID\", \"artifact_type\": \"container\",
       \"artifact_name\": \"payments/payment-service\",
       \"oci_reference\": \"registry.acme.com/payments/payment-service@$DIGEST\",
       \"digest_sha256\": \"${DIGEST#sha256:}\"}"
# Returns {"record": {id, signature, key_id, signing_algorithm, digest_sha256,
#          transparency_entry_id, transparency_index, ...}, "envelope": {...}}
```

Git commits and tags are signed with `POST /svc/signing/signing/git`
(`repository`, `commit_sha`, and the payload).

### 5.5 Verifying

```bash
curl -X POST "https://kms.acme.com/svc/signing/signing/verify?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"record_id\": \"$RECORD_ID\", \"digest_sha256\": \"$SHA256\"}"
# Returns {"valid", "signature_valid", "digest_checked", "digest_match", "verified_at", ...}
```

Verification checks the stored signature with keycore and, when a digest or
payload is given, that it matches what was signed.

### 5.6 Signing Records

Every signature is stored as a record (`GET /svc/signing/signing/records`)
with a per-tenant sequence number (`transparency_index`) and a hash over the
payload and signature (`transparency_hash`). This is an append-only record in
the KMS, not a public transparency log: there is no Merkle tree, inclusion
proof or Rekor-compatible API.

### 5.8 Security Considerations for Signing

| Consideration | Recommendation |
|---|---|
| Key algorithm | EC-P384 or Ed25519 minimum; no RSA < 3072 for new signing keys |
| Key storage | HSM backend for all production signing keys |
| Profile identities | Restrict `allowed_subject_patterns` / workload patterns to CI identities, not developer accounts |
| Branch policies | Require protected branches for production signing |
| Key rotation | Rotate signing keys annually; re-sign any long-lived artifacts |
| Verification | Verify (`/svc/signing/signing/verify`) in the deploy pipeline before an image runs |
| SBOM signing | Sign SBOMs alongside binaries for full provenance chain |

---

## 6. Use Cases

### Use Case 1 — BYOK for AWS S3 Server-Side Encryption

**Scenario:** Regulatory requirement that encryption keys for customer data stored in S3 are generated by the customer (not AWS). GDPR compliance for EU customer data.

**Architecture:** Tenant HSM (via the KMS HSM connector) → BYOK import → AWS KMS CMK → S3 SSE-KMS

**Steps:**
1. Generate the AES-256 key in the KMS (Section 1.3, Steps 1–7). To have it generated inside your own HSM, check **Create in HSM** (docs/SECURITY/HSM_INTEGRATION.md); note a key that never leaves the HSM can't be exported for BYOK, so BYOK keys are created in the KMS
2. Configure S3 bucket default encryption to use CMK
3. Register auto-rotation sync in Vecta (annual)
4. Test: upload object, verify encryption; rotate key, verify old objects still accessible

**Key metrics:** Key generation in the KMS, key material import via RSA-OAEP (no plaintext in transit), all S3 objects encrypted with CMK, rotation logged in Vecta audit trail.

---

### Use Case 2 — HYOK for Microsoft 365 Classified Documents

**Scenario:** Legal and M&A documents classified as "Strictly Confidential" encrypted with DKE. Not even Microsoft can access the content under subpoena.

**Architecture:** M365 Sensitivity Label → DKE policy → Vecta HYOK proxy → Vecta KMS (keys optionally resident in the tenant's HSM)

**Steps:**
1. Create the RSA-4096 DKE key in the KMS (RSA decryption for DKE runs in the KMS; HSM-resident RSA keys sign only)
2. Create HYOK policy with `allowed_callers` = legal team members, business hours restriction
3. Configure Azure AD app registration for DKE
4. Create "Strictly Confidential" sensitivity label in Microsoft Purview pointing to Vecta DKE endpoint
5. Publish label to legal team
6. Test: apply label to document, open from another user, verify HYOK proxy audit log shows the decrypt call

---

### Use Case 3 — Database TDE for PCI DSS Scope Reduction

**Scenario:** Payment card data stored in MySQL Enterprise or PostgreSQL
(Percona pg_tde). PCI DSS Requirement 3.5 requires key custodian separation:
the TDE master key is held in Vecta, not on the database host.

**Architecture:** database TDE → KMIP (mTLS, port 5696) → Vecta KMS

**Steps:**
1. Issue a KMIP client certificate for the database host and register the client (KMIP tab)
2. Configure the engine's KMIP key provider (Section 3.3)
3. Enable TDE on the PCI-scoped tables or tablespaces
4. Document key custodian roles (security team = Vecta admin, DBA = database admin)

**PCI DSS evidence:** the Vecta audit log records every KMIP key operation.
SQL Server and Oracle cannot use Vecta for their TDE keys (Section 3.3).

---

### Use Case 4 — KMIP with VMware vSphere VM Encryption

**Scenario:** All production VMs on vSphere encrypted. Keys managed by Vecta, not stored on vCenter or ESXi hosts.

**Architecture:** VM disk files → vSphere encryption → KMIP → Vecta KMS → HSM

**Steps:**
1. Issue KMIP client cert for vCenter from Vecta PKI
2. Create KMIP client profile for vCenter in Vecta
3. Configure vCenter Key Provider pointing to Vecta KMIP (port 5696)
4. Create vSphere VM Encryption Storage Policy using Vecta key provider
5. Assign policy to production VM storage
6. Verify: VMs show encrypted status; check Vecta KMIP audit log for Create operations

---

### Use Case 5 — Container Signing in CI/CD Pipeline

**Scenario:** GitLab CI pipeline builds container images and signs them; the deploy job refuses an image whose signature does not verify.

**Architecture:** GitLab CI → sign image (signing record) → deploy job verifies → deploy

**Steps:**
1. Create an Ed25519 signing key in the KMS (for a key that never leaves your HSM, create an ECDSA P-256 key with **Create in HSM**)
2. Create a container signing profile limited to the GitLab CI identity (Section 5.3)
3. Add the signing call to `.gitlab-ci.yml` (Section 5.4)
4. Add a verify call to the deploy job and stop on `"valid": false` (Section 5.5)
5. Test: a signed image deploys; an unsigned or altered one stops the job

---

### Use Case 6 — Git Commit Signing for Source Integrity

**Scenario:** Every commit merged to `main` gets a KMS-held signature and a signing record, so a release can prove which commits CI accepted.

**Steps:**
1. Create a signing key in Vecta and a `git` signing profile limited to the CI identity and `required_branch_patterns: ["refs/heads/main"]` (Section 5.3)
2. In the merge pipeline, sign each commit with `POST /svc/signing/signing/git` (`repository`, `commit_sha`)
3. Before a release, verify the commits' records with `POST /svc/signing/signing/verify`

Vecta does not act as a local `git commit -S` signing program; developers' own commit signatures stay with their Git hosting.

---

## 7. API Reference

### BYOK Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/cloud/cloud/sync` | Trigger BYOK sync |

### HYOK Endpoints

### EKM Endpoints

### KMIP Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/kmip/kmip/profiles` | Create KMIP client profile |
| `GET` | `/svc/kmip/kmip/profiles` | List KMIP client profiles |
| `DELETE` | `/svc/kmip/kmip/profiles/{id}` | Delete KMIP client profile |

### Artifact Signing Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/signing/signing/verify` | Verify a signature |

### Common Query Parameters

All endpoints that return lists support:

| Parameter | Description |
|---|---|
| `tenant_id` | Required. Tenant identifier (e.g., `root`) |
| `page` | Page number (1-based) |
| `per_page` | Items per page (default 50, max 500) |
| `sort` | Sort field (e.g., `created_at`, `name`) |
| `order` | Sort direction: `asc` or `desc` |

### Authentication

All endpoints require a Bearer token in the `Authorization` header:

```bash
Authorization: Bearer eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
```

Tokens are obtained via:

```bash
curl -X POST "https://localhost/svc/auth/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "grant_type": "client_credentials"
  }'
```

---

*Last updated: 2026-03-22 | Vecta KMS Cloud & Integration Documentation*
