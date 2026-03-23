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
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=root" \
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
curl -X POST "http://localhost:5173/svc/keycore/keys/{VECTA_KEY_ID}/export?tenant_id=root" \
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

```bash
curl -X POST "http://localhost:5173/svc/cloud/byok/configs?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-aws-s3-byok",
    "provider": "aws",
    "region": "us-east-1",
    "account_id": "123456789012",
    "key_arn": "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123...",
    "vecta_key_id": "VECTA_KEY_ID",
    "config_json": {
      "wrapping_algorithm": "RSAES_OAEP_SHA_256",
      "wrapping_key_spec": "RSA_2048",
      "expiration_model": "KEY_MATERIAL_EXPIRES",
      "valid_to": "2027-03-22T00:00:00Z"
    },
    "credentials_ref": "aws-prod-creds",
    "auto_rotate": true,
    "rotate_before_expiry_days": 30
  }'
```

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
curl -X POST "http://localhost:5173/svc/cloud/byok/sync?tenant_id=root" \
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

```bash
curl -X POST "http://localhost:5173/svc/cloud/byok/configs?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-azure-kv-byok",
    "provider": "azure",
    "azure_vault_url": "https://acme-prod-kv.vault.azure.net",
    "azure_key_name": "payments-cmk",
    "vecta_key_id": "VECTA_KEY_ID",
    "config_json": {
      "kek_kid": "https://acme-prod-kv.vault.azure.net/keys/vecta-byok-kek/version",
      "kek_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
      "wrapping_algorithm": "CKM_RSA_AES_KEY_WRAP",
      "target_key_type": "RSA-HSM",
      "target_key_size": 2048
    },
    "credentials_ref": "azure-prod-creds"
  }'
```

**Step 4 — Generate wrapped key material in Vecta**

```bash
curl -X POST "http://localhost:5173/svc/cloud/byok/configs/{CONFIG_ID}/wrap?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_format": "azure_byok_v1",
    "kek_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }'
# Returns: {"byok_blob": "base64-encoded-byok-blob", "key_release_policy": "..."}
```

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
# Register GCP BYOK config
curl -X POST "http://localhost:5173/svc/cloud/byok/configs?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-gcp-kms-byok",
    "provider": "gcp",
    "project_id": "acme-prod",
    "location": "us-east1",
    "keyring": "vecta-managed",
    "key_name": "payments-cmk",
    "vecta_key_id": "VECTA_KEY_ID",
    "config_json": {
      "import_job_name": "vecta-byok-job-001",
      "import_method": "rsa-oaep-4096-sha256-aes-256",
      "protection_level": "HSM",
      "wrapping_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    },
    "credentials_ref": "gcp-prod-creds"
  }'

# Trigger Vecta to wrap and import
curl -X POST "http://localhost:5173/svc/cloud/byok/sync?tenant_id=root" \
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

```bash
# Trigger BYOK rotation (Vecta generates new key material, imports to cloud)
curl -X POST "http://localhost:5173/svc/cloud/byok/configs/{CONFIG_ID}/rotate?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "annual_rotation",
    "revoke_old_version": false,
    "old_version_expiry_days": 90
  }'
```

After rotation:
- AWS: old key material remains importable via key version. Data keys encrypted with old CMK version continue working until you explicitly delete the old key version.
- Azure: old key version kept accessible for decryption. New operations use new version.
- GCP: old import job and key version remain. Create a new import job and new key version for rotation.

#### Destruction

Destroying the Vecta key does not automatically destroy the cloud CMK. Both must be destroyed explicitly:

```bash
# Step 1: Schedule Vecta key deletion
curl -X DELETE "http://localhost:5173/svc/keycore/keys/{VECTA_KEY_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

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

```bash
# List all BYOK configs
curl "http://localhost:5173/svc/cloud/byok/configs?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get sync status for a config
curl "http://localhost:5173/svc/cloud/byok/configs/{CONFIG_ID}/status?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

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
2. Calls your DKE endpoint → POST /svc/hyok/proxy/decrypt
   - Body: D-CEK (wrapped CEK), user identity JWT
3. Your endpoint validates the user's identity and decrypts D-CEK → CEK
4. M365 uses CEK to decrypt the document content
```

#### Vecta DKE Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/svc/hyok/proxy/keys/{keyId}/publickey` | Returns DKE public key (RSA PEM). Microsoft calls this at encryption time. |
| `POST` | `/svc/hyok/proxy/decrypt` | Decrypts a wrapped CEK. Microsoft calls this at document open time. |

#### DKE Public Key Endpoint

```bash
# Microsoft calls this at encryption time to get your DKE public key
curl "http://localhost:5173/svc/hyok/proxy/keys/{KEY_ID}/publickey"
```

**Response (Microsoft-compatible format):**

```json
{
  "key": {
    "kty": "RSA",
    "n": "modulus-base64url...",
    "e": "AQAB",
    "alg": "RS256",
    "kid": "{KEY_ID}"
  }
}
```

#### DKE Decrypt Endpoint

```bash
# Microsoft calls this when a user opens a DKE-protected document
curl -X POST "http://localhost:5173/svc/hyok/proxy/decrypt" \
  -H "Authorization: Bearer {USER_JWT_FROM_MICROSOFT}" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "{KEY_ID}",
    "encrypted_data": "base64-encoded-wrapped-CEK",
    "algorithm": "RS256",
    "tenant_id": "azure-tenant-id",
    "user_oid": "azure-user-object-id"
  }'
```

**Response:**

```json
{
  "decrypted_data": "base64-encoded-CEK",
  "key_id": "{KEY_ID}"
}
```

#### DKE Azure AD Configuration

In **Microsoft Purview** (formerly Azure Information Protection):

```
1. Azure Portal → Azure Active Directory → App Registrations
   Create app registration for Vecta DKE:
   - Name: Vecta DKE Service
   - Redirect URI: https://kms.internal.acme.com/svc/hyok/proxy/callback
   - API Permissions: Microsoft Information Protection → DelegatedPermissions

2. Microsoft Purview → Sensitivity Labels → Create Label
   - Assign label to DKE encryption
   - DKE key URL: https://kms.internal.acme.com/svc/hyok/proxy/keys/{KEY_ID}
   - Template ID: (from DKE configuration)

3. Microsoft 365 Admin Center → Compliance → Information Protection
   - Publish label policy
   - Assign to security-classified document library
```

#### DKE Vecta Configuration

```bash
# Create DKE key (RSA-4096 for DKE, per Microsoft requirements)
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "m365-dke-key",
    "algorithm": "RSA-4096",
    "purpose": "encrypt_decrypt",
    "key_backend": "hsm",
    "tags": {"use": "dke", "provider": "microsoft"}
  }'

# Create HYOK policy for DKE
curl -X POST "http://localhost:5173/svc/hyok/policies?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "m365-dke-policy",
    "provider": "microsoft_dke",
    "key_id": "DKE_KEY_ID",
    "allowed_callers": [
      "user:alice@acme.com",
      "user:bob@acme.com",
      "group:finance-team@acme.com"
    ],
    "allowed_tenants": ["azure-tenant-id-here"],
    "time_restrictions": {
      "start_time": "06:00",
      "end_time": "22:00",
      "days_of_week": ["Mon", "Tue", "Wed", "Thu", "Fri"],
      "timezone": "America/New_York"
    },
    "require_justification": false,
    "governance_policy_id": null,
    "audit_all_operations": true
  }'
```

---

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

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/hyok/proxy/google-cse/wrap` | Wrap a DEK. Called at upload/encryption time. |
| `POST` | `/svc/hyok/proxy/google-cse/unwrap` | Unwrap a DEK. Called at download/decryption time. |
| `GET` | `/svc/hyok/proxy/google-cse/status` | Health check endpoint (required by Google). |

```bash
# Google CSE wrap (called at encryption time)
curl -X POST "http://localhost:5173/svc/hyok/proxy/google-cse/wrap" \
  -H "Authorization: Bearer {GOOGLE_USER_JWT}" \
  -H "Content-Type: application/json" \
  -d '{
    "authentication": "{GOOGLE_IDENTITY_TOKEN}",
    "authorization": "{GOOGLE_RESOURCE_TOKEN}",
    "key": "base64-encoded-plaintext-DEKS",
    "reason": "drive_upload"
  }'
# Returns: {"wrappedKey": "base64-encoded-wrapped-DEKS"}

# Google CSE unwrap (called at decryption time)
curl -X POST "http://localhost:5173/svc/hyok/proxy/google-cse/unwrap" \
  -H "Authorization: Bearer {GOOGLE_USER_JWT}" \
  -H "Content-Type: application/json" \
  -d '{
    "authentication": "{GOOGLE_IDENTITY_TOKEN}",
    "authorization": "{GOOGLE_RESOURCE_TOKEN}",
    "wrappedKey": "base64-encoded-wrapped-DEKS",
    "reason": "drive_download"
  }'
# Returns: {"key": "base64-encoded-plaintext-DEKS"}
```

#### Google Workspace Admin Setup

```
1. Google Admin Console → Apps → Google Workspace → Drive and Docs → Client-side encryption
2. Configure key access control list service:
   - Key Access Control List (KACL) URL: https://kms.internal.acme.com/svc/hyok/proxy/google-cse
   - Issuer: accounts.google.com
3. Enable CSE for specific organizational units
4. Configure CSE labels for document classification
```

---

### 2.5 HYOK Policies

HYOK policies define who can request key operations, when, and under what conditions.

#### Policy Fields

| Field | Type | Description |
|---|---|---|
| `name` | string | Policy identifier |
| `provider` | string | `microsoft_dke`, `google_cse`, `custom` |
| `key_id` | string | Vecta key this policy governs |
| `allowed_callers` | array | User, group, or service identifiers permitted to call |
| `allowed_tenants` | array | Cloud provider tenant IDs allowed |
| `time_restrictions` | object | Business hours, days of week, timezone |
| `require_justification` | boolean | Require free-text justification field |
| `require_ticket` | boolean | Require a ticket ID in the request |
| `governance_policy_id` | string | Link to a governance workflow for approval |
| `max_decrypt_per_hour` | integer | Rate limit on decrypt operations |
| `emergency_override` | object | Break-glass procedure for emergency access |

#### Policy Examples

```bash
# Standard business-hours DKE policy
curl -X POST "http://localhost:5173/svc/hyok/policies?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "finance-dke-business-hours",
    "provider": "microsoft_dke",
    "key_id": "DKE_KEY_ID",
    "allowed_callers": [
      "user:cfo@acme.com",
      "user:finance-manager@acme.com",
      "group:finance-analysts@acme.com"
    ],
    "allowed_tenants": ["72f988bf-86f1-41af-91ab-2d7cd011db47"],
    "time_restrictions": {
      "start_time": "08:00",
      "end_time": "18:00",
      "days_of_week": ["Mon", "Tue", "Wed", "Thu", "Fri"],
      "timezone": "America/New_York"
    },
    "require_justification": false,
    "max_decrypt_per_hour": 100,
    "audit_all_operations": true
  }'

# Sensitive data policy with justification and ticket requirement
curl -X POST "http://localhost:5173/svc/hyok/policies?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "classified-docs-policy",
    "provider": "microsoft_dke",
    "key_id": "CLASSIFIED_DKE_KEY_ID",
    "allowed_callers": [
      "user:security-officer@acme.com"
    ],
    "time_restrictions": {
      "start_time": "09:00",
      "end_time": "17:00",
      "days_of_week": ["Mon", "Tue", "Wed", "Thu", "Fri"],
      "timezone": "America/Chicago"
    },
    "require_justification": true,
    "require_ticket": true,
    "ticket_validation": {
      "system": "jira",
      "url": "https://jira.acme.com",
      "required_status": "In Progress"
    },
    "max_decrypt_per_hour": 10,
    "emergency_override": {
      "allowed_approvers": ["ciso@acme.com", "cto@acme.com"],
      "require_two_approvers": true,
      "max_duration_hours": 4
    }
  }'
```

#### Policy Enforcement Log

Every HYOK operation generates a structured audit log entry:

```json
{
  "timestamp": "2026-03-22T14:30:00Z",
  "event": "hyok.decrypt",
  "policy_id": "finance-dke-business-hours",
  "key_id": "DKE_KEY_ID",
  "caller_identity": "user:alice@acme.com",
  "caller_tenant": "72f988bf-86f1-41af-91ab-2d7cd011db47",
  "operation": "decrypt",
  "policy_decision": "allow",
  "time_restriction_check": "pass",
  "caller_check": "pass",
  "duration_ms": 12,
  "ip_address": "20.190.133.0",
  "request_id": "req_abc123"
}
```

---

### 2.6 HYOK Proxy Configuration

```bash
# Configure HYOK proxy settings
curl -X PUT "http://localhost:5173/svc/hyok/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jwt_issuers": {
      "microsoft": "https://login.microsoftonline.com/{tenant}/v2.0",
      "google": "https://accounts.google.com"
    },
    "jwt_audiences": ["https://kms.internal.acme.com"],
    "mtls_ca_cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "log_request_bodies": false,
    "rate_limit_per_caller": 1000,
    "cache_jwks": true,
    "jwks_cache_ttl_seconds": 3600
  }'
```

---

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

#### Register Agent Integration

```bash
curl -X POST "http://localhost:5173/svc/ekm/integrations?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-mssql-01",
    "type": "mssql_tde",
    "hostname": "sqlserver01.internal.acme.com",
    "key_id": "AES-256-MASTER-KEY-ID",
    "agent_token": "auto-generated-or-specify",
    "config_json": {
      "database_names": ["PaymentsDB", "CustomersDB", "OrdersDB"],
      "encryption_algorithm": "AES_256"
    },
    "alert_on_heartbeat_miss": true,
    "heartbeat_timeout_seconds": 90
  }'
```

---

### 3.3 Microsoft SQL Server TDE with EKM

#### Full Setup Walkthrough

**Step 1 — Install Vecta EKM Agent on SQL Server host** (see above)

**Step 2 — Copy the EKM provider DLL**

The installer places `vecta-ekm.dll` (or `vecta-ekm-x64.dll`) in `C:\Program Files\Vecta EKM\`. Verify:

```powershell
Test-Path "C:\Program Files\Vecta EKM\vecta-ekm.dll"
# Expected: True
```

**Step 3 — Enable EKM in SQL Server**

```sql
-- Enable advanced options
sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Enable EKM provider
sp_configure 'EKM provider enabled', 1;
RECONFIGURE;
```

**Step 4 — Create EKM Cryptographic Provider**

```sql
CREATE CRYPTOGRAPHIC PROVIDER VectaEKM
FROM FILE = 'C:\Program Files\Vecta EKM\vecta-ekm.dll';

-- Verify provider is registered
SELECT * FROM sys.cryptographic_providers;
```

**Step 5 — Create SQL Server credential**

```sql
CREATE CREDENTIAL VectaEKMCredential
  WITH IDENTITY = N'vecta-ekm-agent',
       SECRET    = N'agent-authentication-token-here';
```

**Step 6 — Create login with EKM credential**

```sql
-- Create a login for EKM operations
CREATE LOGIN VectaEKMLogin FROM WINDOWS
  WITH DEFAULT_DATABASE = master;

-- Alternatively, SQL login:
CREATE LOGIN VectaEKMLogin WITH PASSWORD = 'StrongP@ssw0rd!',
  DEFAULT_DATABASE = master;

ALTER LOGIN VectaEKMLogin
  ADD CREDENTIAL VectaEKMCredential;
```

**Step 7 — Create asymmetric key from EKM**

```sql
-- Run as the EKM login
EXECUTE AS LOGIN = 'VectaEKMLogin';

CREATE ASYMMETRIC KEY VectaMasterKey
FROM PROVIDER VectaEKM
  WITH PROVIDER_KEY_NAME = N'prod-mssql-master-key',
       CREATION_DISPOSITION = CREATE_NEW,
       ALGORITHM = RSA_2048;

REVERT;

-- Verify key
SELECT * FROM sys.asymmetric_keys;
```

**Step 8 — Create Service Master Key backup (for disaster recovery)**

```sql
-- Backup the service master key
BACKUP SERVICE MASTER KEY TO FILE = '\\backup-server\pki\smk-backup.key'
  ENCRYPTION BY PASSWORD = 'BackupP@ssword!';
```

**Step 9 — Create and enable Database Encryption Key**

```sql
USE PaymentsDB;

-- Create Database Encryption Key (encrypted by the EKM asymmetric key)
CREATE DATABASE ENCRYPTION KEY
  WITH ALGORITHM = AES_256
  ENCRYPTION BY SERVER ASYMMETRIC KEY VectaMasterKey;

-- Enable TDE
ALTER DATABASE PaymentsDB
  SET ENCRYPTION ON;

-- Verify encryption state
SELECT
  DB_NAME(database_id)  AS database_name,
  encryption_state,
  CASE encryption_state
    WHEN 0 THEN 'No database encryption key present'
    WHEN 1 THEN 'Unencrypted'
    WHEN 2 THEN 'Encryption in progress'
    WHEN 3 THEN 'Encrypted'
    WHEN 4 THEN 'Key change in progress'
    WHEN 5 THEN 'Decryption in progress'
  END AS encryption_state_desc,
  percent_complete,
  key_algorithm,
  key_length
FROM sys.dm_database_encryption_keys;
```

Repeat Step 9 for each database you want to encrypt.

**Step 10 — Encrypt TempDB (automatically encrypted when first DB is encrypted)**

```sql
-- TempDB is automatically encrypted once any user database is encrypted
-- Verify:
SELECT DB_NAME(database_id), encryption_state
FROM sys.dm_database_encryption_keys
WHERE DB_NAME(database_id) = 'tempdb';
```

#### SQL Server EKM Key Rotation

```bash
# Rotate the master key in Vecta
curl -X POST "http://localhost:5173/svc/keycore/keys/{MASTER_KEY_ID}/rotate?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

```sql
-- After rotating the key in Vecta, update SQL Server to use the new key version
ALTER DATABASE PaymentsDB
  SET ENCRYPTION KEY;
-- SQL Server re-encrypts the DEK with the new key version automatically
```

---

### 3.4 Oracle TDE with EKM

Oracle TDE uses PKCS#11 to communicate with an external keystore. Vecta provides a PKCS#11 library that implements the Oracle External Keystore interface.

#### Oracle EKM Setup

**Step 1 — Install Vecta PKCS#11 library**

```bash
# Copy PKCS#11 library to Oracle host
sudo cp vecta-pkcs11.so /opt/oracle/extapi/64/hsm/vecta/1.0/vecta-pkcs11.so
sudo chmod 755 /opt/oracle/extapi/64/hsm/vecta/1.0/vecta-pkcs11.so

# Configure Vecta PKCS#11
cat > /etc/vecta-pkcs11.conf <<EOF
kms_url = https://kms.internal.acme.com
tenant_id = root
agent_token = pkcs11-agent-token-here
ca_cert_file = /etc/vecta-pkcs11/ca-chain.pem
cert_file = /etc/vecta-pkcs11/client.pem
key_file = /etc/vecta-pkcs11/client.key
slot_id = 1
EOF
```

**Step 2 — Configure Oracle Wallet**

```sql
-- sqlplus / as sysdba

-- Set encryption wallet location to PKCS#11 external keystore
ADMINISTER KEY MANAGEMENT SET KEYSTORE CLOSE;

-- Configure external keystore
ALTER SYSTEM SET ENCRYPTION_WALLET_LOCATION =
  '(SOURCE=(METHOD=PKCS11)(DIRECTORY=/opt/oracle/extapi/64/hsm/vecta/1.0/)(METHOD_DATA=(CREDENTIAL_FILE=/etc/oracle/vecta-pkcs11.conf)))'
  SCOPE = SPFILE;

-- Bounce the database
SHUTDOWN IMMEDIATE;
STARTUP;
```

**Step 3 — Open keystore and set master key**

```sql
-- Open the external keystore
ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN
  IDENTIFIED BY "vecta-slot-pin"
  CONTAINER = ALL;

-- Create master encryption key
ADMINISTER KEY MANAGEMENT SET KEY
  USING TAG 'prod-oracle-tde-2026'
  IDENTIFIED BY "vecta-slot-pin"
  WITH BACKUP USING 'tde-backup-2026'
  CONTAINER = ALL;

-- Enable tablespace encryption
ALTER TABLESPACE users
  ENCRYPTION USING AES256 ENCRYPT;

-- Verify
SELECT * FROM v$encryption_wallet;
SELECT TABLESPACE_NAME, ENCRYPTED FROM DBA_TABLESPACES;
```

---

### 3.5 BitLocker Endpoint Encryption

Vecta EKM manages BitLocker recovery keys for Windows endpoints, providing centralized control and compliance reporting for full-disk encryption.

#### How BitLocker EKM Works

1. EKM agent installed on Windows hosts reports BitLocker status to Vecta.
2. Recovery keys are escrowed to Vecta on encryption enablement.
3. IT/Security can retrieve recovery keys from Vecta (with full audit log).
4. Compliance dashboard shows encryption status per endpoint.

#### Enabling BitLocker with Recovery Key Escrow

```powershell
# On Windows endpoint (via Intune policy or GPO or manual)

# Enable BitLocker on C: drive
$BLStatus = Get-BitLockerVolume -MountPoint "C:"

if ($BLStatus.ProtectionStatus -ne "On") {
    Enable-BitLocker -MountPoint "C:" `
        -EncryptionMethod XtsAes256 `
        -RecoveryPasswordProtector `
        -UsedSpaceOnly

    $RecoveryKey = (Get-BitLockerVolume -MountPoint "C:").KeyProtector |
                   Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}

    # Escrow to Vecta via EKM Agent
    $EscrowBody = @{
        endpoint_id     = $env:COMPUTERNAME
        volume          = "C:"
        recovery_key_id = $RecoveryKey.KeyProtectorId
        # NOTE: Recovery key itself is transmitted over mTLS to Vecta
    } | ConvertTo-Json

    Invoke-RestMethod -Uri "http://localhost:8080/ekm/bitlocker/escrow" `
        -Method POST `
        -ContentType "application/json" `
        -Body $EscrowBody
}
```

#### Retrieving a Recovery Key

```bash
# List endpoints and their BitLocker status
curl "http://localhost:5173/svc/ekm/bitlocker/endpoints?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get endpoint details
curl "http://localhost:5173/svc/ekm/bitlocker/endpoints/{ENDPOINT_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**

```json
{
  "endpoint_id": "ep_01HXYZ...",
  "hostname": "laptop-alice-001",
  "os_version": "Windows 11 23H2",
  "last_seen": "2026-03-22T09:55:00Z",
  "bitlocker_status": "encrypted",
  "volumes": [
    {
      "mount_point": "C:",
      "encryption_method": "XtsAes256",
      "protection_status": "On",
      "key_protectors": ["RecoveryPassword", "TPM"]
    }
  ]
}
```

```bash
# Retrieve recovery key (requires elevated RBAC role: ekm:bitlocker:recover)
curl -X POST "http://localhost:5173/svc/ekm/bitlocker/endpoints/{ENDPOINT_ID}/recovery-key?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "volume": "C:",
    "reason": "User locked out after 10 failed PIN attempts",
    "ticket": "HD-12345"
  }'
```

**Response:**

```json
{
  "recovery_key_id": "{GUID}",
  "recovery_key": "123456-789012-345678-901234-567890-123456-789012-345678",
  "volume": "C:",
  "retrieved_by": "helpdesk-agent@acme.com",
  "retrieved_at": "2026-03-22T14:30:00Z",
  "audit_entry_id": "audit_01HXYZ..."
}
```

#### BitLocker Compliance Report

```bash
# Get encryption compliance summary
curl "http://localhost:5173/svc/ekm/bitlocker/compliance?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**

```json
{
  "total_endpoints": 1247,
  "encrypted": 1201,
  "partially_encrypted": 12,
  "not_encrypted": 34,
  "compliance_percent": 96.3,
  "last_checked": "2026-03-22T10:00:00Z",
  "not_seen_7d": 8,
  "not_seen_30d": 3
}
```

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

#### Server Configuration

```bash
# Configure KMIP server settings
curl -X PUT "http://localhost:5173/svc/kmip/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "port": 5696,
    "tls_version": "TLS1_3",
    "require_client_cert": true,
    "ca_cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "session_timeout_seconds": 300,
    "max_connections": 500,
    "supported_algorithms": ["AES-128", "AES-256", "RSA-2048", "RSA-4096", "EC-P256", "EC-P384"],
    "default_key_format": "Raw"
  }'
```

#### Create KMIP Client Profile

A client profile defines which operations a specific KMIP client is authorized to perform and which key groups it can access.

```bash
curl -X POST "http://localhost:5173/svc/kmip/profiles?tenant_id=root" \
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
curl -X POST "http://localhost:5173/svc/certs/certs?tenant_id=root" \
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
# List KMIP-managed objects
curl "http://localhost:5173/svc/kmip/objects?tenant_id=root&group=storage-keys" \
  -H "Authorization: Bearer $TOKEN"

# Get KMIP object
curl "http://localhost:5173/svc/kmip/objects/{KMIP_OBJECT_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Activate a Pre-Active key (transitions to Active state)
curl -X POST "http://localhost:5173/svc/kmip/objects/{KMIP_OBJECT_ID}/activate?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Revoke (deactivate or mark compromised)
curl -X POST "http://localhost:5173/svc/kmip/objects/{KMIP_OBJECT_ID}/revoke?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "revocation_reason": "KeyCompromise",
    "compromise_date": "2026-03-21T00:00:00Z"
  }'

# Destroy
curl -X POST "http://localhost:5173/svc/kmip/objects/{KMIP_OBJECT_ID}/destroy?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# List KMIP client profiles
curl "http://localhost:5173/svc/kmip/profiles?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get KMIP server status
curl "http://localhost:5173/svc/kmip/status?tenant_id=root" \
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
CERT_RESPONSE=$(curl -s -X POST "http://localhost:5173/svc/certs/certs?tenant_id=${TENANT}" \
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
curl -X POST "http://localhost:5173/svc/kmip/profiles?tenant_id=${TENANT}" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"name\": \"${CLIENT_NAME}\",
    \"client_certificate_pem\": $(jq -Rs . <<< "$CERT_PEM"),
    \"allowed_operations\": [\"create\", \"get\", \"destroy\", \"activate\", \"locate\"],
    \"object_groups\": [\"storage-keys\"]
  }"

# Step 3: Download CA chain
curl "http://localhost:5173/svc/certs/certs/ca/{CA_ID}/chain?tenant_id=${TENANT}" \
  -H "Authorization: Bearer $TOKEN" \
  -o vecta-ca-chain.pem

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
| **Non-repudiation** | Signer cannot deny having signed; transparency log records the event |
| **Timeliness** | Transparency log entry timestamps prove when signing occurred |
| **Verifiability** | Any party with the public key can verify, without trusting the signer |

### 5.2 Supported Artifact Types

| `artifact_type` | Description | Verification |
|---|---|---|
| `artifact` | General file (SHA-256 hash signing) | `sha256sum` + Vecta verify API |
| `blob` | Binary blob (inline data signing) | Vecta verify API |
| `git` | Git commit / tag signing | `git verify-commit`, `git verify-tag` |
| `container` | OCI container image (cosign-compatible) | `cosign verify` |
| `sbom` | Software Bill of Materials (SPDX, CycloneDX) | Vecta verify API |

### 5.3 Signing Policies

A signing policy governs which keys, subjects, and artifact types are permitted.

```bash
# Create a signing policy for container images
curl -X POST "http://localhost:5173/svc/signing/policies?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "production-container-signing",
    "artifact_type": "container",
    "key_id": "ED25519-SIGNING-KEY-ID",
    "allowed_subjects": [
      "ci-pipeline@acme.com",
      "workload:build-service",
      "service-account:github-actions"
    ],
    "branch_policy": {
      "allowed_branches": ["main", "release/*"],
      "require_protected_branch": true
    },
    "require_transparency_log": true,
    "expiry_days": 365,
    "allowed_registries": [
      "registry.acme.com",
      "ghcr.io/acme"
    ],
    "metadata_schema": {
      "required_fields": ["image", "registry", "git_sha", "pipeline_url"]
    }
  }'
```

```bash
# Signing policy for release binaries (code signing)
curl -X POST "http://localhost:5173/svc/signing/policies?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "release-binary-signing",
    "artifact_type": "artifact",
    "key_id": "EC-P384-SIGNING-KEY-ID",
    "allowed_subjects": ["release-pipeline@acme.com"],
    "branch_policy": {
      "allowed_branches": ["main"],
      "require_protected_branch": true,
      "require_tag": true,
      "tag_pattern": "v[0-9]+\\.[0-9]+\\.[0-9]+"
    },
    "require_transparency_log": true,
    "max_sign_per_day": 50
  }'
```

### 5.4 Signing a Container Image

#### Full CI/CD Pipeline Integration

```bash
# Signing script — runs in CI (GitHub Actions / GitLab CI / Jenkins)

set -euo pipefail

IMAGE="registry.acme.com/payments/payment-service"
TAG="${CI_COMMIT_TAG:-${CI_COMMIT_SHA:0:8}}"
FULL_IMAGE="${IMAGE}:${TAG}"

# Build and push image
docker build -t "${FULL_IMAGE}" .
docker push "${FULL_IMAGE}"

# Get image digest (use digest for signing, not tag — tags are mutable)
IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${FULL_IMAGE}" | awk -F@ '{print $2}')
echo "Image digest: ${IMAGE_DIGEST}"

# Sign the image
SIGN_RESPONSE=$(curl -s -X POST "http://kms.internal.acme.com/svc/signing/sign?tenant_id=root" \
  -H "Authorization: Bearer ${CI_VECTA_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"artifact_hash\": \"${IMAGE_DIGEST}\",
    \"artifact_type\": \"container\",
    \"policy_id\": \"${CONTAINER_SIGNING_POLICY_ID}\",
    \"metadata\": {
      \"image\": \"${FULL_IMAGE}\",
      \"registry\": \"registry.acme.com\",
      \"git_sha\": \"${CI_COMMIT_SHA}\",
      \"git_ref\": \"${CI_COMMIT_REF_NAME}\",
      \"pipeline_url\": \"${CI_PIPELINE_URL}\",
      \"builder\": \"${GITLAB_USER_LOGIN:-ci-pipeline}\"
    }
  }")

SIGNATURE=$(echo "${SIGN_RESPONSE}" | jq -r '.signature')
TRANSPARENCY_LOG_ID=$(echo "${SIGN_RESPONSE}" | jq -r '.transparency_log_id')

echo "Signature: ${SIGNATURE}"
echo "Transparency log entry: ${TRANSPARENCY_LOG_ID}"

# Attach signature as OCI artifact (cosign-compatible)
cosign attach signature \
  --signature "${SIGNATURE}" \
  --payload "${IMAGE_DIGEST}" \
  "${IMAGE}@${IMAGE_DIGEST}"

echo "Container image signed and pushed: ${FULL_IMAGE}"
```

#### Verifying a Container Image in Deployment

```bash
# Verification script — runs before deploying

IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE}:${TAG}" | awk -F@ '{print $2}')

VERIFY_RESPONSE=$(curl -s -X POST "http://kms.internal.acme.com/svc/signing/verify?tenant_id=root" \
  -H "Authorization: Bearer ${DEPLOY_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"artifact_hash\": \"${IMAGE_DIGEST}\",
    \"artifact_type\": \"container\",
    \"policy_id\": \"${CONTAINER_SIGNING_POLICY_ID}\"
  }")

VALID=$(echo "${VERIFY_RESPONSE}" | jq -r '.valid')
SIGNER=$(echo "${VERIFY_RESPONSE}" | jq -r '.signer_identity')
SIGNED_AT=$(echo "${VERIFY_RESPONSE}" | jq -r '.signed_at')

if [ "${VALID}" != "true" ]; then
  echo "ERROR: Image signature verification FAILED for ${IMAGE_DIGEST}"
  echo "Response: ${VERIFY_RESPONSE}"
  exit 1
fi

echo "Image verified: signed by ${SIGNER} at ${SIGNED_AT}"
```

#### Kubernetes Admission Controller Integration

Deploy a Vecta signature verification webhook to enforce that only signed images run in Kubernetes:

```yaml
# Admission webhook configuration
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: vecta-signature-verifier
webhooks:
- name: verify-image-signature.vecta.io
  rules:
  - apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
    operations: ["CREATE", "UPDATE"]
  clientConfig:
    service:
      name: vecta-webhook
      namespace: kube-system
      path: "/verify-image"
    caBundle: "BASE64_ENCODED_CA_CERT"
  admissionReviewVersions: ["v1"]
  sideEffects: None
  failurePolicy: Fail
  namespaceSelector:
    matchLabels:
      vecta-signing-enforced: "true"
```

```yaml
# Vecta webhook deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vecta-webhook
  namespace: kube-system
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: vecta-webhook
        image: registry.acme.com/vecta/signature-webhook:latest
        env:
        - name: VECTA_KMS_URL
          value: "https://kms.internal.acme.com"
        - name: SIGNING_POLICY_ID
          value: "production-container-signing"
        - name: VECTA_TOKEN
          valueFrom:
            secretKeyRef:
              name: vecta-webhook-token
              key: token
        ports:
        - containerPort: 8443
```

---

### 5.5 Git Commit Signing

#### SSH Key-Based Git Signing (Git 2.34+)

```bash
# Get the Ed25519 public key from Vecta
curl "http://localhost:5173/svc/keycore/keys/{KEY_ID}/public?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -o vecta-signing.pub

# Configure Git to use SSH signing with Vecta key
git config --global gpg.format ssh
git config --global user.signingkey "$(cat vecta-signing.pub)"

# Create allowed signers file
echo "alice@acme.com $(cat vecta-signing.pub)" >> ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers

# Sign commits (use -S flag, or set globally)
git config --global commit.gpgsign true
git commit -m "feat: add payment processor integration"

# Verify a commit
git verify-commit HEAD

# Verify all commits in a range
git log --show-signature --oneline main..HEAD
```

#### GPG-Compatible Signing

```bash
# Create GPG-compatible signing certificate from Vecta
# (Ed25519 key exported in OpenPGP format)
curl -X POST "http://localhost:5173/svc/signing/git-signing-key?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "key_id": "ED25519_KEY_ID",
    "uid": "Alice Smith <alice@acme.com>",
    "key_type": "openpgp"
  }' \
  -o alice-signing.gpg

# Import to GPG keyring
gpg --import alice-signing.gpg

# Configure Git to use GPG
git config --global gpg.program gpg
git config --global user.signingkey $(gpg --list-secret-keys --keyid-format=long | grep sec | awk '{print $2}' | cut -d/ -f2)

# Sign commits
git config --global commit.gpgsign true
```

#### Uploading Signing Key to GitHub / GitLab

```bash
# GitHub: Settings → SSH and GPG keys → New SSH key (for SSH signing)
# or Settings → SSH and GPG keys → New GPG key (for GPG signing)

# GitLab: User Settings → GPG Keys → Add key
# or User Settings → SSH Keys → Add key (with "Signing" usage type)

# You can also use the GitHub API:
PUBKEY=$(cat vecta-signing.pub)
curl -X POST "https://api.github.com/user/ssh_signing_keys" \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -d "{\"title\": \"Vecta KMS Signing Key\", \"key\": \"${PUBKEY}\"}"
```

---

### 5.6 Artifact and SBOM Signing

```bash
# Sign a release binary
BINARY="myapp-v2.1.0-linux-amd64"
SHA256=$(sha256sum "${BINARY}" | awk '{print $1}')

curl -X POST "http://localhost:5173/svc/signing/sign?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"artifact_hash\": \"sha256:${SHA256}\",
    \"artifact_type\": \"artifact\",
    \"policy_id\": \"RELEASE_SIGNING_POLICY_ID\",
    \"metadata\": {
      \"filename\": \"${BINARY}\",
      \"version\": \"v2.1.0\",
      \"os\": \"linux\",
      \"arch\": \"amd64\"
    }
  }" | tee "${BINARY}.sig.json" | jq .

# Sign an SBOM (CycloneDX JSON)
SBOM="myapp-v2.1.0.sbom.json"
SBOM_SHA256=$(sha256sum "${SBOM}" | awk '{print $1}')

curl -X POST "http://localhost:5173/svc/signing/sign?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"artifact_hash\": \"sha256:${SBOM_SHA256}\",
    \"artifact_type\": \"sbom\",
    \"policy_id\": \"RELEASE_SIGNING_POLICY_ID\",
    \"metadata\": {
      \"sbom_format\": \"CycloneDX\",
      \"sbom_version\": \"1.5\",
      \"component\": \"myapp\",
      \"version\": \"v2.1.0\"
    }
  }"

# Verify binary
VERIFY_SHA256=$(sha256sum "${BINARY}" | awk '{print $1}')
SIGNATURE=$(cat "${BINARY}.sig.json" | jq -r '.signature')

curl -X POST "http://localhost:5173/svc/signing/verify?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"artifact_hash\": \"sha256:${VERIFY_SHA256}\",
    \"signature\": \"${SIGNATURE}\",
    \"policy_id\": \"RELEASE_SIGNING_POLICY_ID\"
  }"
```

---

### 5.7 Transparency Log

Every signing event is appended to an append-only transparency log. Each entry includes a sequence number, timestamps, and a Merkle inclusion proof tying it to the log's root.

```bash
# Browse transparency log
curl "http://localhost:5173/svc/signing/transparency?tenant_id=root&page=1&per_page=50" \
  -H "Authorization: Bearer $TOKEN"

# Get a specific log entry
curl "http://localhost:5173/svc/signing/transparency/{LOG_ENTRY_ID}?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Search by artifact hash
curl "http://localhost:5173/svc/signing/transparency?tenant_id=root&artifact_hash=sha256:abc123..." \
  -H "Authorization: Bearer $TOKEN"

# Search by signer identity
curl "http://localhost:5173/svc/signing/transparency?tenant_id=root&signer=ci-pipeline@acme.com" \
  -H "Authorization: Bearer $TOKEN"
```

**Transparency log entry structure:**

```json
{
  "id": "tlog_01HXYZ...",
  "sequence_number": 10042,
  "artifact_hash": "sha256:abc123...",
  "artifact_type": "container",
  "signer_identity": "ci-pipeline@acme.com",
  "signing_key_id": "ED25519_KEY_ID",
  "policy_id": "production-container-signing",
  "metadata": {
    "image": "registry.acme.com/payments/payment-service:v1.2.3",
    "git_sha": "a1b2c3d4"
  },
  "signature": "base64-encoded-signature",
  "signed_at": "2026-03-22T10:00:00Z",
  "merkle_proof": {
    "leaf_hash": "3f4a5b...",
    "leaf_index": 10042,
    "siblings": ["hash1", "hash2", "hash3"],
    "root": "abc123..."
  }
}
```

#### Rekor-Compatible API

The Vecta transparency log exposes a Rekor-compatible API so existing Sigstore tooling works with it.

```bash
# rekor-cli pointing to Vecta
rekor-cli --rekor_server https://kms.internal.acme.com/svc/signing/rekor \
  search --sha sha256:abc123...

rekor-cli --rekor_server https://kms.internal.acme.com/svc/signing/rekor \
  get --uuid tlog_01HXYZ...
```

---

### 5.8 Security Considerations for Signing

| Consideration | Recommendation |
|---|---|
| Key algorithm | EC-P384 or Ed25519 minimum; no RSA < 3072 for new signing keys |
| Key storage | HSM backend for all production signing keys |
| `allowed_subjects` | Restrict strictly — only CI service accounts, not developer accounts |
| Branch policies | Require protected branches for production signing |
| Transparency log | Require for all production signing; do not allow bypass |
| Key rotation | Rotate signing keys annually; re-sign any long-lived artifacts |
| Verification | Always verify before deploying; use admission controller for K8s |
| SBOM signing | Sign SBOMs alongside binaries for full provenance chain |

---

## 6. Use Cases

### Use Case 1 — BYOK for AWS S3 Server-Side Encryption

**Scenario:** Regulatory requirement that encryption keys for customer data stored in S3 are generated by the customer (not AWS). GDPR compliance for EU customer data.

**Architecture:** Vecta HSM → BYOK import → AWS KMS CMK → S3 SSE-KMS

**Steps:**
1. Generate AES-256 key in Vecta HSM (Section 1.3, Steps 1–7)
2. Configure S3 bucket default encryption to use CMK
3. Register auto-rotation sync in Vecta (annual)
4. Test: upload object, verify encryption; rotate key, verify old objects still accessible

**Key metrics:** Key generation in Vecta HSM (attestable), key material import via RSA-OAEP (no plaintext in transit), all S3 objects encrypted with CMK, rotation logged in Vecta audit trail.

---

### Use Case 2 — HYOK for Microsoft 365 Classified Documents

**Scenario:** Legal and M&A documents classified as "Strictly Confidential" encrypted with DKE. Not even Microsoft can access the content under subpoena.

**Architecture:** M365 Sensitivity Label → DKE policy → Vecta HYOK proxy → Vecta HSM

**Steps:**
1. Create RSA-4096 DKE key in Vecta HSM
2. Create HYOK policy with `allowed_callers` = legal team members, business hours restriction
3. Configure Azure AD app registration for DKE
4. Create "Strictly Confidential" sensitivity label in Microsoft Purview pointing to Vecta DKE endpoint
5. Publish label to legal team
6. Test: apply label to document, open from another user, verify HYOK proxy audit log shows the decrypt call

---

### Use Case 3 — Database TDE for PCI DSS Scope Reduction

**Scenario:** Payment card data stored in SQL Server. PCI DSS Requirement 3.5 requires key custodian separation. Using Vecta EKM, the DBA cannot access the master encryption key.

**Architecture:** SQL Server DEK → Vecta EKM Agent → Vecta KMS → HSM

**Steps:**
1. Register Vecta EKM integration for SQL Server (Section 3.3)
2. Create TDE key in Vecta for each database (PaymentsDB, CardholderDB)
3. Enable TDE on all PCI-scoped databases
4. Configure Vecta EKM alert for agent heartbeat miss
5. Document key custodian roles (Security team = Vecta admin, DBA = SQL Server admin, no overlap)

**PCI DSS evidence:** Vecta audit log shows all key access events; HSM attestation shows key never left hardware; role separation documented and enforced by RBAC.

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

**Scenario:** GitLab CI pipeline builds container images and signs them. Kubernetes admission controller rejects any unsigned image.

**Architecture:** GitLab CI → sign image → Vecta transparency log → K8s admission controller → verify before deploy

**Steps:**
1. Create Ed25519 signing key in Vecta HSM
2. Create container signing policy with `allowed_subjects = gitlab-ci@acme.com`, `require_transparency_log = true`
3. Add signing step to `.gitlab-ci.yml` (Section 5.4)
4. Deploy Vecta webhook admission controller in K8s cluster
5. Enable webhook for `production` and `staging` namespaces
6. Test: deploy signed image succeeds; deploy unsigned image rejected with "signature verification failed"

---

### Use Case 6 — Git Commit Signing for Source Integrity

**Scenario:** Security policy requires all commits to `main` branch to be signed. Developers sign using Vecta-managed Ed25519 keys.

**Steps:**
1. Issue an Ed25519 signing key in Vecta for each developer
2. Export public key from Vecta
3. Developer configures Git with the Vecta signing key (Section 5.5)
4. Upload public key to GitHub/GitLab as signing key
5. Configure branch protection on `main`: require signed commits
6. CI pipeline verifies all commits in a PR are signed before merge

---

## 7. API Reference

### BYOK Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/cloud/byok/configs` | Create BYOK configuration |
| `GET` | `/svc/cloud/byok/configs` | List BYOK configurations |
| `GET` | `/svc/cloud/byok/configs/{id}` | Get BYOK configuration |
| `PUT` | `/svc/cloud/byok/configs/{id}` | Update BYOK configuration |
| `DELETE` | `/svc/cloud/byok/configs/{id}` | Delete BYOK configuration |
| `GET` | `/svc/cloud/byok/configs/{id}/status` | Get sync status |
| `POST` | `/svc/cloud/byok/configs/{id}/wrap` | Generate wrapped key material |
| `POST` | `/svc/cloud/byok/sync` | Trigger BYOK sync |
| `POST` | `/svc/cloud/byok/configs/{id}/rotate` | Rotate BYOK key |

### HYOK Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/hyok/policies` | Create HYOK policy |
| `GET` | `/svc/hyok/policies` | List HYOK policies |
| `GET` | `/svc/hyok/policies/{id}` | Get HYOK policy |
| `PUT` | `/svc/hyok/policies/{id}` | Update HYOK policy |
| `DELETE` | `/svc/hyok/policies/{id}` | Delete HYOK policy |
| `GET` | `/svc/hyok/proxy/keys/{keyId}/publickey` | DKE public key endpoint |
| `POST` | `/svc/hyok/proxy/decrypt` | DKE decrypt endpoint |
| `POST` | `/svc/hyok/proxy/google-cse/wrap` | Google CSE wrap |
| `POST` | `/svc/hyok/proxy/google-cse/unwrap` | Google CSE unwrap |
| `GET` | `/svc/hyok/proxy/google-cse/status` | Google CSE health |
| `PUT` | `/svc/hyok/config` | Update HYOK proxy configuration |
| `GET` | `/svc/hyok/audit` | Browse HYOK audit log |

### EKM Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/ekm/integrations` | Register EKM integration |
| `GET` | `/svc/ekm/integrations` | List EKM integrations |
| `GET` | `/svc/ekm/integrations/{id}` | Get EKM integration |
| `PUT` | `/svc/ekm/integrations/{id}` | Update EKM integration |
| `DELETE` | `/svc/ekm/integrations/{id}` | Delete EKM integration |
| `GET` | `/svc/ekm/integrations/{id}/status` | Agent heartbeat status |
| `GET` | `/svc/ekm/bitlocker/endpoints` | List BitLocker endpoints |
| `GET` | `/svc/ekm/bitlocker/endpoints/{id}` | Get endpoint details |
| `POST` | `/svc/ekm/bitlocker/endpoints/{id}/recovery-key` | Retrieve recovery key |
| `GET` | `/svc/ekm/bitlocker/compliance` | Compliance report |

### KMIP Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/kmip/profiles` | Create KMIP client profile |
| `GET` | `/svc/kmip/profiles` | List KMIP client profiles |
| `GET` | `/svc/kmip/profiles/{id}` | Get KMIP client profile |
| `PUT` | `/svc/kmip/profiles/{id}` | Update KMIP client profile |
| `DELETE` | `/svc/kmip/profiles/{id}` | Delete KMIP client profile |
| `GET` | `/svc/kmip/objects` | List KMIP-managed objects |
| `GET` | `/svc/kmip/objects/{id}` | Get KMIP object |
| `POST` | `/svc/kmip/objects/{id}/activate` | Activate KMIP object |
| `POST` | `/svc/kmip/objects/{id}/revoke` | Revoke KMIP object |
| `POST` | `/svc/kmip/objects/{id}/destroy` | Destroy KMIP object |
| `GET` | `/svc/kmip/status` | KMIP server status |
| `PUT` | `/svc/kmip/config` | Update KMIP configuration |

### Artifact Signing Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/signing/policies` | Create signing policy |
| `GET` | `/svc/signing/policies` | List signing policies |
| `GET` | `/svc/signing/policies/{id}` | Get signing policy |
| `PUT` | `/svc/signing/policies/{id}` | Update signing policy |
| `DELETE` | `/svc/signing/policies/{id}` | Delete signing policy |
| `POST` | `/svc/signing/sign` | Sign an artifact |
| `POST` | `/svc/signing/verify` | Verify a signature |
| `GET` | `/svc/signing/transparency` | Browse transparency log |
| `GET` | `/svc/signing/transparency/{id}` | Get log entry |
| `POST` | `/svc/signing/git-signing-key` | Export Git signing key |

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
curl -X POST "http://localhost:5173/svc/auth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "grant_type": "client_credentials"
  }'
```

---

*Last updated: 2026-03-22 | Vecta KMS Cloud & Integration Documentation*
