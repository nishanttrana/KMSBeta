# Infrastructure — HSM and Cluster

> **Scope:** This document covers the hardware and distributed-systems infrastructure that Vecta KMS relies on: Hardware Security Modules (HSM), and multi-node clustering. QKD, QRNG and MPC/FROST are not part of Vecta KMS (they moved to KMSExtension). Each section contains conceptual background, architecture details, configuration reference, API examples, operational runbooks, and security considerations.

---

## Table of Contents

1. [HSM Integration](#1-hsm-integration)
   - 1.1 Why HSM
   - 1.2 HSM Vendor Comparison
   - 1.3 PKCS#11 Primer
   - 1.4 Configuration Reference
   - 1.5 Creating HSM-Backed Keys
   - 1.6 HSM HA Configuration
   - 1.7 FIPS 140-3 Mode with HSM
   - 1.8 Listing HSM Partitions
   - 1.9 HSM Key Wrapping / Unwrapping
   - 1.10 Troubleshooting HSM Connectivity
   - 1.11 Vendor-Specific Notes

2. [Cluster Management](#2-cluster-management)
   - 2.1 How a cluster works
   - 2.2 Adding a node
   - 2.3 Failover
   - 2.4 Networking
   - 2.5 Upgrades
   - 2.6 Disaster recovery

3. [Security Considerations](#3-security-considerations)
4. [Full API Reference](#4-full-api-reference)

---

## 1. HSM Integration

### 1.1 Why HSM

A Hardware Security Module (HSM) is a dedicated cryptographic processor with the following properties that software key stores cannot replicate:

**Tamper-Resistant Hardware Boundary**

The HSM enforces a hard physical boundary around all private key material. Attempts to probe the chip, expose it to voltage glitching, temperature extremes, or electromagnetic radiation trigger automatic zeroization of all stored secrets. This is codified in FIPS 140-3 Level 3 requirements: physical tamper evidence (coatings, mesh) and the requirement that any penetration triggers immediate key destruction.

**Keys Never Exposed in RAM**

When Vecta instructs an HSM to sign or encrypt, the private key material never leaves the secure boundary. The CPU on the HSM performs the operation internally and returns only the output (signature, ciphertext, wrapped key). Even if the host server running Vecta is fully compromised — root-level access, live memory dumps — the attacker cannot obtain private key material stored in HSM.

**Hardware True Random Number Generator (TRNG)**

HSMs contain a dedicated TRNG seeded from physical entropy sources (thermal noise, ring oscillator jitter). This is categorically different from software DRBGs (Deterministic Random Bit Generators), which are deterministic once their seed state is known. HSM-generated key material is therefore not subject to seed-compromise attacks.

**Audit-Coupled Key Custody**

Every HSM operation is logged with the HSM node identifier, slot reference, and session token. This provides key custody proof that satisfies PCI DSS Requirement 3, GDPR Article 32, and eIDAS qualified electronic signature requirements.

**Certifications and Regulatory Compliance**

- **FIPS 140-3 Level 3**: Physical tamper evidence, zeroization on attack, identity authentication required before cryptographic services
- **FIPS 140-3 Level 4**: Additional environmental attack resistance (voltage, temperature) — used in highest-assurance deployments
- **Common Criteria EAL4+**: Systematic formal security analysis, used by eIDAS Trust Service Providers
- **PCI HSM**: Payment Card Industry HSM standard for PIN and payment key management
- **eIDAS Qualified**: Required for Qualified Electronic Signatures under EU regulation

---

### 1.2 HSM Vendor Comparison

Vecta supports seven HSM backends. The following table documents all relevant characteristics for procurement and configuration decisions.

| Feature | Thales Luna Network HSM | Entrust nShield | Utimaco SecurityServer | Securosys Primus HSM | AWS CloudHSM | Azure Managed HSM | Generic PKCS#11 |
|---|---|---|---|---|---|---|---|
| **FIPS Level** | 140-3 L3 | 140-3 L3 | 140-3 L3 | 140-3 L3 | 140-3 L3 | 140-3 L3 | Varies |
| **Form Factor** | Network Appliance / PCIe | PCIe + Network | Network Appliance | Network Appliance | Cloud Managed | Cloud Managed | Any |
| **Primary Interface** | PKCS#11 + Luna Extend | PKCS#11 + nCore API | PKCS#11 + REST | PKCS#11 + Primus REST | PKCS#11 | PKCS#11 + REST | PKCS#11 |
| **HA Model** | NTL HA Groups | Security World | UTIMACO HA | Active-Active | Cluster-native | Multi-region | Varies |
| **Algorithms (RSA)** | RSA-2048 to 8192 | RSA-2048 to 8192 | RSA-2048 to 8192 | RSA-2048 to 8192 | RSA-2048 to 4096 | RSA-2048 to 4096 | Varies |
| **Algorithms (EC)** | P-256/384/521, K-256 | P-256/384/521 | P-256/384/521 | P-256/384/521 | P-256/384/521 | P-256/384/521 | Varies |
| **Algorithms (Symmetric)** | AES-128/256, 3DES | AES-128/256, 3DES | AES-128/256, 3DES | AES-128/256, 3DES | AES-128/256 | AES-128/256 | Varies |
| **EdDSA / Ed25519** | Yes (firmware 7.4+) | Yes | No | Yes | No | No | Varies |
| **PQC Support** | Partial (ML-KEM via SW) | No | No | ML-KEM-768, ML-DSA-65 | No | No | No |
| **Country of Manufacture** | US / France | US | Germany | Switzerland | US (AWS-managed) | US (MS-managed) | N/A |
| **Certifications** | FIPS, PCI HSM, CC EAL4+, eIDAS | FIPS, PCI HSM, CC EAL4+, eIDAS | FIPS, PCI HSM | FIPS, CC EAL4+, PCI HSM | FIPS 140-3 only | FIPS 140-3 only | Varies |
| **Sovereign / Air-Gapped** | Yes | Yes | Yes | Yes | No | No | N/A |
| **Remote Management** | Luna Shell / REST | Security World Tools | REST API | REST API | AWS Console | Azure Portal | N/A |
| **Typical Latency (RSA-2048 sign)** | <1 ms | <1 ms | <1 ms | <1 ms | 1-3 ms | 1-3 ms | Varies |
| **Max Keys per Partition** | ~200,000 | ~150,000 | ~100,000 | ~500,000 | ~3,300 | ~250 | Varies |

**Selecting a vendor:**

- **Air-gapped / sovereign deployments**: Thales Luna, Entrust nShield, Utimaco, Securosys — all on-premises network appliances with no outbound connectivity requirement.
- **Native cloud deployments**: AWS CloudHSM (ideal within AWS VPC), Azure Managed HSM (ideal within Azure VNET).
- **Post-quantum key storage**: Securosys Primus is the only appliance HSM currently offering hardware-accelerated ML-KEM and ML-DSA.
- **Highest assurance**: Thales Luna 7 Network HSM with FIPS 140-3 Level 3 and CC EAL4+ is the most widely certified for regulated financial and government workloads.
- **Cost-sensitive cloud**: AWS CloudHSM at ~$1.45/hr per HSM is the most economical managed HSM option when already on AWS.

---

### 1.3 PKCS#11 Primer

The KMS talks to every HSM over the PKCS#11 (Cryptoki) interface, through the hsm-connector service (docs/SECURITY/HSM_INTEGRATION.md), defined in RSA Security's PKCS#11 standard v2.40 and OASIS PKCS #11 v3.0.

**Key PKCS#11 concepts:**

| Concept | Description |
|---|---|
| **Slot** | Logical container for a token; typically maps to a physical HSM partition or PCIe slot |
| **Token** | The HSM partition itself; has a label, serial number, PIN |
| **Session** | A connection handle to a token; can be R/O or R/W |
| **Object** | A cryptographic object (key, certificate, data) stored in the token |
| **Mechanism** | The algorithm to use for an operation (e.g. CKM_AES_GCM, CKM_ECDSA_SHA384) |
| **CKA_EXTRACTABLE** | Attribute: if false, key material cannot be exported from HSM |
| **CKA_SENSITIVE** | Attribute: if true, key value cannot be read back (only used inside HSM) |
| **CKA_TOKEN** | Attribute: if true, object persists across sessions; if false, session-only |

Vecta uses `CKA_EXTRACTABLE = false` and `CKA_SENSITIVE = true` for all keys designated `key_backend: hsm`, ensuring keys are permanently bound to the HSM.

---

### 1.4 Configuration Reference

HSM configuration is set per-tenant via the CLI API. All sensitive values (PINs, passwords) are read from environment variables — never from the config payload itself.

**Full field reference for `HSMProviderConfig`:**

| Field | Type | Required | Description |
|---|---|---|---|
| `provider_name` | string | Yes | One of: `luna`, `utimaco`, `entrust`, `securosys`, `aws_cloudhsm`, `azure_mhsm`, `generic_pkcs11` |
| `integration_service` | string | Yes | Which Vecta service owns this HSM: `keycore` or `certs` |
| `library_path` | string | Yes | Absolute path to the PKCS#11 shared library (`.so` on Linux, `.dll` on Windows) |
| `slot_id` | integer | Yes | PKCS#11 slot index (usually `0` for first partition; use list endpoint to discover) |
| `partition_label` | string | No | Partition/token label for Luna and Entrust (used when slot_id is not deterministic) |
| `token_label` | string | No | PKCS#11 token label string; must match the label shown by `C_GetTokenInfo` |
| `pin_env_var` | string | Yes | Name of environment variable containing the HSM PIN (e.g. `VECTA_HSM_PIN`) |
| `read_only` | bool | No | If `true`, prevents new key generation in this HSM slot; use for backup HSMs |
| `enabled` | bool | Yes | Toggle without removing the config |
| `metadata` | object | No | Vendor-specific options (see per-vendor notes below) |

**`metadata` fields by vendor:**

*Thales Luna:*
```json
{
  "ha_group_label": "vecta-ha-group",
  "ntl_hosts": ["hsm1.internal:1792", "hsm2.internal:1792"],
  "keepalive_interval_seconds": 30,
  "failover_mode": "active_active"
}
```

*Entrust nShield:*
```json
{
  "security_world_path": "/opt/nfast/kmdata/local",
  "rfs_host": "nshield-rfs.internal",
  "cardset_name": "vecta-operator",
  "module_id": 1
}
```

*Utimaco:*
```json
{
  "utimaco_host": "utimaco.internal",
  "utimaco_port": 2883,
  "log_device": "/var/log/utimaco/cs.log"
}
```

*Securosys Primus:*
```json
{
  "primus_host": "primus.internal",
  "primus_port": 2310,
  "primus_cluster_mode": true
}
```

*AWS CloudHSM:*
```json
{
  "cluster_id": "cluster-abc123def",
  "region": "us-east-1",
  "daemon_socket": "/opt/cloudhsm/run/cloudhsm_client.sock"
}
```

*Azure Managed HSM:*
```json
{
  "vault_uri": "https://myvault.managedhsm.azure.net",
  "tenant_id": "azure-tenant-uuid",
  "client_id": "azure-client-uuid",
  "client_secret_env": "AZURE_MHSM_SECRET"
}
```

**Complete curl examples:**

```bash
# --- Thales Luna Network HSM ---
curl -X PUT "https://localhost/svc/auth/auth/cli/hsm/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_name": "luna",
    "integration_service": "keycore",
    "library_path": "/usr/safenet/lunaclient/lib/libCryptoki2_64.so",
    "slot_id": 0,
    "partition_label": "prod-partition",
    "token_label": "vecta-prod",
    "pin_env_var": "VECTA_LUNA_PIN",
    "enabled": true,
    "metadata": {
      "ha_group_label": "vecta-ha-group",
      "ntl_hosts": ["hsm1.internal:1792", "hsm2.internal:1792"],
      "keepalive_interval_seconds": 30
    }
  }'

# --- Entrust nShield ---
curl -X PUT "https://localhost/svc/auth/auth/cli/hsm/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_name": "entrust",
    "integration_service": "keycore",
    "library_path": "/opt/nfast/toolkits/pkcs11/libcknfast.so",
    "slot_id": 0,
    "partition_label": "vecta-partition",
    "pin_env_var": "VECTA_NSHIELD_PIN",
    "enabled": true,
    "metadata": {
      "security_world_path": "/opt/nfast/kmdata/local",
      "rfs_host": "nshield-rfs.internal",
      "module_id": 1
    }
  }'

# --- Utimaco SecurityServer ---
curl -X PUT "https://localhost/svc/auth/auth/cli/hsm/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_name": "utimaco",
    "integration_service": "keycore",
    "library_path": "/usr/lib/utimaco/libcs_pkcs11_R2.so",
    "slot_id": 0,
    "pin_env_var": "VECTA_UTIMACO_PIN",
    "enabled": true,
    "metadata": {
      "utimaco_host": "utimaco.internal",
      "utimaco_port": 2883
    }
  }'

# --- Securosys Primus ---
curl -X PUT "https://localhost/svc/auth/auth/cli/hsm/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_name": "securosys",
    "integration_service": "keycore",
    "library_path": "/usr/securosys/provider/libprimusP11.so",
    "slot_id": 0,
    "token_label": "PRIMUS01",
    "pin_env_var": "VECTA_SECUROSYS_PIN",
    "enabled": true,
    "metadata": {
      "primus_host": "primus.internal",
      "primus_port": 2310,
      "primus_cluster_mode": true
    }
  }'

# --- AWS CloudHSM ---
curl -X PUT "https://localhost/svc/auth/auth/cli/hsm/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_name": "aws_cloudhsm",
    "integration_service": "keycore",
    "library_path": "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
    "slot_id": 0,
    "pin_env_var": "VECTA_CLOUDHSM_PIN",
    "enabled": true,
    "metadata": {
      "cluster_id": "cluster-abc123def",
      "region": "us-east-1"
    }
  }'

# --- Azure Managed HSM ---
curl -X PUT "https://localhost/svc/auth/auth/cli/hsm/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_name": "azure_mhsm",
    "integration_service": "keycore",
    "library_path": "/usr/lib/mhsm/libmhsm_pkcs11.so",
    "slot_id": 0,
    "pin_env_var": "VECTA_MHSM_PIN",
    "enabled": true,
    "metadata": {
      "vault_uri": "https://myvault.managedhsm.azure.net",
      "tenant_id": "your-azure-tenant-id",
      "client_id": "your-client-id",
      "client_secret_env": "AZURE_MHSM_SECRET"
    }
  }'

# --- Generic PKCS#11 (any compliant HSM) ---
curl -X PUT "https://localhost/svc/auth/auth/cli/hsm/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_name": "generic_pkcs11",
    "integration_service": "keycore",
    "library_path": "/usr/lib/pkcs11/libpkcs11.so",
    "slot_id": 0,
    "token_label": "MY-HSM-TOKEN",
    "pin_env_var": "VECTA_HSM_PIN",
    "enabled": true
  }'
```

**Retrieve current HSM configuration:**

```bash
curl "https://localhost/svc/auth/auth/cli/hsm/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

**Disable an HSM without removing config:**

```bash
curl -X PUT "https://localhost/svc/auth/auth/cli/hsm/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"enabled": false}'
```

---

### 1.5 Creating HSM-Backed Keys

When `key_backend: hsm` is specified, the key is generated inside the HSM using the HSM's TRNG and stored in the HSM partition. The key handle (a PKCS#11 object reference) is stored in Vecta's database. The raw key bytes are never held in Vecta memory.

```bash
# AES-256 wrapping key (Key Encryption Key) — never exportable
curl -X POST "https://localhost/svc/keycore/keys?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "hsm-root-kek",
    "algorithm": "AES-256",
    "purpose": "wrap",
    "key_backend": "hsm",
    "export_allowed": false,
    "labels": {
      "backend": "hsm",
      "custody": "fips-140-3-l3",
      "classification": "secret"
    }
  }'

# EC-P384 signing key — for TLS certificates, JWT signing
curl -X POST "https://localhost/svc/keycore/keys?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "code-signing-key-p384",
    "algorithm": "EC-P384",
    "purpose": "sign",
    "key_backend": "hsm",
    "export_allowed": false,
    "labels": {"backend": "hsm", "use": "code-signing"}
  }'

# RSA-4096 signing key — for root CA or high-assurance signing
curl -X POST "https://localhost/svc/keycore/keys?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "root-ca-rsa4096",
    "algorithm": "RSA-4096",
    "purpose": "sign",
    "key_backend": "hsm",
    "export_allowed": false,
    "labels": {"backend": "hsm", "use": "root-ca", "tier": "critical"}
  }'

# AES-256 encryption key for data at rest — HSM-backed
curl -X POST "https://localhost/svc/keycore/keys?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "db-encryption-key",
    "algorithm": "AES-256",
    "purpose": "encrypt",
    "key_backend": "hsm",
    "export_allowed": false,
    "labels": {"backend": "hsm", "use": "database-encryption"}
  }'

# List all HSM-backed keys for a tenant
curl "https://localhost/svc/keycore/keys?tenant_id=root&key_backend=hsm" \
  -H "Authorization: Bearer $TOKEN"
```

**Performing cryptographic operations with HSM-backed keys:**

```bash
# Sign a message (operation stays in HSM — only the signature leaves)
curl -X POST "https://localhost/svc/keycore/keys/KEY_ID/sign?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message_b64": "base64-encoded-message",
    "algorithm": "ECDSA-SHA384"
  }'

# Encrypt data using HSM-backed AES-256-GCM key
curl -X POST "https://localhost/svc/keycore/keys/KEY_ID/encrypt?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext_b64": "SGVsbG8gV29ybGQ=",
    "algorithm": "AES-256-GCM"
  }'

# Wrap a software key using the HSM root KEK
curl -X POST "https://localhost/svc/keycore/keys/HSM_KEK_ID/wrap?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_key_id": "SOFTWARE_KEY_ID",
    "wrap_algorithm": "AES-256-KW"
  }'
```

---

### 1.6 HSM HA Configuration

#### Thales Luna HA Groups

Thales Luna HA Groups provide transparent load balancing and automatic failover across multiple Luna partitions.

**Setup procedure:**

1. **Network Trust Link (NTL):** Establish a mutual TLS NTL between the Vecta server and each Luna Network HSM appliance:
   ```bash
   # On each Luna appliance (Luna Shell)
   lunash:> network hostname set -hostname hsm1.internal
   lunash:> ntl bind -nodeip VECTA_SERVER_IP

   # On Vecta server (Luna Client tools)
   vtl addServer -n hsm1.internal -c server.pem
   vtl createCert -n vecta-client
   vtl addServer -n hsm2.internal -c server.pem
   ```

2. **Create partition on each appliance** with identical labels.

3. **Create HA Group** using the Luna client VTL tool:
   ```bash
   vtl haAdmin addMember -group vecta-ha-group -serial PARTITION1_SERIAL
   vtl haAdmin addMember -group vecta-ha-group -serial PARTITION2_SERIAL
   vtl haAdmin enable -group vecta-ha-group
   vtl haAdmin show
   ```

4. **Set `ha_group_label`** in the tenant's HSM profile metadata to the HA group name:
   ```json
   {"ha_group_label": "vecta-ha-group"}
   ```

5. **Verify HA group in Vecta:**
   ```bash
   curl "https://localhost/svc/auth/auth/cli/hsm/partitions?tenant_id=root" \
     -H "Authorization: Bearer $TOKEN"
   ```

Vecta's PKCS#11 library will handle transparent failover: if HSM1 goes offline, requests automatically route to HSM2 without application changes.

#### AWS CloudHSM Cluster HA

AWS CloudHSM clusters distribute HSMs across Availability Zones automatically.

**Setup steps:**

1. Create a CloudHSM cluster in your VPC (AWS Console or CLI):
   ```bash
   aws cloudhsmv2 create-cluster \
     --hsm-type hsm1.medium \
     --subnet-ids subnet-abc123 subnet-def456
   ```

2. Provision HSMs in at least 2 Availability Zones:
   ```bash
   aws cloudhsmv2 create-hsm \
     --cluster-id cluster-abc123def \
     --availability-zone us-east-1a

   aws cloudhsmv2 create-hsm \
     --cluster-id cluster-abc123def \
     --availability-zone us-east-1b
   ```

3. Initialize cluster using the CSR (first-time only):
   ```bash
   aws cloudhsmv2 describe-clusters --filters clusterIds=cluster-abc123def \
     --query 'Clusters[0].Certificates.ClusterCsr' --output text > cluster.csr
   # Sign with your organization's CA, upload signed cert to initialize
   ```

4. Install CloudHSM client on each Vecta server node:
   ```bash
   wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Xenial/cloudhsm-client_latest_amd64.deb
   sudo dpkg -i cloudhsm-client_latest_amd64.deb
   /opt/cloudhsm/bin/configure -a CLUSTER_ENI_IP
   ```

5. Configure Vecta with the CloudHSM PKCS#11 library (see §1.4 above).

#### Securosys Primus Active-Active HA

Securosys Primus HSMs support active-active clustering natively:

1. Configure Primus cluster in the Primus REST API
2. Set `primus_cluster_mode: true` in Vecta metadata
3. Both Primus nodes share synchronized key store; Vecta can address either

---

### 1.7 FIPS 140-3 Mode with HSM

When Vecta's FIPS 140-3 mode is enabled AND the HSM backend is active, the following enforcements apply:

| Behavior | Detail |
|---|---|
| **Key Generation** | All key material generated exclusively using HSM hardware TRNG; no software DRBG used |
| **Algorithm Restrictions** | Non-FIPS algorithms rejected at API layer: ChaCha20-Poly1305, Ed25519 (outside FIPS mode), X25519 |
| **Allowed Algorithms** | AES-128-GCM, AES-256-GCM, AES-256-CTR, RSA-2048+, EC-P256/P384/P521, HMAC-SHA256/SHA384/SHA512 |
| **Key Custody Proof** | Audit event includes `hsm_node_id`, `hsm_slot_id`, `pkcs11_object_handle` for every operation |
| **Physical Tamper Response** | HSM zeroizes keys on intrusion detection; Vecta receives PKCS#11 error, falls back to disabled state |
| **Identity Authentication** | FIPS 140-3 Level 3 requires identity-based authentication before cryptographic services |

---

### 1.8 Listing HSM Partitions

Use this endpoint to discover available PKCS#11 slots and tokens before configuring Vecta.

```bash
# List all slots/tokens on a PKCS#11 library
curl "https://localhost/svc/auth/auth/cli/hsm/partitions?tenant_id=root&library_path=/usr/safenet/lunaclient/lib/libCryptoki2_64.so" \
  -H "Authorization: Bearer $TOKEN"

# Example response:
# {
#   "slots": [
#     {
#       "slot_id": 0,
#       "token_label": "vecta-prod",
#       "token_serial": "660129",
#       "manufacturer": "SafeNet Inc.",
#       "model": "Luna Network HSM 7",
#       "firmware_version": "7.4.0",
#       "flags": ["TOKEN_PRESENT", "TOKEN_INITIALIZED", "LOGIN_REQUIRED"],
#       "mechanisms": ["CKM_AES_GCM", "CKM_ECDSA_SHA384", "CKM_RSA_PKCS_PSS"]
#     },
#     {
#       "slot_id": 1,
#       "token_label": "vecta-dr",
#       "token_serial": "660130",
#       "manufacturer": "SafeNet Inc.",
#       "model": "Luna Network HSM 7",
#       "firmware_version": "7.4.0"
#     }
#   ]
# }
```

---

### 1.9 HSM Key Wrapping and Unwrapping

Wrapping allows a software-resident key to be encrypted by an HSM KEK and stored safely at rest.

```bash
# Wrap a software DEK using the HSM KEK (AES-256-KW)
curl -X POST "https://localhost/svc/keycore/keys/HSM_KEK_ID/wrap?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_key_id": "SOFTWARE_DEK_ID",
    "wrap_algorithm": "AES-256-KW"
  }'
# Response: {wrapped_key_b64: "...", kek_id: "HSM_KEK_ID", wrap_algorithm: "AES-256-KW"}

# Unwrap — decrypt a previously wrapped key back into the HSM
curl -X POST "https://localhost/svc/keycore/keys/HSM_KEK_ID/unwrap?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "wrapped_key_b64": "...",
    "wrap_algorithm": "AES-256-KW",
    "target_key_name": "restored-dek",
    "target_key_algorithm": "AES-256",
    "store_in_hsm": true
  }'
```

---

### 1.10 Troubleshooting HSM Connectivity

**Common errors and resolutions:**

| Error | Likely Cause | Resolution |
|---|---|---|
| `CKR_SLOT_ID_INVALID` | Incorrect `slot_id` in config | Use the partition list endpoint to find correct slot |
| `CKR_PIN_INCORRECT` | Wrong HSM PIN in env var | Verify `$VECTA_HSM_PIN` value; re-initialize PIN if locked |
| `CKR_TOKEN_NOT_PRESENT` | HSM not reachable / NTL down | Check network connectivity; `vtl verify` on Luna client |
| `CKR_LIBRARY_LOAD_FAILED` | Wrong `library_path` | Verify file exists, is executable, architecture matches |
| `CKR_MECHANISM_INVALID` | HSM firmware too old | Update HSM firmware; check mechanism list |
| `CKR_USER_NOT_LOGGED_IN` | Session timeout | Configure `keepalive_interval_seconds`; reduce session idle timeout |
| `CKR_DEVICE_ERROR` | HSM hardware fault / tamper | Contact HSM vendor; check HSM event log; consider zeroization recovery |
| `CKR_BUFFER_TOO_SMALL` | Output buffer too small | Internal error; file a Vecta support ticket |

---

### 1.11 Vendor-Specific Notes

#### Thales Luna: NTL vs STC

Thales Luna supports two transport security modes:
- **NTL (Network Trust Link)**: TLS 1.2 using client/server certificates. Default and most widely deployed.
- **STC (Secure Trusted Channel)**: End-to-end authenticated encrypted channel from the application to the Luna partition. Eliminates network-layer TLS as a trust boundary. Higher assurance.

To enable STC with Vecta:
```json
{
  "metadata": {
    "transport_mode": "stc",
    "stc_partition_identity": "/usr/safenet/lunaclient/stc/partitions/vecta-prod.id"
  }
}
```

#### Entrust nShield: Security World

nShield HSMs use a "Security World" that groups HSMs together cryptographically. All HSMs in a Security World share the same master key (the OCS — Operator Card Set or ACS — Administrator Card Set). This means:
- Keys created in the Security World can be used by any HSM member.
- Quorum of OCS cards required for administrative operations.
- Security World metadata must be present on the Vecta server: `security_world_path`.

#### AWS CloudHSM: User Accounts

CloudHSM uses its own user model separate from IAM. Vecta uses a Crypto User (CU) account to perform cryptographic operations. The `pin_env_var` should contain `CU_USERNAME:CU_PASSWORD`.

```bash
# Set up CloudHSM CU (run on Vecta server with cloudhsm-client installed)
/opt/cloudhsm/bin/cloudhsm_mgmt_util /opt/cloudhsm/etc/cloudhsm_mgmt_util.cfg
> createUser CU vecta_cu "StrongPassword123!"
```

---

## 2. Cluster Management

This section is the operator's summary; [CLUSTERING.md](CLUSTERING.md) is
the reference and states what is done and what isn't. (An earlier version
of this section described Raft consensus, witness nodes, read replicas,
consistency modes and dedicated cluster ports. None of that exists; it was
replaced in 13.37.0-beta.)

### 2.1 How a cluster works

- **One primary writes.** Key and policy lifecycle writes run on the
  primary. A member forwards them to the primary's cluster-manager
  (pinned TLS, per-member credential); crypto operations, reads and logins
  run on every node.
- **Postgres logical replication** carries each feature's tables from the
  primary to the members assigned that feature (replication profiles:
  base, standard, security, full, or custom). Node-local tables (sessions,
  this node's settings, logs) never replicate.
- **Nodes:** primary, member, or fenced (a former primary that learned of a
  newer one). There are no witnesses or read replicas.

### 2.2 Adding a node

Platform → Cluster → Node Management → **Add Instance**. On the primary,
create a join bundle for the new node and choose its profile; on the new
node, paste the bundle and confirm. The join transfers the master key
sealed with ML-KEM-768 and subscribes the node to its components
([CLUSTERING.md](CLUSTERING.md#joining-a-node-slice-2) lists the settings
the primary needs first).

```bash
curl "https://localhost/svc/cluster/cluster/replication/status" -H "Authorization: Bearer $TOKEN"
```

### 2.3 Failover

Platform → Cluster → **Failover**.

| Voters | What happens when the primary is lost |
|---|---|
| 1 or 2 | Lifecycle writes fail (`502 primary_unreachable`) until an administrator promotes a member. Crypto operations continue. |
| 3 or more | After 20 s without the primary, the members elect one by majority; the old primary's lease has already stopped its writes. |

```bash
# On the member to promote. If the primary answers, it is fenced first and
# this node waits for its last write (a switchover).
curl -X POST "https://member.example/svc/cluster/cluster/failover/promote?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"confirm": true, "reason": "maintenance"}'

# If the primary is down: add "force": true. Its writes that had not reached
# this node are lost, and if it still serves clients it accepts writes until
# it learns of the promotion.
curl "https://member.example/svc/cluster/cluster/failover/status?tenant_id=root" -H "Authorization: Bearer $TOKEN"
```

A fenced node rejoins with a join bundle from the current primary.

### 2.4 Networking

| From | To | Port | Purpose |
|---|---|---|---|
| Members | Primary | cluster-manager (`HTTP_PORT`, TLS) | join, forwarded writes, heartbeats |
| Every node | Every node | cluster-manager | votes, status, announcements (signed with the cluster's peer secret) |
| Members | Primary | Postgres (`CLUSTER_PG_ADVERTISE_PORT`, TLS) | logical replication |

A node that may become primary needs `CLUSTER_ADVERTISE_URL`,
`CLUSTER_HTTP_TLS_*` and `CLUSTER_PG_ADVERTISE_HOST`.

### 2.5 Upgrades

Upgrade members one at a time, then promote an upgraded member (a
switchover loses nothing), upgrade the old primary, and rejoin it.

### 2.6 Disaster recovery

Replication is asynchronous: a primary lost without a switchover loses its
writes that had not reached the promoted member. Keep backups
(Backup & Restore) off the cluster.

---

## 3. Security Considerations

### HSM Security

- **Always use non-exportable keys for root KEKs**: Set `export_allowed: false` on all HSM-backed KEKs. Non-exportable keys with `CKA_EXTRACTABLE=false` cannot be exported even by the HSM administrator.
- **Enable FIPS mode in HSM partition settings**: Separate from Vecta's FIPS mode; must be configured on the HSM itself. Luna: set `fips_mode=1` in partition policy. CloudHSM: enable FIPS mode via cluster configuration.
- **PIN rotation**: Rotate HSM PINs on a schedule and always after personnel changes (any role with PIN knowledge).
- **NTL certificate rotation**: Rotate Luna NTL certificates annually. Compromise of NTL client certificate allows establishing sessions but not extracting non-exportable keys.
- **Audit HSM event logs**: Collect HSM-native event logs (Luna Audit Logging, CloudHSM CloudTrail) alongside Vecta audit logs. Discrepancies indicate potential tampering.
- **Zeroization policy**: Document and test the zeroization procedure. Know what triggers automatic zeroization and what the recovery procedure is.

### Cluster Security

- **Three nodes for automatic failover.** With two, a lost primary needs an
  administrator, and a forced promotion can leave both nodes writing until
  they reach each other.
- **Node-to-node traffic is TLS** (cluster-manager pinned by certificate
  fingerprint, Postgres with `CLUSTER_PG_SSLMODE`, default `verify-full`).
- **Keep the cluster-manager and Postgres ports** on a network only the
  nodes reach.

## 4. Full API Reference

### 4.1 HSM API

| Method | Path | Description |
|---|---|---|
| `PUT` | `/svc/auth/auth/cli/hsm/config` | Create or update HSM configuration |
| `GET` | `/svc/auth/auth/cli/hsm/config` | Get current HSM configuration |
| `GET` | `/svc/auth/auth/cli/hsm/partitions` | List PKCS#11 slots and tokens |

### 4.2 Cluster API

| Method | Path | Description |
|---|---|---|
| `GET` | `/svc/cluster/cluster/nodes` | List all cluster nodes and their status |
| `DELETE` | `/svc/cluster/cluster/nodes/{node_id}` | Remove a node from the cluster |
| `GET` | `/svc/cluster/cluster/failover/status` | This node's role, epoch, lease and peers |
| `POST` | `/svc/cluster/cluster/failover/promote` | Promote this node |
| `GET` | `/svc/cluster/cluster/sync/events` | Sync event log |
| `POST` | `/svc/cluster/cluster/profiles` | Create replication profile |
| `GET` | `/svc/cluster/cluster/profiles` | List replication profiles |
| `DELETE` | `/svc/cluster/cluster/profiles/{profile_id}` | Delete replication profile |
