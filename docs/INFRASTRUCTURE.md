# Infrastructure — HSM, Cluster, QKD, QRNG, MPC/FROST

> **Scope:** This document covers the hardware and distributed-systems infrastructure that Vecta KMS relies on: Hardware Security Modules (HSM), multi-node clustering, Quantum Key Distribution (QKD), Quantum Random Number Generation (QRNG), and Multi-Party Computation / FROST threshold signing. Each section contains conceptual background, architecture details, configuration reference, API examples, operational runbooks, and security considerations.

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
   - 2.1 Clustering Architecture
   - 2.2 Node Roles and Raft Consensus
   - 2.3 Adding a Node
   - 2.4 Replication Profiles
   - 2.5 Sync Monitoring
   - 2.6 Role Changes and Failover
   - 2.7 Disaster Recovery
   - 2.8 Cluster Networking Requirements
   - 2.9 Cluster Upgrade Procedures
   - 2.10 Split-Brain Prevention

3. [QKD — Quantum Key Distribution](#3-qkd--quantum-key-distribution)
   - 3.1 Quantum Threat Model
   - 3.2 QKD Protocols
   - 3.3 Integration with Vecta
   - 3.4 Configuring a QKD Link
   - 3.5 ETSI QKD 004 Standard
   - 3.6 QBER Monitoring
   - 3.7 Use Cases and Hybrid Scenarios

4. [QRNG — Quantum Random Number Generation](#4-qrng--quantum-random-number-generation)
   - 4.1 Why QRNG
   - 4.2 Supported Hardware
   - 4.3 Configuring QRNG Sources
   - 4.4 NIST SP 800-22 Health Tests
   - 4.5 Entropy Pooling and Fallback
   - 4.6 Integration with Key Generation

5. [MPC / FROST Threshold Signing](#5-mpc--frost-threshold-signing)
   - 5.1 Threshold Cryptography Concepts
   - 5.2 FROST Protocol
   - 5.3 ECDSA-MPC Protocols
   - 5.4 BLS Threshold Signatures
   - 5.5 Setting Up an MPC Group
   - 5.6 Distributed Key Generation Ceremony
   - 5.7 Threshold Signing
   - 5.8 Share Refresh and Proactive Security
   - 5.9 Use Cases

6. [Security Considerations](#6-security-considerations)
7. [Full API Reference](#7-full-api-reference)

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

All Vecta HSM integrations communicate over the PKCS#11 (Cryptoki) interface, defined in RSA Security's PKCS#11 standard v2.40 and OASIS PKCS #11 v3.0.

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
curl -X PUT "http://localhost:5173/svc/auth/auth/cli/hsm/config?tenant_id=root" \
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
curl -X PUT "http://localhost:5173/svc/auth/auth/cli/hsm/config?tenant_id=root" \
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
curl -X PUT "http://localhost:5173/svc/auth/auth/cli/hsm/config?tenant_id=root" \
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
curl -X PUT "http://localhost:5173/svc/auth/auth/cli/hsm/config?tenant_id=root" \
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
curl -X PUT "http://localhost:5173/svc/auth/auth/cli/hsm/config?tenant_id=root" \
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
curl -X PUT "http://localhost:5173/svc/auth/auth/cli/hsm/config?tenant_id=root" \
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
curl -X PUT "http://localhost:5173/svc/auth/auth/cli/hsm/config?tenant_id=root" \
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
curl "http://localhost:5173/svc/auth/auth/cli/hsm/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

**Disable an HSM without removing config:**

```bash
curl -X PATCH "http://localhost:5173/svc/auth/auth/cli/hsm/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"enabled": false}'
```

---

### 1.5 Creating HSM-Backed Keys

When `key_backend: hsm` is specified, the key is generated inside the HSM using the HSM's TRNG and stored in the HSM partition. The key handle (a PKCS#11 object reference) is stored in Vecta's database. The raw key bytes are never held in Vecta memory.

```bash
# AES-256 wrapping key (Key Encryption Key) — never exportable
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=root" \
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
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=root" \
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
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=root" \
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
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=root" \
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
curl "http://localhost:5173/svc/keycore/keys?tenant_id=root&key_backend=hsm" \
  -H "Authorization: Bearer $TOKEN"
```

**Performing cryptographic operations with HSM-backed keys:**

```bash
# Sign a message (operation stays in HSM — only the signature leaves)
curl -X POST "http://localhost:5173/svc/keycore/keys/KEY_ID/sign?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message_b64": "base64-encoded-message",
    "algorithm": "ECDSA-SHA384"
  }'

# Encrypt data using HSM-backed AES-256-GCM key
curl -X POST "http://localhost:5173/svc/keycore/keys/KEY_ID/encrypt?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext_b64": "SGVsbG8gV29ybGQ=",
    "algorithm": "AES-256-GCM"
  }'

# Wrap a software key using the HSM root KEK
curl -X POST "http://localhost:5173/svc/keycore/keys/HSM_KEK_ID/wrap?tenant_id=root" \
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

4. **Set `ha_group_label`** in Vecta HSM config metadata to the HA group name:
   ```json
   {"ha_group_label": "vecta-ha-group"}
   ```

5. **Verify HA group in Vecta:**
   ```bash
   curl "http://localhost:5173/svc/auth/auth/cli/hsm/partitions?tenant_id=root" \
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

```bash
# Enable FIPS mode on Vecta tenant
curl -X PUT "http://localhost:5173/svc/auth/auth/cli/fips?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"enabled": true, "level": "fips_140_3_l3", "hsm_required": true}'

# Verify FIPS status
curl "http://localhost:5173/svc/auth/auth/cli/fips?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
# Response: {fips_enabled: true, level: "fips_140_3_l3", hsm_active: true, hsm_provider: "luna", fips_mode_since: "2025-01-15T09:00:00Z"}
```

---

### 1.8 Listing HSM Partitions

Use this endpoint to discover available PKCS#11 slots and tokens before configuring Vecta.

```bash
# List all slots/tokens on a PKCS#11 library
curl "http://localhost:5173/svc/auth/auth/cli/hsm/partitions?tenant_id=root&library_path=/usr/safenet/lunaclient/lib/libCryptoki2_64.so" \
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
curl -X POST "http://localhost:5173/svc/keycore/keys/HSM_KEK_ID/wrap?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_key_id": "SOFTWARE_DEK_ID",
    "wrap_algorithm": "AES-256-KW"
  }'
# Response: {wrapped_key_b64: "...", kek_id: "HSM_KEK_ID", wrap_algorithm: "AES-256-KW"}

# Unwrap — decrypt a previously wrapped key back into the HSM
curl -X POST "http://localhost:5173/svc/keycore/keys/HSM_KEK_ID/unwrap?tenant_id=root" \
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

```bash
# Check HSM health status
curl "http://localhost:5173/svc/auth/auth/cli/hsm/health?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
# Response: {
#   "status": "healthy",
#   "provider": "luna",
#   "slot_id": 0,
#   "token_label": "vecta-prod",
#   "session_count": 4,
#   "last_operation_ms": 0.8,
#   "last_check": "2025-03-22T14:00:00Z"
# }

# Run HSM diagnostics
curl -X POST "http://localhost:5173/svc/auth/auth/cli/hsm/diagnostics?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

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

### 2.1 Clustering Architecture

Vecta KMS uses a leader-follower cluster model with Raft-based consensus for distributed coordination. This provides:

- **Strong consistency**: All writes go through the leader and are replicated to a quorum before acknowledgment
- **Automatic failover**: Leader election completes within 300-600ms of leader failure
- **Linear scalability for reads**: Followers can serve reads with configurable consistency guarantees
- **Horizontal scale**: Add up to 9 voting nodes; beyond that, add non-voting read replicas

**Node types:**

| Role | Votes | Accepts Writes | Serves Reads | Data Stored |
|---|---|---|---|---|
| **Leader** | Yes | Yes | Yes | Full |
| **Follower** | Yes | No (proxies to leader) | Yes | Full |
| **Witness** | Yes | No | No | None |
| **Read Replica** | No | No | Yes | Full |

**Quorum calculation:**

For N voting nodes, quorum requires ⌊N/2⌋ + 1 nodes to be online and reachable:

| N nodes | Quorum | Max failures tolerated |
|---|---|---|
| 1 | 1 | 0 |
| 3 | 2 | 1 |
| 5 | 3 | 2 |
| 7 | 4 | 3 |

**Cluster topology recommendations:**

| Environment | Recommended Topology | Rationale |
|---|---|---|
| Development / Test | 1 node | Simplicity; no HA |
| Small production | 3 nodes (2 data + 1 witness) | Tolerates 1 failure; minimal resource overhead |
| Enterprise HA | 5 nodes (3 data + 2 witness) | Tolerates 2 concurrent failures |
| Geo-distributed | 6 nodes (2 per region) + 1 witness in 3rd region | Tolerates single region failure |

---

### 2.2 Node Roles and Raft Consensus

Vecta's clustering layer uses the Raft distributed consensus algorithm. Key Raft properties:

**Leader Election:**
- Each node tracks the current term (monotonically increasing integer)
- If a follower does not receive a heartbeat within the election timeout (150–300ms, randomized to prevent split votes), it becomes a candidate
- Candidate increments its term, votes for itself, sends RequestVote RPCs to all peers
- Node wins election if it receives votes from a majority of voting nodes
- The node with the highest log index and greatest term wins ties
- Election safety: only one leader per term

**Log Replication:**
- Leader receives write request, appends to its local WAL (Write-Ahead Log)
- Leader sends AppendEntries RPCs to all followers in parallel
- Entry committed once a quorum acknowledges
- Followers apply committed entries to their state machines
- Client receives success acknowledgment after commit, not after disk write on leader

**Heartbeat:**
- Leader sends AppendEntries (empty = heartbeat) to all followers every 50ms
- If heartbeat interval elapses without receipt, follower starts election timeout countdown

**Log compaction:**
- Vecta takes snapshots of the state machine periodically
- Old WAL entries before snapshot can be truncated
- New nodes joining the cluster receive snapshot + subsequent log entries (not entire log history)

---

### 2.3 Adding a Node

```bash
# Step 1: Generate a join bundle on the current leader
# The bundle contains a short-lived token, leader endpoint, and cluster CA certificate
curl -X POST "http://localhost:5173/svc/cluster/join-bundle?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "role": "follower",
    "ttl_minutes": 15
  }'
# Response:
# {
#   "bundle_token": "eyJhbGciOiJIUzI1NiJ9...",
#   "leader_endpoint": "https://vecta-leader.internal:5173",
#   "ca_cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
#   "expires_at": "2025-03-22T14:15:00Z"
# }

# Step 2: Start Vecta on the new node with cluster mode enabled
# (Set in vecta.yaml or env vars before starting the service)
# cluster:
#   enabled: true
#   mode: join

# Step 3: On the new node, submit the join request
curl -X POST "http://new-node.internal:5173/svc/cluster/join" \
  -H "Content-Type: application/json" \
  -d '{
    "bundle_token": "eyJhbGciOiJIUzI1NiJ9...",
    "leader_endpoint": "https://vecta-leader.internal:5173",
    "local_bind_address": "0.0.0.0:5173",
    "local_advertise_address": "new-node.internal:5173"
  }'

# Step 4: Verify the node appears in the cluster
curl "http://localhost:5173/svc/cluster/nodes" \
  -H "Authorization: Bearer $TOKEN"
# Response:
# {
#   "nodes": [
#     {"node_id": "node-abc", "role": "leader", "address": "vecta-leader.internal:5173", "healthy": true, "lag_ms": 0},
#     {"node_id": "node-def", "role": "follower", "address": "vecta-node2.internal:5173", "healthy": true, "lag_ms": 12},
#     {"node_id": "node-ghi", "role": "follower", "address": "new-node.internal:5173", "healthy": true, "lag_ms": 150}
#   ],
#   "leader_id": "node-abc",
#   "quorum_size": 2,
#   "quorum_met": true
# }

# Step 5: Add a witness node (votes but stores no data — cheaper)
curl -X POST "http://localhost:5173/svc/cluster/join-bundle?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"role": "witness", "ttl_minutes": 15}'

# Submit join on the witness node
curl -X POST "http://witness-node.internal:5173/svc/cluster/join" \
  -d '{
    "bundle_token": "...",
    "leader_endpoint": "https://vecta-leader.internal:5173",
    "role": "witness"
  }'
```

---

### 2.4 Replication Profiles

Replication profiles define how reads are served from the cluster. They allow trading latency for consistency based on use case.

**Consistency modes:**

| Mode | Read Target | Staleness | Latency | Use Case |
|---|---|---|---|---|
| `strong` | Always leader | Zero | Highest (cross-region) | Financial transactions, key operations |
| `bounded_staleness` | Nearest follower with lag < max_lag_ms | At most max_lag_ms | Medium | Audit reads, reporting |
| `eventual` | Nearest node | Unbounded | Lowest | Monitoring dashboards, metrics |

```bash
# Create a geo-routing profile for EU reads
curl -X POST "http://localhost:5173/svc/cluster/profiles" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "eu-west-reads",
    "node_ids": ["node-eu-west-1", "node-eu-west-2"],
    "consistency_mode": "bounded_staleness",
    "read_preference": "nearest",
    "max_lag_ms": 500,
    "routing_tags": {"region": "eu-west-1", "compliance": "gdpr"}
  }'

# Create a strong-consistency profile for payment operations
curl -X POST "http://localhost:5173/svc/cluster/profiles" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "payment-strong",
    "consistency_mode": "strong",
    "routing_tags": {"tier": "payment"}
  }'

# List all profiles
curl "http://localhost:5173/svc/cluster/profiles" \
  -H "Authorization: Bearer $TOKEN"

# Delete a profile
curl -X DELETE "http://localhost:5173/svc/cluster/profiles/PROFILE_ID" \
  -H "Authorization: Bearer $TOKEN"
```

---

### 2.5 Sync Monitoring

Replication lag monitoring is critical for detecting network partitions or overloaded followers.

```bash
# Check replication lag for every node
curl "http://localhost:5173/svc/cluster/sync/lag" \
  -H "Authorization: Bearer $TOKEN"
# Response:
# {
#   "leader_lsn": 1842930,
#   "nodes": [
#     {"node_id": "node-abc", "role": "leader", "current_lsn": 1842930, "lag_ms": 0, "healthy": true},
#     {"node_id": "node-def", "role": "follower", "current_lsn": 1842885, "lag_ms": 45, "healthy": true},
#     {"node_id": "node-eu-1", "role": "follower", "current_lsn": 1842100, "lag_ms": 830, "healthy": true},
#     {"node_id": "node-eu-2", "role": "follower", "current_lsn": 1840200, "lag_ms": 2700, "healthy": false}
#   ]
# }

# List sync events (filter by type)
curl "http://localhost:5173/svc/cluster/sync/events?event_type=error&limit=50" \
  -H "Authorization: Bearer $TOKEN"

curl "http://localhost:5173/svc/cluster/sync/events?event_type=election&limit=10" \
  -H "Authorization: Bearer $TOKEN"

curl "http://localhost:5173/svc/cluster/sync/events?node_id=node-eu-2&limit=100" \
  -H "Authorization: Bearer $TOKEN"

# Get cluster-wide health summary
curl "http://localhost:5173/svc/cluster/health" \
  -H "Authorization: Bearer $TOKEN"
# Response: {overall: "degraded", quorum_met: true, leader: "node-abc", unhealthy_nodes: ["node-eu-2"], max_lag_ms: 2700}
```

**Alerting thresholds:**

| Metric | Warning | Critical |
|---|---|---|
| Replication lag | > 500ms | > 5000ms |
| Unhealthy nodes | 1 | ≥ quorum size |
| Election frequency | > 1/hour | > 3/hour |
| WAL apply errors | > 0 | > 5 |

---

### 2.6 Role Changes and Failover

**Planned leader step-down (for maintenance):**

```bash
# Gracefully transfer leadership to a specific follower
curl -X POST "http://localhost:5173/svc/cluster/nodes/LEADER_NODE_ID/role" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "new_role": "follower",
    "preferred_successor_id": "node-def",
    "reason": "planned-maintenance-window-2025-03-22"
  }'

# Promote a follower to leader (emergency — forces election)
curl -X POST "http://localhost:5173/svc/cluster/nodes/NODE_ID/role" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"new_role": "leader", "reason": "emergency-failover"}'
```

**Removing a failed node:**

```bash
# Mark node as permanently removed (quorum recalculated)
curl -X DELETE "http://localhost:5173/svc/cluster/nodes/FAILED_NODE_ID" \
  -H "Authorization: Bearer $TOKEN"

# After removing node, verify quorum is still met
curl "http://localhost:5173/svc/cluster/health" \
  -H "Authorization: Bearer $TOKEN"
```

**Changing a node's role:**

```bash
# Promote witness to follower (begins data replication)
curl -X POST "http://localhost:5173/svc/cluster/nodes/WITNESS_NODE_ID/role" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"new_role": "follower"}'

# Demote follower to witness (stops data replication — frees storage)
curl -X POST "http://localhost:5173/svc/cluster/nodes/FOLLOWER_NODE_ID/role" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"new_role": "witness"}'
```

---

### 2.7 Disaster Recovery

**Backup before any cluster topology change:**

```bash
# Create a backup
curl -X POST "http://localhost:5173/svc/governance/governance/backups?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"label": "pre-maintenance-2025-03-22", "include_keys": true}'

# List backups
curl "http://localhost:5173/svc/governance/governance/backups?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Restore from backup
curl -X POST "http://localhost:5173/svc/governance/governance/backups/BACKUP_ID/restore?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target_node_ids": ["node-abc"], "verify_before_restore": true}'
```

**Geo-redundant DR scenarios:**

| Scenario | Impact | Recovery Procedure |
|---|---|---|
| Single node failure | No outage if quorum met | Failed node auto-removed; add replacement; rejoin |
| Single AZ failure (3-node cluster, 1 per AZ) | No outage (2 nodes = quorum) | Replace failed AZ node; rejoin |
| Single region failure (6-node, 2/region) | No outage if 3rd region witness tips quorum | Remaining nodes form quorum; provision new region nodes |
| Total cluster loss | Full outage | Restore leader from backup; rejoin followers from snapshot |
| Data corruption (all nodes) | Full outage | Restore from off-cluster backup; verify key integrity |

**RPO and RTO targets:**

| Failure Type | Target RPO | Target RTO |
|---|---|---|
| Single node | 0 (no data loss) | < 1 min (auto election) |
| Single region | 0 | < 5 min |
| Full DR restore | Last backup | 15–60 min depending on backup size |

**Minimum backup interval recommendations:**

- Root KEKs: continuous replication (no RPO acceptable)
- Key metadata: hourly
- Audit logs: every 15 minutes
- Full backup: daily

---

### 2.8 Cluster Networking Requirements

All inter-node communication uses mTLS (mutual TLS). Vecta generates cluster node certificates from its internal CA during bootstrap.

**Required ports:**

| Port | Protocol | Purpose | Direction |
|---|---|---|---|
| 5173 | TCP (HTTPS) | Vecta API / Raft RPC | Node ↔ Node, Client → Node |
| 5174 | TCP | Cluster gossip / membership | Node ↔ Node |
| 5175 | TCP | WAL replication stream | Follower ← Leader |

**Firewall rules:**

All Vecta nodes must be able to reach each other on ports 5173–5175. Client traffic only needs to reach port 5173. No inbound connections from outside the cluster are required for internal replication.

**Latency requirements:**

| Cluster Type | Max Round-Trip Latency |
|---|---|
| Single-region | < 2ms (same datacenter) |
| Multi-AZ (same region) | < 10ms |
| Multi-region | < 100ms recommended; up to 200ms tolerated |

High inter-node latency increases election timeouts and may cause false leader elections. Vecta automatically adjusts heartbeat and election timeout intervals based on measured latency.

---

### 2.9 Cluster Upgrade Procedures

**Rolling upgrade (zero downtime):**

1. Upgrade followers one at a time (start with the last follower in the ring):
   ```bash
   # Drain in-flight requests on the target node
   curl -X POST "http://target-node:5173/svc/cluster/nodes/NODE_ID/drain" \
     -H "Authorization: Bearer $TOKEN"

   # Stop Vecta on the node
   systemctl stop vecta

   # Upgrade the binary
   dpkg -i vecta_new_version.deb

   # Start Vecta
   systemctl start vecta

   # Verify it rejoined the cluster as follower
   curl "http://localhost:5173/svc/cluster/nodes" -H "Authorization: Bearer $TOKEN"
   ```

2. Repeat for each follower.

3. Step down the leader (triggers election to a now-upgraded follower):
   ```bash
   curl -X POST "http://localhost:5173/svc/cluster/nodes/LEADER_ID/role" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"new_role": "follower"}'
   ```

4. Upgrade the old leader (now a follower).

---

### 2.10 Split-Brain Prevention

Vecta uses strict quorum enforcement to prevent split-brain:

- A minority partition (fewer than quorum nodes) refuses to accept writes.
- The API returns `503 Service Unavailable` with `{"error": "quorum_unavailable"}` on write operations.
- Reads may still be served from minority partitions if `consistency_mode: eventual`.

**Network partition detection:**

```bash
# Check if current node believes it is in a quorum partition
curl "http://localhost:5173/svc/cluster/quorum" \
  -H "Authorization: Bearer $TOKEN"
# Response: {quorum_met: true|false, node_count: 3, quorum_size: 2, leader_reachable: true}
```

If `quorum_met: false`, investigate network connectivity between nodes immediately. The cluster will remain consistent but unavailable for writes until the partition heals.

---

## 3. QKD — Quantum Key Distribution

### 3.1 Quantum Threat Model

**The classical cryptographic problem:**

RSA, Diffie-Hellman, and Elliptic Curve Cryptography derive their security from computational hardness: specifically, the integer factorization problem (RSA) and the discrete logarithm problem (DH, EC). A sufficiently powerful quantum computer running **Shor's Algorithm** (1994) can solve both problems in polynomial time — breaking the security assumption of all classical public-key cryptography.

Timeline context:
- 2019: Google demonstrated quantum supremacy on a narrow problem (Sycamore, 53 qubits)
- 2022: IBM Eagle processor — 127 qubits
- 2023: IBM Condor — 1,121 qubits
- Breaking RSA-2048 requires approximately 4,000 fault-tolerant logical qubits (each logical qubit needs ~1,000 physical qubits for error correction)
- Current estimates: cryptographically-relevant quantum computers by 2030–2035

**Why act now:**

Even if quantum computers are a decade away, data encrypted today with RSA or EC can be archived and decrypted retroactively. This "Harvest Now, Decrypt Later" (HNDL) attack is already documented as a nation-state threat. Any data with a sensitivity lifetime exceeding 7–10 years requires quantum-secure protection today.

**QKD's position in the defense:**

QKD does not protect against Shor's Algorithm — instead, it solves the key distribution problem with **information-theoretic security**: security that holds even against an adversary with unlimited computational power. QKD uses the laws of quantum physics (specifically, the no-cloning theorem and Heisenberg uncertainty principle) to guarantee that any eavesdropping attempt is physically detectable.

---

### 3.2 QKD Protocols

#### BB84 (Bennett-Brassard 1984)

The original QKD protocol. Protocol mechanics:

1. **Alice** prepares photons in random polarization states from two bases: rectilinear (+) and diagonal (×)
   - Rectilinear: |0⟩ (horizontal) = bit 0, |90⟩ (vertical) = bit 1
   - Diagonal: |45⟩ = bit 0, |135⟩ = bit 1

2. **Alice** sends photons one at a time over a quantum channel (optical fiber)

3. **Bob** measures each photon using a randomly chosen basis (+ or ×)

4. **Sifting:** Alice and Bob compare basis choices over a classical authenticated channel. They keep only measurements where they used the same basis (~50% of photons). This forms the raw key.

5. **Error estimation:** They compare a random subset of the sifted key. The error rate = QBER (Quantum Bit Error Rate). If QBER > ~11%, an eavesdropper likely intercepted photons; abort.

6. **Error correction:** Cascade protocol or LDPC codes reconcile differences from channel noise.

7. **Privacy amplification:** Hash the reconciled key to compress out any information an eavesdropper gained. Result: a shorter, provably secure key.

Security: Information-theoretically secure (ITS) — proven secure against any attack, regardless of adversary's computational power.

**Limitations:** Point-to-point only; distance limited by photon loss (~100 km with repeaters, or via satellite); requires dedicated fiber or free-space optical link.

#### E91 (Ekert 1991)

Uses quantum entanglement instead of direct photon transmission:

1. A source generates entangled photon pairs (EPR pairs)
2. Alice receives one photon of each pair; Bob receives the other
3. Each measures in a randomly chosen basis
4. Bell inequality violation is checked: if no eavesdropper, correlations violate Bell inequality (CHSH form)
5. Eavesdropping destroys entanglement → detectable

Theoretically the most elegant protocol. In practice, entangled photon generation at scale is harder than prepare-and-measure (BB84). Used in research systems and satellite QKD (e.g., Micius satellite).

#### CV-QKD (Continuous Variable)

Instead of discrete polarization states, Alice encodes key bits in the quadrature amplitudes (X and P) of coherent light states (Gaussian modulation).

- Compatible with standard telecom components (homodyne detectors, standard fiber)
- Higher secret key rate per photon at short distances (< 50 km)
- Mature integration with DWDM networks (can multiplex with classical data on same fiber)
- ETSI EN 303 083 standard

#### MDI-QKD (Measurement Device Independent)

Addresses a weakness of BB84: detector side-channel attacks. In MDI-QKD:

- Alice and Bob each send photons to an untrusted relay (Charlie) in the middle
- Charlie performs a Bell state measurement
- Even if Charlie is completely compromised (spy), no information about the key leaks
- Suited for metropolitan QKD networks with untrusted intermediate nodes

---

### 3.3 Integration with Vecta

QKD keys arrive at Vecta as raw symmetric key material. The QKD subsystem:

1. Receives key bytes from the QKD hardware via the ETSI GS QKD 004 REST API
2. Stores keys in the **Secure Key Store (SKS)** — a local encrypted FIFO buffer of pre-shared quantum keys
3. Keys in the SKS are tagged `source: qkd` in all audit events
4. When an application requests a QKD key, it is consumed from the SKS (each key used exactly once for OTP applications)

**QKD key usage in Vecta:**

- **One-Time Pad (OTP):** Consume QKD key bytes directly as pad material — XOR with plaintext for information-theoretically secure encryption
- **Hybrid encryption:** Use QKD key as input to HKDF alongside ML-KEM ciphertext to derive a session key — defense-in-depth
- **Key Agreement:** Two Vecta nodes share a QKD link; both derive the same key for inter-node communication without any classical key exchange

---

### 3.4 Configuring a QKD Link

```bash
# Register a QKD link — ID Quantique Cerberis3 over dark fiber
curl -X POST "http://localhost:5173/svc/qkd/links?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "dc-a-to-dc-b-bb84",
    "vendor": "idq",
    "local_node_id": "vecta-node-dc-a",
    "remote_node_id": "vecta-node-dc-b",
    "remote_endpoint": "https://qkd-kms-dc-b.internal:8080",
    "protocol": "bb84",
    "config": {
      "wavelength_nm": 1550,
      "qber_threshold_percent": 8.0,
      "key_block_size_bytes": 256,
      "sks_max_size_mb": 64,
      "reconciliation_protocol": "cascade",
      "privacy_amplification": "toeplitz",
      "authentication_hash": "sha3-256"
    }
  }'

# Register a Toshiba QKD system (CV-QKD)
curl -X POST "http://localhost:5173/svc/qkd/links?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "metro-ring-cvqkd",
    "vendor": "toshiba",
    "local_node_id": "vecta-node-hq",
    "remote_node_id": "vecta-node-branch",
    "remote_endpoint": "https://qkd-branch.internal:8080",
    "protocol": "cv-qkd",
    "config": {
      "wavelength_nm": 1550,
      "qber_threshold_percent": 5.0,
      "key_block_size_bytes": 128,
      "modulation_variance": 4.0
    }
  }'

# List all QKD links
curl "http://localhost:5173/svc/qkd/links?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Check link health (QBER, key rate, SKS availability)
curl "http://localhost:5173/svc/qkd/links/LINK_ID/health" \
  -H "Authorization: Bearer $TOKEN"
# Response:
# {
#   "link_id": "LINK_ID",
#   "status": "operational",
#   "qber_percent": 3.2,
#   "key_rate_kbps": 18.5,
#   "sks_bytes_available": 524288,
#   "sks_keys_available": 2048,
#   "last_key_generated": "2025-03-22T14:00:01Z",
#   "fiber_loss_db": 4.2,
#   "distance_km": 21.0
# }

# Consume a QKD key from the SKS
curl -X POST "http://localhost:5173/svc/qkd/links/LINK_ID/key?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"length_bytes": 32, "consume": true}'
# Response: {key_id: "uuid", key_b64: "...", consumed_at: "...", sks_remaining_bytes: 524256}

# Retrieve QKD key by ID (for decrypting party to retrieve matching key)
curl "http://localhost:5173/svc/qkd/links/LINK_ID/key/KEY_ID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Update link config (e.g. adjust QBER threshold)
curl -X PATCH "http://localhost:5173/svc/qkd/links/LINK_ID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"config": {"qber_threshold_percent": 7.5}}'

# Delete link
curl -X DELETE "http://localhost:5173/svc/qkd/links/LINK_ID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

---

### 3.5 ETSI QKD 004 Standard

Vecta implements the **ETSI GS QKD 004** key delivery API — the industry standard for QKD-to-application integration. This allows any QKD hardware that exposes a QKD 004 interface to interoperate with Vecta without vendor-specific code.

**Standard endpoints:**

```bash
# Retrieve encryption keys for a Secure Application Entity (SAE)
# SAE_ID: the identifier of the peer application that will decrypt
GET /svc/qkd/api/v1/keys/{SAE_ID}/enc_keys?size=32&number=1
# Response: {"keys": [{"key_ID": "uuid", "key": "base64-key-material"}]}

# Retrieve decryption key by ID (receiving party looks up by key_ID)
GET /svc/qkd/api/v1/keys/{SAE_ID}/dec_keys?key_ID={uuid}
# Response: {"keys": [{"key_ID": "uuid", "key": "base64-key-material"}]}

# Get QKD link status (ETSI format)
GET /svc/qkd/api/v1/keys/{SAE_ID}/status
# Response: {"source_KME_ID": "...", "target_KME_ID": "...", "key_size": 256, "stored_key_count": 2048, "max_key_per_request": 128, "status_extension": {"qber": 3.2}}
```

**SAE registration:**

```bash
# Register a Secure Application Entity
curl -X POST "http://localhost:5173/svc/qkd/sae?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "sae_id": "payment-service-dc-a",
    "peer_sae_id": "payment-service-dc-b",
    "link_id": "LINK_ID",
    "max_key_size_bytes": 256,
    "allowed_operations": ["enc_keys", "dec_keys"]
  }'
```

---

### 3.6 QBER Monitoring

QBER (Quantum Bit Error Rate) is the fraction of sifted key bits that differ between Alice and Bob. It is the primary health indicator for a QKD link.

**QBER interpretation:**

| QBER | Interpretation |
|---|---|
| 0–4% | Excellent — normal channel noise only |
| 4–8% | Acceptable — some additional loss/noise; monitor |
| 8–11% | Warning — possible eavesdropping or degraded hardware |
| > 11% | Critical — abort key generation; possible active attack |

```bash
# Get QBER time series for a link (last 24 hours)
curl "http://localhost:5173/svc/qkd/links/LINK_ID/qber/history?hours=24" \
  -H "Authorization: Bearer $TOKEN"
# Response: {data_points: [{timestamp, qber_percent, key_rate_kbps, sks_bytes}], ...}

# Get QBER alerts
curl "http://localhost:5173/svc/qkd/links/LINK_ID/alerts" \
  -H "Authorization: Bearer $TOKEN"
```

**Automated QBER response:**

Vecta's QKD subsystem automatically:
1. Monitors QBER in real-time
2. If QBER exceeds `qber_threshold_percent`: pauses key generation, generates audit alert `QKD_QBER_EXCEEDED`
3. Falls back to hybrid classical+PQC key exchange for new sessions
4. Notifies operations team via configured alert channels
5. Resumes when QBER drops below threshold and remains stable for 60 seconds

---

### 3.7 Use Cases and Hybrid Scenarios

**Use case 1: Inter-datacenter traffic encryption**

Two datacenters connected by a dark fiber QKD link. All inter-DC traffic is encrypted with AES-256-GCM keys derived from QKD key material via HKDF.

```bash
# Application requests hybrid key (QKD + ML-KEM)
curl -X POST "http://localhost:5173/svc/qkd/hybrid-key?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "link_id": "LINK_ID",
    "classical_kem": "ML-KEM-768",
    "derived_key_length_bytes": 32,
    "context": "inter-dc-session-20250322"
  }'
# Returns a key derived from HKDF(QKD_key || ML-KEM_shared_secret)
# Attacker must break both QKD physical security AND ML-KEM
```

**Use case 2: Government / classified communications**

QKD OTP for messages classified above TOP SECRET where information-theoretic security is mandated:
- Sender consumes QKD key bytes equal to message length
- XOR message with key bytes (OTP)
- Receiver retrieves same key from their QKD SKS by key_ID and XORs to recover plaintext
- Neither encryption nor decryption can be broken by any computational attack

**Use case 3: Financial interbank settlement**

Two banks share a QKD link. Settlement messages are authenticated using HMAC-SHA256 with a QKD-derived HMAC key. Even if a quantum computer breaks classical authentication in the future, the HMAC key was derived from QKD and is information-theoretically secure.

---

## 4. QRNG — Quantum Random Number Generation

### 4.1 Why QRNG

**Randomness quality hierarchy:**

| Source Type | Example | Predictable if... | Use in Vecta |
|---|---|---|---|
| **PRNG** (Pseudo) | Math library `rand()` | Seed known | Never for keys |
| **CSPRNG** (Crypto-secure) | `/dev/urandom`, Go `crypto/rand` | OS entropy is poor | Default |
| **DRBG** (Deterministic RBG) | NIST SP 800-90A HMAC-DRBG | Seed or state compromised | FIPS default |
| **TRNG** (Hardware) | CPU RDRAND (Intel), ring oscillators | Physical side-channel | HSM mode |
| **QRNG** (Quantum) | Photon shot noise, vacuum fluctuations | Impossible (quantum mechanics) | Premium mode |

**Why QRNG matters:**

- PRNG/DRBG: If the seed is ever exposed (VM snapshot, coredump, cold-boot attack), all past and future outputs can be reconstructed.
- Hardware TRNG (RDRAND): Intel's RDRAND uses a hardware noise source, but in 2019, a bug was found that caused repeated outputs. Physical side-channels and hardware supply-chain attacks remain theoretical concerns.
- QRNG: Random bits are generated by measuring quantum-mechanical events (e.g., which path a photon takes at a beam splitter, or the timing of photon arrivals). These events are fundamentally non-deterministic under quantum mechanics — there is no hidden variable that could predict them.

**Regulatory context:**

- NIST SP 800-90B: Validation requirements for entropy sources, including QRNG
- BSI AIS 31 (Germany): P1 and P2 quality classes for physical random number generators
- FIPS 140-3: Hardware TRNG required for Level 3+; QRNG qualifies

---

### 4.2 Supported Hardware

| Vendor | Model | Interface | Entropy Rate | Principal Certifications | Notes |
|---|---|---|---|---|---|
| ID Quantique (IDQ) | Quantis PCIe-75 | PCIe x1 | 75 Mbps | FIPS 140-3, AIS 31 P2 | Photon path detection |
| ID Quantique (IDQ) | Quantis USB-QNG | USB 2.0 | 4 Mbps | CE, FCC | Portable; for low-volume |
| Quside | FMC250 | PCIe (FMC) | 250 Mbps | NIST CAVP | Phase diffusion; highest rate |
| Quside | 800U | USB 3.0 | 200 Mbps | CE, FCC | High-rate USB form factor |
| Cambridge Quantum (Quantinuum) | IronBridge | REST API (cloud) | Scalable | SOC 2 Type II | Cloud QRNG as a Service |
| Randomness.INT | QRNG API | REST | Scalable | — | For testing / backup |
| Intel | RDRAND | CPU instruction | ~500 Mbps | FIPS 140 | Not true QRNG; hardware TRNG |
| ARM | TrustZone TRNG | mmio | Varies | CC EAL4+ | Embedded / edge devices |

**Selecting hardware:**

- **Data center, highest assurance**: Quside FMC250 (250 Mbps) with PCIe slot in Vecta server
- **Moderate throughput, proven certification**: IDQ Quantis PCIe-75 (75 Mbps, FIPS 140-3)
- **Cloud-native (no hardware)**: Cambridge Quantum IronBridge — REST API; no physical device required
- **Testing / CI environments**: Randomness.INT QRNG API (no hardware dependency)

---

### 4.3 Configuring QRNG Sources

```bash
# Register a PCIe QRNG (IDQ Quantis PCIe-75)
curl -X POST "http://localhost:5173/svc/qrng/sources?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "pcie-qrng-primary",
    "vendor": "idq",
    "model": "quantis-pcie-75",
    "interface": "pcie",
    "priority": 1,
    "config": {
      "device_path": "/dev/qrng0",
      "buffer_size_mb": 64,
      "health_check_interval_seconds": 60,
      "min_entropy_rate_mbps": 50
    }
  }'

# Register a cloud QRNG (Cambridge Quantum IronBridge)
curl -X POST "http://localhost:5173/svc/qrng/sources?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "ironbridge-cloud-qrng",
    "vendor": "cambridge_quantum",
    "model": "ironbridge",
    "interface": "rest",
    "priority": 2,
    "config": {
      "api_endpoint": "https://api.ironbridge.io/v1/random",
      "api_key_env": "IRONBRIDGE_API_KEY",
      "cache_size_mb": 10,
      "prefetch_threshold_mb": 2
    }
  }'

# Register a USB QRNG (IDQ Quantis USB)
curl -X POST "http://localhost:5173/svc/qrng/sources?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "usb-qrng-backup",
    "vendor": "idq",
    "model": "quantis-usb",
    "interface": "usb",
    "priority": 3,
    "config": {
      "device_path": "/dev/qrng1",
      "buffer_size_mb": 8
    }
  }'

# List all QRNG sources with current status
curl "http://localhost:5173/svc/qrng/sources?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
# Response: [{source_id, name, vendor, interface, status, entropy_rate_mbps, buffer_fill_percent, priority}]

# Generate 32 bytes from the highest-priority healthy QRNG
curl -X POST "http://localhost:5173/svc/qrng/generate?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"length": 32, "format": "base64"}'

# Generate from a specific source
curl -X POST "http://localhost:5173/svc/qrng/generate?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"length": 32, "source_id": "SOURCE_UUID", "format": "hex"}'

# Check health of a specific source (includes NIST SP 800-22 test results)
curl "http://localhost:5173/svc/qrng/sources/SOURCE_ID/health" \
  -H "Authorization: Bearer $TOKEN"
# Response:
# {
#   "source_id": "...",
#   "status": "healthy",
#   "entropy_rate_mbps": 68.4,
#   "buffer_fill_percent": 87.3,
#   "last_health_check": "2025-03-22T14:00:00Z",
#   "nist_800_22_tests": {
#     "last_run": "2025-03-22T13:00:00Z",
#     "all_passed": true,
#     "results": {
#       "frequency": "pass",
#       "block_frequency": "pass",
#       "runs": "pass",
#       "longest_run": "pass",
#       "dft": "pass",
#       "approximate_entropy": "pass"
#     }
#   }
# }

# Disable a QRNG source (falls back to next priority)
curl -X PATCH "http://localhost:5173/svc/qrng/sources/SOURCE_ID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"enabled": false}'

# Delete a QRNG source
curl -X DELETE "http://localhost:5173/svc/qrng/sources/SOURCE_ID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

---

### 4.4 NIST SP 800-22 Health Tests

Vecta runs the full NIST SP 800-22 statistical test battery continuously against each QRNG source. Tests run every `health_check_interval_seconds` using a fresh sample of at least 1,000,000 bits.

**Complete test list:**

| # | Test | What it Detects |
|---|---|---|
| 1 | **Frequency (Monobit) Test** | Proportion of 1s vs 0s. Should be ~50%. Detects biased sources. |
| 2 | **Frequency Test within a Block** | Frequency of 1s within 128-bit blocks. Detects block-level bias. |
| 3 | **Runs Test** | Total number of runs (consecutive identical bits). Detects oscillating or stuck patterns. |
| 4 | **Test for the Longest Run of Ones in a Block** | Longest run of 1s within each 8-bit block. Detects non-random clustering. |
| 5 | **Binary Matrix Rank Test** | Linear independence of fixed-length substrings. Detects linear dependencies. |
| 6 | **Discrete Fourier Transform (Spectral) Test** | Periodic features in the sequence. Detects cyclical patterns. |
| 7 | **Non-overlapping Template Matching Test** | Frequency of a specific non-periodic pattern. Tests for specific pattern avoidance. |
| 8 | **Overlapping Template Matching Test** | Frequency of a specific overlapping pattern. Detects pattern repetition. |
| 9 | **Maurer's "Universal Statistical" Test** | Compressibility of the sequence. Detects structured (compressible) output. |
| 10 | **Linear Complexity Test** | Length of the Linear Feedback Shift Register that generates the sequence. Detects LFSR-like behavior. |
| 11 | **Serial Test** | Frequency of all 2-bit and 3-bit overlapping patterns. Detects pattern imbalance. |
| 12 | **Approximate Entropy Test** | Frequency of all overlapping m-bit patterns (m=10). Similar to serial test, different sensitivity. |
| 13 | **Cumulative Sums (Cusum) Test** | Maximum deviation of partial sums. Detects bias at the start or end of sequences. |
| 14 | **Random Excursions Test** | Number of cycles with a specific number of visits to a state. Detects non-random walk behavior. |
| 15 | **Random Excursions Variant Test** | Total number of times a particular state is visited. Complement to test 14. |

**Failure response cascade:**

```
QRNG Health Test Failure
        │
        ▼
Quarantine QRNG source (stop generating from it)
        │
        ▼
Generate audit alert: QRNG_HEALTH_FAILURE (source_id, test_name, p_value)
        │
        ▼
Promote next-priority QRNG source to primary
        │
        ▼ (if no QRNG available)
Fall back to NIST SP 800-90A HMAC-DRBG seeded from OS entropy
        │
        ▼
Generate alert: QRNG_FALLBACK_ACTIVE
        │
        ▼ (QRNG source recovers — passes 3 consecutive test runs)
Promote QRNG back to active
        │
        ▼
Generate audit event: QRNG_RESTORED
```

**Manual quarantine and release:**

```bash
# Manually quarantine a source
curl -X POST "http://localhost:5173/svc/qrng/sources/SOURCE_ID/quarantine?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"reason": "vendor-reported-firmware-bug"}'

# Release from quarantine
curl -X POST "http://localhost:5173/svc/qrng/sources/SOURCE_ID/release?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

---

### 4.5 Entropy Pooling and Fallback

Vecta maintains an entropy pool that combines randomness from multiple sources:

**Priority order:**
1. QRNG hardware (if configured and healthy)
2. HSM TRNG (if HSM configured and session active)
3. CPU TRNG (RDRAND on Intel / AMD, if available)
4. OS entropy (`/dev/urandom` on Linux, `CryptGenRandom` on Windows)
5. NIST SP 800-90A HMAC-DRBG (deterministic, reseeded from above)

Multiple sources are XOR-combined after whitening. This means:
- Adding a QRNG improves security even if not perfectly trusted — XOR with OS entropy never decreases entropy
- If QRNG fails, security falls back to OS entropy (not zero)

```bash
# Check current entropy pool status
curl "http://localhost:5173/svc/qrng/pool?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
# Response:
# {
#   "active_sources": ["qrng:pcie-qrng-primary", "trng:rdrand"],
#   "fallback_active": false,
#   "pool_entropy_bits": 512,
#   "reseed_count": 18432,
#   "last_reseed": "2025-03-22T14:00:01Z",
#   "entropy_rate_mbps": 68.4
# }
```

---

### 4.6 Integration with Key Generation

When QRNG is configured, all key generation operations use QRNG-sourced entropy:

```bash
# Generate a cryptographically random value using QRNG
curl -X POST "http://localhost:5173/svc/keycore/crypto/random?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"length": 32, "source": "qrng", "format": "base64"}'

# Generate an AES-256 key seeded from QRNG (key material derived inside HSM using QRNG entropy)
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "qrng-seeded-aes-key",
    "algorithm": "AES-256",
    "purpose": "encrypt",
    "entropy_source": "qrng",
    "key_backend": "hsm"
  }'

# Generate an EC key pair using QRNG entropy (key gen in HSM using QRNG as seed input)
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "qrng-ec-signing-key",
    "algorithm": "EC-P384",
    "purpose": "sign",
    "entropy_source": "qrng",
    "key_backend": "hsm"
  }'
```

The audit trail records the entropy source used for each key generation event, providing a full custody chain: `entropy_source: qrng, qrng_source_id: SOURCE_UUID, qrng_health_at_generation: healthy`.

---

## 5. MPC / FROST Threshold Signing

### 5.1 Threshold Cryptography Concepts

**The single-key problem:**

A single private key represents a single point of compromise. If the device holding the key is stolen, hacked, or physically coerced, the attacker gains unlimited signing capability. Even with HSM protection, a single HSM can be physically stolen (particularly in edge deployments) or the HSM operator can be coerced.

**Secret Sharing vs. Threshold Signing:**

**Shamir's Secret Sharing (SSS)** solves key storage: split the key into N shares, any k shares can reconstruct the key. But to sign, the shares must be recombined — creating a moment when the full key exists in memory, at a single machine, defeating the distribution guarantee.

**Threshold Signing (MPC)** solves this definitively: parties each hold a **key share** that is cryptographically bound such that:
1. No individual share reveals anything about the private key
2. k-of-N parties can collaboratively produce a valid signature using only their shares — the private key is **never reconstructed**
3. Compromising k-1 parties yields the attacker nothing

This is the fundamental security property that makes threshold signing superior to even HSM-backed single keys for highest-assurance applications.

---

### 5.2 FROST Protocol (Flexible Round-Optimized Schnorr Threshold)

**Reference:** RFC 9591 (IETF CFRG FROST)

**Algorithm:** Threshold Schnorr signatures (Ed25519, Ristretto255, secp256k1)

**Key properties:**

- **Optimal round complexity:** Only 2 online rounds regardless of threshold size (k-of-N with any k, N)
- **Non-interactive pre-processing:** Round 1 (nonce commitments) can be computed offline and batched before signing requests arrive
- **Identifiable abort:** If a party misbehaves, they can be identified and excluded
- **Compatible with Ed25519:** Produces standard Ed25519-compatible signatures; verifier cannot distinguish from single-party signing
- **Security model:** Proven secure in the Random Oracle Model (ROM) under the Schnorr discrete logarithm assumption

**Protocol detail:**

*Setup phase (Distributed Key Generation — DKG):*

Each party i generates a secret polynomial fᵢ(x) of degree k-1, where fᵢ(0) = aᵢ (their secret contribution). They broadcast commitments {Cᵢⱼ = aᵢⱼ·G} and send shares fᵢ(j) to each party j. Each party's final share is sᵢ = Σ fⱼ(i). The group public key is Y = Σ fⱼ(0)·G.

*Round 1 (Commitment):*

Each signing participant i:
- Samples two random nonces: dᵢ (hiding) and eᵢ (binding)
- Broadcasts commitments: Dᵢ = dᵢ·G, Eᵢ = eᵢ·G

*Round 2 (Signature):*

Each participant receives all commitments {Dⱼ, Eⱼ} for j in the signing set S:
- Computes binding factor ρᵢ = H(i, m, {Dⱼ,Eⱼ})
- Computes group commitment R = Σ (Dⱼ + ρⱼ·Eⱼ)
- Computes challenge c = H(R, Y, m)
- Computes partial signature zᵢ = dᵢ + eᵢ·ρᵢ + λᵢ·sᵢ·c (where λᵢ = Lagrange coefficient)
- Broadcasts zᵢ

*Aggregation:*

Signature aggregator computes z = Σ zᵢ and outputs σ = (R, z). This is a valid Schnorr signature verifiable with standard Ed25519 verification.

---

### 5.3 ECDSA-MPC Protocols

For applications requiring ECDSA (Bitcoin secp256k1, Ethereum, NIST P-256), Vecta supports three ECDSA-MPC protocols:

**GG18 (Gennaro-Goldfeder 2018):**
- First practical threshold ECDSA without trusted dealer
- 6 rounds online, Paillier encryption for zero-knowledge proofs
- Historical reference; superseded by GG20

**GG20 (Gennaro-Goldfeder 2020):**
- Reduced to 3 rounds online (2 preprocessing + 1 signing)
- More efficient ZK proofs using Feldman VSS
- Widely deployed in production (Fireblocks, ZenGo, etc.)
- Security: proven in the UC (Universal Composability) framework

**CGGMP21 (Canetti, Gennaro, Goldfeder, Makriyannis, Peled 2021):**
- State-of-the-art: 3 rounds online, 1 round offline presigning
- Provably secure under adaptive corruptions
- Reduced communication: uses ring Pedersen commitments
- Identifiable abort: faulty party can be identified
- Recommended for new deployments

**Algorithm support by protocol:**

| Protocol | secp256k1 (ETH/BTC) | P-256 | P-384 | Ed25519 |
|---|---|---|---|---|
| GG18 | Yes | Yes | No | No |
| GG20 | Yes | Yes | Limited | No |
| CGGMP21 | Yes | Yes | Yes | No |
| FROST | No | No | No | Yes |

---

### 5.4 BLS Threshold Signatures

**Curve:** BLS12-381 (used by Ethereum 2.0 consensus, Chia, Filecoin, Algorand)

**Key properties:**
- **Signature aggregation:** N individual BLS signatures can be combined into a single short signature (~96 bytes). A verifier checks one aggregated signature instead of N individual ones.
- **Non-interactive threshold:** Once key shares are distributed, partial signatures from k parties can be combined by any aggregator without interaction between signers. No protocol rounds required.
- **Batch verification:** Thousands of aggregated BLS signatures can be verified together with minimal marginal cost.

**Use cases:**
- Ethereum validator signing: validator key split among multiple servers; threshold signing prevents single-server compromise from causing slashing
- Consensus protocols: committee members each produce partial signatures; aggregated signature represents committee decision
- dVRF (distributed Verifiable Random Function): threshold BLS signatures on input produce unpredictable, verifiable random output

```bash
# Create a BLS threshold group (3-of-5)
curl -X POST "http://localhost:5173/svc/mpc/groups?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "eth-validator-committee",
    "algorithm": "BLS-BLS12-381",
    "threshold": 3,
    "total_parties": 5
  }'

# BLS partial signature
curl -X POST "http://localhost:5173/svc/mpc/sign?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "group_id": "GROUP_ID",
    "message_hash": "sha256:abc123",
    "algorithm": "BLS-BLS12-381"
  }'
```

---

### 5.5 Setting Up an MPC Group

```bash
# Create a FROST-Ed25519 group (3-of-5)
curl -X POST "http://localhost:5173/svc/mpc/groups?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "payment-signing-committee",
    "algorithm": "FROST-Ed25519",
    "threshold": 3,
    "total_parties": 5,
    "party_endpoints": [
      "https://party1.internal:9000",
      "https://party2.internal:9000",
      "https://party3.internal:9000",
      "https://party4.internal:9000",
      "https://party5.internal:9000"
    ],
    "party_hsm_backed": true,
    "metadata": {
      "description": "Payment authorization committee — 3-of-5 required",
      "contact": "security@acme.com"
    }
  }'
# Response: {group_id: "GROUP_UUID", status: "pending_keygen", created_at: "..."}

# Create a CGGMP21 ECDSA group (2-of-3, secp256k1 for Ethereum)
curl -X POST "http://localhost:5173/svc/mpc/groups?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "eth-custody-multisig",
    "algorithm": "CGGMP21-secp256k1",
    "threshold": 2,
    "total_parties": 3,
    "party_endpoints": [
      "https://custody1.internal:9000",
      "https://custody2.internal:9000",
      "https://custody3.internal:9000"
    ]
  }'

# List all MPC groups
curl "http://localhost:5173/svc/mpc/groups?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get group details
curl "http://localhost:5173/svc/mpc/groups/GROUP_ID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
# Response: {group_id, name, algorithm, threshold, total_parties, status, public_key_b64, parties: [...]}

# Delete MPC group (destroys all shares — irreversible)
curl -X DELETE "http://localhost:5173/svc/mpc/groups/GROUP_ID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

---

### 5.6 Distributed Key Generation Ceremony

The DKG ceremony is the most security-critical step — all party representatives must be identity-verified before participating.

```bash
# Initiate DKG ceremony for the group
curl -X POST "http://localhost:5173/svc/mpc/groups/GROUP_ID/keygen?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ceremony_label": "initial-keygen-2025-03-22",
    "timeout_minutes": 30,
    "require_all_parties": true
  }'
# Response: {ceremony_id: "CEREMONY_UUID", round: 1, awaiting_parties: ["party1", "party2", ...]}

# Party 1 submits Round 1 commitment (nonce commitments + VSS commitments)
curl -X POST "http://localhost:5173/svc/mpc/ceremonies/CEREMONY_ID/round?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "party_id": "party1",
    "round": 1,
    "round_data": "base64-encoded-round1-data"
  }'

# Repeat for all 5 parties in Round 1...

# Once all parties submit Round 1, proceed to Round 2 (share distribution)
# Party 1 submits Round 2 data (encrypted shares for each other party)
curl -X POST "http://localhost:5173/svc/mpc/ceremonies/CEREMONY_ID/round?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "party_id": "party1",
    "round": 2,
    "round_data": "base64-encoded-round2-data"
  }'

# Check ceremony status
curl "http://localhost:5173/svc/mpc/ceremonies/CEREMONY_ID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
# Response:
# {
#   "ceremony_id": "CEREMONY_UUID",
#   "group_id": "GROUP_UUID",
#   "status": "in_progress",
#   "current_round": 2,
#   "submitted_parties": ["party1", "party3"],
#   "awaiting_parties": ["party2", "party4", "party5"],
#   "started_at": "2025-03-22T14:00:00Z",
#   "timeout_at": "2025-03-22T14:30:00Z"
# }

# After all rounds complete, ceremony finishes and group public key is available
curl "http://localhost:5173/svc/mpc/ceremonies/CEREMONY_ID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
# Response: {status: "complete", group_public_key_b64: "...", completed_at: "..."}

# List all ceremonies (for audit)
curl "http://localhost:5173/svc/mpc/ceremonies?tenant_id=root&group_id=GROUP_ID" \
  -H "Authorization: Bearer $TOKEN"
```

**DKG security requirements:**

1. All party representatives must authenticate to Vecta with MFA before the ceremony
2. Party endpoints must communicate over mTLS
3. Out-of-band verification: each party verifies the group public key hash over a separate channel (phone, secure channel) to detect MitM attacks during the ceremony
4. Audit log of the ceremony is written to the immutable audit trail
5. At least one offline backup of each party's share should be created immediately after DKG

---

### 5.7 Threshold Signing

```bash
# Initiate a signing request (requires 3-of-5 approvals)
curl -X POST "http://localhost:5173/svc/mpc/sign?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "group_id": "GROUP_UUID",
    "message_b64": "base64-encoded-message-to-sign",
    "message_hash_algorithm": "SHA-256",
    "algorithm": "FROST-Ed25519",
    "metadata": {
      "purpose": "payment-authorization",
      "amount_usd": 1000000,
      "requestor": "treasury-system"
    }
  }'
# Response: {sign_request_id: "SIGN_UUID", status: "awaiting_approval", approvals_needed: 3, approvals_received: 0}

# Party 2 approves and contributes partial signature (Round 1)
curl -X POST "http://localhost:5173/svc/mpc/sign/SIGN_UUID/approve?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "party_id": "party2",
    "approval": true,
    "round": 1,
    "round_data": "base64-nonce-commitment"
  }'

# Parties submit Round 2 data after receiving all Round 1 commitments
curl -X POST "http://localhost:5173/svc/mpc/sign/SIGN_UUID/approve?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "party_id": "party2",
    "round": 2,
    "round_data": "base64-partial-signature"
  }'

# Check signing request status
curl "http://localhost:5173/svc/mpc/sign/SIGN_UUID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
# Response:
# {
#   "sign_request_id": "SIGN_UUID",
#   "status": "complete",
#   "signature_b64": "base64-final-signature",
#   "signers": ["party2", "party3", "party5"],
#   "algorithm": "FROST-Ed25519",
#   "message_hash": "sha256:...",
#   "completed_at": "2025-03-22T14:05:23Z"
# }

# Reject a signing request (any party can veto)
curl -X POST "http://localhost:5173/svc/mpc/sign/SIGN_UUID/reject?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"party_id": "party4", "reason": "amount-exceeds-daily-limit"}'

# List all pending signing requests
curl "http://localhost:5173/svc/mpc/sign?tenant_id=root&status=awaiting_approval" \
  -H "Authorization: Bearer $TOKEN"

# Verify a produced signature
curl -X POST "http://localhost:5173/svc/mpc/verify?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "group_id": "GROUP_UUID",
    "message_b64": "base64-original-message",
    "signature_b64": "base64-signature",
    "algorithm": "FROST-Ed25519"
  }'
# Response: {valid: true, public_key_b64: "...", verified_at: "..."}
```

---

### 5.8 Share Refresh and Proactive Security

**Proactive secret sharing** periodically refreshes all key shares without changing the group public key. This bounds the attacker's time window: even if they compromise k-1 shares over time, the shares become invalid after each refresh cycle, making accumulated compromises useless.

```bash
# Initiate a share refresh ceremony
# All N parties must participate; at the end, old shares are invalid
curl -X POST "http://localhost:5173/svc/mpc/groups/GROUP_ID/refresh?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "ceremony_label": "quarterly-share-refresh-Q1-2025",
    "timeout_minutes": 60
  }'
# Response: {ceremony_id: "REFRESH_CEREMONY_UUID", type: "share_refresh"}

# Parties participate identically to DKG — submit round data for each round
curl -X POST "http://localhost:5173/svc/mpc/ceremonies/REFRESH_CEREMONY_UUID/round?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"party_id": "party1", "round": 1, "round_data": "..."}'

# After completion, old shares cryptographically invalidated
# Group public key unchanged — no need to update certificate or addresses
```

**Recommended refresh schedule:**

| Risk Level | Refresh Interval |
|---|---|
| Low | Annual |
| Medium | Quarterly |
| High | Monthly |
| Critical (key custody, root CA) | Weekly |

---

### 5.9 Use Cases

**Cryptocurrency Exchange Cold Wallet Custody:**

3-of-5 CGGMP21 threshold signing for secp256k1 (Ethereum/Bitcoin). Each of the 5 share holders is in a different jurisdiction. Withdrawal signing requires approval from 3 share holders. No single compromise, no single legal jurisdiction can unilaterally move funds.

**Root CA Key Ceremony:**

HSM-backed FROST-Ed25519 group. 5 parties represent: CISO, CTO, Legal, Compliance, External Auditor. Any 3 can sign. Root CA private key never exists anywhere — only the 5 distributed shares exist. DKG ceremony is recorded on video and signed in the audit log.

**High-Value Payment Authorization:**

FROST group for treasury payments above $500,000. Payment system creates a signing request; CFO and two VP-level approvers contribute partial signatures. Finance team cannot unilaterally move large amounts.

**Geographically Distributed HSM Key:**

5 parties, each backed by an HSM in a different region (US-East, EU-West, APAC, US-West, EU-North). 3-of-5 threshold. No single data center, no single country holds a complete key. Key ceremony conducted with in-person participants in each region.

**DAO On-Chain Governance:**

Token holders vote; the top k vote-holders constitute the signing committee. Governance decisions require threshold signatures from committee members, published on-chain as verifiable BLS aggregated signatures.

---

## 6. Security Considerations

### HSM Security

- **Always use non-exportable keys for root KEKs**: Set `export_allowed: false` on all HSM-backed KEKs. Non-exportable keys with `CKA_EXTRACTABLE=false` cannot be exported even by the HSM administrator.
- **Enable FIPS mode in HSM partition settings**: Separate from Vecta's FIPS mode; must be configured on the HSM itself. Luna: set `fips_mode=1` in partition policy. CloudHSM: enable FIPS mode via cluster configuration.
- **PIN rotation**: Rotate HSM PINs on a schedule and always after personnel changes (any role with PIN knowledge).
- **NTL certificate rotation**: Rotate Luna NTL certificates annually. Compromise of NTL client certificate allows establishing sessions but not extracting non-exportable keys.
- **Audit HSM event logs**: Collect HSM-native event logs (Luna Audit Logging, CloudHSM CloudTrail) alongside Vecta audit logs. Discrepancies indicate potential tampering.
- **Zeroization policy**: Document and test the zeroization procedure. Know what triggers automatic zeroization and what the recovery procedure is.

### Cluster Security

- **Minimum 3 nodes for any production deployment**: 1 or 2 nodes offer no HA — a single node failure causes complete unavailability.
- **Take backups before topology changes**: Adding, removing, or changing roles on nodes can cause quorum instability. Always back up before these operations.
- **mTLS enforcement**: Vecta enforces mTLS for all inter-node connections. Do not disable certificate verification in any configuration.
- **Node certificate expiry**: Monitor cluster certificate expiry. Expired node certificates cause inter-node connection failures and cluster unavailability. Default validity: 1 year; rotate at 90 days before expiry.
- **Network segmentation**: Cluster replication ports (5174, 5175) should not be accessible from outside the cluster network. Use a dedicated cluster VLAN.

### QKD Security

- **QBER threshold is your first line of defense**: If QBER rises above your threshold, assume an eavesdropper until proven otherwise. Do not raise the threshold to mask the problem.
- **Physical fiber security**: QKD protects the key distribution, but a physical attacker with access to the fiber can still disrupt (DoS) the QKD link by inducing loss. Physical fiber security (conduits, monitoring) is still required.
- **Classical channel authentication**: The classical channel (where Alice and Bob exchange basis choices) must be authenticated with an information-theoretically secure MAC (using pre-shared key) to prevent MitM attacks during basis sifting. Vecta uses HMAC-SHA256 with a bootstrapped pre-shared key.
- **SKS security**: The Secure Key Store buffer is encrypted at rest with an HSM-backed KEK. Compromise of the Vecta server does not expose the SKS plaintext.
- **Hybrid with PQC**: Always combine QKD keys with ML-KEM or another PQC mechanism in hybrid mode. This provides defense-in-depth: attacker must simultaneously compromise the quantum channel AND break the PQC algorithm.

### QRNG Security

- **Never silence health test failures**: Health test failures on a QRNG source indicate either hardware malfunction or a physical attack on the entropy source. Always investigate.
- **Multiple QRNG sources**: Configure at least one backup QRNG source so that if the primary fails health checks, a fallback is available without degrading to software entropy.
- **Monitor entropy rate**: A sudden drop in entropy rate from a PCIe QRNG may indicate hardware failure or a physical interference attack. Alert on rate drops > 20%.
- **Supply chain**: Verify QRNG hardware integrity on delivery (check vendor signatures and certificates). Some attacks are introduced during shipping.

### MPC / FROST Security

- **Store party shares in separate HSMs**: Each party's share should be stored in an HSM, not in software. An attacker who compromises the Vecta server database should not be able to extract shares.
- **Geographically separate parties**: Physical separation of party nodes prevents a single attacker from compromising enough parties for signing quorum.
- **Identity-verify DKG participants**: The DKG ceremony is the most critical security event. Verify all participants in person or via strong identity proofing before the ceremony begins.
- **Audit all ceremony events**: DKG and share refresh ceremonies generate detailed audit events. Review these logs after every ceremony.
- **Proactive refresh schedule**: Implement proactive share refresh (§5.8) on a schedule proportional to the risk level. This limits the window for a slow, persistent attacker who may be gradually compromising shares.
- **Veto rights**: Ensure all parties understand their right and responsibility to reject signing requests. A party that suspects fraud or a process violation should reject the signing request and escalate.
- **Signing request approval policy**: Layer MPC signing approvals with business process controls (ticket number, approval from business owner) via Key Access Justifications.

---

## 7. Full API Reference

### 7.1 HSM API

| Method | Path | Description |
|---|---|---|
| `PUT` | `/svc/auth/auth/cli/hsm/config` | Create or update HSM configuration |
| `GET` | `/svc/auth/auth/cli/hsm/config` | Get current HSM configuration |
| `PATCH` | `/svc/auth/auth/cli/hsm/config` | Partially update HSM config (e.g. enable/disable) |
| `DELETE` | `/svc/auth/auth/cli/hsm/config` | Remove HSM configuration |
| `GET` | `/svc/auth/auth/cli/hsm/partitions` | List PKCS#11 slots and tokens |
| `GET` | `/svc/auth/auth/cli/hsm/health` | HSM health status |
| `POST` | `/svc/auth/auth/cli/hsm/diagnostics` | Run HSM diagnostics |

### 7.2 Cluster API

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/cluster/join-bundle` | Generate a join bundle for a new node |
| `POST` | `/svc/cluster/join` | Submit join request (called on the joining node) |
| `GET` | `/svc/cluster/nodes` | List all cluster nodes and their status |
| `DELETE` | `/svc/cluster/nodes/{node_id}` | Remove a node from the cluster |
| `POST` | `/svc/cluster/nodes/{node_id}/role` | Change node role |
| `POST` | `/svc/cluster/nodes/{node_id}/drain` | Drain in-flight requests before maintenance |
| `GET` | `/svc/cluster/health` | Cluster health summary |
| `GET` | `/svc/cluster/quorum` | Check quorum status |
| `GET` | `/svc/cluster/sync/lag` | Replication lag per node |
| `GET` | `/svc/cluster/sync/events` | Sync event log |
| `POST` | `/svc/cluster/profiles` | Create replication profile |
| `GET` | `/svc/cluster/profiles` | List replication profiles |
| `DELETE` | `/svc/cluster/profiles/{profile_id}` | Delete replication profile |

### 7.3 QKD API

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/qkd/links` | Register a QKD link |
| `GET` | `/svc/qkd/links` | List all QKD links |
| `GET` | `/svc/qkd/links/{link_id}` | Get link details |
| `PATCH` | `/svc/qkd/links/{link_id}` | Update link configuration |
| `DELETE` | `/svc/qkd/links/{link_id}` | Remove link |
| `GET` | `/svc/qkd/links/{link_id}/health` | Link health (QBER, key rate, SKS) |
| `GET` | `/svc/qkd/links/{link_id}/qber/history` | QBER time series |
| `GET` | `/svc/qkd/links/{link_id}/alerts` | Link alerts |
| `POST` | `/svc/qkd/links/{link_id}/key` | Consume a key from SKS |
| `GET` | `/svc/qkd/links/{link_id}/key/{key_id}` | Retrieve specific QKD key by ID |
| `POST` | `/svc/qkd/hybrid-key` | Generate hybrid QKD+PQC key |
| `POST` | `/svc/qkd/sae` | Register a Secure Application Entity |
| `GET` | `/svc/qkd/api/v1/keys/{sae_id}/enc_keys` | ETSI QKD 004: retrieve encryption keys |
| `GET` | `/svc/qkd/api/v1/keys/{sae_id}/dec_keys` | ETSI QKD 004: retrieve decryption keys by ID |
| `GET` | `/svc/qkd/api/v1/keys/{sae_id}/status` | ETSI QKD 004: link status |

### 7.4 QRNG API

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/qrng/sources` | Register a QRNG source |
| `GET` | `/svc/qrng/sources` | List all QRNG sources |
| `GET` | `/svc/qrng/sources/{source_id}` | Get source details |
| `PATCH` | `/svc/qrng/sources/{source_id}` | Update source config |
| `DELETE` | `/svc/qrng/sources/{source_id}` | Remove source |
| `GET` | `/svc/qrng/sources/{source_id}/health` | Source health and NIST test results |
| `POST` | `/svc/qrng/sources/{source_id}/quarantine` | Manually quarantine source |
| `POST` | `/svc/qrng/sources/{source_id}/release` | Release source from quarantine |
| `POST` | `/svc/qrng/generate` | Generate random bytes from QRNG |
| `GET` | `/svc/qrng/pool` | Entropy pool status |
| `POST` | `/svc/keycore/crypto/random` | Generate random bytes (with source selection) |

### 7.5 MPC / FROST API

| Method | Path | Description |
|---|---|---|
| `POST` | `/svc/mpc/groups` | Create MPC group |
| `GET` | `/svc/mpc/groups` | List all MPC groups |
| `GET` | `/svc/mpc/groups/{group_id}` | Get group details |
| `DELETE` | `/svc/mpc/groups/{group_id}` | Delete group (destroys shares) |
| `POST` | `/svc/mpc/groups/{group_id}/keygen` | Initiate DKG ceremony |
| `POST` | `/svc/mpc/groups/{group_id}/refresh` | Initiate share refresh ceremony |
| `GET` | `/svc/mpc/ceremonies` | List ceremonies |
| `GET` | `/svc/mpc/ceremonies/{ceremony_id}` | Get ceremony status |
| `POST` | `/svc/mpc/ceremonies/{ceremony_id}/round` | Submit round data |
| `POST` | `/svc/mpc/sign` | Initiate signing request |
| `GET` | `/svc/mpc/sign` | List signing requests |
| `GET` | `/svc/mpc/sign/{request_id}` | Get signing request status |
| `POST` | `/svc/mpc/sign/{request_id}/approve` | Approve and submit partial signature |
| `POST` | `/svc/mpc/sign/{request_id}/reject` | Reject signing request |
| `POST` | `/svc/mpc/verify` | Verify a threshold signature |

---

*Last updated: 2026-03-22. For support, contact the Vecta platform team or open a ticket in the internal issue tracker.*
