# Vecta KMS — Getting Started

> **Version:** Beta — Last updated 2026-03-22
> **Audience:** Operators, Platform Engineers, Security Engineers, Application Developers

---

## Table of Contents

1. [What Is Vecta KMS](#1-what-is-vecta-kms)
2. [Architecture Overview](#2-architecture-overview)
3. [Security Model](#3-security-model)
4. [Installation](#4-installation)
5. [First Login](#5-first-login)
6. [Creating Your First Tenant](#6-creating-your-first-tenant)
7. [Creating Your First Key](#7-creating-your-first-key)
8. [Encrypting Data](#8-encrypting-data)
9. [Feature Decision Tree](#9-feature-decision-tree)
10. [Dashboard Tour](#10-dashboard-tour)
11. [Next Steps](#11-next-steps)

---

## 1. What Is Vecta KMS

Vecta KMS is an **enterprise-grade, multi-tenant key management platform** built on a microservices architecture. It provides a unified control plane for all cryptographic material and operations across an organization's entire technology stack — from containerized cloud-native workloads to air-gapped on-premises HSMs.

### 1.1 Core Value Proposition

Unlike bolt-on secrets managers, Vecta KMS is purpose-built for **cryptographic key management at scale**. Every design decision — from the tamper-evident audit chain to the SPIFFE workload identity integration — is made with key security as the primary objective.

| Capability | Vecta KMS | HashiCorp Vault | AWS KMS | Azure Key Vault | Thales CipherTrust |
|---|---|---|---|---|---|
| Multi-tenant native | Yes (full data isolation) | Namespace-based | Account-based | Vault-based | Domain-based |
| Post-quantum algorithms | Yes (ML-KEM, ML-DSA, SLH-DSA) | No | No | No | Limited |
| KMIP server built-in | Yes | Plugin only | No | No | Yes |
| MPC / FROST signing | Yes | No | No | No | No |
| Governance / N-of-M approvals | Yes | Enterprise only | No | No | Yes |
| QKD / QRNG integration | Yes | No | No | No | No |
| FIPS 140-3 mode | Yes | Enterprise only | Yes | Yes | Yes |
| Workload identity (SPIFFE) | Yes (native) | Yes | Limited | Limited | No |
| Confidential compute (TEE) | Yes | No | No | Limited | No |
| Tokenization / FPE | Yes (built-in) | Plugin | No | No | Yes |
| Payment crypto (TR-31) | Yes | No | No | No | Yes |
| EKM (database TDE) | Yes | No | Yes | Yes | Yes |
| Open-source core | Yes | Yes (CE) | No | No | No |

### 1.2 Microservices Map

Vecta KMS is composed of the following services, each independently deployable and scalable:

| Service | Internal Name | Primary Responsibility |
|---|---|---|
| Key Core | `keycore` | Central key store: CRUD, lifecycle management, all crypto operations |
| Authentication | `auth` | Token issuance, JWT validation, tenant header verification |
| Certificates & PKI | `certs` | X.509 certificate issuance, CRL, OCSP, CA hierarchy |
| Audit | `audit` | Tamper-evident audit log, hash chain, export |
| Governance | `governance` | N-of-M approval workflows, policy enforcement |
| Reporting | `reporting` | Usage reports, key inventory, compliance dashboards |
| Compliance | `compliance` | Policy frameworks (FIPS, PCI-DSS, HIPAA, SOC2, ISO27001) |
| Posture | `posture` | Continuous security posture assessment, drift detection |
| Workload Identity | `workload` | SPIFFE/SVID issuance, workload attestation, OIDC federation |
| Confidential Compute | `confidential` | TEE attestation, enclave key sealing |
| Post-Quantum Crypto | `pqc` | ML-KEM, ML-DSA, SLH-DSA operations |
| Data Protection | `dataprotect` | Tokenization, FPE (format-preserving encryption), masking |
| Payment Crypto | `payment` | TR-31 key blocks, PCI-DSS key management |
| Autokey | `autokey` | Self-service key provisioning with governance templates |
| Cloud KMS Proxy | `cloud` | BYOK/HYOK for AWS, Azure, GCP |
| External Key Manager | `ekm` | Database TDE proxy (PostgreSQL, MySQL, Oracle, SQL Server) |
| KMIP Server | `kmip` | KMIP 1.x/2.x protocol server for storage appliances |
| Signing Service | `signing` | Code signing, artifact signing, transparency log |
| MPC / Threshold | `mpc` | Multi-party computation, FROST threshold signatures |
| Cluster Manager | `cluster` | Node membership, replication, split-brain prevention |
| QKD Gateway | `qkd` | Quantum key distribution integration (ETSI QKD API) |
| QRNG Service | `qrng` | Quantum random number generator integration |

### 1.3 Deployment Models

Vecta KMS supports five deployment topologies, selectable at install time:

**Single-Node (Development / Lab)**
A single host runs all services. No replication. Suitable for evaluation and local development. Not recommended for production data.

**Clustered HA (Production Standard)**
Three or more nodes with Raft consensus for keycore and audit. Automatic leader election, automatic failover under 30 seconds. Load balancer sits in front; sessions are stateless (JWT-based).

**Geo-Distributed (Multi-Region)**
Cluster nodes spread across geographic regions with tunable consistency: strong (linearizable, higher latency) or eventual (lower latency, bounded staleness). Write forwarding to primary region; reads from local replica.

**HSM-Backed (High Assurance)**
Key material never enters software memory. All key generation, wrapping, and cryptographic operations performed inside an HSM. Supported HSM models: Thales Luna 7, Entrust nShield 5c, Utimaco SecurityServer, Securosys Primus X, AWS CloudHSM, Azure Managed HSM.

**Air-Gapped**
No outbound internet connectivity. All updates delivered via signed update bundles loaded via removable media or unidirectional data diode. Suitable for classified environments, critical infrastructure, and highly regulated industries.

---

## 2. Architecture Overview

### 2.1 Service Interaction Map

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          External Clients                                │
│   Browser   CLI   SDK   CI/CD   Storage Appliance   Database   Cloud     │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │ HTTPS / mTLS / KMIP / gRPC
                             ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                       Ingress / TLS Termination                          │
│            (nginx / Envoy / cloud load balancer)                         │
└────────┬────────────────────────────────────────────────────────┬────────┘
         │                                                        │
         ▼                                                        ▼
┌─────────────────┐                                    ┌──────────────────┐
│   Dashboard     │                                    │   KMIP Listener  │
│   :5173         │                                    │   :5696          │
│  (Vite/React)   │                                    │   (service:kmip) │
└────────┬────────┘                                    └────────┬─────────┘
         │ /svc/{service}/...                                   │
         ▼                                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        Auth Service                                      │
│   JWT validation · tenant header check · token introspection             │
└────────┬─────────────────────────────────────────────────────────────────┘
         │  validated principal + tenant context
         ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                       Keycore Service                                    │
│   Key store · lifecycle engine · access policy evaluation                │
│   Crypto dispatch (AES, RSA, EC, EdDSA, PQC, HMAC, KDF, KEM)           │
└────────┬──────────────────────────────────┬──────────────────────────────┘
         │                                  │
         ▼                                  ▼
┌─────────────────┐               ┌──────────────────────┐
│  Software Crypto│               │     HSM Hardware     │
│  (Go stdlib +   │               │  Thales / Entrust /  │
│   PQC libs)     │               │  AWS CloudHSM / etc. │
└────────┬────────┘               └──────────┬───────────┘
         │                                   │
         └─────────────┬─────────────────────┘
                       │ result + metadata
                       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        Audit Service                                     │
│   Every operation logged · hash chain computed · immutable append-only   │
└──────────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              Response returned to caller                                 │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.2 API Proxy Pattern

The dashboard (React, served on `:5173`) uses a **development proxy** and a **production reverse proxy** to forward all service API calls via the path prefix `/svc/{service}/`. This means:

- `/svc/keycore/keys` → keycore service
- `/svc/auth/tokens` → auth service
- `/svc/certs/certificates` → certs service
- `/svc/audit/events` → audit service

In production, this proxy is handled by nginx or Envoy, not the Vite dev server. All API calls from external clients should use the same `/svc/{service}/` prefix through the load balancer.

### 2.3 Trust Boundaries

Vecta KMS defines four trust boundaries:

```
[UNTRUSTED] External network
    │
    │ TLS (certificate pinning optional)
    ▼
[BOUNDARY 1] TLS termination + mTLS enforcement
    │
    │ Authenticated request
    ▼
[BOUNDARY 2] Auth service — JWT validation, tenant isolation
    │
    │ Validated principal + tenant context
    ▼
[BOUNDARY 3] Keycore — access policy evaluation, rate limit check
    │
    │ Authorized operation
    ▼
[BOUNDARY 4] HSM / software crypto — key material handling
```

Nothing crosses a boundary without explicit validation. A request that fails at boundary 2 never reaches boundary 3. A request that fails policy at boundary 3 never touches key material at boundary 4.

### 2.4 Multi-Tenancy Architecture

Each tenant in Vecta KMS is a **completely isolated namespace**:

- Separate key stores (no cross-tenant key references possible)
- Separate audit logs
- Separate access policies and governance workflows
- Separate service accounts and API tokens
- Separate rate limits and quotas

The tenant context is established via two required elements on every API call:

1. `Authorization: Bearer <token>` — token scoped to a specific tenant
2. `X-Tenant-ID: <tenant_id>` header OR `?tenant_id=<tenant_id>` query parameter

A token issued for tenant A will be rejected when attempting to access tenant B's resources even if the caller knows tenant B's ID. Token validation includes tenant binding.

### 2.5 Data Flow: Key Encryption Operation (Detailed)

The following trace shows exactly what happens when an application calls `POST /svc/keycore/keys/{id}/encrypt`:

```
1. Application sends HTTPS POST to load balancer
   Headers: Authorization: Bearer eyJ..., Content-Type: application/json
   Body: {"plaintext_b64": "SGVsbG8=", "aad_b64": "Y29udGV4dA=="}

2. Load balancer terminates TLS, forwards to keycore (or auth first, depending on config)

3. Auth service validates JWT:
   - Signature verification (RS256 or EdDSA key from auth service's JWKS)
   - Expiry check (exp claim)
   - Tenant binding: token's tenant_id claim must match request tenant_id param
   - Token not revoked (checks revocation list)
   - Result: principal = "svc-account-1", tenant = "acme-corp"

4. Keycore resolves the key:
   - Looks up key {id} in tenant "acme-corp" keystore
   - Key found, status = Active
   - Key algorithm = AES-256, purpose includes encrypt

5. Access policy evaluation:
   - Does principal "svc-account-1" have a grant for operation "encrypt" on this key?
   - Grant found: {subject: "svc-account-1", operation: "encrypt", expires_at: null}
   - Rate limit check: current ops count < ops_limit → allowed
   - Result: AUTHORIZED

6. Crypto dispatch:
   - If key_backend = "software": AES-256-GCM executed in Go process
   - If key_backend = "hsm": operation dispatched to HSM via PKCS#11

7. AES-256-GCM encryption:
   - IV: auto-generated 12-byte random nonce
   - AAD: decoded from aad_b64
   - Output: ciphertext + 16-byte GCM authentication tag

8. Response constructed:
   {
     "ciphertext_b64": "...",
     "iv_b64": "...",
     "tag_b64": "...",
     "key_id": "...",
     "key_version": 3,
     "algorithm": "AES-256-GCM"
   }

9. Audit event written:
   {
     "event_type": "key.encrypt",
     "tenant_id": "acme-corp",
     "key_id": "...",
     "key_version": 3,
     "principal": "svc-account-1",
     "timestamp": "2026-03-22T14:32:01.883Z",
     "result": "success",
     "chain_hash": "sha256:abc123..."  ← links to previous audit event
   }

10. HTTP 200 response returned to application
```

---

## 3. Security Model

### 3.1 Zero-Trust Architecture

Every request to Vecta KMS is treated as untrusted by default. There is no concept of "internal" vs "external" requests at the API level — the same validation pipeline applies regardless of whether the caller is on the same Kubernetes cluster or across the internet.

**Zero-trust requirements on every request:**
- Valid, non-expired JWT token
- Token tenant binding matches request tenant context
- Token not in revocation list
- Principal has an explicit grant for the requested operation on the specific key
- Rate limit not exceeded
- (If configured) HTTP Message Signature present and valid
- (If configured) Source IP within allowed CIDR range

### 3.2 Deny-by-Default Access Policy

When `deny_by_default` is enabled on a key ring (recommended for all production keys), **every operation requires an explicit, matching grant**. There are no implicit permissions.

```
Key Ring: production-keys
  deny_by_default: true

  Grants:
    - subject: svc-payments, operation: encrypt, expires_at: 2026-06-01
    - subject: svc-payments, operation: decrypt, expires_at: 2026-06-01
    - subject: svc-reporting, operation: encrypt (no decrypt!)
    - subject: admin-alice, operation: admin, not_before: 2026-01-01

  Any other principal → 403 Forbidden on any operation
  svc-reporting calling decrypt → 403 Forbidden (no decrypt grant)
```

### 3.3 Tamper-Evident Audit Chain

Every operation — reads, writes, lifecycle changes, policy changes, failed attempts — produces an audit event. Events form a **cryptographic hash chain**: each event includes the SHA-256 hash of the previous event. This means:

- Deleting or modifying a historical event breaks the chain and is immediately detectable
- Exporting and independently verifying the chain is possible at any time
- The chain covers all tenants (the root chain) and per-tenant sub-chains

```
Event N-1: {data: "...", hash_of_N_minus_2: "abc123", self_hash: "def456"}
Event N:   {data: "...", hash_of_N_minus_1: "def456", self_hash: "ghi789"}
Event N+1: {data: "...", hash_of_N: "ghi789", self_hash: "jkl012"}
```

Chain verification:
```bash
curl http://localhost:5173/svc/audit/chain/verify?tenant_id=acme-corp \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Returns:
{
  "chain_valid": true,
  "event_count": 14823,
  "first_event_id": "evt_...",
  "last_event_id": "evt_...",
  "last_verified_at": "2026-03-22T14:00:00Z"
}
```

### 3.4 FIPS 140-3 Mode

When `VECTA_FIPS_MODE=true` is set, Vecta KMS restricts all cryptographic operations to FIPS 140-3 validated algorithms:

**Allowed in FIPS mode:**
- AES-128, AES-192, AES-256 (ECB, CBC, CTR, GCM, CCM, XTS modes)
- HMAC-SHA-1 (legacy only), HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512
- RSA-2048+ (PKCS#1v1.5, PSS, OAEP)
- ECDSA with P-256, P-384, P-521
- ECDH with P-256, P-384, P-521
- SHA-1 (legacy verification only), SHA-224, SHA-256, SHA-384, SHA-512
- SP800-90A DRBG (AES-CTR-DRBG, HMAC-DRBG, Hash-DRBG)
- ML-KEM (NIST FIPS 203)
- ML-DSA (NIST FIPS 204)
- SLH-DSA (NIST FIPS 205)

**Rejected in FIPS mode:**
- ChaCha20, ChaCha20-Poly1305
- Ed25519, Ed448, X25519, X448
- BLAKE2b
- MD5, SHA-1 for new MACs or signatures
- Any custom or non-standard algorithm

Attempting to create a key with a non-FIPS algorithm in FIPS mode returns `422 Unprocessable Entity` with error code `FIPS_VIOLATION`.

### 3.5 Governance: N-of-M Approval Workflows

Sensitive operations can be configured to require **approval from N out of M designated approvers** before execution. Examples of operations that can require governance approval:

- Key destruction
- Key export
- Access policy changes
- Compliance framework changes
- HSM partition management
- Adding new admin users

Governance workflow lifecycle:

```
1. Requester submits operation → governance service creates Pending approval request
2. Approvers receive notification (email/webhook/Slack)
3. N approvers approve (each approval is signed with their token)
4. After N approvals: operation executes automatically
5. If any approver rejects: request moves to Rejected state, operation blocked
6. If timeout expires without N approvals: request expires, operation blocked
7. All approval actions are audit-logged
```

### 3.6 Workload Identity (SPIFFE/SVID)

Vecta KMS integrates with SPIFFE (Secure Production Identity Framework For Everyone) to provide **workload-native authentication** without static secrets:

- Workloads prove identity via SPIFFE Verifiable Identity Documents (SVIDs)
- SVIDs are short-lived X.509 certificates or JWTs issued by the SPIFFE Workload API
- Vecta KMS validates SVIDs and issues scoped tokens
- No API keys, no passwords, no long-lived secrets in workload config

SPIFFE attestation flow:
```
1. Container starts → requests SVID from SPIFFE agent (via Unix socket)
2. SPIFFE agent attests workload identity (via Kubernetes pod annotations, AWS EC2 metadata, etc.)
3. Workload presents SVID to Vecta auth service
4. Auth validates SVID against configured SPIFFE Trust Domain
5. Auth issues scoped Vecta JWT (TTL: typically 1 hour)
6. Workload uses Vecta JWT for key operations
7. JWT expires → workload gets fresh SVID → repeat
```

---

## 4. Installation

### 4.1 Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 16 GB |
| Disk | 20 GB | 100 GB SSD |
| OS | Linux (kernel 5.4+) | Ubuntu 22.04 LTS / RHEL 9 |
| Docker | 24.0+ | Latest stable |
| Docker Compose | v2.20+ | Latest stable |
| Kubernetes (prod) | 1.28+ | 1.30+ |
| PostgreSQL | 15+ | 16 |
| Go (source build) | 1.23+ | 1.24+ |

### 4.2 Docker Compose — Quickstart

This is the fastest way to get Vecta KMS running locally for evaluation.

```bash
# Clone the repository
git clone https://github.com/your-org/vecta-kms
cd vecta-kms

# Copy and review environment configuration
cp .env.example .env
# Edit .env to set at minimum:
#   VECTA_ADMIN_PASSWORD=<strong-password>
#   VECTA_DB_URL=postgres://vecta:vecta@postgres:5432/vecta
#   VECTA_JWT_SECRET=<random-32-bytes>

# Start all services
docker compose up -d

# Wait for health checks to pass (usually 30-60 seconds)
docker compose ps

# Check service health
curl http://localhost:5173/svc/keycore/health
# Expected: {"status":"ok","version":"1.0.0-beta"}

# Dashboard available at:
open http://localhost:5173
```

The default Docker Compose configuration starts:
- All microservices on internal Docker network
- PostgreSQL 16 for persistence
- Dashboard on `localhost:5173`
- KMIP listener on `localhost:5696`

### 4.3 Development Compose Override

For local development with hot reload:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

The dev override mounts source directories as volumes and enables Go's hot-reload via `air`.

### 4.4 Production Deployment — Kubernetes with Helm

```bash
# Add the Vecta Helm repository
helm repo add vecta https://charts.vecta.io
helm repo update

# Create namespace
kubectl create namespace vecta-kms

# Create secret for sensitive values
kubectl create secret generic vecta-kms-secrets \
  --namespace vecta-kms \
  --from-literal=db-url="postgres://vecta:STRONG_PASSWORD@db.internal:5432/vecta" \
  --from-literal=jwt-secret="$(openssl rand -hex 32)" \
  --from-literal=hsm-pin="$(cat /secure/hsm-pin)"

# Install with production values
helm install vecta-kms vecta/vecta-kms \
  --namespace vecta-kms \
  --values values-production.yaml \
  --set cluster.replicas=3 \
  --set keycore.hsm.enabled=true \
  --set fipsMode=true

# Check rollout status
kubectl rollout status deployment/vecta-keycore -n vecta-kms
kubectl rollout status deployment/vecta-auth -n vecta-kms
```

Example `values-production.yaml`:

```yaml
global:
  tenantId: "your-org"
  fipsMode: true
  logLevel: "warn"

keycore:
  replicas: 3
  hsm:
    enabled: true
    provider: "thales-luna"
    slot: 0
  resources:
    requests:
      cpu: "500m"
      memory: "512Mi"
    limits:
      cpu: "2000m"
      memory: "2Gi"

auth:
  replicas: 2
  jwtTTLSeconds: 3600

audit:
  replicas: 2
  retention:
    days: 2555  # 7 years for compliance

database:
  external: true
  url: ""  # Set via secret
  poolSize: 20

ingress:
  enabled: true
  className: "nginx"
  tls:
    enabled: true
    secretName: "vecta-tls"
  hosts:
    - host: kms.your-org.internal
      paths:
        - path: /
          pathType: Prefix
```

### 4.5 Production Deployment — Bare Metal with systemd

```bash
# Download the latest release
curl -LO https://releases.vecta.io/vecta-kms-linux-amd64-latest.tar.gz
tar -xzf vecta-kms-linux-amd64-latest.tar.gz
sudo mv vecta-kms /usr/local/bin/

# Create system user
sudo useradd --system --no-create-home --shell /bin/false vecta

# Create configuration directory
sudo mkdir -p /etc/vecta-kms /var/lib/vecta-kms /var/log/vecta-kms
sudo chown vecta:vecta /var/lib/vecta-kms /var/log/vecta-kms

# Write configuration
sudo tee /etc/vecta-kms/config.yaml > /dev/null <<EOF
tenant_id: "your-org"
db_url: "postgres://vecta:PASSWORD@localhost:5432/vecta"
jwt_secret_file: "/etc/vecta-kms/jwt.secret"
fips_mode: true
log_level: "warn"
listen_addr: ":8080"
dashboard_addr: ":5173"
EOF

# Create systemd unit for keycore (repeat for each service)
sudo tee /etc/systemd/system/vecta-keycore.service > /dev/null <<EOF
[Unit]
Description=Vecta KMS - Key Core Service
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=vecta
Group=vecta
ExecStart=/usr/local/bin/vecta-kms serve keycore --config /etc/vecta-kms/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/vecta-kms /var/log/vecta-kms

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vecta-keycore
sudo systemctl status vecta-keycore
```

### 4.6 HSM-Backed Deployment

#### Thales Luna HSM

```bash
# Prerequisites: Luna client software installed, partition created
# Environment variables:
export VECTA_HSM_PROVIDER=thales-luna
export VECTA_HSM_SLOT=0
export VECTA_HSM_PIN_FILE=/etc/vecta-kms/hsm.pin     # file, not env var, for security
export VECTA_HSM_LIBRARY=/usr/safenet/lunaclient/lib/libCryptoki2_64.so

# Verify HSM connectivity before starting
vecta-kms hsm verify --provider thales-luna --slot 0
# Expected: HSM connectivity OK, FIPS mode: enabled, firmware: 7.7.1
```

#### AWS CloudHSM

```bash
export VECTA_HSM_PROVIDER=aws-cloudhsm
export VECTA_HSM_CLUSTER_ID=cluster-xxxxxxxxx
export VECTA_HSM_USERNAME=vecta-crypto-user
export VECTA_HSM_PASSWORD_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789:secret:vecta-hsm-pw
# AWS IAM role must have CloudHSM permissions
```

#### Securosys Primus X

```bash
export VECTA_HSM_PROVIDER=securosys
export VECTA_HSM_ENDPOINT=https://primusdev.cloudshsm.com
export VECTA_HSM_API_KEY=<securosys-api-key>
export VECTA_HSM_PARTITION=vecta-partition
```

### 4.7 Environment Variables Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `VECTA_TENANT_ID` | Yes | — | Default tenant for single-tenant deployments |
| `VECTA_DB_URL` | Yes | — | PostgreSQL connection string |
| `VECTA_JWT_SECRET` | Yes | — | JWT signing secret (HS256) or path to key file |
| `VECTA_ADMIN_PASSWORD` | Yes (first run) | — | Initial admin password |
| `VECTA_FIPS_MODE` | No | `false` | Enable FIPS 140-3 algorithm restrictions |
| `VECTA_HSM_PROVIDER` | No | — | HSM provider: `thales-luna`, `aws-cloudhsm`, `securosys`, `entrust`, `utimaco` |
| `VECTA_HSM_PIN` | No | — | HSM partition PIN (prefer `VECTA_HSM_PIN_FILE`) |
| `VECTA_HSM_PIN_FILE` | No | — | Path to file containing HSM PIN |
| `VECTA_LOG_LEVEL` | No | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `VECTA_LISTEN_ADDR` | No | `:8080` | Internal service listen address |
| `VECTA_DASHBOARD_ADDR` | No | `:5173` | Dashboard listen address |
| `VECTA_KMIP_ADDR` | No | `:5696` | KMIP protocol listener |
| `VECTA_CORS_ORIGINS` | No | `*` | Allowed CORS origins for dashboard |
| `VECTA_TLS_CERT` | No | — | Path to TLS certificate file |
| `VECTA_TLS_KEY` | No | — | Path to TLS private key file |
| `VECTA_AUDIT_RETENTION_DAYS` | No | `730` | Days to retain audit events |
| `VECTA_CLUSTER_NODES` | No | — | Comma-separated cluster node addresses |
| `VECTA_CLUSTER_RAFT_PORT` | No | `9000` | Raft consensus port |

---

## 5. First Login

### 5.1 Default Admin Credentials

After first startup, a default `root` tenant and `admin` user are created.

**Default credentials:**
- Username: `admin`
- Password: set via `VECTA_ADMIN_PASSWORD` environment variable (required; no fallback default)
- Tenant: `root`

> **Security requirement:** You must change the admin password before enabling any external access. The system enforces this — API calls from the admin account return `403 MUST_CHANGE_PASSWORD` until the password is changed.

### 5.2 Changing the Initial Password

**Via Dashboard:**
1. Navigate to `http://localhost:5173`
2. Enter credentials on the login screen
3. The system redirects to the **Change Password** screen automatically
4. Enter a new password (minimum 16 characters, must include uppercase, lowercase, digit, symbol)
5. Click **Save** — you are redirected to the main dashboard

**Via API:**
```bash
# First, get a token with the initial password
TOKEN=$(curl -s -X POST http://localhost:5173/svc/auth/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "YOUR_INITIAL_PASSWORD",
    "tenant_id": "root"
  }' | jq -r '.token')

# Change password
curl -X POST http://localhost:5173/svc/auth/users/admin/change-password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "YOUR_INITIAL_PASSWORD",
    "new_password": "YourNewStr0ng!Password#2026"
  }'
```

### 5.3 Navigating the Dashboard

The dashboard is organized into a **left sidebar navigation** grouped by functional area, a **top bar** with tenant selector, search, notifications, and user menu, and a **main content area**.

**Top Bar Elements:**
- **Tenant selector:** Dropdown showing your current tenant context. Click to switch tenants (you must have access to the target tenant).
- **Global search:** `Cmd+K` / `Ctrl+K` — search across keys, certificates, audit events, users.
- **Notifications bell:** Governance approvals pending, expiring keys, compliance alerts.
- **Theme toggle:** Dark / Light / Auto (follows system preference). Located in user menu → Preferences.
- **Timezone picker:** Display timestamps in your local timezone or UTC. Located in user menu → Preferences.
- **Pinned tabs:** Pin frequently-used pages with the pin icon on any page header.

### 5.4 Dashboard Navigation Sections

The left sidebar is organized into these sections:

**CORE**
- **Keys** — Create, view, manage all cryptographic keys. Includes search, filtering by algorithm/status/label, bulk operations.
- **Key Rings** — Logical groupings of keys with shared access policy configuration.
- **Secrets** — Non-cryptographic secret storage (API keys, passwords, config values).
- **Tokens** — Service account tokens, viewing active sessions, revocation.

**CRYPTO & PKI**
- **Certificates** — X.509 certificate issuance, renewal, revocation, OCSP.
- **Certificate Authorities** — Manage root CAs, intermediate CAs, CA hierarchy.
- **Signing** — Code signing, artifact signing, signature verification, transparency log.
- **MPC / Threshold** — Multi-party computation signing, FROST threshold setup.
- **Post-Quantum** — ML-KEM, ML-DSA, SLH-DSA key operations.

**DATA & POLICY**
- **Data Protection** — Tokenization, format-preserving encryption, vaults (PAN, SSN, etc.).
- **Payment Crypto** — TR-31 key blocks, payment key management.
- **Autokey** — Self-service key request portal with governance templates.
- **Access Policies** — Per-key and key-ring access policy management.

**CLOUD & IDENTITY**
- **Cloud KMS** — BYOK/HYOK configuration for AWS, Azure, GCP.
- **Workload Identity** — SPIFFE trust domains, workload attestations.
- **Confidential Compute** — TEE policies, enclave key sealing.
- **EKM** — External Key Manager proxy for database TDE.

**INFRASTRUCTURE**
- **KMIP** — KMIP server status, connected clients, KMIP object inventory.
- **QKD** — Quantum key distribution link status and key consumption metrics.
- **QRNG** — Quantum RNG source health, entropy pool status.
- **Cluster** — Node status, Raft leader, replication lag, split-brain detection.
- **HSM** — HSM health, partition utilization, PKCS#11 session count.

**GOVERNANCE**
- **Approvals** — Pending approval requests, approval history, approver management.
- **Policies** — Governance policies: which operations require N-of-M approval.
- **Compliance** — Compliance framework status (FIPS, PCI-DSS, HIPAA, SOC2, ISO 27001).
- **Posture** — Security posture score, drift alerts, remediation recommendations.
- **Reporting** — Usage reports, key inventory reports, compliance reports.
- **Audit** — Audit event browser, chain verification, event export.

**ADMIN**
- **Users** — User management, role assignments.
- **Groups** — Group management, group membership.
- **Tenants** — Tenant management (root admin only).
- **Settings** — Global platform settings, FIPS mode, SMTP, LDAP/OIDC integration.

---

## 6. Creating Your First Tenant

### 6.1 Why Tenants Matter

Tenants provide **complete cryptographic isolation** between organizations, business units, environments, or any logical grouping. Key material in tenant A can never be accessed by principals in tenant B — this is enforced at the database level (row-level isolation with tenant_id foreign key constraints) and at the API level (token binding).

Typical tenant organization patterns:

| Pattern | Example |
|---|---|
| Per-organization (MSP/SaaS) | `acme-corp`, `beta-inc`, `gamma-llc` |
| Per-environment | `production`, `staging`, `development` |
| Per-business-unit | `payments`, `data-platform`, `security` |
| Per-region | `us-east`, `eu-west`, `ap-southeast` |
| Combination | `acme-corp-production-us-east` |

### 6.2 Creating a Tenant — Via Dashboard

1. Navigate to **Admin → Tenants** (requires `root` admin)
2. Click **Create Tenant**
3. Fill in:
   - **Tenant ID:** URL-safe, lowercase, hyphens allowed (e.g., `acme-corp`)
   - **Display Name:** Human-readable (e.g., `Acme Corporation`)
   - **Contact Email:** Admin contact for this tenant
   - **Plan / Quota:** Key count limit, operation rate limit
4. Click **Create**
5. System creates tenant and generates an initial admin token for that tenant
6. Share the initial admin token securely with the tenant's admin

### 6.3 Creating a Tenant — Via API

```bash
# Requires root admin token
curl -X POST http://localhost:5173/svc/auth/tenants \
  -H "Authorization: Bearer $ROOT_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme-corp",
    "display_name": "Acme Corporation",
    "contact_email": "kms-admin@acme.corp",
    "quota": {
      "max_keys": 10000,
      "ops_per_second": 1000
    }
  }'

# Response:
{
  "tenant_id": "acme-corp",
  "display_name": "Acme Corporation",
  "created_at": "2026-03-22T14:00:00Z",
  "initial_admin_token": "vkms_t1_...",  ← share this securely, rotates after first use
  "status": "active"
}
```

### 6.4 Switching Tenant Context

**In the Dashboard:** Use the **Tenant Selector** dropdown in the top bar.

**In API calls:** Change the `?tenant_id=` parameter or `X-Tenant-ID` header, and use a token scoped to that tenant.

```bash
# Token for tenant acme-corp
export ACME_TOKEN="vkms_t1_..."

# All subsequent calls use acme-corp context
curl http://localhost:5173/svc/keycore/keys?tenant_id=acme-corp \
  -H "Authorization: Bearer $ACME_TOKEN"
```

---

## 7. Creating Your First Key

### 7.1 Via Dashboard — Step by Step

1. **Navigate to Keys:** Click **CORE → Keys** in the left sidebar.
2. **Click Create Key:** Blue button in the top right of the Keys page.
3. **Key Details form:**
   - **Name:** Enter a descriptive name (e.g., `app-database-encryption-key`). Max 255 chars. No leading/trailing spaces.
   - **Algorithm:** Select from the dropdown. For data encryption, choose `AES-256`. For signing, choose `EC-P256` or `Ed25519`.
   - **Purpose:** Auto-populated based on algorithm. Verify it matches your intent (`encrypt`, `sign`, etc.).
   - **Key Backend:** `Software` (default) or `HSM` (requires HSM configured).
4. **Lifecycle Settings (optional):**
   - **Activation Date:** Leave blank to activate immediately, or set a future date (key starts in PreActive state).
   - **Expiry Date:** Date when key automatically moves to Deactivated state.
   - **Destruction Date:** Date when key is automatically destroyed.
5. **Labels (optional):** Add key-value metadata (e.g., `env=production`, `team=platform`, `app=payments-service`).
6. **Tags (optional):** Add string tags for grouping (e.g., `pci-scope`, `critical`).
7. **Access Policy (optional):** Configure deny-by-default and initial grants now, or configure later.
8. **Click Create Key.**
9. The key appears in your key list with status **Active** (or **PreActive** if activation date is in the future).

### 7.2 Via API — Full Example

```bash
# Set your token
export TOKEN="your-token-here"

# Create an AES-256 encryption key
curl -X POST "http://localhost:5173/svc/keycore/keys?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-first-key",
    "algorithm": "AES-256",
    "purpose": "encrypt",
    "key_backend": "software",
    "labels": {
      "env": "dev",
      "team": "platform",
      "app": "demo"
    },
    "tags": ["demo", "getting-started"]
  }'
```

**Successful response (HTTP 201):**

```json
{
  "id": "key_01J3XVQB5M9N4KPFGHWCZ8D",
  "name": "my-first-key",
  "algorithm": "AES-256",
  "purpose": "encrypt",
  "status": "active",
  "version": 1,
  "key_backend": "software",
  "export_allowed": false,
  "tenant_id": "acme-corp",
  "labels": {
    "env": "dev",
    "team": "platform",
    "app": "demo"
  },
  "tags": ["demo", "getting-started"],
  "created_at": "2026-03-22T14:00:00Z",
  "updated_at": "2026-03-22T14:00:00Z",
  "activation_date": null,
  "expires_at": null,
  "destroy_date": null,
  "kcv": "A3F2E1"
}
```

**Key fields in response:**
- `id` — unique key identifier, use this in all subsequent API calls
- `version` — starts at 1, increments on each rotation
- `kcv` — Key Check Value (3-byte truncated AES ECB of null plaintext), used to verify successful key import/wrap operations
- `status` — current lifecycle state (`active`, `preactive`, `deactivated`, `compromised`, `destroyed`)

### 7.3 Verifying the Key

```bash
# Retrieve the key you just created
curl "http://localhost:5173/svc/keycore/keys/key_01J3XVQB5M9N4KPFGHWCZ8D?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 8. Encrypting Data

### 8.1 Basic Encrypt Call

```bash
# The plaintext must be Base64-encoded
# "Hello Vecta KMS" → base64 = "SGVsbG8gVmVjdGEgS01T"

curl -X POST \
  "http://localhost:5173/svc/keycore/keys/key_01J3XVQB5M9N4KPFGHWCZ8D/encrypt?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext_b64": "SGVsbG8gVmVjdGEgS01T"
  }'
```

**Response (HTTP 200):**

```json
{
  "ciphertext_b64": "7KgQ9rZ2mN4pL1wX8vB...",
  "iv_b64": "dGhpcyBpcyBhIG5vbm...",
  "tag_b64": "aGVsbG8gd29ybGQ=",
  "key_id": "key_01J3XVQB5M9N4KPFGHWCZ8D",
  "key_version": 1,
  "algorithm": "AES-256-GCM"
}
```

> Store `ciphertext_b64`, `iv_b64`, `tag_b64`, `key_id`, and `key_version` together. You need all of them to decrypt.

### 8.2 Decrypt Call

```bash
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/key_01J3XVQB5M9N4KPFGHWCZ8D/decrypt?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext_b64": "7KgQ9rZ2mN4pL1wX8vB...",
    "iv_b64": "dGhpcyBpcyBhIG5vbm...",
    "tag_b64": "aGVsbG8gd29ybGQ=",
    "key_version": 1
  }'
```

**Response (HTTP 200):**

```json
{
  "plaintext_b64": "SGVsbG8gVmVjdGEgS01T",
  "key_id": "key_01J3XVQB5M9N4KPFGHWCZ8D",
  "key_version": 1
}
```

### 8.3 Encrypt with Additional Authenticated Data (AAD)

AAD binds ciphertext to a specific context — decryption fails if the AAD doesn't match. This prevents ciphertext from being moved to a different context (e.g., a ciphertext for user A cannot be decrypted as if it were for user B).

```bash
# Encrypt with AAD (AAD must also be base64 encoded)
# AAD context: "user:alice:field:ssn" → base64 = "dXNlcjphbGljZTpmaWVsZDpzc24="

curl -X POST \
  "http://localhost:5173/svc/keycore/keys/key_01J3XVQB5M9N4KPFGHWCZ8D/encrypt?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext_b64": "MTIzLTQ1LTY3ODk=",
    "aad_b64": "dXNlcjphbGljZTpmaWVsZDpzc24="
  }'

# Decrypt — must provide the SAME AAD
curl -X POST \
  "http://localhost:5173/svc/keycore/keys/key_01J3XVQB5M9N4KPFGHWCZ8D/decrypt?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext_b64": "...",
    "iv_b64": "...",
    "tag_b64": "...",
    "aad_b64": "dXNlcjphbGljZTpmaWVsZDpzc24=",
    "key_version": 1
  }'
```

---

## 9. Feature Decision Tree

Use this tree to select the right Vecta KMS feature for your use case.

```
What are you trying to accomplish?
│
├── Encrypt data at rest?
│   ├── Application manages encryption → Keys API (AES-256-GCM)
│   │   └── Many keys needed across teams → Autokey (governance-controlled self-service)
│   ├── Database TDE (transparent to app) → EKM service
│   ├── Tokenize sensitive fields (PAN, SSN) → Data Protection (FPE / tokenization)
│   └── Format-preserving (output same format as input) → Data Protection (FPE)
│
├── Sign data or code?
│   ├── API request signing → Keys API (EC-P256 or Ed25519, ECDSA/EdDSA)
│   ├── Code/artifact signing → Signing service + transparency log
│   ├── Multi-party signing (threshold) → MPC / FROST
│   └── Post-quantum signatures → PQC service (ML-DSA, SLH-DSA)
│
├── Manage certificates?
│   ├── Issue X.509 certificates → Certs / PKI service
│   ├── Store CA private key securely → Keys API (HSM-backed EC-P384)
│   └── OCSP / CRL management → Certs service
│
├── Cloud encryption key ownership?
│   ├── Bring your own key to cloud (BYOK) → Cloud KMS service
│   └── Hold your own key (HYOK, cloud never sees key) → Cloud KMS / EKM HYOK mode
│
├── Authenticate workloads (no static secrets)?
│   ├── Kubernetes / container workloads → Workload Identity (SPIFFE/SVID)
│   ├── TEE / enclave workloads → Confidential Compute service
│   └── Cloud VMs (EC2, GCE, Azure VM) → Workload Identity (cloud attestation)
│
├── KMIP-compatible storage or devices?
│   └── KMIP appliances, storage arrays → KMIP server
│
├── Payment keys (PCI-DSS)?
│   └── TR-31 key blocks, LMK, ZMK, PIK → Payment Crypto service
│
├── Post-quantum migration?
│   ├── Key exchange → PQC service (ML-KEM-768)
│   └── Signatures → PQC service (ML-DSA-65 or SLH-DSA-SHA2-128s)
│
└── Quantum entropy?
    ├── True random number generation → QRNG service
    └── Quantum key distribution → QKD service
```

### 9.1 Quick Reference — Feature to Service Mapping

| Use Case | Service | API Path |
|---|---|---|
| Application data encryption | `keycore` | `/svc/keycore/keys/{id}/encrypt` |
| Self-service key provisioning with approval | `autokey` | `/svc/autokey/requests` |
| Containerized workload auth | `workload` | `/svc/workload/attestation` |
| TEE / enclave key sealing | `confidential` | `/svc/confidential/seal` |
| AWS/Azure BYOK | `cloud` | `/svc/cloud/byok` |
| AWS/Azure HYOK | `cloud` | `/svc/cloud/hyok` |
| Database TDE | `ekm` | `/svc/ekm/wrap` |
| KMIP storage | `kmip` | KMIP protocol :5696 |
| Certificate issuance | `certs` | `/svc/certs/certificates` |
| PAN/SSN tokenization | `dataprotect` | `/svc/dataprotect/tokenize` |
| Format-preserving encryption | `dataprotect` | `/svc/dataprotect/fpe/encrypt` |
| Payment keys (TR-31) | `payment` | `/svc/payment/key-blocks` |
| Post-quantum KEM | `pqc` | `/svc/pqc/kem/encapsulate` |
| Post-quantum signatures | `pqc` | `/svc/pqc/sign` |
| Code/artifact signing | `signing` | `/svc/signing/sign` |
| MPC threshold signing | `mpc` | `/svc/mpc/sessions` |
| Quantum RNG | `qrng` | `/svc/qrng/random` |
| QKD | `qkd` | `/svc/qkd/keys` |

---

## 10. Dashboard Tour

### 10.1 CORE — Keys

**List View:** Displays all keys for the current tenant in a paginated table. Columns: Key ID, Name, Algorithm, Purpose, Status, Version, Key Backend, Created At, Expires At, Labels. Filterable by status, algorithm, purpose, labels, tags. Sortable by name, created date, expiry. Bulk operations: Rotate selected, Deactivate selected, Add tags.

**Key Detail View:** Clicking a key opens its detail page showing:
- **Overview card:** Full key metadata, current status badge, version history.
- **Operations panel:** Quick-launch encrypt/decrypt/sign/verify directly from the dashboard (for testing — not for production use).
- **Lifecycle panel:** Visual timeline of activation, expiry, and destruction dates. Lifecycle transition buttons: Rotate, Deactivate, Compromise, Destroy.
- **Access Policy panel:** Current grants, add/remove grants, deny-by-default toggle.
- **Interface Policies panel:** Per-interface allowlists.
- **Rate Limiting panel:** Configure ops_limit and ops_limit_window.
- **Audit History panel:** All audit events for this specific key, filterable by event type and date range.
- **Labels & Tags panel:** Add/remove labels and tags.

### 10.2 CORE — Key Rings

Key rings are logical containers for keys sharing an access policy. Viewing a key ring shows:
- Member keys list
- Shared access policy (applies to all keys in ring)
- Ring-level deny-by-default setting
- Governance settings: require_approval_for_policy_change

### 10.3 CRYPTO & PKI — Certificates

**Certificate List:** All issued certificates. Columns: Subject CN, SAN, Issuer, Not Before, Not After, Status, Serial. Filter by CA, status (valid/revoked/expired). Export to PEM/DER/PFX.

**Certificate Detail:** Full certificate fields, download buttons, revoke action, OCSP status, chain view (leaf → intermediate → root).

**Certificate Authorities:** Tree view of your CA hierarchy. Root CA → Intermediate CAs → Issuing CAs. Each CA shows: certificate details, signing policy (max path length, allowed SANs, key usage), CRL distribution points.

### 10.4 GOVERNANCE — Approvals

**Pending Approvals:** List of operations waiting for N-of-M approval. For each: operation type, requested by, requested at, justification, current approval count (e.g., 1 of 3 required), expiry time. Buttons: Approve (with comment), Reject (with reason).

**Approval History:** Historical list of completed, rejected, and expired approval requests. Full audit trail per request.

### 10.5 GOVERNANCE — Audit

**Event Browser:** Full-text searchable, filterable audit event log. Filters: event type, principal, key ID, date range, result (success/failure). Timeline visualization. Click any event for full JSON detail including chain hash.

**Chain Verification:** One-click chain integrity verification. Shows verification progress and result.

**Export:** Export audit events to JSON, CSV, or SIEM-compatible formats (CEF, LEEF). Signed export bundles for court-admissible evidence.

### 10.6 GOVERNANCE — Compliance

For each compliance framework (FIPS 140-3, PCI-DSS v4, HIPAA, SOC 2 Type II, ISO 27001):
- Compliance score (percentage of controls passing)
- Control-by-control status: Pass / Fail / Not Applicable / Warning
- Remediation guidance for failing controls
- Last assessment timestamp
- Download compliance report PDF

### 10.7 INFRASTRUCTURE — Cluster

**Node Status:** Table of all cluster nodes. Columns: Node ID, Address, Role (Leader/Follower), Status (healthy/unreachable), Last Heartbeat, Raft Log Index, Replication Lag.

**Raft State:** Current term, current leader, vote count, log commit index vs applied index.

**Split-Brain Detector:** Visual indicator (green: quorum healthy, yellow: minority partition detected, red: split-brain suspected).

### 10.8 INFRASTRUCTURE — HSM

**HSM Health Panel:** Provider name, firmware version, FIPS validation certificate, operational status (green/yellow/red), last connectivity test.

**Partition Utilization:** Key slot usage (used/available), session count (current/max), entropy pool level.

**Operations per second:** Real-time gauge of HSM crypto operations throughput.

---

## 11. Next Steps

Now that you have Vecta KMS running and have created your first key, here are the recommended next steps:

### 11.1 Immediate Next Steps

1. **Read the Key Management documentation:** See [KEYS.md](./KEYS.md) for comprehensive coverage of all key types, operations, lifecycle management, and security considerations.

2. **Configure access policies:** Enable `deny_by_default` on your key rings and create explicit grants. See [KEYS.md § Access Policy](./KEYS.md#9-key-access-policy).

3. **Set up audit log export:** Configure your SIEM integration via Admin → Settings → Audit → Export. Ensure audit events flow to your central log management system.

4. **Enable FIPS mode** if in a regulated environment: `VECTA_FIPS_MODE=true` in environment configuration.

5. **Create service accounts** for your applications rather than using the admin account: Admin → Users → Create Service Account.

### 11.2 Deeper Documentation

| Document | Description |
|---|---|
| [KEYS.md](./KEYS.md) | Comprehensive key management: algorithms, lifecycle, operations, access policy |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Deep dive into service architecture and data flows |
| [ADMINISTRATION.md](./ADMINISTRATION.md) | Operational administration, backup, upgrade, monitoring |
| [ADMIN_GUIDE.md](./ADMIN_GUIDE.md) | Day-to-day admin tasks reference |
| [COMPONENT_GUIDE.md](./COMPONENT_GUIDE.md) | Per-service configuration reference |
| [OPERATIONS_GUIDE.md](./OPERATIONS_GUIDE.md) | Runbooks for common operational scenarios |
| [FEATURE_REFERENCE.md](./FEATURE_REFERENCE.md) | Complete feature reference for all services |
| [WORKFLOW_EXAMPLES.md](./WORKFLOW_EXAMPLES.md) | End-to-end workflow examples |
| [REST_API_ADDITIONS.md](./REST_API_ADDITIONS.md) | Additional REST API documentation |
| [openapi/](./openapi/) | OpenAPI 3.1 specifications for all services |

### 11.3 SDK and Integration Resources

```bash
# Go SDK
go get github.com/your-org/vecta-kms-go

# Python SDK
pip install vecta-kms

# Node.js SDK
npm install @vecta/kms-client

# Terraform provider
# registry.terraform.io/providers/your-org/vectakms

# Kubernetes operator
kubectl apply -f https://releases.vecta.io/k8s-operator/latest/install.yaml
```

### 11.4 Getting Help

- **Documentation:** This docs directory and the OpenAPI specifications in `openapi/`
- **Slack community:** `#vecta-kms` on your organization's Slack
- **GitHub Issues:** `https://github.com/your-org/vecta-kms/issues`
- **Security disclosures:** `security@vecta.io` (PGP key available)
- **Enterprise support:** `support@vecta.io`

---

*Vecta KMS Getting Started Guide — Version Beta — 2026-03-22*
