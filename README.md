# Vecta KMS

Enterprise Key Management System with full lifecycle cryptographic operations, compliance frameworks, and multi-cloud key orchestration.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Web Dashboard (React/Vite)                  │
├────────┬────────┬────────┬────────┬────────┬────────┬──────────┤
│KeyCore │ Auth   │ Audit  │ Certs  │ EKM    │ Secrets│ HSM      │
│Service │Service │Service │Service │Service │Service │Integ     │
├────────┴────────┴────────┴────────┴────────┴────────┴──────────┤
│            Shared Packages (pkg/*)                              │
│  agentauth │ keycache │ crypto │ db │ events │ tlsprofile      │
├─────────────────────────────────────────────────────────────────┤
│  SQLite/BadgerDB  │  Raft Cluster  │  Consul  │  HSM Backend   │
└─────────────────────────────────────────────────────────────────┘
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| **keycore** | 8443 | Core key lifecycle — create, import, rotate, destroy, wrap/unwrap |
| **auth** | 9443 | Authentication, RBAC, tenant management, user provisioning |
| **audit** | 8445 | Tamper-evident audit log with blockchain-anchored chain integrity |
| **certs** | 8443 | X.509 certificate authority — issue, renew, revoke, CRL/OCSP |
| **ekm** | 8444 | External Key Manager — TDE keys, agents, BitLocker, database encryption |
| **secrets** | 8443 | Secret vault — envelope encryption, versioning, rotation policies |
| **compliance** | — | Compliance assessment — NIST, PCI-DSS, HIPAA, SOC2 frameworks |
| **posture** | — | Security posture scoring, risk assessment, automated findings |
| **governance** | — | Approval workflows, quorum policies, separation of duties |
| **cloud** | — | Multi-cloud BYOK/HYOK — AWS, Azure, GCP, Salesforce key sync |
| **kmip** | 5696 | KMIP 1.4/2.0 protocol server for enterprise integration |
| **reporting** | — | Alert management, channels, metrics, MTTR analytics |
| **discovery** | — | Cryptographic asset discovery and inventory |
| **pqc** | — | Post-quantum cryptography — ML-KEM, ML-DSA, SLH-DSA |
| **qkd** | — | Quantum Key Distribution integration |
| **qrng** | — | Quantum Random Number Generator |
| **mpc** | — | Multi-party computation for distributed key ceremonies |
| **payment** | — | Payment HSM integration (PCI PIN, DUKPT, TR-31) |
| **dataprotect** | — | Data protection — tokenization, masking, format-preserving encryption |
| **sbom** | — | Software Bill of Materials tracking and vulnerability scanning |
| **ai** | — | AI/ML model encryption and key management |
| **software-vault** | — | Software-based secure enclave for key storage |
| **cluster-manager** | — | Raft-based cluster coordination, leader election, replication |
| **firstboot** | — | First-boot setup wizard for initial configuration |
| **hsm-integration** | — | HSM backend abstraction — PKCS#11, proprietary APIs |

## Agent & Provider Packages

| Package | Type | Description |
|---------|------|-------------|
| **ekm-agent** | Go binary | Windows/Linux agent for TDE key management, BitLocker ops, heartbeat |
| **pkcs11-provider** | C shared lib | PKCS#11 v2.40 provider — plugs into OpenSSL, Java, databases |
| **jca-provider** | Java JAR | JCA/JCE provider — `Cipher`, `Signature`, `KeyStore`, `SecureRandom` |

## Shared Packages (`pkg/`)

| Package | Purpose |
|---------|---------|
| `agentauth` | Multi-auth provider: mTLS → JWT → API Key → Bearer token |
| `keycache` | Secure local key cache with mlock'd memory and TTL eviction |
| `crypto` | Cryptographic primitives, Mlock/Munlock/Zeroize, key derivation |
| `db` | SQLite database layer with migrations |
| `events` | Event bus for inter-service communication |
| `tlsprofile` | TLS configuration profiles (FIPS, PQC, hybrid) |
| `auditmw` | Audit middleware for HTTP handlers |
| `auth` | Auth middleware and token validation |
| `cache` | Generic in-memory cache |
| `clustersync` | Cluster synchronization primitives |
| `config` | Configuration loading and validation |
| `consul` | Consul service discovery integration |
| `grpc` | gRPC transport utilities |
| `metering` | Usage metering and billing |
| `mpc` | Multi-party computation protocol helpers |
| `payment` | Payment HSM protocol helpers |
| `pdfutil` | PDF generation for compliance reports |
| `ratelimit` | Rate limiting middleware |
| `runtimecfg` | Runtime configuration hot-reload |

## Quick Start

### Prerequisites

- Go 1.26+
- Node.js 18+ (for dashboard)
- SQLite 3.35+ (embedded)
- Optional: JDK 11+ (for JCA provider), GCC/CGo (for PKCS#11 provider)

### Install

```bash
# Linux
./install.sh

# macOS
./install-macos.sh

# Windows (PowerShell)
.\install-windows.ps1
```

### Development

```bash
# Start all services
./run-local.sh

# Build everything
make all

# Build dashboard
cd web/dashboard && npm install && npm run build

# Build Go services
go build ./...

# Run tests
go test ./...
```

### Docker

```bash
# Development
docker-compose -f docker-compose.dev.yml up

# Production
docker-compose up -d
```

## Network Interfaces

| Interface | Port | Protocol | Description |
|-----------|------|----------|-------------|
| rest-api | 8443 | TLS 1.3 | Primary REST API |
| kmip-tls | 5696 | mTLS | KMIP protocol |
| management | 9443 | mTLS | Admin management plane |
| hsm-bridge | 9500 | mTLS | HSM communication |
| ekm-data | 8444 | TLS 1.3 | EKM/TDE endpoint |
| audit-stream | 8445 | mTLS | Audit event stream |

## Security Features

- **FIPS 140-3** compliant cryptographic module (strict/standard modes)
- **Post-quantum** ready: ML-KEM, ML-DSA, SLH-DSA, hybrid key exchange
- **HSM integration**: PKCS#11, proprietary APIs, key reference model
- **mTLS everywhere**: Certificate-based service-to-service authentication
- **Tamper-evident audit**: Blockchain-anchored hash chain for log integrity
- **Quorum approvals**: M-of-N approval workflows for sensitive operations
- **Shamir secret sharing**: Recovery key splitting (3-of-5 default)
- **Key cache security**: mlock'd memory, automatic zeroization on eviction
- **Rate limiting**: Per-tenant, per-endpoint throttling
- **Nonce replay protection**: Configurable replay window with TTL

## Cloud BYOK/HYOK

| Provider | BYOK | HYOK | Key Sync | Status |
|----------|------|------|----------|--------|
| AWS KMS | Yes | Yes | Automatic | Production |
| Azure Key Vault | Yes | Yes | Automatic | Production |
| Google Cloud KMS | Yes | Yes | Automatic | Production |
| Salesforce Shield | Yes | — | Manual | Production |

## Compliance Frameworks

NIST SP 800-57, PCI-DSS v4.0, HIPAA, SOC 2 Type II, GDPR, eIDAS, ISO 27001, FIPS 140-3

## Project Structure

```
├── services/           # Microservices (Go)
│   ├── keycore/        # Core key management
│   ├── auth/           # Authentication & RBAC
│   ├── audit/          # Audit logging
│   ├── certs/          # Certificate authority
│   ├── ekm/            # External key manager
│   ├── ekm-agent/      # EKM agent (Windows/Linux)
│   ├── secrets/        # Secret vault
│   ├── compliance/     # Compliance engine
│   ├── posture/        # Security posture
│   ├── governance/     # Approval workflows
│   ├── cloud/          # Cloud BYOK/HYOK
│   ├── kmip/           # KMIP server
│   ├── pqc/            # Post-quantum crypto
│   ├── qkd/            # Quantum key distribution
│   ├── qrng/           # Quantum RNG
│   ├── mpc/            # Multi-party computation
│   ├── dataprotect/    # Tokenization & masking
│   ├── payment/        # Payment HSM
│   ├── discovery/      # Crypto discovery
│   ├── reporting/      # Alerts & analytics
│   ├── sbom/           # SBOM tracking
│   ├── ai/             # AI model encryption
│   ├── hsm-integration/# HSM backend
│   ├── pkcs11-provider/# PKCS#11 shared library
│   └── jca-provider/   # Java JCA provider
├── pkg/                # Shared Go packages
├── web/dashboard/      # React dashboard (Vite + TypeScript)
├── infra/              # Infrastructure configs
│   ├── certs/          # TLS certificate templates
│   ├── consul/         # Consul service mesh
│   ├── deployment/     # Deployment manifests
│   ├── envoy/          # Envoy proxy configs
│   ├── network/        # Network policies
│   ├── packer/         # VM image builds
│   ├── scripts/        # Infrastructure scripts
│   ├── security/       # Security policies
│   └── systemd/        # Systemd service units
├── proto/              # gRPC/Protobuf definitions
├── scripts/            # Build and utility scripts
└── local-data/         # Runtime data (SQLite, logs, certs)
```

## Runtime Documentation

See [RUNTIME_CONTROL_FLOW.md](RUNTIME_CONTROL_FLOW.md) for the complete runtime control flow map of all services and feature profiles.

## License

Proprietary. All rights reserved.
