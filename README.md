# Vecta KMS

Vecta KMS is a multi-service key management platform for centralized cryptographic operations, internal PKI, SCIM-based identity provisioning, workload identity, attested key release, payment crypto, compliance, and security posture management.

This README is the landing page. Detailed operator documentation now lives under [`docs/`](docs/README.md).

## Documentation Map

- [Documentation Index](docs/README.md)
  - Start here for role-based and task-based reading paths.
- [Component Guide](docs/COMPONENT_GUIDE.md)
  - Explains what each major service does, who uses it, when to use it, and the main UI/API entry points.
- [Architecture Guide](docs/ARCHITECTURE.md)
  - Explains how the platform is structured, where trust boundaries live, and how the services fit together.
- [Administrator Guide](docs/ADMIN_GUIDE.md)
  - Explains the dashboard navigation, day-0/day-1/day-2 operator tasks, and how admins should use each major module.
- [Feature Reference](docs/FEATURE_REFERENCE.md)
  - Provides product-style explanations for the major security and crypto features, including when to use them and what they affect.
- [Operations Guide](docs/OPERATIONS_GUIDE.md)
  - Covers installation, startup, health checks, backups, cluster operations, and troubleshooting.
- [Workflow Examples](docs/WORKFLOW_EXAMPLES.md)
  - End-to-end examples for onboarding apps, PKI automation, payment policy, workload identity, PQC migration, and more.
- [REST API Additions](docs/REST_API_ADDITIONS.md)
  - Detailed REST notes and expanded API coverage for the newer features.
- Service-specific references:
  - [KMIP Service](services/kmip/README.md)
  - [Posture Service](services/posture/README.md)
  - [HSM Integration](services/hsm-integration/README.md)
  - [EKM Agent](services/ekm-agent/README.md)

## Platform Overview

Vecta KMS is organized into five working areas:

- Core control plane
  - `keycore`, `auth`, `policy`, `audit`, `governance`, `cluster-manager`
- Certificate, secret, and data protection services
  - `certs`, `secrets`, `dataprotect`, `software-vault`
- External integration surfaces
  - `cloud`, `ekm`, `kmip`, `payment`, `hsm-integration`, `ekm-agent`
- Assurance and operations
  - `compliance`, `posture`, `reporting`, `discovery`, `sbom`
- Advanced crypto and identity
  - `autokey`, `keyaccess`, `signing`, `workload`, `confidential`, `pqc`, `qkd`, `qrng`, `mpc`, `ai`

## Service Map

| Service | Main Role | Typical Use Cases |
| --- | --- | --- |
| `keycore` | Key lifecycle and crypto execution | application keys, wrap/unwrap, sign/verify, encryption, KEM |
| `auth` | Identity, tenants, users, clients | login, RBAC, SCIM provisioning, SSO, API clients, sender-constrained auth |
| `audit` | Tamper-evident event storage | audit review, investigations, control evidence |
| `policy` | Runtime guardrails | algorithm restrictions, approval requirements, access policy |
| `governance` | Quorum and operational approvals | destructive actions, backups, posture controls, FDE checks |
| `cluster-manager` | Cluster profile and replication control | multi-node deployments, sync policy, node lifecycle |
| `certs` | Internal PKI and certificate automation | CA hierarchy, ACME, ACME ARI/STAR, EST, SCEP, CRL/OCSP, renewal intelligence |
| `secrets` | Secret storage and generation | application secrets, generated credentials, Vault-style access |
| `dataprotect` | Tokenization and masking | PCI tokenization, data masking, FPE-style data protection |
| `cloud` | BYOK/HYOK orchestration | cloud key import, sync, rotation tracking |
| `ekm` | External key manager and database protection | TDE keys, BitLocker, agent-managed database encryption |
| `kmip` | KMIP protocol server | HSM clients, appliances, middleware, enterprise tools |
| `payment` | Payment key management and crypto | TR-31, PIN, CVV, MAC, ISO 20022, AP2 |
| `compliance` | Framework scoring and assessments | PCI DSS, FIPS, NIST, evidence review |
| `posture` | Risk detection and remediation | drift detection, findings, blast radius, actions |
| `reporting` | Alerts and reports | MTTR/MTTD, incident reporting, scheduled exports |
| `discovery` | Crypto asset inventory | scan results, asset classification, posture input |
| `sbom` | SBOM/CBOM and vulnerability context | software inventory, PQC readiness, compliance input |
| `autokey` | Policy-driven key handle provisioning | self-service key requests under central policy |
| `keyaccess` | External key-use justification policy | HYOK/EKM/cloud decrypt or sign requests with reason codes and approvals |
| `signing` | Artifact and code signing control plane | Git, blob, and OCI signing with workload or OIDC identity constraints |
| `workload` | SPIFFE/SVID and workload identity | workload-to-key auth, token exchange, federation |
| `confidential` | Attested key release | enclave/TEE gated key release |
| `pqc` | Post-quantum migration and policy | ML-KEM, ML-DSA, SLH-DSA, hybrid rollout |
| `qkd`, `qrng`, `mpc`, `ai` | Specialist advanced crypto capabilities | quantum integrations, FROST-style threshold ceremonies, AI model protection |

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Bash 4+ on macOS and Linux
- Optional for development:
  - Go 1.26+
  - Node.js 20+ or 22+

### Install

```bash
# Linux
./install.sh

# macOS
./install-macos.sh

# Windows
.\install-windows.ps1
```

### Start and Stop

```bash
./infra/scripts/start-kms.sh
./infra/scripts/healthcheck-enabled-services.sh
./infra/scripts/stop-kms.sh
```

### Common Local URLs

- Dashboard: `http://127.0.0.1:5173/`
- HTTPS edge: `https://127.0.0.1/`
- KMIP mTLS: `127.0.0.1:5696`
- Direct service ports are listed in [`docker-compose.yml`](docker-compose.yml)

## Configuration Model

The deployment is driven by [`infra/deployment/deployment.yaml`](infra/deployment/deployment.yaml).

Important behaviors:

- feature selection determines active Compose profiles
- startup scripts translate deployment YAML into runtime environment and protocol settings
- cluster state is replicated selectively by component
- backup coverage is component-aware and documented through governance metadata

For configuration details, see:

- [Deployment Documentation](infra/deployment/README.md)
- [Script Documentation](infra/scripts/README.md)

## Recommended Reading Paths

### Platform Admin

1. [Documentation Index](docs/README.md)
2. [Architecture Guide](docs/ARCHITECTURE.md)
3. [Administrator Guide](docs/ADMIN_GUIDE.md)
4. [Component Guide](docs/COMPONENT_GUIDE.md)
5. [Feature Reference](docs/FEATURE_REFERENCE.md)
6. [Workflow Examples](docs/WORKFLOW_EXAMPLES.md)
7. [REST API Additions](docs/REST_API_ADDITIONS.md)

### Security and Compliance Team

1. [Architecture Guide](docs/ARCHITECTURE.md)
2. [Feature Reference](docs/FEATURE_REFERENCE.md)
3. [Component Guide -> Compliance, Posture, Audit, Governance](docs/COMPONENT_GUIDE.md)
4. [Workflow Examples -> Incident and evidence workflows](docs/WORKFLOW_EXAMPLES.md)
5. [REST API Additions](docs/REST_API_ADDITIONS.md)

### Application Team

1. [Architecture Guide](docs/ARCHITECTURE.md)
2. [Component Guide -> KeyCore, Auth, Workload Identity, Autokey](docs/COMPONENT_GUIDE.md)
3. [Feature Reference](docs/FEATURE_REFERENCE.md)
4. [Workflow Examples -> App onboarding and workload identity](docs/WORKFLOW_EXAMPLES.md)

### PKI or Integration Team

1. [Architecture Guide](docs/ARCHITECTURE.md)
2. [Component Guide -> Certs, KMIP, EKM, Cloud, HSM Integration](docs/COMPONENT_GUIDE.md)
3. [Feature Reference](docs/FEATURE_REFERENCE.md)
4. [Workflow Examples -> PKI automation and EKM/TDE examples](docs/WORKFLOW_EXAMPLES.md)

## Development

```bash
# Run service tests
go test ./...

# Build dashboard
docker run --rm -v "$PWD":/src -w /src/web/dashboard node:22-bookworm bash -lc 'npm ci && npm run build'

# Validate compose
docker compose config -q
```

## Notes

- Generated dashboard bundles under `web/dashboard/dist/` are tracked in this repository.
- Newer feature surfaces are documented first in markdown under `docs/`, then reflected in the dashboard docs tab and generated REST catalog.
- When in doubt, prefer the component guide for behavior and the REST additions file for route-level detail.
