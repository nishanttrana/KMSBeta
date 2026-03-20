# Vecta KMS

Enterprise Key Management System with full lifecycle cryptographic operations, compliance frameworks, and multi-cloud key orchestration.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 Web Dashboard (React 19 / Vite 8)               │
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
| **certs** | 8443 | X.509 certificate authority — issue, renew, revoke, CRL/OCSP, ACME Renewal Information (RFC 9773) |
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
| **payment** | — | Payment HSM integration (PCI PIN, DUKPT, TR-31, ISO 20022, AP2 agent payments) |
| **autokey** | — | Policy-driven Autokey templates, key handle provisioning, and approval-backed self-service requests |
| **confidential** | — | Attested key release for TEEs/enclaves with claim, measurement, and cluster-node policy |
| **workload** | — | SPIFFE trust domains, SVID issuance, federation, and workload-to-key authorization |
| **dataprotect** | — | Data protection — tokenization, masking, format-preserving encryption |
| **sbom** | — | Software Bill of Materials tracking and vulnerability scanning |
| **ai** | — | AI/ML model encryption and key management |
| **software-vault** | — | Software-based secure enclave for key storage |
| **cluster-manager** | — | Raft-based cluster coordination, leader election, replication |
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
| `payment` | Payment HSM, AP2 agent payment policy, and payment protocol helpers |

## Certificate Lifecycle Automation

The PKI stack now supports coordinated certificate renewal with ACME Renewal Information (RFC 9773), not just fixed alert windows.

- Each active certificate gets a coordinated renewal window and scheduled renewal time.
- The dashboard surfaces renewal windows, CA-directed renewal schedules, and mass-renewal hotspots.
- Audit and compliance surface missed renewal windows and emergency rotation events.
- ACME clients can consume renewal guidance from `GET /acme/renewal-info/{id}` and respect `Retry-After` for the next poll.
- `infra/deployment/deployment.yaml` now supports `spec.cert_security.acme_renewal`, and the runtime start scripts apply that policy automatically on boot.
- Cluster replication treats renewal intelligence as part of the `certs` control-plane state, and encrypted backups preserve it when certificate tables are included.
| `pdfutil` | PDF generation for compliance reports |
| `ratelimit` | Rate limiting middleware |
| `runtimecfg` | Runtime configuration hot-reload |

## Quick Start

### Prerequisites

- Go 1.26+
- Node.js 20.19+ or 22.12+ (for dashboard)
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

The installer generates `infra/deployment/deployment.yaml`, understands the newer optional profiles such as `autokey_provisioning`, `posture_management`, `qrng_generator`, `workload_identity`, and `confidential_compute`, supports built-in cluster replication presets (`cluster-profile-base`, `cluster-profile-standard`, `cluster-profile-security`, and `cluster-profile-full`), and now writes ACME renewal coordination defaults under `spec.cert_security.acme_renewal`.

## Policy-Driven Autokey / Key Handle Provisioning

- Autokey is a dedicated tenant-scoped capability for policy-driven key handle provisioning.
- It gives teams a self-service request path while keeping the real key shape under central KMS policy.
- The operator UI is a dedicated top-level `Autokey` module immediately after `Data Protection`.

### What It Adds

- resource templates for handle naming, key naming, algorithm, purpose, and labels
- per-service default policies
- approval flow for key-handle creation
- real provisioning through KeyCore after policy resolution and optional governance approval
- managed handle catalog for tenant workloads and services

### REST API

- `GET /svc/autokey/autokey/settings?tenant_id=root`
- `PUT /svc/autokey/autokey/settings?tenant_id=root`
- `GET /svc/autokey/autokey/templates?tenant_id=root`
- `POST /svc/autokey/autokey/templates`
- `PUT /svc/autokey/autokey/templates/{id}`
- `DELETE /svc/autokey/autokey/templates/{id}`
- `GET /svc/autokey/autokey/service-policies?tenant_id=root`
- `POST /svc/autokey/autokey/service-policies`
- `PUT /svc/autokey/autokey/service-policies/{service}`
- `DELETE /svc/autokey/autokey/service-policies/{service}`
- `POST /svc/autokey/autokey/requests`
- `GET /svc/autokey/autokey/requests?tenant_id=root`
- `GET /svc/autokey/autokey/requests/{id}?tenant_id=root`
- `GET /svc/autokey/autokey/handles?tenant_id=root`
- `GET /svc/autokey/autokey/summary?tenant_id=root`

### Audit, Cluster, Posture, Compliance, Backup

- Audit events:
  - `audit.autokey.settings_updated`
  - `audit.autokey.template_upserted`
  - `audit.autokey.service_policy_upserted`
  - `audit.autokey.request_pending_approval`
  - `audit.autokey.request_provisioned`
  - `audit.autokey.request_denied`
  - `audit.autokey.request_failed`
- Cluster:
  - built-in cluster profiles now include Autokey where appropriate
  - the cluster control plane treats Autokey templates, defaults, requests, and handles as shared component state
- Posture / compliance:
  - the live dashboards now surface Autokey approval backlog, policy mismatches, and managed-handle coverage
- Backup:
  - encrypted backup coverage now explicitly includes Autokey tables when present

### Using Autokey

1. Open `Autokey`.
2. Enable tenant Autokey and choose `enforce` or `audit`.
3. Save one or more resource templates.
4. Save per-service defaults for each application or platform service.
5. Submit a provisioning request for a resource.
6. If approval is required, approve it in `Governance`.
7. Review the resulting managed handle and the backing KeyCore key binding.

### Dependency Baseline

- Dashboard toolchain: React 19, Vite 8, Tailwind CSS 4, Vitest 4
- Core transport/runtime libraries: `github.com/nats-io/nats.go` 1.49, `github.com/redis/go-redis/v9` 9.18, `github.com/golang-jwt/jwt/v5` 5.3
- Verified with `npm audit` and `govulncheck` after the upgrade pass

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
| dashboard-ui | 5173 | HTTP / HTTPS | Direct web dashboard |
| rest-api | 443 | HTTPS / TLS 1.3 / mTLS | Primary REST API |
| kmip-tls | 5696 | mTLS | KMIP protocol |
| ekm-data | 8130 | HTTP / HTTPS / TLS 1.3 | EKM/TDE endpoint |
| payment-tcp | 9170 | TCP | Payment crypto endpoint |
| hyok-api | 8120 | HTTP / HTTPS / TLS 1.3 | HYOK endpoint |

### Runtime TLS And Interface Precedence

- `System Administration -> Runtime Crypto -> Configure TLS` is the authoritative certificate binding for user-facing TLS interfaces.
- `System Administration -> Interfaces` controls bind address, port, listener protocol, and enable/disable state for request-handling endpoints.
- If an interface uses `HTTPS`, `TLS 1.3`, or `mTLS`, the certificate source selected in Runtime Crypto wins over any interface-level certificate fields.
- Certificate binding can be backed by:
  - internal CA auto-issuance
  - a CA selected from the PKI / CA inventory
  - an uploaded certificate selected from the PKI / CA inventory

### Runtime TLS API

- `GET /svc/keycore/access/interface-tls-config?tenant_id=root`
  - returns the effective certificate binding used by TLS-enabled request interfaces
- `PUT /svc/keycore/access/interface-tls-config`
  - updates the authoritative TLS certificate binding and reapplies it to TLS-enabled interfaces
- `GET /svc/keycore/access/interface-ports?tenant_id=root`
  - returns the effective request interfaces after the runtime TLS binding has been applied

## Sender-Constrained REST Client Security

- KMS now supports real sender-constrained REST client authentication for SDKs, agents, and automation:
  - OAuth mTLS
  - DPoP
  - HTTP Message Signatures
- Operators manage this from `REST API -> REST Client Security`.
- Each client registration now carries:
  - `auth_mode`
  - replay protection state
  - certificate or public-key binding data
  - verification counters for accepted, replayed, unsigned, and signature-failed requests
- REST endpoints:
  - `POST /svc/auth/auth/client-token`
  - `GET /svc/auth/auth/clients`
  - `PUT /svc/auth/auth/clients/{id}`
  - `GET /svc/auth/auth/rest-client-security/summary`
- Audit events:
  - `audit.auth.mtls_binding_failed`
  - `audit.auth.client_dpop_failed`
  - `audit.auth.dpop_replay_detected`
  - `audit.auth.client_http_signature_failed`
  - `audit.auth.http_signature_replay_detected`
  - `audit.auth.rest_client_security_viewed`
  - `audit.key.rest_mtls_binding_failed`
  - `audit.key.rest_signature_failed`
  - `audit.key.rest_unsigned_blocked`
  - `audit.key.request_replay_detected`
- Posture and compliance now surface:
  - how many REST clients still use replayable bearer/API-key mode
  - replay violations
  - signature verification failures
  - unsigned call blocks
- Cluster and backup behavior:
  - sender-constrained client registrations and counters are shared control-plane state and replicate with the `auth` component
  - short-lived replay nonce caches remain node-local and are excluded from encrypted backups by design

### Choosing A REST Client Auth Mode

1. Use `OAuth mTLS` when the client can present a managed client certificate end to end.
2. Use `DPoP` when the client is browserless or agent-based and can mint a proof JWT per request.
3. Use `HTTP Message Signatures` when the client already owns a long-term signing key and needs explicit request-component signing and body digest verification.
4. Leave `API Key / Bearer` only for transitional clients; posture and compliance treat it as non-compliant until migrated.

### Example: Move A Client To DPoP

```bash
curl -X PUT http://localhost:8001/auth/clients/reg_123?tenant_id=root \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_mode": "dpop",
    "replay_protection_enabled": true,
    "rate_limit": 1500,
    "ip_whitelist": ["10.10.10.0/24"]
  }'
```

After that, the client obtains its bearer token from `/auth/client-token` with a valid DPoP proof and sends a fresh DPoP proof on every protected REST request.

## Payment Policy and AP2

- Payment policy is now a dedicated screen separate from tokenization.
- The operator UI splits payment controls into:
  - `Traditional Payment`: TR-31, KBPK, PIN, CVV, MAC, Payment TCP, and runtime handling guardrails
  - `Modern Payment`: ISO 20022 and AP2 agent-payment policy
- The REST model remains stable:
  - `GET /svc/payment/payment/policy?tenant_id=root`
  - `PUT /svc/payment/payment/policy?tenant_id=root`
  - `GET /svc/payment/payment/ap2/profile?tenant_id=root`
  - `PUT /svc/payment/payment/ap2/profile?tenant_id=root`
  - `POST /svc/payment/payment/ap2/evaluate`
- AP2 policy covers:
  - allowed protocol binding (`a2a`, `mcp`, optional `x402`)
  - allowed rails and currencies
  - human-present vs human-not-present thresholds
  - required intent/cart/payment mandates
  - required merchant signature, verifiable credential, wallet attestation, risk signals, and tokenized instrument
- Payment policy and AP2 activity are auditable end-to-end:
  - `audit.payment.policy_updated`
  - `audit.payment.ap2_profile_updated`
  - `audit.payment.ap2_evaluated`
- Traditional payment policy, modern ISO 20022 policy, and AP2 state are persisted as tenant payment control-plane data, so they follow the same shared cluster and backup path as the rest of the payment service rather than living in node-local files.

### Using Payment Policy and AP2

1. Open `Data Protection -> Payment Policy`.
2. Use `Traditional Payment` to save TR-31, KBPK, PIN, CVV, MAC, TCP, and runtime guardrails.
3. Use `Modern Payment` to save ISO 20022 and AP2 trust policy for the tenant.
4. Open `Workbench -> Payment Crypto` to test and execute traditional or modern payment operations.
5. Use the AP2 evaluator there, or call `POST /svc/payment/payment/ap2/evaluate`, with the protocol binding, rail, amount, currency, and proof flags for mandates, credentials, wallet trust, and tokenization.
6. Use the returned `allow`, `review`, or `deny` decision to gate the downstream payment authorization flow.

Example:

```bash
curl -X PUT http://localhost:8170/payment/ap2/profile?tenant_id=root \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "enabled": true,
    "allowed_protocol_bindings": ["a2a", "mcp"],
    "allowed_payment_rails": ["card", "ach", "rtp"],
    "allowed_currencies": ["USD", "EUR"],
    "default_currency": "USD",
    "require_intent_mandate": true,
    "require_cart_mandate": true,
    "require_payment_mandate": true,
    "require_verifiable_credential": true,
    "require_risk_signals": true,
    "require_tokenized_instrument": true,
    "max_human_present_amount_minor": 1000000,
    "max_human_not_present_amount_minor": 250000
  }'
```

## Production-Grade Post-Quantum Crypto

- Post-Quantum Crypto is a dedicated tenant-scoped capability for production PQC policy, readiness, and migration.
- UI path:
  - `Post-Quantum Crypto`
- Docker profile:
  - `pqc_migration`
- Service:
  - `kms-pqc` on `8060 / 18060`

What it does:
- Adds real PQC key material support in Key Management for:
  - `ML-KEM-768`
  - `ML-KEM-1024`
  - `ML-DSA-65`
  - `ML-DSA-87`
  - `SLH-DSA`
- Stores a tenant PQC policy profile with defaults for KEM, signatures, interface mode, and certificate mode.
- Classifies key, certificate, and request-handling interface inventory as `classical`, `hybrid`, or `pqc_only`.
- Produces a migration report that highlights:
  - where RSA / ECC is still used
  - non-migrated interfaces
  - non-migrated certificates
  - next recommended actions and target milestones
- Lets TLS-capable interfaces inherit the tenant PQC policy or override to `classical`, `hybrid`, or `pqc_only` from `Administration -> Interfaces`.

Control-plane surfaces:
- REST:
  - `GET /svc/pqc/pqc/policy?tenant_id=root`
  - `PUT /svc/pqc/pqc/policy?tenant_id=root`
  - `GET /svc/pqc/pqc/inventory?tenant_id=root`
  - `POST /svc/pqc/pqc/scan`
  - `GET /svc/pqc/pqc/readiness?tenant_id=root`
  - `GET /svc/pqc/pqc/migration/report?tenant_id=root`
  - `POST /svc/pqc/pqc/migration/plans`
  - `GET /svc/pqc/pqc/timeline?tenant_id=root`
  - `GET /svc/pqc/pqc/cbom/export?tenant_id=root`
- Audit:
  - `audit.pqc.policy_viewed`
  - `audit.pqc.policy_updated`
  - `audit.pqc.inventory_viewed`
  - `audit.pqc.migration_report_viewed`
  - existing scan / migration audit subjects remain active
- Cluster / backup:
  - policy and migration state are shared PostgreSQL control-plane state
  - cluster profiles can include `pqc`
  - backup coverage includes PQC readiness, policy, migration plans, and runs

Recommended operator flow:
1. Open `Post-Quantum Crypto`.
2. Select a tenant policy profile such as `Balanced Hybrid` or `Quantum First`.
3. Set the default ML-KEM and signature family.
4. Run a readiness scan.
5. Review the live inventory split across keys, certificates, and interfaces.
6. Move TLS-capable interfaces to `hybrid` or `pqc_only` where compatibility allows.
7. Use the migration report to sequence RSA / ECC retirement.

Standards context:
- NIST finalized the first three PQC standards in August 2024:
  - [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
  - [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
  - [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
- NIST selected HQC in March 2025 as the backup KEM track:
  - [NIST announcement](https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption)

## Attested Key Release / Confidential Compute

- Confidential Compute is a dedicated tenant-scoped capability for attested key release.
- UI path:
  - `Confidential Compute`
- Docker profile:
  - `confidential_compute`
- Service:
  - `kms-confidential` on `8240 / 18240`

What it does:
- Releases keys only to workloads whose enclave or TEE evidence matches tenant policy.
- Supports provider-aware policy for:
  - AWS Nitro Enclaves
  - AWS NitroTPM
  - Azure Secure Key Release
  - GCP Confidential Space
  - generic attestation brokers
- For AWS, Azure, and GCP, the service now performs real provider-side cryptographic verification before policy evaluation:
  - AWS: COSE_Sign1 signature validation plus AWS Nitro certificate-chain verification
  - Azure: issuer discovery and JWKS validation for Azure Attestation JWTs
  - GCP: issuer discovery and JWKS validation for Confidential Space attestation JWTs
- Enforces approved key scopes, approved workload images, approved workload subjects, allowed attesters, required claims, required measurements, secure boot, debug-disabled posture, evidence freshness, and optional cluster-node allowlists.

Control-plane surfaces:
- REST:
  - `GET /svc/confidential/confidential/policy?tenant_id=root`
  - `PUT /svc/confidential/confidential/policy?tenant_id=root`
  - `GET /svc/confidential/confidential/summary?tenant_id=root`
  - `POST /svc/confidential/confidential/evaluate`
  - `GET /svc/confidential/confidential/releases?tenant_id=root`
  - `GET /svc/confidential/confidential/releases/{id}?tenant_id=root`
- Audit:
  - `audit.confidential.policy_updated`
  - `audit.confidential.key_release_evaluated`
- Cluster / backup:
  - policy and release history are shared PostgreSQL control-plane state, not node-local files
  - cluster profiles can include `confidential`
  - backup coverage metadata includes `attested_key_release_and_confidential_compute`

Recommended operator flow:
1. Open `Confidential Compute`.
2. Save a tenant policy with provider, approved images, approved workload identities, required claims, required measurements, and cluster-node constraints.
3. Use `Evaluate Release` with a real or dry-run attestation payload to confirm the decision path.
4. For AWS, Azure, and GCP, send the signed provider attestation document instead of synthetic claims; the service will derive signed claims and measurements from the document after cryptographic verification.
5. Review `Release History` and `Audit Log` for decision evidence and rollout troubleshooting.

Example policy save:

```bash
curl -X PUT http://localhost:8240/confidential/policy?tenant_id=root \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "enabled": true,
    "provider": "aws_nitro_enclaves",
    "mode": "enforce",
    "key_scopes": ["payments-prod", "signing-prod"],
    "approved_images": [
      "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/authorizer:v1.4.2",
      "sha256:1f2d3c4b5a6978877665544332211000aabbccddeeff00112233445566778899"
    ],
    "approved_subjects": ["spiffe://root/workloads/payments-authorizer"],
    "allowed_attesters": ["aws.nitro-enclaves"],
    "required_claims": {
      "environment": "prod",
      "team": "payments"
    },
    "required_measurements": {
      "pcr0": "baseline-image-hash",
      "pcr8": "secure-boot-chain-hash"
    },
    "require_secure_boot": true,
    "require_debug_disabled": true,
    "max_evidence_age_sec": 300,
    "cluster_scope": "node_allowlist",
    "allowed_cluster_nodes": ["vecta-kms-01", "vecta-kms-02"],
    "fallback_action": "deny"
  }'
```

Example AWS evaluation:

```bash
curl -X POST http://localhost:8240/confidential/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "key_id": "key-prod-root",
    "key_scope": "payments-prod",
    "provider": "aws_nitro_enclaves",
    "attestation_format": "cose_sign1",
    "attestation_document": "BASE64_AWS_NITRO_ATTESTATION_DOCUMENT",
    "audience": "kms-key-release",
    "nonce": "nonce-demo-001",
    "cluster_node_id": "vecta-kms-01",
    "requester": "platform-ops",
    "release_reason": "authorize payment enclave",
    "dry_run": true
  }'
```

Example Azure or GCP evaluation:

```bash
curl -X POST http://localhost:8240/confidential/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "key_id": "key-prod-root",
    "key_scope": "payments-prod",
    "provider": "azure_secure_key_release",
    "attestation_format": "jwt",
    "attestation_document": "SIGNED_PROVIDER_ATTESTATION_JWT",
    "audience": "kms-key-release",
    "cluster_node_id": "vecta-kms-01",
    "requester": "platform-ops",
    "release_reason": "authorize attested key release",
    "dry_run": true
  }'
```

Operational notes:
- Azure and GCP verification require outbound HTTPS from `kms-confidential` to the issuer discovery and JWKS endpoints.
- AWS verification is self-contained once the service trusts the embedded Nitro root certificate or an override configured through `CONFIDENTIAL_AWS_ROOT_PEM_PATH`.
- Audit and release history now record cryptographic verification status, verification issuer, verification key ID, attestation document hash, and document format.

```bash
curl -X POST http://localhost:8170/payment/ap2/evaluate?tenant_id=root \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "agent_id": "shopping-agent-1",
    "merchant_id": "merchant-demo",
    "operation": "authorize",
    "protocol_binding": "a2a",
    "transaction_mode": "human_not_present",
    "payment_rail": "card",
    "currency": "USD",
    "amount_minor": 12500,
    "has_intent_mandate": true,
    "has_cart_mandate": true,
    "has_payment_mandate": true,
    "has_merchant_signature": true,
    "has_verifiable_credential": true,
    "has_risk_signals": true,
    "payment_instrument_tokenized": true
  }'
```

## Workload Identity / SPIFFE

- Workload Identity is a dedicated tenant-scoped capability for SPIFFE trust domains, SVID issuance, federation, and workload-to-key authorization.
- UI path:
  - `Workload Identity`
- Docker profile:
  - `workload_identity`
- Service:
  - `kms-workload-identity` on `8250 / 18250`

What it does:
- Issues local X.509-SVIDs and JWT-SVIDs for registered workloads.
- Maintains a tenant SPIFFE trust domain and optional federated trust bundles.
- Exchanges valid SVIDs into short-lived KMS bearer tokens instead of static API keys.
- Carries workload identity, trust domain, interface name, and scoped key bindings into key-operation audit events.

Control-plane surfaces:
- REST:
  - `GET /svc/workload/workload-identity/settings?tenant_id=root`
  - `PUT /svc/workload/workload-identity/settings?tenant_id=root`
  - `GET /svc/workload/workload-identity/summary?tenant_id=root`
  - `GET /svc/workload/workload-identity/registrations?tenant_id=root`
  - `POST /svc/workload/workload-identity/registrations`
  - `PUT /svc/workload/workload-identity/registrations/{id}`
  - `DELETE /svc/workload/workload-identity/registrations/{id}?tenant_id=root`
  - `GET /svc/workload/workload-identity/federation?tenant_id=root`
  - `POST /svc/workload/workload-identity/federation`
  - `PUT /svc/workload/workload-identity/federation/{id}`
  - `DELETE /svc/workload/workload-identity/federation/{id}?tenant_id=root`
  - `POST /svc/workload/workload-identity/issue`
  - `GET /svc/workload/workload-identity/issuances?tenant_id=root`
  - `POST /svc/workload/workload-identity/token/exchange`
  - `GET /svc/workload/workload-identity/graph?tenant_id=root`
  - `GET /svc/workload/workload-identity/usage?tenant_id=root`
- Audit:
  - `audit.workload.settings_updated`
  - `audit.workload.registration_upserted`
  - `audit.workload.registration_deleted`
  - `audit.workload.federation_bundle_upserted`
  - `audit.workload.federation_bundle_deleted`
  - `audit.workload.svid_issued`
  - `audit.workload.token_exchanged`
  - `audit.workload.summary_viewed`
  - `audit.workload.graph_viewed`
  - `audit.workload.key_usage_viewed`
- Cluster / backup:
  - workload identity settings, registrations, federation bundles, and issuance history are shared PostgreSQL control-plane state
  - cluster profiles can include `workload`
  - backup coverage includes `workload_identity_and_spiffe_federation`

Recommended operator flow:
1. Open `Workload Identity`.
2. Enable the tenant trust domain and disable static API keys for workload callers.
3. Register workloads with SPIFFE IDs, allowed interfaces, allowed permissions, and allowed key IDs.
4. Add federated bundles for external trust domains if multi-cluster or partner workloads must authenticate.
5. Issue a JWT-SVID or X.509-SVID for a workload.
6. Exchange that SVID into a short-lived KMS token for the target interface.
7. Review the workload-to-key graph and recent workload key usage to confirm least-privilege behavior.

Example registration:

```bash
curl -X POST http://localhost:8250/workload-identity/registrations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "name": "payments-api",
    "spiffe_id": "spiffe://root/workloads/payments-api",
    "selectors": ["docker:image:payments-api", "env:prod"],
    "allowed_interfaces": ["rest", "payment-tcp"],
    "allowed_key_ids": ["key_payments_prod"],
    "permissions": ["key.encrypt", "key.decrypt", "key.sign"],
    "issue_jwt_svid": true,
    "issue_x509_svid": true,
    "enabled": true
  }'
```

Example token exchange:

```bash
curl -X POST http://localhost:8250/workload-identity/token/exchange \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "registration_id": "wid_abcd1234",
    "interface_name": "rest",
    "audience": "kms",
    "requested_permissions": ["key.encrypt", "key.decrypt"],
    "jwt_svid": "eyJhbGciOiJFZERTQSIsImtpZCI6IndpZC1yb290In0..."
  }'
```

## Security Features

- **FIPS 140-3** compliant cryptographic module (strict/standard modes)
- **Post-quantum** ready: ML-KEM, ML-DSA, SLH-DSA, hybrid key exchange
- **HSM integration**: PKCS#11, proprietary APIs, key reference model
- **mTLS everywhere**: Certificate-based service-to-service authentication
- **Strict JWT validation**: RS256 service tokens require `exp` and `iat`, and request parsers enforce issuer/audience bindings with bounded leeway
- **Tamper-evident audit**: Blockchain-anchored hash chain for log integrity
- **Quorum approvals**: M-of-N approval workflows for sensitive operations
- **Shamir secret sharing**: Recovery key splitting (3-of-5 default)
- **Key cache security**: mlock'd memory, automatic zeroization on eviction
- **Resilient event streaming**: NATS clients use hardened reconnect, ping, and buffer defaults across services
- **TLS-forward cache defaults**: Valkey/Redis connections use bounded timeouts, connection lifetime limits, and a TLS 1.3 floor when `rediss://` is configured
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

See [docs/REST_API_ADDITIONS.md](docs/REST_API_ADDITIONS.md) for detailed REST API documentation covering the newer AI configuration, AI assistant, SBOM vulnerability, offline advisory, CBOM readiness, posture dashboards, compliance deltas, evidence packs, and alert timing workflows.

See [docs/openapi/README.md](docs/openapi/README.md) for generated OpenAPI/Swagger specs for the AI, SBOM/CBOM, posture, compliance, and reporting service APIs.

## License

Proprietary. All rights reserved.
