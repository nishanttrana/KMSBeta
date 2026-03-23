# Vecta KMS Documentation

Vecta KMS is an enterprise-grade, multi-tenant key management platform providing cryptographic key lifecycle management, PKI, data protection, cloud integration, workload identity, compliance, and advanced infrastructure features including HSM, QKD, QRNG, and MPC/FROST threshold signing.

---

## Documentation Map

### Start Here

| Document | Audience | What It Covers |
|---|---|---|
| [GETTING_STARTED.md](GETTING_STARTED.md) | Everyone | Architecture overview, first login, first key, security model, dashboard tour |
| [KEYS.md](KEYS.md) | All users | Key lifecycle, algorithms, access policy, crypto operations, rotation |
| [CERTIFICATES.md](CERTIFICATES.md) | PKI, platform | PKI hierarchy, certificate lifecycle, ACME/EST/SCEP/CMPv2, STAR, ARI |
| [DATA_PROTECTION.md](DATA_PROTECTION.md) | App, data teams | Tokenization, FPE, masking, payment crypto, PKCS#11/JCA, Autokey |
| [CLOUD_INTEGRATION.md](CLOUD_INTEGRATION.md) | Cloud, integration | BYOK, HYOK, EKM/TDE, KMIP, artifact signing |
| [IDENTITY_AND_PQC.md](IDENTITY_AND_PQC.md) | Security, platform | Workload identity, confidential compute, key access justifications, PQC migration |
| [GOVERNANCE_AND_COMPLIANCE.md](GOVERNANCE_AND_COMPLIANCE.md) | Compliance, ops | Audit log, governance/approvals, compliance frameworks, alerts, posture, SBOM |
| [INFRASTRUCTURE.md](INFRASTRUCTURE.md) | Platform, ops | HSM integration, cluster management, QKD, QRNG, MPC/FROST |
| [ADMINISTRATION.md](ADMINISTRATION.md) | Administrators | Users, tenants, IdP, SCIM, API clients, FIPS, network config |
| [API_REFERENCE.md](API_REFERENCE.md) | Developers | Complete endpoint reference, schemas, curl examples, error codes |

### Legacy/Additional Docs

| Document | What It Covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Service architecture, trust boundaries |
| [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md) | Per-component quick reference |
| [FEATURE_REFERENCE.md](FEATURE_REFERENCE.md) | Feature overview (concise) |
| [OPERATIONS_GUIDE.md](OPERATIONS_GUIDE.md) | Install, startup, health, backup, cluster |
| [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md) | Step-by-step scenario walkthroughs |
| [REST_API_ADDITIONS.md](REST_API_ADDITIONS.md) | Supplementary REST surface detail |
| [ADMIN_GUIDE.md](ADMIN_GUIDE.md) | Operator day-to-day guidance |
| [openapi/](openapi/) | OpenAPI specifications |

---

## Read By Role

### Platform Administrator
1. [GETTING_STARTED.md](GETTING_STARTED.md) — architecture and first login
2. [ADMINISTRATION.md](ADMINISTRATION.md) — users, tenants, FIPS, network
3. [KEYS.md](KEYS.md) — key creation, access policy
4. [INFRASTRUCTURE.md](INFRASTRUCTURE.md) — HSM, cluster
5. [GOVERNANCE_AND_COMPLIANCE.md](GOVERNANCE_AND_COMPLIANCE.md) — backups, approvals, audit

### Security Architect
1. [GETTING_STARTED.md](GETTING_STARTED.md) — security model
2. [IDENTITY_AND_PQC.md](IDENTITY_AND_PQC.md) — workload identity, confidential compute, PQC
3. [GOVERNANCE_AND_COMPLIANCE.md](GOVERNANCE_AND_COMPLIANCE.md) — compliance, posture, audit
4. [KEYS.md](KEYS.md) — access policy, interface hardening
5. [CLOUD_INTEGRATION.md](CLOUD_INTEGRATION.md) — HYOK, signing

### Application Developer
1. [GETTING_STARTED.md](GETTING_STARTED.md) — first steps
2. [KEYS.md](KEYS.md) — creating and using keys
3. [API_REFERENCE.md](API_REFERENCE.md) — endpoint reference
4. [DATA_PROTECTION.md](DATA_PROTECTION.md) — tokenization, field encryption
5. [IDENTITY_AND_PQC.md](IDENTITY_AND_PQC.md) — workload identity (no static API keys)

### PKI / Integration Team
1. [CERTIFICATES.md](CERTIFICATES.md) — PKI hierarchy, enrollment protocols
2. [CLOUD_INTEGRATION.md](CLOUD_INTEGRATION.md) — BYOK, HYOK, KMIP, EKM
3. [DATA_PROTECTION.md](DATA_PROTECTION.md) — payment crypto, PKCS#11
4. [API_REFERENCE.md](API_REFERENCE.md) — full endpoint reference

### Compliance / Audit Team
1. [GOVERNANCE_AND_COMPLIANCE.md](GOVERNANCE_AND_COMPLIANCE.md) — all compliance features
2. [IDENTITY_AND_PQC.md](IDENTITY_AND_PQC.md) — PQC readiness, access justifications
3. [KEYS.md](KEYS.md) — key lifecycle audit evidence
4. [API_REFERENCE.md](API_REFERENCE.md) — audit API endpoints

---

## Read By Task

| Task | Document |
|---|---|
| Install and start Vecta KMS | [GETTING_STARTED.md](GETTING_STARTED.md), [OPERATIONS_GUIDE.md](OPERATIONS_GUIDE.md) |
| Create a cryptographic key | [KEYS.md](KEYS.md) |
| Encrypt or sign data | [KEYS.md](KEYS.md), [API_REFERENCE.md](API_REFERENCE.md) |
| Set up internal PKI | [CERTIFICATES.md](CERTIFICATES.md) |
| Configure ACME / EST / SCEP | [CERTIFICATES.md](CERTIFICATES.md) |
| Tokenize PAN / SSN data | [DATA_PROTECTION.md](DATA_PROTECTION.md) |
| Integrate with AWS KMS (BYOK) | [CLOUD_INTEGRATION.md](CLOUD_INTEGRATION.md) |
| Configure Microsoft DKE (HYOK) | [CLOUD_INTEGRATION.md](CLOUD_INTEGRATION.md) |
| Protect MSSQL / Oracle with TDE | [CLOUD_INTEGRATION.md](CLOUD_INTEGRATION.md) |
| Connect a KMIP appliance | [CLOUD_INTEGRATION.md](CLOUD_INTEGRATION.md) |
| Sign container images / Git commits | [CLOUD_INTEGRATION.md](CLOUD_INTEGRATION.md) |
| Set up workload identity (SPIFFE) | [IDENTITY_AND_PQC.md](IDENTITY_AND_PQC.md) |
| Configure TEE attested key release | [IDENTITY_AND_PQC.md](IDENTITY_AND_PQC.md) |
| Plan PQC migration | [IDENTITY_AND_PQC.md](IDENTITY_AND_PQC.md) |
| Require access justification codes | [IDENTITY_AND_PQC.md](IDENTITY_AND_PQC.md) |
| Run a compliance assessment | [GOVERNANCE_AND_COMPLIANCE.md](GOVERNANCE_AND_COMPLIANCE.md) |
| Set up multi-quorum governance | [GOVERNANCE_AND_COMPLIANCE.md](GOVERNANCE_AND_COMPLIANCE.md) |
| Search the audit log | [GOVERNANCE_AND_COMPLIANCE.md](GOVERNANCE_AND_COMPLIANCE.md) |
| Export audit events to SIEM | [GOVERNANCE_AND_COMPLIANCE.md](GOVERNANCE_AND_COMPLIANCE.md) |
| Integrate an HSM | [INFRASTRUCTURE.md](INFRASTRUCTURE.md) |
| Set up a multi-node cluster | [INFRASTRUCTURE.md](INFRASTRUCTURE.md) |
| Configure QKD or QRNG | [INFRASTRUCTURE.md](INFRASTRUCTURE.md) |
| Deploy threshold MPC signing | [INFRASTRUCTURE.md](INFRASTRUCTURE.md) |
| Create users and assign roles | [ADMINISTRATION.md](ADMINISTRATION.md) |
| Configure Okta / Azure AD SSO | [ADMINISTRATION.md](ADMINISTRATION.md) |
| Set up SCIM provisioning | [ADMINISTRATION.md](ADMINISTRATION.md) |
| Enable FIPS mode | [ADMINISTRATION.md](ADMINISTRATION.md) |
| Back up and restore the platform | [GOVERNANCE_AND_COMPLIANCE.md](GOVERNANCE_AND_COMPLIANCE.md) |
| Look up an API endpoint | [API_REFERENCE.md](API_REFERENCE.md) |

---

## Service and API Quick Reference

All API calls use the proxy path `http://{host}/svc/{service}/...`.

| Service Name | Base Path | Primary Feature Area |
|---|---|---|
| `keycore` | `/svc/keycore/` | Key lifecycle, crypto operations, access policy |
| `auth` | `/svc/auth/` | Authentication, users, tenants, clients, IdP, SCIM |
| `certs` | `/svc/certs/` | PKI, certificate lifecycle, enrollment protocols |
| `audit` | `/svc/audit/` | Audit log, alert management, Merkle proofs |
| `governance` | `/svc/governance/` | Governance policies, approvals, backups, system state |
| `reporting` | `/svc/reporting/` | Alert rules, reports, scheduled reports |
| `compliance` | `/svc/compliance/` | Framework scoring, assessment, posture |
| `posture` | `/svc/posture/` | Risk findings, drift detection, remediation |
| `workload` | `/svc/workload/` | Workload identity, SPIFFE/SVID, token exchange |
| `confidential` | `/svc/confidential/` | TEE attestation, attested key release |
| `pqc` | `/svc/pqc/` | PQC policy, inventory, migration planning |
| `keyaccess` | `/svc/keyaccess/` | Access justification rules and audit |
| `dataprotect` | `/svc/dataprotect/` | Tokenization, masking, field encryption |
| `payment` | `/svc/payment/` | TR-31, PIN blocks, ISO 20022 signing |
| `autokey` | `/svc/autokey/` | Key provisioning templates and handle requests |
| `cloud` | `/svc/cloud/` | BYOK, cloud key sync |
| `hyok` | `/svc/hyok/` | HYOK proxy, hold-your-own-key policies |
| `ekm` | `/svc/ekm/` | Database TDE, BitLocker endpoint management |
| `kmip` | `/svc/kmip/` | KMIP profile management, object lifecycle |
| `signing` | `/svc/signing/` | Artifact, blob, Git, container signing |
| `mpc` | `/svc/mpc/` | MPC groups, FROST ceremonies, threshold signing |
| `cluster` | `/svc/cluster/` | Cluster nodes, replication, sync monitoring |
| `qkd` | `/svc/qkd/` | Quantum key distribution links |
| `qrng` | `/svc/qrng/` | Quantum random number generation |
| `secrets` | `/svc/secrets/` | Secret vault storage |
| `sbom` | `/svc/sbom/` | SBOM/CBOM intelligence |
| `ai` | `/svc/ai/` | AI guidance and policy recommendations |

---

## Conventions Used In This Documentation

- API examples use `http://localhost:5173` as the base URL (dashboard dev proxy). Replace with your deployed host.
- `tenant_id=root` is used as the sample tenant ID unless noted otherwise.
- `$TOKEN` refers to the Bearer token from `POST /svc/auth/auth/login`.
- Request body examples use realistic but fictional data.
- All timestamps are ISO-8601 UTC.
- Binary data (keys, ciphertext, signatures) is base64-encoded in all API payloads.

---

## Service-Specific README Files

- [KMIP Service](../services/kmip/README.md)
- [Posture Service](../services/posture/README.md)
- [HSM Integration](../services/hsm-integration/README.md)
- [EKM Agent](../services/ekm-agent/README.md)
- [PKCS#11 Provider](../services/pkcs11-provider/samples/README.md)
- [JCA Provider](../services/jca-provider/samples/README.md)
