# Vecta KMS Component Guide

This guide explains what each major component does, when to use it, who typically owns it, and how operators or application teams usually interact with it.

For broader context, pair this guide with:

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [ADMIN_GUIDE.md](ADMIN_GUIDE.md)
- [FEATURE_REFERENCE.md](FEATURE_REFERENCE.md)
- [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md)

## Conventions

- UI paths use the dashboard labels, for example `Data Protection -> Payment Policy`
- API paths use the dashboard proxy style, for example `/svc/keycore/keys`
- `tenant_id=root` is used in examples
- For route-level detail and larger REST coverage, see [REST_API_ADDITIONS.md](REST_API_ADDITIONS.md)

## Quick Map

| Component | Primary Users | Use It When | Primary Entry Point |
| --- | --- | --- | --- |
| `keycore` | platform, app teams | you need keys or crypto operations | Keys UI, `/svc/keycore/...` |
| `auth` | platform, security | you need users, tenants, clients, SSO, or API auth | Auth/Admin UI, `/svc/auth/...` |
| `audit` | security, compliance | you need a trace of who did what | Audit Log UI |
| `policy` | security, platform | you want enforced crypto or access guardrails | policy-backed runtime behavior |
| `governance` | ops, security | you need approvals, backups, or system controls | Governance UI, `/svc/governance/...` |
| `cluster-manager` | platform | you run more than one node or use component replication | Cluster UI |
| `certs` | PKI, platform | you issue or automate certificates | Certificates UI, `/svc/certs/...` |
| `secrets` | app teams, platform | you need secret storage or generated credentials | Secrets UI, `/svc/secrets/...` |
| `dataprotect` | data owners | you need tokenization or masking | Data Protection UI |
| `cloud` | cloud/platform teams | you manage BYOK or HYOK across clouds | Cloud UI, `/svc/cloud/...` |
| `ekm` | database/platform teams | you protect databases or BitLocker endpoints | EKM UI, `/svc/ekm/...` |
| `kmip` | integration teams | you integrate KMIP clients and appliances | KMIP UI, `:5696`, `/svc/kmip/...` |
| `payment` | payments/HSM teams | you manage payment keys and payment crypto policy | Payment Crypto UI, `/svc/payment/...` |
| `compliance` | compliance, audit | you need framework scoring and evidence views | Compliance UI, `/svc/compliance/...` |
| `posture` | security ops | you need risk, findings, or remediation | Posture UI, `/svc/posture/...` |
| `reporting` | ops, management | you need alerts, incidents, and reports | Reporting UI, `/svc/reporting/...` |
| `discovery` | security, platform | you need crypto asset inventory | Discovery UI, `/svc/discovery/...` |
| `sbom` | security, compliance | you need software/component visibility | SBOM UI |
| `autokey` | app teams, platform | teams need governed self-service keys | Autokey UI, `/svc/autokey/...` |
| `workload` | platform, security | workloads should auth with SPIFFE/SVID, not static API keys | Workload Identity UI, `/svc/workload/...` |
| `confidential` | platform, security | key release must depend on TEE/enclave evidence | Confidential Compute UI, `/svc/confidential/...` |
| `pqc` | crypto architecture | you are planning or executing PQC migration | Post-Quantum Crypto UI, `/svc/pqc/...` |
| `qkd`, `qrng`, `mpc`, `ai` | specialist teams | you need advanced or emerging crypto capabilities | dedicated UI modules |

## Core Control Plane

### KeyCore

What it does:

- owns the lifecycle of keys and key versions
- performs crypto operations such as encrypt, decrypt, sign, verify, wrap, unwrap, MAC, derive, and KEM operations
- stores interface and access hardening state for request-handling surfaces

Use cases:

- create application KEKs and DEKs
- rotate signing keys on a fixed schedule
- wrap cloud or agent keys under centrally managed root keys
- expose controlled request interfaces for REST, KMIP, HYOK, EKM, and payment integrations

How teams use it:

- operators use the Keys and Administration areas to define lifecycle, usage limits, approvals, and interface behavior
- app teams call crypto endpoints through the REST API
- platform teams attach key access policy to workloads, groups, or integrations

Common APIs:

- `POST /svc/keycore/keys?tenant_id=root`
- `GET /svc/keycore/keys?tenant_id=root`
- `POST /svc/keycore/keys/{id}/encrypt?tenant_id=root`
- `POST /svc/keycore/keys/{id}/sign?tenant_id=root`
- `GET /svc/keycore/access/interface-ports?tenant_id=root`

Sample:

```bash
curl -X POST http://127.0.0.1:5173/svc/keycore/keys?tenant_id=root \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "payments-kek",
    "algorithm": "AES-256",
    "purpose": "wrap",
    "labels": {"environment": "prod", "team": "payments"}
  }'
```

### Auth

What it does:

- manages tenants, users, roles, groups, SSO, clients, and tokens
- provides tenant-scoped SCIM 2.0 provisioning for users and groups
- issues login tokens, client tokens, and workload tokens
- enforces modern REST auth modes such as OAuth mTLS, DPoP, and HTTP Message Signatures

Use cases:

- create a new tenant and bootstrap admins
- let Okta, Entra ID, or another IdP provision KMS users and groups automatically
- onboard SSO through OIDC or SAML
- register SDK and automation clients
- enforce sender-constrained auth for high-risk API clients

Common APIs:

- `POST /svc/auth/auth/login`
- `GET /svc/auth/auth/me`
- `GET /svc/auth/tenants`
- `POST /svc/auth/tenants`
- `GET /svc/auth/auth/scim/settings`
- `POST /svc/auth/auth/scim/settings/rotate-token`
- `POST /svc/auth/scim/v2/Users`
- `POST /svc/auth/scim/v2/Groups`
- `GET /svc/auth/auth/clients`
- `PUT /svc/auth/auth/clients/{id}`

Sample:

```bash
curl -X POST http://127.0.0.1:5173/svc/auth/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"VectaAdmin@2026"}'
```

### Audit

What it does:

- records operational, security, governance, and protocol activity
- classifies events by service, severity, and category
- acts as the evidence source for posture, compliance, reporting, and investigations

Use cases:

- prove who requested a key, changed a policy, or approved a destructive action
- trace AP2 decisions, attested releases, workload token exchanges, and certificate lifecycle events
- support incident response and audit evidence collection

How to use it:

- filter by service, actor, severity, category, or request ID in the Audit Log UI
- use governance/reporting exports when you need packaged evidence instead of raw events

### Policy

What it does:

- centralizes decision logic and guardrails that influence runtime behavior
- backs decisions such as approval requirements, crypto restrictions, and interface posture

Use cases:

- require approvals for exportable or destructive operations
- block weak algorithms or disallowed usages
- separate tenant policy from application code

How to use it:

- treat policy as the platform control layer that other services consult
- review policy-driven effects through KeyCore, Governance, Auth, and Compliance rather than thinking of policy as a standalone app-only surface

### Governance

What it does:

- handles approval workflows, quorum policies, backups, restores, and sensitive system controls
- coordinates operational changes that should not happen through one-click unreviewed actions

Use cases:

- approval flow for key creation, key export, or Autokey requests
- encrypted backup and restore
- posture control changes
- system integrity and FDE-related operations

Common APIs:

- `GET /svc/governance/governance/policies?tenant_id=root`
- `POST /svc/governance/governance/requests`
- `GET /svc/governance/governance/backups?tenant_id=root`
- `POST /svc/governance/governance/backups`

### Cluster Manager

What it does:

- manages cluster profiles, node sync, join flows, and component-aware replication
- determines which control-plane state is shared and which state remains node-local

Use cases:

- scale from a single appliance to a multi-node deployment
- replicate PKI, auth, Autokey, workload identity, or PQC state across nodes
- validate selective replication boundaries before production expansion

How to use it:

- use the Cluster UI to review enabled component profiles
- confirm that the cluster profile matches the set of enabled services in the deployment YAML

## PKI, Secrets, and Data Protection

### Certs

What it does:

- runs the internal CA and certificate inventory
- supports ACME, ACME STAR, EST, SCEP, CMPv2, CRL, OCSP, internal mTLS issuance, and certificate renewal intelligence
- exposes ACME Renewal Information so renewals are coordinated rather than cron-only
- maintains ACME STAR subscriptions for short-lived and delegated-subscriber certificates

Use cases:

- issue internal service certificates
- onboard external CSRs
- automate ACME issuance for services and gateways
- run short-lived delegated certificates for mesh edges and gateways
- detect mass-renewal hotspots, missed renewal windows, and emergency rotation conditions

Common APIs:

- `POST /svc/certs/certs/ca?tenant_id=root`
- `POST /svc/certs/certs?tenant_id=root`
- `GET /svc/certs/certs?tenant_id=root`
- `GET /svc/certs/certs/renewal-intelligence?tenant_id=root`
- `GET /svc/certs/certs/star/summary?tenant_id=root`
- `POST /svc/certs/certs/star/subscriptions`
- `GET /svc/certs/acme/directory?tenant_id=root`
- `GET /svc/certs/acme/renewal-info/{id}?tenant_id=root`

Sample:

```bash
curl -X GET http://127.0.0.1:5173/svc/certs/certs/renewal-intelligence?tenant_id=root \
  -H "Authorization: Bearer $TOKEN"
```

### Secrets

What it does:

- stores versioned secrets and generated credentials
- supports generated keypairs and Vault-style compatibility endpoints

Use cases:

- store application credentials
- rotate secrets on schedule
- expose a Vault-like access path for migration or compatibility

Common APIs:

- `POST /svc/secrets/secrets?tenant_id=root`
- `GET /svc/secrets/secrets?tenant_id=root`
- `POST /svc/secrets/secrets/{id}/rotate?tenant_id=root`
- `GET /svc/secrets/v1/sys/health`

### Data Protection

What it does:

- handles tokenization, masking, and related protection controls for sensitive datasets
- hosts the `Payment Policy` tab because payment guardrails are KMS-wide data protection policy, not just a workbench action

Use cases:

- tokenize PAN, identifiers, or regulated fields
- configure masking and redaction policy
- separate data protection policy from raw key lifecycle operations

### Software Vault

What it does:

- provides software-based secure storage where no external HSM is used
- backs development, evaluation, and software-only deployments

Use cases:

- development and lab deployments
- software-only environments
- fall-back mode when hardware HSM is not part of the platform profile

## External Integrations and Protocol Surfaces

### Cloud

What it does:

- orchestrates BYOK and HYOK style cloud bindings
- tracks registered cloud accounts, region mapping, imported keys, and sync state

Use cases:

- import local keys into cloud KMS wrappers
- rotate a cloud binding under central control
- audit which tenant key is bound to which cloud account and region

Common APIs:

- `POST /svc/cloud/cloud/accounts`
- `GET /svc/cloud/cloud/accounts`
- `POST /svc/cloud/cloud/import`
- `POST /svc/cloud/cloud/sync`

### EKM

What it does:

- manages external key manager and database encryption workflows
- handles TDE key wrapping/rotation and BitLocker client orchestration

Use cases:

- issue TDE keys to MSSQL or Oracle
- rotate wrapped DEKs
- manage BitLocker clients and recovery workflows

Common APIs:

- `POST /svc/ekm/ekm/agents/register`
- `POST /svc/ekm/ekm/tde/keys`
- `POST /svc/ekm/ekm/tde/keys/{id}/wrap`
- `GET /svc/ekm/ekm/bitlocker/clients`

### KMIP

What it does:

- runs a KMIP-over-mTLS endpoint backed by KeyCore
- also exposes a management API for client profiles and interoperability targets

Use cases:

- integrate enterprise middleware that expects KMIP
- validate KMIP client interoperability
- separate KMIP client permissions from REST API permissions

References:

- [KMIP Service README](../services/kmip/README.md)

Common APIs:

- `GET /svc/kmip/kmip/capabilities`
- `GET /svc/kmip/kmip/profiles`
- `POST /svc/kmip/kmip/interop/targets`
- `POST /svc/kmip/kmip/interop/targets/{id}/validate`

### Payment

What it does:

- manages payment keys, payment crypto operations, and policy
- splits policy into `Traditional Payment` and `Modern Payment`
- supports TR-31, PIN, CVV, MAC, ISO 20022, remote injection, and AP2 policy/evaluation

Use cases:

- define payment key usage and rotation
- run test crypto flows in `Workbench -> Payment Crypto`
- enforce production payment guardrails in `Data Protection -> Payment Policy`

Common APIs:

- `GET /svc/payment/payment/policy?tenant_id=root`
- `PUT /svc/payment/payment/policy?tenant_id=root`
- `POST /svc/payment/payment/tr31/create?tenant_id=root`
- `POST /svc/payment/payment/iso20022/sign?tenant_id=root`
- `POST /svc/payment/payment/ap2/evaluate?tenant_id=root`

### HSM Integration

What it does:

- provides the operator-facing HSM onboarding workspace
- helps teams install provider libraries, inspect partitions, and verify connectivity

Use cases:

- upload or install vendor PKCS#11 libraries
- discover slot/partition details
- stage HSM onboarding before enabling production key storage

References:

- [HSM Integration README](../services/hsm-integration/README.md)

### EKM Agent

What it does:

- is the Windows-first agent used for TDE and BitLocker endpoints
- connects remote infrastructure to the `ekm` service

Use cases:

- database encryption for MSSQL and Oracle
- BitLocker orchestration on managed Windows hosts
- local cached crypto for supported workloads

References:

- [EKM Agent README](../services/ekm-agent/README.md)

## Assurance and Operational Visibility

### Compliance

What it does:

- computes framework posture, assessment history, control gaps, CBOM/SBOM views, and deltas between assessments
- now incorporates certificate renewal intelligence, payment policy posture, PQC readiness, and other platform-level controls

Use cases:

- run a tenant assessment
- compare latest assessment vs prior run
- show framework-specific gaps or CBOM/PQC readiness

Common APIs:

- `GET /svc/compliance/compliance/posture?tenant_id=root`
- `GET /svc/compliance/compliance/assessment?tenant_id=root`
- `GET /svc/compliance/compliance/assessment/delta?tenant_id=root`
- `POST /svc/compliance/compliance/assessment/run?tenant_id=root`

### Posture

What it does:

- converts audit and runtime evidence into risk snapshots, findings, and remediation actions
- groups actions into safe auto-fix, approval-required, and manual paths

Use cases:

- spot drift before it becomes an outage
- explain why risk moved
- prioritize by blast radius and SLA impact

References:

- [Posture Service README](../services/posture/README.md)

Common APIs:

- `GET /svc/posture/posture/dashboard?tenant_id=root`
- `GET /svc/posture/posture/findings?tenant_id=root`
- `GET /svc/posture/posture/actions?tenant_id=root`
- `POST /svc/posture/posture/scan?tenant_id=root`

### Reporting

What it does:

- manages alerts, incidents, scheduled reports, telemetry, MTTR, MTTD, and evidence-pack style exports

Use cases:

- route alerts to channels
- review unresolved incidents
- export posture, compliance, or operational evidence

Common APIs:

- `GET /svc/reporting/alerts`
- `GET /svc/reporting/incidents`
- `POST /svc/reporting/reports/generate`
- `GET /svc/reporting/alerts/stats/mttd`

### Discovery

What it does:

- discovers crypto assets and classifies them for posture and migration work

Use cases:

- build an inventory of keys, certificates, endpoints, and crypto usage
- classify discovered assets before remediation or migration

Common APIs:

- `POST /svc/discovery/discovery/scan`
- `GET /svc/discovery/discovery/assets`
- `GET /svc/discovery/discovery/summary`

### SBOM

What it does:

- tracks software and crypto bill-of-materials data used by compliance and reporting

Use cases:

- vulnerability and component inventory review
- PQC readiness reporting through CBOM
- audit evidence on software supply chain state

## Advanced Crypto, Identity, and Self-Service

### Autokey

What it does:

- gives app teams a governed self-service key request path
- uses resource templates and per-service defaults to provision key handles under central policy

Use cases:

- app teams request keys without hand-authoring every key parameter
- central teams enforce naming, purpose, algorithm, approvals, and export behavior

Common APIs:

- `GET /svc/autokey/autokey/settings?tenant_id=root`
- `GET /svc/autokey/autokey/templates?tenant_id=root`
- `POST /svc/autokey/autokey/requests?tenant_id=root`
- `GET /svc/autokey/autokey/handles?tenant_id=root`

### Key Access Justifications

What it does:

- enforces per-request justification codes for external decrypt, sign, wrap, and unwrap operations
- can deny, allow, or send requests to governance approval depending on reason code and service scope

Use cases:

- regulated HYOK or EKM operations where every external key use needs an explainable reason
- cloud and external-key workflows where a requester must declare intent before key release or signing
- investigations into bypassed or unjustified usage

Common APIs:

- `GET /svc/keyaccess/key-access/settings?tenant_id=root`
- `GET /svc/keyaccess/key-access/summary?tenant_id=root`
- `GET /svc/keyaccess/key-access/codes?tenant_id=root`
- `GET /svc/keyaccess/key-access/decisions?tenant_id=root`

### Artifact Signing

What it does:

- manages signing profiles for blobs, Git artifacts, and OCI-related release metadata
- binds signing to workload identity or OIDC subject constraints
- stores transparency-style signature metadata and verification state

Use cases:

- release pipeline signing with workload-issued identity instead of copied private keys
- Git or blob signing backed by KMS-managed signing keys
- visibility into who signed which artifact and whether the signature can still be verified

Common APIs:

- `GET /svc/signing/signing/settings?tenant_id=root`
- `GET /svc/signing/signing/summary?tenant_id=root`
- `GET /svc/signing/signing/profiles?tenant_id=root`
- `POST /svc/signing/signing/blob`
- `POST /svc/signing/signing/git`
- `POST /svc/signing/signing/verify`

### Workload Identity

What it does:

- manages SPIFFE trust domain settings, workload registrations, federation bundles, SVID issuance, and workload token exchange

Use cases:

- replace static API keys with short-lived workload-backed credentials
- tie key access to workload identity rather than network location alone
- inspect which workload used which key

Common APIs:

- `GET /svc/workload/workload-identity/settings?tenant_id=root`
- `POST /svc/workload/workload-identity/registrations?tenant_id=root`
- `POST /svc/workload/workload-identity/issue?tenant_id=root`
- `POST /svc/workload/workload-identity/token/exchange?tenant_id=root`
- `GET /svc/workload/workload-identity/graph?tenant_id=root`

### Confidential Compute

What it does:

- releases keys only after attestation evidence is verified and matched against tenant policy
- supports AWS, Azure, GCP, and generic attestation evidence paths

Use cases:

- release keys only to approved enclave images
- bind key release to measurements, claims, secure boot, debug-disabled state, and cluster-node policy

Common APIs:

- `GET /svc/confidential/confidential/policy?tenant_id=root`
- `PUT /svc/confidential/confidential/policy?tenant_id=root`
- `POST /svc/confidential/confidential/evaluate`
- `GET /svc/confidential/confidential/releases?tenant_id=root`

### Post-Quantum Crypto

What it does:

- stores tenant PQC policy and readiness state
- tracks inventory as classical, hybrid, or PQC-only
- drives migration plans, scans, reports, and CBOM export

Use cases:

- decide which interfaces should move to hybrid first
- quantify where RSA/ECC is still used
- stage ML-KEM and ML-DSA adoption with rollback-safe plans

Common APIs:

- `GET /svc/pqc/pqc/policy?tenant_id=root`
- `GET /svc/pqc/pqc/inventory?tenant_id=root`
- `GET /svc/pqc/pqc/readiness?tenant_id=root`
- `GET /svc/pqc/pqc/migration/report?tenant_id=root`

### QKD

What it does:

- integrates with quantum key distribution workflows where specialized network or partner infrastructure exists

Use cases:

- evaluate high-assurance transport key distribution
- compare QKD-delivered material with software-only alternatives in controlled environments

### QRNG

What it does:

- surfaces quantum random number generation as an entropy source or validation input

Use cases:

- compare entropy sources
- validate runtime crypto mode and entropy posture

### MPC

What it does:

- supports multi-party computation and distributed ceremonies for cases where no single node should hold unilateral control
- provides quorum-backed threshold workflows that map cleanly to FROST-style operational models for high-assurance signing

Use cases:

- high-assurance signing or ceremony workflows
- distributed trust separation between teams or sites
- split-operator approval for CA roots, treasury operations, or high-value signers

### AI

What it does:

- applies key management and control patterns to AI and model-related assets

Use cases:

- encrypt or compartmentalize model artifacts
- attach governance and audit to AI-specific sensitive assets

## Provider and Package Components

### PKCS#11 Provider

Use it when:

- third-party middleware expects a PKCS#11 shared library rather than a REST API

### JCA Provider

Use it when:

- Java applications must consume KMS-backed crypto through standard JCA/JCE abstractions

### Shared `pkg/` Modules

Notable packages:

- `pkg/auth`
  - shared auth and token validation logic
- `pkg/restauth`
  - sender-constrained REST auth helpers for DPoP, HTTP signatures, and related verification
- `pkg/events`
  - service event publishing and subscription
- `pkg/tlsprofile`
  - TLS profile selection across FIPS, classical, hybrid, and PQC-related modes

## When To Use Which Path

- Use `Workbench` when you want to test or operate crypto capabilities interactively.
- Use `Data Protection`, `REST API`, `Certificates`, `Compliance`, `Posture`, and `Governance` when you are defining platform policy or long-lived operational state.
- Use the REST API when onboarding apps, agents, or automation.
- Use generated reports and audit evidence for external review, not screenshots alone.
