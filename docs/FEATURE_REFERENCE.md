# Vecta KMS Feature Reference

This guide explains the major platform features in a product-style format: what problem each feature solves, when to use it, how it works, which UI and API surfaces it affects, and what evidence it leaves behind.

## How To Read This Guide

Each feature section includes:

- what it is
- why teams adopt it
- when to use it
- primary UI and API entry points
- what audit, posture, and compliance should show

## Sender-Constrained REST Client Security

### What It Is

The platform supports stronger API client authentication than plain bearer tokens:

- OAuth mTLS
- DPoP
- HTTP Message Signatures

This prevents or reduces abuse from replayable tokens and weak client identity binding.

### Why Teams Use It

Use this feature when:

- SDKs or agents run outside tightly controlled networks
- a client certificate or proof key can be managed reliably
- you want visibility into unsigned, replayed, or malformed requests

### UI

- `REST API`

### Primary APIs

- `GET /svc/auth/auth/clients`
- `PUT /svc/auth/auth/clients/{id}`
- `GET /svc/auth/auth/rest-client-security/summary`
- `POST /svc/auth/auth/client-token`

### Operational Outcome

Operators can answer:

- which clients still use legacy bearer-only mode
- which clients are replay-protected
- which clients are failing signature verification

### Evidence Surfaces

- Audit: replay attempts, signature failures, unsigned blocks, mode changes
- Posture: risky or non-migrated client auth posture
- Compliance: sender-constrained coverage and residual gaps

## Workload Identity

### What It Is

Workload identity provides SPIFFE/SVID-based workload authentication and token exchange so applications authenticate as workloads rather than by storing static API keys.

### Why Teams Use It

Use it when:

- workloads are short-lived or autoscaled
- a service mesh or SPIFFE estate already exists
- static secret sprawl is a recurring operational problem

### UI

- `Workload Identity`

### Primary APIs

- `GET /svc/workload/workload-identity/settings?tenant_id=root`
- `POST /svc/workload/workload-identity/registrations?tenant_id=root`
- `POST /svc/workload/workload-identity/issue?tenant_id=root`
- `POST /svc/workload/workload-identity/token/exchange?tenant_id=root`
- `GET /svc/workload/workload-identity/graph?tenant_id=root`

### Operational Outcome

Operators can see:

- trust domains
- issued SVIDs and rotation state
- which workload accessed which key
- which workloads are over-permissioned or expired

### Evidence Surfaces

- Audit: registration changes, issuance, token exchange, workload key use
- Posture: expired, over-privileged, or under-rotated workload identity states
- Compliance: workload identity control adoption and hygiene

## Confidential Compute And Attested Key Release

### What It Is

Confidential Compute uses attestation evidence so keys are released only to approved measured runtimes, such as TEEs or enclaves.

### Why Teams Use It

Use it when:

- workload identity alone is not enough
- the runtime measurement matters as much as the workload name
- signing or decryption should happen only inside approved confidential-compute environments

### UI

- `Confidential Compute`

### Primary APIs

- `GET /svc/confidential/confidential/policy?tenant_id=root`
- `PUT /svc/confidential/confidential/policy?tenant_id=root`
- `POST /svc/confidential/confidential/evaluate`
- `GET /svc/confidential/confidential/releases?tenant_id=root`

### Operational Outcome

Operators can review:

- allowed providers and measurements
- approved images and attesters
- release history and decision reasons
- cryptographic verification metadata

### Evidence Surfaces

- Audit: policy updates, evaluation requests, allow/review/deny results
- Posture: attestation drift or non-verified release attempts
- Compliance: control coverage around attested release

## Post-Quantum Crypto

### What It Is

The PQC feature set turns migration into an operational program rather than a lab-only toggle. It provides:

- tenant policy profiles
- inventory classification
- hybrid and PQC mode signaling for interfaces
- readiness scoring
- migration reporting

### Why Teams Use It

Use it when:

- RSA and ECC usage must be inventoried and reduced
- hybrid rollout should be staged rather than abrupt
- executives and auditors need objective migration signals

### UI

- `Post-Quantum Crypto`
- `Interfaces`
- `Compliance`
- `Posture`

### Primary APIs

- `GET /svc/pqc/pqc/policy?tenant_id=root`
- `GET /svc/pqc/pqc/inventory?tenant_id=root`
- `GET /svc/pqc/pqc/readiness?tenant_id=root`
- `GET /svc/pqc/pqc/migration/report?tenant_id=root`

### Operational Outcome

Operators can answer:

- where RSA or ECC still dominates
- which certificates and interfaces are not migrated
- whether a tenant is classical, hybrid, or PQC-heavy

### Evidence Surfaces

- Audit: policy changes and report access
- Posture: non-migrated interfaces or certificates
- Compliance: readiness scoring and framework-specific crypto posture

## Autokey

### What It Is

Autokey gives teams a self-service request path for managed key handles, while central platform teams keep standards around templates, naming, algorithms, and approvals.

### Why Teams Use It

Use it when:

- application teams should not manually define every key detail
- central teams want opinionated defaults
- approvals should exist for exceptional cases only

### UI

- `Autokey`

### Primary APIs

- `GET /svc/autokey/autokey/settings?tenant_id=root`
- `GET /svc/autokey/autokey/templates?tenant_id=root`
- `POST /svc/autokey/autokey/requests?tenant_id=root`
- `GET /svc/autokey/autokey/handles?tenant_id=root`

### Operational Outcome

Operators can provide:

- resource templates
- per-service defaults
- governed approval flow
- consistent handles across teams

### Evidence Surfaces

- Audit: request, approval, provisioning, and settings changes
- Posture: policy drift or excessive exceptions
- Compliance: whether generated keys matched org standards

## ACME Renewal Intelligence

### What It Is

The certificate lifecycle automation layer uses ACME Renewal Information so renewal timing is coordinated by CA-directed windows rather than blind cron schedules.

### Why Teams Use It

Use it when:

- many services renew from the same CA
- renewal storms or synchronized expiry are real risks
- compliance and operations both care about renewal quality

### UI

- `Certificates`
- `Compliance`

### Primary APIs

- `GET /svc/certs/certs/renewal-intelligence?tenant_id=root`
- `GET /svc/certs/certs/renewal-intelligence/{id}?tenant_id=root`
- `POST /svc/certs/certs/renewal-intelligence/refresh?tenant_id=root`
- `GET /svc/certs/acme/renewal-info/{id}?tenant_id=root`

### Operational Outcome

Operators can see:

- renewal windows
- CA-directed renewal schedules
- missed windows
- mass-renewal risk
- emergency rotation signals

### Evidence Surfaces

- Audit: missed windows, emergency rotation, schedule checks
- Posture: renewal risk and drift
- Compliance: certificate lifecycle control status

## Payment Policy And Payment Crypto

### What It Is

Payment is split intentionally into:

- `Data Protection -> Payment Policy`
- `Workbench -> Payment Crypto`

This separates KMS-wide payment guardrails from test and operational crypto actions.

### Why Teams Use It

Use `Payment Policy` when:

- a tenant needs governed settings for traditional and modern payment workflows

Use `Payment Crypto` when:

- operators or engineers need to test or execute approved payment crypto operations

### Traditional Payment

This covers:

- TR-31
- KBPK
- PIN
- CVV
- MAC
- payment TCP controls

### Modern Payment

This covers:

- ISO 20022
- AP2 and agent-payment policy

### Evidence Surfaces

- Audit: policy updates, runtime operations, AP2 evaluations
- Compliance: payment control status
- Posture: payment policy drift or unsafe interface exposure

## Compliance

### What It Is

Compliance turns technical and operational state into framework-oriented control posture.

### Why Teams Use It

Use it when:

- a security team needs structured assessment output
- auditors need evidence across controls
- leadership wants a normalized posture view

### What It Shows

- assessment history
- current posture
- deltas since the last scan
- framework-level findings
- readiness and risk derived from multiple services

## Posture Management

### What It Is

Posture is the risk and remediation layer. It focuses on drift, findings, prioritization, and action rather than framework mapping.

### Why Teams Use It

Use it when:

- operators need to know what to fix first
- leadership needs a live risk view
- evidence should drive operational prioritization

### What It Shows

- findings
- risk-driver explanation
- blast radius
- grouped remediation actions
- trend and SLA-oriented data

## Governance, Backup, And Cluster Awareness

### What It Is

These features make the KMS operationally safe in production:

- explicit approvals
- recoverable backups
- selective cluster replication

### Why Teams Use It

Use these capabilities when:

- operations must be reviewable
- platform state must survive disaster or node loss
- multiple nodes share the same control-plane state

### Evidence Surfaces

- Audit: approvals, backups, restores, cluster changes
- Compliance: operational control status
- Posture: backup freshness or replication drift

## HSM And External Integration Features

### What They Are

These features help the KMS act as a central crypto authority while fitting into real enterprise estates:

- HSM onboarding
- KMIP
- EKM
- cloud BYOK and HYOK
- payment protocol surfaces

### Why Teams Use Them

Use these features when existing infrastructure cannot or should not be rewritten to use one new API style.

## Recommended Use Sequence

For most teams, the highest-value adoption order is:

1. key lifecycle and Auth basics
2. REST client hardening
3. workload identity
4. certificate automation
5. governance and backup discipline
6. confidential compute where needed
7. Autokey for internal self-service
8. PQC readiness and migration

## Related References

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [ADMIN_GUIDE.md](ADMIN_GUIDE.md)
- [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md)
- [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md)
- [REST_API_ADDITIONS.md](REST_API_ADDITIONS.md)
