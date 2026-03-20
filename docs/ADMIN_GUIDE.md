# Vecta KMS Administrator Guide

This guide is written for operators and platform administrators who run the KMS day to day. It explains where features live in the UI, what the tabs are for, and how to perform common tasks without guessing which service owns which setting.

## Administrator Goals

Most teams use Vecta KMS for one or more of these jobs:

- manage tenants, users, and machine access
- create and rotate keys
- run internal PKI and certificate renewal
- define request-handling interfaces and TLS posture
- govern payment, data protection, workload identity, or attested release
- monitor compliance, posture, and alerts
- back up, restore, and cluster the platform

This guide follows that operational flow.

## UI Navigation Model

The dashboard is organized around long-lived platform state rather than individual microservices.

### Home And Dashboard

Use the home dashboard for:

- system health
- operational summaries
- compliance posture summary
- trending operational signals

Use it when you need a quick answer to "is the platform healthy and what needs attention?"

### Keys

Use the Keys area for:

- creating keys
- viewing versions
- rotating or retiring keys
- testing sign, encrypt, decrypt, wrap, and unwrap behavior

This is the primary operator workspace for application-facing crypto material.

### Data Protection

Use this area for policies that affect protected data rather than just raw keys.

Typical use:

- tokenization and masking
- payment policy
- field-level data protection controls

Important distinction:

- `Data Protection -> Payment Policy` defines long-lived guardrails
- `Workbench -> Payment Crypto` is for controlled operational testing

### Certificates

Use this area when you need to:

- create or inspect CAs
- issue certificates
- review certificate inventory
- check renewal windows and CA-directed renewal schedules
- inspect mass-renewal risk

This is the main operator surface for the `certs` service.

### Interfaces

Use this area to define which external request surfaces the KMS should expose.

Typical changes:

- enable or disable interfaces
- bind addresses and ports
- choose HTTP, HTTPS, TLS, or mTLS behavior
- review runtime listening state

This is the correct place to think about external request handling. It should not be confused with internal service ports.

### REST API

Use this area to manage REST-facing client security and API exposure.

Typical tasks:

- review sender-constrained client posture
- choose OAuth mTLS, DPoP, or HTTP Message Signatures per client
- inspect replay protection status
- review signature verification failures

### Workload Identity

Use this area when applications should authenticate to KMS using workload identity instead of static API keys.

Typical tasks:

- define SPIFFE trust domains
- register workloads
- issue SVIDs
- configure federation
- inspect workload-to-key authorization graphs

### Confidential Compute

Use this area when keys should be released only to approved TEE or enclave environments.

Typical tasks:

- define attestation policy
- match measurements or claims
- approve image identity
- review release decisions and history

### Post-Quantum Crypto

Use this area for migration from classical-only crypto to hybrid or PQC-aware operation.

Typical tasks:

- define PQC profiles
- review readiness scores
- classify interfaces and certificates
- find non-migrated assets

### Autokey

Use this area to create centrally governed self-service key provisioning.

Typical tasks:

- define templates
- set per-service defaults
- review and approve requests
- inspect generated handles

### Compliance

Use this area to understand control alignment and framework posture.

Typical tasks:

- run assessments
- compare current vs previous runs
- inspect control gaps
- review posture implications of runtime drift

### Posture

Use this area for operational security triage.

Typical tasks:

- review findings
- understand why risk moved
- inspect blast radius
- execute or route remediation actions

### Governance

Use this area for sensitive workflows that should be explicit and reviewable.

Typical tasks:

- create backups
- restore backups
- review approval requests
- enforce quorum or approval policy

### Audit Log

Use this area when you need evidence, sequence, or accountability.

Typical tasks:

- search by service, actor, request ID, or severity
- confirm who changed a policy
- prove a workload or client used a key
- trace emergency events such as certificate rotation or replay failures

### Cluster

Use this area in multi-node or cluster-aware environments.

Typical tasks:

- inspect replication profiles
- confirm which state is shared
- review node membership and sync posture

### Workbench

Use Workbench for guided, controlled testing of capabilities without treating the workbench as the system of record.

Typical use:

- payment crypto
- protocol and capability evaluation
- controlled crypto testing

## Day 0: First Administrative Tasks

After installation, a new platform admin should usually do these tasks first:

1. Log in and confirm dashboard health.
2. Confirm tenant, admin user, and authentication posture.
3. Review enabled interfaces and TLS defaults.
4. Decide whether REST clients will stay bearer-based or move to sender-constrained modes.
5. Review internal CA state and certificate issuance defaults.
6. Confirm backup settings and run an initial backup.
7. Review feature set enabled in the deployment profile.

## Day 1: Tenant And Access Setup

### Create Or Review Tenant Layout

Decide whether teams should be separated by:

- business unit
- environment
- customer
- geography

Use a separate tenant when:

- the audit boundary must be distinct
- admins should not see each other's keys or certificates
- posture and compliance should be reported independently

### Register API Clients

For each automation or SDK client:

- decide if it is low-risk internal automation or high-value production access
- choose `bearer`, `oauth_mtls`, `dpop`, or `http_message_signature`
- record allowed IP or certificate bindings if used

### Decide On Workload Identity

If workloads are dynamic, containerized, or service-mesh integrated, prefer `Workload Identity` over static API keys.

## Day 1: Key Management Setup

### Create Base Keys

Typical starting keys:

- application encryption KEKs
- signing keys
- wrapping keys
- payment keys if payment features are enabled

Good practice:

- label by application, environment, and owner
- define intended purpose clearly
- avoid reusing one key for unrelated functions

### Set Interface Policy

Check whether:

- REST should stay public on HTTP for local-only labs or move to HTTPS/TLS
- KMIP should be enabled
- payment TCP should be enabled
- PQC interface mode should inherit, stay classical, or move to hybrid

## Day 1: PKI Setup

### Internal CA

If KMS will issue certificates internally:

- create or validate the tenant CA hierarchy
- define issuance rules
- decide whether services will use internal CA or imported certificates

### Renewal Intelligence

If ACME renewal is enabled:

- verify `renewalInfo` is advertised
- review renewal windows
- check for mass-renewal hotspots

This is especially useful in service-heavy environments where many certificates share issuance history.

## Day 2: Hardening And Modern Identity

### Sender-Constrained REST Clients

Use sender-constrained modes when:

- SDKs or automation run outside a strictly trusted network zone
- replay protection matters
- bearer-token theft is a meaningful risk

Choose:

- OAuth mTLS when client cert management is already mature
- DPoP when public-key proof per request is more practical
- HTTP Message Signatures when request signing semantics fit the integration pattern

### Workload Identity

Use workload identity when:

- workloads are ephemeral
- a service mesh or SPIFFE estate already exists
- static secret distribution is operationally painful or risky

### Confidential Compute

Use attested release when:

- signing or decryption should happen only in measured runtimes
- HSM-only access control is not enough
- enclave or confidential-compute patterns are part of the application design

## Day 2: Governance, Backup, And Evidence

### Backups

Run backups through Governance when you need:

- recoverable control-plane state
- approval-aware restore
- evidence of when backups were taken and what they covered

Recommended practice:

- take an initial known-good backup after setup
- take backups before large tenant, PKI, or policy changes
- verify backup coverage metadata, not just job success

### Audit Review

Use the Audit Log to answer questions such as:

- who changed this client policy?
- which workload used this key?
- did the AP2 evaluation deny because of policy or missing claims?
- was a certificate renewed inside the requested window?

### Compliance And Posture Review

Use both surfaces together:

- `Compliance` answers "which controls and frameworks are satisfied or missing?"
- `Posture` answers "what is drifting, risky, or urgent right now?"

## Common Administrator Playbooks

### Playbook: Harden REST Access

1. Open `REST API`.
2. Review current client inventory.
3. Move high-value clients to sender-constrained auth.
4. Confirm replay protection and failure counters.
5. Watch `Audit Log` and `Posture` for blocked or malformed traffic.

### Playbook: Roll Out Workload Identity

1. Enable workload identity settings.
2. Define trust domain.
3. Add workload registrations.
4. Issue SVIDs and test token exchange.
5. Confirm workload-to-key graph and audit events.

### Playbook: Enable Payment Guardrails

1. Open `Data Protection -> Payment Policy`.
2. Configure `Traditional Payment`.
3. Configure `Modern Payment`.
4. Use `Workbench -> Payment Crypto` to verify expected operations.
5. Review payment audit events separately from workbench tests.

### Playbook: Investigate Renewal Risk

1. Open `Certificates`.
2. Review renewal window and CA-directed schedule data.
3. Look for missed windows or mass-renewal hotspots.
4. Correlate with `Compliance` and `Audit Log`.
5. Decide whether emergency rotation is needed.

### Playbook: Approve Autokey For App Teams

1. Define templates and service defaults.
2. Review submitted requests.
3. Approve or reject according to policy.
4. Confirm generated handles match naming and algorithm standards.
5. Review compliance and audit evidence.

## Operational Cadence

### Daily

- check dashboard health
- review critical posture findings
- review alert and incident activity
- inspect failed or suspicious auth and signature events

### Weekly

- run or review compliance assessments
- inspect renewal and certificate risk
- check backup freshness
- review high-value client auth posture

### Monthly

- review tenant and role hygiene
- review Autokey template drift
- review workload registrations and federation state
- review PQC readiness and migration backlog

## Troubleshooting Map

If the problem is:

- login or tokens: start in `Auth`
- replay or signature failures: start in `REST API` and `Audit Log`
- missing or denied key operations: start in `Keys`, `Policy`, and `Audit Log`
- certificate issuance or renewal timing: start in `Certificates`
- workload auth failure: start in `Workload Identity`
- enclave or TEE release denial: start in `Confidential Compute`
- migration scoring or hybrid mode confusion: start in `Post-Quantum Crypto`
- why risk changed: start in `Posture`
- why a framework score changed: start in `Compliance`
- backup or restore issue: start in `Governance`

## Related References

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md)
- [FEATURE_REFERENCE.md](FEATURE_REFERENCE.md)
- [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md)
- [../infra/deployment/README.md](../infra/deployment/README.md)
- [../infra/scripts/README.md](../infra/scripts/README.md)
