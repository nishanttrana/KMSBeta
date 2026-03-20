# Vecta KMS Architecture Guide

This guide explains how the platform is assembled, how the services interact, where policy and trust boundaries live, and how to choose the right path for a given workload.

## Why This Platform Exists

Vecta KMS is not a single API server. It is a control plane for:

- cryptographic key lifecycle
- certificate issuance and renewal
- protocol surfaces such as REST, KMIP, EKM, payment, and HSM-adjacent flows
- workload and machine identity
- attested key release
- policy-driven self-service key provisioning
- posture, compliance, and operational evidence

The design goal is to let security teams define policy centrally while application, platform, PKI, and integration teams consume controlled capabilities without each team building its own crypto workflow.

## Architecture At A Glance

The platform is split into four layers:

1. Control plane
   - `keycore`, `auth`, `policy`, `audit`, `governance`, `cluster-manager`
2. Protection services
   - `certs`, `secrets`, `dataprotect`, `software-vault`
3. Integration and protocol surfaces
   - `cloud`, `ekm`, `kmip`, `payment`, `hsm-integration`, `ekm-agent`
4. Assurance and advanced capability services
   - `compliance`, `posture`, `reporting`, `discovery`, `sbom`, `autokey`, `workload`, `confidential`, `pqc`, `qkd`, `qrng`, `mpc`, `ai`

## Core Concepts

### Tenant

A tenant is the primary logical security boundary. Most configuration, policy, audit views, and inventory are tenant-scoped.

Use tenant separation when:

- business units must have separate keys and admins
- customer-dedicated control is required
- policy or evidence must be partitioned

### Interface

An interface is a request-handling surface exposed by the KMS, such as REST, KMIP, EKM, or payment TCP.

An interface combines:

- bind address and port
- protocol mode
- TLS or mTLS behavior
- certificate source
- runtime policy such as hybrid or classical posture

### Policy

Policy is the control layer that turns the platform from a key store into an opinionated security system. Policy influences:

- what can be created
- which algorithms are allowed
- whether approvals are required
- how clients authenticate
- whether an attested environment can receive a key
- whether a workload or service can use a handle automatically

### Handle

A handle is a durable reference to a managed object, commonly used by Autokey and integration services to avoid leaking raw internal key identifiers into application workflows.

### Evidence

Evidence is the operational record used by posture, compliance, and reporting. It is produced by:

- audit events
- protocol activity
- certificate and key inventory
- policy evaluation results
- workload, attestation, and renewal state

## Service Responsibilities

### KeyCore

`keycore` is the cryptographic heart of the system. It owns:

- key lifecycle
- key versions
- encrypt, decrypt, sign, verify, wrap, unwrap, derive, MAC, and KEM operations
- interface policy state used by request-handling surfaces

Choose KeyCore when your need is fundamentally about cryptographic material and operations.

### Auth

`auth` manages:

- users, tenants, roles, groups
- SSO and identity provider bindings
- human and machine login flows
- API client registration
- sender-constrained REST client settings

Choose Auth when the main question is "who is allowed to talk to KMS and how?"

### Audit

`audit` stores the event trail that the rest of the platform relies on for evidence and incident reconstruction.

Choose Audit when the question is "what happened, who did it, when, and under what policy?"

### Governance

`governance` manages approval-oriented and operationally sensitive flows such as:

- backup and restore
- approval requests
- quorum-bound actions
- sensitive operational controls

Choose Governance when a change should not happen silently or unilaterally.

## Request Paths

Most operators interact through one of four paths:

### Dashboard Path

Human administrators typically use:

- [http://127.0.0.1:5173/](http://127.0.0.1:5173/)

The dashboard speaks to service endpoints through proxied `/svc/<service>/...` routes.

### REST API Path

Applications and automation typically use:

- `/svc/keycore/...`
- `/svc/auth/...`
- `/svc/certs/...`
- `/svc/autokey/...`
- `/svc/workload/...`

This is the preferred path for new application integrations unless the application already depends on a protocol such as KMIP or EKM.

### Protocol Path

Specialized clients use protocol-native surfaces:

- KMIP on `:5696`
- payment TCP interfaces where enabled
- EKM and agent-managed database or endpoint workflows

### Cluster Path

Multi-node control uses `cluster-manager` plus deployment profile and startup scripts. This is how shared state, selective replication, and node lifecycle are coordinated.

## Trust Boundaries

The platform is designed around several trust boundaries:

### Human Operator Boundary

Administrators authenticate through Auth and operate through the dashboard or administrative APIs. Sensitive changes should be visible in Audit and, where needed, Governance.

### Workload Boundary

Workloads should ideally authenticate through:

- sender-constrained REST clients
- SPIFFE/SVID-backed workload identity
- attested confidential-compute release paths

This reduces reliance on static bearer tokens or copied long-lived credentials.

### Crypto Execution Boundary

KeyCore is the execution boundary for most crypto operations. Other services should call into KeyCore rather than inventing shadow key lifecycles.

### Evidence Boundary

Audit is the source of truth for event evidence, while posture, compliance, and reporting interpret that evidence for different audiences.

## Data And State Model

Not all state is equal. A useful way to think about the platform is:

### Shared Control-Plane State

This is the configuration and catalog state that should usually survive restarts and often replicate across nodes:

- tenants, users, and clients
- keys and handles
- PKI inventory
- workload identity registrations
- confidential-compute policy
- PQC policy and migration data
- Autokey templates and requests
- posture and compliance evidence where applicable

### Node-Local Runtime State

This includes service-health and runtime-specific context that may not be appropriate for cluster replication:

- live socket state
- node-local caches
- ephemeral protocol sessions
- transient health snapshots

### Backup Model

Backups should capture shared operational state, not every transient runtime counter. Governance exposes backup coverage so operators can see what is included for each domain.

## How Features Fit Together

### Workload Identity + KeyCore

Use this combination when workloads need short-lived, identity-bound access to keys.

### Confidential Compute + KeyCore

Use this when a key should only be usable inside an approved TEE or enclave.

### Autokey + Governance + KeyCore

Use this when teams need self-service handles, but the central platform team must preserve standards around naming, algorithms, approvals, or export policy.

### Certs + Compliance + Posture

Use this when certificate lifecycle is not just operational, but also a risk and control-management concern.

### Payment + Data Protection

Use `Workbench -> Payment Crypto` for controlled operational testing and `Data Protection -> Payment Policy` for tenant-wide guardrails that affect request-handling behavior.

### PQC + Interfaces + Certificates

Use this when you need an actual migration program, not a laboratory demo. PQC policy should be reflected in interface behavior, certificate inventory, posture, and compliance.

## UI Model

The dashboard is intentionally split into:

- operational and executive visibility modules
- control-plane modules
- test and workbench modules

As a rule:

- use `Workbench` for guided testing and capability exploration
- use administrative tabs for long-lived platform state
- use posture and compliance for interpretation, not primary configuration

## Deployment Model

The platform is deployment-driven. Features are enabled through:

- [infra/deployment/README.md](../infra/deployment/README.md)
- [infra/scripts/README.md](../infra/scripts/README.md)

The deployment YAML controls which services are active, and startup scripts translate that into Compose profiles and runtime policy application.

This means the "real platform" is the combination of:

- deployment profile
- service set
- persisted tenant state
- policy and approval settings

## Common Architectural Patterns

### Single-Node Appliance

Best for:

- lab environments
- offline or constrained deployments
- evaluation environments
- small production estates with clear operational ownership

### Multi-Node Cluster

Best for:

- higher availability requirements
- operational separation between nodes
- replicated control-plane state
- larger tenant or certificate estates

### Protocol Gateway Pattern

Use when:

- legacy tools require KMIP, payment TCP, or EKM
- application teams still consume modern REST APIs
- the same platform must serve both worlds

### Central Security Platform Pattern

Use when:

- multiple business teams need shared security services
- central policy should drive local autonomy
- audit, posture, compliance, and evidence need to align

## Choosing The Right Feature

If the primary need is:

- application crypto: use `keycore`
- human and machine access control: use `auth`
- certificate lifecycle: use `certs`
- secret storage: use `secrets`
- tokenization and field protection: use `dataprotect`
- cloud binding: use `cloud`
- enterprise protocol integration: use `kmip`, `ekm`, or `payment`
- self-service key provisioning: use `autokey`
- workload-native access: use `workload`
- TEE-gated release: use `confidential`
- migration away from classical-only crypto: use `pqc`
- executive and operational security visibility: use `compliance`, `posture`, and `reporting`

## Recommended Next Reads

- [README.md](../README.md)
- [README.md](README.md)
- [ADMIN_GUIDE.md](ADMIN_GUIDE.md)
- [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md)
- [FEATURE_REFERENCE.md](FEATURE_REFERENCE.md)
- [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md)
