# Documentation Index

This directory contains the operator-focused documentation for Vecta KMS.

## Start Here

- [../README.md](../README.md)
  - Repository landing page, quick start, and documentation map.
- [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md)
  - Explains what each service or major component does, when to use it, and the primary UI/API entry points.
- [ARCHITECTURE.md](ARCHITECTURE.md)
  - Explains how the platform is put together, which services own which decisions, and how trust boundaries work.
- [ADMIN_GUIDE.md](ADMIN_GUIDE.md)
  - Explains how administrators should navigate the UI and run day-to-day operations.
- [FEATURE_REFERENCE.md](FEATURE_REFERENCE.md)
  - Explains the major platform features in a product-style format with usage guidance and operational impact.
- [OPERATIONS_GUIDE.md](OPERATIONS_GUIDE.md)
  - Covers install, startup, health, backup, restore, and cluster operations.
- [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md)
  - Step-by-step scenarios for common deployments and operational tasks.
- [REST_API_ADDITIONS.md](REST_API_ADDITIONS.md)
  - Route-level detail for the newer REST surfaces.

## Read By Role

### Platform Administrator

Read in this order:

1. [../README.md](../README.md)
2. [ARCHITECTURE.md](ARCHITECTURE.md)
3. [ADMIN_GUIDE.md](ADMIN_GUIDE.md)
4. [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md)
5. [OPERATIONS_GUIDE.md](OPERATIONS_GUIDE.md)
6. [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md)

Focus areas:

- deployment configuration
- startup and health checks
- interfaces, TLS, and tenant operations
- backup, restore, governance, and cluster controls

### Security Architect

Read in this order:

1. [ARCHITECTURE.md](ARCHITECTURE.md)
2. [FEATURE_REFERENCE.md](FEATURE_REFERENCE.md)
3. [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md)
4. [REST_API_ADDITIONS.md](REST_API_ADDITIONS.md)
5. [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md)

Focus areas:

- sender-constrained REST auth
- workload identity and SVID exchange
- attested key release
- PQC migration
- compliance, posture, and audit

### Application Team

Read in this order:

1. [ARCHITECTURE.md](ARCHITECTURE.md)
2. [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md)
3. [FEATURE_REFERENCE.md](FEATURE_REFERENCE.md)
4. [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md)

Focus areas:

- creating and using keys
- choosing API auth mode
- workload identity onboarding
- Autokey self-service
- secret storage and rotation

### PKI and Integration Team

Read in this order:

1. [ARCHITECTURE.md](ARCHITECTURE.md)
2. [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md)
3. [FEATURE_REFERENCE.md](FEATURE_REFERENCE.md)
4. [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md)
5. [REST_API_ADDITIONS.md](REST_API_ADDITIONS.md)

Focus areas:

- internal PKI
- ACME/EST/SCEP/CMPv2
- KMIP
- EKM agent and TDE
- cloud BYOK/HYOK
- payment interfaces

## Read By Task

| Task | Primary Doc |
| --- | --- |
| Understand what a component is for | [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md) |
| Understand how the platform is put together | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Learn how to operate the dashboard and admin surfaces | [ADMIN_GUIDE.md](ADMIN_GUIDE.md) |
| Understand the major security and crypto features | [FEATURE_REFERENCE.md](FEATURE_REFERENCE.md) |
| Find a realistic onboarding flow | [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md) |
| Look up newer API surfaces | [REST_API_ADDITIONS.md](REST_API_ADDITIONS.md) |
| Run startup, backup, or cluster operations | [OPERATIONS_GUIDE.md](OPERATIONS_GUIDE.md) |
| Install or start the platform | [../README.md](../README.md), [../infra/scripts/README.md](../infra/scripts/README.md) |
| Edit deployment YAML | [../infra/deployment/README.md](../infra/deployment/README.md) |

## Service-Specific References

- [KMIP](../services/kmip/README.md)
- [Posture](../services/posture/README.md)
- [HSM Integration](../services/hsm-integration/README.md)
- [EKM Agent](../services/ekm-agent/README.md)

## Conventions Used In These Docs

- API examples generally use the dashboard proxy path: `/svc/<service>/...`
- `tenant_id=root` is used as the sample tenant unless noted otherwise
- Examples assume a Bearer token in `Authorization`
- UI paths use the visible dashboard labels, for example `Data Protection -> Payment Policy`

## Practical Reading Path For New Environments

1. Confirm install and startup from [../README.md](../README.md)
2. Review [ARCHITECTURE.md](ARCHITECTURE.md) to understand how the platform is assembled
3. Review [ADMIN_GUIDE.md](ADMIN_GUIDE.md) to understand how operators should use the platform
4. Review [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md) to understand the role of each service
5. Review [FEATURE_REFERENCE.md](FEATURE_REFERENCE.md) to understand the major security and crypto capabilities
6. Execute one or two relevant flows from [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md)
7. Use [REST_API_ADDITIONS.md](REST_API_ADDITIONS.md) when automating or integrating
