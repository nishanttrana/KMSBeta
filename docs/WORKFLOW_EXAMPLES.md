# Vecta KMS Workflow Examples

This guide shows realistic end-to-end workflows that combine multiple components.

Use it together with:

- [ARCHITECTURE.md](ARCHITECTURE.md) for the control-plane model
- [ADMIN_GUIDE.md](ADMIN_GUIDE.md) for UI-driven operations
- [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md) for service ownership and role clarity
- [FEATURE_REFERENCE.md](FEATURE_REFERENCE.md) for capability-level detail

## Conventions

- All examples use the dashboard proxy path: `http://127.0.0.1:5173/svc/...`
- Replace `root` with your tenant ID when needed
- Replace `$TOKEN` with an authenticated Bearer token

## 1. Onboard A New Application To KeyCore

Goal:

- create a tenant application key
- attach app metadata
- give the app a clean crypto path

Components used:

- `auth`
- `keycore`
- `audit`

Steps:

1. Log in and obtain an access token.
2. Create a key in KeyCore.
3. Optionally define usage limits, approval requirements, or access policy.
4. Use the key for encrypt, decrypt, sign, or verify operations.
5. Review the audit log for proof of creation and usage.

Sample:

```bash
TOKEN="$(curl -s -X POST http://127.0.0.1:5173/svc/auth/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"VectaAdmin@2026"}' | jq -r '.token')"

curl -X POST http://127.0.0.1:5173/svc/keycore/keys?tenant_id=root \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "app-orders-primary",
    "algorithm": "AES-256",
    "purpose": "encrypt",
    "labels": {"app": "orders", "environment": "prod"}
  }'
```

When this workflow is a good fit:

- service-to-KMS encryption
- per-app signing keys
- central rotation and usage monitoring

## 2. Replace Static API Keys With Workload Identity

Goal:

- let workloads authenticate through SPIFFE/SVID and token exchange
- stop distributing static API keys to runtime workloads

Components used:

- `workload`
- `auth`
- `keycore`
- `audit`
- `posture`

Steps:

1. Enable workload identity settings for the tenant.
2. Register a workload SPIFFE ID and allowed interfaces.
3. Issue an SVID.
4. Exchange the SVID for a short-lived KMS token.
5. Use that token against KeyCore or another approved interface.
6. Confirm usage and graph entries in the Workload Identity UI.

Sample registration:

```bash
curl -X POST http://127.0.0.1:5173/svc/workload/workload-identity/registrations?tenant_id=root \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "spiffe_id": "spiffe://root/workloads/orders-api",
    "name": "orders-api",
    "allowed_interfaces": ["rest-api"],
    "allowed_key_ids": ["key_orders_prod"],
    "permissions": ["key.encrypt", "key.decrypt"],
    "enabled": true
  }'
```

Best for:

- Kubernetes or service-mesh workloads
- short-lived machine identities
- reducing static secret sprawl

## 3. Use Autokey For Self-Service Key Provisioning

Goal:

- let app teams request handles under central rules
- avoid manual one-off key creation for each app

Components used:

- `autokey`
- `governance`
- `keycore`
- `audit`

Steps:

1. Configure tenant Autokey settings.
2. Create one or more templates.
3. Create per-service default policy.
4. Submit a request.
5. If required, approve the request in Governance.
6. Review the resulting managed handle.

Template sample:

```bash
curl -X POST http://127.0.0.1:5173/svc/autokey/autokey/templates?tenant_id=root \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "service-default-aes",
    "resource_type": "service",
    "algorithm": "AES-256",
    "purpose": "encrypt",
    "handle_prefix": "svc",
    "key_prefix": "key",
    "labels": {"managed_by": "autokey"}
  }'
```

Best for:

- platform-owned developer self-service
- large application estates
- central guardrails with low day-2 operational overhead

## 4. Run Internal PKI With Coordinated Renewals

Goal:

- issue certificates internally
- automate renewal through ACME
- prevent renewal storms with ACME Renewal Information

Components used:

- `certs`
- `audit`
- `compliance`
- `posture`
- `cluster-manager`

Steps:

1. Create a CA or use the existing runtime CA.
2. Issue or sign certificates for services.
3. Configure the ACME protocol policy.
4. Let clients poll `renewalInfo` and renew inside the CA-directed window.
5. Monitor renewal windows, missed windows, and mass-renewal risk in the Certificates UI.
6. Confirm posture/compliance integration.

Renewal intelligence sample:

```bash
curl -X GET http://127.0.0.1:5173/svc/certs/certs/renewal-intelligence?tenant_id=root \
  -H "Authorization: Bearer $TOKEN"
```

Best for:

- internal service PKI
- appliance and service mesh deployments
- environments where coordinated renewals matter more than simple cron-based rotation

### 4A. Issue Short-Lived Certificates With ACME STAR

Goal:

- keep workload certificates intentionally short-lived
- let delegated subscribers retrieve certs without losing central renewal policy
- detect mass rollout risk before many short-lived subscriptions renew together

Components used:

- `certs`
- `audit`
- `posture`
- `compliance`

Steps:

1. Enable ACME STAR in the ACME protocol policy.
2. Choose a tenant CA and optional certificate profile.
3. Create a STAR subscription with a short lifetime, renew-before window, and rollout group.
4. If needed, set a delegated subscriber identity.
5. Monitor next renewal time, latest certificate, and rollout risk in `Certificates`.

STAR summary sample:

```bash
curl -X GET http://127.0.0.1:5173/svc/certs/certs/star/summary?tenant_id=root \
  -H "Authorization: Bearer $TOKEN"
```

STAR create sample:

```bash
curl -X POST http://127.0.0.1:5173/svc/certs/certs/star/subscriptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "name": "mesh-edge",
    "ca_id": "ca_runtime",
    "subject_cn": "edge.root.example",
    "sans": ["edge.root.example"],
    "validity_hours": 24,
    "renew_before_minutes": 120,
    "auto_renew": true,
    "allow_delegation": true,
    "delegated_subscriber": "spiffe://prod/ns/edge/sa/gateway",
    "rollout_group": "mesh-us-east-1"
  }'
```

## 5. Configure Sender-Constrained REST Clients

Goal:

- harden SDK and automation access to the REST API
- detect replay and unsigned requests

Components used:

- `auth`
- `keycore`
- `audit`
- `compliance`
- `posture`

Steps:

1. Register or locate the API client in Auth.
2. Choose `OAuth mTLS`, `DPoP`, or `HTTP Message Signatures`.
3. Rotate or bind the client key material.
4. Call `rest-client-security/summary` to confirm counters and mode.
5. Review replay and signature failures in Audit and Posture.

DPoP example:

```bash
curl -X PUT http://127.0.0.1:5173/svc/auth/auth/clients/reg_orders_sdk?tenant_id=root \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_mode": "dpop",
    "replay_protection_enabled": true,
    "rate_limit": 1200
  }'
```

Best for:

- SDKs
- agents
- automation systems
- environments that want to eliminate replayable bearer-only access

## 5A. Govern HYOK Or EKM Requests With Key Access Justifications

Goal:

- require external key requests to declare intent
- send sensitive usage to approval instead of immediate allow

Components used:

- `keyaccess`
- `governance`
- `audit`
- `hyok` or `ekm`

Steps:

1. Enable Key Access Justifications for the tenant.
2. Create reason codes for each allowed service and operation pair.
3. Bind high-risk codes to an approval policy.
4. Route HYOK or EKM callers through the governed path.
5. Review decisions and bypass signals in Audit, Posture, and Compliance.

Settings sample:

```bash
curl -X PUT http://127.0.0.1:5173/svc/keyaccess/key-access/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "enabled": true,
    "mode": "enforce",
    "default_action": "deny",
    "require_justification_code": true,
    "require_justification_text": false
  }'
```

Reason-code sample:

```bash
curl -X POST http://127.0.0.1:5173/svc/keyaccess/key-access/codes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "code": "iso20022_payment",
    "label": "ISO 20022 payment signing",
    "action": "allow",
    "services": ["payment", "hyok"],
    "operations": ["sign", "decrypt"],
    "enabled": true
  }'
```

Best for:

- regulated external-key workflows
- explainable cloud or HYOK decrypt/sign access
- approval-aware high-value key use

## 5B. Sign Release Artifacts With KMS-Backed Identity Policy

Goal:

- sign build outputs without exporting private keys
- bind release signing to workload or OIDC identity

Components used:

- `signing`
- `keycore`
- `workload` or external OIDC
- `audit`

Steps:

1. Enable Artifact Signing for the tenant.
2. Create a signing profile with the correct key, artifact type, and identity mode.
3. Restrict allowed workload or OIDC claims.
4. Sign the blob or Git artifact.
5. Verify the record and inspect transparency metadata.

Profile sample:

```bash
curl -X POST http://127.0.0.1:5173/svc/signing/signing/profiles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "name": "prod-release-git",
    "artifact_type": "git",
    "key_id": "key_signing_prod",
    "signing_algorithm": "ecdsa-sha384",
    "identity_mode": "workload",
    "allowed_workload_patterns": ["spiffe://root/workloads/release-*"],
    "transparency_required": true,
    "enabled": true
  }'
```

Sign sample:

```bash
curl -X POST http://127.0.0.1:5173/svc/signing/signing/git \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "profile_id": "sigprof_prod_release",
    "artifact_name": "kms-dashboard",
    "commit_sha": "7a33a1b9",
    "repository": "github.com/example/kms-dashboard",
    "workload_identity": "spiffe://root/workloads/release-runner",
    "payload": "release-metadata"
  }'
```

Best for:

- software supply-chain controls
- CI/CD signing
- KMS-managed provenance

## 6. Protect Databases With EKM And Agents

Goal:

- register databases or BitLocker endpoints
- manage wrapped keys and agent health centrally

Components used:

- `ekm`
- `ekm-agent`
- `keycore`
- `audit`

Steps:

1. Install the EKM agent on the target host.
2. Register the agent or database.
3. Create TDE keys or BitLocker policies through EKM.
4. Wrap and unwrap DEKs through the service.
5. Review status, heartbeats, jobs, and audit records.

Database registration sample:

```bash
curl -X POST http://127.0.0.1:5173/svc/ekm/ekm/databases?tenant_id=root \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "oracle-prod-01",
    "db_engine": "oracle",
    "host_ip": "10.0.0.16",
    "environment": "prod"
  }'
```

Best for:

- MSSQL TDE
- Oracle TDE
- Windows BitLocker control

## 7. Build A KMIP Integration

Goal:

- support enterprise tools that speak KMIP instead of REST

Components used:

- `kmip`
- `certs`
- `keycore`

Steps:

1. Generate or issue KMIP client certificates.
2. Create KMIP client profile and client object.
3. Validate interoperability target if needed.
4. Point the KMIP client to `127.0.0.1:5696` or the edge proxy.

See the detailed KMIP smoke-test examples in [../services/kmip/README.md](../services/kmip/README.md).

Best for:

- middleware
- appliances
- enterprise key consumers that already standardize on KMIP

## 8. Enforce Payment Policy And Run Payment Crypto

Goal:

- separate production payment guardrails from workbench operations

Components used:

- `payment`
- `dataprotect`
- `governance`
- `audit`

Steps:

1. Open `Data Protection -> Payment Policy`.
2. Configure `Traditional Payment` for TR-31, KBPK, PIN, CVV, MAC, and TCP controls.
3. Configure `Modern Payment` for ISO 20022 and AP2.
4. Open `Workbench -> Payment Crypto` for test operations.
5. Audit policy updates and runtime operations separately.

AP2 profile sample:

```bash
curl -X PUT http://127.0.0.1:5173/svc/payment/payment/ap2/profile?tenant_id=root \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "allowed_protocol_bindings": ["a2a", "mcp"],
    "allowed_payment_rails": ["card", "ach"],
    "allowed_currencies": ["USD"],
    "require_payment_mandate": true
  }'
```

Best for:

- PCI and card-processing environments
- ISO 20022 adoption
- agentic payment evaluation under policy

## 9. Gate Key Release On Attestation

Goal:

- release keys only to approved confidential-compute runtimes

Components used:

- `confidential`
- `keycore`
- `audit`
- `cluster-manager`

Steps:

1. Create a tenant attestation policy.
2. Define provider, allowed subjects, images, and required measurements.
3. Send a signed attestation document for evaluation.
4. Review allow/review/deny result and release history.

Evaluation sample:

```bash
curl -X POST http://127.0.0.1:5173/svc/confidential/confidential/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "key_id": "key_signing_prod",
    "key_scope": "signing-prod",
    "provider": "aws_nitro_enclaves",
    "attestation_format": "cose_sign1",
    "dry_run": true,
    "attestation_document": "<provider-document>"
  }'
```

Best for:

- enclave-based authorizers
- TEE-protected signers
- environments that require measurement-aware release decisions

## 10. Plan And Execute PQC Migration

Goal:

- understand where classical crypto is still used
- move to hybrid or PQC-only in controlled stages

Components used:

- `pqc`
- `keycore`
- `certs`
- `compliance`
- `posture`

Steps:

1. Set tenant PQC policy.
2. Run a scan.
3. Review inventory and readiness.
4. Create migration plans.
5. Execute or roll back plans as needed.
6. Review compliance/posture outputs for remaining drift.

Readiness sample:

```bash
curl -X GET http://127.0.0.1:5173/svc/pqc/pqc/readiness?tenant_id=root \
  -H "Authorization: Bearer $TOKEN"
```

Best for:

- staged hybrid TLS rollout
- migration inventory and planning
- executive reporting on quantum readiness

## 10A. Run A Threshold Signing Ceremony For A High-Assurance Key

Goal:

- require multiple operators or services to sign together
- keep a full ceremony trail for high-value keys

Components used:

- `mpc`
- `governance`
- `audit`

Steps:

1. Register participants.
2. Create a threshold policy.
3. Initiate DKG or sign ceremony.
4. Collect enough contributions to reach the threshold.
5. Retrieve the signature result and review the ceremony trail.

Overview sample:

```bash
curl -X GET http://127.0.0.1:5173/svc/mpc/mpc/overview?tenant_id=root \
  -H "Authorization: Bearer $TOKEN"
```

Sign-initiate sample:

```bash
curl -X POST http://127.0.0.1:5173/svc/mpc/mpc/sign/initiate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "key_id": "mpc_root_ca_01",
    "message_hash": "4dbaf4...e3",
    "participants": ["alice@bank.com", "bob@bank.com", "hsm-partition"]
  }'
```

Best for:

- root CA ceremony control
- high-value transaction signing
- split-operator trust separation

## 11. Run Compliance And Posture As Daily Operations

Goal:

- use evidence, not snapshots, to drive remediation

Components used:

- `audit`
- `compliance`
- `posture`
- `reporting`
- `governance`

Steps:

1. Run or schedule compliance assessments.
2. Review posture dashboard for risk drivers and blast radius.
3. Group remediation into safe auto-fix, approval-required, and manual.
4. Use reporting to export alerts, incidents, and evidence packs.
5. Route high-impact actions into Governance approval flow.

Assessment sample:

```bash
curl -X POST http://127.0.0.1:5173/svc/compliance/compliance/assessment/run?tenant_id=root \
  -H "Authorization: Bearer $TOKEN"
```

Best for:

- security operations centers
- regulated environments
- executive and operator reporting

## 12. Run BYOK Or HYOK Across Cloud Estates

Goal:

- keep control of key policy while integrating with cloud-native services

Components used:

- `cloud`
- `keycore`
- `audit`
- `compliance`

Steps:

1. Register cloud accounts and region mappings.
2. Import or bind KMS-managed key material.
3. Run sync and monitor the inventory.
4. Rotate the cloud binding under central governance.

Sample:

```bash
curl -X POST http://127.0.0.1:5173/svc/cloud/cloud/sync?tenant_id=root \
  -H "Authorization: Bearer $TOKEN"
```

Best for:

- AWS, Azure, and GCP estates
- customer-controlled key requirements
- cloud-to-platform inventory and drift tracking

## 13. Provision KMS Users And Groups From Okta Or Entra With SCIM

Goal:

- let the identity provider manage KMS users and groups automatically
- map external directory groups to tenant roles without manual per-user edits

Components used:

- `auth`
- `audit`
- `posture`
- `compliance`

Steps:

1. Open `Administration -> User Admin -> SCIM Provisioning`.
2. Enable SCIM for the tenant, choose the default role and deprovision mode, and keep group-role mapping enabled if directory groups should drive RBAC.
3. Rotate the bearer token and copy it into Okta, Entra ID, or another SCIM client.
4. In the IdP, configure the SCIM base URL as the KMS auth service SCIM endpoint.
5. Push users and groups from the directory.
6. Map provisioned group IDs to KMS roles using the group-role bindings view.
7. Confirm the SCIM summary, posture, compliance, and audit views show the new managed identities.

Sample admin setup:

```bash
curl -X PUT http://127.0.0.1:5173/svc/auth/auth/scim/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "enabled": true,
    "default_role": "readonly",
    "default_status": "active",
    "deprovision_mode": "disable",
    "group_role_mappings_enabled": true
  }'

curl -X POST http://127.0.0.1:5173/svc/auth/auth/scim/settings/rotate-token \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"root"}'
```

Sample IdP push:

```bash
curl -X POST http://127.0.0.1:5173/svc/auth/scim/v2/Users \
  -H "Authorization: Bearer scim_xxxxx" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "externalId": "okta-user-01",
    "userName": "alice.scim",
    "displayName": "Alice SCIM",
    "active": true,
    "emails": [{"value": "alice@example.com", "primary": true}],
    "roles": [{"value": "readonly"}]
  }'
```

Best for:

- enterprise onboarding with Okta or Entra ID
- lifecycle-driven disable/deprovision workflows
- group-driven RBAC for platform and security teams
