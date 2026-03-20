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
