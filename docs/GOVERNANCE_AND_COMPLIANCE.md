# Governance, Compliance, Audit & Alerting — Vecta KMS

> **Scope:** This document covers every aspect of Vecta KMS governance, compliance, audit logging, alerting, reporting, posture management, and related operational workflows. It is intended for security engineers, compliance officers, platform operators, and auditors who need to understand, configure, or evidence these capabilities.

---

## Table of Contents

1. [Audit Log](#1-audit-log)
   - 1.1 [Why Immutable Audit Logging Matters](#11-why-immutable-audit-logging-matters)
   - 1.2 [Audit Chain Integrity](#12-audit-chain-integrity)
   - 1.3 [Event Schema](#13-event-schema-all-fields-explained)
   - 1.4 [Complete Action Taxonomy](#14-complete-action-taxonomy)
   - 1.5 [Querying the Audit Log](#15-querying-the-audit-log)
   - 1.6 [Merkle Proof Verification](#16-merkle-proof-verification)
   - 1.7 [SIEM Export Formats](#17-siem-export-formats)
2. [Governance & Approvals](#2-governance--approvals)
   - 2.1 [Multi-Quorum Governance Model](#21-multi-quorum-governance-model)
   - 2.2 [Policy Configuration](#22-policy-configuration)
   - 2.3 [Request Lifecycle](#23-request-lifecycle)
   - 2.4 [Notification Channels Setup](#24-notification-channels-setup)
   - 2.5 [Backup & Restore](#25-backup--restore)
   - 2.6 [System State Management](#26-system-state-management)
3. [Compliance Framework](#3-compliance-framework)
   - 3.1 [Supported Frameworks](#31-supported-frameworks)
   - 3.2 [Compliance Templates](#32-compliance-templates)
   - 3.3 [Assessment Engine](#33-assessment-engine)
   - 3.4 [Posture Breakdown](#34-posture-breakdown)
   - 3.5 [Key Hygiene Metrics](#35-key-hygiene-metrics)
   - 3.6 [Scheduling](#36-scheduling)
4. [Alert Center](#4-alert-center)
   - 4.1 [Alert Rules](#41-alert-rules)
   - 4.2 [Notification Channels](#42-notification-channels)
   - 4.3 [MTTR and MTTD](#43-mttr-and-mttd)
   - 4.4 [Reporting](#44-reporting)
5. [Posture & Risk Detection](#5-posture--risk-detection)
6. [SBOM / CBOM](#6-sbom--cbom)
7. [Operational Use Cases](#7-operational-use-cases)
8. [Full API Reference](#8-full-api-reference)

---

## 1. Audit Log

### 1.1 Why Immutable Audit Logging Matters

Audit logging in Vecta KMS is not an afterthought — it is a first-class security control designed to satisfy the most demanding regulatory environments. The audit subsystem provides:

**Regulatory compliance evidence.** Major frameworks mandate audit trails for cryptographic key operations:

| Framework | Relevant Requirement | Vecta Control |
|---|---|---|
| PCI DSS v4.0 | Req 10: Log and monitor all access to system components and cardholder data | Immutable chained event log with chain hash verification |
| PCI DSS v4.0 | Req 10.3.2: Audit log files are protected from destruction and unauthorized modifications | Merkle tree sealing, tamper-evident chain |
| SOC 2 CC6.1 | Logical access controls and authentication events logged | Full authentication event capture |
| SOC 2 CC7.2 | Anomalies and incidents detected and monitored | Alert rules with CEL expressions |
| HIPAA §164.312(b) | Audit controls: hardware, software, and procedural mechanisms to record activity | Nanosecond-precision event recording |
| GDPR Art. 30 | Records of processing activities | Actor, action, target, timestamp captured for every operation |
| NIST SP 800-92 | Guide to Computer Security Log Management | Structured JSON events, SIEM export, retention policies |
| ISO 27001 A.12.4 | Event logging and protection of log information | Chain integrity, Merkle proof, signed export |
| DORA Art. 10 | ICT-related incident management | Correlation ID grouping, timeline views, incident evidence packages |

**Forensic investigation.** When a security incident occurs — unauthorized key access, privilege escalation, data exfiltration — the audit log provides the evidence trail needed to reconstruct what happened, who did it, when, from where, and what the outcome was. Every API call that touches a key, certificate, user, or policy is recorded with full context.

**Non-repudiation.** Because events are cryptographically chained (SHA-256 chain hash) and can be sealed into Merkle trees with inclusion proofs, no actor can later deny that an operation occurred. The chain hash scheme makes it mathematically detectable if any historical record is altered, deleted, or inserted.

**Operational visibility.** Beyond compliance, the audit log enables operational monitoring: detect unusual usage patterns, identify service accounts making unexpected calls, track the drift of key usage across environments, and feed real-time dashboards.

**Chain of custody for keys.** Every key has a complete lifecycle history: who created it, who granted access, who used it (and for what), when it was rotated, and when it was destroyed. This chain of custody is essential for regulated environments and forensic readiness.

---

### 1.2 Audit Chain Integrity

Vecta KMS implements a **sequential hash chain** across all audit events. This is a lightweight, deterministic mechanism that makes any tampering — insertion, deletion, or modification of any event — immediately detectable.

#### How the Chain Works

Each audit event carries two hash fields:

- `previous_hash`: the `chain_hash` value of the immediately preceding event in the sequence
- `chain_hash`: the SHA-256 digest of the concatenation of `previous_hash` and a canonical serialisation of the current event's data

```
event[n].chain_hash = SHA-256(event[n-1].chain_hash || canonical_bytes(event[n]))
```

The **genesis event** (the very first event ever recorded) uses a fixed sentinel as its previous hash:

```
event[0].previous_hash = "genesis"
event[0].chain_hash    = SHA-256("genesis" || canonical_bytes(event[0]))
```

#### Tamper Detection

To verify that event `n` has not been altered:

1. Retrieve event `n` and event `n-1` from the store.
2. Recompute: `expected = SHA-256(event[n-1].chain_hash || canonical_bytes(event[n]))`.
3. Compare `expected` against the stored `event[n].chain_hash`.
4. A mismatch proves the record at position `n` was modified after it was written.

To verify the **entire chain** up to the current head:

```bash
curl -X GET "http://localhost:5173/svc/audit/audit/chain/verify?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "valid": true,
  "events_checked": 142857,
  "first_sequence": 1,
  "last_sequence": 142857,
  "first_chain_hash": "sha256:4b2a...",
  "last_chain_hash":  "sha256:9f3c...",
  "broken_at_sequence": null,
  "verification_duration_ms": 4312
}
```

If tampering is detected, `valid` is `false` and `broken_at_sequence` identifies the first event where the chain breaks.

#### Monotonic Sequence Numbers

In addition to the hash chain, every event carries a `sequence` number that is strictly monotonically increasing per tenant. Gaps in the sequence (e.g. sequence jumps from 1000 to 1002 with no 1001) indicate deletion. The verification endpoint checks both the hash chain and sequence continuity.

#### Epoch Sealing

At regular intervals (or on demand), the current head of the chain is sealed into a **Merkle epoch**. The Merkle root is an immutable commitment to the entire batch of events. Once sealed, the epoch root can be stored externally (in a notary service, a blockchain, or a hardware security module) to provide a second, independent proof layer.

---

### 1.3 Event Schema (All Fields Explained)

Every audit event is a structured JSON object conforming to the `AuditEvent` schema. All fields are described below.

#### Identity & Sequencing

| Field | Type | Description |
|---|---|---|
| `id` | UUID string | Globally unique event identifier. Use this as the stable reference when filing evidence packages or linking events across systems. |
| `tenant_id` | string | The tenant that owns this event. In a multi-tenant deployment, events from different tenants are stored separately and are never visible across tenant boundaries without root access. |
| `sequence` | int64 | Monotonically increasing sequence number within the tenant's event stream. Sequence numbers start at 1 and never repeat or reset. Gaps indicate deleted events. |
| `chain_hash` | string | SHA-256 hash of `previous_hash + canonical_event_bytes`. Proves this event has not been modified since it was written. Format: `sha256:<hex>`. |
| `previous_hash` | string | The `chain_hash` of the immediately preceding event. For the genesis event, this is the string literal `"genesis"`. |

#### Timing

| Field | Type | Description |
|---|---|---|
| `timestamp` | RFC3339Nano string | Nanosecond-precision UTC timestamp of when the event was recorded by the audit service. For distributed deployments, this is the time the audit service received and persisted the event. |

#### Service & Action Classification

| Field | Type | Description |
|---|---|---|
| `service` | string | The Vecta microservice that emitted this event. Values: `keycore`, `auth`, `certs`, `governance`, `compliance`, `reporting`, `dataprotect`, `payment`, `autokey`. |
| `action` | string | The specific operation performed. Hierarchically structured as `resource.verb` or `resource.sub-resource.verb` (e.g. `key.encrypt`, `key.access_policy.update`). See the complete taxonomy in section 1.4. |

#### Actor (Who Performed the Action)

| Field | Type | Description |
|---|---|---|
| `actor_id` | UUID string | The identity of the entity that performed the operation. For human users this is the user UUID. For service accounts and workloads, it is the client/service UUID. |
| `actor_type` | enum | One of: `user` (human operator authenticated via password/SSO/MFA), `service` (machine-to-machine OAuth2 client credential), `workload` (short-lived workload identity token), `system` (internal platform automation, e.g. scheduled rotation). |

#### Target (What Was Acted Upon)

| Field | Type | Description |
|---|---|---|
| `target_type` | string | The type of resource that was the subject of the action. Examples: `key`, `certificate`, `ca`, `user`, `tenant`, `policy`, `backup`, `governance_request`. |
| `target_id` | UUID string | The specific resource instance. Combine with `target_type` to look up the resource. May be empty for actions that create a new resource (use the `details` field for the created resource's ID). |

#### Request Context

| Field | Type | Description |
|---|---|---|
| `method` | string | HTTP method used: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. |
| `endpoint` | string | Full URL path of the API call, including path parameters (e.g. `/svc/keycore/keys/uuid-here/encrypt`). Query parameters are excluded for brevity; they appear in `details`. |
| `source_ip` | string | The IP address of the caller as seen by the API gateway. For requests through a load balancer, this is the forwarded client IP (from `X-Forwarded-For`). |
| `user_agent` | string | The HTTP `User-Agent` header, useful for identifying SDK versions, browser types, or custom integrations. |
| `request_hash` | string | SHA-256 hash of the raw request body (before any decoding). This proves exactly what payload was sent. For key operations, this lets auditors verify the ciphertext or plaintext size without storing the actual payload. Format: `sha256:<hex>`. |

#### Correlation & Grouping

| Field | Type | Description |
|---|---|---|
| `correlation_id` | UUID string | Groups all events that belong to the same logical operation, even if that operation spans multiple microservices. Example: a key rotation that triggers a governance request, a backup, and re-encryption of dependent data will all share the same `correlation_id`. |
| `parent_event_id` | UUID string | For child events spawned by a parent operation (e.g. a key rotation emits child events for each dependent key update), this links back to the originating event. Enables tree reconstruction of complex operations. |
| `session_id` | UUID string | Groups all events from a single authenticated session (e.g. all actions taken by a user during one login session). Enables session replay for forensic investigation. |

#### Result

| Field | Type | Description |
|---|---|---|
| `result` | enum | Outcome of the operation: `success` (completed as requested), `failure` (operation rejected or errored), `partial` (operation partially completed, e.g. bulk operation where some items succeeded and others failed). |
| `status_code` | int | HTTP status code returned to the caller. 2xx = success, 4xx = client error, 5xx = server error. |
| `error_message` | string | Human-readable error description when `result` is `failure`. Sanitised — never contains sensitive data. |
| `duration_ms` | int64 | Total time in milliseconds between request receipt and response dispatch. Used for performance monitoring and detecting timing-based anomalies. |

#### Compliance & Risk

| Field | Type | Description |
|---|---|---|
| `fips_compliant` | boolean | `true` if the operation used only FIPS 140-3 approved algorithms and was processed by a FIPS-validated module. `false` if non-FIPS algorithms were used. |
| `approval_id` | UUID string | If this operation required and received governance approval, this is the `id` of the governance request that approved it. Links the operation to its approval chain. |
| `risk_score` | int | Risk severity of this event on a 0–100 scale. 0 = routine read operation. 100 = catastrophic (e.g. root CA deletion). Used by the alert engine and compliance posture engine. See risk score guidance in section 1.4. |

#### Metadata

| Field | Type | Description |
|---|---|---|
| `tags` | string[] | Free-form labels attached to the event. Propagated from the key's labels (e.g. `["env:production", "team:payments"]`), the tenant's labels, and any explicit tags added by the SDK. Enables filtered reporting by business dimension. |
| `node_id` | string | Identifier of the Vecta KMS node that processed the request. In a clustered deployment, this lets operators correlate events to specific nodes for debugging (e.g. after a node crash). |
| `details` | object | Service-specific JSON object containing additional context that does not fit the standard schema. Structure varies by action. Examples: for `key.create`, includes `algorithm`, `key_size`, `purpose`; for `cert.issued`, includes `subject_cn`, `san_list`, `validity_days`. Always check `details` for action-specific context. |

---

### 1.4 Complete Action Taxonomy

The table below lists every defined audit action across all Vecta services, along with a description of what triggers it, typical risk scores, and the fields most likely to be populated in `details`.

#### keycore — Key Lifecycle & Operations

| Action | Description | Typical Risk Score | Key `details` Fields |
|---|---|---|---|
| `key.create` | A new cryptographic key was created (algorithm, purpose, labels set). | 40 | `algorithm`, `key_size`, `purpose`, `curve`, `labels` |
| `key.import` | An external key material was imported into the KMS. Higher risk than creation because provenance of key material is unknown. | 65 | `algorithm`, `key_size`, `import_method`, `wrapped` |
| `key.rotate` | Key material was rotated; old version retired, new version promoted. Previous version remains for decryption of existing ciphertext. | 55 | `old_version`, `new_version`, `rotation_reason` |
| `key.destroy` | Key material permanently deleted. This action is irreversible. Any data encrypted with this key becomes unrecoverable. | 95 | `version_destroyed`, `destruction_reason`, `approved_by` |
| `key.activate` | Key state changed to Active (operational, can be used for all permitted operations). | 30 | `previous_state`, `new_state` |
| `key.deactivate` | Key state changed to Deactivated (no longer available for encryption/signing; decryption may still be permitted for legacy data). | 60 | `previous_state`, `new_state`, `deactivation_reason` |
| `key.encrypt` | Data was encrypted using this key. Records ciphertext size but never plaintext. | 20 | `plaintext_length`, `ciphertext_length`, `algorithm`, `aad_present` |
| `key.decrypt` | Data was decrypted using this key. High-sensitivity operation — correlate failed decrypts with brute-force detection rules. | 35 | `ciphertext_length`, `algorithm`, `aad_present` |
| `key.sign` | A digital signature was created using this key. | 25 | `message_length`, `signature_algorithm`, `digest_algorithm` |
| `key.verify` | A digital signature was verified using this key. | 10 | `signature_valid`, `signature_algorithm`, `digest_algorithm` |
| `key.wrap` | Another key was wrapped (encrypted) using this key. Common in key hierarchy operations. | 50 | `wrapped_key_id`, `wrap_algorithm` |
| `key.unwrap` | A wrapped key was unwrapped (decrypted) using this key. | 55 | `wrapped_key_id`, `unwrap_algorithm` |
| `key.derive` | A derived key was created from this key using a KDF (HKDF, PBKDF2, SP800-108). | 45 | `kdf_algorithm`, `context`, `derived_key_id` |
| `key.export` | Raw key material was exported from the KMS. Extremely high risk — only permitted when `exportable` policy is true. | 90 | `export_format`, `recipient`, `approval_id` |
| `key.kem.encapsulate` | A KEM (Key Encapsulation Mechanism) encapsulation was performed (post-quantum: ML-KEM / Kyber). | 25 | `kem_algorithm`, `shared_secret_length` |
| `key.kem.decapsulate` | KEM decapsulation — shared secret recovered from ciphertext. | 35 | `kem_algorithm`, `shared_secret_length` |
| `key.access_policy.update` | The access control policy on the key was modified (grants added or removed). | 70 | `previous_policy_hash`, `new_policy_hash`, `changes` |
| `key.access_policy.grant_denied` | An access check was performed and the requesting principal was denied. | 55 | `denied_principal`, `attempted_operation`, `policy_rule` |
| `key.usage_limit.set` | Usage limits were set or updated on the key (max encrypt operations, expiry). | 40 | `max_operations`, `expiry_date`, `previous_limits` |
| `key.interface_policy.update` | The interface policy was updated (which APIs can be used with this key). | 50 | `previous_interfaces`, `new_interfaces` |

#### auth — Authentication & Identity

| Action | Description | Typical Risk Score | Key `details` Fields |
|---|---|---|---|
| `user.login` | Successful authentication. | 5 | `auth_method`, `mfa_used`, `ip_country` |
| `user.logout` | Explicit logout (session terminated by user). | 2 | `session_duration_s` |
| `user.login_failed` | Failed authentication attempt. | 45 | `failure_reason`, `attempt_count`, `ip_country` |
| `user.locked` | Account locked after repeated failed attempts. | 75 | `failed_attempts`, `lockout_duration_s` |
| `user.unlocked` | Account unlocked by administrator. | 30 | `unlocked_by`, `previous_lock_reason` |
| `user.password_changed` | Password was changed (either by user or admin reset). | 40 | `changed_by`, `forced_reset` |
| `user.created` | New user account provisioned. | 35 | `roles_assigned`, `provisioning_method` |
| `user.role_changed` | User's roles were modified. | 65 | `previous_roles`, `new_roles`, `changed_by` |
| `user.status_changed` | User enabled/disabled. | 50 | `previous_status`, `new_status`, `reason` |
| `tenant.created` | A new tenant was created. | 60 | `tenant_name`, `admin_user_id` |
| `tenant.disabled` | Tenant was administratively disabled (all sessions terminated). | 80 | `disabled_by`, `reason` |
| `tenant.deleted` | Tenant permanently deleted with all associated data. | 100 | `deleted_by`, `data_purged` |
| `client.registered` | An OAuth2 client (service account) was registered. | 40 | `client_name`, `grant_types`, `scopes` |
| `client.revoked` | An OAuth2 client's credentials were revoked. | 55 | `revoked_by`, `reason` |
| `scim.user_provisioned` | User provisioned via SCIM 2.0 (from IdP). | 25 | `idp_user_id`, `groups` |
| `scim.user_deprovisioned` | User deprovisioned via SCIM 2.0. | 45 | `idp_user_id`, `sessions_terminated` |
| `sso.login` | Login completed via SSO (SAML 2.0 or OIDC). | 5 | `idp_entity_id`, `name_id_format`, `authn_context` |
| `mfa.success` | MFA challenge completed successfully. | 5 | `mfa_method`, `device_id` |
| `mfa.failure` | MFA challenge failed. | 60 | `mfa_method`, `failure_reason`, `attempt_count` |

#### certs — PKI & Certificate Management

| Action | Description | Typical Risk Score | Key `details` Fields |
|---|---|---|---|
| `cert.issued` | Certificate issued by a CA. | 30 | `subject_cn`, `san_list`, `validity_days`, `issuing_ca_id` |
| `cert.renewed` | Certificate renewed (new validity period). | 20 | `previous_expiry`, `new_expiry`, `renewal_method` |
| `cert.revoked` | Certificate revoked (added to CRL and/or OCSP). | 70 | `revocation_reason`, `revoked_by` |
| `cert.deleted` | Certificate record deleted from store. | 50 | `deleted_by` |
| `ca.created` | Certificate Authority created. | 75 | `ca_type`, `subject_dn`, `key_algorithm`, `path_length` |
| `ca.deleted` | Certificate Authority deleted. | 90 | `deleted_by`, `certs_invalidated` |
| `acme.order_created` | ACME protocol order created (Let's Encrypt-style). | 15 | `domain`, `challenge_type` |
| `acme.order_finalized` | ACME order completed and certificate issued. | 25 | `domain`, `cert_id` |
| `est.enrolled` | EST (RFC 7030) enrollment completed. | 30 | `device_id`, `issuing_ca_id` |
| `scep.enrolled` | SCEP enrollment completed (legacy device support). | 30 | `device_id`, `challenge_verified` |
| `star.subscription_created` | STAR (Short-Term Automatic Renewal) subscription created. | 20 | `domain`, `renewal_period_hours` |
| `star.cert_issued` | STAR automatic renewal certificate issued. | 15 | `domain`, `validity_hours`, `renewal_count` |

#### governance — Governance, Backup & Policy

| Action | Description | Typical Risk Score | Key `details` Fields |
|---|---|---|---|
| `governance.request.created` | A governance approval request was created. | 35 | `triggered_action`, `triggered_resource_id`, `policy_id` |
| `governance.request.approved` | A governance request reached quorum and was approved. | 20 | `approvers`, `votes_cast`, `quorum_required` |
| `governance.request.denied` | A governance request was denied. | 30 | `deniers`, `denial_reasons` |
| `governance.request.expired` | A governance request expired before quorum was reached. | 40 | `timeout_hours`, `votes_received`, `quorum_required` |
| `governance.backup.created` | A backup artifact was created. | 45 | `scope`, `encryption_algorithm`, `hsm_bound`, `artifact_size_bytes` |
| `governance.backup.restored` | A backup was restored. | 85 | `backup_id`, `target_tenant`, `restored_by` |
| `governance.policy.created` | A governance policy was created or updated. | 50 | `policy_name`, `scope`, `trigger_actions`, `quorum_mode` |
| `governance.fips.enabled` | FIPS mode was enabled for the system. | 60 | `enabled_by`, `previous_mode` |
| `governance.fips.disabled` | FIPS mode was disabled. | 70 | `disabled_by`, `reason` |

---

### 1.5 Querying the Audit Log

The audit service exposes a rich query interface. All query parameters are optional and can be combined. Results are paginated.

#### List Events with Filters

```bash
# List recent key operations with high risk score (risk >= 70)
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&service=keycore&min_risk_score=70&limit=100" \
  -H "Authorization: Bearer $TOKEN"

# All events for a specific key (full lifecycle history)
curl "http://localhost:5173/svc/audit/audit/timeline/KEY_UUID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Session replay — all events in a single user session
curl "http://localhost:5173/svc/audit/audit/session/SESSION_UUID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Correlation group — all events in a distributed operation
curl "http://localhost:5173/svc/audit/audit/correlation/CORRELATION_UUID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Events for a specific actor in a date range
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&actor_id=USER_UUID&date_from=2024-01-01T00:00:00Z&date_to=2024-01-31T23:59:59Z" \
  -H "Authorization: Bearer $TOKEN"

# Failed operations only (for incident investigation)
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&result=failure&limit=50" \
  -H "Authorization: Bearer $TOKEN"

# All key destruction events ever
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&action=key.destroy" \
  -H "Authorization: Bearer $TOKEN"

# High-risk events from a specific IP address
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&source_ip=198.51.100.42&min_risk_score=50" \
  -H "Authorization: Bearer $TOKEN"

# Events requiring governance approval (filter by approval_id non-empty)
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&has_approval=true" \
  -H "Authorization: Bearer $TOKEN"

# Events tagged with a specific label (e.g. production payment keys only)
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&tag=env:production&service=keycore" \
  -H "Authorization: Bearer $TOKEN"
```

#### Query Parameters Reference

| Parameter | Type | Description |
|---|---|---|
| `tenant_id` | string | **Required.** Tenant to query. Use `root` for the root tenant. |
| `service` | string | Filter by service: `keycore`, `auth`, `certs`, `governance`, etc. |
| `action` | string | Exact action match: `key.encrypt`, `cert.revoked`, etc. |
| `actor_id` | UUID | Filter by actor (user, service account). |
| `actor_type` | enum | `user`, `service`, `workload`, `system`. |
| `target_id` | UUID | Filter by target resource (e.g. a specific key UUID). |
| `target_type` | string | Filter by target resource type: `key`, `certificate`, `user`, etc. |
| `result` | enum | `success`, `failure`, `partial`. |
| `source_ip` | string | Exact IP address match. |
| `min_risk_score` | int | Include only events with `risk_score >= N`. |
| `max_risk_score` | int | Include only events with `risk_score <= N`. |
| `date_from` | RFC3339 | Start of time range (inclusive). |
| `date_to` | RFC3339 | End of time range (inclusive). |
| `tag` | string | Filter by tag (format: `key:value`). |
| `has_approval` | boolean | `true` = only events with a governance approval. |
| `correlation_id` | UUID | Events in a specific correlation group. |
| `session_id` | UUID | Events in a specific session. |
| `fips_compliant` | boolean | Filter by FIPS compliance flag. |
| `node_id` | string | Events processed by a specific cluster node. |
| `limit` | int | Results per page (default: 50, max: 1000). |
| `offset` | int | Pagination offset. |
| `sort` | string | `timestamp_asc` or `timestamp_desc` (default: `timestamp_desc`). |

---

### 1.6 Merkle Proof Verification

Merkle tree sealing provides a second layer of tamper evidence beyond the hash chain. While the chain hash detects modification of individual events, Merkle proofs provide **non-interactive inclusion proofs**: a third party can verify that a specific event was recorded in a specific epoch without access to the full event log.

#### How Merkle Epochs Work

1. A **Merkle epoch** is a snapshot of a batch of audit events (up to `max_leaves` events).
2. Each event is hashed (SHA-256 of its canonical bytes) to form a **leaf**.
3. Leaves are combined in pairs up the tree to form a **binary Merkle tree**.
4. The **Merkle root** is a single hash that commits to the entire batch.
5. The root is stored durably (and optionally exported to an external notary service).

#### Inclusion Proof

For any event in an epoch, Vecta can generate an **inclusion proof**: the set of sibling hashes along the path from the event's leaf to the root. A verifier recomputes the path and checks that it produces the known root — without needing any other events.

This is particularly powerful for:

- **Regulatory evidence packages**: Submit event + proof to an auditor. They verify independently without accessing your KMS.
- **Court admissibility**: Chain + Merkle proof constitutes cryptographic evidence of a specific log entry at a specific time.
- **External notarization**: Publish epoch roots to a trusted timestamping authority (RFC 3161) or a public blockchain.

#### Merkle Operations

```bash
# Build a new Merkle epoch (seal current events)
curl -X POST "http://localhost:5173/svc/audit/audit/merkle/build?tenant_id=root&max_leaves=50000" \
  -H "Authorization: Bearer $TOKEN"

# Response:
# {
#   "epoch_id": "epoch-uuid",
#   "root": "sha256:abc123...",
#   "leaf_count": 50000,
#   "first_sequence": 1,
#   "last_sequence": 50000,
#   "built_at": "2024-03-15T00:00:00Z"
# }

# List all epochs
curl "http://localhost:5173/svc/audit/audit/merkle/epochs?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get Merkle inclusion proof for a specific event
curl "http://localhost:5173/svc/audit/audit/events/EVENT_UUID/proof?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Response:
# {
#   "event_id": "EVENT_UUID",
#   "epoch_id": "epoch-uuid",
#   "leaf_index": 42,
#   "leaf_hash": "sha256:def456...",
#   "siblings": [
#     {"index": 43, "hash": "sha256:ghi789..."},
#     {"index": 21, "hash": "sha256:jkl012..."},
#     {"index": 11, "hash": "sha256:mno345..."}
#   ],
#   "root": "sha256:pqr678...",
#   "tree_depth": 16
# }

# Verify a proof (can be done by any party with this endpoint)
curl -X POST "http://localhost:5173/svc/audit/audit/merkle/verify" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "EVENT_UUID",
    "leaf_hash": "sha256:def456...",
    "leaf_index": 42,
    "siblings": [
      {"index": 43, "hash": "sha256:ghi789..."},
      {"index": 21, "hash": "sha256:jkl012..."},
      {"index": 11, "hash": "sha256:mno345..."}
    ],
    "root": "sha256:pqr678...",
    "epoch_id": "epoch-uuid"
  }'

# Response:
# {
#   "valid": true,
#   "computed_root": "sha256:pqr678...",
#   "provided_root": "sha256:pqr678...",
#   "root_matches": true
# }
```

#### Verification Algorithm (Step by Step)

Given an event with leaf index `i`, leaf hash `h`, and sibling list `[(i1, h1), (i2, h2), ...]`:

```
current_hash = h
current_index = i

for each sibling (sibling_index, sibling_hash):
    if current_index is even:
        current_hash = SHA-256(current_hash || sibling_hash)
    else:
        current_hash = SHA-256(sibling_hash || current_hash)
    current_index = current_index / 2

assert current_hash == known_root
```

This computation can be performed by any party with knowledge of the leaf hash, the sibling list, and the expected root — no access to the event store is required.

---

### 1.7 SIEM Export Formats

Vecta supports exporting audit events in multiple formats compatible with common Security Information and Event Management (SIEM) platforms.

#### CSV Export

The CSV export provides a flat, spreadsheet-compatible view of audit events. Column order is fixed.

**Columns:** `id`, `timestamp`, `service`, `action`, `actor_id`, `actor_type`, `target_type`, `target_id`, `source_ip`, `result`, `status_code`, `risk_score`, `duration_ms`, `node_id`, `fips_compliant`, `correlation_id`, `session_id`, `approval_id`, `chain_hash`

```bash
# Export last 30 days of keycore events as CSV
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&service=keycore&format=csv&date_from=2024-01-01T00:00:00Z&date_to=2024-01-31T23:59:59Z" \
  -H "Authorization: Bearer $TOKEN" > keycore-jan-2024.csv

# Signed CSV export (tamper-evident — includes digital signature of file contents)
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&format=csv&signing_key_id=SIGNING_KEY_UUID" \
  -H "Authorization: Bearer $TOKEN" > audit-signed-export.csv
# The signing_key_id must reference a KMS key with purpose=sign
# Signature is embedded in the final row of the CSV: SIGNATURE_ROW,sha256:<hex>,<base64_signature>
```

#### JSON-Lines Export (for Splunk/Elastic/OpenSearch)

```bash
# Export as JSON-Lines (one JSON object per line — ideal for log shippers)
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&format=jsonl&limit=10000" \
  -H "Authorization: Bearer $TOKEN" > audit-export.jsonl

# Pipe directly to Splunk HEC (HTTP Event Collector)
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&format=jsonl" \
  -H "Authorization: Bearer $TOKEN" | \
  jq -c '{event: .}' | \
  curl -X POST "https://splunk:8088/services/collector/event" \
    -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
    --data-binary @-
```

#### CEF (Common Event Format) — Splunk / QRadar / ArcSight

CEF is a vendor-neutral syslog-compatible format used by most enterprise SIEM platforms.

**CEF Header format:**
```
CEF:0|Vendor|Product|Version|DeviceEventClassID|Name|Severity|Extensions
```

**Vecta CEF mapping:**

| CEF Field | Source |
|---|---|
| `Vendor` | `Vecta` |
| `Product` | `KMS` |
| `Version` | `1.0` |
| `DeviceEventClassID` | `action` (e.g. `key.encrypt`) |
| `Name` | Human-readable description of action |
| `Severity` | Derived from `risk_score`: 0-19→1, 20-39→3, 40-59→5, 60-79→7, 80-100→10 |

**Extension field mappings:**

| CEF Extension | Vecta Field |
|---|---|
| `deviceReceiptTime` | `timestamp` |
| `src` | `source_ip` |
| `suser` | `actor_id` |
| `fname` | `target_id` |
| `outcome` | `result` |
| `cn1` / `cn1Label` | `risk_score` / `riskScore` |
| `requestMethod` | `method` |
| `request` | `endpoint` |
| `rt` | `duration_ms` |
| `cs1` / `cs1Label` | `correlation_id` / `correlationId` |
| `cs2` / `cs2Label` | `session_id` / `sessionId` |
| `cs3` / `cs3Label` | `chain_hash` / `chainHash` |

**Example CEF event:**

```
CEF:0|Vecta|KMS|1.0|key.encrypt|Key encrypt operation|3|
  deviceReceiptTime=2024-01-15T10:23:45.123456789Z
  src=192.168.1.100
  suser=3f4a7b2c-1234-5678-abcd-ef0123456789
  fname=a1b2c3d4-5678-90ab-cdef-012345678901
  outcome=success
  cn1=20 cn1Label=riskScore
  requestMethod=POST
  request=/svc/keycore/keys/a1b2c3d4-5678-90ab-cdef-012345678901/encrypt
  rt=14
  cs1=99887766-5544-3322-1100-aabbccddeeff cs1Label=correlationId
  cs3=sha256:4b2a9f3c... cs3Label=chainHash
```

```bash
# Export as CEF (one event per line, syslog-compatible)
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&format=cef" \
  -H "Authorization: Bearer $TOKEN" > audit-export.cef

# Forward CEF events to QRadar via syslog
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&format=cef" \
  -H "Authorization: Bearer $TOKEN" | \
  nc -u qradar.company.internal 514
```

#### Leef (Log Event Extended Format) — IBM QRadar

```bash
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&format=leef" \
  -H "Authorization: Bearer $TOKEN" > audit-export.leef
```

#### Streaming via Webhook Push

Rather than polling, configure a push webhook to receive events in real time:

```bash
# Configure audit webhook (receives events within ~1 second of occurrence)
curl -X PUT "http://localhost:5173/svc/audit/audit/webhook?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://siem.company.internal/vecta-ingest",
    "format": "jsonl",
    "secret": "hmac-shared-secret",
    "min_risk_score": 0,
    "services": ["keycore", "auth", "certs"],
    "retry_attempts": 5,
    "retry_backoff_seconds": 30
  }'
```

The webhook delivers a POST with `X-Vecta-Signature: sha256=<hmac>` for receiver authentication.

---

## 2. Governance & Approvals

### 2.1 Multi-Quorum Governance Model

Vecta KMS implements a **multi-quorum governance model** that enforces four-eyes (or N-eyes) control over sensitive operations. This is the platform's mechanism for meeting "dual control" and "split knowledge" requirements found in PCI DSS, NIST SP 800-57, and other frameworks.

**Core concept:** Certain operations — destroying a key, exporting key material, rotating a root CA, disabling FIPS mode — are "gated." Before the system executes them, it requires explicit approval votes from a quorum of authorised approvers. No single person, regardless of their role, can perform these operations unilaterally.

**Why this matters in regulated environments:**

- **PCI DSS Req 3.7.1:** Key management procedures require dual control and split knowledge for key components.
- **NIST SP 800-57 Part 1 §8.2.3:** Key management practices should include human controls such as dual control.
- **SOC 2 CC6.3:** Access to sensitive operations is restricted and reviewed.
- **DORA Art. 9:** ICT risk management controls for critical operations.

**Architecture:**

```
Requester submits operation
        │
        ▼
API Gateway → Governance Middleware
        │
        ├─ Is this action in a policy's trigger_actions? ─── No → Execute immediately
        │
        └─ Yes → Create GovernanceRequest (status: pending)
                        │
                        ├─ Notify approvers (dashboard, email, Slack, Teams)
                        │
                        ▼
                 Approvers vote (approve / deny + comment)
                        │
                        ├─ Quorum reached (approved) → Auto-execute operation → Audit event with approval_id
                        │
                        ├─ Quorum reached (denied) → Block operation → Notify requester
                        │
                        └─ Timeout → Auto-deny → Notify requester + escalation contact
```

---

### 2.2 Policy Configuration

A governance policy defines the rules that gate a set of operations.

#### Policy Fields

| Field | Type | Description |
|---|---|---|
| `id` | UUID | Auto-assigned policy identifier. |
| `name` | string | Human-readable policy name (e.g. "Key Destruction Quorum"). |
| `scope` | enum | What the policy applies to: `global` (all resources), `tenant` (tenant-level operations), `key` (key operations), `cert` (certificate operations), `user` (user management operations). |
| `trigger_actions` | string[] | List of audit action strings that trigger this policy (e.g. `["key.destroy", "key.deactivate"]`). |
| `quorum_mode` | enum | How votes are counted: `any` (N approvers from the pool), `all` (every approver in the pool must vote yes), `weighted` (each approver has a vote weight; threshold = sum of weights). |
| `required_approvals` | int | Number of affirmative votes needed to reach quorum (for `any` mode). |
| `total_approvers` | int | Total size of the approver pool (for display and validation). |
| `approver_roles` | string[] | All users with these roles are eligible approvers. |
| `approver_users` | UUID[] | Specific user UUIDs who are eligible approvers. |
| `timeout_hours` | int | Hours before a pending request auto-expires and is denied. |
| `escalation_hours` | int | Hours before an unresolved request triggers an escalation notification. Must be less than `timeout_hours`. |
| `escalation_to` | string | Email address (or webhook URL) for escalation notifications. |
| `notification_channels` | string[] | Channels to notify approvers: `dashboard`, `email`, `slack`, `teams`, `webhook`. |
| `retention_days` | int | How long completed governance requests are retained before archival. |

#### Quorum Modes Explained

**`any` mode (N-of-M):** The most common mode. Any N approvers from the pool of M eligible approvers must vote affirmatively. If M=3 and required_approvals=2, then any 2 of the 3 can approve.

**`all` mode:** Every eligible approver must vote yes. Used for the highest-sensitivity operations (e.g. annual root CA key ceremony).

**`weighted` mode:** Each approver has an assigned weight. The sum of weights of yes votes must reach the threshold. Example: CISO has weight 3, Security Officers each have weight 1; threshold=5. CISO + any 2 officers can approve, or any 5 officers.

#### Common Policy Scenarios

```bash
# Scenario 1: 2-of-3 admin approvals required for any key destruction or deactivation
curl -X POST "http://localhost:5173/svc/governance/governance/policies?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Key Destruction Quorum",
    "scope": "key",
    "trigger_actions": ["key.destroy", "key.deactivate"],
    "quorum_mode": "any",
    "required_approvals": 2,
    "total_approvers": 3,
    "approver_roles": ["admin"],
    "timeout_hours": 24,
    "escalation_hours": 8,
    "escalation_to": "security-team@acme.com",
    "notification_channels": ["dashboard", "email", "slack"],
    "retention_days": 2555
  }'

# Scenario 2: Any 1 senior operator required before key export
curl -X POST "http://localhost:5173/svc/governance/governance/policies?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Key Export Authorization",
    "scope": "key",
    "trigger_actions": ["key.export"],
    "quorum_mode": "any",
    "required_approvals": 1,
    "total_approvers": 5,
    "approver_roles": ["senior_operator", "admin"],
    "timeout_hours": 4,
    "escalation_hours": 2,
    "notification_channels": ["dashboard", "email", "pagerduty"]
  }'

# Scenario 3: All 3 key custodians required for root CA rotation
curl -X POST "http://localhost:5173/svc/governance/governance/policies?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Root CA Rotation — All Custodians",
    "scope": "cert",
    "trigger_actions": ["ca.created", "cert.revoked"],
    "quorum_mode": "all",
    "approver_users": [
      "custodian-1-uuid",
      "custodian-2-uuid",
      "custodian-3-uuid"
    ],
    "timeout_hours": 72,
    "escalation_hours": 24,
    "escalation_to": "pki-manager@acme.com",
    "notification_channels": ["dashboard", "email", "teams"]
  }'

# Scenario 4: Disable FIPS mode requires CISO + 2 security officers (weighted)
curl -X POST "http://localhost:5173/svc/governance/governance/policies?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "FIPS Mode Change",
    "scope": "global",
    "trigger_actions": ["governance.fips.disabled"],
    "quorum_mode": "weighted",
    "required_approvals": 5,
    "approver_weights": {
      "ciso-user-uuid": 3,
      "sec-officer-1-uuid": 1,
      "sec-officer-2-uuid": 1,
      "sec-officer-3-uuid": 1
    },
    "timeout_hours": 12,
    "notification_channels": ["dashboard", "email"]
  }'
```

---

### 2.3 Request Lifecycle

#### States

```
created → pending → approved → [operation executed]
                 ↘ denied
                 ↘ expired
                 ↘ cancelled (by requester, before quorum)
```

#### Lifecycle in Detail

1. **Creation:** The requester submits the operation via the normal API. The governance middleware intercepts the call, determines a policy matches, and creates a `GovernanceRequest` record. The original API call is held (or returns a `202 Accepted` with a `request_id`).

2. **Notification:** All eligible approvers are notified via configured channels simultaneously. The notification includes: what was requested, who requested it, what resource is affected, and a direct link to approve/deny.

3. **Voting:** Each approver independently navigates to the governance queue (dashboard, email link, or Slack button) and casts a vote: `approve` or `deny`, with an optional comment. Comments are recorded in the audit log.

4. **Quorum resolution:**
   - If quorum is reached with approvals → request transitions to `approved` → the original operation is automatically executed → an audit event is created with `approval_id` set.
   - If any single denial creates an irrecoverable state (deny count makes quorum impossible) → request transitions to `denied` → requester is notified.
   - If `timeout_hours` elapses without quorum → request transitions to `expired` → operation is blocked → requester is notified.

5. **Escalation:** If `escalation_hours` elapses without a vote from any approver, an escalation notification is sent to `escalation_to`. This catches cases where approvers are unreachable (vacation, illness, incident).

#### Request API

```bash
# List all pending requests (approver's view — shows only requests the caller can act on)
curl "http://localhost:5173/svc/governance/governance/requests?tenant_id=root&status=pending" \
  -H "Authorization: Bearer $TOKEN"

# List all requests (admin view — all statuses, all actors)
curl "http://localhost:5173/svc/governance/governance/requests?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get a specific request with vote history
curl "http://localhost:5173/svc/governance/governance/requests/REQUEST_UUID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Vote to approve
curl -X POST "http://localhost:5173/svc/governance/governance/approve/REQUEST_UUID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "vote": "approve",
    "comment": "Verified this is scheduled maintenance window JIRA-8812"
  }'

# Vote to deny
curl -X POST "http://localhost:5173/svc/governance/governance/approve/REQUEST_UUID" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "vote": "deny",
    "comment": "No change request approved for this key — escalate to security team"
  }'

# Requester cancels their own pending request
curl -X POST "http://localhost:5173/svc/governance/governance/requests/REQUEST_UUID/cancel?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"reason": "Submitted in error — wrong key selected"}'

# Admin view: requests expiring in the next 2 hours
curl "http://localhost:5173/svc/governance/governance/requests?tenant_id=root&expiring_before=2h" \
  -H "Authorization: Bearer $TOKEN"
```

---

### 2.4 Notification Channels Setup

All channel configuration is stored in governance settings. Changes take effect immediately.

```bash
# Get current notification settings
curl "http://localhost:5173/svc/governance/governance/settings?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Configure all channels at once
curl -X PUT "http://localhost:5173/svc/governance/governance/settings?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "smtp": {
      "host": "smtp.company.internal",
      "port": 587,
      "from": "kms-governance@company.com",
      "username": "kms-smtp-svc",
      "password_secret_ref": "smtp-password",
      "starttls": true,
      "verify_cert": true
    },
    "slack": {
      "webhook_url": "https://hooks.slack.com/services/T.../B.../...",
      "channel": "#security-approvals"
    },
    "teams": {
      "webhook_url": "https://outlook.office.com/webhook/..."
    },
    "webhook": {
      "url": "https://jira.company.internal/rest/api/2/issue",
      "method": "POST",
      "headers": {
        "Authorization": "Bearer JIRA_TOKEN",
        "Content-Type": "application/json"
      },
      "body_template": "{\"fields\": {\"project\": {\"key\": \"SEC\"}, \"summary\": \"KMS Approval Required: {{.action}}\", \"issuetype\": {\"name\": \"Task\"}}}"
    },
    "pagerduty": {
      "integration_key": "pd-integration-key-here",
      "severity_threshold": "high"
    }
  }'

# Test email channel
curl -X POST "http://localhost:5173/svc/governance/governance/settings/test?tenant_id=root&channel=email" \
  -H "Authorization: Bearer $TOKEN"
```

---

### 2.5 Backup & Restore

Vecta KMS backups capture the full encrypted state of the system (or a specific tenant) and are themselves encrypted before storage. This section documents the complete backup and restore workflow.

#### Backup Scopes

| Scope | What's Included | When to Use |
|---|---|---|
| `system` | All tenants, all keys, all certificates, all users, all governance policies, all compliance configuration | Full disaster recovery — system migration |
| `tenant` | A single tenant's keys, certs, users, policies | Per-tenant offboarding, multi-tenant isolation of backups |

#### Backup Encryption

Every backup consists of two artifacts that must be stored separately:

1. **Backup artifact** (`.enc`): The encrypted data blob. Large file, contains all the data.
2. **Key package** (`.key`): The encrypted data encryption key (DEK) used to encrypt the artifact. Small file. The DEK is itself wrapped under:
   - The KMS's own master key (software-backed), or
   - An HSM key (when `hsm_bound: true`). HSM-bound backups require the HSM to be operational for restore.

Security requirement: store the artifact and the key package in **separate locations**. Possession of only one is insufficient to restore.

```bash
# Create a system backup (HSM-bound, AES-256-GCM)
curl -X POST "http://localhost:5173/svc/governance/governance/backups?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scope": "system",
    "encryption_algorithm": "AES-256-GCM",
    "hsm_bound": true,
    "description": "Pre-upgrade backup 2024-03-15",
    "tags": ["pre-upgrade", "quarterly"]
  }'

# Create a tenant-scoped backup (software-backed)
curl -X POST "http://localhost:5173/svc/governance/governance/backups?tenant_id=acme-corp" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "scope": "tenant",
    "encryption_algorithm": "AES-256-GCM",
    "hsm_bound": false
  }'

# List all backups with metadata
curl "http://localhost:5173/svc/governance/governance/backups?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Download backup artifact to local file
curl "http://localhost:5173/svc/governance/governance/backups/BACKUP_UUID/artifact" \
  -H "Authorization: Bearer $TOKEN" \
  -o backup-$(date +%Y%m%d).enc

# Download key package to separate location
curl "http://localhost:5173/svc/governance/governance/backups/BACKUP_UUID/key" \
  -H "Authorization: Bearer $TOKEN" \
  -o backup-key-$(date +%Y%m%d).key

# Restore from artifact + key package (both base64 encoded)
ARTIFACT_B64=$(base64 -i backup-20240315.enc)
KEY_B64=$(base64 -i backup-key-20240315.key)

curl -X POST "http://localhost:5173/svc/governance/governance/backups/restore" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"artifact_b64\": \"$ARTIFACT_B64\",
    \"key_package_b64\": \"$KEY_B64\",
    \"target_tenant_id\": \"root\",
    \"merge_mode\": \"overwrite\",
    \"dry_run\": false
  }"

# Dry-run restore (validate without applying changes)
curl -X POST "http://localhost:5173/svc/governance/governance/backups/restore" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"artifact_b64\": \"$ARTIFACT_B64\",
    \"key_package_b64\": \"$KEY_B64\",
    \"target_tenant_id\": \"root\",
    \"dry_run\": true
  }"
```

#### Backup Rotation Policy

```bash
# Set backup retention: keep last 30 daily backups, last 12 monthly
curl -X PUT "http://localhost:5173/svc/governance/governance/backups/retention?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "max_backups": 30,
    "max_age_days": 365,
    "monthly_retention_months": 12
  }'
```

---

### 2.6 System State Management

The governance service also manages platform-wide configuration that affects security posture:

```bash
# Get current system state
curl "http://localhost:5173/svc/governance/governance/system/state?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Toggle FIPS mode (requires governance approval if a FIPS policy exists)
curl -X PUT "http://localhost:5173/svc/governance/governance/system/fips?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"fips_enabled": true}'

# Update network bind configuration
curl -X PUT "http://localhost:5173/svc/governance/governance/system/network?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "api_bind": "0.0.0.0:8443",
    "tls_enabled": true,
    "tls_cert_path": "/etc/vecta/tls/server.crt",
    "tls_key_path": "/etc/vecta/tls/server.key",
    "mtls_required": true,
    "client_ca_path": "/etc/vecta/tls/client-ca.crt"
  }'

# Get audit log of all system state changes
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&service=governance&action=governance.fips.enabled" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 3. Compliance Framework

### 3.1 Supported Frameworks

Vecta KMS's compliance engine supports the following regulatory and standards frameworks. Each framework is mapped to specific platform controls that are automatically assessed.

#### PCI DSS v4.0 — Payment Card Industry Data Security Standard

The most operationally relevant framework for organisations that handle payment card data.

| PCI DSS Requirement | Description | Vecta Control Mapping |
|---|---|---|
| Req 3.3.1 | SAD (Sensitive Authentication Data) must not be stored after authorisation | Tokenization policies, field-level encryption |
| Req 3.5.1 | PAN protected wherever stored | AES-256 encryption, key access policies |
| Req 3.7.1 | Key management procedures: dual control, split knowledge | Governance quorum policies |
| Req 3.7.2 | Keys changed at least annually (or when compromised) | Rotation policy coverage percentage |
| Req 3.7.3 | Retired or replaced cryptographic keys not used for encryption | Key state lifecycle enforcement |
| Req 3.7.4 | Key management procedures documented and implemented | Compliance template assessment |
| Req 10.2 | Audit log events implemented | Immutable audit chain, all events captured |
| Req 10.3.2 | Audit logs protected from modification | Hash chain, Merkle sealing |
| Req 10.5.1 | Retain audit logs for at least 12 months | Retention policy enforcement |
| Req 12.3.2 | Targeted risk analysis for each PCI DSS requirement | Compliance posture scores, gap findings |

#### NIST SP 800-57 — Key Management Recommendations

NIST's comprehensive guidance on cryptographic key management practices.

Vecta maps NIST SP 800-57 Part 1 (General), Part 2 (Best Practices for Key Management), and Part 3 (Application-Specific Key Management Guidance):

- **Key states** (Pre-activation, Active, Deactivated, Compromised, Destroyed, Destroyed-Compromised) are directly implemented in the keycore service. The compliance engine checks that keys are not used in states that NIST prohibits for each operation type.
- **Cryptoperiods** (maximum active use periods) are enforced via rotation policies. The compliance engine flags keys that exceed NIST-recommended cryptoperiods.
- **Algorithm transitions**: NIST SP 800-131A Rev2 algorithm deprecation schedule is built into the compliance engine. Keys using deprecated algorithms (RSA-1024, SHA-1, 3DES) are flagged.
- **Key hierarchy**: The compliance engine validates that each level of the key hierarchy uses an algorithm with equal or greater security strength than the keys it protects.

#### FIPS 140-3 — Federal Information Processing Standard for Cryptographic Modules

FIPS 140-3 (and its predecessor FIPS 140-2) defines security requirements for cryptographic modules.

| FIPS 140-3 Area | Vecta Implementation |
|---|---|
| Approved algorithms | AES-128/192/256, SHA-256/384/512, HMAC-SHA-256/384/512, RSA-2048+, ECDSA P-256/P-384, EdDSA Ed25519, ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) |
| Prohibited algorithms | MD5, SHA-1 (for signatures), DES, 3DES (in new deployments), RC4, RSA <2048 |
| FIPS mode enforcement | When enabled, API calls using non-FIPS algorithms are rejected. `fips_compliant: true` on audit events. |
| Module boundary | All cryptographic operations in FIPS mode are routed through the FIPS-validated code path or HSM. |

The compliance assessment checks: are any active keys using non-FIPS algorithms? Are any operations recorded in the audit log with `fips_compliant: false`?

#### ISO/IEC 27001:2022 — Information Security Management

| Annex A Control | Description | Vecta Mapping |
|---|---|---|
| A.8.24 | Use of cryptography | Algorithm policy enforcement, FIPS mode |
| A.8.10 | Information deletion | Key destruction audit trail |
| A.8.16 | Monitoring activities | Alert rules, SIEM export |
| A.5.33 | Protection of records | Immutable audit log, retention policies |
| A.8.15 | Logging | Full audit event schema |
| A.6.8 | Information security event reporting | Alert center, PagerDuty integration |

#### SOC 2 Type II — Trust Service Criteria

| Criteria | Description | Vecta Mapping |
|---|---|---|
| CC6.1 | Logical access uses authentication mechanisms | Multi-factor authentication, OIDC SSO |
| CC6.2 | Prior to issuing credentials, identity is registered | SCIM provisioning, user lifecycle |
| CC6.3 | Access to data assets is limited to authorised users | Key access policies, role-based access |
| CC6.6 | Logical access restrictions (changes to infrastructure) | Governance approval workflow |
| CC6.8 | Measures to prevent or detect malware | Alert rules for anomalous access patterns |
| CC7.2 | System monitoring to detect anomalies | Alert center, MTTD/MTTR tracking |
| CC7.3 | Evaluation and containment of security incidents | Incident response workflow in section 7.2 |
| CC9.1 | Risk assessment includes risks from business disruption | Compliance posture assessment |

#### HIPAA Security Rule — Health Insurance Portability and Accountability Act

| HIPAA §164 Section | Requirement | Vecta Implementation |
|---|---|---|
| §164.312(a)(2)(iv) | Encryption and decryption of ePHI | AES-256-GCM encryption, field-level encryption |
| §164.312(b) | Audit controls for access to ePHI | Immutable audit log with actor, action, timestamp |
| §164.312(c)(2) | Mechanism to authenticate ePHI integrity | HMAC integrity verification |
| §164.312(e)(2)(ii) | Encryption of ePHI in transit | TLS 1.3 enforcement for all API calls |
| §164.308(a)(1)(ii)(D) | Information system activity review | Audit log querying, alert rules |

#### GDPR Article 32 — Security of Processing

GDPR Article 32 requires "appropriate technical and organisational measures" including:

- Pseudonymisation and encryption of personal data → Tokenization (FPE), field-level encryption
- Ongoing confidentiality, integrity, availability → Key availability monitoring, backup/restore
- Regular testing and evaluation → Compliance assessment engine, scheduled assessments
- Process for regularly restoring availability → Backup/restore workflow, tested DR runbook

The compliance assessment checks: are keys used for personal data encryption compliant (rotation coverage, access controls, non-export)?

#### DORA — Digital Operational Resilience Act (EU Financial Sector)

DORA (EU 2022/2554) requires financial entities to manage ICT risks, including:

- ICT incident management → Alert center, incident evidence packages (section 7.2)
- Digital operational resilience testing → Compliance assessment schedules
- ICT third-party risk → Audit log records of key operations by third-party service accounts
- Information sharing → Audit export in standardised formats (CEF, LEEF)
- ICT risk management → Compliance posture scores, governance workflow

#### NIS2 — Network and Information Systems Directive

NIS2 (EU 2022/2555) extends NIS to more sectors. Relevant to KMS:
- Security of network and information systems → Key security posture assessment
- Incident reporting obligations → Audit evidence packages, timeline reconstruction
- Cryptographic policies → Algorithm compliance, FIPS mode

#### BSI C5 — Cloud Computing Compliance Controls Criteria

German BSI C5 (2020) for cloud service providers:
- OIS-08 (Cryptography and Key Management) → Full key lifecycle management, access controls
- RB-02 (Logging and monitoring) → Immutable audit log, SIEM export
- OIS-09 (Vulnerability management) → SBOM/CBOM, CVE exposure tracking

---

### 3.2 Compliance Templates

A compliance template defines which frameworks to assess, and the weights applied to each framework's controls when computing the overall posture score.

```bash
# List available templates (includes built-in templates)
curl "http://localhost:5173/svc/compliance/compliance/templates?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Built-in templates:
# - baseline: all frameworks, equal weights
# - pci_focused: PCI DSS 70%, NIST 20%, FIPS 10%
# - hipaa_focused: HIPAA 60%, SOC2 30%, ISO27001 10%
# - fips_strict: FIPS 140-3 compliance only

# Create a custom template
curl -X POST "http://localhost:5173/svc/compliance/compliance/templates?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "FinTech Regulatory Stack",
    "description": "PCI DSS primary, DORA secondary, FIPS for federal contracts",
    "frameworks": [
      {"framework_id": "pci_dss_v4", "weight": 0.40},
      {"framework_id": "dora", "weight": 0.25},
      {"framework_id": "fips_140_3", "weight": 0.20},
      {"framework_id": "soc2_type2", "weight": 0.10},
      {"framework_id": "iso_27001_2022", "weight": 0.05}
    ],
    "thresholds": {
      "critical_below": 60,
      "warning_below": 80,
      "target": 95
    }
  }'
```

---

### 3.3 Assessment Engine

The compliance assessment engine scans the current state of the KMS and produces a scored report against the configured frameworks.

#### What the Engine Checks

| Check Category | Specific Checks |
|---|---|
| Algorithm compliance | Active keys using deprecated algorithms (SHA-1, MD5, DES, RSA-1024, 3DES) |
| Rotation coverage | Keys with no rotation policy configured |
| Rotation timeliness | Keys where last rotation exceeds cryptoperiod for their algorithm and purpose |
| Access control | Keys with no access policy grants (orphaned) |
| Access control | Keys with overly-broad grants (wildcard actor, no scope restriction) |
| Certificate expiry | Certificates expiring within 30 days |
| CA security | Root CAs with online private keys (should be offline) |
| FIPS compliance | Audit events with `fips_compliant: false` in FIPS-enabled mode |
| PQC readiness | Keys using quantum-vulnerable algorithms (RSA, EC) without a PQC migration plan |
| Audit completeness | Gaps in audit chain sequence |
| Governance coverage | High-risk actions without governance policies |
| Interface hardening | Keys accessible via all interfaces when restricted-interface policy exists |
| Export risk | Keys with `exportable: true` without governance approval policy |
| Backup recency | Last backup older than 24 hours (configurable threshold) |

#### Running Assessments

```bash
# Run immediate assessment against custom template
curl -X POST "http://localhost:5173/svc/compliance/compliance/assess?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"template_id": "custom-template-uuid"}'

# Run against built-in baseline
curl -X POST "http://localhost:5173/svc/compliance/compliance/assess?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"template_id": "baseline"}'

# Get list of assessments (most recent first)
curl "http://localhost:5173/svc/compliance/compliance/assessments?tenant_id=root&limit=10" \
  -H "Authorization: Bearer $TOKEN"

# Get a specific assessment report (full JSON)
curl "http://localhost:5173/svc/compliance/compliance/assessments/ASSESSMENT_UUID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get delta from previous scan (what improved, what regressed)
curl "http://localhost:5173/svc/compliance/compliance/assessments/delta?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get framework-specific gaps (all failing controls for PCI DSS)
curl "http://localhost:5173/svc/compliance/compliance/framework-gaps?tenant_id=root&framework_id=pci_dss_v4" \
  -H "Authorization: Bearer $TOKEN"

# Get findings by severity (all critical findings across all frameworks)
curl "http://localhost:5173/svc/compliance/compliance/findings?tenant_id=root&severity=critical" \
  -H "Authorization: Bearer $TOKEN"
```

#### Assessment Response Structure

```json
{
  "id": "assessment-uuid",
  "tenant_id": "root",
  "template_id": "custom-template-uuid",
  "timestamp": "2024-03-15T02:00:00Z",
  "overall_score": 87,
  "framework_scores": {
    "pci_dss_v4": 91,
    "dora": 83,
    "fips_140_3": 100,
    "soc2_type2": 78,
    "iso_27001_2022": 85
  },
  "posture_breakdown": {
    "key_hygiene": 89,
    "policy_compliance": 92,
    "access_security": 84,
    "crypto_posture": 95,
    "pqc_readiness": 62
  },
  "findings": [
    {
      "id": "finding-uuid",
      "severity": "critical",
      "category": "key_hygiene",
      "type": "rotation_overdue",
      "description": "Key 'payment-signing-key-prod' has not been rotated in 547 days (limit: 365)",
      "affected_resource_id": "key-uuid",
      "frameworks": ["pci_dss_v4", "nist_sp800_57"],
      "remediation": "Rotate the key immediately via POST /svc/keycore/keys/{id}/rotate",
      "risk_score": 78
    },
    {
      "id": "finding-uuid-2",
      "severity": "high",
      "category": "pqc_readiness",
      "type": "pqc_gap",
      "description": "15 keys use RSA-2048 which is vulnerable to quantum attack (NIST FIPS 140-3 deprecation: 2030)",
      "affected_count": 15,
      "frameworks": ["nist_sp800_57", "fips_140_3"],
      "remediation": "Migrate to ML-KEM or ML-DSA equivalents before 2030",
      "risk_score": 55
    }
  ],
  "key_hygiene_metrics": {
    "total_keys": 342,
    "rotation_coverage_percent": 87.4,
    "orphaned_count": 3,
    "expiring_in_30_days": 7,
    "algorithm_distribution": {
      "AES-256": 198,
      "RSA-2048": 15,
      "EC-P256": 89,
      "EC-P384": 22,
      "ML-KEM-768": 12,
      "ML-DSA-65": 6
    }
  }
}
```

---

### 3.4 Posture Breakdown

The posture breakdown provides a high-level view of security health across five dimensions:

| Category | What It Measures | Ideal Score |
|---|---|---|
| **Key Hygiene** | Rotation coverage, orphaned keys, expiring keys, algorithm currency | ≥ 95 |
| **Policy Compliance** | Governance policy coverage for high-risk actions, retention policy configuration | ≥ 90 |
| **Access Security** | Keys with no grants, overly-broad grants, unused grants, export risk | ≥ 90 |
| **Crypto Posture** | FIPS compliance rate, algorithm strength distribution, interface restrictions | ≥ 95 |
| **PQC Readiness** | Percentage of operations covered by post-quantum algorithms, migration progress | Tracked |

PQC Readiness is tracked rather than scored against a threshold, because the NIST timeline (quantum-vulnerable algorithms deprecated by 2030) gives organisations time to migrate. The compliance engine provides a "PQC migration debt" figure: the number of keys and certificates that need migration.

---

### 3.5 Key Hygiene Metrics

```bash
# Get key hygiene metrics for a tenant
curl "http://localhost:5173/svc/compliance/compliance/hygiene?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

| Metric | Description |
|---|---|
| `rotation_coverage_percent` | Percentage of active keys that have a rotation policy configured. Target: 100%. |
| `rotation_compliance_percent` | Percentage of keys with a rotation policy whose last rotation is within the policy interval. Target: 100%. |
| `orphaned_count` | Keys with no access policy grants and no recorded usage in 90 days. These are waste and represent unnecessary risk surface. |
| `expiring_count` | Active keys expiring within the next 30 days. Requires immediate attention to prevent service disruption. |
| `algorithm_distribution` | Count of keys by algorithm. Reveals legacy algorithm usage (DES, 3DES, RSA-1024, RC4) that needs remediation. |
| `average_key_age_days` | Average age of active keys. High values indicate stale key inventory. |
| `max_key_age_days` | Oldest active key. A single very old key can fail a PCI DSS audit. |
| `unmanaged_expiry_count` | Keys with no expiry date set. For compliance, all keys should have bounded lifetimes. |
| `over_usage_limit_count` | Keys that have exceeded their configured maximum operation count. |
| `export_enabled_count` | Keys with `exportable: true`. Should be minimised and require governance approval. |

---

### 3.6 Scheduling

Automated assessment scheduling ensures continuous compliance visibility without manual intervention.

```bash
# Set daily assessment at 02:00 UTC
curl -X PUT "http://localhost:5173/svc/compliance/compliance/assessments/schedule?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "frequency": "daily",
    "time": "02:00",
    "timezone": "UTC",
    "template_id": "fintech-regulatory-stack-uuid",
    "notify_on_regression": true,
    "notify_on_critical_finding": true,
    "notification_emails": ["compliance@company.com", "security@company.com"]
  }'

# Set weekly assessment (Monday 00:00 UTC)
curl -X PUT "http://localhost:5173/svc/compliance/compliance/assessments/schedule?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "enabled": true,
    "frequency": "weekly",
    "day_of_week": "monday",
    "time": "00:00",
    "timezone": "UTC",
    "template_id": "baseline"
  }'

# Disable scheduled assessment
curl -X PUT "http://localhost:5173/svc/compliance/compliance/assessments/schedule?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"enabled": false}'

# Get current schedule
curl "http://localhost:5173/svc/compliance/compliance/assessments/schedule?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 4. Alert Center

### 4.1 Alert Rules

Alert rules define conditions that, when matched by incoming audit events, trigger notifications through configured channels. Rules are evaluated in real time as events are ingested — the typical detection latency is under 2 seconds.

#### Alert Rule Structure

| Field | Type | Description |
|---|---|---|
| `id` | UUID | Rule identifier. |
| `name` | string | Human-readable name. |
| `description` | string | What this rule detects and why it matters. |
| `enabled` | boolean | Rules can be disabled without deletion. |
| `condition` | string | CEL (Common Expression Language) expression evaluated against each incoming event. |
| `window_seconds` | int | Sliding time window for count-based and rate-based conditions. |
| `severity` | enum | `critical`, `high`, `warning`, `info`. |
| `channels` | string[] | Notification channels: `dashboard`, `email`, `slack`, `pagerduty`, `webhook`. |
| `cooldown_seconds` | int | Minimum time between repeated alerts for the same rule+actor combination. Prevents alert storms. |
| `tags` | string[] | Labels for grouping rules (e.g. `["pci-dss", "incident-response"]`). |

#### CEL Expression Reference

CEL expressions have access to the current event as `event` (all fields from the audit schema) and a `count()` function for sliding window aggregation:

```
# Simple field match
event.action == "key.export"

# Boolean AND
event.action == "key.destroy" && event.result == "success"

# High risk score
event.risk_score >= 80

# Specific actor type
event.actor_type == "service" && event.action.startsWith("key.")

# Count-based (N events in window)
event.action == "key.decrypt" && event.result == "failure" && count(events, 300) >= 5
# Alert if 5+ failed decryptions in 5 minutes

# Time-of-day guard (outside business hours: before 08:00 or after 18:00 UTC)
event.action == "key.export" && (hour(event.timestamp) < 8 || hour(event.timestamp) > 18)

# Source IP not in known range
event.action.startsWith("key.") && !event.source_ip.startsWith("10.0.")

# Actor not in allowed list
event.action == "key.destroy" && !event.actor_id.in(["admin-1-uuid", "admin-2-uuid"])

# New source IP for an actor (first time seen in 30 days)
event.actor_type == "user" && is_new_source_ip(event.actor_id, event.source_ip, 2592000)

# Combination: brute force + specific resource type
event.target_type == "key" && event.result == "failure" && count(events, 60) >= 10
```

#### Managing Alert Rules

```bash
# Create an alert rule
curl -X POST "http://localhost:5173/svc/alerting/rules?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Brute Force Key Decryption",
    "description": "Detects repeated failed decryption attempts from the same source, indicating key misuse or brute force",
    "enabled": true,
    "condition": "event.action == \"key.decrypt\" && event.result == \"failure\" && count(events, 300) >= 5",
    "window_seconds": 300,
    "severity": "critical",
    "channels": ["dashboard", "pagerduty", "slack"],
    "cooldown_seconds": 600,
    "tags": ["brute-force", "pci-dss", "incident-response"]
  }'

# Create a key export outside business hours rule
curl -X POST "http://localhost:5173/svc/alerting/rules?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "After-Hours Key Export",
    "description": "Key exports outside 08:00-18:00 UTC are unusual and should be reviewed",
    "enabled": true,
    "condition": "event.action == \"key.export\" && (hour(event.timestamp) < 8 || hour(event.timestamp) > 18)",
    "severity": "high",
    "channels": ["dashboard", "email", "slack"],
    "cooldown_seconds": 3600
  }'

# Create a FIPS mode change alert
curl -X POST "http://localhost:5173/svc/alerting/rules?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "FIPS Mode Disabled",
    "description": "FIPS mode was disabled — this may violate regulatory requirements",
    "enabled": true,
    "condition": "event.action == \"governance.fips.disabled\"",
    "severity": "critical",
    "channels": ["dashboard", "pagerduty", "email"],
    "cooldown_seconds": 0
  }'

# List all rules
curl "http://localhost:5173/svc/alerting/rules?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Enable/disable a rule
curl -X PATCH "http://localhost:5173/svc/alerting/rules/RULE_UUID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"enabled": false}'

# Test a rule against a synthetic event
curl -X POST "http://localhost:5173/svc/alerting/rules/RULE_UUID/test?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "synthetic_event": {
      "action": "key.decrypt",
      "result": "failure",
      "actor_id": "user-uuid",
      "source_ip": "198.51.100.42"
    }
  }'
```

#### Built-In Alert Rule Templates

Vecta ships with the following pre-built rules that can be enabled immediately:

| Rule Name | Condition Summary | Default Severity |
|---|---|---|
| Key Destruction | Any `key.destroy` success | Critical |
| Key Export | Any `key.export` success | Critical |
| Root CA Deletion | Any `ca.deleted` | Critical |
| FIPS Mode Disabled | `governance.fips.disabled` | Critical |
| Brute Force Decrypt | 5+ failed decrypts in 5 min | Critical |
| Brute Force Login | 5+ failed logins in 2 min | High |
| Account Locked | `user.locked` | High |
| After-Hours Key Operation | Key op outside 08:00-18:00 | High |
| Governance Expired | `governance.request.expired` | High |
| Certificate Expiry (7 days) | Cert expiring in ≤ 7 days | High |
| Certificate Expiry (30 days) | Cert expiring in ≤ 30 days | Warning |
| Orphaned Key Created | Key with no access policy | Warning |
| Non-FIPS Operation in FIPS Mode | `fips_compliant: false` | Warning |
| New Source IP for Admin | Admin login from unseen IP | Warning |

---

### 4.2 Notification Channels

Alert notification channels are configured separately from governance notification channels (they share the same settings store but can be configured independently per rule).

```bash
# Configure PagerDuty integration for critical alerts
curl -X PUT "http://localhost:5173/svc/alerting/channels/pagerduty?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "integration_key": "pd-routing-key-here",
    "default_severity": "critical",
    "dedup_key_template": "{{.rule_id}}-{{.actor_id}}"
  }'

# Configure Slack channel
curl -X PUT "http://localhost:5173/svc/alerting/channels/slack?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "webhook_url": "https://hooks.slack.com/services/...",
    "channel": "#security-alerts",
    "mention_on_critical": "@here"
  }'

# Configure custom webhook (e.g. ServiceNow incident creation)
curl -X PUT "http://localhost:5173/svc/alerting/channels/webhook?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "url": "https://servicenow.company.internal/api/now/table/incident",
    "method": "POST",
    "auth_header": "Authorization: Bearer SN_TOKEN",
    "body_template": "{\"short_description\": \"KMS Alert: {{.rule_name}}\", \"description\": \"{{.description}}\", \"category\": \"Security\", \"severity\": \"{{.severity}}\"}"
  }'
```

#### Alert Dashboard

The dashboard channel provides real-time alert visibility in the Vecta UI:

- **Unread badge:** Count of unacknowledged alerts by severity level
- **Alert feed:** Chronological list with rule name, event details, affected resource, severity, and timestamp
- **Acknowledge:** Single alert or bulk acknowledge
- **Resolve:** Mark as resolved with optional comment (creates audit event)
- **Assign:** Assign alert to a team member for investigation
- **Snooze:** Suppress repeat notifications for a configurable period

---

### 4.3 MTTR and MTTD

The alert center tracks two key operational metrics:

**MTTD (Mean Time to Detect):** Average time elapsed between when the triggering event occurred (`event.timestamp`) and when the alert was created and first delivered. Measures the effectiveness of the detection pipeline.

**MTTR (Mean Time to Resolve):** Average time elapsed between alert creation and when the alert was marked as resolved. Measures the team's incident response speed.

Both metrics are tracked per severity level and per rule, with 14-day rolling trend charts in the dashboard.

```bash
# Get MTTD/MTTR metrics
curl "http://localhost:5173/svc/alerting/metrics?tenant_id=root&period_days=30" \
  -H "Authorization: Bearer $TOKEN"

# Example response:
# {
#   "mttd_seconds": {"critical": 1.8, "high": 2.1, "warning": 3.4},
#   "mttr_seconds": {"critical": 1823, "high": 7442, "warning": 28800},
#   "alert_volume": {"critical": 3, "high": 14, "warning": 42, "info": 201},
#   "top_rules_by_volume": [...]
# }
```

---

### 4.4 Reporting

The reporting service generates structured compliance and operational reports on demand or on schedule.

#### Report Templates

| Template ID | Description | Formats |
|---|---|---|
| `compliance_summary` | Overall posture score, framework scores, top findings, trend | PDF, JSON |
| `key_inventory` | All keys with state, algorithm, age, rotation status, access policy summary | PDF, CSV, XLSX |
| `audit_export` | Raw audit events with optional filters, signed | CSV, JSON-Lines |
| `incident_report` | Timeline of a specific incident, correlation graph, affected resources | PDF, JSON |
| `executive_summary` | 1-page: overall risk score, top 5 risks, compliance status by framework | PDF |
| `certificate_inventory` | All certificates with expiry dates, issuers, subjects, revocation status | PDF, CSV |
| `governance_activity` | Governance requests, approval rates, quorum timing, pending items | PDF, JSON |
| `pqc_readiness` | PQC migration progress, quantum-vulnerable assets, recommended actions | PDF, JSON |

#### Generating Reports

```bash
# Generate compliance summary PDF for Q1 2024
curl -X POST "http://localhost:5173/svc/reporting/reports/generate?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "template_id": "compliance_summary",
    "format": "pdf",
    "filters": {
      "date_range": {
        "from": "2024-01-01T00:00:00Z",
        "to": "2024-03-31T23:59:59Z"
      },
      "frameworks": ["pci_dss_v4", "soc2_type2"]
    },
    "title": "Q1 2024 Compliance Summary — ACME Corp",
    "recipient_emails": ["compliance@acme.com"]
  }'

# Response: {"job_id": "job-uuid", "status": "queued", "estimated_seconds": 30}

# Poll for job completion
curl "http://localhost:5173/svc/reporting/reports/jobs/JOB_UUID?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Download completed report
curl "http://localhost:5173/svc/reporting/reports/jobs/JOB_UUID/download?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -o compliance-q1-2024.pdf

# Generate key inventory as XLSX
curl -X POST "http://localhost:5173/svc/reporting/reports/generate?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "template_id": "key_inventory",
    "format": "xlsx",
    "filters": {"tags": ["env:production"]}
  }'

# Generate executive summary
curl -X POST "http://localhost:5173/svc/reporting/reports/generate?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"template_id": "executive_summary", "format": "pdf"}'
```

#### Scheduled Reports

```bash
# Schedule monthly compliance summary (1st of each month at 07:00 UTC)
curl -X POST "http://localhost:5173/svc/reporting/reports/schedules?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Monthly Compliance Summary",
    "template_id": "compliance_summary",
    "format": "pdf",
    "frequency": "monthly",
    "day_of_month": 1,
    "time": "07:00",
    "timezone": "UTC",
    "recipients": ["ciso@company.com", "compliance@company.com"],
    "filters": {}
  }'

# Schedule weekly key inventory (every Monday)
curl -X POST "http://localhost:5173/svc/reporting/reports/schedules?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Weekly Key Inventory",
    "template_id": "key_inventory",
    "format": "csv",
    "frequency": "weekly",
    "day_of_week": "monday",
    "time": "06:00",
    "timezone": "UTC",
    "recipients": ["key-custodian@company.com"]
  }'
```

---

## 5. Posture & Risk Detection

The posture engine continuously analyses the KMS state to detect configuration drift, security gaps, and emerging risks. Unlike the compliance assessment (which runs on a schedule), the posture engine updates in near real-time as keys, certificates, and policies change.

### Finding Types

| Finding Type | Severity | Description | Remediation |
|---|---|---|---|
| `weak_algorithm` | Critical | Key uses deprecated algorithm: DES, 3DES, RC4, RSA-1024, MD5, SHA-1 signatures | Migrate to AES-256, RSA-2048+, or EC-P256+ |
| `expiring_key` | High | Key expires within 30 days | Rotate before expiry |
| `orphaned_key` | Warning | Key has no access grants and no usage in 90 days | Delete if unused; grant access if needed |
| `rotation_overdue` | High/Critical | Key's last rotation exceeds its policy interval | Rotate immediately |
| `policy_drift` | High | Key's access policy diverges from the baseline template | Review and reconcile |
| `access_anomaly` | High | Unusual access pattern detected (new actor, unusual time, high volume) | Investigate; revoke if unauthorised |
| `cert_expiry` | High | Certificate expiring within 30 days | Renew certificate |
| `pqc_gap` | Warning | Key uses quantum-vulnerable algorithm with no migration plan | Schedule PQC migration |
| `export_risk` | High | Exportable key without governance approval policy | Add governance policy or disable export |
| `offline_backup_stale` | Warning | Last backup older than configured threshold | Run backup |
| `fips_violation` | Critical | Non-FIPS operation in FIPS mode | Investigate and remediate non-compliant integration |
| `broad_grant` | Warning | Key grant allows all operations to all actors | Narrow scope |
| `ca_online_private_key` | High | Root CA private key is online (accessible via API) | Move root CA to HSM or offline |

### Drift Detection

Drift detection compares the current state of each key and certificate against a **baseline snapshot** taken when it was first provisioned or last reviewed. Changes in:

- Algorithm
- Access policy grants
- Interface policy
- Export flag
- Rotation policy interval

...trigger a `policy_drift` finding that requires review and explicit acknowledgement.

### Remediation Workflow

```bash
# List all open posture findings
curl "http://localhost:5173/svc/compliance/compliance/findings?tenant_id=root&status=open" \
  -H "Authorization: Bearer $TOKEN"

# Acknowledge a finding (with explanation)
curl -X POST "http://localhost:5173/svc/compliance/compliance/findings/FINDING_UUID/acknowledge?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "comment": "Legacy key kept for decrypt-only use of archived data — rotation not feasible",
    "accepted_risk": true,
    "review_date": "2025-01-01"
  }'

# Mark finding as resolved (after remediation)
curl -X POST "http://localhost:5173/svc/compliance/compliance/findings/FINDING_UUID/resolve?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"comment": "Key rotated — rotation policy now 180 days"}'
```

---

## 6. SBOM / CBOM

### Software Bill of Materials (SBOM)

The SBOM (Software Bill of Materials) tracks the software dependency inventory of each Vecta KMS service:

```bash
# Get SBOM for all services
curl "http://localhost:5173/svc/compliance/compliance/sbom?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Get SBOM for a specific service
curl "http://localhost:5173/svc/compliance/compliance/sbom/keycore?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"

# Export SBOM in CycloneDX format
curl "http://localhost:5173/svc/compliance/compliance/sbom?tenant_id=root&format=cyclonedx" \
  -H "Authorization: Bearer $TOKEN" > sbom-cyclonedx.json

# Export SBOM in SPDX format
curl "http://localhost:5173/svc/compliance/compliance/sbom?tenant_id=root&format=spdx" \
  -H "Authorization: Bearer $TOKEN" > sbom-spdx.json
```

SBOM fields per component: `name`, `version`, `package_url`, `license`, `cve_count`, `cve_ids`, `last_updated`.

### Cryptographic Bill of Materials (CBOM)

The CBOM (Cryptographic Bill of Materials) inventories every cryptographic primitive used across the platform:

```bash
# Get CBOM
curl "http://localhost:5173/svc/compliance/compliance/cbom?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

CBOM entry fields:

| Field | Description |
|---|---|
| `primitive` | Algorithm name (e.g. `AES-256-GCM`, `ECDSA-P384`, `ML-KEM-768`) |
| `usage_context` | Where used: `key_encryption`, `data_encryption`, `signing`, `mac`, `kdf`, `tls`, `hash` |
| `services` | Which Vecta services use this primitive |
| `key_count` | Number of active keys using this primitive |
| `operation_count_30d` | Number of operations using this primitive in the last 30 days |
| `fips_approved` | Whether the primitive is FIPS 140-3 approved |
| `quantum_resistant` | Whether the primitive is quantum-resistant (ML-KEM, ML-DSA, SLH-DSA, XMSS) |
| `deprecation_date` | If applicable, the NIST-scheduled deprecation date |
| `migration_target` | Recommended quantum-resistant replacement |

### PQC Readiness from CBOM

The CBOM powers the PQC (Post-Quantum Cryptography) readiness score. The engine calculates:

- **PQC coverage rate:** (operations using PQC algorithms) / (total operations that require confidentiality or signing)
- **Migration debt:** Total count of keys, certificates, and TLS connections using quantum-vulnerable algorithms
- **Priority list:** Ranked by operation volume — highest-traffic quantum-vulnerable assets should migrate first

```bash
# Get PQC readiness report
curl "http://localhost:5173/svc/compliance/compliance/pqc-readiness?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN"
```

### Compliance Mapping: CBOM to Framework Controls

| CBOM Entry | PCI DSS | NIST SP 800-57 | FIPS 140-3 |
|---|---|---|---|
| AES-256-GCM | Req 3.5.1 (encryption of PAN) | Approved for 2030+ | Approved |
| RSA-2048 | Req 3.7.2 (key algorithm) | Approved until 2030 | Approved until 2030 |
| RSA-1024 | FAIL: insufficient key size | Disallowed since 2013 | Disallowed |
| ML-KEM-768 | Forward-secure | FIPS 203 approved | FIPS 203 approved |
| SHA-1 (signatures) | FAIL: deprecated | Disallowed for new use | Disallowed |
| HMAC-SHA-256 | Req 3.7 (integrity) | Approved | Approved |

---

## 7. Operational Use Cases

### 7.1 PCI DSS Annual Audit Preparation

**Scenario:** A fintech company's QSA (Qualified Security Assessor) requires 12 months of evidence for PCI DSS Req 10.2 (audit logging), Req 3.7 (key management procedures), and Req 10.3.2 (log protection).

**Steps:**

1. **Run compliance assessment** against the `pci_focused` template to get the current posture score and identify gaps before the auditor does:
   ```bash
   curl -X POST "http://localhost:5173/svc/compliance/compliance/assess?tenant_id=root" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"template_id": "pci_focused"}'
   ```

2. **Export 12 months of audit events** as signed CSV (tamper-evident):
   ```bash
   curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&date_from=2023-03-01T00:00:00Z&date_to=2024-03-01T00:00:00Z&format=csv&signing_key_id=SIGNING_KEY_UUID" \
     -H "Authorization: Bearer $TOKEN" > pci-audit-evidence.csv
   ```

3. **Generate Merkle inclusion proofs** for sampled events to prove non-tamperability:
   ```bash
   curl "http://localhost:5173/svc/audit/audit/events/SAMPLE_EVENT_UUID/proof?tenant_id=root" \
     -H "Authorization: Bearer $TOKEN" > merkle-proof-sample.json
   ```

4. **Generate key inventory report** showing all CDE (Cardholder Data Environment) keys with rotation history:
   ```bash
   curl -X POST "http://localhost:5173/svc/reporting/reports/generate?tenant_id=root" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{
       "template_id": "key_inventory",
       "format": "xlsx",
       "filters": {"tags": ["env:cde", "scope:pci"]}
     }'
   ```

5. **Export governance records** showing dual-control approvals for key operations:
   ```bash
   curl "http://localhost:5173/svc/governance/governance/requests?tenant_id=root&status=approved&date_from=2023-03-01T00:00:00Z" \
     -H "Authorization: Bearer $TOKEN" > governance-approvals.json
   ```

6. **Generate compliance summary PDF** for the auditor package:
   ```bash
   curl -X POST "http://localhost:5173/svc/reporting/reports/generate?tenant_id=root" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{
       "template_id": "compliance_summary",
       "format": "pdf",
       "filters": {
         "date_range": {"from": "2023-03-01", "to": "2024-03-01"},
         "frameworks": ["pci_dss_v4"]
       },
       "title": "PCI DSS 2023-2024 Compliance Evidence Package"
     }'
   ```

---

### 7.2 Responding to a Key Compromise (Incident Response)

**Scenario:** The security team receives a report that a service account's credentials may have been compromised. The service account had access to several encryption keys.

**Steps:**

1. **Immediately revoke the compromised service account's tokens:**
   ```bash
   curl -X POST "http://localhost:5173/svc/auth/clients/COMPROMISED_CLIENT_UUID/revoke?tenant_id=root" \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

2. **Identify all keys the compromised account had access to:**
   ```bash
   curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&actor_id=COMPROMISED_CLIENT_UUID&service=keycore" \
     -H "Authorization: Bearer $ADMIN_TOKEN" > compromised-account-activity.json
   ```

3. **Get the timeline of each accessed key:**
   ```bash
   for KEY_ID in $(jq -r '.[].target_id' compromised-account-activity.json | sort -u); do
     curl "http://localhost:5173/svc/audit/audit/timeline/$KEY_ID?tenant_id=root" \
       -H "Authorization: Bearer $ADMIN_TOKEN" > "key-timeline-$KEY_ID.json"
   done
   ```

4. **Determine exposure window** (from first suspicious event to revocation):
   ```bash
   curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&actor_id=COMPROMISED_CLIENT_UUID&date_from=2024-03-01T00:00:00Z&action=key.decrypt" \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

5. **Initiate key rotation** for all accessed keys (requires governance approval if policy exists):
   ```bash
   curl -X POST "http://localhost:5173/svc/keycore/keys/AFFECTED_KEY_UUID/rotate?tenant_id=root" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{"reason": "Key compromise — service account COMPROMISED_CLIENT_UUID potentially exposed"}'
   ```

6. **Generate incident report:**
   ```bash
   curl -X POST "http://localhost:5173/svc/reporting/reports/generate?tenant_id=root" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{
       "template_id": "incident_report",
       "format": "pdf",
       "filters": {
         "actor_id": "COMPROMISED_CLIENT_UUID",
         "correlation_ids": ["incident-correlation-uuid"]
       },
       "title": "Key Compromise Incident Report 2024-03-15"
     }'
   ```

---

### 7.3 SOC 2 Evidence Collection Automation

**Scenario:** A SaaS company needs to collect continuous evidence for their SOC 2 Type II audit covering CC6 (logical access) and CC7 (system operations).

**Automated evidence pipeline:**

```bash
# Daily: export access events (CC6 — logical access controls)
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&date_from=$(date -d '1 day ago' -u +%Y-%m-%dT00:00:00Z)&date_to=$(date -u +%Y-%m-%dT23:59:59Z)&format=jsonl&service=auth" \
  -H "Authorization: Bearer $TOKEN" >> /evidence/cc6-access-events.jsonl

# Daily: export anomaly alerts (CC7 — monitoring)
curl "http://localhost:5173/svc/alerting/alerts?tenant_id=root&date_from=$(date -d '1 day ago' -u +%Y-%m-%dT00:00:00Z)&format=json" \
  -H "Authorization: Bearer $TOKEN" >> /evidence/cc7-alerts.json

# Weekly: compliance assessment (CC9 — risk management)
curl -X POST "http://localhost:5173/svc/compliance/compliance/assess?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"template_id": "soc2_focused"}' >> /evidence/weekly-assessments.json

# Monthly: governance activity report (CC6.6 — access restrictions)
curl -X POST "http://localhost:5173/svc/reporting/reports/generate?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"template_id": "governance_activity", "format": "json"}' | \
  jq '.job_id' | xargs -I{} sh -c 'sleep 30; curl "http://localhost:5173/svc/reporting/reports/jobs/{}/download?tenant_id=root" -H "Authorization: Bearer '$TOKEN'"' > /evidence/monthly-governance.json
```

---

### 7.4 GDPR Data Subject Access Request with Audit Trail

**Scenario:** A GDPR Data Subject Access Request (DSAR) requires the organisation to provide evidence of all processing activities involving a specific person's data.

```bash
# Find all encryption/decryption events involving the data subject's data
# (Keys tagged with the data subject's pseudonymous ID)
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&tag=data-subject:pseudonym-hash-abc123" \
  -H "Authorization: Bearer $TOKEN" > dsar-activity.json

# Get timeline of all keys used for this subject's data
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&service=keycore&tag=data-subject:pseudonym-hash-abc123&date_from=2018-05-25T00:00:00Z" \
  -H "Authorization: Bearer $TOKEN"

# Generate signed, tamper-evident export as DSAR evidence
curl "http://localhost:5173/svc/audit/audit/events?tenant_id=root&tag=data-subject:pseudonym-hash-abc123&format=csv&signing_key_id=DSAR_SIGNING_KEY_UUID" \
  -H "Authorization: Bearer $TOKEN" > dsar-evidence-signed.csv
```

---

### 7.5 DORA ICT Risk Reporting

**Scenario:** A EU financial entity subject to DORA Art. 10 must report ICT incidents and demonstrate operational resilience.

```bash
# Generate ICT risk report (DORA Art. 5 — ICT risk management)
curl -X POST "http://localhost:5173/svc/reporting/reports/generate?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "template_id": "compliance_summary",
    "format": "pdf",
    "filters": {
      "frameworks": ["dora"],
      "date_range": {"from": "2024-01-01", "to": "2024-12-31"}
    },
    "title": "DORA ICT Risk Report 2024"
  }'

# Export incident timeline for DORA Art. 10 reporting
curl -X POST "http://localhost:5173/svc/reporting/reports/generate?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "template_id": "incident_report",
    "format": "pdf",
    "filters": {"severity": ["critical", "high"], "date_range": {"from": "2024-01-01", "to": "2024-12-31"}}
  }'

# Backup recency evidence (DORA Art. 12 — backup policies)
curl "http://localhost:5173/svc/governance/governance/backups?tenant_id=root&date_from=2024-01-01T00:00:00Z" \
  -H "Authorization: Bearer $TOKEN" > dora-backup-evidence.json
```

---

## 8. Full API Reference

### Audit Service (`/svc/audit/audit/`)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/events` | List audit events with filters |
| GET | `/events/{id}` | Get single event by ID |
| GET | `/events/{id}/proof` | Get Merkle inclusion proof for event |
| GET | `/timeline/{resource_id}` | All events for a specific resource |
| GET | `/session/{session_id}` | All events in a session |
| GET | `/correlation/{correlation_id}` | All events in a correlation group |
| GET | `/chain/verify` | Verify entire audit chain integrity |
| POST | `/merkle/build` | Build new Merkle epoch |
| GET | `/merkle/epochs` | List all Merkle epochs |
| GET | `/merkle/epochs/{epoch_id}` | Get specific epoch with root |
| POST | `/merkle/verify` | Verify a Merkle inclusion proof |
| PUT | `/webhook` | Configure audit event push webhook |
| DELETE | `/webhook` | Remove audit webhook |

**Query parameters for GET /events:**

```
tenant_id, service, action, actor_id, actor_type, target_id, target_type,
result, source_ip, min_risk_score, max_risk_score, date_from, date_to,
tag, has_approval, correlation_id, session_id, fips_compliant, node_id,
format (json|jsonl|csv|cef|leef), signing_key_id, limit, offset, sort
```

---

### Governance Service (`/svc/governance/governance/`)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/policies` | List governance policies |
| POST | `/policies` | Create governance policy |
| GET | `/policies/{id}` | Get policy by ID |
| PUT | `/policies/{id}` | Update policy |
| DELETE | `/policies/{id}` | Delete policy |
| GET | `/requests` | List governance requests |
| GET | `/requests/{id}` | Get specific request with vote history |
| POST | `/approve/{id}` | Vote on a governance request |
| POST | `/requests/{id}/cancel` | Cancel a pending request |
| GET | `/settings` | Get notification settings |
| PUT | `/settings` | Update notification settings |
| POST | `/settings/test` | Test a notification channel |
| GET | `/backups` | List backups |
| POST | `/backups` | Create backup |
| GET | `/backups/{id}/artifact` | Download backup artifact |
| GET | `/backups/{id}/key` | Download backup key package |
| POST | `/backups/restore` | Restore from backup |
| PUT | `/backups/retention` | Set backup retention policy |
| GET | `/system/state` | Get system state |
| PUT | `/system/fips` | Toggle FIPS mode |
| PUT | `/system/network` | Update network configuration |

---

### Compliance Service (`/svc/compliance/compliance/`)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/templates` | List compliance templates |
| POST | `/templates` | Create custom template |
| GET | `/templates/{id}` | Get template |
| PUT | `/templates/{id}` | Update template |
| DELETE | `/templates/{id}` | Delete template |
| POST | `/assess` | Run compliance assessment |
| GET | `/assessments` | List assessments |
| GET | `/assessments/{id}` | Get assessment by ID |
| GET | `/assessments/delta` | Get delta from previous assessment |
| PUT | `/assessments/schedule` | Set assessment schedule |
| GET | `/assessments/schedule` | Get current schedule |
| GET | `/framework-gaps` | Get framework-specific gaps |
| GET | `/findings` | List posture findings |
| GET | `/findings/{id}` | Get finding by ID |
| POST | `/findings/{id}/acknowledge` | Acknowledge a finding |
| POST | `/findings/{id}/resolve` | Resolve a finding |
| GET | `/hygiene` | Get key hygiene metrics |
| GET | `/sbom` | Get Software Bill of Materials |
| GET | `/sbom/{service}` | Get SBOM for specific service |
| GET | `/cbom` | Get Cryptographic Bill of Materials |
| GET | `/pqc-readiness` | Get PQC readiness report |

---

### Alerting Service (`/svc/alerting/`)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/rules` | List alert rules |
| POST | `/rules` | Create alert rule |
| GET | `/rules/{id}` | Get rule by ID |
| PUT | `/rules/{id}` | Update rule |
| PATCH | `/rules/{id}` | Partial update (e.g. enable/disable) |
| DELETE | `/rules/{id}` | Delete rule |
| POST | `/rules/{id}/test` | Test rule against synthetic event |
| GET | `/alerts` | List triggered alerts |
| GET | `/alerts/{id}` | Get alert by ID |
| POST | `/alerts/{id}/acknowledge` | Acknowledge alert |
| POST | `/alerts/{id}/resolve` | Resolve alert |
| POST | `/alerts/{id}/assign` | Assign alert to user |
| GET | `/metrics` | Get MTTD/MTTR metrics |
| PUT | `/channels/slack` | Configure Slack channel |
| PUT | `/channels/pagerduty` | Configure PagerDuty |
| PUT | `/channels/webhook` | Configure webhook channel |

---

### Reporting Service (`/svc/reporting/reports/`)

| Method | Endpoint | Description |
|---|---|---|
| POST | `/generate` | Start report generation job |
| GET | `/jobs` | List report jobs |
| GET | `/jobs/{id}` | Get job status |
| GET | `/jobs/{id}/download` | Download completed report |
| GET | `/schedules` | List scheduled reports |
| POST | `/schedules` | Create scheduled report |
| PUT | `/schedules/{id}` | Update schedule |
| DELETE | `/schedules/{id}` | Delete schedule |

---

*Document version: 1.0.0 — Generated for Vecta KMS. All API paths assume the default gateway at `http://localhost:5173`. In production, substitute the actual gateway hostname and use HTTPS.*
