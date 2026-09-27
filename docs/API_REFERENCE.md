# Vecta KMS — Complete API Reference

Complete endpoint reference for all 27 Vecta KMS services.

## Quick Navigation

| Service | Base Path | Domain |
|---------|-----------|--------|
| auth | /svc/auth/ | Authentication, users, tenants, IdP, SCIM |
| keycore | /svc/keycore/ | Key lifecycle, crypto operations |
| certs | /svc/certs/ | PKI, certificates, enrollment |
| audit | /svc/audit/ | Audit log, SIEM export |
| governance | /svc/governance/ | Approvals, backup, system state |
| compliance | /svc/compliance/ | Framework scoring, assessments |
| posture | /svc/posture/ | Risk findings, drift detection |
| reporting | /svc/reporting/ | Alerts, reports, scheduled jobs |
| workload | /svc/workload/ | SPIFFE/SVID, token exchange |
| confidential | /svc/confidential/ | TEE attestation, attested key release |
| pqc | /svc/pqc/ | PQC policy, inventory, migration |
| keyaccess | /svc/keyaccess/ | Access justification rules |
| dataprotect | /svc/dataprotect/ | Tokenization, masking, field encryption |
| payment | /svc/payment/ | TR-31, PIN blocks, ISO 20022 |
| autokey | /svc/autokey/ | Key provisioning templates, handles |
| cloud | /svc/cloud/ | BYOK, cloud key sync |
| hyok | /svc/hyok/ | HYOK proxy, DKE, Google CSE |
| ekm | /svc/ekm/ | Database TDE, BitLocker |
| kmip | /svc/kmip/ | KMIP protocol management |
| signing | /svc/signing/ | Artifact, container, git signing |
| cluster | /svc/cluster/ | Cluster nodes, HSM registration |
| secrets | /svc/secrets/ | Secret vault |
| sbom | /svc/sbom/ | SBOM/CBOM inventory |
| ai-gateway | /svc/ai-gateway/ | AI gateway (DLP, guardrails) |

---

## Conventions

**Base URL**: `http://{host}` — use `https://localhost` for local dev

**All API paths**: `http://{host}/svc/{service}/{path}`

**Authentication**: Include on all requests except noted:
```
Authorization: Bearer {token}
X-Tenant-ID: {tenantId}
Content-Type: application/json
```

**Token**: JWT from `POST /svc/auth/auth/login`. Contains claims: `sub` (user ID), `tid` (tenant ID), `roles` (array), `exp`, `iat`.

**Pagination**: Cursor-based on all list endpoints. Request: `pageSize` (max 100, default 20), `pageToken`. Response: `{"items": [...], "nextPageToken": "...", "totalCount": 1234}`

**Idempotency**: POST requests accept `X-Idempotency-Key: {uuid}` header to safely retry.

**Error Response**:
```json
{
  "code": "KEY_NOT_FOUND",
  "message": "Key abc123 not found in tenant root",
  "details": {"keyId": "abc123"},
  "requestId": "req-01ARZ3NDEKTSV4RRFFQ69G5FAV"
}
```

**Preview features** ([PREVIEW_FEATURES.md](PREVIEW_FEATURES.md)): responses
from features that store configuration without enforcing it carry
`X-Vecta-Feature-Status: preview` and `X-Vecta-Feature-Status-Id: <id>`
(keycore control records also include `feature_status` / `feature_id`).
Operations such a feature cannot perform return `409 feature_preview`.

**Common Error Codes**:
| HTTP | Code | Meaning |
|------|------|---------|
| 400 | INVALID_REQUEST | Validation failed |
| 401 | UNAUTHENTICATED | Missing/invalid token |
| 403 | UNAUTHORIZED | Insufficient permissions |
| 403 | JUSTIFICATION_REQUIRED | Missing X-Key-Access-Justification |
| 404 | NOT_FOUND | Resource does not exist |
| 409 | CONFLICT | State conflict or duplicate |
| 422 | UNPROCESSABLE | Semantic validation failed |
| 429 | RATE_LIMITED | Rate limit exceeded |
| 500 | INTERNAL_ERROR | Server error |
| 503 | SERVICE_UNAVAILABLE | Dependency unavailable |

**Rate Limiting**: Response headers when rate limited:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1735689600
Retry-After: 60
```

**Binary data**: All keys, signatures, ciphertext are base64url-encoded (no padding)

**Timestamps**: ISO-8601 UTC: `2025-03-15T14:22:00.000Z`

---

## Service 1: Auth (`/svc/auth/`)

Authentication, session management, users, tenants, API clients, IdP integration, SCIM provisioning.

---

### POST /svc/auth/auth/login

**Authentication**: None (public)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| username | string | Yes | Username or email |
| password | string | Yes | Password |
| tenantId | string | Yes | Tenant to authenticate against |
| mfaCode | string | No | TOTP code if MFA enabled |

**Response 200**: `token`, `refreshToken`, `expiresAt`, `userId`, `tenantId`, `roles[]`, `mfaRequired`

```bash
export TOKEN=$(curl -sk -X POST https://localhost/svc/auth/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme","tenantId":"root"}' | jq -r '.token')
```

Response:
```json
{
  "token": "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyLTAxQVJaMk5ERUtUU1Y0UlJGRlE2OUc1RkFWIiwidGlkIjoicm9vdCIsInJvbGVzIjpbImFkbWluIl0sImlhdCI6MTc0MDU2ODAwMCwiZXhwIjoxNzQwNTcxNjAwfQ.signature",
  "refreshToken": "rt_01ARZ3NDEKTSV4RRFFQ69G5FAV_longstring",
  "expiresAt": "2025-03-15T15:22:00Z",
  "userId": "user-01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "tenantId": "root",
  "roles": ["admin"],
  "mfaRequired": false
}
```

Errors: `INVALID_CREDENTIALS` (401), `MFA_REQUIRED` (401), `ACCOUNT_LOCKED` (401), `TENANT_NOT_FOUND` (404)

---

### POST /svc/auth/auth/logout

Bearer required. No body. Invalidates token. Response: 204.

---

### POST /svc/auth/auth/refresh

Public. Body: `refreshToken`. Response: `token`, `refreshToken`, `expiresAt`.

---

### POST /svc/auth/auth/client-token

Issues sender-constrained client tokens. Supports mTLS (`oauth_mtls`), DPoP, HTTP Message Signature binding.

Body: `clientId`, `clientSecret` (for secret mode), `grantType: client_credentials`, `scope`

Response: `token`, `expiresAt`, `tokenType`, `boundThumbprint` (if sender-constrained)

---

### GET /svc/auth/auth/rest-client-security/summary

Bearer, admin. Response: `totalClients`, `senderConstrainedClients`, `legacyClients`, `replayProtectedClients`, `replayViolations`, `signatureFailures`, `unsignedRequestRejects`

---

### GET /svc/auth/auth/users

Bearer, admin. Query: `pageSize`, `pageToken`, `search`, `role`, `tenantId`, `locked`. Response: paginated UserSummary[].

UserSummary fields: id, username, email, displayName, roles[], tenantId, lastLoginAt, locked, mfaEnabled, createdAt

---

### POST /svc/auth/auth/users

Bearer, admin. Body: `username`, `email`, `displayName`, `password`, `roles[]`, `tenantId`, `sendWelcomeEmail`. Response 201: User.

```bash
curl -sk -X POST https://localhost/svc/auth/auth/users \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"username":"bob","email":"bob@example.com","password":"SecurePass123!","roles":["operator"],"tenantId":"root"}'
```

---

### POST /svc/auth/auth/users/{id}/reset-password

Body: `newPassword` OR `sendResetEmail: true`. Response 200: `{"message": "Password reset successful"}`

---

### GET/POST /svc/auth/tenants / GET/DELETE /svc/auth/tenants/{id}

Create body: `id` (slug), `name`, `plan`, `config` (maxKeys, maxUsers, enforceMfa, sessionTimeoutMinutes, allowedIpRanges[]).

```bash
curl -sk -X POST https://localhost/svc/auth/tenants \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"id":"acme-corp","name":"Acme Corporation","plan":"enterprise","config":{"maxKeys":10000,"enforceMfa":true}}'
```

---

### GET/PUT /svc/auth/auth/scim/settings

Settings: `enabled`, `defaultRole`, `deprovisionMode` (disable/delete), `groupRoleMappingActive`, `requirePasswordChangeOnFirstLogin`

---

### POST /svc/auth/auth/scim/settings/rotate-token

Returns raw SCIM bearer token once. Response: `{"token": "...", "rotatedAt": "..."}`

---

### GET /svc/auth/auth/scim/summary

Response: `managedUsers`, `managedGroups`, `memberships`, `roleMappedGroups`, `lastProvisionedAt`, `lastDeprovisionedAt`

---

### SCIM 2.0 (`/svc/auth/scim/v2/`)

Auth: SCIM bearer token. Discovery: ServiceProviderConfig, Schemas, ResourceTypes. RFC 7644 User and Group CRUD. PATCH uses SCIM patch operations (add/replace/remove members).

---

### POST /svc/auth/auth/cluster/mint (internal)

Only the `kms-cluster-manager` service identity may call it (`403
service_identity_required` otherwise). Body: `{"claims": {…}, "forwarded_by":
"<member node id>"}`.

Returns a 5-minute access token signed by this node. It carries the source
identity fields only (tenant, user, role, permissions, client) plus
`fwd_node`. `403 password_change_required` if the user must change their
password first.

Audit: `audit.auth.cluster_token_minted` (warning when the source is itself a
service principal); refusals emit `audit.auth.cluster_mint_refused`.

## Service 2: Keycore (`/svc/keycore/`)

Key lifecycle management and all cryptographic operations.

### HSM integration: `GET/PUT /svc/keycore/hsm/settings`

A tenant's two HSM switches ([SECURITY/HSM_INTEGRATION.md](SECURITY/HSM_INTEGRATION.md)).
`GET` (`key.hsm.read`) returns `settings` (`tenant_key_enabled`,
`hsm_keys_enabled`, `tenant_key_label`), `connector` (whether this platform
runs the hsm-connector) and `hsm`: what the connector reports after loading
the tenant's PKCS#11 library (`configured`, `connected`, `manufacturer`,
`model`, `token_label`, `firmware`, `tenant_key_ready`, `error`). `PUT`
(`key.hsm.write`, body `tenant_key_enabled`, `hsm_keys_enabled`) is refused
unless the HSM is configured and connected (`409 hsm_not_configured` /
`hsm_not_connected`, `503 hsm_unavailable`). Turning the tenant key on
generates it in the HSM.

`POST /svc/keycore/keys` takes `"hsm": true` to generate the key in the
tenant's HSM (AES-128/192/256-GCM, RSA-2048/3072/4096 PSS, ECDSA
P-256/P-384). The key is never exportable. Encrypt, decrypt, sign and verify
run in the HSM, and operations that need the material answer
`409 hsm_operation_unsupported`. Key versions report `protection` (`mek`,
`tenant_hsm`, `hsm_resident`) and `hsm_label`. An HSM key's labels record
the device that generated it (`hsm_serial`, `hsm_token`, `hsm_model`,
`hsm_manufacturer`). If its object is missing from the HSM the tenant's
profile now points at, operations answer `409 hsm_key_not_found` naming the
recorded serial.

`GET /svc/keycore/keys/{id}/hsm` (`key.hsm.read`, "Verify in HSM") reads the
key's objects back from the HSM: `recorded_hsm`, `current_hsm`,
`same_device`, and per version `label`, `protection` and `objects` (class,
key type, size or curve, and the HSM's own `local`, `sensitive`,
`extractable`, `never_extractable`, `always_sensitive` and usage flags; key
values are never read). A key with no HSM versions answers `409 not_hsm_key`.

`GET /svc/keycore/hsm/objects` (`key.hsm.read`) lists the tenant's HSM
partition: `hsm` (identity) and `objects`, each with the attributes above,
`managed` (created by the KMS for this tenant, with `key_id`, `version` and
`kms_role` `key`/`tenant_key`) or not (already in the partition), and for
certificates `certificate` (`subject`, `issuer`, `serial`, `not_before`,
`not_after`, `sha256`). Other tenants' KMS objects are never listed.
Read-only: partition objects can't yet be adopted as KMS keys.

### hsm-connector (internal, port 8430)

Only `kms-keycore` and `kms-governance` may call the key routes (others get
`403 caller_not_allowed`). Labels must start with `vecta:<tenant_id>:`.
Routes: `POST /hsm/keys`, `/hsm/tenant-key`, `/hsm/encrypt`,
`/hsm/decrypt`, `/hsm/sign`, `/hsm/verify`, `/hsm/keys/destroy`,
`/hsm/random` (body `tenant_id`, `length` 1–4096; returns `bytes_b64` from the
token's `C_GenerateRandom` and the token identity `hsm`), and
`GET /hsm/status` (also open to tenant administrators). Keycore only:
`POST /hsm/keys/inspect` (body `tenant_id`, `label`) and
`GET /hsm/objects?tenant_id=` return object attributes and the token's
identity (`manufacturer`, `model`, `serial_number`, `token_label`), which
`POST /hsm/keys` also returns as `hsm`. Env:
`HSM_LIBRARY_ROOTS` (default `/var/lib/vecta/hsm/providers`), plus the PIN
variable each profile names (or `<name>_FILE`). Keycore and governance use
`HSM_CONNECTOR_URL` (default `http://hsm-connector:8430`).

---

### Key Object Schema

| Field | Type | Description |
|-------|------|-------------|
| id | string | UUID key identifier |
| name | string | Unique name within tenant |
| algorithm | string | AES-256, AES-128, EC-P256, EC-P384, EC-P521, Ed25519, RSA-2048, RSA-4096, ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA-SHA2-128s |
| purpose | string | encrypt / sign / both / wrap / derive |
| state | string | PENDING / ACTIVE / DEACTIVATED / PENDING_DELETION / DESTROYED |
| currentVersion | int | Active version number |
| publicKey | string | PEM public key (asymmetric) |
| fingerprint | string | SHA-256 of key material |
| hsmBacked | boolean | Key material in HSM |
| hsmGroupId | string | HSM group ID |
| tenantId | string | Owning tenant |
| tags | object | Searchable key-value pairs |
| metadata | object | Non-indexed metadata |
| expiresAt | string | Expiry or null |
| rotationPolicy | object | intervalDays, notifyDaysBefore, autoRotate |
| exportPolicy | object | mode (disabled/enabled/wrapped), requireWrapping |
| interfacePolicy | object | maxUsesPerPeriod, periodSeconds, blockedOperations[] |
| accessPolicy | object | grants[] |
| createdAt | string | Creation timestamp |
| createdBy | string | Creator identity |
| updatedAt | string | Last update |

---

### POST /svc/keycore/keys

Bearer, roles: operator or admin.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Unique key name |
| algorithm | string | Yes | One keycore generates: AES-128/192/256[-mode], 3DES, HMAC-SHA256/384/512, RSA-2048/3072/4096/8192, ECDSA/ECDH P-256/P-384/P-521, Ed25519, X25519, ML-KEM-768/1024, ML-DSA-65/87, SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}. Anything else: `400 algorithm_unsupported` (audited `audit.key.create_refused`) |
| purpose | string | Yes | encrypt / sign / both / wrap / derive |
| hsmGroup | string | No | HSM group name |
| tags | object | No | Searchable tags |
| metadata | object | No | Non-indexed metadata |
| expiresAt | string | No | Expiry timestamp |
| rotationPolicy | object | No | intervalDays, notifyDaysBefore, autoRotate |
| exportPolicy | object | No | mode, requireWrapping |
| interfacePolicy | object | No | maxUsesPerPeriod, periodSeconds, blockedOperations[] |
| accessPolicy | object | No | Access grants |

```bash
curl -sk -X POST https://localhost/svc/keycore/keys \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"customer-data-key","algorithm":"AES-256","purpose":"encrypt","tags":{"env":"prod","dataClass":"pii"},"rotationPolicy":{"intervalDays":90,"notifyDaysBefore":14,"autoRotate":true},"exportPolicy":{"mode":"disabled"}}'
```

Response:
```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "name": "customer-data-key",
  "algorithm": "AES-256",
  "purpose": "encrypt",
  "state": "ACTIVE",
  "currentVersion": 1,
  "hsmBacked": false,
  "tenantId": "root",
  "tags": {"env": "prod", "dataClass": "pii"},
  "rotationPolicy": {"intervalDays": 90, "notifyDaysBefore": 14, "autoRotate": true},
  "exportPolicy": {"mode": "disabled"},
  "fingerprint": "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "createdAt": "2025-03-15T14:22:00Z",
  "createdBy": "user-admin",
  "updatedAt": "2025-03-15T14:22:00Z"
}
```

---

### GET /svc/keycore/keys

Query: `pageSize`, `pageToken`, `algorithm`, `purpose`, `state`, `search`, `tag:{key}={value}`, `hsmBacked`

---

### GET /svc/keycore/keys/{id}

Returns full Key object.

---

### POST /svc/keycore/keys/{id}/activate

PENDING → ACTIVE. No body.

---

### POST /svc/keycore/keys/{id}/deactivate

ACTIVE → DEACTIVATED. Existing ciphertext can still be decrypted.

---

### POST /svc/keycore/keys/{id}/rotate

New version created, previous retired but still available for decryption.

```bash
curl -sk -X POST https://localhost/svc/keycore/keys/3fa85f64-5717-4562-b3fc-2c963f66afa6/rotate \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### POST /svc/keycore/keys/{id}/destroy

Irreversible. All versions and material destroyed. State → DESTROYED.

---

### POST /svc/keycore/keys/{id}/encrypt

Body: `plaintext` (base64), `aad` (base64, optional), `iv` (optional), `keyVersion` (optional)

Response: `ciphertext`, `iv`, `tag`, `keyId`, `keyVersion`, `algorithm`

```bash
curl -sk -X POST https://localhost/svc/keycore/keys/3fa85f64-5717-4562-b3fc-2c963f66afa6/encrypt \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"plaintext":"SGVsbG8sIFdvcmxkIQ==","aad":"dXNlcklkPTEyMw=="}'
```

Response:
```json
{
  "ciphertext": "7Yp3K2vXmNqL8fGhRtAzBw==",
  "iv": "YWJjZGVmZ2hpamts",
  "tag": "a1b2c3d4e5f6a7b8",
  "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "keyVersion": 1,
  "algorithm": "AES-256-GCM"
}
```

---

### POST /svc/keycore/keys/{id}/decrypt

Body: `ciphertext`, `iv`, `tag`, `aad` (optional), `keyVersion` (optional). Response: `plaintext` (base64), `keyId`, `keyVersion`

---

### POST /svc/keycore/keys/{id}/sign

Body: `message` (base64), `messageType` (raw/digest), `algorithm` (ECDSA-SHA256, ECDSA-SHA384, EdDSA, RSA-PSS-SHA256, ML-DSA, SLH-DSA), `keyVersion`

Response: `signature` (base64), `algorithm`, `keyId`, `keyVersion`, `publicKeyPem`

`prehashed: true` signs `data` as an already computed digest (the HSM CA
path). HSM keys only; the hash (`algorithm` SHA-256/384/512) must match the
digest length, else `400`. A software key answers `400` ("prehashed signing
is supported for HSM keys only").

---

### POST /svc/keycore/keys/{id}/verify

Body: `message`, `signature`, `messageType`, `algorithm`, `keyVersion`. Response: `valid` (boolean), `keyId`, `keyVersion`, `algorithm`

---

### POST /svc/keycore/keys/{id}/wrap

Body: `plaintext` (base64 key material), `aad` (base64, optional), `iv_mode`.
Response: `ciphertext`, `iv`, `version`, `key_id`, `kcv`. Same checks as
`encrypt`, metered and policy-evaluated as `key.wrap`.

---

### POST /svc/keycore/keys/{id}/unwrap

Body: `ciphertext`, `iv`, `aad` (all base64). Response: `plaintext` (base64),
`version`, `key_id`. Evaluated as `key.unwrap`.

---

### POST /svc/keycore/keys/{id}/generate-data-key

Envelope encryption. Keycore generates a data key (DEK) from the FIPS module's
DRBG and wraps it under this key.

Body: `key_bytes` (16, 24 or 32; default 32), `aad` (base64, optional; the
same value must be given to `/unwrap`), `include_plaintext` (default `true`;
`false` returns only the wrapped DEK).

Response: `plaintext_dek` (base64, omitted when `include_plaintext` is
`false`), `wrapped_dek`, `wrapped_dek_iv`, `key_bytes`, `key_id`, `version`,
`kcv`.

Encrypt the data locally with the DEK, discard it, and store `wrapped_dek` +
`wrapped_dek_iv` with the ciphertext. Recover the DEK with `/unwrap`
(`ciphertext` = `wrapped_dek`, `iv` = `wrapped_dek_iv`).

- Permission `key.wrap`. The key's access policy, governance policy, FIPS mode,
  approval, metering and ops limit apply as for `/wrap`. An approval-gated key
  answers `202` with `approval_request_id`.
- Audit `audit.key.data_key_generated`. Refusals carry `result: refused` and
  `reason` (for example `ops_limit_reached` → `429`, `policy_denied` /
  `fips_mode_violation` → `403`).
- Runs locally on a cluster member.

---

### Crypto agility: /svc/keycore/agility/*

Every figure is computed from the tenant's live keys (status not `deleted` or
`destroyed`); nothing is estimated or seeded. Served by the `pkg/route` kernel:
the tenant comes from the token (a conflicting `tenant_id` is refused as
`tenant_mismatch`), and each call emits its own audit event, refusals
included.

| Route | Permission | Audit | Response `data` |
|---|---|---|---|
| `GET /agility/score` | `key.agility.read` | `audit.key.agility_score_read` | `assessed` (false with no live keys: `score` 0, `grade` ""), `score`, `grade`, `quantum_readiness`, `legacy_key_count`, `total_keys`, `algorithms`, `recommendations` |
| `GET /agility/algorithms` | `key.agility.read` | `audit.key.agility_inventory_read` | `[{algorithm, key_count, percentage, is_legacy, is_quantum_safe}]`, plus top-level `total_keys` |
| `GET /agility/keys-by-algorithm?algorithm=` | `key.agility.read` | `audit.key.agility_keys_by_algorithm_read` | `{algorithm, keys}` |
| `GET /agility/migration-plans` | `key.agility.read` | `audit.key.agility_migration_plans_listed` | plans with derived progress |
| `POST /agility/migration-plans` | `key.agility.write` | `audit.key.agility_migration_plan_created` | the new plan (`201`) |
| `PATCH /agility/migration-plans/{id}` | `key.agility.write` | `audit.key.agility_migration_plan_updated` | the updated plan |

- Create body: `name`, `from_algorithm`, `to_algorithm` (must differ),
  optional `target_date` (`YYYY-MM-DD` or RFC3339). Unknown fields are
  rejected: `affected_keys` is counted by keycore, never supplied.
- Update body: `status` only (`planned`, `in_progress`, `paused`,
  `completed`). Progress can't be set.
- Plan progress: `affected_keys` is the live `from_algorithm` key count when
  the plan was created; `remaining_keys` is that count now; `completed_keys` =
  `affected_keys - remaining_keys`, floored at 0.

---

### Key rotation policies: /svc/keycore/rotation/*

A policy rotates the tenant's **active** keys that match `target_filter`,
through the same path as `POST /keys/{id}/rotate`: policy check, key access,
HSM, and a per-key `audit.key.rotate`. Each key gets its own run row with the
real outcome. Served by the `pkg/route` kernel.

| Route | Permission | Audit |
|---|---|---|
| `GET /rotation/policies` | `key.rotation.read` | `audit.key.rotation_policies_listed` |
| `POST /rotation/policies` | `key.rotation.write` | `audit.key.rotation_policy_created` |
| `PATCH /rotation/policies/{id}` | `key.rotation.write` | `audit.key.rotation_policy_updated` |
| `DELETE /rotation/policies/{id}` | `key.rotation.write` | `audit.key.rotation_policy_deleted` |
| `POST /rotation/policies/{id}/trigger` | `key.rotation.write` | `audit.key.rotation_policy_triggered` (details `matched`, `rotated`, `failed`) |
| `GET /rotation/runs[?policy_id=]` | `key.rotation.read` | `audit.key.rotation_runs_listed` |
| `GET /rotation/upcoming` | `key.rotation.read` | `audit.key.rotation_upcoming_listed` |

- **Create body:** `name`, `target_filter`, `interval_days` (1–3650) and
  `auto_rotate`. `target_type` may be omitted or `key`; `secret` and
  `certificate` are refused (`unsupported_target_type`).
- **`target_filter`:** `*` (every active key), `tag:<tag>`, `id:<key id>`, or
  a glob on the key name (`prod-*`). A filter that matches more than 1,000
  active keys is refused.
- **Update body:** any of `name`, `target_filter`, `interval_days`,
  `auto_rotate` and `enabled`.
- **Removed fields:** `cron_expr` and `notify_days_before` were stored but
  never used. Requests carrying them are now rejected (400, unknown field).
- **Trigger:** rotates the matching keys now, *as the caller*, so their key
  grants apply. Response: `outcome` `{matched, rotated, failed, runs[]}`. A
  key the caller may not rotate gives a `failed` run with the refusal, and
  the policy's `status` becomes `error` with `last_error`.
- **Schedule:** on the primary, every minute, keycore runs enabled
  `auto_rotate` policies whose `next_rotation_at` has passed. They run under
  keycore's own in-process service identity. Each run emits
  `audit.key.rotation_policy_run` (details `matched`, `rotated`, `failed`,
  `result: failure` if any key failed). `next_rotation_at` advances by
  `interval_days`. Cluster members never run the schedule.
- **Runs:** `triggered_by` is `schedule` or `manual:<actor>`, and `status` is
  `success` or `failed` with `error`.

---

### Webhooks: /svc/audit/webhooks

The audit service delivers every persisted audit event whose `action`
matches one of a webhook's `events` patterns to the tenant's enabled
webhooks. Delivery runs on the node that ingested the event.

| Route | Permission | Audit |
|---|---|---|
| `GET /webhooks` | `audit.webhook.read` | `audit.audit.webhooks_listed` |
| `POST /webhooks` | `audit.webhook.write` | `audit.audit.webhook_created` |
| `PATCH /webhooks/{id}` | `audit.webhook.write` | `audit.audit.webhook_updated` |
| `DELETE /webhooks/{id}` | `audit.webhook.write` | `audit.audit.webhook_deleted` |
| `POST /webhooks/{id}/test` | `audit.webhook.write` | `audit.audit.webhook_tested` |
| `GET /webhooks/{id}/deliveries` | `audit.webhook.read` | `audit.audit.webhook_deliveries_listed` |

- **Every delivery,** real or test, emits `audit.audit.webhook_delivered`:
  `result` is `success` or `failure`; details are `event_id`,
  `event_action`, `http_status`, `attempts`, `latency_ms` and `format`. It
  is also recorded in the node-local `webhook_deliveries`.
  `audit.audit.webhook_*` events are never delivered.
- **`url`:** `https` only. It passes the SSRF guard, and delivery dials the
  address it checked (no DNS rebinding), with no redirects, no proxy and TLS
  1.3. A refused URL is audited as `result: refused`, `reason: url_blocked`.
- **`events`:** `*`, a prefix such as `audit.key.*`, or an exact action such
  as `audit.key.rotate`. Older names like `key.created` never matched an
  audit action and are refused.
- **`format`:**
  - `json`: `{event_type, event}`
  - `splunk_hec`: the HEC envelope, `sourcetype` `vecta:audit`
  - `datadog`: a Logs intake array
  - `slack`: `{text}`

  `pagerduty` and `generic_siem` are refused: neither was ever produced.
- **`secret`:** optional, at least 16 characters (HMAC keys under 112 bits
  are not approved). Each body is signed as
  `X-KMS-Signature: sha256=<hex HMAC-SHA256(secret, body)>`. Every request
  also carries `X-KMS-Event-Type` and `X-KMS-Event-ID`.
- **`headers`:** custom headers, for example `Authorization: Splunk <token>`
  or `DD-API-KEY`. The platform's own headers can't be overridden.
- **At rest:** the secret and header values are sealed as one envelope under
  the audit service master key from keycore (`pkg/mek`,
  docs/SECURITY/SERVICE_MASTER_KEYS.md). Until that key is open, a create or
  update carrying credentials returns `503 credentials_key_unavailable`. The
  master-key routes `GET /svc/audit/mek/exposure` and
  `POST /svc/audit/mek/exposure/{item_type}/{item_id}/acknowledge` list and
  acknowledge webhooks whose credentials were once stored in plaintext.
- **Write-only values:** responses never carry the secret or header values.
  They show `has_secret` and header names with empty values. On update, a
  header sent with an empty value keeps its stored value, and
  `clear_secret: true` removes the secret.
- **Delivery:** three attempts with backoff and a per-webhook circuit
  breaker. The queue holds 4,096 events. A full queue is recorded as a failed
  delivery (`delivery queue full`) and audited; it is never dropped silently.
  Only the primary updates `last_delivery_*` and `failure_count` (a
  replicated row); members keep their attempts in `webhook_deliveries`.
- **Test:** sends a labelled event (`audit.audit.webhook_test`) through the
  same path. Response: `success`, `status`, `http_status`, `latency_ms`,
  `error`.

---

### Leak scanner: /svc/posture/leaks/*

| Route | Permission | Audit |
|---|---|---|
| `GET /leaks/targets` | `posture.leak.read` | `audit.posture.leak_targets_listed` |
| `POST /leaks/targets` | `posture.leak.write` | `audit.posture.leak_target_created` |
| `DELETE /leaks/targets/{id}` | `posture.leak.write` | `audit.posture.leak_target_deleted` |
| `POST /leaks/targets/{id}/scan` | `posture.leak.write` | `audit.posture.leak_scan_started`; the outcome is `audit.posture.leak_scan_completed` |
| `GET /leaks/jobs` | `posture.leak.read` | `audit.posture.leak_jobs_listed` |
| `GET /leaks/findings` | `posture.leak.read` | `audit.posture.leak_findings_listed` |
| `PATCH /leaks/findings/{id}` | `posture.leak.write` | `audit.posture.leak_finding_updated` |

- **Target `type`:** `git_repo`, `container_image`, `log_stream`,
  `s3_bucket` or `env_file`.
- **Scanned content:** either the optional scan body `{content, filename}`,
  or files at the target's path under the server's `LEAK_SCAN_ROOT`. Remote
  URLs are not fetched: the job fails with that reason, and never invents
  findings.
- **Findings:** keep a redacted preview and a SHA-256 fingerprint only.
- **`leak_scan_completed`:** carries `status`, `findings` and `job_id`. Its
  severity is warning when there are findings or the scan failed.
- **Finding update body:** `status` (`open`, `acknowledged`, `resolved`,
  `false_positive`) and optional `notes`. `resolved_by` is the verified
  caller; a `resolved_by` in the body is rejected.
- **Disabled target:** a scan request is refused (`409`, `reason:
  target_disabled`).

---

### POST /svc/keycore/keys/{id}/derive

Body: `algorithm` (HKDF-SHA256/384/512, PBKDF2-SHA256, SP800-108-CTR), `salt`, `info`, `outputLength` (16–64), `outputKeySpec` (optional)

Response: Key object or `derivedKeyMaterial` (base64)

`info` must not start with the reserved prefix `vecta/service-derive/`. Such a
request is refused and audited as `audit.key.derive_refused` (critical).

---

### POST /svc/keycore/keys/{id}/service-derive

**Internal services only.** The caller needs a verified service JWT
(`kms-*` client). Any other caller gets 403 `service_identity_required`.
Returns a 32-byte working key:
`HKDF-SHA256(key material, "vecta-service-derive", "vecta/service-derive/v1|<client>|<tenant>|<key>|<purpose>|v<version>")`.
The result is bound to the calling service, and the pinned version keeps it
stable across rotation. The key must be symmetric and active or deactivated.

Body: `tenant_id`, `purpose` (`[a-z0-9-]`, 1–64 chars), `version` (0 = current).
Response: `key_id`, `version`, `purpose`, `kdf` (`HKDF-SHA256`), `derived_key` (base64).
Audit: `audit.key.service_derive`. See
[SECURITY/DATAPROTECT_KEY_DERIVATION.md](SECURITY/DATAPROTECT_KEY_DERIVATION.md).

---

### POST /svc/keycore/keys/{id}/mac

Body: `data`, `operation` (generate/verify), `mac` (for verify), `algorithm` (HMAC-SHA256/384/512, CMAC). Response: `mac` or `valid`.

---

### POST /svc/keycore/keys/{id}/export

Body: `format` (raw/pkcs8/spki/jwk/pkcs12), `wrappingKeyId` (if required). Response: `keyMaterial` (base64) or `jwk`.

---

### GET /svc/keycore/keys/{id}/versions

Response: `KeyVersion[]` — version, state, fingerprint, createdAt, retiredAt

---

### GET /svc/keycore/keys/{id}/versions/{version}

Single version detail.

---

### Enterprise Key Audit and Analytics

These endpoints provide the Tier 1 enterprise audit surface for rotation analytics, compromise response, health scoring, inventory, dependency mapping, hotspots, trends, and algorithm benchmarks. Full examples are in [ENTERPRISE_KEY_AUDIT.md](ENTERPRISE_KEY_AUDIT.md).

| Method | Path | Description |
|---|---|---|
| GET | `/svc/keycore/enterprise/summary` | Consolidated rotation, health, inventory, compromise, hotspot, benchmark, and roadmap summary. |
| GET | `/svc/keycore/rotation/analytics` | Rotation success, failure, overdue, duration, and batch metrics. |
| GET | `/svc/keycore/rotation/analytics/overdue` | Scheduled/in-progress rotations past scheduled time. |
| GET | `/svc/keycore/keys/{id}/rotation-metrics` | Rotation metric history for one key. |
| POST | `/svc/keycore/keys/{id}/rotation-metrics` | Record external rotation metric evidence. |
| GET | `/svc/keycore/keys/{id}/health` | Get or calculate key health score. |
| POST | `/svc/keycore/keys/{id}/health/recalculate` | Force health score recalculation. |
| GET | `/svc/keycore/health/summary` | Tenant health summary plus lowest-scoring keys. |
| POST | `/svc/keycore/inventory/sync` | Sync KeyCore metadata into enterprise inventory and recalculate health. |
| GET | `/svc/keycore/inventory/keys` | List inventory records. Query: `status`, `owner`, `limit`, `offset`. |
| GET | `/svc/keycore/inventory/orphans` | List active/pre-active/suspended keys with no dependency records. |
| GET | `/svc/keycore/inventory/duplicates` | List duplicate key groups by algorithm and KCV. |
| GET | `/svc/keycore/inventory/dependencies` | List dependency records. Query: `key_id`, `limit`. |
| POST | `/svc/keycore/inventory/dependencies` | Upsert key-to-service dependency record. |
| GET | `/svc/keycore/compromise/events` | List compromise events. Query: `status`, `severity`, `limit`. |
| POST | `/svc/keycore/compromise/events` | Report a compromise event; high/critical events can auto-suspend keys. |
| POST | `/svc/keycore/compromise/events/{id}/status` | Update incident/remediation workflow status. |
| POST | `/svc/keycore/compromise/advisories/ingest` | Ingest feed-style advisories by key ID or algorithm. |
| POST | `/svc/keycore/analytics/metrics` | Record custom key analytics metric. |
| GET | `/svc/keycore/analytics/usage` | Aggregate metric summary. Query: `key_id`, `days`, `since`. |
| GET | `/svc/keycore/analytics/hotspots` | Highest-use keys for the window. Query: `days`, `limit`. |
| GET | `/svc/keycore/analytics/trends` | Time-ordered metric trend. Query: `metric_type`, `days`, `since`. |
| GET | `/svc/keycore/analytics/algorithms` | Algorithm latency/performance benchmarks. |
| GET | `/svc/keycore/enterprise/controls` | List enterprise control records. Query: `category`, `key_id`, `status`, `limit`, `offset`. |
| POST | `/svc/keycore/enterprise/controls` | Upsert a generic enterprise control record. |
| GET | `/svc/keycore/enterprise/controls/{category}/{id}` | Fetch one enterprise control record. |
| POST | `/svc/keycore/enterprise/anomaly/scan` | Run statistical anomaly detection and upsert KeyCore DSPM findings. |
| GET | `/svc/keycore/enterprise/dspm/findings` | List KeyCore DSPM findings. Query: `source`, `finding_type`, `status`, `severity`, `key_id`. |
| POST | `/svc/keycore/enterprise/dspm/findings` | Upsert a KeyCore DSPM finding. |
| GET | `/svc/keycore/enterprise/dspm/events` | Export DSPM/posture-compatible normalized events. |
| POST | `/svc/keycore/enterprise/kdf/derive` | Derive key material with HKDF-SHA256, PBKDF2-SHA256, Scrypt, or Argon2id. |
| GET | `/svc/keycore/enterprise/audit-chain/anchors` | List audit-chain anchors. |
| POST | `/svc/keycore/enterprise/audit-chain/anchors` | Create a Merkle-style audit-chain anchor with optional external reference. |
| GET | `/svc/keycore/enterprise/compliance/dashboard` | KeyCore enterprise compliance score and evidence summary. |
| GET | `/svc/keycore/enterprise/cost/optimization` | Usage-cost estimate and optimization recommendations. |
| POST | `/svc/keycore/enterprise/verification/fingerprint` | Verify a key KCV/fingerprint using constant-time comparison. |
| POST | `/svc/keycore/enterprise/advanced-encryption/search-token` | Generate deterministic HMAC token for equality search. |
| POST | `/svc/keycore/enterprise/advanced-encryption/modes` | Register governed advanced-encryption mode controls. |
| POST | `/svc/keycore/enterprise/orchestration/workflows` | Register workflow/cron orchestration metadata. |
| POST | `/svc/keycore/enterprise/orchestration/runs` | Trigger orchestration run; can execute batch key rotations. |
| POST | `/svc/keycore/enterprise/federation/providers` | Register multi-KMS provider metadata. |
| POST | `/svc/keycore/enterprise/federation/mappings` | Register cross-KMS key mappings. |
| POST | `/svc/keycore/enterprise/federation/failovers` | Record cross-region/provider failover state. |
| POST | `/svc/keycore/enterprise/binding/policies` | Register hardware attestation/geolocation binding policy. |
| POST | `/svc/keycore/enterprise/edge/agents` | Register Edge/IoT KMS agents. |
| POST | `/svc/keycore/enterprise/edge/leases` | Register offline key lease state. |
| POST | `/svc/keycore/enterprise/edge/receipts` | Register edge operation receipts. |
| POST | `/svc/keycore/enterprise/sharing/grants` | Register temporary/delegated key-sharing grants. |
| POST | `/svc/keycore/enterprise/metadata/profiles` | Register classification/tagging/enrichment profiles. |
| POST | `/svc/keycore/enterprise/threat/signals` | Register advanced threat signals such as side-channel/DPA alerts. |

Example compromise event:

```bash
curl -sk -X POST "https://localhost/svc/keycore/compromise/events?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"key_id":"key-prod-001","cve_id":"CVE-2026-0001","threat_type":"cve","severity":"critical","detection_source":"nvd","auto_suspend":true}'
```

Example inventory dependency:

```bash
curl -sk -X POST "https://localhost/svc/keycore/inventory/dependencies?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"dependency_id":"dep-payments-api","key_id":"key-prod-001","service_id":"payments-api","dependency_type":"encryption","criticality":"critical","verification_status":"verified"}'
```

---

### Caller identity and access denials

Every key operation needs a verified token (a user token through the
gateway, or a service JWT); a request without one gets `403 access_denied`
with `reason: authentication_required`. Keycore refuses to start without the
key that verifies tokens. Keycore decides key access from the verified token only. `X-Actor-*`,
`X-KMS-Subject` and `X-KMS-Interface` headers are ignored for authorization
and recorded in `audit.key.actor_headers_ignored`. A key operation the caller
may not perform returns `403 access_denied` and emits
`audit.key.access_refused` with a `reason`.

### POST /svc/keycore/system-keys/ensure

Internal, service identities only (a `kms-*` service JWT), each for itself.
Returns the calling service's system key for a purpose, creating it on first
use: `{"purpose":"secrets-mek"}` returns `{"key_id","tenant_id","version","created"}`.
Services derive their master key from it with `POST /keys/{id}/service-derive`
(`pkg/mek`). Any other caller gets `403 service_identity_required`. Every call
emits `audit.key.system_key_ensure`.

A system key can't be destroyed (immediate, scheduled or bulk), disabled,
marked compromised, have a version deleted, or be made exportable:
`409 system_key_protected` and `audit.key.system_key_change_refused`. Rotate
and deactivate are allowed. See docs/SECURITY/SERVICE_MASTER_KEYS.md.

---

## Service 3: Certs (`/svc/certs/`)

PKI, CA management, certificate lifecycle, enrollment protocols (ACME, EST, SCEP), CRL/OCSP, renewal intelligence, STAR subscriptions.

### Internal mTLS enrolment (`https://certs:8035/v1/enroll`, service network only)

Every platform service gets its internal mTLS certificate here at start-up
and renews it at two thirds of its lifetime (docs/SECURITY/INTERNAL_TLS.md).
It isn't routed through the edge.

- **Transport:** TLS 1.3 with the certs service's own internal certificate. No
  client certificate is required, since the caller doesn't have one yet.
- **Body:** `{"identity": "kms-<service>", "csr_pem": "...", "timestamp": <unix>}`.
- **Header:** `X-Vecta-Enroll-Proof: hex(HMAC-SHA256(DeriveAPIKey(INTERNAL_SERVICE_BOOTSTRAP_SECRET, identity), "vecta-enroll-v1\n" + identity + "\n" + timestamp + "\n" + hex(SHA256(csr_der))))`.
  The timestamp must be within 5 minutes.
- **Response 200:** `certificate_pem`, `chain_pem` (the Sub CA), `serial`,
  `not_after`.
  - The certificate comes from the `vecta-internal-services` Sub CA, valid
    for `CERTS_INTERNAL_MTLS_VALIDITY_DAYS` days (default 7).
  - CN is the identity; the DNS SANs come from the platform registry
    (`pkg/svctls.Services`), never from the CSR.
  - The key must be ECDSA P-256/P-384 or RSA ≥ 3072.
  - The identity's previous certificate is revoked as `superseded`.
- **Refusals:** 400 (bad request or CSR) and 403 (proof rejected). Each is
  audited.

### Service mTLS: `/svc/certs/certs/internal-mtls` (1.16.0, root tenant only)

The certificate key, key exchange and rotation of every internal identity
(docs/SECURITY/INTERNAL_TLS.md). Permissions `cert.internal_mtls.read` and
`cert.internal_mtls.write`. Another tenant is refused with `not_root_tenant`.
Every call is audited as `audit.certs.<action>`, refusals included.

- **`GET /certs/internal-mtls`** (`internal_mtls_inventory_read`): every
  identity in `pkg/svctls` (services, Envoy and the dashboard, Postgres,
  NATS, Valkey, Consul) with:
  - `policy` (`key_algorithm`, `kx_profile`, `generation`, `restart_mode`,
    `apply_after`);
  - `certificates`: its active certificates from the Sub CA;
  - `observed`: what each running instance reports (serial, key, profile,
    generation, last negotiated group and time);
  - `served_file`: what certs last wrote, for a daemon;
  - `applied`: every instance runs the current generation.

  `meta` lists the choices, the groups of each profile and the FIPS mode.
- **`PUT /certs/internal-mtls/{identity}/policy`**
  (`internal_mtls_policy_updated`):
  - **Body:** `{"key_algorithm": "ECDSA-P256|ECDSA-P384|RSA-3072",
    "kx_profile": "pqc-required|pqc-preferred|classical", "reason": "..."}`.
  - **A service** restarts gracefully to apply it.
  - **A daemon** gets a new certificate with that key at once and reloads it.
    `kx_profile` is refused for daemons (`kx_profile_not_applicable`).
  - **Refusals:** `unchanged`, `invalid_policy`, `unknown_identity`.
- **`POST /certs/internal-mtls/{identity}/rotate`**
  (`internal_mtls_rotated`):
  - **Body:** `{"mode": "graceful|force", "reason": "..."}`.
  - **A service:** the active certificate is revoked (`superseded`, or
    `keyCompromise` when forced), the generation increases, and the service
    restarts and enrols a fresh key.
  - **A daemon:** a new certificate is written; `force` is refused with
    `force_not_available`, because certs doesn't restart the daemons.
- **`POST /certs/internal-mtls/rotate-all`** (`internal_mtls_rotated_all`):
  - **Body:** `{"mode": ..., "reason": ..., "confirm": "rotate-all"}`.
  - **Staggering:** services restart one every 20 s, certs last; daemons
    are reissued at once.
  - **Refusal:** without the confirmation, `confirmation_required`.

**How a service learns its policy:**
- Certs publishes it as `/run/vecta/trust/mtls-policy.json`, which is
  public: algorithms and generations only.
- Each service reads it before enrolling and re-reads it every 15 s.
- Each service reports what it runs to `platform_mtls_observed` every
  30 s.

`POST /certs/internal/mtls/{service}` is **removed**. It let any authenticated
caller obtain a certificate *and private key* for any service name.

Environment:
- **certs:** `CERTS_TRUST_DIR` (default `/run/vecta/trust`),
  `CERTS_ENROLL_PORT` (8035), `CERTS_INTERNAL_SUBCA_NAME`
  (`vecta-internal-services`), `CERTS_INTERNAL_MTLS_VALIDITY_DAYS` (7),
  `CERTS_DASHBOARD_TLS_DIR`, `CERTS_DASHBOARD_TLS_GID`.
- **certs (1.9.0):** `CERTS_INFRA_TLS_DIR` (default `/run/vecta/infra-tls`,
  one subdirectory per daemon), `CERTS_INTERNAL_PKI_CACHE` (default
  `/var/lib/vecta/certs/internal-pki.json`).
- **certs (1.15.0):** `CERTS_CRWK_USE_TPM_SEAL` and
  `cert_security.use_tpm_seal` are removed; they never sealed anything to a
  TPM. `GET /certs/security/status` no longer returns `use_tpm_seal`. The
  start scripts and `deploy-local.sh` warn if an old config still sets it.
- **hsm-integration (1.11.0):** `HSM_INTEGRATION_SSH_AUTHORIZED_KEYS` (SSH
  public keys, `;`-separated; set means password login off),
  `HSM_INTEGRATION_SSH_BIND` (bind address of port 2222, default
  `127.0.0.1`). `HSM_INTEGRATION_PASSWORD` never existed in code and is
  gone from the README. auth refuses to start when
  `AUTH_BOOTSTRAP_CLI_PASSWORD` is a retired public value.
- **certs (1.10.0):**
  - `CERTS_CRWK_PREVIOUS_PASSPHRASE_FILE` (default
    `$CERTS_CRWK_PASSPHRASE_FILE.previous`): the passphrase the CRWK was
    sealed under before a rotation. It is read only to re-key off it, then
    deleted.
  - `CERTS_CRWK_BOOTSTRAP_PASSPHRASE` and the passphrase file must be at
    least 32 characters, with at least 8 distinct characters, and not a
    retired public value. Otherwise certs refuses to start.
  - `GET /certs/security/status` reports `state: rotation_pending` and
    `rotation_pending: true` until the rewrap completes.
- **Infrastructure (1.9.0):**
  - `POSTGRES_DSN` uses
    `sslmode=verify-full&sslrootcert=/run/vecta/trust/internal-ca.crt`.
  - `REDIS_URL` is `rediss://:${VALKEY_PASSWORD}@valkey:6379`, and
    `VALKEY_PASSWORD` is required.
  - `CONSUL_HTTP_ADDR` is `https://consul:8501`.
  - `VECTA_PLATFORM_STATE_DIR` (default `/run/vecta/platform`, the FIPS mode
    file) and `VECTA_PLATFORM_FIPS_MODE_FILE` (governance).
- **Every service:** `CERTS_ENROLL_URL` (default
  `https://certs:8035/v1/enroll`), `VECTA_INTERNAL_CA_FILE` (default
  `/run/vecta/trust/internal-ca.crt`). `VECTA_MTLS_KEY_ALGORITHM` is
  removed in 1.16.0: the certificate key comes from the Service mTLS policy.
- **All `*_URL` service addresses are now `https://`.** Plain `http://` to a
  platform host is refused by the client.

Dashboard API calls under `/svc/<service>/` and `/auth` are routed by Envoy
directly to each service over mTLS.

---

### CA Object Schema

id, name, type (root/intermediate/issuing), keyId, subject (cn, o, ou, c, st, l), validity (notBefore, notAfter), constraints (pathLen, permittedDNS[], permittedIP[]), crlDistributionPoints[], ocspUrls[], issuingCaId, tenantId, state, fingerprint, pem, createdAt

---

### GET /svc/certs/certs/ca

Create: `name`, `type`, `keyId`, `subject`, `validityDays`, `pathLen`, `permittedDNS[]`, `permittedIP[]`, `crlUrls[]`, `ocspUrls[]`, `issuingCaId` (required for non-root)

`key_backend`: `software` (default), `keycore` (software key, keycore
co-signs) or `hsm`: the CA key is generated in the tenant's HSM through
keycore and certificates, CRLs and OCSP responses are signed there. `hsm`
takes ECDSA P-256/P-384 only (`400` otherwise) and needs HSM keys enabled for
the tenant. A CRL that can't be signed is an error
(`audit.cert.crl_generation_failed`), never an unsigned placeholder.

---

### GET/POST/DELETE /svc/certs/certs/profiles

Fields: name, type (server/client/code_signing/email/ca), keyUsage[], extendedKeyUsage[], validityDays, allowedAlgorithms[], requireCsr

---

### ACME / ARI

- `GET /svc/certs/acme/directory` — RFC 8555 directory
- `GET /svc/certs/acme/renewal-info/{id}` — RFC 9773 ARI: suggestedWindow (start, end), explanationURL, Retry-After header

---

### ACME STAR

- `GET /svc/certs/certs/star/summary` — totalSubscriptions, delegatedSubscriberCount, dueSoonCount, rolloutGroupRiskCounts
- `GET /svc/certs/certs/star/subscriptions` — List with next renewal, issuance counters
- `POST /svc/certs/certs/star/subscriptions` — Create subscription
- `POST /svc/certs/certs/star/subscriptions/{id}/refresh` — Force re-issuance
- `DELETE /svc/certs/certs/star/subscriptions/{id}` — Remove

---

### Renewal Intelligence

- `GET /svc/certs/certs/renewal-intelligence` — Coordinated windows, hotspots, missed-window counters
- `GET /svc/certs/certs/renewal-intelligence/{id}` — Per-certificate record
- `POST /svc/certs/certs/renewal-intelligence/refresh` — Recompute immediately

---

### EST / SCEP / CRL / OCSP

- `GET /svc/certs/est/.well-known/est/cacerts`, `.../csrattrs` — EST CA certificates and CSR attributes
- `POST /svc/certs/est/.well-known/est/simpleenroll` — EST enrollment (PKCS#10)
- `POST /svc/certs/est/.well-known/est/simplereenroll` — EST re-enrollment
- `POST /svc/certs/est/.well-known/est/serverkeygen` — EST server-side key generation
- `GET/POST /svc/certs/scep/pkiclient.exe` — SCEP GetCACert / PKIOperation
- `POST /svc/certs/cmpv2`, `POST /svc/certs/cmpv2/confirm` — CMPv2
- `GET /svc/certs/certs/crl` — CRL download
- `GET/POST /svc/certs/certs/ocsp` — OCSP responder (RFC 6960)

---

## Service 4: Audit (`/svc/audit/`)

Immutable, Merkle-chained audit log with SIEM export.

### AuditEvent Object

id, tenantId, timestamp, action, actorType (user/client/system), actorId, actorName, actorIp, resourceType, resourceId, resourceName, outcome (success/failure/denied), errorCode, requestId, merkleHash, prevHash, metadata

---

### GET /svc/audit/audit/events

Bearer, roles: auditor or admin.

Query: `action`, `actorId`, `resourceId`, `resourceType`, `outcome`, `startTime`, `endTime`, `pageSize`, `pageToken`, `action_prefix` (repeatable, up to 5, OR-ed; matched literally, so `_` and `%` are not wildcards; the HSM tab uses `action_prefix=audit.hsm.&action_prefix=audit.key.hsm_`)

```bash
curl -sk "https://localhost/svc/audit/audit/events?action=audit.key&outcome=failure&startTime=2025-03-01T00:00:00Z" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

Response:
```json
{
  "items": [{
    "id": "evt-01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "tenantId": "root",
    "timestamp": "2025-03-15T14:22:00Z",
    "action": "audit.key.decrypt",
    "actorType": "user",
    "actorId": "user-alice",
    "actorName": "Alice Smith",
    "actorIp": "10.0.1.42",
    "resourceType": "key",
    "resourceId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "resourceName": "customer-data-key",
    "outcome": "failure",
    "errorCode": "UNAUTHORIZED",
    "requestId": "req-01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "merkleHash": "sha256:aabbccddeeff...",
    "prevHash": "sha256:001122334455..."
  }],
  "nextPageToken": null,
  "totalCount": 1
}
```

---

### GET /svc/audit/audit/events/{id}

Single event.

---

### GET /svc/audit/audit/events/{id}/proof

Merkle inclusion proof. Response: `eventId`, `merkleRoot`, `proof[]`, `proofIndex`, `chainHeight`

---

## Service 5: Governance (`/svc/governance/`)

**Approver roles (1.28.0-beta).** When a request opens, its approvers are the
policy's `approver_users` plus every active user of the tenant who holds one of
its `approver_roles`, directly or through a group role binding, minus the
requester. A policy whose roles nobody holds opens no request.

Multi-party approvals, encrypted backup/restore, emergency bypass, system state.

**System administration** (`/governance/settings*`, `/governance/backups*`, `/governance/system/*`)
needs a verified root administrator: `tenant_id=root`, a token for the root
tenant, and role `admin`/`super-admin` or permission `*` (writes) /
`auth.tenant.*`, `auth.policy.*`. There is no unauthenticated access:
governance refuses to start without its token-verification key
(`GOVERNANCE_JWT_PUBLIC_KEY_PEM`/`_B64`, else the shared
`JWT_PUBLIC_KEY_PEM`/`_B64`). Platform services are admitted only on the
routes named for them: `kms-keycore` and `kms-policy` on
`GET /governance/system/state`, `kms-posture` on
`PUT /governance/system/posture-controls`.

| Refusal | Status | `error.code` | Audit `reason` |
|---|---|---|---|
| no token | 401 | `unauthorized` | `authentication_required` |
| token doesn't verify (any governance route) | 401 | `unauthorized` | `invalid_token` (`audit.governance.authentication_refused`) |
| no `tenant_id` | 400 | `bad_request` | `tenant_required` |
| `tenant_id` isn't the token's tenant | 403 | `forbidden` | `tenant_mismatch` |
| `tenant_id` isn't `root` | 403 | `forbidden` | `not_root_tenant` |
| token tenant isn't `root` | 403 | `forbidden` | `token_tenant_not_root` |
| not a root administrator or an allowed service | 403 | `forbidden` | `insufficient_privileges` |

System-admin refusals are audited as `audit.governance.system_admin_refused`.

---

### GET /svc/governance/governance/policies / POST /svc/governance/governance/policies

GovernancePolicy: name, triggerActions[], minApprovers, approverGroups[], timeoutHours, notificationChannels[], emergencyBypassAllowed

```bash
curl -sk -X POST https://localhost/svc/governance/governance/policies \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"Key Destruction Approval","triggerActions":["audit.key.destroy","audit.key.export"],"minApprovers":2,"approverGroups":["admin","security-team"],"timeoutHours":24,"emergencyBypassAllowed":false}'
```

Response:
```json
{
  "id": "policy-01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "name": "Key Destruction Approval",
  "triggerActions": ["audit.key.destroy", "audit.key.export"],
  "minApprovers": 2,
  "approverGroups": ["admin", "security-team"],
  "timeoutHours": 24,
  "emergencyBypassAllowed": false
}
```

---

### DELETE /svc/governance/governance/policies/{id}

---

### Backups: `/svc/governance/governance/backups`

Root administrators only (`tenant_id=root`, an admin token). Keys are
described in [SECURITY/BACKUP_KEYS.md](SECURITY/BACKUP_KEYS.md).

| Route | Purpose |
|---|---|
| `POST /governance/backups` | Capture and encrypt a backup. Body: `scope` (`system`/`tenant`), `target_tenant_id`, `bind_to_hsm` (default `true`; used when the tenant has an enabled HSM configuration). Optional `key_split`: `{"threshold": M, "guardians": ["name", ...]}` (2–16 unique guardians, 2 ≤ M ≤ N) splits a software-mode key into one Shamir share per guardian; refused with `bind_to_hsm` on an HSM-enabled tenant. Response 201: `job` and **`key_file`** (`file_name`, `content_type`, `content_base64`), or with `key_split` **`key_shares`** (one file per guardian, adding `guardian` and `share_index`). Returned only here: for a software-mode backup they are the only copies of the key. |
| `GET /governance/backups` | List jobs. `job.key_package` holds only `mode`, `key_retained`, coverage and the HSM binding summary, never key material. |
| `GET /governance/backups/{id}` | One job. |
| `GET /governance/backups/{id}/artifact` | The encrypted `.vbk` artifact (`artifact.content_base64`). |
| `GET /governance/backups/{id}/key` | The key file again, **HSM-bound backups only** (the key is wrapped by the tenant's key inside the HSM). A software-mode backup, or one whose stored key was removed, answers `410 backup_key_not_retained`. |
| `POST /governance/backups/restore` | Body: `artifact_file_name` (`.vbk`), `artifact_content_base64`, and either `key_file_name` (`.key.json`) with `key_content_base64`, or `key_shares` (`[{file_name, content_base64}]`, at least the split's threshold, all from the same backup; the rebuilt key must match the backup's key fingerprint). A single share given as `key_file_name` is refused. HSM-bound key files restore only when wrapped by the HSM (`key_wrap: "hsm_tenant_key"`), through the hsm-connector. |
| `POST /governance/backups/verify` | Root admin only. Same body as restore (a key file or `key_shares`). Opens the backup exactly as restore does (key resolution, guardian shares, AES-GCM under its AAD, snapshot parse) and returns `result`: `verified`, `scope`, `target_tenant_id`, `backup_captured_at`, `table_count`, `row_count_total`, `table_row_counts`, `key_source`, `share_guardians`, `elapsed_ms`, `data_modified: false`. Changes no data. It doesn't check that services can re-wrap retired-key rows; restore does that before applying. |
| `DELETE /governance/backups/{id}` | Delete a job and its artifact. |

HSM-bound backups need the tenant's HSM profile (HSM tab) and the
hsm-connector: the backup key is wrapped inside that HSM under the tenant's
key (`key_wrap: "hsm_tenant_key"`). `BACKUP_HSM_WRAP_SECRET` is no longer
used; packages from it (`key_derivation` v1/v2) are refused.

---

### GET /svc/governance/governance/system/state

Response: `status`, `services` (map of service → up/down), `pendingApprovals`, `lastBackupAt`, `clusterNodes`, `healthyNodes`, `checkedAt`

---

### GET /svc/governance/governance/system/fips-mode

Root-tenant administrators only (`tenant_id=root`). Response `status`:
- `desired`: `{mode, previous, reason, requested_by, requested_at}`, or `null` if never set
- `effective`: `on` | `only` | `off`
- `services`: `[{service, instance, mode, module_version, validated, started_at, updated_at}]`
- `converged`, `pending`

### GET /svc/governance/governance/system/fips-mode/impact?target=on|only|off

Root admin. Response `impact`:
- `from`, `to`, `downgrade`
- `stops` / `starts`: `[{service, feature, detail}]`
- `notes`
- `restarts`, `estimated_seconds`

### PUT /svc/governance/governance/system/fips-mode

Root admin with write rights. Body: `mode`, `confirm` (must repeat `mode`),
`reason`. Response: `impact`.

Services apply the change by a staggered graceful restart.

Audit:
- `audit.governance.fips_mode_changed` (critical for a downgrade)
- `audit.auth.sso_login_refused` (SAML/OIDC callback refused: signature, issuer, audience, recipient, request binding, replay, state), `audit.auth.client_activation_refused` (`reason`; missing or unapproved governance request, cross-tenant)
- `audit.governance.approval_refused` (`reason`: `authentication_required`, `tenant_required`, `tenant_mismatch`, `insufficient_privileges`, `not_a_user`, `no_user_email`, and `vote_refused` for a refused vote: not an approver, the requester, a wrong challenge code), `audit.governance.link_refused` (approval page with an invalid or used token)
- `audit.hyok.dke_refused` (Microsoft DKE: missing or invalid token, Entra issuer/audience/tenant/user not allowed, anonymous fetch on another host, non-current key version), `audit.hyok.admin_refused` (endpoint administration), `audit.hyok.approval_refused` (retry with an approval that is not approved, for another key/operation/payload, or already used), `audit.hyok.request_denied` with `reason: key_access_unavailable` (fail-closed)
- `audit.signing.sign_refused` (identity, policy or token refusal, with `code`), `audit.signing.request_refused` (`reason: tenant_mismatch`)
- `audit.confidential.key_released` (key sealed to the attested recipient key; `recipient_key_binding`, `key_version`, `seal_algorithm`), `audit.confidential.key_release_refused` (`reason`: no binding, verdict, keycore refusal), `audit.confidential.key_release` (kernel), `audit.key.attested_release` (keycore kernel, refusals included)
- `audit.ekm.request_refused` (EKM `401`/`403`: no verified tenant token, cross-tenant, BitLocker agent token missing or wrong role)
- then `audit.governance.fips_mode_applied` for each service start
- and `audit.governance.fips_mode_rollout_completed` when all match

See [SECURITY/FIPS.md](SECURITY/FIPS.md).

---

## Service 6: Compliance (`/svc/compliance/`)

Framework-oriented compliance scoring, control assessments, delta tracking.

---

### GET /svc/compliance/compliance/frameworks

Response: Framework[] — id, name, description, controlCount, lastAssessedAt, score, passCount, failCount

```bash
curl -sk https://localhost/svc/compliance/compliance/frameworks \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

Supported frameworks: FIPS-140-3, PCI-DSS-v4, SOC2, ISO-27001, NIST-CSF-2, HIPAA, GDPR

---

### GET /svc/compliance/compliance/frameworks/{id}/controls

Framework detail with controls: id, title, description, status (pass/fail/not_applicable), evidence, remediationSteps

---

### GET /svc/compliance/compliance/assessment/delta

Compares latest vs previous assessment.

Response: `addedFindings`, `resolvedFindings`, `recoveredDomains[]`, `regressedDomains[]`, `newFailingConnectors[]`

---

### GET /svc/compliance/compliance/assessment/history

Query: `frameworkId`, `startTime`, `endTime`, `granularity` (day/week/month). Response: trend data points.

---

### POST /svc/compliance/compliance/assessment/run

Body: `frameworkId`, `templateId`, `scope`, `recompute`. Response 202: assessment job.

---

## Service 7: Posture (`/svc/posture/`)

Risk findings, risk drivers, blast radius, remediation actions. Every route,
engine and [leak scanner](#leak-scanner-svcpostureleaks) alike, is on the
`pkg/route` kernel (1.32.0-beta): a verified bearer token is required, the
tenant is the token's (a `tenant_id` query, `X-Tenant-ID` header or body
`tenant_id` must match it), and each request is audited as
`audit.posture.<action>`. Refusals are audited under the same action with
`result: refused` and `reason` = `unauthenticated`, `permission_denied`,
`tenant_mismatch`, `tenant_conflict` or `tenant_wildcard` (`*` or `all`
named as the tenant; the cross-tenant aggregate is not served). Internal
callers present their `kms-*` service token; reporting reads findings and
actions as `kms-reporting`.

| Route | Permission | Audit |
|---|---|---|
| `GET /posture/health` | any verified identity | `audit.posture.health_read` |
| `GET /posture/dashboard` | `posture.read` | `audit.posture.dashboard_viewed` (`risk_24h`, `open_findings`, `critical_findings`, `risk_driver_count`, `blast_radius`, `action_count`) |
| `GET /posture/risk` | `posture.read` | `audit.posture.risk_read` (`assessed: false` when the tenant was never scanned) |
| `GET /posture/risk/history` | `posture.read` | `audit.posture.risk_history_read` |
| `POST /posture/scan` | `posture.write` | `audit.posture.scan_run` (`sync_audit`, `risk_24h`) |
| `POST /posture/events` | `posture.write` | `audit.posture.events_ingested` (`submitted`, `inserted`) |
| `POST /posture/events/batch` | `posture.write` | `audit.posture.events_ingested` (`batch: true`) |
| `POST /posture/ingest/audit` | `posture.write` | `audit.posture.audit_synced` (`inserted`) |
| `GET /posture/findings` | `posture.read` | `audit.posture.findings_listed` |
| `PUT /posture/findings/{id}/status` | `posture.write` | `audit.posture.finding_status_updated` (`status`) |
| `GET /posture/actions` | `posture.read` | `audit.posture.actions_listed` |
| `POST /posture/actions/{id}/execute` | `posture.action.execute` | `audit.posture.action_executed` (warning; `approval_request_id`) |

`kms.read` / `kms.write` grants don't reach posture (it is not in
`route.CoarseDomains`); `posture.*` or `*` does.

---

### GET /svc/posture/posture/findings

Query: `engine`, `status`, `severity`, `finding_type`, `from`, `to`,
`limit` (1–1000, default 200), `offset`.

Response: `items[]` (`id`, `engine`, `finding_type`, `title`, `description`,
`severity`, `risk_score`, `recommended_action`, `status`, `sla_due_at`,
`risk_drivers`, `blast_radius`, ...), `request_id`.

```bash
curl -sk "https://localhost/svc/posture/posture/findings?severity=critical&status=open" \
  -H "Authorization: Bearer $TOKEN"
```

---

### GET /svc/posture/posture/dashboard

Response: `risk`, `recent_findings[]`, `pending_actions[]`, `open_findings`,
`critical_findings`, `risk_drivers`, `remediation_cockpit[]`,
`blast_radius[]`, `scenario_simulator[]`, `validation_badges[]`,
`sla_overview`, `request_id`.

---

### GET /svc/posture/posture/actions

Query: `status`, `action_type`, `limit`, `offset`. Response: `items[]`
(`id`, `finding_id`, `action_type`, `approval_required`, `status`,
`executed_by`, `impact_estimate`, `rollback_hint`, `blast_radius`,
`priority`), `request_id`.

---

### POST /svc/posture/posture/actions/{id}/execute

Body (optional): `approval_request_id`. Publishes the runbook event
(`audit.posture.runbook.execute`) and marks the action `executed`, with
`executed_by` = the verified caller. An `actor` body field is rejected
(`400`) and `X-Actor-ID` is ignored. Response `200`: `ok`, `request_id`.
Errors: `404` unknown action, `409 approval_required` (approval-required
action without `approval_request_id`), `409 already_executed`,
`502 dispatch_failed` (event bus unavailable or publish failed; the action
is marked `failed`).

---

### POST /svc/posture/posture/scan

Query: `sync_audit` (bool). Scans the request tenant synchronously; the
engine scheduler scans every tenant in-process. Response `200`: `risk`
(snapshot), `tenant_id`, `request_id`.

---

### POST /svc/posture/posture/events, /events/batch

Body: one event, or `{items: [...]}`. Fields: `service` and `action`
(required), `result`, `severity`, `actor` (the actor the event describes;
data, not the caller), `ip`, `request_id`, `resource_id`, `error_code`,
`latency_ms`, `node_id`, `details`, `timestamp`, `tenant_id` (optional, must
be the request tenant). A batch item naming another tenant refuses the whole
batch. Response `200`: `inserted`, `request_id`.

---

## Service 8: Reporting (`/svc/reporting/`)

Alert rules, alert history, report generation, scheduled delivery.

Every route is on the `pkg/route` kernel (since 1.33.0-beta): a verified bearer
token is required, the tenant is the token's (a `tenant_id` in the query,
`X-Tenant-ID` or body must match it; `kms-*` service principals act for the
tenant they name), and each request emits `audit.reporting.<action>`, refusals
included. Permissions: `reporting.read` (lists, reads, stats, templates),
`reporting.write` (alert operations, rules, severity config, channels,
incidents, report generation and schedules), `reporting.delete` (rules and
report jobs). `POST /telemetry/errors` needs only a verified token. Identity is
the verified caller: acknowledging, resolving, requesting and deleting record
it, and the old `actor` / `requested_by` body fields are rejected (the `actor`
query parameter and `X-Actor-ID` header are ignored).

---

### GET /svc/reporting/alerts

Query: `ruleId`, `severity`, `acknowledged`, `startTime`, `endTime`. Response: paginated Alert[].

Alert: id, ruleId, severity, triggeredAt, summary, acknowledged, acknowledgedBy, acknowledgedAt

---

### GET /svc/reporting/alerts/{id} / PUT /svc/reporting/alerts/{id}/{op}

`op` is `acknowledge`, `resolve`, `false-positive` or `escalate`
(`audit.reporting.alert_updated`, `operation` in the details). Body: optional
`note` (resolve, false-positive) or `severity` (escalate). Response:
`{"status":"ok"}`.

---

### GET /svc/reporting/alerts/stats/mttd

Mean time to detect by severity. Response: `{"critical": 4.2, "high": 12.7, "medium": 48.3, "unit": "minutes"}`

---

### GET /svc/reporting/alerts/stats/mttr

Mean time to resolve by severity.

---

### GET /svc/reporting/alerts/stats/top-sources

Top actors, IPs, and services driving alerts. Response: `{"topActors": [...], "topIps": [...], "topServices": [...]}`

---

### GET /svc/reporting/reports/jobs/{id} / GET /svc/reporting/reports/jobs/{id}/download / DELETE /svc/reporting/reports/jobs/{id}

Delete records the verified caller as the actor (`audit.reporting.report_deleted`
with `template_id`, `format`, `requested_by`).

---

### POST /svc/reporting/reports/generate

Body: `template_id` (use `evidence_pack` for full audit package), `format`,
`filters`. The job is queued for the token's tenant with `requested_by` set to
the verified caller; `tenant_id` and `requested_by` are no longer read from the
body. Audited as `audit.reporting.report_requested` (a scheduled run publishes
the same subject with `trigger: scheduled`); an evidence pack also emits
`audit.reporting.evidence_pack_requested`.

---

## Service 9: Workload (`/svc/workload/`)

SPIFFE/SVID workload identity, token exchange, attestors, trust bundles. Enables workloads to authenticate without static API keys.

---

### GET /svc/workload/workload-identity/settings

Returns tenant workload identity configuration.

**Response 200**:
| Field | Type | Description |
|-------|------|-------------|
| enabled | boolean | Whether workload identity is active |
| trustDomain | string | SPIFFE trust domain (e.g. spiffe://acme.example) |
| defaultSvid | string | Default SVID type (x509/jwt) |
| tokenExchangeEnabled | boolean | Whether token exchange is active |
| attestationMode | string | required / optional |

```bash
curl -sk "https://localhost/svc/workload/workload-identity/settings?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### PUT /svc/workload/workload-identity/settings

Updates workload identity settings. Body: same fields as GET response (excluding read-only).

---

### POST /svc/workload/workload-identity/token/exchange

Exchanges an SVID or OIDC token for a KMS bearer token.

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| subjectToken | string | Yes | SVID or OIDC token to exchange |
| subjectTokenType | string | Yes | urn:ietf:params:oauth:token-type:jwt or x509 |
| audience | string | No | Intended audience |
| requestedScopes | string[] | No | Scopes for the resulting token |

**Response 200**: `accessToken`, `tokenType`, `expiresIn`, `scope`

```bash
curl -sk -X POST https://localhost/svc/workload/workload-identity/token/exchange \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"subjectToken":"eyJhbGc...","subjectTokenType":"urn:ietf:params:oauth:token-type:jwt","requestedScopes":["encrypt","decrypt"]}'
```

---

### GET /svc/workload/workload-identity/registrations / POST /svc/workload/workload-identity/registrations

Registration: spiffeId, attestorId, selectors[], ttlSeconds, allowedOperations[], parentId

---

### DELETE /svc/workload/workload-identity/registrations/{id}

---

### GET /svc/workload/workload-identity/graph

Returns the workload identity relationship graph: trust domain, issued SVIDs, registration counts, expiry states.

---

## Service 10: Confidential (`/svc/confidential/`)

TEE attestation verification (AWS Nitro COSE, Azure MAA and GCP Confidential Space JWTs) against tenant policy, and **attested key release** (1.30.0-beta). `POST /confidential/evaluate` returns a verdict only (`allow`, `review` or `deny`); nothing is released. `POST /confidential/release` releases a key: on an `allow` whose verified evidence commits to the caller's recipient public key, keycore returns the key's current material **sealed to that key** (RSA-OAEP-256 wrapping an AES-256-GCM key), so only the enclave holding the private key can open it. `generic` (self-asserted) evidence is never allowed. Before 1.26.0-beta the allow verdict was called `release`; stored records keep that value.

### POST /svc/confidential/confidential/release

Kernel route (`audit.confidential.key_release`, permission `confidential.release`). Body: the evaluate fields (`key_id`, `provider`, `attestation_document`, `audience`, …) plus `recipient_public_key`: base64 DER SubjectPublicKeyInfo of an RSA 2048–8192 key generated inside the enclave. The evidence must commit to it:

| Provider | Binding |
|---|---|
| `aws_nitro_enclaves`, `aws_nitro_tpm` | the attestation document's signed `public_key` equals the recipient key |
| `azure_secure_key_release`, `gcp_confidential_space` | the verified token's `nonce` (or `eat_nonce`) equals base64url(SHA-256(recipient DER)), unpadded |

The key must be active, allow export, and pass policy and FIPS checks; HSM-resident keys are refused. `dry_run` is refused. Response 200: `decision` with `released: true`, `recipient_key_binding` and `release` = `{key_id, version, algorithm, key_type, kcv, seal_algorithm: "RSA-OAEP-256+A256GCM", wrapped_key, nonce, ciphertext, aad}`. To open: RSA-OAEP-SHA-256 decrypt `wrapped_key` with label `vecta-kms recipient seal v1`, then AES-256-GCM decrypt `ciphertext` with `nonce` and `aad` (`vecta-attested-release|<tenant>|<key>|<version>|<release_id>`). 403 `release_refused` lists the reasons (no binding, verdict not allow, keycore refusal); every attempt is recorded in the release history with `released`.

### POST /svc/keycore/keys/{id}/attested-release

Internal: accepted only from the `kms-confidential` service identity (403 `caller_not_confidential_service` otherwise). Body: `tenant_id`, `recipient_public_key`, `release_id`, `attestation_document_hash`, `provider`. Audited as `audit.key.attested_release` (refusals: `caller_not_confidential_service`, `export_not_allowed`, `key_not_active`, `hsm_operation_unsupported`, policy and FIPS refusals).

---

### GET /svc/confidential/confidential/policy

Returns the tenant confidential compute policy.

**Response 200**:
| Field | Type | Description |
|-------|------|-------------|
| enabled | boolean | Whether attested release is active |
| allowedProviders | string[] | Accepted attestation providers (aws-nitro/azure-sev/intel-tdx/amd-sev/google-cce) |
| allowedMeasurements | object[] | Measurement constraints: provider, pcrValues or mrenclave, allowedImages |
| requireNonce | boolean | Whether to require fresh nonce in attestation |
| defaultAction | string | allow / review / deny for unmatched requests |
| auditAll | boolean | Whether to audit all evaluation results |

```bash
curl -sk "https://localhost/svc/confidential/confidential/policy?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### PUT /svc/confidential/confidential/policy

Updates the confidential compute policy. Body: same fields as GET response.

---

### POST /svc/confidential/confidential/evaluate

Evaluates attestation evidence against policy without releasing a key. Useful for testing policy rules.

**Request Body**: `attestationProvider`, `attestationDocument`, `nonce`

**Response 200**: `decision` (allow/review/deny), `matchedMeasurement`, `reasons[]`, `provider`

---

### GET /svc/confidential/confidential/releases

Lists past key release decisions.

**Query Parameters**: `decision`, `keyId`, `provider`, `startTime`, `endTime`, `pageSize`, `pageToken`

**Response 200**: Paginated release records — id, keyId, decision, provider, measurementVerified, actorSpiffeId, evaluatedAt, reasons[]

---

### GET /svc/confidential/confidential/releases/{id}

Single release record with full evaluation detail.

---

## Service 11: PQC (`/svc/pqc/`)

Post-quantum crypto policy, inventory classification, migration planning, and readiness scoring.

---

### GET /svc/pqc/pqc/policy

Returns the tenant PQC policy profile.

**Response 200**:
| Field | Type | Description |
|-------|------|-------------|
| mode | string | classical / hybrid / pqc-only |
| allowedClassicalAlgorithms | string[] | Classical algorithms still permitted |
| requiredHybridAlgorithms | string[] | Required hybrid combinations |
| preferredPqcAlgorithms | string[] | Preferred PQC algorithms |
| newKeysMustBePqc | boolean | Enforce PQC on all new keys |
| hybridSigningRequired | boolean | Require hybrid signing |
| migrationDeadline | string | Target migration completion date |
| warnOnClassical | boolean | Raise posture findings for classical usage |

```bash
curl -sk "https://localhost/svc/pqc/pqc/policy?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### PUT /svc/pqc/pqc/policy

Updates the PQC policy profile. Response: updated policy.

---

### GET /svc/pqc/pqc/inventory

Returns the PQC inventory — all crypto assets classified by algorithm family.

**Query Parameters**: `algorithmFamily`, `pqcReady`, `pageSize`, `pageToken`

**Response 200**: Paginated inventory items — id, resourceType (key/certificate/interface), resourceId, algorithm, algorithmFamily (classical/hybrid/pqc), pqcReady, strength, deprecated, tenantId

---

### GET /svc/pqc/pqc/readiness

Returns PQC readiness metrics for the tenant.

**Response 200**:
```json
{
  "totalAssets": 42,
  "pqcReadyCount": 8,
  "pqcReadinessPercent": 19,
  "hybridCount": 5,
  "classicalCount": 29,
  "deprecatedCount": 4,
  "algorithmDistribution": {"AES": 16, "RSA": 9, "ECDSA": 9, "ML-DSA": 8},
  "migrationDeadline": "2030-01-01",
  "daysToDeadline": 1752
}
```

---

### POST /svc/pqc/pqc/migration/plans/{id}/execute and /rollback

`execute` (body `actor`, `dry_run`) changes keys in keycore, step by step:

| Step | Outcome (step `status`) |
|---|---|
| key whose target is another algorithm (ML-DSA-65, ML-KEM-768, AES-256) | `successor_created`: a new keycore key of the target algorithm, id in `metadata.successor_key_id` (label `pqc_successor_of`); the old key is untouched until its consumers move |
| key already at the target algorithm | `rotated` |
| certificate, TLS endpoint, code finding | `manual_required` (the KMS can't change it) |
| keycore error | `failed` with `metadata.error` |

The plan ends `completed`, `manual_steps_remaining` or `failed`. A dry run
changes nothing and marks nothing done. `rollback` deactivates the successor
keys the plan created; rotations are reported as not reversible (plan status
`partially_rolled_back`). Events: `audit.pqc.migration_step_executed`,
`audit.pqc.migration_executed`, `audit.pqc.migration_failed`,
`audit.pqc.migration_rolled_back`.

---

### GET /svc/pqc/pqc/migration/plans

List or get migration plans.

---

### GET /svc/pqc/pqc/migration/report

Returns the current migration status report.

**Response 200**: `{"migratedCount": 8, "inProgressCount": 3, "remainingCount": 31, "lastUpdatedAt": "..."}`

---

## Service 12: Keyaccess (`/svc/keyaccess/`)

Key Access Justifications for external key governance (HYOK, EKM, cloud key paths).

---

### GET /svc/keyaccess/key-access/settings

Returns tenant justification enforcement settings.

**Response 200**:
| Field | Type | Description |
|-------|------|-------------|
| enabled | boolean | Whether KAJ enforcement is active |
| defaultAction | string | allow / deny / require_approval |
| requireCode | boolean | Caller must provide a reason code |
| requireText | boolean | Caller must provide justification text |
| auditUnjustified | boolean | Audit requests without justification |

```bash
curl -sk "https://localhost/svc/keyaccess/key-access/settings?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### PUT /svc/keyaccess/key-access/settings

Updates enforcement mode.

---

### GET /svc/keyaccess/key-access/summary

Dashboard/posture/compliance counters.

**Response 200**: `totalRequests`, `allowed`, `denied`, `approvalHeld`, `unjustifiedRequests`, `bypassSignals`

---

### GET /svc/keyaccess/key-access/codes / POST /svc/keyaccess/key-access/codes

Reason-code rules. Fields: name, code (string), allowedServices[], allowedOperations[], action (allow/deny/require_approval), enabled

```bash
curl -sk -X POST https://localhost/svc/keyaccess/key-access/codes \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"Customer Support Access","code":"customer-support","allowedServices":["crm","ticketing"],"allowedOperations":["decrypt"],"action":"allow"}'
```

---

### PUT/DELETE /svc/keyaccess/key-access/codes/{id}

---

### GET /svc/keyaccess/key-access/decisions

Lists evaluated justification decisions.

**Query Parameters**: `decision` (allow/deny/approval_held), `code`, `service`, `startTime`, `endTime`, `pageSize`, `pageToken`

**Response 200**: Paginated decision records — id, keyId, requestedOperation, code, text, decision, service, actorId, evaluatedAt, policyMatchId

---

## Service 13: Dataprotect (`/svc/dataprotect/`)

Tokenization, masking, field-level encryption, and secure vault search.

**FPE** (`POST /fpe/encrypt`, `POST /fpe/decrypt`; body `tenant_id`, `key_id`,
`algorithm`, `radix` 2–36, `tweak`, `plaintext`/`ciphertext`): `FF1` (NIST
SP 800-38G; the default). `FF3`/`FF3-1` → `400 fpe_algorithm_refused`
(audited `audit.dataprotect.fpe_refused`). `LEGACY-FF1` / `LEGACY-FF3-1` decrypt
pre-1.26.0 ciphertext for migration only (audited
`audit.dataprotect.fpe_legacy_decrypted`); encrypting with them is refused.
See docs/DATA_PROTECTION.md.

**Working keys** come from keycore `service-derive` (v2). Keys that predate
2026-09-25 start in state `legacy` (identifier-derived, v1) until migrated.
While a key is `migrating`, any operation accepts the header
`X-Vecta-KDF-Version: v1|v2` to read old data and write new data. Refusals
return 409:
- `kdf_migration_not_started`
- `legacy_kdf_retired` (audited as `audit.dataprotect.kdf_refused`)
- `key_material_unavailable` (FIPS strict mode)

See [SECURITY/DATAPROTECT_KEY_DERIVATION.md](SECURITY/DATAPROTECT_KEY_DERIVATION.md).

### GET /svc/dataprotect/kdf/keys

Each key's derivation state: `key_id`, `state` (`legacy`|`migrating`|`v2`),
`key_version` (pinned), `legacy_uses`, `last_legacy_use_at`,
`legacy_vault_tokens`.

### POST /svc/dataprotect/kdf/keys/{key_id}/start-migration

`legacy` → `migrating`; pins the current keycore version.
Audit: `audit.dataprotect.kdf_migration_started`.

### POST /svc/dataprotect/kdf/keys/{key_id}/reprotect-vault

Body: `limit` (default 500, max 5000). Re-protects stored vault tokens from v1
to v2; token strings don't change. Response: `converted`,
`irreversible_hashes_dropped`, `failed`, `failed_token_ids`, `remaining`.
Audit: `audit.dataprotect.kdf_vault_reprotected`.

### POST /svc/dataprotect/kdf/keys/{key_id}/complete

`migrating` → `v2`. Returns 409 `legacy_tokens_remaining` unless
`{"force": true}`. Audit: `audit.dataprotect.kdf_migration_completed`.

### POST /svc/dataprotect/kdf/keys/{key_id}/abort

`migrating` → `legacy`. Audit: `audit.dataprotect.kdf_migration_aborted`.

---

### POST /svc/dataprotect/tokenize

Tokenizes a single value.

**Request Body**: `value` (string), `schemeId` (string), `context` (object, optional)

**Response 200**: `token` (string), `schemeId`, `tokenId` (for vault lookup)

```bash
curl -sk -X POST https://localhost/svc/dataprotect/tokenize \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"value":"4111111111111111","schemeId":"pci-pan-scheme"}'
```

Response:
```json
{
  "token": "4111XXXXXXXX1111",
  "schemeId": "pci-pan-scheme",
  "tokenId": "tok-01ARZ3NDEKTSV4RRFFQ69G5FAV"
}
```

---

### POST /svc/dataprotect/tokenize/batch

Tokenizes multiple values in one request.

**Request Body**: `items[]` — each: value, schemeId, context. **Response 200**: `results[]` matching order.

---

### POST /svc/dataprotect/detokenize

Retrieves the original value for a token.

**Request Body**: `token` (string), `schemeId` (string), `justification` (string, if required)

**Response 200**: `value` (original string), `tokenId`, `schemeId`

---

### POST /svc/dataprotect/detokenize/batch

Detokenizes multiple tokens. Body: `items[]`. Response: `results[]`.

---

### POST /svc/dataprotect/mask

Applies a masking policy to a data object.

**Request Body**: `data` (object), `policyId` (string)

**Response 200**: `maskedData` (object with masked fields), `fieldsAffected[]`

---

## Service 14: Payment (`/svc/payment/`)

Payment crypto: TR-31 key blocks, PIN operations, ISO 20022 message signing.

---

### POST /svc/payment/payment/tr31/translate

Translates a TR-31 key block from one KBPK to another (for inter-system key exchange).

**Request Body**: `keyBlock`, `sourcekbpkId`, `targetKbpkId`, `targetKeyUsage`, `targetModeOfUse`

**Response 200**: `keyBlock` (new TR-31 block under target KBPK)

---

### POST /svc/payment/payment/pin/translate

Translates a PIN block from one format or key to another.

**Request Body**: `pinBlock` (hex), `sourceFormat`, `sourceKeyId`, `targetFormat`, `targetKeyId`, `pan`

**Response 200**: `pinBlock` (hex), `targetFormat`, `targetKeyId`

---

### POST /svc/payment/payment/iso20022/sign

Signs an ISO 20022 XML or JSON message.

**Request Body**: `message` (base64-encoded message), `messageType` (string, e.g. pacs.008), `signingKeyId`, `algorithm`, `includeCertificate` (boolean)

**Response 200**: `signedMessage` (base64), `signature` (base64), `signatureAlgorithm`, `keyId`, `certificateId`

---

### POST /svc/payment/payment/iso20022/verify

Verifies a signed ISO 20022 message.

**Request Body**: `signedMessage` (base64), `messageType`, `signingKeyId`, `signature`

**Response 200**: `valid` (boolean), `signerIdentity`, `keyId`, `verifiedAt`

---

## Service 15: Autokey (`/svc/autokey/`)

Policy-driven key provisioning: templates, handles, per-service defaults, governed self-service.

---

### GET /svc/autokey/autokey/settings

Returns tenant Autokey control settings.

**Response 200**:
| Field | Type | Description |
|-------|------|-------------|
| enabled | boolean | Whether Autokey is active |
| enforceMode | string | enforce / audit |
| requireApproval | boolean | Whether handle creation requires approval |
| requireJustification | boolean | Whether justification is required |
| templateOverrideRules | object | Rules for template selection |

```bash
curl -sk "https://localhost/svc/autokey/autokey/settings?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### PUT /svc/autokey/autokey/settings

Updates Autokey settings.

---

### GET /svc/autokey/autokey/summary

Dashboard/posture/compliance summary.

**Response 200**: `templateCount`, `servicePolicyCount`, `handleCount`, `pendingApprovals`, `provisionedLast24h`, `deniedCount`, `policyMatchedCount`, `policyMismatchedCount`

---

### GET /svc/autokey/autokey/templates / POST /svc/autokey/autokey/templates

Template: name, resourceType, keyNameTemplate, algorithm, purpose, labels (object), rotationPolicyTemplate, exportPolicyTemplate, approvalRequired

```bash
curl -sk -X POST https://localhost/svc/autokey/autokey/templates \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"s3-encryption","resourceType":"s3-bucket","keyNameTemplate":"s3-{resource}-dek","algorithm":"AES-256","purpose":"encrypt","labels":{"managed-by":"autokey"},"approvalRequired":false}'
```

---

### PUT/DELETE /svc/autokey/autokey/templates/{id}

---

### GET /svc/autokey/autokey/service-policies / POST /svc/autokey/autokey/service-policies

Service policy: service (identifier), defaultTemplateId, centralKeyPolicy (object), autoApprove (boolean)

---

### PUT/DELETE /svc/autokey/autokey/service-policies/{service}

---

### POST /svc/autokey/autokey/requests

Creates a key-handle provisioning request. The service either reuses an existing handle, creates a pending governance request, or provisions immediately.

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| resourceType | string | Yes | Resource type requesting the key |
| resourceId | string | Yes | Unique resource identifier |
| service | string | Yes | Service requesting the key |
| templateId | string | No | Override template (if allowed) |
| justification | string | Conditional | Required if enforced |
| labels | object | No | Additional labels |

**Response 201/202**: Handle request — id, status (fulfilled/pending_approval/reused), handleId, keyId (if fulfilled), approvalRequestId (if pending)

---

### GET /svc/autokey/autokey/requests / GET /svc/autokey/autokey/requests/{id}

List or get provisioning requests.

---

### GET /svc/autokey/autokey/handles

Lists the managed handle catalog.

**Response 200**: Handle[] — id, resourceType, resourceId, service, keyId, templateId, labels, state (active/revoked), provisionedAt

---

---

## Service 16: Cloud (`/svc/cloud/`)

BYOK (Bring Your Own Key) for AWS KMS, Azure Key Vault, GCP KMS. Sync, rotation, revocation.

---

## Service 17: HYOK (`/svc/hyok/`)

Hold Your Own Key proxy for Microsoft DKE, Salesforce, Google EKM, Alibaba,
ServiceNow and generic callers. Every route is in the route index below.

### Microsoft DKE (1.28.0-beta)

- `GET /svc/hyok/api/v1/keys/{id}` returns
  `{"key": {"kty": "RSA", "n", "e" (number), "alg", "kid"}, "cache": {"exp"}}`.
  `kid` is the key URL the caller used (including `/svc/hyok`) plus
  `/<current version>`. Without a token it is served only on the host an
  enabled DKE endpoint names in `key_uri_hostname`.
- `POST /svc/hyok/api/v1/keys/{id}/{version}/decrypt` takes
  `{"alg": "RSA-OAEP-256", "value": "<base64>"}` and returns
  `{"value": "<base64>"}`. A non-current `version` gets
  `409 key_version_not_current`. The old `POST /api/v1/keys/{id}/decrypt` is
  removed.
- **Entra ID tokens**: verified with `pkg/oidc` against
  `login.microsoftonline.com/{tid}/discovery/v2.0/keys`. The issuer must be in
  the endpoint's `valid_issuers`, the audience in `jwt_audiences` (required),
  `tid` must match the issuer, and the user must be in `authorized_emails`
  (`upn`/`preferred_username`; never the mutable `email` claim) or hold one of `authorized_roles`
  (`roles` claim). At least one of the two lists is required. The tenant is
  `tenant_id` when given, else the only tenant whose DKE endpoint trusts the
  issuer. For Entra callers `authorized_tenants` lists Entra tenant IDs.
- Endpoint metadata (`PUT /svc/hyok/hyok/v1/endpoints/dke`, `metadata_json`):
  `valid_issuers`, `jwt_audiences`, `authorized_emails`, `authorized_roles`,
  `authorized_tenants`, `key_uri_hostname`, `allowed_algorithms`.
- Refusals: `audit.hyok.dke_refused` (`reason`, `result: refused`, `status`).

---

## Service 18: EKM (`/svc/ekm/`)

External Key Manager for database TDE (Transparent Data Encryption), BitLocker,
Google CSE (KACLS), Azure EKM and the Java SDK.

- **Google CSE configs** (`/svc/ekm/ekm/google-cse/configs`) carry
  `authentication_client_ids` (1.28.0-beta): required on create, settable with
  `PUT .../configs/{id}`. The KACLS authentication token's `aud` must be one
  of them. A config without any refuses every KACLS call. Creating a CSE key
  needs the config's `kacls_endpoint`.
- **Java SDK**: `GET /svc/ekm/ekm/sdk/download?provider=jca` returns the
  provider source from `services/jca-provider` (`Cipher.VectaKeyWrap` over
  `POST /svc/ekm/ekm/tde/keys/{id}/wrap` and `.../unwrap`).

---

## Service 19: KMIP (`/svc/kmip/`)

KMIP protocol management for KMIP-compliant clients and legacy HSM integrations.

---

### GET /svc/kmip/kmip/profiles / POST /svc/kmip/kmip/profiles

KMIP profile: name, kmipVersion (1.1/1.2/2.0), allowedOperations[], requireMtls, allowedAlgorithms[], description

---

### DELETE /svc/kmip/kmip/profiles/{id}

---

### GET /svc/kmip/kmip/clients / POST /svc/kmip/kmip/clients

KMIP client: name, profileId, certificate (PEM), allowedIps[], enabled

```bash
curl -sk -X POST https://localhost/svc/kmip/kmip/clients \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"NetApp StorageGrid","profileId":"kmip-profile-01","certificate":"-----BEGIN CERTIFICATE-----\n...","allowedIps":["10.0.10.0/24"]}'
```

---

### GET/DELETE /svc/kmip/kmip/clients/{id}

---

## Service 20: Signing (`/svc/signing/`)

Artifact signing, container image signing, Git artifact signing, keyless provenance.

---

### GET /svc/signing/signing/settings

Tenant signing policy and allowed identity modes.

**Response 200**: `enabled`, `allowedIdentityModes[]` (key/workload/oidc), `requireTransparencyLog`, `defaultProfileId`, `verificationPolicyId`

---

### PUT /svc/signing/signing/settings

Updates tenant signing defaults and transparency requirements.

---

### GET /svc/signing/signing/summary

Dashboard summary: `profileCount`, `signedLast24h`, `transparencyLoggedCount`, `workloadSigningCount`, `oidcSigningCount`, `verificationFailures`

---

### GET /svc/signing/signing/profiles / POST /svc/signing/signing/profiles

Profile: name, keyId, identityMode (key/workload/oidc), allowedSpiffeIds[], allowedOidcIssuers[], requireTransparency, format (cosign/sigstore/pkcs7/raw)

```bash
curl -sk -X POST https://localhost/svc/signing/signing/profiles \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"Release Pipeline","keyId":"3fa85f64-5717-4562-b3fc-2c963f66afa6","identityMode":"workload","allowedSpiffeIds":["spiffe://acme.example/pipeline"],"requireTransparency":true}'
```

---

### PUT/DELETE /svc/signing/signing/profiles/{id}

---

### POST /svc/signing/signing/blob

Signs a generic blob artifact.

**Request Body**: `artifact` (base64), `profileId`, `artifactType` (string), `annotations` (object), `mediaType` (string)

**Response 200**: `recordId`, `signature` (base64), `publicKeyPem`, `transparencyLogEntry` (object if logged), `signedAt`

---

### POST /svc/signing/signing/git

Signs Git-oriented artifact metadata.

**Request Body**: `profileId`, `commitSha` (string), `repoUrl`, `ref`, `annotations`

**Response 200**: `recordId`, `signature`, `signedPayload`, `transparencyLogEntry`, `signedAt`

---

### POST /svc/signing/signing/verify

Verifies a signing record and, optionally, that a presented artifact is the one that was signed.

**Request Body**: `tenant_id`, `record_id` (required); `payload` (base64 artifact bytes) or `digest_sha256` (hex), both optional.

**Response 200**:
- `valid`: `signature_valid`, and when an artifact was presented, `digest_match`.
- `signature_valid`: keycore verified the signature over the exact signed envelope, and the envelope agrees with the record's digest column.
- `digest_checked`, `digest_match`: whether an artifact was presented and whether it matches.
- `record_id`, `transparency_hash`, `transparency_entry_id`, `verified_at`.

The audit event `audit.signing.artifact_verified` carries `verification_status`: `verified`, `signature_invalid` or `artifact_mismatch`.

---

### GET /svc/signing/signing/records

Lists signing records.

**Query Parameters**: `profileId`, `artifactType`, `startTime`, `endTime`, `pageSize`, `pageToken`

**Response 200**: Paginated record[] — id, profileId, artifactType, signerIdentity, transparencyLogged, signedAt

---

## Service 22: Cluster (`/svc/cluster/`)

Cluster node management, HSM registration, replication, leader election.

---

### GET /svc/cluster/cluster/nodes / POST /svc/cluster/cluster/nodes

Node: id, address, role (leader/follower), state (healthy/degraded/offline), version, joinedAt

---

### GET /svc/cluster/hsm/{id}

---

### Cluster authentication

Every cluster route requires a root administrator or an internal service JWT,
except:
- `GET /healthz`;
- `POST /cluster/join/exchange` (authenticated by the one-time join token);
- `POST /cluster/sync/events` (HMAC signature).

### POST /svc/cluster/cluster/join/request (on the primary)

Body: `target_node_id`, `target_node_name`, `profile_id`, `expires_minutes`.
Response:
- `join`: the token record with `issued_secret`;
- `bundle`: `vecta-join-v1:…`, what you paste on the new node. It's present
  only when `CLUSTER_ADVERTISE_URL` is set.

### POST /svc/cluster/cluster/join/connect (on the joining node)

Body: `join_bundle`, optional `node_name` and `endpoint`, and
`confirm_replace: true` (required).

This exchanges the bundle with the primary, installs the cluster master key
(keycore restarts on it) and subscribes to the assigned components. Response
`result`: `{primary_node_id, components, subscribed, status}`.

Audit: `audit.cluster.joined_cluster` here, and
`audit.cluster.member_joined` on the primary.

### POST /cluster/join/exchange (node-to-node, primary)

Called by a joining node's cluster-manager over pinned TLS.

Body: `token_id`, `join_secret`, `node_id`, `node_name`, `endpoint`,
`keycore_join_key` and `cluster_manager_join_key` (ML-KEM-768 encapsulation
keys). Response `result`: `{primary_node_id, components, context, sealed_mek,
mek_fingerprint, sealed_replication}`.

### POST /svc/keycore/cluster/mek/join-key, /export, /import

The cluster-manager service identity only (anything else gets 403
`service_identity_required`). These are the keycore side of the master-key
transfer:
- `join-key`: creates a one-time ML-KEM join key, valid 10 minutes;
- `export`: seals this node's master key to a join key, bound to `context`;
- `import`: opens it, checks `mek_fingerprint`, requires `confirm_replace`
  if the node already holds keys, stores it and restarts keycore.

Audit events are `audit.key.cluster_join_key_created`,
`cluster_mek_exported` and `cluster_mek_imported`; the last two are critical.

### GET /svc/cluster/cluster/replication/status

This node's real Postgres logical replication state:
- `wal_level`
- `publications`: `[{component, publication, tables}]`
- `subscriptions`: `[{subscription, component, enabled, worker_running, lag_seconds, ready, tables: [{table, state}]}]`
- `forwards_to`: on a member, the primary it forwards lifecycle writes to
  (absent on a standalone node or the primary)
- `error`

`GET /cluster/overview` includes the same object under `replication`. Its
`selective_component_sync.note` is computed from it. See
[CLUSTERING.md](CLUSTERING.md).

---

### Write forwarding on a member (every service)

On a cluster member, every service's HTTP server (`pkg/config.NewHTTPServer`)
routes each request with `pkg/clusterroute.Decide`:

- **Runs locally:** reads (GET, HEAD, OPTIONS); crypto operations (keycore
  encrypt, decrypt, sign, verify, mac, wrap, derive, service-derive, attest,
  hash, random; dataprotect fpe, mask, redact, `/app/*`); logins and token
  issuance (auth); this node's system settings (governance); audit publish,
  search and Merkle operations; the cluster services themselves.
- **Forwarded to the primary:** every other write. The response comes back
  unchanged, with the header `X-Vecta-Forwarded-To: <primary node id>`.
- **Refused** with `409 primary_write_required`: a write to a service the
  primary can't be reached for (no internal route).

Other member-side errors:

| Status | Code | Meaning |
|---|---|---|
| 401 | `unauthorized` | the caller's token didn't verify on the member; nothing was sent |
| 502 | `primary_unreachable` | the primary is down or its TLS certificate doesn't match the pinned fingerprint. The write was not made anywhere |

Clients can't set the cluster headers: the member strips any
`X-Vecta-Cluster-*`, `X-Vecta-Forward-Claims` and `Authorization` header before
forwarding.

Audit (member): `audit.<service>.cluster_write_forwarded` and
`audit.<service>.cluster_write_refused`.

## Service 25: Secrets (`/svc/secrets/`)

Hierarchical secret vault with versioning, rollback, and path-based policy.

### Master key and exposure register

The service's master key comes from keycore (`pkg/mek`); there's nothing to
configure. See docs/SECURITY/SERVICE_MASTER_KEYS.md.

| Route | Permission | Meaning |
|---|---|---|
| `GET /mek/exposure?open=false` | `secrets.read` | the tenant's exposure register: secrets stored under a public key before 1.2.0-beta, open until rotated or deleted |
| `POST /mek/exposure/{item_type}/{item_id}/acknowledge` | `secrets.exposure.acknowledge` | close an entry with `{"reason": "..."}` (at least 10 characters) |
| `POST /mek/rewrap-legacy` | `kms-governance` identity only | re-wrap wrapped DEKs from backup contents (`{"entries":[{"iv","dek","table","tenant_id","item_id"}],"restoring":bool}`) |

The same three routes exist on certs (`cert.*`), cloud (`cloud.*`) and ekm
(`ekm.*`).

### Authorization and audit (pkg/route kernel)

Every route requires a verified token. The tenant comes from `tenant_id`
(query or JSON body) or `X-Tenant-ID`, and for Vault routes also from
`X-Vault-Namespace` / `X-Namespace`. When none is given, the token's tenant is
used. A tenant other than the token's is refused with `403 tenant_mismatch`,
and disagreeing sources with `403 tenant_conflict`. Each request emits one
`audit.secrets.<action>` event with `result` `success`, `failure` or
`refused` (with `reason`).

| Route | Permission | Audit action |
|---|---|---|
| `POST /secrets` | `secrets.write` | `created` |
| `GET /secrets` | `secrets.read` | `listed` |
| `GET /secrets/{id}` | `secrets.read` | `read` |
| `GET /secrets/{id}/value` | `secrets.value.read` | `value_read` (warning) |
| `PUT /secrets/{id}` | `secrets.write` | `updated` |
| `DELETE /secrets/{id}` | `secrets.delete` | `deleted` (warning) |
| `POST /secrets/generate/ssh_key`, `/generate/keypair` | `secrets.write` | `generated` |
| `GET /secrets/{id}/versions` | `secrets.read` | `versions_listed` |
| `GET /secrets/{id}/audit` | `secrets.read` | `audit_log_read` |
| `POST /secrets/{id}/rotate` | `secrets.write` | `rotated` |
| `GET /secrets/stats` | `secrets.read` | `stats_read` |
| `GET /v1/sys/health`, `/v1/sys/seal-status` | any identity | `vault_health_read`, `vault_seal_status_read`
- `audit.<svc>.dev_mek_rewrapped`, `dev_mek_rewrap_refused`, `mek_rewrapped`, `mek_rewrap_refused`, `mek_unreadable`, `mek_check_refused`, `mek_exposure_remediated`, `mek_exposure_listed`, `mek_exposure_acknowledged`, `mek_backup_rewrap` for `<svc>` in secrets, cert, cloud, ekm: service master keys (docs/SECURITY/SERVICE_MASTER_KEYS.md)
- `audit.key.system_key_ensure`, `audit.key.system_key_created`, `audit.key.system_key_change_refused`: keycore system keys
- `audit.key.access_refused` (every key-access denial, `result: refused` with `reason`), `audit.key.actor_headers_ignored` (identity headers were sent and ignored): keycore key access
- `audit.governance.backup_create_refused` (`reason`, `result: refused`), `audit.governance.backup_key_downloaded`, `audit.governance.backup_key_download_refused` (`reason: key_not_retained`): governance backup keys (docs/SECURITY/BACKUP_KEYS.md) |
| `POST /v1/auth/token/lookup-self` | any identity | `vault_token_lookup` |
| `GET /v1/{mount}/data/{path}`, `GET /v1/{mount}/{path}` | `secrets.value.read` | `vault_kv_read` |
| `POST /v1/{mount}/data/{path}`, `POST /v1/{mount}/{path}` | `secrets.write` | `vault_kv_written` (`created` in details) |
| `DELETE /v1/{mount}/data/{path}`, `DELETE /v1/{mount}/{path}` | `secrets.delete` | `vault_kv_deleted` |
| `GET /v1/{mount}/metadata/{path}` | `secrets.read` | `vault_metadata_read` |

`*` grants all of these. `secrets` is in `route.CoarseDomains`, so `kms.read`
grants the `.read` permissions and `kms.write` grants `.write` and `.delete`.
A Vault KV v1 write body is the secret's data, so a `tenant_id` key inside it
is stored, not treated as a tenant. `created_by` / `updated_by` are
set to the verified caller.

---

### GET /svc/secrets/secrets

Lists secrets at the root path.

**Query Parameters**: `path` (prefix), `pageSize`, `pageToken`

**Response 200**: Paginated path entries — path, version, updatedAt, createdBy (no secret values)

---

### POST /svc/secrets/secrets

Creates or updates a secret at a path.

**Request Body**: `path` (string), `value` (object or string), `metadata` (object), `ttl` (int seconds, optional)

**Response 201**: `{"path": "...", "version": 1, "createdAt": "..."}`

---

### GET /svc/secrets/secrets/{path}

Retrieves the current version of a secret.

**Response 200**: `{"path": "...", "value": {...}, "version": 3, "metadata": {...}, "createdAt": "...", "updatedAt": "..."}`

Response:
```json
{
  "path": "services/database/credentials",
  "value": {"username": "app_user", "password": "retrieved_from_vault"},
  "version": 3,
  "metadata": {"environment": "production"},
  "createdAt": "2025-01-01T00:00:00Z",
  "updatedAt": "2025-03-15T14:22:00Z"
}
```

---

### PUT /svc/secrets/secrets/{path}

Full replacement of a secret value. Creates new version.

**Request Body**: `value` (object or string), `metadata` (optional), `ttl` (optional)

**Response 200**: Updated secret metadata (version incremented, no value returned)

---

### DELETE /svc/secrets/secrets/{path}

Soft-deletes the current version. All versions remain accessible.

**Response**: 204 No Content

---

### GET /svc/secrets/secrets/{path}/versions

Lists all versions of a secret (no values).

**Response 200**: `Version[]` — version, state (current/deleted/destroyed), createdAt, deletedAt

---

### GET /svc/secrets/secrets/policy/{path}

Returns the access policy for a path (and all sub-paths).

**Response 200**: Policy object with `grants[]` — subject, subjectType, operations[], pathPattern

---

## Discovery (`/svc/discovery/`) — scan sources

`POST /discovery/scan` (body `tenant_id`, `scan_types`: `network`, `cloud`,
`certs`, `code`) records only what each source observed:

- `network`: a TLS handshake with each endpoint in `DISCOVERY_TLS_ENDPOINTS`
  (operator config, no default). It records the negotiated key exchange,
  protocol, cipher, leaf key and `chain_trusted`.
- `cloud`: each registered account's live KMS inventory via the cloud
  service (`CLOUD_URL`, default `https://cloud:8080`).
- `certs`: the certs service's certificates.
- `code`: the tree mounted at `WORKSPACE_ROOT` (required). It records
  file:line and `fingerprint_sha256_prefix`, never the secret.

An unconfigured or failed source is recorded in `stats.errors`. The scan
status is then `completed_with_errors`, or `failed` if every source failed.

---

## Service 26: SBOM (`/svc/sbom/`)

Software BOM, Cryptographic BOM, vulnerability correlation, offline advisory management.

Every route is on the `pkg/route` kernel (since 1.33.0-beta; before it sbom
verified no token at all): a verified bearer token is required and each request
emits `audit.sbom.<action>`, refusals included. Permissions: `sbom.read`,
`sbom.write` (generate, save advisory), `sbom.delete` (delete advisory). CBOM
routes are scoped to the token's tenant (`kms-*` service principals act for the
tenant they name). The platform SBOM and its advisories are shared by every
tenant, so `POST /sbom/generate`, `POST /sbom/advisories` and
`DELETE /sbom/advisories/{id}` also require the platform tenant (or a
tenant-less root token or service principal); anyone else is refused with
reason `platform_tenant_required`.

---

### GET /svc/sbom/sbom/latest

Returns the latest SBOM snapshot.

**Response 200**: `snapshotId`, `createdAt`, `componentCount`, `components[]` (name, version, ecosystem, purl, license)

---

### POST /svc/sbom/sbom/generate

Generates a fresh software BOM snapshot.

**Request Body**: `trigger` (manual/scheduled), `format` (cyclonedx/spdx, optional)

**Response 202**: `{"status": "accepted", "snapshot": {"id": "sbom_20260311_001", "createdAt": "2026-03-11T09:45:00Z"}}`

```bash
curl -sk -X POST https://localhost/svc/sbom/sbom/generate \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"trigger":"manual"}'
```

---

### GET /svc/sbom/sbom/vulnerabilities

Returns merged vulnerability findings from OSV online, Trivy, and manual advisories. If any enabled source fails, the response is `503 vulnerability_source_unavailable` (not assessed): there is no built-in fallback list, and partial results are not returned as complete. `OSV_ENABLED=false` disables OSV for air-gapped installs; `TRIVY_ENABLED=false` disables Trivy.

**Response 200**: `items[]` — id (CVE), source (OSV/Trivy/manual), severity, component, installedVersion, fixedVersion, summary, reference

```json
{
  "items": [
    {
      "id": "CVE-2026-1000",
      "source": "OSV",
      "severity": "high",
      "component": "golang.org/x/net",
      "installedVersion": "v0.20.0",
      "fixedVersion": "v0.35.0",
      "summary": "HTTP issue in golang.org/x/net",
      "reference": "https://osv.dev/vulnerability/GO-2026-0001"
    }
  ]
}
```

---

### GET /svc/sbom/sbom/vulnerabilities

Vulnerabilities matched to the components of the latest snapshot.

---

### GET /svc/sbom/sbom/advisories

Lists manually managed offline advisories for air-gapped environments.

---

### POST /svc/sbom/sbom/advisories

Creates or updates a manual offline advisory.

**Request Body**: `id` (CVE ID), `component`, `ecosystem`, `introducedVersion`, `fixedVersion`, `severity`, `summary`, `reference`

```bash
curl -sk -X POST https://localhost/svc/sbom/sbom/advisories \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"id":"CVE-2026-5000","component":"example/module","ecosystem":"go","introducedVersion":"v1.0.0","fixedVersion":"v1.3.0","severity":"critical","summary":"Offline advisory for air-gapped deployment","reference":"https://example.test/CVE-2026-5000"}'
```

Response:
```json
{
  "item": {
    "id": "CVE-2026-5000",
    "component": "example/module",
    "ecosystem": "go",
    "fixedVersion": "v1.3.0",
    "severity": "critical",
    "summary": "Offline advisory for air-gapped deployment"
  }
}
```

---

### DELETE /svc/sbom/sbom/advisories/{id}

Removes a manual advisory.

```bash
curl -sk -X DELETE "https://localhost/svc/sbom/sbom/advisories/CVE-2026-5000?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### POST /svc/sbom/cbom/generate

Generates a Cryptographic BOM snapshot for the token's tenant (a named
`tenant_id` must match it).

**Request Body**: `trigger` (optional)

**Response 202**: `{"status": "accepted", "snapshot": {"id": "cbom_20260311_001", "createdAt": "..."}}`

---

### GET /svc/sbom/cbom/pqc-readiness

Returns PQC readiness metrics from the latest CBOM.

**Response 200**:
```json
{
  "pqcReadiness": {
    "totalAssets": 42,
    "pqcReadyCount": 8,
    "pqcReadinessPercent": 19,
    "deprecatedCount": 4,
    "algorithmDistribution": {"AES": 16, "RSA": 9, "ECDSA": 9, "ML-DSA": 8},
    "strengthHistogram": {"128": 8, "256": 34}
  }
}
```

---

## AI gateway health

`GET /ai-gateway/v1/health` returns the checks it ran: `database` (a
round trip), and `dlp` / `guardrails` (the detectors run on a known input).
It answers `503` with `status: degraded` when any check fails.

---

## Authentication and capability changes in 1.27.0-beta

Behaviour that changed in 1.27.0-beta (CHANGELOG 1.27.0-beta,
[REAL_CAPABILITY.md](SECURITY/REAL_CAPABILITY.md)). Every refusal below is
audited with `result: refused` and a `reason`.

**Auth — SSO.** `GET /auth/sso/{provider}/login` returns an IdP redirect whose
state is one-time and bound to the request: SAML sends `RelayState` bound to
the AuthnRequest ID, OIDC sends `state` bound to a `nonce`.
`POST /auth/sso/saml/callback` accepts only a SAML Response whose Assertion (or
Response) XML signature verifies against the configured `idp_certificate`
(RSA/ECDSA with SHA-2; SHA-1 refused), from `idp_entity_id`, for audience
`sp_entity_id` and recipient `acs_url`, answering the outstanding request,
within its validity window, and not seen before; encrypted assertions are
refused. The OIDC callback verifies the ID token against the issuer's JWKS
(RS/PS/ES algorithms only) with `iss`, `aud` = `client_id`, `exp`, `nonce` and
`azp`. SAML config: `idp_entity_id` and `idp_certificate` are required;
`idp_metadata_url`, `sign_requests` and `sp_private_key` were never used and
are gone. OIDC config: `response_type` is gone (code flow only).
Refusals: `audit.auth.sso_login_refused`.

**Auth — client activation.** `POST /auth/register/{id}/activate` with
`governance_enabled`, or for a tenant whose platform policy covers
`client.activate`, needs `approval_id` naming an approved governance request
for action `client.activate`, target `client`/`{id}`; a body `tenant_id` other
than the caller's needs cross-tenant permission. Refusals:
`audit.auth.client_activation_refused`.

**Governance — approvals.** Every `/governance/policies`, `/governance/requests*`,
`/governance/key-approval*` route and dashboard vote needs a verified bearer
token for the tenant (a platform service principal may act for any tenant);
policy changes need a tenant administrator. A JSON vote without `token` is cast
as the authenticated user, whose email is read from their account; body
`approver_email`/`approver_id` are ignored. Only emails the request issued
approve tokens to may vote, the requester may not vote, and a challenge code
must belong to the voter. A user-created request cannot set its requester,
`target_details.approver_emails` or a callback. `GET /governance/approve/{id}`
needs a live token for that request. `GET /governance/key-approval/{id}/status`
also returns `action`, `target_type`, `target_id`, `operation` and
`payload_hash`. Removed: `/governance/system/fde/*` (status, integrity-check,
rotate-key, test-recovery, recovery-shares) and
`POST /governance/system/network/apply`. `GET/PUT /governance/system/state`
no longer carries network, license, backup-schedule, TLS-mode/PEM, HSM/cluster
labels or QRNG fields; `fips_tls_profile` (`tls13_minimum`), `fips_rng_mode`
(`ctr_drbg` in FIPS mode, else `os_csprng`) and `fips_entropy_source`
(`os-csprng`) report the runtime, and `fips_entropy_bits_per_byte` is gone.
Refusals: `audit.governance.approval_refused`, `audit.governance.link_refused`.

**HYOK.** Crypto routes accept only a verified bearer JWT (no client
certificate or `X-Client-*` header identity). `auth_mode` is `jwt`; `mtls` is
refused (`400 auth_mode_unavailable`), stored `mtls_or_jwt` reads as `jwt`.
A `202 pending_approval` response carries `approval_request_id`; retrying the
same request body with `"approval_request_id"` runs it once the approval is
approved for that key, operation and payload (`403 approval_invalid`
otherwise; `audit.hyok.approval_refused`). With `HYOK_POLICY_FAIL_CLOSED`
(default true) an unreachable key-access service refuses (`424
key_access_unavailable`). `approver_emails` is no longer accepted.
Endpoint administration (`/hyok/v1/endpoints*`, `/hyok/v1/requests`,
`/hyok/v1/health`) needs a verified token; changes need a tenant
administrator (`audit.hyok.admin_refused`).

**Signing.** `POST /signing/blob|git` and `/signing/verify` enforce the body
`tenant_id` against the token. OIDC mode takes `oidc_token` (the signer's ID
token, audience `SIGNING_OIDC_AUDIENCE`, default `vecta-kms-signing`); its
issuer must be listed exactly in the profile and its `sub` (and `repository`
claim, when present) are what is checked and signed. Workload mode signs as
the caller token's `workload_identity`. Body `oidc_issuer`, `oidc_subject`
and `workload_identity` are ignored. `require_transparency` /
`transparency_required` are gone (every record is in the tenant signing log).
Refusals: `audit.signing.sign_refused`, `audit.signing.request_refused`.

**Reporting.** Notification channels are `screen` only; alerts record
`channels_sent: ["screen"]`. Scheduled reports take no `recipients`.

**Secrets.** Export format `ppk` is refused; `armored` returns a stored armored
key unchanged and armors binary packets with RFC 4880 armor. The
Vault-compatible `sys/health` and `sys/seal-status` no longer report Shamir,
replication, cluster or build fields.

**KMIP.** Query reports only the routed operations (Create, Register, Get,
GetAttributes, Locate, Activate, Revoke, Destroy, ReKey, Encrypt, Decrypt,
Sign, SignatureVerify, Query, DiscoverVersions).

**EKM.** Every tenant route needs a verified bearer token for the tenant; the
TLS peer is never an identity. BitLocker agent routes need a bitlocker-role
JWT. Deploy-package scripts read `EKM_TOKEN` from the environment.
`GET /ekm/sdk/overview` lists the Java JCA provider only (no usage figures);
`/ekm/sdk/download?provider=pkcs11` is refused. The TDE setup guide describes
KMIP for MySQL (`keyring_okv`), pg_tde and Db2 and states SQL Server, Oracle
and MariaDB are not supported. KACLS (`/ekm/kacls/*`) verifies the Google CSE
authorization token (issuer `gsuitecse-tokenissuer-*@system.gserviceaccount.com`,
audience `cse-authorization`), requires its email to match the authentication
token, requires `exp` and an allowed `hd` on the authentication token, and
uses only the key the authorization token names.

## Appendix: Audit Action Subject Reference

Audit events use dot-separated action subjects. Common prefixes:

| Prefix | Domain |
|--------|--------|
| audit.auth.* | Authentication and identity |
| audit.key.* | Key lifecycle and crypto operations |
| audit.cert.* | Certificate and CA operations |
| audit.governance.* | Approvals, encrypted backup/restore, platform FIPS mode |
| audit.backup.* | Backup scheduler (preview): policy changes and refused runs/restores |
| audit.cluster.* | Cluster join, replication publications, write forwarding |
| audit.kmip.* | KMIP sessions, operations and denials |
| audit.dataprotect.* | Data protection operations and key-derivation migration |
| audit.compliance.* | Compliance assessments |
| audit.posture.* | Posture engine (reads, scans, event ingest, action execution) and leak scanner |
| audit.scim.* | SCIM provisioning |
| audit.mpc.* | MPC ceremonies |
| audit.signing.* | Artifact signing |
| audit.workload.* | Workload identity |
| audit.confidential.* | Attestation verdicts and attested key release |
| audit.payment.* | Payment crypto operations |
| audit.secrets.* | Secret vault access |
| audit.sbom.* | SBOM/CBOM generation |
| audit.ai.* | AI queries and recommendations |

Selected events with dedicated audit classification:
- `audit.dataprotect.fpe_encrypted`, `audit.dataprotect.fpe_decrypted` (FF1), `audit.dataprotect.fpe_legacy_decrypted` (pre-1.26.0 migration), `audit.dataprotect.fpe_refused` (FF3-1, legacy encrypt, unknown; `result: refused`)
- `audit.key.create_refused` (unsupported algorithm), `audit.key.algorithm_label_corrected` (startup relabel of faked key material), `audit.key.kdf_refused` (scrypt/Argon2id in strict mode)
- `audit.crypto.random` (with the source that produced the bytes; `hsm_serial` for `hsm-trng`), `audit.crypto.random_refused` (QKD/QRNG/no HSM)
- `audit.hsm.random_generated` (hsm-connector `POST /hsm/random`)
- `audit.pqc.migration_step_executed` (per step: `successor_created` or `rotated`), `audit.pqc.migration_executed`, `audit.pqc.migration_failed`, `audit.pqc.migration_rolled_back`
- `audit.sbom.generated` (`vulnerabilities_assessed: false` and `vulnerability_error` when sources failed; no count), `audit.cbom.generated`: the snapshot produced, manual or scheduled (`trigger`)
- `audit.sbom.*` request events (route kernel): `sbom_generate_requested`, `sbom_latest_read`, `sbom_history_listed`, `sbom_vulnerabilities_listed`, `sbom_advisories_listed`, `sbom_advisory_saved`, `sbom_advisory_deleted`, `sbom_diff_read`, `sbom_exported`, `sbom_read`, `cbom_generate_requested`, `cbom_latest_read`, `cbom_history_listed`, `cbom_summary_read`, `cbom_pqc_readiness_read`, `cbom_diff_read`, `cbom_exported`, `cbom_read`; handler refusal reason `platform_tenant_required`
- `audit.reporting.*` request events (route kernel): `alerts_listed`, `alerts_feed_streamed`, `alerts_unread_counted`, `alert_read`, `alert_updated` (`operation`: acknowledge / resolve / false_positive / escalate; replaces `alert_escalated`), `alerts_bulk_acknowledged`, `alerts_bulk_resolved`, `incidents_listed`, `incident_read`, `incident_status_updated`, `incident_assigned`, `rules_listed`, `rule_created`, `rule_updated`, `rule_deleted`, `severity_config_read`, `severity_config_updated`, `channels_listed`, `channels_updated`, `report_templates_listed`, `report_requested`, `report_jobs_listed`, `report_job_read`, `report_downloaded`, `report_deleted`, `scheduled_reports_listed`, `report_scheduled`, `error_telemetry_captured`, `error_telemetry_listed`, `alert_stats_read`, `mttd_stats_viewed`, `mttr_stats_read`, `top_sources_read`. Background: `audit.reporting.alert_created`, `audit.reporting.report_requested` (`trigger: scheduled`), `audit.reporting.evidence_pack_requested`
- `audit.key.encrypt`, `audit.key.decrypt`, `audit.key.sign`, `audit.key.verify`
- `audit.key.rotate`, `audit.key.destroy`, `audit.key.export`, `audit.key.wrap`, `audit.key.unwrap`
- `audit.key.data_key_generated` (refusals: `reason` = `ops_limit_reached`, `policy_denied`, `fips_mode_violation`, access and HSM refusals, `permission_denied`): envelope-encryption DEK generation
- `audit.key.rotation_policies_listed`, `audit.key.rotation_policy_created`, `audit.key.rotation_policy_updated`, `audit.key.rotation_policy_deleted`, `audit.key.rotation_policy_triggered`, `audit.key.rotation_runs_listed`, `audit.key.rotation_upcoming_listed` (kernel events; refusals `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`), `audit.key.rotation_policy_run` (scheduled run; `result: failure` when any key failed): key rotation policies
- `audit.audit.webhooks_listed`, `audit.audit.webhook_created`, `audit.audit.webhook_updated`, `audit.audit.webhook_deleted`, `audit.audit.webhook_tested`, `audit.audit.webhook_deliveries_listed` (kernel events; also refused with `reason: url_blocked`), `audit.audit.webhook_delivered` (every delivery, `result` success/failure), `audit.audit.webhook_credentials_sealed` / `audit.audit.webhook_credentials_seal_refused` (plaintext rows from before 1.25.0-beta), `audit.audit.mek_exposure_recorded` and the `audit.audit.mek_*` master-key events: webhooks
- `audit.posture.health_read`, `audit.posture.dashboard_viewed`, `audit.posture.risk_read`, `audit.posture.risk_history_read`, `audit.posture.scan_run`, `audit.posture.events_ingested`, `audit.posture.audit_synced`, `audit.posture.findings_listed`, `audit.posture.finding_status_updated`, `audit.posture.actions_listed`, `audit.posture.action_executed` (kernel events; refusals `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`, `tenant_wildcard`), `audit.posture.events_ingested` (also from the scheduled audit sync, `source: scheduled_audit_sync`, under the synced tenant), `audit.posture.risk_snapshot`, `audit.posture.preventive_controls_applied`, `audit.posture.runbook.execute` (engine events): posture engine
- `audit.posture.leak_targets_listed`, `audit.posture.leak_target_created`, `audit.posture.leak_target_deleted`, `audit.posture.leak_scan_started` (refused `target_disabled`), `audit.posture.leak_jobs_listed`, `audit.posture.leak_findings_listed`, `audit.posture.leak_finding_updated` (kernel events), `audit.posture.leak_scan_completed` (scan outcome, `findings`): leak scanner
- `audit.key.agility_score_read`, `audit.key.agility_inventory_read`, `audit.key.agility_keys_by_algorithm_read`, `audit.key.agility_migration_plans_listed`, `audit.key.agility_migration_plan_created`, `audit.key.agility_migration_plan_updated` (kernel events; refusals `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`): crypto agility
- `audit.auth.login`, `audit.auth.logout`, `audit.auth.mfa_verified`
- `audit.auth.scim_user_provisioned`, `audit.auth.scim_user_deprovisioned`
- `audit.auth.scim_settings_updated`, `audit.auth.scim_token_rotated`
- `audit.cert.internal_subca_created`, `audit.certs.internal_enroll` (refusals: `reason` = `invalid_request`, `invalid_csr`, `proof_rejected`, `issuance_refused`), `audit.cert.internal_enrolled`: internal mTLS (docs/SECURITY/INTERNAL_TLS.md)
- `audit.auth.cli_session_refused` (`reason`: `invalid_credentials`, `public_default_password`), `audit.auth.cli_ssh_password_synced`, `audit.auth.cli_password_revoked`: CLI/SSH access to hsm-integration (docs/SECURITY/HSM_INTEGRATION.md)
- `audit.hsm.provider_library_inventory`, `audit.hsm.provider_library_added`, `audit.hsm.provider_library_changed`, `audit.hsm.provider_library_removed`: files in the PKCS#11 provider workspace, with SHA-256
- `audit.certs.internal_mtls_inventory_read`, `audit.certs.internal_mtls_policy_updated`, `audit.certs.internal_mtls_rotated`, `audit.certs.internal_mtls_rotated_all` (refusals: `not_root_tenant`, `unchanged`, `invalid_policy`, `unknown_identity`, `kx_profile_not_applicable`, `force_not_available`, `confirmation_required`), `audit.certs.internal_mtls_applied` (a change is running on every instance), `audit.certs.certificate_key_label_corrected`: Service mTLS (docs/SECURITY/INTERNAL_TLS.md)
- `audit.cert.pqc_issuance_refused` (`reason: pqc_certificates_removed`), `audit.certs.pqc_profile_removed`: post-quantum and hybrid certificates are removed (1.19.0); `POST /certs/validate-pqc`, `POST /certs/pqc/migrate/{id}`, `GET /certs/pqc-readiness` and `GET /certs/ots-status/{ca_id}` no longer exist, and `audit.cert.pqc_cert_issued`, `pqc_cert_validated` and `pqc_migration_executed` are no longer emitted
- `audit.certs.crwk_rotated` (`reason`: `passphrase_rotation`, `public_default_passphrase`; failures `result: failure`, `reason: rewrap_failed`): certs root wrapping key re-keyed and every CA signer rewrapped (docs/SECURITY/SECRET_ROTATION.md)
- `audit.cert.issued`, `audit.cert.revoked`, `audit.cert.renewed`
- `audit.cert.renewal_window_missed`, `audit.cert.emergency_rotation_started`
- `audit.cert.star_subscription_created`, `audit.cert.star_subscription_renewed`
- `audit.governance.approval_requested`, `audit.governance.approved`, `audit.governance.rejected`, `audit.governance.bypassed`
- `audit.governance.backup_created` (`key_mode`, `key_retained`), `audit.governance.backup_deleted`, `audit.governance.backup_restored`, `audit.governance.backup_restore_refused` (tampered artifact, wrong key, changed scope, wrong file type, retired v1 key package; carries `reason`)
- `audit.governance.backup_verified` (`table_count`, `row_count_total`, `key_source`, `elapsed_ms`, `verified_by`), `audit.governance.backup_verify_refused` (`reason`, `result: refused`). Restore and verify name the caller from the verified token (`restored_by`, `requested_by`), never from `created_by` in the body
- `audit.governance.backup_key_split` (`threshold`, `shares_total`, `guardians`; high), `audit.governance.backup_restored` carries `key_source` (`key_file`/`guardian_shares`) and `share_guardians`; `backup_restore_refused` carries `key_shares_given`
- `audit.governance.backup_create_refused` (`reason`), `audit.governance.backup_key_downloaded`, `audit.governance.backup_key_download_refused` (`reason: key_not_retained`)
- `audit.hsm.*` (connector: `key_generated`, `tenant_key_ensured`, `encrypt`, `decrypt`, `sign`, `verify`, `key_destroyed`, `status_read`), `audit.key.hsm_settings_updated`, `audit.key.hsm_refused` (`reason`), `audit.key.hsm_objects_destroyed`, `audit.key.hsm_destroy_failed`, `audit.key.hsm_status_read`, `audit.key.hsm_settings_update`, `audit.hsm.key_inspected`, `audit.hsm.objects_listed`, `audit.key.hsm_objects_listed`, `audit.key.hsm_key_inspected`, `audit.key.hsm_device_changed`, `audit.cert.crl_generation_failed`: HSM integration (docs/SECURITY/HSM_INTEGRATION.md)
- `audit.governance.system_admin_refused` (`reason`: `authentication_required`, `tenant_required`, `tenant_mismatch`, `not_root_tenant`, `token_tenant_not_root`, `insufficient_privileges`), `audit.governance.authentication_refused` (`reason: invalid_token`)
- `audit.governance.fips_mode_changed` (critical for a downgrade)
- `audit.backup.policy_created`, `audit.backup.policy_updated`, `audit.backup.policy_deleted`, `audit.backup.run_refused_preview`, `audit.backup.restore_refused_preview`
- `audit.auth.cluster_token_minted`, `audit.auth.cluster_mint_refused`; `audit.cluster.write_forwarded`, `audit.cluster.forward_refused` (primary); `audit.<service>.cluster_write_forwarded`, `audit.<service>.cluster_write_refused` (member; `reason`: invalid_token / primary_unreachable / primary_write_required); refusals carry `result: refused`
- `audit.key.service_derive`, `audit.key.audit_chain_anchored` (preview), enterprise control upserts carry `feature_status` / `feature_id`
- Services on the `pkg/route` kernel emit one `audit.<service>.<action>` per request, including `result: failure` (with `error_code`) and `result: refused` (with `reason`: `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`, or a handler reason such as `feature_preview`). `audit.secrets.*`: `created`, `listed`, `read`, `value_read`, `updated`, `deleted`, `generated`, `versions_listed`, `audit_log_read`, `rotated`, `stats_read`, `vault_kv_read`, `vault_kv_written`, `vault_kv_deleted`, `vault_metadata_read`, `vault_token_lookup`, `vault_health_read`, `vault_seal_status_read`
- `audit.kmip.client_connected`, `audit.kmip.authorization_denied`, `audit.kmip.operation_panic` (critical), `audit.kmip.<operation>` with `status` / `reason` (lifecycle-state refusals included)
- `audit.dataprotect.kdf_legacy_used`, `audit.dataprotect.kdf_migration_started`, `audit.dataprotect.kdf_vault_reprotected`, `audit.dataprotect.kdf_migration_completed`, `audit.dataprotect.kdf_migration_aborted`
- `audit.mpc.dkg_initiated`, `audit.mpc.sign_initiated`, `audit.mpc.sign_completed`
- `audit.signing.artifact_signed`, `audit.signing.artifact_verified` (`verification_status`: verified / signature_invalid / artifact_mismatch), `audit.signing.records_viewed`
- `audit.confidential.key_released`, `audit.confidential.attestation_denied`
- `audit.payment.pin_verified`, `audit.payment.tr31_wrapped`

---

## Appendix: Common Workflows

### Encrypt application data

```bash
# 1. Login
export TOKEN=$(curl -sk -X POST https://localhost/svc/auth/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"app-service","password":"pass","tenantId":"root"}' | jq -r '.token')

# 2. Create key (once)
KEY_ID=$(curl -sk -X POST https://localhost/svc/keycore/keys \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"app-data-key","algorithm":"AES-256","purpose":"encrypt"}' | jq -r '.id')

# 3. Encrypt
curl -sk -X POST "https://localhost/svc/keycore/keys/$KEY_ID/encrypt" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"plaintext":"c2Vuc2l0aXZlIGRhdGE="}'
```

### Issue a TLS certificate

```bash
# 1. Generate CSR with openssl
openssl req -new -newkey rsa:2048 -nodes -keyout server.key \
  -subj "/CN=api.acme.example/O=Acme Corp" -out server.csr

```

### Provision a workload key via Autokey

```bash
# 1. Create a provisioning request
curl -sk -X POST https://localhost/svc/autokey/autokey/requests \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"resourceType":"s3-bucket","resourceId":"my-app-data-bucket","service":"data-pipeline","justification":"production encryption for GDPR scope data"}'
```

## Appendix: Route index (generated)

<!-- route-index:start (generated by scripts/check-doc-routes.py --write-index) -->

Every route each service registers, as reached through the edge. Generated
from the code; do not edit by hand.

### ai-gateway (`/svc/ai-gateway/`)

- `GET /svc/ai-gateway/ai-gateway/v1/access-rules`
- `POST /svc/ai-gateway/ai-gateway/v1/access-rules`
- `DELETE /svc/ai-gateway/ai-gateway/v1/access-rules/{id}`
- `GET /svc/ai-gateway/ai-gateway/v1/audit`
- `GET /svc/ai-gateway/ai-gateway/v1/audit/stats`
- `GET /svc/ai-gateway/ai-gateway/v1/audit/{id}`
- `GET /svc/ai-gateway/ai-gateway/v1/budgets`
- `POST /svc/ai-gateway/ai-gateway/v1/budgets`
- `GET /svc/ai-gateway/ai-gateway/v1/budgets/usage`
- `PUT /svc/ai-gateway/ai-gateway/v1/budgets/{id}`
- `POST /svc/ai-gateway/ai-gateway/v1/chat/completions`
- `POST /svc/ai-gateway/ai-gateway/v1/completions`
- `POST /svc/ai-gateway/ai-gateway/v1/embeddings`
- `POST /svc/ai-gateway/ai-gateway/v1/evaluate`
- `GET /svc/ai-gateway/ai-gateway/v1/guardrails`
- `POST /svc/ai-gateway/ai-gateway/v1/guardrails`
- `DELETE /svc/ai-gateway/ai-gateway/v1/guardrails/{id}`
- `GET /svc/ai-gateway/ai-gateway/v1/health`
- `GET /svc/ai-gateway/ai-gateway/v1/metrics`
- `GET /svc/ai-gateway/ai-gateway/v1/models`
- `POST /svc/ai-gateway/ai-gateway/v1/models`
- `DELETE /svc/ai-gateway/ai-gateway/v1/models/{id}`
- `PUT /svc/ai-gateway/ai-gateway/v1/models/{id}`
- `POST /svc/ai-gateway/ai-gateway/v1/models/{id}/test`
- `GET /svc/ai-gateway/ai-gateway/v1/policies`
- `POST /svc/ai-gateway/ai-gateway/v1/policies`
- `DELETE /svc/ai-gateway/ai-gateway/v1/policies/{id}`
- `GET /svc/ai-gateway/ai-gateway/v1/policies/{id}`
- `PUT /svc/ai-gateway/ai-gateway/v1/policies/{id}`
- `POST /svc/ai-gateway/ai-gateway/v1/redact`
- `POST /svc/ai-gateway/ai-gateway/v1/scan`

### audit (`/svc/audit/`)

- `GET /svc/audit/alerts`
- `GET /svc/audit/alerts/channels`
- `PUT /svc/audit/alerts/channels`
- `POST /svc/audit/alerts/channels/test`
- `GET /svc/audit/alerts/rules`
- `POST /svc/audit/alerts/rules`
- `DELETE /svc/audit/alerts/rules/{id}`
- `PUT /svc/audit/alerts/rules/{id}`
- `GET /svc/audit/alerts/stats`
- `GET /svc/audit/alerts/stream`
- `POST /svc/audit/alerts/test-rule`
- `GET /svc/audit/alerts/{id}`
- `PUT /svc/audit/alerts/{id}/{action}`
- `GET /svc/audit/audit/cbom/diff`
- `GET /svc/audit/audit/cbom/inventory`
- `GET /svc/audit/audit/chain/verify`
- `POST /svc/audit/audit/cluster/signing-key/export`
- `POST /svc/audit/audit/cluster/signing-key/import`
- `POST /svc/audit/audit/cluster/signing-key/join-key`
- `GET /svc/audit/audit/config`
- `GET /svc/audit/audit/correlation/{id}`
- `GET /svc/audit/audit/events`
- `GET /svc/audit/audit/events/{id}`
- `GET /svc/audit/audit/events/{id}/proof`
- `GET /svc/audit/audit/fips/boundary`
- `POST /svc/audit/audit/merkle/build`
- `GET /svc/audit/audit/merkle/epochs`
- `GET /svc/audit/audit/merkle/epochs/{id}`
- `POST /svc/audit/audit/merkle/verify`
- `POST /svc/audit/audit/publish`
- `POST /svc/audit/audit/search`
- `GET /svc/audit/audit/session/{session_id}`
- `GET /svc/audit/audit/stats`
- `GET /svc/audit/audit/stream`
- `GET /svc/audit/audit/timeline/{target_id}`
- `GET /svc/audit/metrics`
- `GET /svc/audit/ops-metrics/by-service`
- `GET /svc/audit/ops-metrics/errors`
- `GET /svc/audit/ops-metrics/latency`
- `GET /svc/audit/ops-metrics/overview`
- `POST /svc/audit/ops-metrics/record`
- `GET /svc/audit/ops-metrics/timeseries`
- `GET /svc/audit/webhooks`
- `POST /svc/audit/webhooks`
- `DELETE /svc/audit/webhooks/{id}`
- `PATCH /svc/audit/webhooks/{id}`
- `GET /svc/audit/webhooks/{id}/deliveries`
- `POST /svc/audit/webhooks/{id}/test`

### auth (`/svc/auth/`)

- `POST /svc/auth/auth/api-keys`
- `DELETE /svc/auth/auth/api-keys/{id}`
- `POST /svc/auth/auth/change-password`
- `GET /svc/auth/auth/cli/hsm/config`
- `PUT /svc/auth/auth/cli/hsm/config`
- `GET /svc/auth/auth/cli/hsm/partitions`
- `POST /svc/auth/auth/cli/session`
- `GET /svc/auth/auth/cli/status`
- `POST /svc/auth/auth/client-token`
- `GET /svc/auth/auth/clients`
- `GET /svc/auth/auth/clients/{id}`
- `PUT /svc/auth/auth/clients/{id}`
- `POST /svc/auth/auth/clients/{id}/revoke`
- `POST /svc/auth/auth/clients/{id}/rotate-key`
- `POST /svc/auth/auth/cluster/mint`
- `GET /svc/auth/auth/groups/roles`
- `DELETE /svc/auth/auth/groups/{id}/role`
- `PUT /svc/auth/auth/groups/{id}/role`
- `POST /svc/auth/auth/identity/import/users`
- `GET /svc/auth/auth/identity/providers`
- `GET /svc/auth/auth/identity/providers/{provider}`
- `PUT /svc/auth/auth/identity/providers/{provider}`
- `GET /svc/auth/auth/identity/providers/{provider}/groups`
- `GET /svc/auth/auth/identity/providers/{provider}/groups/{id}/members`
- `POST /svc/auth/auth/identity/providers/{provider}/test`
- `GET /svc/auth/auth/identity/providers/{provider}/users`
- `POST /svc/auth/auth/login`
- `POST /svc/auth/auth/logout`
- `GET /svc/auth/auth/me`
- `GET /svc/auth/auth/password-policy`
- `PUT /svc/auth/auth/password-policy`
- `POST /svc/auth/auth/refresh`
- `POST /svc/auth/auth/register`
- `POST /svc/auth/auth/register/{id}/activate`
- `GET /svc/auth/auth/register/{id}/status`
- `GET /svc/auth/auth/rest-client-security/summary`
- `GET /svc/auth/auth/scim/groups`
- `GET /svc/auth/auth/scim/settings`
- `PUT /svc/auth/auth/scim/settings`
- `POST /svc/auth/auth/scim/settings/rotate-token`
- `GET /svc/auth/auth/scim/summary`
- `GET /svc/auth/auth/scim/users`
- `GET /svc/auth/auth/security-policy`
- `PUT /svc/auth/auth/security-policy`
- `GET /svc/auth/auth/sso/providers`
- `GET /svc/auth/auth/sso/saml/metadata`
- `GET /svc/auth/auth/sso/{provider}/callback`
- `POST /svc/auth/auth/sso/{provider}/callback`
- `GET /svc/auth/auth/sso/{provider}/login`
- `GET /svc/auth/auth/system-health`
- `POST /svc/auth/auth/system-health/restart`
- `GET /svc/auth/auth/users`
- `POST /svc/auth/auth/users`
- `POST /svc/auth/auth/users/{id}/reset-password`
- `PUT /svc/auth/auth/users/{id}/role`
- `PUT /svc/auth/auth/users/{id}/status`
- `POST /svc/auth/auth/workload-token`
- `GET /svc/auth/scim/v2/Groups`
- `POST /svc/auth/scim/v2/Groups`
- `DELETE /svc/auth/scim/v2/Groups/{id}`
- `GET /svc/auth/scim/v2/Groups/{id}`
- `PATCH /svc/auth/scim/v2/Groups/{id}`
- `PUT /svc/auth/scim/v2/Groups/{id}`
- `GET /svc/auth/scim/v2/ResourceTypes`
- `GET /svc/auth/scim/v2/Schemas`
- `GET /svc/auth/scim/v2/ServiceProviderConfig`
- `GET /svc/auth/scim/v2/Users`
- `POST /svc/auth/scim/v2/Users`
- `DELETE /svc/auth/scim/v2/Users/{id}`
- `GET /svc/auth/scim/v2/Users/{id}`
- `PATCH /svc/auth/scim/v2/Users/{id}`
- `PUT /svc/auth/scim/v2/Users/{id}`
- `GET /svc/auth/tenants`
- `POST /svc/auth/tenants`
- `DELETE /svc/auth/tenants/{id}`
- `GET /svc/auth/tenants/{id}`
- `PUT /svc/auth/tenants/{id}`
- `GET /svc/auth/tenants/{id}/delete-readiness`
- `POST /svc/auth/tenants/{id}/disable`
- `POST /svc/auth/tenants/{id}/roles`
- `DELETE /svc/auth/tenants/{id}/roles/{name}`
- `PUT /svc/auth/tenants/{id}/roles/{name}`

### autokey (`/svc/autokey/`)

- `GET /svc/autokey/autokey/handles`
- `GET /svc/autokey/autokey/requests`
- `POST /svc/autokey/autokey/requests`
- `GET /svc/autokey/autokey/requests/{id}`
- `GET /svc/autokey/autokey/service-policies`
- `POST /svc/autokey/autokey/service-policies`
- `DELETE /svc/autokey/autokey/service-policies/{service}`
- `PUT /svc/autokey/autokey/service-policies/{service}`
- `GET /svc/autokey/autokey/settings`
- `PUT /svc/autokey/autokey/settings`
- `GET /svc/autokey/autokey/summary`
- `GET /svc/autokey/autokey/templates`
- `POST /svc/autokey/autokey/templates`
- `DELETE /svc/autokey/autokey/templates/{id}`
- `PUT /svc/autokey/autokey/templates/{id}`

### backup (`/svc/backup/`)

- `GET /svc/backup/backup/metrics`
- `GET /svc/backup/backup/policies`
- `POST /svc/backup/backup/policies`
- `DELETE /svc/backup/backup/policies/{id}`
- `PATCH /svc/backup/backup/policies/{id}`
- `POST /svc/backup/backup/policies/{id}/trigger`
- `GET /svc/backup/backup/restore-points`
- `POST /svc/backup/backup/restore-points/{id}/restore`
- `GET /svc/backup/backup/runs`
- `GET /svc/backup/backup/runs/{id}`
- `GET /svc/backup/healthz`

### certs (`/svc/certs/`)

- `GET /svc/certs/acme/cert/{id}`
- `GET /svc/certs/acme/challenge/{id}`
- `POST /svc/certs/acme/challenge/{id}`
- `GET /svc/certs/acme/directory`
- `POST /svc/certs/acme/finalize/{id}`
- `POST /svc/certs/acme/new-account`
- `POST /svc/certs/acme/new-nonce`
- `POST /svc/certs/acme/new-order`
- `GET /svc/certs/acme/renewal-info/{id}`
- `GET /svc/certs/certs`
- `POST /svc/certs/certs`
- `GET /svc/certs/certs/alert-policy`
- `PUT /svc/certs/certs/alert-policy`
- `GET /svc/certs/certs/ca`
- `POST /svc/certs/certs/ca`
- `DELETE /svc/certs/certs/ca/{id}`
- `GET /svc/certs/certs/clm/policy`
- `PUT /svc/certs/certs/clm/policy`
- `GET /svc/certs/certs/clm/status`
- `GET /svc/certs/certs/crl`
- `GET /svc/certs/certs/download/{id}`
- `GET /svc/certs/certs/internal-mtls`
- `POST /svc/certs/certs/internal-mtls/rotate-all`
- `PUT /svc/certs/certs/internal-mtls/{identity}/policy`
- `POST /svc/certs/certs/internal-mtls/{identity}/rotate`
- `GET /svc/certs/certs/inventory`
- `POST /svc/certs/certs/merkle/build`
- `GET /svc/certs/certs/merkle/epochs`
- `GET /svc/certs/certs/merkle/epochs/{id}`
- `GET /svc/certs/certs/merkle/proof/{id}`
- `POST /svc/certs/certs/merkle/verify`
- `GET /svc/certs/certs/ocsp`
- `POST /svc/certs/certs/ocsp`
- `GET /svc/certs/certs/profiles`
- `POST /svc/certs/certs/profiles`
- `GET /svc/certs/certs/profiles/{id}`
- `GET /svc/certs/certs/protocols`
- `GET /svc/certs/certs/protocols/schema`
- `PUT /svc/certs/certs/protocols/{protocol}`
- `GET /svc/certs/certs/renewal-intelligence`
- `POST /svc/certs/certs/renewal-intelligence/refresh`
- `GET /svc/certs/certs/renewal-intelligence/{id}`
- `GET /svc/certs/certs/security/status`
- `POST /svc/certs/certs/sign-csr`
- `GET /svc/certs/certs/star/subscriptions`
- `POST /svc/certs/certs/star/subscriptions`
- `DELETE /svc/certs/certs/star/subscriptions/{id}`
- `POST /svc/certs/certs/star/subscriptions/{id}/refresh`
- `GET /svc/certs/certs/star/summary`
- `POST /svc/certs/certs/upload-3p`
- `DELETE /svc/certs/certs/{id}`
- `GET /svc/certs/certs/{id}`
- `POST /svc/certs/certs/{id}/renew`
- `POST /svc/certs/certs/{id}/revoke`
- `POST /svc/certs/cmpv2`
- `POST /svc/certs/cmpv2/confirm`
- `GET /svc/certs/est/.well-known/est/cacerts`
- `GET /svc/certs/est/.well-known/est/csrattrs`
- `POST /svc/certs/est/.well-known/est/serverkeygen`
- `POST /svc/certs/est/.well-known/est/simpleenroll`
- `POST /svc/certs/est/.well-known/est/simplereenroll`
- `GET /svc/certs/scep/pkiclient.exe`
- `POST /svc/certs/scep/pkiclient.exe`

### cloud (`/svc/cloud/`)

- `GET /svc/cloud/cloud/accounts`
- `POST /svc/cloud/cloud/accounts`
- `DELETE /svc/cloud/cloud/accounts/{id}`
- `GET /svc/cloud/cloud/bindings`
- `GET /svc/cloud/cloud/bindings/{id}`
- `POST /svc/cloud/cloud/bindings/{id}/rotate`
- `POST /svc/cloud/cloud/import`
- `GET /svc/cloud/cloud/inventory`
- `GET /svc/cloud/cloud/region-mappings`
- `POST /svc/cloud/cloud/region-mappings`
- `POST /svc/cloud/cloud/sync`

### cluster-manager (`/svc/cluster/`)

- `ANY /svc/cluster/cluster/forward/{svc}/{rest...}`
- `POST /svc/cluster/cluster/join/complete`
- `POST /svc/cluster/cluster/join/connect`
- `POST /svc/cluster/cluster/join/exchange`
- `POST /svc/cluster/cluster/join/request`
- `GET /svc/cluster/cluster/logs`
- `GET /svc/cluster/cluster/members`
- `GET /svc/cluster/cluster/nodes`
- `POST /svc/cluster/cluster/nodes`
- `DELETE /svc/cluster/cluster/nodes/{id}`
- `POST /svc/cluster/cluster/nodes/{id}/heartbeat`
- `POST /svc/cluster/cluster/nodes/{id}/role`
- `GET /svc/cluster/cluster/overview`
- `GET /svc/cluster/cluster/profiles`
- `POST /svc/cluster/cluster/profiles`
- `DELETE /svc/cluster/cluster/profiles/{id}`
- `GET /svc/cluster/cluster/replication/status`
- `POST /svc/cluster/cluster/sync/ack`
- `GET /svc/cluster/cluster/sync/checkpoint`
- `GET /svc/cluster/cluster/sync/events`
- `POST /svc/cluster/cluster/sync/events`
- `GET /svc/cluster/healthz`

### compliance (`/svc/compliance/`)

- `GET /svc/compliance/compliance/assessment`
- `GET /svc/compliance/compliance/assessment/delta`
- `GET /svc/compliance/compliance/assessment/history`
- `POST /svc/compliance/compliance/assessment/run`
- `GET /svc/compliance/compliance/assessment/schedule`
- `PUT /svc/compliance/compliance/assessment/schedule`
- `GET /svc/compliance/compliance/audit/anomalies`
- `GET /svc/compliance/compliance/audit/correlations`
- `GET /svc/compliance/compliance/cbom`
- `GET /svc/compliance/compliance/cbom/diff`
- `GET /svc/compliance/compliance/cbom/export`
- `GET /svc/compliance/compliance/cbom/pqc-readiness`
- `GET /svc/compliance/compliance/cbom/summary`
- `GET /svc/compliance/compliance/evidence/export`
- `GET /svc/compliance/compliance/frameworks`
- `GET /svc/compliance/compliance/frameworks/{id}/controls`
- `GET /svc/compliance/compliance/frameworks/{id}/gaps`
- `GET /svc/compliance/compliance/keys/expired`
- `GET /svc/compliance/compliance/keys/hygiene`
- `GET /svc/compliance/compliance/keys/orphaned`
- `GET /svc/compliance/compliance/playbooks`
- `POST /svc/compliance/compliance/playbooks`
- `GET /svc/compliance/compliance/playbooks/summary`
- `DELETE /svc/compliance/compliance/playbooks/{id}`
- `GET /svc/compliance/compliance/playbooks/{id}`
- `PUT /svc/compliance/compliance/playbooks/{id}`
- `POST /svc/compliance/compliance/playbooks/{id}/run`
- `GET /svc/compliance/compliance/playbooks/{id}/runs`
- `GET /svc/compliance/compliance/posture`
- `GET /svc/compliance/compliance/posture/breakdown`
- `GET /svc/compliance/compliance/posture/history`
- `GET /svc/compliance/compliance/risk/keys`
- `GET /svc/compliance/compliance/risk/remediation`
- `GET /svc/compliance/compliance/risk/summary`
- `GET /svc/compliance/compliance/sbom`
- `GET /svc/compliance/compliance/sbom/services`
- `GET /svc/compliance/compliance/sbom/services/{name}`
- `GET /svc/compliance/compliance/sbom/vulnerabilities`
- `GET /svc/compliance/compliance/templates`
- `POST /svc/compliance/compliance/templates`
- `DELETE /svc/compliance/compliance/templates/{id}`
- `GET /svc/compliance/compliance/templates/{id}`

### confidential (`/svc/confidential/`)

- `POST /svc/confidential/confidential/evaluate`
- `GET /svc/confidential/confidential/policy`
- `PUT /svc/confidential/confidential/policy`
- `GET /svc/confidential/confidential/releases`
- `GET /svc/confidential/confidential/releases/{id}`
- `GET /svc/confidential/confidential/summary`

### dataprotect (`/svc/dataprotect/`)

- `POST /svc/dataprotect/app/decrypt-fields`
- `POST /svc/dataprotect/app/encrypt-fields`
- `POST /svc/dataprotect/app/envelope-decrypt`
- `POST /svc/dataprotect/app/envelope-encrypt`
- `POST /svc/dataprotect/app/searchable-decrypt`
- `POST /svc/dataprotect/app/searchable-encrypt`
- `GET /svc/dataprotect/audit-log`
- `POST /svc/dataprotect/detokenize`
- `POST /svc/dataprotect/detokenize/batch`
- `GET /svc/dataprotect/field-encryption/leases`
- `POST /svc/dataprotect/field-encryption/leases`
- `POST /svc/dataprotect/field-encryption/leases/{id}/renew`
- `POST /svc/dataprotect/field-encryption/leases/{id}/revoke`
- `POST /svc/dataprotect/field-encryption/receipts`
- `POST /svc/dataprotect/field-encryption/register/complete`
- `POST /svc/dataprotect/field-encryption/register/init`
- `GET /svc/dataprotect/field-encryption/sdk/download`
- `GET /svc/dataprotect/field-encryption/wrappers`
- `GET /svc/dataprotect/field-protection/profiles`
- `POST /svc/dataprotect/field-protection/profiles`
- `DELETE /svc/dataprotect/field-protection/profiles/{id}`
- `PUT /svc/dataprotect/field-protection/profiles/{id}`
- `GET /svc/dataprotect/field-protection/resolve`
- `POST /svc/dataprotect/fpe/decrypt`
- `POST /svc/dataprotect/fpe/encrypt`
- `GET /svc/dataprotect/kdf/keys`
- `POST /svc/dataprotect/kdf/keys/{key_id}/abort`
- `POST /svc/dataprotect/kdf/keys/{key_id}/complete`
- `POST /svc/dataprotect/kdf/keys/{key_id}/reprotect-vault`
- `POST /svc/dataprotect/kdf/keys/{key_id}/start-migration`
- `POST /svc/dataprotect/mask`
- `POST /svc/dataprotect/mask/preview`
- `GET /svc/dataprotect/masking-policies`
- `POST /svc/dataprotect/masking-policies`
- `DELETE /svc/dataprotect/masking-policies/{id}`
- `PUT /svc/dataprotect/masking-policies/{id}`
- `GET /svc/dataprotect/policy`
- `PUT /svc/dataprotect/policy`
- `POST /svc/dataprotect/redact`
- `POST /svc/dataprotect/redact/detect`
- `GET /svc/dataprotect/redaction-policies`
- `POST /svc/dataprotect/redaction-policies`
- `GET /svc/dataprotect/stats`
- `GET /svc/dataprotect/token-vaults`
- `POST /svc/dataprotect/token-vaults`
- `GET /svc/dataprotect/token-vaults/external-schema`
- `DELETE /svc/dataprotect/token-vaults/{id}`
- `GET /svc/dataprotect/token-vaults/{id}`
- `POST /svc/dataprotect/tokenize`
- `POST /svc/dataprotect/tokenize/batch`

### discovery (`/svc/discovery/`)

- `GET /svc/discovery/discovery/assets`
- `GET /svc/discovery/discovery/assets/{id}`
- `PUT /svc/discovery/discovery/assets/{id}/classify`
- `GET /svc/discovery/discovery/crypto/assets`
- `GET /svc/discovery/discovery/data-inventory`
- `GET /svc/discovery/discovery/lineage/access-patterns/{key_id}`
- `GET /svc/discovery/discovery/lineage/chain-of-custody/{key_id}`
- `GET /svc/discovery/discovery/lineage/data-flow/{key_id}`
- `GET /svc/discovery/discovery/lineage/dependencies/{key_id}`
- `GET /svc/discovery/discovery/lineage/graph`
- `GET /svc/discovery/discovery/lineage/impact/{key_id}`
- `GET /svc/discovery/discovery/lineage/key/{key_id}`
- `GET /svc/discovery/discovery/lineage/provenance/{key_id}`
- `POST /svc/discovery/discovery/lineage/record`
- `GET /svc/discovery/discovery/lineage/risk-heatmap`
- `POST /svc/discovery/discovery/lineage/search`
- `GET /svc/discovery/discovery/lineage/stats`
- `POST /svc/discovery/discovery/lineage/tamper-check/{key_id}`
- `GET /svc/discovery/discovery/lineage/timeline/{key_id}`
- `GET /svc/discovery/discovery/pii/patterns`
- `POST /svc/discovery/discovery/pii/scan`
- `GET /svc/discovery/discovery/posture`
- `POST /svc/discovery/discovery/scan`
- `GET /svc/discovery/discovery/scans`
- `GET /svc/discovery/discovery/scans/{id}`
- `GET /svc/discovery/discovery/summary`

### ekm (`/svc/ekm/`)

- `GET /svc/ekm/ekm/agents`
- `POST /svc/ekm/ekm/agents/register`
- `DELETE /svc/ekm/ekm/agents/{id}`
- `GET /svc/ekm/ekm/agents/{id}/deploy`
- `GET /svc/ekm/ekm/agents/{id}/health`
- `POST /svc/ekm/ekm/agents/{id}/heartbeat`
- `GET /svc/ekm/ekm/agents/{id}/logs`
- `POST /svc/ekm/ekm/agents/{id}/rotate`
- `GET /svc/ekm/ekm/agents/{id}/status`
- `POST /svc/ekm/ekm/agents/{id}/validate-deploy`
- `GET /svc/ekm/ekm/azure/configs`
- `POST /svc/ekm/ekm/azure/configs`
- `DELETE /svc/ekm/ekm/azure/configs/{id}`
- `GET /svc/ekm/ekm/azure/configs/{id}`
- `PUT /svc/ekm/ekm/azure/configs/{id}`
- `POST /svc/ekm/ekm/azure/configs/{id}/sync`
- `POST /svc/ekm/ekm/azure/configs/{id}/test`
- `GET /svc/ekm/ekm/azure/mappings`
- `POST /svc/ekm/ekm/azure/mappings`
- `DELETE /svc/ekm/ekm/azure/mappings/{id}`
- `POST /svc/ekm/ekm/azure/mappings/{id}/import`
- `POST /svc/ekm/ekm/azure/mappings/{id}/rotate`
- `POST /svc/ekm/ekm/azure/mappings/{id}/unwrap`
- `POST /svc/ekm/ekm/azure/mappings/{id}/wrap`
- `GET /svc/ekm/ekm/bitlocker/clients`
- `POST /svc/ekm/ekm/bitlocker/clients/register`
- `DELETE /svc/ekm/ekm/bitlocker/clients/{id}`
- `GET /svc/ekm/ekm/bitlocker/clients/{id}`
- `GET /svc/ekm/ekm/bitlocker/clients/{id}/delete-preview`
- `GET /svc/ekm/ekm/bitlocker/clients/{id}/deploy`
- `POST /svc/ekm/ekm/bitlocker/clients/{id}/heartbeat`
- `GET /svc/ekm/ekm/bitlocker/clients/{id}/jobs`
- `POST /svc/ekm/ekm/bitlocker/clients/{id}/jobs/next`
- `POST /svc/ekm/ekm/bitlocker/clients/{id}/jobs/{job_id}/result`
- `POST /svc/ekm/ekm/bitlocker/clients/{id}/operations`
- `POST /svc/ekm/ekm/bitlocker/network/scan`
- `GET /svc/ekm/ekm/bitlocker/recovery`
- `GET /svc/ekm/ekm/databases`
- `POST /svc/ekm/ekm/databases`
- `GET /svc/ekm/ekm/databases/{id}`
- `POST /svc/ekm/ekm/databases/{id}/revoke-tde`
- `GET /svc/ekm/ekm/google-cse/configs`
- `POST /svc/ekm/ekm/google-cse/configs`
- `DELETE /svc/ekm/ekm/google-cse/configs/{id}`
- `GET /svc/ekm/ekm/google-cse/configs/{id}`
- `PUT /svc/ekm/ekm/google-cse/configs/{id}`
- `GET /svc/ekm/ekm/google-cse/keys`
- `POST /svc/ekm/ekm/google-cse/keys`
- `DELETE /svc/ekm/ekm/google-cse/keys/{id}`
- `POST /svc/ekm/ekm/kacls/privilegedunwrap`
- `GET /svc/ekm/ekm/kacls/status`
- `POST /svc/ekm/ekm/kacls/unwrap`
- `POST /svc/ekm/ekm/kacls/wrap`
- `GET /svc/ekm/ekm/sdk/download`
- `GET /svc/ekm/ekm/sdk/overview`
- `POST /svc/ekm/ekm/tde/keys`
- `GET /svc/ekm/ekm/tde/keys/{id}/public`
- `POST /svc/ekm/ekm/tde/keys/{id}/revoke`
- `POST /svc/ekm/ekm/tde/keys/{id}/rotate`
- `POST /svc/ekm/ekm/tde/keys/{id}/unwrap`
- `POST /svc/ekm/ekm/tde/keys/{id}/wrap`

### governance (`/svc/governance/`)

- `GET /svc/governance/governance/approve/{id}`
- `POST /svc/governance/governance/approve/{id}`
- `GET /svc/governance/governance/backups`
- `POST /svc/governance/governance/backups`
- `POST /svc/governance/governance/backups/restore`
- `POST /svc/governance/governance/backups/verify`
- `DELETE /svc/governance/governance/backups/{id}`
- `GET /svc/governance/governance/backups/{id}`
- `GET /svc/governance/governance/backups/{id}/artifact`
- `GET /svc/governance/governance/backups/{id}/key`
- `POST /svc/governance/governance/key-approval`
- `GET /svc/governance/governance/key-approval/{id}/status`
- `GET /svc/governance/governance/policies`
- `POST /svc/governance/governance/policies`
- `DELETE /svc/governance/governance/policies/{id}`
- `PUT /svc/governance/governance/policies/{id}`
- `GET /svc/governance/governance/requests`
- `POST /svc/governance/governance/requests`
- `GET /svc/governance/governance/requests/pending`
- `GET /svc/governance/governance/requests/pending/count`
- `GET /svc/governance/governance/requests/{id}`
- `POST /svc/governance/governance/requests/{id}/cancel`
- `GET /svc/governance/governance/settings`
- `PUT /svc/governance/governance/settings`
- `POST /svc/governance/governance/settings/smtp/test`
- `POST /svc/governance/governance/settings/webhook/test`
- `GET /svc/governance/governance/system/fips-mode`
- `PUT /svc/governance/governance/system/fips-mode`
- `GET /svc/governance/governance/system/fips-mode/impact`
- `GET /svc/governance/governance/system/integrity`
- `PUT /svc/governance/governance/system/posture-controls`
- `POST /svc/governance/governance/system/snmp/test`
- `GET /svc/governance/governance/system/state`
- `PUT /svc/governance/governance/system/state`

### hyok (`/svc/hyok/`)

- `GET /svc/hyok/api/v1/keys/{id}`
- `POST /svc/hyok/api/v1/keys/{id}/{version}/decrypt`
- `POST /svc/hyok/hyok/alibaba/v1/keys/{id}/decrypt`
- `POST /svc/hyok/hyok/alibaba/v1/keys/{id}/encrypt`
- `POST /svc/hyok/hyok/dke/v1/keys/{id}/decrypt`
- `GET /svc/hyok/hyok/dke/v1/keys/{id}/publickey`
- `POST /svc/hyok/hyok/generic/v1/keys/{id}/decrypt`
- `POST /svc/hyok/hyok/generic/v1/keys/{id}/encrypt`
- `POST /svc/hyok/hyok/generic/v1/keys/{id}/unwrap`
- `POST /svc/hyok/hyok/generic/v1/keys/{id}/wrap`
- `POST /svc/hyok/hyok/google/v1/keys/{id}/unwrap`
- `POST /svc/hyok/hyok/google/v1/keys/{id}/wrap`
- `POST /svc/hyok/hyok/salesforce/v1/keys/{id}/unwrap`
- `POST /svc/hyok/hyok/salesforce/v1/keys/{id}/wrap`
- `POST /svc/hyok/hyok/servicenow/v1/keys/{id}/unwrap`
- `POST /svc/hyok/hyok/servicenow/v1/keys/{id}/wrap`
- `GET /svc/hyok/hyok/v1/endpoints`
- `DELETE /svc/hyok/hyok/v1/endpoints/{protocol}`
- `PUT /svc/hyok/hyok/v1/endpoints/{protocol}`
- `GET /svc/hyok/hyok/v1/health`
- `GET /svc/hyok/hyok/v1/requests`

### keyaccess (`/svc/keyaccess/`)

- `GET /svc/keyaccess/key-access/codes`
- `POST /svc/keyaccess/key-access/codes`
- `DELETE /svc/keyaccess/key-access/codes/{id}`
- `PUT /svc/keyaccess/key-access/codes/{id}`
- `GET /svc/keyaccess/key-access/decisions`
- `POST /svc/keyaccess/key-access/evaluate`
- `GET /svc/keyaccess/key-access/settings`
- `PUT /svc/keyaccess/key-access/settings`
- `GET /svc/keyaccess/key-access/summary`

### keycore (`/svc/keycore/`)

- `GET /svc/keycore/access/groups`
- `POST /svc/keycore/access/groups`
- `DELETE /svc/keycore/access/groups/{id}`
- `PUT /svc/keycore/access/groups/{id}/members`
- `GET /svc/keycore/access/interface-policies`
- `POST /svc/keycore/access/interface-policies`
- `DELETE /svc/keycore/access/interface-policies/{id}`
- `GET /svc/keycore/access/interface-ports`
- `POST /svc/keycore/access/interface-ports`
- `DELETE /svc/keycore/access/interface-ports/{name}`
- `GET /svc/keycore/access/interface-tls-config`
- `PUT /svc/keycore/access/interface-tls-config`
- `GET /svc/keycore/access/settings`
- `PUT /svc/keycore/access/settings`
- `GET /svc/keycore/agility/algorithms`
- `GET /svc/keycore/agility/keys-by-algorithm`
- `GET /svc/keycore/agility/migration-plans`
- `POST /svc/keycore/agility/migration-plans`
- `PATCH /svc/keycore/agility/migration-plans/{id}`
- `GET /svc/keycore/agility/score`
- `GET /svc/keycore/analytics/algorithms`
- `GET /svc/keycore/analytics/hotspots`
- `POST /svc/keycore/analytics/metrics`
- `GET /svc/keycore/analytics/trends`
- `GET /svc/keycore/analytics/usage`
- `GET /svc/keycore/attestation/public-key`
- `GET /svc/keycore/canary`
- `POST /svc/keycore/canary`
- `POST /svc/keycore/canary/`
- `GET /svc/keycore/canary/keys`
- `POST /svc/keycore/canary/keys`
- `GET /svc/keycore/canary/summary`
- `DELETE /svc/keycore/canary/{id}`
- `GET /svc/keycore/canary/{id}`
- `POST /svc/keycore/canary/{id}/trip`
- `GET /svc/keycore/canary/{id}/trips`
- `GET /svc/keycore/ceremony`
- `POST /svc/keycore/ceremony`
- `GET /svc/keycore/ceremony/guardians`
- `POST /svc/keycore/ceremony/guardians`
- `DELETE /svc/keycore/ceremony/guardians/{id}`
- `GET /svc/keycore/ceremony/{id}`
- `POST /svc/keycore/ceremony/{id}/abort`
- `POST /svc/keycore/ceremony/{id}/complete`
- `POST /svc/keycore/ceremony/{id}/shares`
- `POST /svc/keycore/cluster/mek/export`
- `POST /svc/keycore/cluster/mek/import`
- `POST /svc/keycore/cluster/mek/join-key`
- `POST /svc/keycore/compromise/advisories/ingest`
- `GET /svc/keycore/compromise/events`
- `POST /svc/keycore/compromise/events`
- `POST /svc/keycore/compromise/events/{id}/status`
- `POST /svc/keycore/credential-bindings/resolve`
- `DELETE /svc/keycore/credential-bindings/{binding_id}`
- `POST /svc/keycore/crypto/hash`
- `POST /svc/keycore/crypto/random`
- `POST /svc/keycore/enterprise/advanced-encryption/modes`
- `POST /svc/keycore/enterprise/advanced-encryption/search-token`
- `POST /svc/keycore/enterprise/anomaly/scan`
- `GET /svc/keycore/enterprise/audit-chain/anchors`
- `POST /svc/keycore/enterprise/audit-chain/anchors`
- `POST /svc/keycore/enterprise/binding/policies`
- `GET /svc/keycore/enterprise/compliance/dashboard`
- `GET /svc/keycore/enterprise/controls`
- `POST /svc/keycore/enterprise/controls`
- `GET /svc/keycore/enterprise/controls/{category}/{id}`
- `GET /svc/keycore/enterprise/cost/optimization`
- `GET /svc/keycore/enterprise/dspm/events`
- `GET /svc/keycore/enterprise/dspm/findings`
- `POST /svc/keycore/enterprise/dspm/findings`
- `POST /svc/keycore/enterprise/edge/agents`
- `POST /svc/keycore/enterprise/edge/leases`
- `POST /svc/keycore/enterprise/edge/receipts`
- `POST /svc/keycore/enterprise/federation/failovers`
- `POST /svc/keycore/enterprise/federation/mappings`
- `POST /svc/keycore/enterprise/federation/providers`
- `POST /svc/keycore/enterprise/kdf/derive`
- `POST /svc/keycore/enterprise/metadata/profiles`
- `POST /svc/keycore/enterprise/orchestration/runs`
- `POST /svc/keycore/enterprise/orchestration/workflows`
- `POST /svc/keycore/enterprise/sharing/grants`
- `GET /svc/keycore/enterprise/summary`
- `POST /svc/keycore/enterprise/threat/signals`
- `POST /svc/keycore/enterprise/verification/fingerprint`
- `GET /svc/keycore/fips/rng-health`
- `POST /svc/keycore/fips/self-test`
- `GET /svc/keycore/health/summary`
- `GET /svc/keycore/hsm/objects`
- `GET /svc/keycore/hsm/settings`
- `PUT /svc/keycore/hsm/settings`
- `GET /svc/keycore/inventory/dependencies`
- `POST /svc/keycore/inventory/dependencies`
- `GET /svc/keycore/inventory/duplicates`
- `GET /svc/keycore/inventory/keys`
- `GET /svc/keycore/inventory/orphans`
- `POST /svc/keycore/inventory/sync`
- `GET /svc/keycore/keys`
- `POST /svc/keycore/keys`
- `POST /svc/keycore/keys/bulk-delete`
- `POST /svc/keycore/keys/bulk-import`
- `POST /svc/keycore/keys/bulk-rotate`
- `GET /svc/keycore/keys/due-for-lifecycle`
- `POST /svc/keycore/keys/form`
- `POST /svc/keycore/keys/import`
- `GET /svc/keycore/keys/{id}`
- `PUT /svc/keycore/keys/{id}`
- `GET /svc/keycore/keys/{id}/access-policy`
- `PUT /svc/keycore/keys/{id}/access-policy`
- `POST /svc/keycore/keys/{id}/activate`
- `GET /svc/keycore/keys/{id}/approval`
- `PUT /svc/keycore/keys/{id}/approval`
- `POST /svc/keycore/keys/{id}/archive`
- `POST /svc/keycore/keys/{id}/attest`
- `GET /svc/keycore/keys/{id}/credential-bindings`
- `POST /svc/keycore/keys/{id}/credential-bindings`
- `POST /svc/keycore/keys/{id}/deactivate`
- `POST /svc/keycore/keys/{id}/decrypt`
- `POST /svc/keycore/keys/{id}/derive`
- `POST /svc/keycore/keys/{id}/destroy`
- `POST /svc/keycore/keys/{id}/disable`
- `POST /svc/keycore/keys/{id}/encrypt`
- `POST /svc/keycore/keys/{id}/export`
- `PUT /svc/keycore/keys/{id}/export-policy`
- `POST /svc/keycore/keys/{id}/generate-data-key`
- `GET /svc/keycore/keys/{id}/health`
- `POST /svc/keycore/keys/{id}/health/recalculate`
- `GET /svc/keycore/keys/{id}/hsm`
- `GET /svc/keycore/keys/{id}/iv-log`
- `GET /svc/keycore/keys/{id}/iv-log/{ref}`
- `PUT /svc/keycore/keys/{id}/iv-mode`
- `GET /svc/keycore/keys/{id}/kcv`
- `POST /svc/keycore/keys/{id}/kem/decapsulate`
- `POST /svc/keycore/keys/{id}/kem/encapsulate`
- `POST /svc/keycore/keys/{id}/mac`
- `POST /svc/keycore/keys/{id}/rotate`
- `GET /svc/keycore/keys/{id}/rotation-metrics`
- `POST /svc/keycore/keys/{id}/rotation-metrics`
- `POST /svc/keycore/keys/{id}/service-derive`
- `POST /svc/keycore/keys/{id}/sign`
- `POST /svc/keycore/keys/{id}/unwrap`
- `GET /svc/keycore/keys/{id}/usage`
- `PUT /svc/keycore/keys/{id}/usage/limit`
- `POST /svc/keycore/keys/{id}/usage/meter`
- `POST /svc/keycore/keys/{id}/usage/reset`
- `POST /svc/keycore/keys/{id}/verify`
- `POST /svc/keycore/keys/{id}/verify-material`
- `GET /svc/keycore/keys/{id}/versions`
- `DELETE /svc/keycore/keys/{id}/versions/{ver}`
- `GET /svc/keycore/keys/{id}/versions/{ver}`
- `POST /svc/keycore/keys/{id}/versions/{ver}/activate`
- `POST /svc/keycore/keys/{id}/versions/{ver}/deactivate`
- `POST /svc/keycore/keys/{id}/wrap`
- `POST /svc/keycore/keys/{id}/zeroize-verify`
- `GET /svc/keycore/rotation/analytics`
- `GET /svc/keycore/rotation/analytics/overdue`
- `GET /svc/keycore/rotation/policies`
- `POST /svc/keycore/rotation/policies`
- `DELETE /svc/keycore/rotation/policies/{id}`
- `PATCH /svc/keycore/rotation/policies/{id}`
- `POST /svc/keycore/rotation/policies/{id}/trigger`
- `GET /svc/keycore/rotation/runs`
- `GET /svc/keycore/rotation/upcoming`
- `GET /svc/keycore/scheduling/jobs`
- `POST /svc/keycore/scheduling/jobs`
- `DELETE /svc/keycore/scheduling/jobs/{id}`
- `PATCH /svc/keycore/scheduling/jobs/{id}`
- `POST /svc/keycore/system-keys/ensure`
- `GET /svc/keycore/tags`
- `POST /svc/keycore/tags`
- `DELETE /svc/keycore/tags/{name}`
- `POST /svc/keycore/tenants/onboard`
- `GET /svc/keycore/threat/dashboard`
- `GET /svc/keycore/threat/signals`
- `POST /svc/keycore/threat/signals/{id}/ack`

### kmip (`/svc/kmip/`)

- `GET /svc/kmip/kmip/capabilities`
- `GET /svc/kmip/kmip/clients`
- `POST /svc/kmip/kmip/clients`
- `GET /svc/kmip/kmip/clients/decommission-candidates`
- `DELETE /svc/kmip/kmip/clients/{id}`
- `GET /svc/kmip/kmip/clients/{id}`
- `POST /svc/kmip/kmip/clients/{id}/decommission`
- `GET /svc/kmip/kmip/interop/targets`
- `POST /svc/kmip/kmip/interop/targets`
- `DELETE /svc/kmip/kmip/interop/targets/{id}`
- `POST /svc/kmip/kmip/interop/targets/{id}/validate`
- `GET /svc/kmip/kmip/profiles`
- `POST /svc/kmip/kmip/profiles`
- `DELETE /svc/kmip/kmip/profiles/{id}`

### payment (`/svc/payment/`)

- `POST /svc/payment/payment/ap2/evaluate`
- `GET /svc/payment/payment/ap2/profile`
- `PUT /svc/payment/payment/ap2/profile`
- `POST /svc/payment/payment/crypto`
- `GET /svc/payment/payment/crypto/operations`
- `GET /svc/payment/payment/injection/jobs`
- `POST /svc/payment/payment/injection/jobs`
- `POST /svc/payment/payment/injection/jobs/{id}/ack`
- `GET /svc/payment/payment/injection/terminals`
- `POST /svc/payment/payment/injection/terminals`
- `POST /svc/payment/payment/injection/terminals/{id}/challenge`
- `GET /svc/payment/payment/injection/terminals/{id}/jobs/next`
- `POST /svc/payment/payment/injection/terminals/{id}/verify`
- `POST /svc/payment/payment/iso20022/decrypt`
- `POST /svc/payment/payment/iso20022/encrypt`
- `POST /svc/payment/payment/iso20022/lau/generate`
- `POST /svc/payment/payment/iso20022/lau/verify`
- `POST /svc/payment/payment/iso20022/sign`
- `POST /svc/payment/payment/iso20022/verify`
- `GET /svc/payment/payment/keys`
- `POST /svc/payment/payment/keys`
- `GET /svc/payment/payment/keys/{id}`
- `PUT /svc/payment/payment/keys/{id}`
- `POST /svc/payment/payment/keys/{id}/rotate`
- `POST /svc/payment/payment/mac/cmac`
- `POST /svc/payment/payment/mac/iso9797`
- `POST /svc/payment/payment/mac/retail`
- `POST /svc/payment/payment/mac/verify`
- `POST /svc/payment/payment/pin/cvv/compute`
- `POST /svc/payment/payment/pin/cvv/verify`
- `POST /svc/payment/payment/pin/offset/generate`
- `POST /svc/payment/payment/pin/offset/verify`
- `POST /svc/payment/payment/pin/pvv/generate`
- `POST /svc/payment/payment/pin/pvv/verify`
- `POST /svc/payment/payment/pin/translate`
- `GET /svc/payment/payment/policy`
- `PUT /svc/payment/payment/policy`
- `POST /svc/payment/payment/tr31/create`
- `GET /svc/payment/payment/tr31/key-usages`
- `POST /svc/payment/payment/tr31/parse`
- `POST /svc/payment/payment/tr31/translate`
- `POST /svc/payment/payment/tr31/validate`

### policy (`/svc/policy/`)

- `GET /svc/policy/policies`
- `POST /svc/policy/policies`
- `POST /svc/policy/policies/dry-run`
- `POST /svc/policy/policies/lint`
- `DELETE /svc/policy/policies/{id}`
- `GET /svc/policy/policies/{id}`
- `PUT /svc/policy/policies/{id}`
- `GET /svc/policy/policies/{id}/versions`
- `GET /svc/policy/policies/{id}/versions/{version}`
- `POST /svc/policy/policy/evaluate`
- `GET /svc/policy/policy/quota/{tenant_id}`
- `PUT /svc/policy/policy/quota/{tenant_id}`

### posture (`/svc/posture/`)

- `GET /svc/posture/leaks/findings`
- `PATCH /svc/posture/leaks/findings/{id}`
- `GET /svc/posture/leaks/jobs`
- `GET /svc/posture/leaks/targets`
- `POST /svc/posture/leaks/targets`
- `DELETE /svc/posture/leaks/targets/{id}`
- `POST /svc/posture/leaks/targets/{id}/scan`
- `GET /svc/posture/posture/actions`
- `POST /svc/posture/posture/actions/{id}/execute`
- `GET /svc/posture/posture/dashboard`
- `POST /svc/posture/posture/events`
- `POST /svc/posture/posture/events/batch`
- `GET /svc/posture/posture/findings`
- `PUT /svc/posture/posture/findings/{id}/status`
- `GET /svc/posture/posture/health`
- `POST /svc/posture/posture/ingest/audit`
- `GET /svc/posture/posture/risk`
- `GET /svc/posture/posture/risk/history`
- `POST /svc/posture/posture/scan`

### pqc (`/svc/pqc/`)

- `GET /svc/pqc/pqc/cbom/export`
- `GET /svc/pqc/pqc/inventory`
- `GET /svc/pqc/pqc/migration/plans`
- `POST /svc/pqc/pqc/migration/plans`
- `GET /svc/pqc/pqc/migration/plans/{id}`
- `POST /svc/pqc/pqc/migration/plans/{id}/execute`
- `POST /svc/pqc/pqc/migration/plans/{id}/rollback`
- `GET /svc/pqc/pqc/migration/plans/{id}/runs`
- `GET /svc/pqc/pqc/migration/report`
- `GET /svc/pqc/pqc/policy`
- `PUT /svc/pqc/pqc/policy`
- `GET /svc/pqc/pqc/readiness`
- `POST /svc/pqc/pqc/scan`
- `GET /svc/pqc/pqc/scans`
- `GET /svc/pqc/pqc/scans/{id}`
- `GET /svc/pqc/pqc/timeline`

### reporting (`/svc/reporting/`)

- `GET /svc/reporting/alerts`
- `PUT /svc/reporting/alerts/`
- `POST /svc/reporting/alerts/bulk/acknowledge`
- `POST /svc/reporting/alerts/bulk/resolve`
- `GET /svc/reporting/alerts/channels`
- `PUT /svc/reporting/alerts/channels`
- `GET /svc/reporting/alerts/feed`
- `GET /svc/reporting/alerts/rules`
- `POST /svc/reporting/alerts/rules`
- `DELETE /svc/reporting/alerts/rules/{id}`
- `PUT /svc/reporting/alerts/rules/{id}`
- `GET /svc/reporting/alerts/severity-config`
- `PUT /svc/reporting/alerts/severity-config`
- `GET /svc/reporting/alerts/stats`
- `GET /svc/reporting/alerts/stats/mttd`
- `GET /svc/reporting/alerts/stats/mttr`
- `GET /svc/reporting/alerts/stats/top-sources`
- `GET /svc/reporting/alerts/unread`
- `GET /svc/reporting/alerts/{id}`
- `GET /svc/reporting/incidents`
- `GET /svc/reporting/incidents/{id}`
- `PUT /svc/reporting/incidents/{id}/assign`
- `PUT /svc/reporting/incidents/{id}/status`
- `POST /svc/reporting/reports/generate`
- `GET /svc/reporting/reports/jobs`
- `DELETE /svc/reporting/reports/jobs/{id}`
- `GET /svc/reporting/reports/jobs/{id}`
- `GET /svc/reporting/reports/jobs/{id}/download`
- `GET /svc/reporting/reports/scheduled`
- `POST /svc/reporting/reports/scheduled`
- `GET /svc/reporting/reports/templates`
- `GET /svc/reporting/telemetry/errors`
- `POST /svc/reporting/telemetry/errors`

### sbom (`/svc/sbom/`)

- `GET /svc/sbom/cbom/diff`
- `POST /svc/sbom/cbom/generate`
- `GET /svc/sbom/cbom/history`
- `GET /svc/sbom/cbom/latest`
- `GET /svc/sbom/cbom/pqc-readiness`
- `GET /svc/sbom/cbom/summary`
- `GET /svc/sbom/cbom/{id}`
- `GET /svc/sbom/cbom/{id}/export`
- `GET /svc/sbom/sbom/advisories`
- `POST /svc/sbom/sbom/advisories`
- `DELETE /svc/sbom/sbom/advisories/{id}`
- `GET /svc/sbom/sbom/diff`
- `POST /svc/sbom/sbom/generate`
- `GET /svc/sbom/sbom/history`
- `GET /svc/sbom/sbom/latest`
- `GET /svc/sbom/sbom/vulnerabilities`
- `GET /svc/sbom/sbom/{id}`
- `GET /svc/sbom/sbom/{id}/export`

### secrets (`/svc/secrets/`)

- `GET /svc/secrets/secrets`
- `POST /svc/secrets/secrets`
- `POST /svc/secrets/secrets/generate/keypair`
- `POST /svc/secrets/secrets/generate/ssh_key`
- `GET /svc/secrets/secrets/stats`
- `DELETE /svc/secrets/secrets/{id}`
- `GET /svc/secrets/secrets/{id}`
- `PUT /svc/secrets/secrets/{id}`
- `GET /svc/secrets/secrets/{id}/audit`
- `POST /svc/secrets/secrets/{id}/rotate`
- `GET /svc/secrets/secrets/{id}/value`
- `GET /svc/secrets/secrets/{id}/versions`
- `POST /svc/secrets/v1/auth/token/lookup-self`
- `GET /svc/secrets/v1/sys/health`
- `GET /svc/secrets/v1/sys/seal-status`
- `DELETE /svc/secrets/v1/{mount}/data/{path...}`
- `GET /svc/secrets/v1/{mount}/data/{path...}`
- `POST /svc/secrets/v1/{mount}/data/{path...}`
- `GET /svc/secrets/v1/{mount}/metadata/{path...}`
- `DELETE /svc/secrets/v1/{mount}/{path...}`
- `GET /svc/secrets/v1/{mount}/{path...}`
- `POST /svc/secrets/v1/{mount}/{path...}`

### signing (`/svc/signing/`)

- `POST /svc/signing/signing/blob`
- `POST /svc/signing/signing/git`
- `GET /svc/signing/signing/profiles`
- `POST /svc/signing/signing/profiles`
- `DELETE /svc/signing/signing/profiles/{id}`
- `PUT /svc/signing/signing/profiles/{id}`
- `GET /svc/signing/signing/records`
- `GET /svc/signing/signing/settings`
- `PUT /svc/signing/signing/settings`
- `GET /svc/signing/signing/summary`
- `POST /svc/signing/signing/verify`

### workload (`/svc/workload/`)

- `GET /svc/workload/workload-identity/federation`
- `POST /svc/workload/workload-identity/federation`
- `DELETE /svc/workload/workload-identity/federation/{id}`
- `PUT /svc/workload/workload-identity/federation/{id}`
- `GET /svc/workload/workload-identity/graph`
- `GET /svc/workload/workload-identity/issuances`
- `POST /svc/workload/workload-identity/issue`
- `GET /svc/workload/workload-identity/registrations`
- `POST /svc/workload/workload-identity/registrations`
- `DELETE /svc/workload/workload-identity/registrations/{id}`
- `PUT /svc/workload/workload-identity/registrations/{id}`
- `GET /svc/workload/workload-identity/settings`
- `PUT /svc/workload/workload-identity/settings`
- `GET /svc/workload/workload-identity/summary`
- `POST /svc/workload/workload-identity/token/exchange`
- `GET /svc/workload/workload-identity/usage`

<!-- route-index:end -->
