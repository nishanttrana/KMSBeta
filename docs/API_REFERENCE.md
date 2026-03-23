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
| mpc | /svc/mpc/ | MPC groups, FROST threshold signing |
| cluster | /svc/cluster/ | Cluster nodes, HSM registration |
| qkd | /svc/qkd/ | Quantum key distribution links |
| qrng | /svc/qrng/ | Quantum random number generation |
| secrets | /svc/secrets/ | Secret vault |
| sbom | /svc/sbom/ | SBOM/CBOM inventory |
| ai | /svc/ai/ | AI guidance and recommendations |

---

## Conventions

**Base URL**: `http://{host}` — use `http://localhost:5173` for local dev

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
export TOKEN=$(curl -s -X POST http://localhost:5173/svc/auth/auth/login \
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

### GET /svc/auth/auth/session

Bearer required. Response: `userId`, `username`, `email`, `tenantId`, `roles[]`, `issuedAt`, `expiresAt`, `mfaVerified`, `clientId`

---

### POST /svc/auth/auth/mfa/totp/setup

Bearer required. No body. Response: `secret` (base32), `qrCodeUrl` (data URI), `backupCodes[10]`

---

### POST /svc/auth/auth/mfa/totp/verify

Bearer required. Body: `code` (6-digit TOTP). Response: `verified` (boolean), `backupCodesRemaining` (int)

---

### POST /svc/auth/auth/client-token

Issues sender-constrained client tokens. Supports mTLS (`oauth_mtls`), DPoP, HTTP Message Signature binding.

Body: `clientId`, `clientSecret` (for secret mode), `grantType: client_credentials`, `scope`

Response: `token`, `expiresAt`, `tokenType`, `boundThumbprint` (if sender-constrained)

---

### GET /svc/auth/auth/rest-client-security/summary

Bearer, admin. Response: `totalClients`, `senderConstrainedClients`, `legacyClients`, `replayProtectedClients`, `replayViolations`, `signatureFailures`, `unsignedRequestRejects`

---

### GET /svc/auth/users

Bearer, admin. Query: `pageSize`, `pageToken`, `search`, `role`, `tenantId`, `locked`. Response: paginated UserSummary[].

UserSummary fields: id, username, email, displayName, roles[], tenantId, lastLoginAt, locked, mfaEnabled, createdAt

---

### POST /svc/auth/users

Bearer, admin. Body: `username`, `email`, `displayName`, `password`, `roles[]`, `tenantId`, `sendWelcomeEmail`. Response 201: User.

```bash
curl -s -X POST http://localhost:5173/svc/auth/users \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"username":"bob","email":"bob@example.com","password":"SecurePass123!","roles":["operator"],"tenantId":"root"}'
```

---

### GET/PATCH/DELETE /svc/auth/users/{id}

GET returns full User. PATCH accepts `displayName`, `email`, `roles[]`, `locked`. DELETE returns 204.

---

### POST /svc/auth/users/{id}/reset-password

Body: `newPassword` OR `sendResetEmail: true`. Response 200: `{"message": "Password reset successful"}`

---

### POST /svc/auth/users/{id}/lock / .../unlock

No body. Returns updated User.

---

### GET /svc/auth/roles

Response: `Role[]` — name, description, permissions[].

---

### GET /svc/auth/tenants / POST /svc/auth/tenants / GET/PATCH/DELETE /svc/auth/tenants/{id}

Create body: `id` (slug), `name`, `plan`, `config` (maxKeys, maxUsers, enforceMfa, sessionTimeoutMinutes, allowedIpRanges[]).

```bash
curl -s -X POST http://localhost:5173/svc/auth/tenants \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"id":"acme-corp","name":"Acme Corporation","plan":"enterprise","config":{"maxKeys":10000,"enforceMfa":true}}'
```

---

### GET/POST/PATCH/DELETE /svc/auth/idp / POST /svc/auth/idp/{id}/test

Types: `ldap`, `saml`, `oidc`, `entra`. OIDC fields: issuerUrl, clientId, clientSecret, scopes[], usernameClaim, groupsClaim. Test returns `{"success": true, "latencyMs": 42}`.

---

### GET/PUT /svc/auth/scim/settings

Settings: `enabled`, `defaultRole`, `deprovisionMode` (disable/delete), `groupRoleMappingActive`, `requirePasswordChangeOnFirstLogin`

---

### POST /svc/auth/scim/settings/rotate-token

Returns raw SCIM bearer token once. Response: `{"token": "...", "rotatedAt": "..."}`

---

### GET /svc/auth/scim/summary

Response: `managedUsers`, `managedGroups`, `memberships`, `roleMappedGroups`, `lastProvisionedAt`, `lastDeprovisionedAt`

---

### GET/POST/PUT/PATCH/DELETE /svc/auth/clients / POST /svc/auth/clients/{id}/rotate-secret

`clientSecret` shown once on create and rotate. Body: name, tenantId, roles[], allowedIps[], tokenTtlSeconds, authMode (secret/mtls/dpop/http_message_signature).

---

### SCIM 2.0 (`/svc/auth/scim/v2/`)

Auth: SCIM bearer token. Discovery: ServiceProviderConfig, Schemas, ResourceTypes. RFC 7644 User and Group CRUD. PATCH uses SCIM patch operations (add/replace/remove members).

---

## Service 2: Keycore (`/svc/keycore/`)

Key lifecycle management and all cryptographic operations.

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
| algorithm | string | Yes | Algorithm |
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
curl -s -X POST http://localhost:5173/svc/keycore/keys \
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

### PATCH /svc/keycore/keys/{id}

Updatable: `name`, `tags`, `metadata`, `expiresAt`, `rotationPolicy`, `exportPolicy`, `interfacePolicy`

---

### DELETE /svc/keycore/keys/{id}

Schedules deletion. Sets `state: PENDING_DELETION`.

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
curl -s -X POST http://localhost:5173/svc/keycore/keys/3fa85f64-5717-4562-b3fc-2c963f66afa6/rotate \
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
curl -s -X POST http://localhost:5173/svc/keycore/keys/3fa85f64-5717-4562-b3fc-2c963f66afa6/encrypt \
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

---

### POST /svc/keycore/keys/{id}/verify

Body: `message`, `signature`, `messageType`, `algorithm`, `keyVersion`. Response: `valid` (boolean), `keyId`, `keyVersion`, `algorithm`

---

### POST /svc/keycore/keys/{id}/wrap

Body: `targetKeyId` (UUID) OR `keyMaterial` (base64), `algorithm` (AES-KW/AES-KWP/RSA-OAEP). Response: `wrappedKey`, `algorithm`, `wrappingKeyId`, `wrappingKeyVersion`

---

### POST /svc/keycore/keys/{id}/unwrap

Body: `wrappedKey`, `algorithm`, `keySpec` (name, algorithm, purpose, tags). Response: new Key object.

---

### POST /svc/keycore/keys/{id}/derive

Body: `algorithm` (HKDF-SHA256/384/512, PBKDF2-SHA256, SP800-108-CTR), `salt`, `info`, `outputLength` (16–64), `outputKeySpec` (optional)

Response: Key object or `derivedKeyMaterial` (base64)

---

### POST /svc/keycore/keys/{id}/encapsulate (KEM)

For ML-KEM keys. No body. Response: `ciphertext` (KEM ciphertext), `sharedSecret`, `algorithm`

---

### POST /svc/keycore/keys/{id}/hash

Body: `data` (base64), `algorithm` (SHA-256/384/512, SHA3-256/512, BLAKE2b-256). Response: `hash` (base64), `algorithm`

---

### POST /svc/keycore/keys/{id}/mac

Body: `data`, `operation` (generate/verify), `mac` (for verify), `algorithm` (HMAC-SHA256/384/512, CMAC). Response: `mac` or `valid`.

---

### POST /svc/keycore/keys/{id}/export

Body: `format` (raw/pkcs8/spki/jwk/pkcs12), `wrappingKeyId` (if required). Response: `keyMaterial` (base64) or `jwk`.

---

### POST /svc/keycore/keys/{id}/reencrypt

Body: `ciphertext`, `iv`, `aad`, `targetKeyId` (optional), `targetKeyVersion`. Response: new `ciphertext`, `iv`, `keyId`, `keyVersion`

---

### GET /svc/keycore/keys/{id}/versions

Response: `KeyVersion[]` — version, state, fingerprint, createdAt, retiredAt

---

### GET /svc/keycore/keys/{id}/versions/{version}

Single version detail.

---

### GET/PUT /svc/keycore/keys/{id}/policy

Policy: `grants[]` — subject, subjectType (user/client/role), operations[], conditions

---

### POST /svc/keycore/random

Body: `size` (1–65536), `encoding` (base64/hex), `source` (csprng/qrng/hsm). Response: `random`, `source`, `size`, `generatedAt`

```bash
curl -s -X POST http://localhost:5173/svc/keycore/random \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"size":32,"encoding":"hex","source":"csprng"}'
```

---

## Service 3: Certs (`/svc/certs/`)

PKI, CA management, certificate lifecycle, enrollment protocols (ACME, EST, SCEP), CRL/OCSP, renewal intelligence, STAR subscriptions.

---

### CA Object Schema

id, name, type (root/intermediate/issuing), keyId, subject (cn, o, ou, c, st, l), validity (notBefore, notAfter), constraints (pathLen, permittedDNS[], permittedIP[]), crlDistributionPoints[], ocspUrls[], issuingCaId, tenantId, state, fingerprint, pem, createdAt

---

### GET /svc/certs/cas / POST /svc/certs/cas

Create: `name`, `type`, `keyId`, `subject`, `validityDays`, `pathLen`, `permittedDNS[]`, `permittedIP[]`, `crlUrls[]`, `ocspUrls[]`, `issuingCaId` (required for non-root)

```bash
curl -s -X POST http://localhost:5173/svc/certs/cas \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"Acme Issuing CA","type":"issuing","keyId":"3fa85f64-5717-4562-b3fc-2c963f66afa6","subject":{"cn":"Acme Issuing CA","o":"Acme Corp","c":"US"},"validityDays":1825,"issuingCaId":"root-ca-id"}'
```

---

### GET/PATCH/DELETE /svc/certs/cas/{id}

PATCH: name, crlUrls, ocspUrls.

---

### POST /svc/certs/cas/{id}/issue

Body: `csr` (PEM), `profileId`, `expiresAt`, `san` (dnsNames[], ipAddresses[], emailAddresses[], uris[]), `customExtensions[]`

Response: Certificate — id, pem, chain, subject, san, notBefore, notAfter, serialNumber, fingerprint, revoked, issuingCaId, keyUsage[], extendedKeyUsage[]

---

### GET/POST /svc/certs/certificates

List (query: caId, state, expiresBeforeDays, search) or import external cert.

---

### GET/DELETE /svc/certs/certificates/{id}

---

### POST /svc/certs/certificates/{id}/revoke

Body: `reason` (unspecified/keyCompromise/caCompromise/affiliationChanged/superseded/cessationOfOperation/certificateHold), `comment`

```bash
curl -s -X POST http://localhost:5173/svc/certs/certificates/cert-abc123/revoke \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"reason":"keyCompromise","comment":"Key compromised in INC-2025-042"}'
```

---

### POST /svc/certs/certificates/{id}/renew

Body: `validityDays` (optional). Response: new Certificate.

---

### GET /svc/certs/certificates/{id}/chain

Response: `chain` (full PEM, leaf to root)

---

### GET/POST/PATCH/DELETE /svc/certs/profiles

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

- `POST /svc/certs/est/{caLabel}/.well-known/est/simpleenroll` — EST enrollment (PKCS#10)
- `POST /svc/certs/est/{caLabel}/.well-known/est/simplereenroll` — EST re-enrollment
- `POST /svc/certs/scep/{profile}` — SCEP PKIOperation
- `GET /svc/certs/crl/{caId}` — DER CRL download
- `POST /svc/certs/ocsp/{caId}` — OCSP responder (RFC 6960)

---

## Service 4: Audit (`/svc/audit/`)

Immutable, Merkle-chained audit log with SIEM export.

### AuditEvent Object

id, tenantId, timestamp, action, actorType (user/client/system), actorId, actorName, actorIp, resourceType, resourceId, resourceName, outcome (success/failure/denied), errorCode, requestId, merkleHash, prevHash, metadata

---

### GET /svc/audit/events

Bearer, roles: auditor or admin.

Query: `action`, `actorId`, `resourceId`, `resourceType`, `outcome`, `startTime`, `endTime`, `pageSize`, `pageToken`

```bash
curl -s "http://localhost:5173/svc/audit/events?action=audit.key&outcome=failure&startTime=2025-03-01T00:00:00Z" \
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

### GET /svc/audit/events/{id}

Single event.

---

### GET /svc/audit/events/{id}/proof

Merkle inclusion proof. Response: `eventId`, `merkleRoot`, `proof[]`, `proofIndex`, `chainHeight`

---

### POST /svc/audit/verify

Body: `startEventId`, `endEventId`. Response: `valid`, `eventsChecked`, `chainIntact`, `errors[]`, `verifiedAt`

---

### GET /svc/audit/chain/status

Response: `leader`, `lastEventId`, `lastEventAt`, `chainHash`, `totalEvents`, `healthy`

---

### GET /svc/audit/export/targets / POST /svc/audit/export/targets

List or create SIEM export targets. Fields: name, type (siem_syslog/siem_http/splunk/elasticsearch/s3/azure_sentinel), endpoint, format (cef/leef/json/raw), credentials, filters, batchSize, flushIntervalSeconds

```bash
curl -s -X POST http://localhost:5173/svc/audit/export/targets \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"Splunk Cloud","type":"splunk","endpoint":"https://splunk.acme.example:8088/services/collector","format":"json","credentials":{"token":"splunk-hec-token"},"batchSize":200}'
```

---

### PATCH/DELETE /svc/audit/export/targets/{id}

### POST /svc/audit/export/targets/{id}/test

No body. Response: `{"success": true, "latencyMs": 123}`

### POST /svc/audit/export/targets/{id}/enable / .../disable

No body. Returns updated ExportTarget.

---

## Service 5: Governance (`/svc/governance/`)

Multi-party approvals, encrypted backup/restore, emergency bypass, system state.

---

### GET /svc/governance/policies / POST /svc/governance/policies

GovernancePolicy: name, triggerActions[], minApprovers, approverGroups[], timeoutHours, notificationChannels[], emergencyBypassAllowed

```bash
curl -s -X POST http://localhost:5173/svc/governance/policies \
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

### GET/PATCH/DELETE /svc/governance/policies/{id}

---

### GET /svc/governance/approvals

Query: `status` (pending/approved/rejected/expired), `pageSize`, `pageToken`

---

### GET /svc/governance/approvals/{id}

ApprovalRequest: id, status, requestedBy, requestedAt, operation (type, resourceId, resourceType, parameters), policyId, approvals[], rejections[], resolvedAt, expiresAt

---

### POST /svc/governance/approvals/{id}/approve

Body: `comment` (optional). Proceeds automatically if minApprovers threshold met.

```bash
curl -s -X POST http://localhost:5173/svc/governance/approvals/req-01ARZ3/approve \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"comment":"Approved — matches INC-2025-042 remediation plan"}'
```

---

### POST /svc/governance/approvals/{id}/reject

Body: `reason` (required). Response: updated ApprovalRequest with `status: rejected`.

---

### POST /svc/governance/approvals/{id}/bypass

Requires breakglass permission. Body: `justification` (required). Emits high-severity audit event.

---

### GET /svc/governance/backup/targets / POST /svc/governance/backup/targets

BackupTarget: name, type (s3/azure-blob/gcs/sftp/local), config, encryptionKeyId, scheduleExpression

---

### PATCH/DELETE /svc/governance/backup/targets/{id}

---

### POST /svc/governance/backup/run

Body: `targetId`, `scope` (full/incremental). Response 202: `archiveId`, `jobId`, `status`

---

### GET /svc/governance/backup/archives / GET /svc/governance/backup/archives/{id}

Archive includes `backupCoverage` metadata listing preserved capability classes.

---

### POST /svc/governance/restore

Body: `archiveId`, `shamirShares[]` (M-of-N), `dryRun` (boolean). Response 202: `restoreId`, `status`

---

### GET /svc/governance/restore/{id}/status

Response: `restoreId`, `status`, `restoredObjects`, `errors[]`, `completedAt`

---

### GET /svc/governance/system/state

Response: `status`, `services` (map of service → up/down), `pendingApprovals`, `lastBackupAt`, `clusterNodes`, `healthyNodes`, `checkedAt`

---

## Service 6: Compliance (`/svc/compliance/`)

Framework-oriented compliance scoring, control assessments, delta tracking.

---

### GET /svc/compliance/frameworks

Response: Framework[] — id, name, description, controlCount, lastAssessedAt, score, passCount, failCount

```bash
curl -s http://localhost:5173/svc/compliance/frameworks \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

Supported frameworks: FIPS-140-3, PCI-DSS-v4, SOC2, ISO-27001, NIST-CSF-2, HIPAA, GDPR

---

### GET /svc/compliance/frameworks/{id} / GET /svc/compliance/frameworks/{id}/controls

Framework detail with controls: id, title, description, status (pass/fail/not_applicable), evidence, remediationSteps

---

### POST /svc/compliance/assessments

Body: `frameworkId`, `scope` (tenant/full), `notes`, `recompute` (boolean). Response 202: assessmentId, status.

---

### GET /svc/compliance/assessments

Query: `frameworkId`, `status`, `pageSize`, `pageToken`. Response: paginated Assessment[].

---

### GET /svc/compliance/assessments/{id}

Assessment: id, frameworkId, status, score, passCount, failCount, controls[], startedAt, completedAt, notes

---

### GET /svc/compliance/assessments/{id}/controls

ControlResult[]: id, title, status, evidence, remediationSteps, lastCheckedAt

---

### GET /svc/compliance/assessments/{id}/score

Response: `{"assessmentId": "...", "frameworkId": "...", "score": 87.5, "passCount": 56, "failCount": 8}`

---

### POST /svc/compliance/assessments/{id}/export

Body: `format` (pdf/json/csv). Response 202: `downloadUrl`, `expiresAt`

---

### POST /svc/compliance/assessments/{id}/refresh

Re-runs assessment. Response 202: updated status.

---

### GET /svc/compliance/assessment/delta

Compares latest vs previous assessment.

Response: `addedFindings`, `resolvedFindings`, `recoveredDomains[]`, `regressedDomains[]`, `newFailingConnectors[]`

---

### GET /svc/compliance/assessment/history

Query: `frameworkId`, `startTime`, `endTime`, `granularity` (day/week/month). Response: trend data points.

---

### POST /svc/compliance/assessment/run

Body: `frameworkId`, `templateId`, `scope`, `recompute`. Response 202: assessment job.

---

## Service 7: Posture (`/svc/posture/`)

Risk findings, risk drivers, blast radius, remediation actions, drift detection.

---

### GET /svc/posture/findings

Query: `severity`, `findingType`, `status`, `resourceType`, `resourceId`, `pageSize`, `pageToken`

Finding: id, severity, findingType, title, description, affectedResourceType, affectedResourceId, remediationSteps[], status, riskDrivers, blastRadius, owner, dueDate, createdAt

```bash
curl -s "http://localhost:5173/svc/posture/findings?severity=critical&status=open" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### GET /svc/posture/findings/{id}

Full finding with riskDrivers and blastRadius.

---

### PATCH /svc/posture/findings/{id}

Update: `status`, `owner`, `dueDate`

---

### POST /svc/posture/findings/{id}/acknowledge

Body: `comment`. Response: updated Finding with `status: acknowledged`.

---

### POST /svc/posture/findings/{id}/resolve

Body: `resolutionNote` (required). Response: updated Finding with `status: resolved`.

---

### POST /svc/posture/findings/{id}/suppress

Body: `reason`, `expiresAt`. Response: updated Finding with `status: suppressed`.

---

### GET /svc/posture/score

Response: `score`, `riskLevel`, `criticalFindings`, `highFindings`, `mediumFindings`, `lowFindings`, `calculatedAt`

---

### GET /svc/posture/score/history

Query: `startTime`, `endTime`, `granularity` (hour/day/week). Response: time series.

---

### GET /svc/posture/dashboard

Response: `riskDrivers[]`, `remediationCockpit`, `blastRadius`, `scenarioSimulator`, `validationBadges[]`, `slaOverview`

---

### GET /svc/posture/actions

Action[]: id, findingId, title, priority, impactEstimate, rollbackHint, blastRadius, status

---

### POST /svc/posture/actions/{id}/execute

Executes approved remediation. Response 202: `actionId`, `status: executing`

---

### POST /svc/posture/scan

Triggers full posture scan. Response 202: `scanId`, `status: running`

---

### GET /svc/posture/rules / POST /svc/posture/rules / PATCH/DELETE /svc/posture/rules/{id}

PostureRule: name, severity, findingType, condition (CEL expression), remediationTemplate, enabled

```bash
curl -s -X POST http://localhost:5173/svc/posture/rules \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"Key Without Rotation Policy","severity":"high","findingType":"key_no_rotation","condition":"key.rotationPolicy == null && key.state == \"ACTIVE\"","remediationTemplate":"Add a rotation policy with intervalDays <= 365"}'
```

---

## Service 8: Reporting (`/svc/reporting/`)

Alert rules, alert history, report generation, scheduled delivery.

---

### GET /svc/reporting/alert-rules / POST /svc/reporting/alert-rules

AlertRule: name, conditionType (threshold/pattern/anomaly/absence), conditionConfig, severity, actions[] (email/webhook/pagerduty/opsgenie/slack), throttleMinutes, enabled

```bash
curl -s -X POST http://localhost:5173/svc/reporting/alert-rules \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"Mass Decrypt Alert","conditionType":"threshold","conditionConfig":{"metric":"decrypt_operations","window":"5m","threshold":1000},"severity":"high","actions":[{"type":"slack","config":{"webhookUrl":"https://hooks.slack.com/services/..."}}]}'
```

---

### GET/PATCH/DELETE /svc/reporting/alert-rules/{id} / POST /svc/reporting/alert-rules/{id}/test

Test fires a test alert. Response: `{"success": true, "deliveredTo": ["slack"], "latencyMs": 245}`

---

### GET /svc/reporting/alerts

Query: `ruleId`, `severity`, `acknowledged`, `startTime`, `endTime`. Response: paginated Alert[].

Alert: id, ruleId, severity, triggeredAt, summary, acknowledged, acknowledgedBy, acknowledgedAt

---

### GET /svc/reporting/alerts/{id} / POST /svc/reporting/alerts/{id}/acknowledge

Acknowledge body: `comment`. Response: updated Alert.

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

### GET /svc/reporting/reports / POST /svc/reporting/reports

Report: name, type (key-inventory/access-summary/compliance-trend/audit-volume/evidence_pack), params, format (pdf/csv/json), status, downloadUrl

```bash
curl -s -X POST http://localhost:5173/svc/reporting/reports \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"Q1 Key Inventory","type":"key-inventory","params":{"startDate":"2025-01-01","endDate":"2025-03-31"},"format":"pdf"}'
```

---

### GET /svc/reporting/reports/{id} / GET /svc/reporting/reports/{id}/download

---

### GET /svc/reporting/report-templates

Includes `evidence_pack` template for one-click audit export.

---

### POST /svc/reporting/reports/generate

Body: `templateId` (use `evidence_pack` for full audit package), `params`, `format`

---

### GET /svc/reporting/scheduled / POST /svc/reporting/scheduled / PATCH/DELETE /svc/reporting/scheduled/{id}

ScheduledReport: reportConfig, schedule (cron), delivery (type: email/s3/webhook, config), enabled, lastRunAt, nextRunAt

```bash
curl -s -X POST http://localhost:5173/svc/reporting/scheduled \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"reportConfig":{"name":"Weekly Audit Summary","type":"audit-volume","format":"pdf"},"schedule":"0 8 * * MON","delivery":{"type":"email","config":{"recipients":["security@acme.example"]}},"enabled":true}'
```

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
curl -s "http://localhost:5173/svc/workload/workload-identity/settings?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### PUT /svc/workload/workload-identity/settings

Updates workload identity settings. Body: same fields as GET response (excluding read-only).

---

### POST /svc/workload/workload-identity/svid/x509

Issues an X.509 SVID for a workload.

**Request Body**: `spiffeId` (string), `attestorId` (string), `attestationEvidence` (object), `ttlSeconds` (int)

**Response 200**: `svid` (PEM certificate), `privateKey` (PEM), `bundle` (trust bundle PEM), `spiffeId`, `expiresAt`

---

### POST /svc/workload/workload-identity/svid/jwt

Issues a JWT-SVID.

**Request Body**: `spiffeId`, `audiences[]`, `attestorId`, `attestationEvidence`, `ttlSeconds`

**Response 200**: `token` (JWT), `spiffeId`, `expiresAt`

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
curl -s -X POST http://localhost:5173/svc/workload/workload-identity/token/exchange \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"subjectToken":"eyJhbGc...","subjectTokenType":"urn:ietf:params:oauth:token-type:jwt","requestedScopes":["encrypt","decrypt"]}'
```

---

### GET /svc/workload/workload-identity/trust-bundles

Returns trust bundles for the tenant's trust domain.

**Response 200**: `{"trustDomain": "spiffe://acme.example", "x509Authorities": ["PEM..."], "jwtAuthorities": [...]}`

---

### GET /svc/workload/workload-identity/registrations / POST /svc/workload/workload-identity/registrations

Registration: spiffeId, attestorId, selectors[], ttlSeconds, allowedOperations[], parentId

---

### GET/PATCH/DELETE /svc/workload/workload-identity/registrations/{id}

---

### GET /svc/workload/workload-identity/attestors / POST /svc/workload/workload-identity/attestors

Attestor: name, type (aws-iid/gcp-iit/azure-msi/kubernetes/tpm/oidc), config, enabled

---

### GET/PATCH/DELETE /svc/workload/workload-identity/attestors/{id}

---

### GET /svc/workload/workload-identity/policies / POST /svc/workload/workload-identity/policies

Policy: name, spiffeIdPattern (glob), allowedOperations[], keyConstraints, ttlSeconds

---

### GET /svc/workload/workload-identity/graph

Returns the workload identity relationship graph: trust domain, issued SVIDs, registration counts, expiry states.

---

## Service 10: Confidential (`/svc/confidential/`)

TEE attestation verification and attested key release. Keys released only to measured runtimes.

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
curl -s "http://localhost:5173/svc/confidential/confidential/policy?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### PUT /svc/confidential/confidential/policy

Updates the confidential compute policy. Body: same fields as GET response.

---

### POST /svc/confidential/confidential/attest/key-release

Evaluates attestation evidence and, if valid, releases the requested key.

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| keyId | string | Yes | Key to release |
| operation | string | Yes | decrypt / sign / unwrap |
| attestationProvider | string | Yes | Provider type |
| attestationDocument | string | Yes | Base64-encoded attestation document |
| nonce | string | Conditional | Freshness nonce (required if policy.requireNonce) |
| justification | string | No | Access justification code |

**Response 200**: If allowed, includes `token` (short-lived token bound to attested context) or direct operation result.

```bash
curl -s -X POST http://localhost:5173/svc/confidential/confidential/attest/key-release \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"keyId":"3fa85f64-5717-4562-b3fc-2c963f66afa6","operation":"decrypt","attestationProvider":"aws-nitro","attestationDocument":"base64_document","nonce":"random-nonce-123"}'
```

Response:
```json
{
  "decision": "allow",
  "keyId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "token": "attested_ephemeral_token",
  "tokenExpiresAt": "2025-03-15T14:32:00Z",
  "measurementVerified": true,
  "provider": "aws-nitro"
}
```

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
curl -s "http://localhost:5173/svc/pqc/pqc/policy?tenant_id=root" \
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

### GET /svc/pqc/pqc/inventory/{id}

Single inventory item with full algorithm detail.

---

### GET /svc/pqc/pqc/algorithms

Lists all supported algorithms with PQC classification.

**Response 200**: `Algorithm[]` — name, family, keySize, pqcReady, deprecated, nistStatus, recommendedReplacement

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

### POST /svc/pqc/pqc/migration/plan

Creates a PQC migration plan.

**Request Body**: `scope` (full/keys/certs/interfaces), `targetMode` (hybrid/pqc-only), `targetDate`

**Response 201**: Migration plan — id, status, totalItems, itemsToMigrate, estimatedEffort, phases[], createdAt

---

### GET /svc/pqc/pqc/migration/plans / GET /svc/pqc/pqc/migration/plan/{id}

List or get migration plans.

---

### GET /svc/pqc/pqc/migration/report

Returns the current migration status report.

**Response 200**: `{"migratedCount": 8, "inProgressCount": 3, "remainingCount": 31, "lastUpdatedAt": "..."}`

---

### POST /svc/pqc/pqc/assess

Triggers a full PQC readiness assessment. Response 202: `assessmentId`, `status`.

---

### GET /svc/pqc/pqc/findings

Returns PQC-specific posture findings. Query: `severity`, `algorithmFamily`, `pageSize`, `pageToken`.

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
curl -s "http://localhost:5173/svc/keyaccess/key-access/settings?tenant_id=root" \
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
curl -s -X POST http://localhost:5173/svc/keyaccess/key-access/codes \
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

---

### GET /svc/dataprotect/schemes / POST /svc/dataprotect/schemes

Tokenization scheme: name, format (preserve-format/random/hash), algorithm, keyId, preservePrefix, preserveSuffix, charSet, length

---

### GET/PATCH/DELETE /svc/dataprotect/schemes/{id}

---

### POST /svc/dataprotect/tokenize

Tokenizes a single value.

**Request Body**: `value` (string), `schemeId` (string), `context` (object, optional)

**Response 200**: `token` (string), `schemeId`, `tokenId` (for vault lookup)

```bash
curl -s -X POST http://localhost:5173/svc/dataprotect/tokenize \
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

### GET /svc/dataprotect/vault/search

Searches the token vault.

**Query Parameters**: `schemeId`, `prefix`, `tokenId`, `pageSize`, `pageToken`

**Response 200**: Paginated token index records (no values returned — only metadata)

---

### GET /svc/dataprotect/masking/policies / POST /svc/dataprotect/masking/policies

Masking policy: name, rules[] (field, maskType (full/partial/hash/redact), pattern, replacement)

---

### GET/PATCH/DELETE /svc/dataprotect/masking/policies/{id}

---

### POST /svc/dataprotect/mask

Applies a masking policy to a data object.

**Request Body**: `data` (object), `policyId` (string)

**Response 200**: `maskedData` (object with masked fields), `fieldsAffected[]`

---

### POST /svc/dataprotect/mask/batch

Body: `items[]` — each: data, policyId. Response: `results[]`.

---

### POST /svc/dataprotect/encrypt/field

Encrypts individual fields within a data structure.

**Request Body**: `data` (object), `keyId` (string), `fields[]` (field paths to encrypt), `aad` (optional)

**Response 200**: `data` (object with encrypted field values), `keyId`, `keyVersion`

---

### POST /svc/dataprotect/decrypt/field

**Request Body**: `data` (object with encrypted fields), `keyId` (string), `fields[]`, `aad`

**Response 200**: `data` (object with decrypted field values)

---

### POST /svc/dataprotect/reencrypt/field

Re-encrypts fields under a new key without exposing plaintext.

**Request Body**: `data`, `currentKeyId`, `targetKeyId`, `fields[]`

**Response 200**: `data` (re-encrypted), `targetKeyId`, `targetKeyVersion`

---

## Service 14: Payment (`/svc/payment/`)

Payment crypto: TR-31 key blocks, PIN operations, ISO 20022 message signing.

---

### POST /svc/payment/tr31/wrap

Wraps a payment key in a TR-31 key block.

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| keyId | string | Yes | Key to wrap (the DEK or PIN key) |
| kbpkId | string | Yes | Key Block Protection Key ID |
| keyUsage | string | Yes | TR-31 key usage code (e.g. P0, D0, M3) |
| algorithm | string | Yes | TR-31 algorithm code (A, D, R, T) |
| modeOfUse | string | Yes | TR-31 mode of use (E, D, B, C, G, S, V, N, X) |
| exportability | string | No | E (exportable), S (sensitive), N (non-exportable) |
| optionalBlocks | object[] | No | Optional block headers |

**Response 200**: `keyBlock` (TR-31 formatted string), `headerVersion`, `keyUsage`, `algorithm`, `modeOfUse`

```bash
curl -s -X POST http://localhost:5173/svc/payment/tr31/wrap \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"keyId":"3fa85f64-5717-4562-b3fc-2c963f66afa6","kbpkId":"kbpk-key-id","keyUsage":"P0","algorithm":"A","modeOfUse":"E"}'
```

---

### POST /svc/payment/tr31/unwrap

Unwraps a TR-31 key block.

**Request Body**: `keyBlock` (string), `kbpkId` (string), `storeAs` (object: name, tags — if storing the unwrapped key)

**Response 200**: `keyId` (newly stored key) or `keyMaterial` (base64, if not storing)

---

### POST /svc/payment/tr31/translate

Translates a TR-31 key block from one KBPK to another (for inter-system key exchange).

**Request Body**: `keyBlock`, `sourcekbpkId`, `targetKbpkId`, `targetKeyUsage`, `targetModeOfUse`

**Response 200**: `keyBlock` (new TR-31 block under target KBPK)

---

### POST /svc/payment/pin/generate-block

Generates a PIN block in the specified format.

**Request Body**: `pin` (string, 4–12 digits), `pan` (string, 12–19 digits), `format` (ISO-0/ISO-1/ISO-2/ISO-3/ISO-4), `encryptionKeyId` (PIN encryption key)

**Response 200**: `pinBlock` (hex), `format`, `keyId`, `keyVersion`

---

### POST /svc/payment/pin/translate

Translates a PIN block from one format or key to another.

**Request Body**: `pinBlock` (hex), `sourceFormat`, `sourceKeyId`, `targetFormat`, `targetKeyId`, `pan`

**Response 200**: `pinBlock` (hex), `targetFormat`, `targetKeyId`

---

### POST /svc/payment/pin/verify/pvv

Verifies a PIN using PVV (PIN Verification Value) method.

**Request Body**: `pinBlock` (hex), `format`, `encryptionKeyId`, `pvv` (hex), `pvkIndex` (int), `pan`

**Response 200**: `valid` (boolean)

---

### POST /svc/payment/pin/verify/offset

Verifies a PIN using PIN Offset method.

**Request Body**: `pinBlock` (hex), `format`, `encryptionKeyId`, `offset` (string), `pan`, `pvkId`

**Response 200**: `valid` (boolean)

---

### POST /svc/payment/pin/generate

Generates a random PIN.

**Request Body**: `length` (int, 4–12), `pan`, `encryptionKeyId`, `format`

**Response 200**: `pinBlock` (hex), `pvv` (hex, optional), `offset` (string, optional), `format`

---

### POST /svc/payment/iso20022/sign

Signs an ISO 20022 XML or JSON message.

**Request Body**: `message` (base64-encoded message), `messageType` (string, e.g. pacs.008), `signingKeyId`, `algorithm`, `includeCertificate` (boolean)

**Response 200**: `signedMessage` (base64), `signature` (base64), `signatureAlgorithm`, `keyId`, `certificateId`

---

### POST /svc/payment/iso20022/verify

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
curl -s "http://localhost:5173/svc/autokey/autokey/settings?tenant_id=root" \
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
curl -s -X POST http://localhost:5173/svc/autokey/autokey/templates \
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

### GET /svc/cloud/byok/providers / POST /svc/cloud/byok/providers

BYOK provider: name, type (aws/azure/gcp), credentials (type-specific), region, endpoint, enabled

```bash
curl -s -X POST http://localhost:5173/svc/cloud/byok/providers \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"AWS Primary","type":"aws","credentials":{"accessKeyId":"AKIA...","secretAccessKey":"secret","region":"us-east-1"},"enabled":true}'
```

---

### GET/PATCH/DELETE /svc/cloud/byok/providers/{id}

---

### GET /svc/cloud/byok/keys / POST /svc/cloud/byok/keys

BYOK key: name, providerId, keyId (KMS key ID), vectaKeyId (backing Vecta key), syncInterval, enabled, lastSyncAt, state

---

### GET/DELETE /svc/cloud/byok/keys/{id}

---

### POST /svc/cloud/byok/keys/{id}/sync

Pushes current key material to the cloud provider. No body. Response: `{"syncedAt": "...", "cloudKeyVersion": "v2"}`

---

### POST /svc/cloud/byok/keys/{id}/rotate

Rotates the key in Vecta and syncs the new version to the cloud provider.

No body. Response: `{"keyId": "...", "newVersion": 2, "syncedAt": "..."}`

---

### POST /svc/cloud/byok/keys/{id}/revoke

Revokes cloud provider access to the key material.

**Request Body**: `reason` (string). Response: `{"revoked": true, "revokedAt": "..."}`

---

## Service 17: HYOK (`/svc/hyok/`)

Hold Your Own Key proxy: Microsoft DKE (Double Key Encryption), Google CSE (Client-Side Encryption).

---

### GET /svc/hyok/policies / POST /svc/hyok/policies

HYOK policy: name, keyId, allowedCallers[], claimsRequired (object), durationSeconds, auditAll

---

### GET/PATCH/DELETE /svc/hyok/policies/{id}

---

### GET /svc/hyok/dke/{policyId}

DKE public key endpoint. Returns the public key for the specified policy (Microsoft DKE protocol).

**Response 200**: `{"publicKey": "PEM...", "keyId": "...", "algorithm": "RSA-4096"}`

---

### POST /svc/hyok/dke/{policyId}/decrypt

DKE decrypt endpoint. Decrypts ciphertext under the policy key.

**Request Body**: `value` (base64 ciphertext), `wrappedKey` (base64), `alg` (string)

**Response 200**: `value` (base64 plaintext)

---

### POST /svc/hyok/google/wrap

Google CSE key wrapping. Wraps a data encryption key for Google Workspace.

**Request Body**: `authentication` (JWT), `authorization` (JWT), `key` (base64 DEK), `reason` (string)

**Response 200**: `wrappedKey` (base64), `keyUri` (string)

---

### POST /svc/hyok/google/unwrap

Google CSE key unwrapping.

**Request Body**: `authentication`, `authorization`, `wrappedKey`, `reason`

**Response 200**: `key` (base64 DEK)

---

### POST /svc/hyok/google/status

Google CSE status check. Returns service health for CSE eligibility.

**Response 200**: `{"ok": true, "message": "KMS is available"}`

---

### POST /svc/hyok/google/privilegedpolicyunwrap

Privileged unwrap for admin override scenarios.

**Request Body**: `authentication`, `authorization`, `wrappedKey`, `reason`, `resourceName`

**Response 200**: `key` (base64 DEK)

---

## Service 18: EKM (`/svc/ekm/`)

External Key Manager for database TDE (Transparent Data Encryption) and BitLocker.

---

### GET /svc/ekm/providers / POST /svc/ekm/providers

EKM provider: name, type (mysql/mssql/oracle/postgresql/bitlocker), config, enabled

---

### GET/PATCH/DELETE /svc/ekm/providers/{id}

---

### GET /svc/ekm/keys / POST /svc/ekm/keys

EKM key binding: name, providerId, vectaKeyId, externalKeyId, algorithm, purpose, state

```bash
curl -s -X POST http://localhost:5173/svc/ekm/keys \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"sql-tde-key","providerId":"prov-mssql-01","vectaKeyId":"3fa85f64-5717-4562-b3fc-2c963f66afa6","algorithm":"AES-256","purpose":"encrypt"}'
```

---

### GET/DELETE /svc/ekm/keys/{id}

---

### GET /svc/ekm/bitlocker/protectors / POST /svc/ekm/bitlocker/protectors

BitLocker key protector: name, keyId, driveIdentifier, protectorType (tpm/password/recovery-key/ekm), enabled

---

### GET/DELETE /svc/ekm/bitlocker/protectors/{id}

---

## Service 19: KMIP (`/svc/kmip/`)

KMIP protocol management for KMIP-compliant clients and legacy HSM integrations.

---

### GET /svc/kmip/profiles / POST /svc/kmip/profiles

KMIP profile: name, kmipVersion (1.1/1.2/2.0), allowedOperations[], requireMtls, allowedAlgorithms[], description

---

### GET/PATCH/DELETE /svc/kmip/profiles/{id}

---

### GET /svc/kmip/objects

Lists KMIP-managed objects.

**Query Parameters**: `objectType`, `state`, `profileId`, `pageSize`, `pageToken`

**Response 200**: Paginated KMIP object records — id, objectType (SymmetricKey/PublicKey/PrivateKey/Certificate), state, algorithm, profileId, createdAt

---

### GET /svc/kmip/objects/{id}

Returns a KMIP object record.

---

### DELETE /svc/kmip/objects/{id}

Destroys a KMIP object.

---

### GET /svc/kmip/clients / POST /svc/kmip/clients

KMIP client: name, profileId, certificate (PEM), allowedIps[], enabled

```bash
curl -s -X POST http://localhost:5173/svc/kmip/clients \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"NetApp StorageGrid","profileId":"kmip-profile-01","certificate":"-----BEGIN CERTIFICATE-----\n...","allowedIps":["10.0.10.0/24"]}'
```

---

### GET/PATCH/DELETE /svc/kmip/clients/{id}

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
curl -s -X POST http://localhost:5173/svc/signing/signing/profiles \
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

Re-verifies a stored signing record.

**Request Body**: `recordId` (string) OR `artifact` (base64) + `signature` + `profileId`

**Response 200**: `valid`, `recordId`, `signerIdentity`, `profileId`, `transparencyVerified`, `verifiedAt`

---

### GET /svc/signing/signing/records

Lists signing records.

**Query Parameters**: `profileId`, `artifactType`, `startTime`, `endTime`, `pageSize`, `pageToken`

**Response 200**: Paginated record[] — id, profileId, artifactType, signerIdentity, transparencyLogged, signedAt

---

## Service 21: MPC (`/svc/mpc/`)

Multi-party computation groups, FROST threshold signing, DKG ceremonies.

---

### GET /svc/mpc/mpc/overview

Dashboard overview for all MPC state.

**Response 200**: `activeGroups`, `activeKeys`, `pendingCeremonies`, `failedCeremonies`, `participantCount`, `policyCount`

---

### GET /svc/mpc/mpc/participants / POST participant configuration

Lists registered MPC participants: id, name, endpoint, publicKey, status, groupMemberships[]

---

### GET /svc/mpc/mpc/policies

Lists threshold policies: id, name, groupId, threshold (int), totalParticipants (int), allowedOperations[]

---

### GET /svc/mpc/mpc/keys

Lists MPC-backed keys: id, name, groupId, threshold, algorithm, state, createdAt

---

### GET /svc/mpc/mpc/groups / POST /svc/mpc/mpc/groups

MPC group: name, participants[] (ids), threshold, algorithm, policy

```bash
curl -s -X POST http://localhost:5173/svc/mpc/mpc/groups \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"root-ca-signers","participants":["part-alice","part-bob","part-carol"],"threshold":2,"algorithm":"Ed25519"}'
```

---

### GET /svc/mpc/mpc/groups/{id}

---

### DELETE /svc/mpc/mpc/groups/{id}

---

### GET /svc/mpc/mpc/groups/{id}/status

Group health: participantsOnline, lastActivityAt, pendingCeremonies[]

---

### POST /svc/mpc/mpc/dkg/initiate

Initiates a Distributed Key Generation ceremony.

**Request Body**: `groupId`, `algorithm`, `keyName`, `purpose`

**Response 202**: `ceremonyId`, `status: initiated`, `roundsRequired`

---

### POST /svc/mpc/mpc/sign/initiate

Initiates a threshold signing ceremony.

**Request Body**: `keyId`, `message` (base64), `messageType` (raw/digest), `algorithm`

**Response 202**: `ceremonyId`, `status: awaiting_contributions`

---

### POST /svc/mpc/mpc/sign/{id}/contribute

Submit a participant's signing contribution.

**Request Body**: `participantId`, `contribution` (base64 partial signature share)

**Response 200**: `status`, `contributionsReceived`, `contributionsRequired`

---

### GET /svc/mpc/mpc/sign/{id}/result

Retrieve completed threshold signing result.

**Response 200**: `ceremonyId`, `signature` (base64), `status`, `completedAt`

---

### GET /svc/mpc/mpc/ceremonies

Lists all ceremonies. Query: `status`, `groupId`, `type` (dkg/sign/reshare), `pageSize`, `pageToken`

---

### GET /svc/mpc/mpc/ceremonies/{id}

Ceremony detail: id, type, groupId, status, participants[], contributions[], result, startedAt, completedAt

---

### POST /svc/mpc/mpc/ceremonies/{id}/participate

Alternative contribution endpoint for ceremony participation.

---

### POST /svc/mpc/mpc/groups/{id}/reshare

Initiates a resharing ceremony to update the participant set or threshold without changing the key.

**Request Body**: `newParticipants[]`, `newThreshold`, `reason`

**Response 202**: `ceremonyId`, `status: resharing`

---

## Service 22: Cluster (`/svc/cluster/`)

Cluster node management, HSM registration, replication, leader election.

---

### GET /svc/cluster/nodes / POST /svc/cluster/nodes

Node: id, address, role (leader/follower), state (healthy/degraded/offline), version, joinedAt

---

### GET /svc/cluster/status

Cluster-wide status: `leader`, `nodes[]`, `quorum`, `replicationLag`, `healthy`

---

### GET /svc/cluster/replication

Replication status per follower: `nodeId`, `address`, `replicationLag`, `lastAppliedAt`, `state`

---

### POST /svc/cluster/leader/transfer

Transfers leadership to a specified node.

**Request Body**: `targetNodeId` (string)

**Response 200**: `{"newLeader": "node-02", "transferredAt": "..."}`

---

### GET /svc/cluster/snapshots / POST /svc/cluster/snapshots

Cluster state snapshots for backup and disaster recovery. Create triggers an immediate snapshot.

---

### GET /svc/cluster/hsm / POST /svc/cluster/hsm

HSM registration: name, type (thales/entrust/aws-cloudhsm/pkcs11/softhsm), config, partitionCount, enabled

```bash
curl -s -X POST http://localhost:5173/svc/cluster/hsm \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"Thales Luna Network HSM","type":"thales","config":{"host":"hsm.acme.example","partition":"kms-partition","pin":"hsm-partition-pin"},"enabled":true}'
```

---

### GET/PATCH/DELETE /svc/cluster/hsm/{id}

---

### POST /svc/cluster/hsm/{id}/test

Tests HSM connectivity. Response: `{"connected": true, "latencyMs": 12, "firmwareVersion": "7.4.0"}`

---

## Service 23: QKD (`/svc/qkd/`)

Quantum Key Distribution: ETSI GS QKD 014 compatible links for quantum-secure key exchange.

---

### GET /svc/qkd/links / POST /svc/qkd/links

QKD link: name, remoteKmsEndpoint, etsiApiUrl, credentials, keyRate (keys/sec), keyLength (bits), enabled, state

```bash
curl -s -X POST http://localhost:5173/svc/qkd/links \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"QKD-Link-DataCenter-A","remoteKmsEndpoint":"https://kms-b.acme.example","etsiApiUrl":"https://qkd-a.acme.example:9090","keyLength":256,"enabled":true}'
```

---

### GET/PATCH/DELETE /svc/qkd/links/{id}

---

### GET /svc/qkd/links/{id}/keys

Fetches available quantum keys from the QKD link.

**Query Parameters**: `count` (int, 1–10), `keyLength` (bits)

**Response 200**: `{"keys": [{"keyId": "qkd-key-01", "keyMaterial": "base64"}], "linkId": "..."}`

---

### GET /svc/qkd/links/{id}/status

Link health: `state` (up/degraded/down), `keyRate`, `qberRate` (quantum bit error rate), `availableKeys`, `lastKeyAt`

---

### POST /svc/qkd/links/{id}/test

Tests QKD link connectivity and key delivery. Response: `{"connected": true, "keyDelivered": true, "qber": 0.02}`

---

## Service 24: QRNG (`/svc/qrng/`)

Quantum random number generation from hardware quantum sources.

---

### GET /svc/qrng/sources / POST /svc/qrng/sources

QRNG source: name, type (photonic/vacuum-fluctuation/nuclear/api), endpoint, credentials, enabled, state

---

### GET/PATCH/DELETE /svc/qrng/sources/{id}

---

### GET /svc/qrng/sources/{id}/health

Source health: `state` (up/degraded/down), `entropyRate` (bits/sec), `lastGeneratedAt`, `qualityScore`

---

### POST /svc/qrng/generate

Generates quantum random bytes.

**Request Body**: `size` (int, 1–65536), `encoding` (base64/hex), `sourceId` (optional, uses default if omitted)

**Response 200**: `random` (string), `sourceId`, `size`, `sourceType`, `generatedAt`

```bash
curl -s -X POST http://localhost:5173/svc/qrng/generate \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"size":64,"encoding":"hex"}'
```

Response:
```json
{
  "random": "a3f7e2b1c9d4f8a2e6b3c7d1f5a9e3b7c2d6f1a4e8b2c5d9f3a7e1b4c8d2f6a9",
  "sourceId": "qrng-source-01",
  "size": 64,
  "sourceType": "photonic",
  "generatedAt": "2025-03-15T14:22:00Z"
}
```

---

### GET /svc/qrng/stats

Aggregate QRNG statistics: `totalGenerated` (bytes), `sourcesOnline`, `averageEntropyRate`, `lastGeneratedAt`

---

## Service 25: Secrets (`/svc/secrets/`)

Hierarchical secret vault with versioning, rollback, and path-based policy.

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

```bash
curl -s "http://localhost:5173/svc/secrets/secrets/services/database/credentials" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

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

### POST /svc/secrets/secrets/{path}/destroy/{version}

Permanently destroys a specific secret version. Irreversible.

**Response**: 204 No Content

---

### GET /svc/secrets/secrets/{path}/versions

Lists all versions of a secret (no values).

**Response 200**: `Version[]` — version, state (current/deleted/destroyed), createdAt, deletedAt

---

### GET /svc/secrets/secrets/{path}/versions/{version}

Retrieves a specific secret version including its value.

---

### POST /svc/secrets/secrets/{path}/rollback/{version}

Rolls back the secret to a previous version by creating a new version with the old value.

**Response 200**: `{"path": "...", "newVersion": 4, "rolledBackFrom": 3, "rolledBackTo": 2}`

---

### GET /svc/secrets/policy/{path}

Returns the access policy for a path (and all sub-paths).

**Response 200**: Policy object with `grants[]` — subject, subjectType, operations[], pathPattern

---

### PUT /svc/secrets/policy/{path}

Sets the access policy for a path.

```bash
curl -s -X PUT http://localhost:5173/svc/secrets/policy/services/database \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"grants":[{"subject":"service-account-api","subjectType":"client","operations":["read"],"pathPattern":"services/database/*"}]}'
```

---

## Service 26: SBOM (`/svc/sbom/`)

Software BOM, Cryptographic BOM, vulnerability correlation, offline advisory management.

---

### GET /svc/sbom/sbom/inventory

Returns the latest SBOM snapshot inventory.

**Response 200**: `snapshotId`, `createdAt`, `componentCount`, `components[]` (name, version, ecosystem, purl, license)

---

### POST /svc/sbom/sbom/generate

Generates a fresh software BOM snapshot.

**Request Body**: `trigger` (manual/scheduled), `format` (cyclonedx/spdx, optional)

**Response 202**: `{"status": "accepted", "snapshot": {"id": "sbom_20260311_001", "createdAt": "2026-03-11T09:45:00Z"}}`

```bash
curl -s -X POST http://localhost:5173/svc/sbom/sbom/generate \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"trigger":"manual"}'
```

---

### GET /svc/sbom/sbom/ingest/{id}/status

Returns status of a SBOM ingest job.

---

### GET /svc/sbom/sbom/vulnerabilities

Returns merged vulnerability findings from OSV online, Trivy, and manual advisories.

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

### GET /svc/sbom/sbom/findings / GET /svc/sbom/sbom/findings/{id}

Enriched finding objects linking vulnerabilities to specific components.

---

### GET /svc/sbom/sbom/advisories

Lists manually managed offline advisories for air-gapped environments.

---

### POST /svc/sbom/sbom/advisories

Creates or updates a manual offline advisory.

**Request Body**: `id` (CVE ID), `component`, `ecosystem`, `introducedVersion`, `fixedVersion`, `severity`, `summary`, `reference`

```bash
curl -s -X POST http://localhost:5173/svc/sbom/sbom/advisories \
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
curl -s -X DELETE "http://localhost:5173/svc/sbom/sbom/advisories/CVE-2026-5000?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### POST /svc/sbom/cbom/generate

Generates a Cryptographic BOM snapshot.

**Request Body**: `tenantId`, `trigger` (manual/scheduled)

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

## Service 27: AI (`/svc/ai/`)

AI-powered guidance: natural-language queries, incident analysis, posture recommendations, policy explanation. Provider-backed with governance-aware context assembly and redaction before prompt delivery.

---

### GET /svc/ai/ai/config

Returns the saved AI configuration for the tenant.

**Query Parameters**: `tenant_id` (required)

**Response 200**:
```json
{
  "config": {
    "tenantId": "root",
    "backend": "claude",
    "endpoint": "https://api.anthropic.com/v1/messages",
    "model": "claude-sonnet-4-6",
    "apiKeySecret": "ai-provider-token",
    "providerAuth": {"required": true, "type": "bearer"},
    "mcp": {"enabled": false, "endpoint": ""},
    "maxContextTokens": 8000,
    "temperature": 0.3,
    "contextSources": {
      "keys": {"enabled": true, "limit": 25, "fields": ["id", "name", "algorithm", "status"]},
      "policies": {"enabled": true, "all": false, "limit": 20},
      "audit": {"enabled": true, "lastHours": 24, "limit": 100},
      "posture": {"enabled": true, "current": true},
      "alerts": {"enabled": true, "unresolved": true, "limit": 50}
    },
    "redactionFields": ["encrypted_material", "wrapped_dek", "pwd_hash", "api_key", "passphrase"],
    "updatedAt": "2026-03-11T09:30:00Z"
  }
}
```

```bash
curl -s "http://localhost:5173/svc/ai/ai/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### PUT /svc/ai/ai/config

Updates the tenant AI configuration.

**Request Body**: backend, endpoint, model, apiKeySecret, providerAuth (required, type), mcp (enabled, endpoint), maxContextTokens, temperature, contextSources, redactionFields

Validation: `backend` must be supported; managed providers require `providerAuth.required: true`; if `mcp.enabled: true`, `mcp.endpoint` must be set.

```bash
curl -s -X PUT "http://localhost:5173/svc/ai/ai/config?tenant_id=root" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"backend":"claude","endpoint":"https://api.anthropic.com/v1/messages","model":"claude-sonnet-4-6","apiKeySecret":"my-api-key-secret","providerAuth":{"required":true,"type":"bearer"},"maxContextTokens":8000,"temperature":0.3}'
```

---

### POST /svc/ai/ai/query

Submits a natural-language assistant request. Context is assembled from enabled sources, redacted, then sent to the configured provider.

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| tenantId | string | Yes | Tenant context |
| query | string | Yes | Natural-language question or task |
| includeContext | boolean | No | Whether to assemble and include KMS context |

**Response 200**:
```json
{
  "result": {
    "action": "query",
    "tenantId": "root",
    "answer": "There are 3 unresolved alerts. Start with the posture risk spike and the pending approval backlog.",
    "backend": "claude",
    "model": "claude-sonnet-4-6",
    "redactionsApplied": 4,
    "contextSummary": {
      "keys": 12,
      "policies": 6,
      "auditEvents": 45,
      "alerts": 3
    },
    "warnings": [],
    "generatedAt": "2026-03-15T09:40:00Z"
  }
}
```

```bash
curl -s -X POST http://localhost:5173/svc/ai/ai/query \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"tenantId":"root","query":"Analyze recent unresolved alerts and recommend actions","includeContext":true}'
```

---

### POST /svc/ai/ai/analyze/incident

Produces an AI explanation for a security or governance event.

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| tenantId | string | Yes | Tenant context |
| incidentId | string | Yes | Incident identifier |
| title | string | Yes | Incident title |
| description | string | Yes | Incident description |
| details | object | No | Additional structured details |

**Response 200**: `result.answer` (AI analysis and recommendations), `result.backend`, `result.redactionsApplied`

```bash
curl -s -X POST http://localhost:5173/svc/ai/ai/analyze/incident \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"tenantId":"root","incidentId":"inc-001","title":"Unauthorized key export attempt","description":"A privileged user attempted an export against a production key.","details":{"keyId":"key_123","actor":"ops-admin","approvalStatus":"missing"}}'
```

---

### POST /svc/ai/ai/recommend/posture

Builds posture guidance for the requested focus area.

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| tenantId | string | Yes | Tenant context |
| focus | string | Yes | Focus area: key-rotation / mfa-enforcement / pqc-migration / backup-discipline / access-review |

**Response 200**: `result.answer` (prioritized recommendations), `result.warnings` (if provider unavailable, falls back to deterministic guidance)

```bash
curl -s -X POST http://localhost:5173/svc/ai/ai/recommend/posture \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"tenantId":"root","focus":"key-rotation"}'
```

---

### POST /svc/ai/ai/recommend/pqc

Provides PQC migration recommendations based on the tenant's current inventory.

**Request Body**: `tenantId`, `targetMode` (hybrid/pqc-only), `prioritize` (certificates/keys/interfaces)

**Response 200**: `result.answer` (migration steps and prioritization), `result.contextSummary`

---

### POST /svc/ai/ai/explain/policy

Explains a KMS policy in plain language.

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| tenantId | string | Yes | Tenant context |
| policyId | string | Conditional | ID of policy to explain (mutually exclusive with inline policy) |
| policy | object | Conditional | Inline policy object to explain |

```bash
curl -s -X POST http://localhost:5173/svc/ai/ai/explain/policy \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"tenantId":"root","policyId":"policy-rotate-90d"}'
```

---

### GET /svc/ai/ai/anomalies

Lists AI-detected anomalies in key usage, access patterns, or audit events.

**Query Parameters**: `severity`, `resolved`, `startTime`, `endTime`, `pageSize`, `pageToken`

**Response 200**: Paginated anomaly records — id, severity, description, affectedResource, detectedAt, resolved, resolutionNote

---

### GET /svc/ai/ai/anomalies/{id}

Returns a single anomaly with full AI analysis and recommended actions.

---

## Appendix: Audit Action Subject Reference

Audit events use dot-separated action subjects. Common prefixes:

| Prefix | Domain |
|--------|--------|
| audit.auth.* | Authentication and identity |
| audit.key.* | Key lifecycle and crypto operations |
| audit.cert.* | Certificate and CA operations |
| audit.governance.* | Approvals and backup |
| audit.compliance.* | Compliance assessments |
| audit.posture.* | Posture scan and findings |
| audit.scim.* | SCIM provisioning |
| audit.mpc.* | MPC ceremonies |
| audit.signing.* | Artifact signing |
| audit.workload.* | Workload identity |
| audit.confidential.* | Attested key release |
| audit.payment.* | Payment crypto operations |
| audit.secrets.* | Secret vault access |
| audit.sbom.* | SBOM/CBOM generation |
| audit.ai.* | AI queries and recommendations |

Selected events with dedicated audit classification:
- `audit.key.encrypt`, `audit.key.decrypt`, `audit.key.sign`, `audit.key.verify`
- `audit.key.rotate`, `audit.key.destroy`, `audit.key.export`, `audit.key.wrap`, `audit.key.unwrap`
- `audit.auth.login`, `audit.auth.logout`, `audit.auth.mfa_verified`
- `audit.auth.scim_user_provisioned`, `audit.auth.scim_user_deprovisioned`
- `audit.auth.scim_settings_updated`, `audit.auth.scim_token_rotated`
- `audit.cert.issued`, `audit.cert.revoked`, `audit.cert.renewed`
- `audit.cert.renewal_window_missed`, `audit.cert.emergency_rotation_started`
- `audit.cert.star_subscription_created`, `audit.cert.star_subscription_renewed`
- `audit.governance.approval_requested`, `audit.governance.approved`, `audit.governance.rejected`, `audit.governance.bypassed`
- `audit.governance.backup_completed`, `audit.governance.restore_completed`
- `audit.mpc.dkg_initiated`, `audit.mpc.sign_initiated`, `audit.mpc.sign_completed`
- `audit.signing.blob_signed`, `audit.signing.verify_failed`
- `audit.confidential.key_released`, `audit.confidential.attestation_denied`
- `audit.payment.pin_verified`, `audit.payment.tr31_wrapped`

---

## Appendix: Common Workflows

### Encrypt application data

```bash
# 1. Login
export TOKEN=$(curl -s -X POST http://localhost:5173/svc/auth/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"app-service","password":"pass","tenantId":"root"}' | jq -r '.token')

# 2. Create key (once)
KEY_ID=$(curl -s -X POST http://localhost:5173/svc/keycore/keys \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"name":"app-data-key","algorithm":"AES-256","purpose":"encrypt"}' | jq -r '.id')

# 3. Encrypt
curl -s -X POST "http://localhost:5173/svc/keycore/keys/$KEY_ID/encrypt" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"plaintext":"c2Vuc2l0aXZlIGRhdGE="}'
```

### Issue a TLS certificate

```bash
# 1. Generate CSR with openssl
openssl req -new -newkey rsa:2048 -nodes -keyout server.key \
  -subj "/CN=api.acme.example/O=Acme Corp" -out server.csr

# 2. Issue from KMS CA
curl -s -X POST http://localhost:5173/svc/certs/cas/issuing-ca-id/issue \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d "{\"csr\":\"$(base64 -w0 server.csr)\",\"profileId\":\"tls-server\",\"san\":{\"dnsNames\":[\"api.acme.example\"]}}"
```

### Run a compliance assessment

```bash
# 1. Trigger assessment
ASMT_ID=$(curl -s -X POST http://localhost:5173/svc/compliance/assessments \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"frameworkId":"pci-dss-v4","scope":"tenant"}' | jq -r '.assessmentId')

# 2. Poll until complete
curl -s "http://localhost:5173/svc/compliance/assessments/$ASMT_ID" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"

# 3. Export report
curl -s -X POST "http://localhost:5173/svc/compliance/assessments/$ASMT_ID/export" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"format":"pdf"}'
```

### Provision a workload key via Autokey

```bash
# 1. Create a provisioning request
curl -s -X POST http://localhost:5173/svc/autokey/autokey/requests \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" -H "Content-Type: application/json" \
  -d '{"resourceType":"s3-bucket","resourceId":"my-app-data-bucket","service":"data-pipeline","justification":"production encryption for GDPR scope data"}'
```
