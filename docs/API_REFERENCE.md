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
| pqc | /svc/pqc/ | PQC inventory, readiness scans, migration |
| keyaccess | /svc/keyaccess/ | Access justification rules |
| dataprotect | /svc/dataprotect/ | Tokenization, masking, field encryption |
| autokey | /svc/autokey/ | Key provisioning templates, handles |
| cloud | /svc/cloud/ | BYOK, cloud key sync |
| hyok | /svc/hyok/ | HYOK proxy, DKE, Google CSE |
| ekm | /svc/ekm/ | Database TDE, BitLocker |
| kmip | /svc/kmip/ | KMIP protocol management |
| signing | /svc/signing/ | Artifact, container, git signing |
| cluster | /svc/cluster/ | Cluster nodes, HSM registration |
| secrets | /svc/secrets/ | Secret vault |
| sbom | /svc/sbom/ | SBOM/CBOM inventory |

---

## Conventions

Checked against the code in 7.16.0-beta.

**Base URL**: `https://{host}`. Everything is TLS; there is no plain-HTTP
listener. For a local install, pass the internal root CA
(PKI tab) with `--cacert` instead of `-k`.

**All API paths**: `https://{host}/svc/{service}/{path}`. Envoy strips
`/svc/{service}`, so the service sees `/{path}` (for example
`/svc/keycore/keys/{id}/rotate` reaches keycore as `/keys/{id}/rotate`).

**Authentication**: `Authorization: Bearer {token}` on every call except
the public ones noted (login, client registration, client-token, SSO).
The token is a JWT from `POST /svc/auth/auth/login` (users) or
`POST /svc/auth/auth/client-token` (REST clients,
[CI_CD_AUTOMATION.md](CI_CD_AUTOMATION.md)). Its claims include
`tenant_id`, `role`, `permissions[]`, `user_id` (users) or `client_id`
(clients), `exp`, `iat`.

**Tenant**: the token's `tenant_id` is the tenant. A request may also name
it (`X-Tenant-ID` header, `tenant_id` query or body field). Some older
routes require it (for example `GET /svc/keycore/keys?tenant_id=...`). A
named tenant that differs from the token's is refused
(`403`, `tenant_mismatch`, audited).

**Field names** are `snake_case` in requests and responses.

**Lists** return `{"items": [...], "request_id": "..."}`. Where a list
pages, it says so in its section (for example keycore keys: `limit` and
`offset`, or the `after_created_at` + `after_id` cursor, returning
`next_cursor` and `has_more`). There is no platform-wide `pageToken`.

**Idempotency**: no `X-Idempotency-Key` support. Don't blindly retry a
non-idempotent POST (key create, rotate) on a timeout: check state first.

**Error response**:
```json
{"error": {"code": "not_found", "message": "key not found", "request_id": "req_...", "tenant_id": "acme"}}
```

`code` is lowercase snake_case and route-specific. The common ones:

| HTTP | Typical `code` | Meaning |
|------|---------|---------|
| 400 | `bad_request` | Validation failed |
| 401 | `unauthorized` | Missing, invalid or expired token |
| 403 | `forbidden`, `permission_denied`, `tenant_mismatch` | Not allowed (every refusal is audited) |
| 404 | `not_found` | Resource does not exist |
| 409 | route-specific (e.g. `feature_preview`, `algorithm_change_refused`) | State conflict |
| 429 | `RATE_LIMITED` | Tenant rate limit exceeded (keycore) |
| 500 | `store_error`, `internal_error` | Server error |
| 503 | `event_publish_failed` | The audit event could not be recorded, so the operation did not complete |

**Rate limiting**: keycore limits requests per tenant. A limited request gets
`429` with `Retry-After`. There are no `X-RateLimit-*` headers.

**Timestamps**: RFC 3339 UTC, for example `2026-09-30T14:22:00Z`.

**Preview features** ([PREVIEW_FEATURES.md](PREVIEW_FEATURES.md)): responses
from features that store configuration without enforcing it carry
`X-Vecta-Feature-Status: preview` and `X-Vecta-Feature-Status-Id: <id>`
(keycore control records also include `feature_status` / `feature_id`).
Operations such a feature cannot perform return `409 feature_preview`.


---

## Service 1: Auth (`/svc/auth/`)

Authentication, session management, users, tenants, API clients, IdP integration, SCIM provisioning.

---

### Delegated operations (2.5.0-beta)

Route kernel routes that only the `kms-compliance` service identity may call
(anyone else: `403 service_identity_required`), for the tenant in
`X-Tenant-ID`. Body: `on_behalf_of` (a user ID), `reason`,
`playbook_run_id`. Auth checks the named user now: they must exist in the
tenant, be active, and hold the operation's permission. Otherwise the
request is refused (`403` with `delegator_unknown`, `delegator_inactive` or
`delegator_lacks_permission`).

| Route | Needs (of `on_behalf_of`) | Audit action | Also refused |
|---|---|---|---|
| `POST /svc/auth/auth/delegated/authority` (body `user_id`, `permissions[]`; returns `active`, `missing[]`; callable by `kms-compliance` and, since 7.20.0-beta, `kms-discovery`) | none | `delegated_authority_checked` | none |
| `POST /svc/auth/auth/delegated/users/{id}/disable` | `auth.user.write` | `delegated_user_disabled` | `self_target`, `last_administrator` (409) |
| `POST /svc/auth/auth/delegated/api-keys/{id}/revoke` | `auth.api_key.write` | `delegated_api_key_revoked` | `service_identity_protected` (409) |
| `POST /svc/auth/auth/delegated/clients/{id}/revoke` | `auth.client.write` | `delegated_client_revoked` | `service_identity_protected` (409) |

---

### POST /svc/auth/auth/login

**Authentication**: None (public)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| tenant_id | string | Yes | Tenant to authenticate against |
| username | string | Yes | Username or email |
| password | string | Yes | Password |
| totp_code | string | No | TOTP code if MFA is enabled |

**Response 200**: `access_token`, `token_type` (`Bearer`), `expires_at`,
`must_change_password`, `security_policy`, `request_id`. While
`must_change_password` is true the token only carries
`auth.password.change`.

```bash
# Password comes from the environment and goes to curl on stdin, never argv.
export TOKEN=$(jq -n '{tenant_id: "root", username: env.KMS_USER, password: env.KMS_PASSWORD}' |
  curl -sS --fail-with-body --cacert vecta-root-ca.pem -X POST https://localhost/svc/auth/auth/login \
    -H "Content-Type: application/json" --data-binary @- | jq -r .access_token)
```

Errors: `401 unauthorized` (bad credentials, disabled user or bad MFA code), `429` (locked out
after repeated failures).

---

### POST /svc/auth/auth/logout

Bearer required. No body. Invalidates token. Response: 204.

---

### POST /svc/auth/auth/refresh

Bearer (`auth.token.refresh`). No refresh tokens exist: the caller's
current, still-valid token is exchanged for a new one. Response:
`access_token`, `expires_at`.

---

### REST clients: register, approve, token, rotate, revoke

The pipeline flow is in [CI_CD_AUTOMATION.md](CI_CD_AUTOMATION.md). In the
dashboard: Workbench → REST API → REST Client Security.

| Route | Auth | Body / response | Audit |
|---|---|---|---|
| `POST /svc/auth/auth/register` | public | `tenant_id`, `client_name` (required), `interface_name` (default `rest`), `auth_mode` (`api_key`, `oauth_mtls`, `dpop`, `http_message_signature`), `subject_id`, `description`, `contact_email`, `requested_role` → `registration_id`, `status: pending` | `audit.auth.client_registered` |
| `POST /svc/auth/auth/register/{id}/activate` | `auth.client.activate` | `tenant_id`, `approval_id` (when governance requires it), `ip_whitelist[]`, `rate_limit` → `api_key` (**shown once**), `api_key_prefix` | `audit.auth.client_activated`; refused (`governance_required`, `client_state` when not pending, `not_found`): `audit.auth.client_activation_refused` |
| `POST /svc/auth/auth/client-token` | public, API key in `X-API-Key` (or `Authorization: ApiKey ...`) | `tenant_id`, `client_id` (the registration ID), optional `permissions[]` (a subset of the key's), `ttl_seconds` (60–3600, default 300) → `access_token`, `token_type`, `expires_at`, `client_id`, `subject_id`, `interface_name`. `oauth_mtls`, `dpop` and `http_message_signature` clients also present their certificate, `DPoP` proof or signature | binding and replay refusals: `audit.auth.mtls_binding_failed`, `client_dpop_failed`, `dpop_replay_detected`, `client_http_signature_failed`, `http_signature_replay_detected` |
| `POST /svc/auth/auth/clients/{id}/rotate-key` | `auth.client.write` | → `api_key` (**shown once**), `api_key_prefix`. The previous key is deleted in the same transaction and stops working immediately | `audit.auth.client_key_rotated`; refused `client_state` (not approved), `service_identity_protected` (409) |
| `POST /svc/auth/auth/clients/{id}/revoke` | `auth.client.write` | status becomes `revoked` and the client's API keys are deleted | `audit.auth.client_revoked`; refused `service_identity_protected` (409) |
| `DELETE /svc/auth/auth/api-keys/{id}` | `auth.api_key.write` | deletes one API key; platform service keys are refused | `audit.auth.api_key_revoked`; refused `service_identity_protected` (409) |
| `GET /svc/auth/auth/clients`, `GET/PUT /svc/auth/auth/clients/{id}` | `auth.client.read` / `auth.client.write` | list, read, and update security settings (`auth_mode`, `ip_whitelist`, `rate_limit`, `replay_protection_enabled`, mTLS and HTTP-signature bindings) | `audit.auth.client_updated` |

A client token holds the key's `kms.read` / `kms.write`, which the route
kernel honours only in the `secrets` domain. Key operations need a user
whose role holds `key.*`. `POST /auth/api-keys` was removed in 7.16.0-beta:
it minted keys bound to no client, with any permissions the caller named,
and auth deletes any such keys left over at startup
(`audit.auth.unbound_api_keys_retired`).

---

### GET /svc/auth/auth/rest-client-security/summary

`auth.client.read`. Response `summary`: `total_clients`,
`sender_constrained_clients`, `oauth_mtls_clients`, `dpop_clients`,
`http_message_signature_clients`, `replay_protected_clients`,
`verified_requests`, `replay_violations`, `signature_failures`,
`unsigned_rejects`, `non_compliant_clients`, `last_violation_at`.

---

### GET /svc/auth/auth/users

`auth.user.read`. Query: `tenant_id` (another tenant needs
`auth.tenant.read`). Response `items[]`: `id`, `tenant_id`, `username`,
`email`, `role`, `status`, `must_change_password`, `created_at`. Not paged.

---

### POST /svc/auth/auth/users

`auth.user.write`. Body: `username`, `email`, `password`, `role`,
`status`, `must_change_password`, `totp_secret` (optional), `tenant_id`.
The password must meet the tenant's password policy. Response `201`:
`user_id`.

```bash
jq -n '{tenant_id: "root", username: "bob", email: "bob@example.com", role: "operator",
        password: env.NEW_USER_PASSWORD, must_change_password: true}' |
  { printf 'Authorization: Bearer %s\n' "$TOKEN" > "$HDR"; \
    curl -sS --fail-with-body --cacert vecta-root-ca.pem -X POST https://localhost/svc/auth/auth/users \
      -H @"$HDR" -H "Content-Type: application/json" --data-binary @-; rm -f "$HDR"; }
```

---

### POST /svc/auth/auth/users/{id}/reset-password

`auth.user.write`. Body: `new_password`, `must_change_password`
(optional). Response: `{"status": "ok"}`. Audited
`audit.auth.user_password_reset`.

---

### GET/POST /svc/auth/tenants / GET/PUT/DELETE /svc/auth/tenants/{id}

`auth.tenant.read` / `auth.tenant.write` (or the `super-admin` role).
Create body: `id`, `name`, `status`, and the tenant's first administrator
`admin_username`, `admin_email`, `admin_password`, `admin_role`,
`admin_status`, `admin_must_change_password`. Response: `status`,
`tenant_id`, `admin_user_id`. `GET /tenants/{id}` returns `tenant`
(`id`, `name`, `status`, `created_at`). Other routes:
`GET /tenants/{id}/delete-readiness`, `POST /tenants/{id}/disable`, and
`POST /tenants/{id}/roles` and `PUT`/`DELETE /tenants/{id}/roles/{name}`.

---

### GET/PUT /svc/auth/auth/scim/settings

`auth.user.read` / `auth.user.write`. `settings`: `enabled`,
`token_prefix`, `default_role`, `default_status`,
`default_must_change_password`, `deprovision_mode`,
`group_role_mappings_enabled`, `updated_by`, `updated_at`.

---

### POST /svc/auth/auth/scim/settings/rotate-token

`auth.user.write`. Response: `settings` and `bearer_token`, which is
**shown once** and is the SCIM client's credential. Audited
`audit.auth.scim_token_rotated`.

---

### GET /svc/auth/auth/scim/summary

`auth.user.read`. Response `summary`: `enabled`, `token_configured`,
`token_prefix`, `default_role`, `default_status`, `deprovision_mode`,
`group_role_mappings_enabled`, `managed_users`, `active_users`,
`disabled_users`, `managed_groups`, `managed_memberships`,
`role_mapped_groups`, `last_provisioned_at`, `last_deprovisioned_at`.

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

`GET /svc/keycore/keys/{id}/public-key` (any verified identity; kernel
event `audit.key.public_key_read`, details `algorithm`, `version`; 6.18.0-beta)
returns the current version's public key: `key_id`, `version`, `algorithm`,
`format: spki-pem` and `public_key_pem` (PEM SubjectPublicKeyInfo). The key
must be visible to the caller (hidden or missing: `404 not_found`).
Refused, `result: refused`: `409 not_asymmetric` (no public half),
`409 key_deleted`, `409 spki_unavailable` (ML-KEM, ML-DSA and SLH-DSA
public keys have no SPKI encoding here yet). A software key pair's public
key is derived from its stored private key; an HSM key pair's is the one
the HSM returned.

`GET /svc/keycore/keys/{id}/consumers` (`key.usage.read`; kernel event
`audit.key.key_consumers_read`, detail `consumers`) lists the key's callers
from keycore's usage trail, which every successful crypto operation writes:
`consumers[]` (`actor_id`, `interface`, `operations` by name, `total`,
`first_seen`, `last_seen`), `since` and `window_days` (the trail's 30-day
retention), `node_local: true` (each node keeps its own trail), and `impact`
(`key_status`, `current_version`, `versions_by_status`, `active_callers`,
`interfaces`, `last_used_at`, `approval_required`). `404` for an unknown key.
The Keys detail view's **History & usage** panel shows it under "Used by"
and "Before you rotate or delete".

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

What `GET /svc/keycore/keys/{id}` returns under `key`, and each item of
`GET /svc/keycore/keys`. Key material is never returned.

| Field | Type | Description |
|-------|------|-------------|
| id | string | Key ID |
| tenant_id | string | Owning tenant |
| name | string | Name |
| algorithm | string | For example `AES-256`, `RSA-3072`, `ECDSA-P384`, `ML-DSA-65` |
| key_type | string | For example `symmetric`, `asymmetric` (or `public` for a public half) |
| purpose | string | Intended use as given at creation |
| status | string | `pre-active`, `active`, `disabled`, `deactivated`, `destroy-pending`, `deleted` |
| activation_date, expires_at, destroy_date | string or null | RFC 3339 |
| current_version | int | Current version number |
| kcv, kcv_algorithm | string | Key check value (uppercase hex) and how it was computed |
| iv_mode | string | IV handling for AEAD encryption |
| tags | string[] | Tags |
| labels | object | String key/value labels |
| export_allowed | bool | Whether export is permitted |
| ops_total, ops_encrypt, ops_decrypt, ops_sign | int | Usage counters |
| ops_limit, ops_limit_window | int, string | Usage limit and its window |
| approval_required, approval_policy_id | bool, string | Operations need a governance approval |
| created_at, updated_at | string | RFC 3339 |

Rotation schedules are separate objects: `/svc/keycore/rotation/policies`.

---

### POST /svc/keycore/keys

Permission `key.create`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Key name |
| algorithm | string | Yes | One keycore generates: AES-128/192/256[-mode], 3DES, HMAC-SHA256/384/512, RSA-2048/3072/4096/8192, ECDSA/ECDH P-256/P-384/P-521, Ed25519, X25519, ML-KEM-768/1024, ML-DSA-65/87, SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}. Anything else: `400 algorithm_unsupported` (audited `audit.key.create_refused`) |
| purpose | string | No | Intended use (for example `encrypt`, `sign`, `wrap`) |
| key_type | string | No | Derived from the algorithm when omitted |
| activation_mode | string | No | `immediate` (default), `pre-active`, or `scheduled` with `activation_date` |
| activation_date | string | For `scheduled` | RFC 3339 |
| tags | string[] | No | Tags |
| labels | object | No | String key/value labels |
| owner, cloud, region | string | No | Descriptive ownership fields |
| compliance | string[] | No | Compliance labels |
| iv_mode | string | No | IV handling for AEAD encryption |
| export_allowed | bool | No | Allow export (default false) |
| ops_limit, ops_limit_window | int, string | No | Usage limit |
| approval_required, approval_policy_id | bool, string | No | Require governance approval for operations |
| hsm | bool | No | Generate and keep the key in the tenant's HSM ([HSM_INTEGRATION.md](SECURITY/HSM_INTEGRATION.md)) |

```bash
printf 'Authorization: Bearer %s\n' "$TOKEN" |
  curl -sS --fail-with-body --cacert vecta-root-ca.pem -X POST https://localhost/svc/keycore/keys \
    -H @- -H "Content-Type: application/json" \
    -d '{"name":"customer-data-key","algorithm":"AES-256","purpose":"encrypt","tags":["prod","pii"],"labels":{"owner":"payments"}}'
```

Response `201`:
```json
{"key_id": "key_...", "tenant_id": "root", "kcv": "A1B2C3", "request_id": "req_..."}
```

---

### GET /svc/keycore/keys

Query: `tenant_id` (required), `limit`, `offset`, `include_deleted`.
For cursor paging pass `after_created_at` (RFC 3339) and `after_id` from
the previous page's `next_cursor`; the response then also carries
`has_more`. Response: `{"items": [Key, ...], "request_id": "..."}`. Only
keys the caller may see are listed ([KEY_ACCESS_MODEL.md](SECURITY/KEY_ACCESS_MODEL.md)).

---

### GET /svc/keycore/keys/{id}

Response: `{"key": Key, "request_id": "..."}`.

---

### POST /svc/keycore/keys/{id}/activate

PENDING → ACTIVE. No body.

---

### POST /svc/keycore/keys/{id}/deactivate

ACTIVE → DEACTIVATED. Existing ciphertext can still be decrypted.

---

### POST /svc/keycore/keys/{id}/rotate

New version created; the previous one is deactivated (default), kept active
or destroyed per `old_version_action`, and while not destroyed it still
decrypts and verifies what it protected (pass its `version`).

Body (all optional): `reason`, `old_version_action` (`deactivate`,
`keep-active`, `destroy`), `target_algorithm`. A `target_algorithm` other
than the key's moves the key to it **under the same key ID**: the new
version uses the target, older versions keep their own algorithm, and callers
change nothing (NIST CSWP 39 crypto agility). Keycore checks the FIPS mode
and the tenant's migration policy against the target, and answers `409
algorithm_change_refused` (audited `audit.key.algorithm_change_refused`) when
the target is unknown or weak, can't serve an operation the key serves (e.g.
an encryption key to ML-DSA), or the key is HSM-resident. Success emits
`audit.key.algorithm_changed` besides `audit.key.rotate`. Response:
`version_id`, `version`, `algorithm` (set when it changed), `kcv`.

```bash
curl -sk -X POST https://localhost/svc/keycore/keys/3fa85f64-5717-4562-b3fc-2c963f66afa6/rotate \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root"
```

---

### POST /svc/keycore/keys/{id}/destroy

Irreversible. All versions and material destroyed. State → DESTROYED.

---

### POST /svc/keycore/keys/{id}/encrypt

Body: `plaintext` (base64, standard encoding), `aad` (base64, optional),
`iv` (base64, optional), `iv_mode` (optional), `reference_id` (optional).

Response: `ciphertext` (base64), `iv` (base64), `version`, `key_id`,
`kcv`. A key with `approval_required` answers `202` with
`status: pending_approval` and `approval_request_id` instead.

```bash
printf 'Authorization: Bearer %s\n' "$TOKEN" |
  curl -sS --fail-with-body --cacert vecta-root-ca.pem -X POST "https://localhost/svc/keycore/keys/$KEY_ID/encrypt" \
    -H @- -H "Content-Type: application/json" \
    -d '{"plaintext":"SGVsbG8sIFdvcmxkIQ==","aad":"dXNlcklkPTEyMw=="}'
```

Response:
```json
{"ciphertext": "7Yp3K2vX...", "iv": "YWJjZGVmZ2hpamts", "version": 1, "key_id": "key_...", "kcv": "A1B2C3", "request_id": "req_..."}
```

---

### POST /svc/keycore/keys/{id}/decrypt

Body: `ciphertext`, `iv`, `aad` (optional), `version` (optional: the key
version encrypt returned; `0` or absent = current). Response: `plaintext`
(base64), `key_id`, `version`. An older version decrypts while it is `active`
or `deactivated` (SP 800-57 processing use); a deleted version, or a version
above the current one, answers `400` (`key version refused`).

---

### POST /svc/keycore/keys/{id}/rewrap

`key.rewrap`. Moves ciphertext onto the key's current version inside
keycore: it decrypts under `version` and encrypts under the current version,
with every check decrypt and encrypt make (key access, migration policy,
approval, FIPS) and their `audit.key.decrypt` / `audit.key.encrypt` events.
The plaintext never leaves keycore. Body: `ciphertext`, `iv`, `aad`
(optional, kept), `version` (the version that produced the ciphertext),
`reference_id` (optional). Response `data`: `key_id`, `from_version`,
`version`, `ciphertext`, `iv`. Audited as `audit.key.ciphertext_rewrapped`
(details `from_version`, `version`); refusals `result: refused` with
`version_refused` (`409`), `policy_denied`, `fips_mode_violation`,
`access_denied` (`403`).

---

### POST /svc/keycore/keys/{id}/sign

Body: `data` (base64), `algorithm` (optional signature/hash choice for the
key's type), `prehashed` (optional, below).

Response: `signature` (base64), `version`, `key_id`. The public key is at
`GET /svc/keycore/keys/{id}/public-key`.

`prehashed: true` signs `data` as an already computed digest (the HSM CA
path). HSM keys only; the hash (`algorithm` SHA-256/384/512) must match the
digest length, else `400`. A software key answers `400` ("prehashed signing
is supported for HSM keys only").

---

### POST /svc/keycore/keys/{id}/verify

Body: `data`, `signature`, `algorithm`, `version` (optional: the version
sign returned; `0` = current). Response: `verified` (boolean), `key_id`,
`version`. An older version verifies with its own algorithm while `active` or
`deactivated`.

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

Every count is computed from the tenant's live keys (status not `deleted` or
`destroyed`); technical facts (strength, post-quantum category, quantum
vulnerability, weakness) come from `pkg/cryptocatalog`; every status and date
comes from the tenant's own migration policy rules, which keycore enforces
on every key operation (docs/SECURITY/ALGORITHM_TRANSITIONS.md). The product
ships no rules and no dates. Nothing is estimated or seeded. Served by the `pkg/route` kernel:
the tenant comes from the token (a conflicting `tenant_id` is refused as
`tenant_mismatch`), and each call emits its own audit event, refusals
included.

| Route | Permission | Audit | Response `data` |
|---|---|---|---|
| `GET /agility/posture` | `key.agility.read` | `audit.key.agility_posture_read` (details `total_keys`, `quantum_vulnerable_keys`, `not_assessed_keys`, `uncovered_keys`) | `assessed` (false with no live keys), `as_of`, `total_keys`, `not_assessed_keys`, `quantum_vulnerable_keys`, `post_quantum_keys`, `weak_keys`, `uncovered_keys` (weak or quantum-vulnerable keys no rule covers), `policy_rules`, `min_algorithm_tier` (governance posture), `status_counts` (live keys by policy status today: `allowed`, `deprecated`, `decrypt_only`, `disallowed`), `milestones` (`[{date, action, rule_id, rule_name, target_algorithm, key_count, algorithms}]`: upcoming rules that reach live keys), `algorithms`, `findings` |
| `GET /agility/algorithms` | `key.agility.read` | `audit.key.agility_inventory_read` | `[{algorithm, key_count, percentage, assessed, canonical, family, security_bits, pqc_category, quantum_vulnerable, post_quantum, weak, note, policy_status, policy_rule, target_algorithm, next_change}]`, plus top-level `total_keys`. `assessed: false` means the name states no parameter set (e.g. `RSA`) |
| `GET /agility/policy/rules` | `key.agility.read` | `audit.key.agility_policy_rules_listed` | the tenant's migration rules |
| `POST /agility/policy/rules` | `key.agility.write` | `audit.key.agility_policy_rule_created` (details `name`, `match_kind`, `match_value`, `action`, `effective_date`, `target_algorithm`) | the new rule (`201`) |
| `PUT /agility/policy/rules/{id}` | `key.agility.write` | `audit.key.agility_policy_rule_updated` | the updated rule |
| `DELETE /agility/policy/rules/{id}` | `key.agility.write` | `audit.key.agility_policy_rule_deleted` | `{deleted: true}` |
| `GET /agility/keys-by-algorithm?algorithm=` | `key.agility.read` | `audit.key.agility_keys_by_algorithm_read` | `{algorithm, keys}` |

The keycore migration plans (`/agility/migration-plans`) were removed in
7.3.0-beta: they recorded intent only and inferred progress from
tenant-wide algorithm counts. Migrations run in the pqc service
(`/pqc/migration/plans`, execute and rollback), which moves a keycore key to
its target with `POST /keys/{id}/rotate` `target_algorithm`.

**Migration policy rules.** Body: `name`; `match_kind` `algorithm` (with
`match_value` the algorithm), `family` (`match_value` e.g. `RSA`, `ECDSA`,
`AES`), `quantum_vulnerable`, `weak`, or `below_strength` (`match_value` a
number of bits); `action` `deprecated` (keys keep working, flagged),
`decrypt_only` (create, import, rotate, encrypt, sign, wrap, MAC, derive,
service-derive, KEM encapsulate and data-key generation refused; decrypt,
verify, unwrap, decapsulate and attested release still work) or `disallowed`
(every cryptographic operation refused; export, destroy and policy changes
still work); `effective_date` (required, the customer's choice); optional
`target_algorithm` (a known, non-weak algorithm) and `note`. The strictest
rule in force applies. A refusal answers `403 policy_denied` and emits
`audit.key.crypto_policy_refused` (`reason` `crypto_policy_decrypt_only` or
`crypto_policy_disallowed`, `operation`, `algorithm`, `key_id`, `rule_id`,
`rule_name`, `rule_action`); the operation's own event carries the same
`reason`. Rules are cached per tenant for up to 10 seconds.

**Floors are rules.** `quantum_vulnerable → decrypt_only` requires
post-quantum algorithms for new protection; `below_strength` sets a strength
floor. (The 5.1.0-beta tenant-tier check read a governance setting that does
not exist and was removed in 5.4.0-beta.)

**Risk assessment (CARAF).** Every value is the customer's; keycore computes
exposure (X + Y against the soonest threat's Z) and tracks decisions.

| Route | Permission | Audit | Response `data` |
|---|---|---|---|
| `GET /agility/caraf/assessment` | `key.agility.read` | `audit.key.caraf_assessment_read` (details `assets`, `exposed`, `undecided_at_risk`) | `as_of`, `summary` (`assets`, `threats`, `exposed`, `at_limit`, `time_to_spare`, `not_assessed`, `no_threat`, `undecided_at_risk`, `overdue`, `acceptance_expired`), `profile` (assets with each value recorded: `owner`, `shelf_life`, `migration_time`, `cost`, `sensitivity`, `live_keys`, `complete`; `unknown` is not counted), `heatmap` (`{sensitivity: {timeline: count}}`), `assets` (`[{asset, algorithms, missing_keys, threats, x, y, z, timeline, margin_years, missing, suggestion, decision_state}]`), `roadmap`, `findings` |
| `GET\|POST /agility/caraf/threats`, `PUT\|DELETE /agility/caraf/threats/{id}` | read / `key.agility.write` | `audit.key.caraf_threats_listed`, `caraf_threat_created`, `caraf_threat_updated`, `caraf_threat_deleted` | threats: `name`, `category` (`quantum`, `cryptanalytic`, `regulatory`, `business`, `other`), `match_kind`/`match_value` (as rules), `years_to_threat` (required, 0-100), `note` |
| `GET\|POST /agility/caraf/assets`, `PUT\|DELETE /agility/caraf/assets/{id}` | read / `key.agility.write` | `audit.key.caraf_assets_listed`, `caraf_asset_created`, `caraf_asset_updated`, `caraf_asset_deleted` | assets: `name`, `description`, `owner`, `ownership` (`enterprise`, `third_party`), `implementation` (`software`, `hardware`, `hsm`, `cloud_service`, `embedded`), `pqc_support` (`supported`, `planned`, `none`), `location` (`on_prem`, `cloud`, `hybrid`, `edge`), `jurisdiction`, `sensitivity` (`low`…`critical`), `shelf_life_years` (X), `migration_years` (Y), `cost` (`low`, `medium`, `high`), `algorithms`, `key_ids` (must be keys of the tenant); omitted enums are `unknown`. An update keeps the decision |
| `PUT /agility/caraf/assets/{id}/decision` | `key.agility.write` | `audit.key.caraf_decision_recorded` (warning; details `asset`, `decision`, `owner`, `status`, `due`, `review_by`) | the asset. Body `decision` (`secure`, `accept`, `phase_out`, `compensating_control`; empty clears), `owner`, `due` (required except for accept), `review_by` (required and future for accept), `status` (`open`, `in_progress`, `done`), `note`. `decided_by` is the verified caller |

**Swap drill.** A real rehearsal on the keycore node that serves the
request: throwaway keys from keycore's key generation, checked round trips
through the key engine, nothing added to the inventory. Both algorithms
must pass the tenant's FIPS mode; the target must be allowed for new
protection by the tenant's migration policy.

| Route | Permission | Audit | Response |
|---|---|---|---|
| `POST /agility/drills` | `key.agility.write` | `audit.key.agility_drill_run` (details `from_algorithm`, `to_algorithm`, `iterations`, `drill_result`, `drill_error`; refused `fips_mode_violation`, `crypto_policy_disallowed`, `crypto_policy_decrypt_only`) | `201 data`: `id`, `from`/`to` (`algorithm`, `operation` `sign_verify`\|`encrypt_decrypt`\|`encapsulate_decapsulate`, medians `keygen_us`, `operation_us`, `check_us`, `private_key_bytes`, `public_key_bytes`, `output_bytes`, `round_trips`), `iterations`, `result` (`passed`, `failed` with `error`), `comparison` (`keygen_ratio`, `operation_ratio`, `check_ratio` target over source; `output_bytes_diff`, `public_key_bytes_diff`), `run_by`, `created_at`. Body `from_algorithm`, `to_algorithm` (parameter sets, must differ), `iterations` (1-10, default 5; each algorithm stops after 20 s, `round_trips` is what ran). `400 drill_unsupported` for a name without a parameter set or an algorithm with no round trip (ECDH); `409 drill_in_progress` while another drill runs on the node |
| `GET /agility/drills` | `key.agility.read` | `audit.key.agility_drills_listed` | `items`: the latest 50 drills, newest first |

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
| `GET /rotation/cryptoperiods` | `key.rotation.read` | `audit.key.cryptoperiods_listed` (each category's `default_days`, `days`, `custom`) |
| `PUT /rotation/cryptoperiods/{category}` | `key.rotation.write` | `audit.key.cryptoperiod_set` (body `{"days": 1..3650}`; refused `invalid_days`, `unknown_category`) |
| `DELETE /rotation/cryptoperiods/{category}` | `key.rotation.write` | `audit.key.cryptoperiod_reset` (refused `not_custom`) |
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

### Event streams: /svc/audit/webhooks

An event stream delivers every persisted audit event whose `action`
matches one of its `events` patterns, through a **connection** (Playbooks →
Connections, `/svc/compliance/compliance/playbooks/connections`). The
connection holds the endpoint and credentials, sealed in compliance; the
stream holds only `connection_id` (2.10.0-beta,
docs/SECURITY/CONNECTIONS.md). Delivery runs on the node that ingested the
event. The dashboard shows streams under Playbooks → Event streaming; the
API path keeps its old name.

| Route | Permission | Audit |
|---|---|---|
| `GET /webhooks` | `audit.webhook.read` | `audit.audit.webhooks_listed` |
| `POST /webhooks` | `audit.webhook.write` | `audit.audit.webhook_created` |
| `PATCH /webhooks/{id}` | `audit.webhook.write` | `audit.audit.webhook_updated` |
| `DELETE /webhooks/{id}` | `audit.webhook.write` | `audit.audit.webhook_deleted` |
| `POST /webhooks/{id}/test` | `audit.webhook.write` | `audit.audit.webhook_tested` |
| `GET /webhooks/{id}/deliveries` | `audit.webhook.read` | `audit.audit.webhook_deliveries_listed` |

- **Body:** `{"name", "connection_id", "events", "enabled"}`. `url`,
  `format`, `secret`, `clear_secret` and `headers` are refused (400): streams
  send through a connection.
- **`connection_id`:** checked with compliance when saved. Unknown in the
  tenant: 400. A type that can't carry a stream (Jira, ServiceNow): refused,
  `reason: connection_not_streamable`. Compliance unreachable: `503
  connections_unavailable`. The response carries `connection_type`.
- **What each connection type receives:** `webhook`: `{event_type, event}`,
  with the connection's `headers`, and
  `X-KMS-Signature: sha256=<hex HMAC-SHA256(signing_secret, body)>` when it
  has a signing secret; `slack`: `{text}`; `teams`: an Adaptive Card;
  `splunk_hec`, `datadog`, `elastic`, `sentinel`, `syslog`: see
  **Connections** under Playbooks (`pkg/siem`). HTTP requests also carry
  `X-KMS-Event-Type` and `X-KMS-Event-ID`.
- **Opening the connection:** the audit service asks compliance for it
  (`POST /compliance/connections/{id}/resolve`, callable only by `kms-audit`
  and `kms-governance`, audited as `audit.compliance.connection_resolved`)
  and keeps it in memory for 60 seconds. A change in compliance reaches
  deliveries within that time. If it can't be opened, the delivery is
  recorded as failed with the reason.
- **Every delivery,** real or test, emits `audit.audit.webhook_delivered`:
  `result` is `success` or `failure`; details are `event_id`,
  `event_action`, `http_status` (0 for syslog), `attempts`, `latency_ms`,
  `format` (the connection type) and `connection_id`. It is also recorded in
  the node-local `webhook_deliveries`. `audit.audit.webhook_*` events are
  never delivered. Errors name the host, never the URL (a Slack or Teams URL
  is a credential).
- **`events`:** `*`, a prefix such as `audit.key.*`, or an exact action such
  as `audit.key.rotate`. Older names like `key.created` never matched an
  audit action and are refused.
- **Legacy streams** (`legacy: true`): a stream a release before 2.10.0-beta
  stored with its own `url`, `format`, secret and headers (sealed under the
  audit master key). It keeps delivering that way until the primary's
  migration job moves its credentials into a connection
  (`audit.audit.webhook_migrated`; any open exposure-register entry moves
  with them). `json` becomes a `webhook` connection (headers and signing
  secret kept), `slack` a `slack` one, `splunk_hec` a `splunk_hec` one (token
  from `Authorization: Splunk <token>`), `datadog` a `datadog` one (key from
  `DD-API-KEY`). A stream whose headers don't map is left as it is and
  reported once per process as `audit.audit.webhook_migration_refused`
  (`reason`: `no_splunk_token_header`, `no_datadog_api_key_header`,
  `unmapped_headers`, `unknown_format`). Choosing a connection for it
  (`PATCH` with `connection_id`) drops its own credentials and retires their
  exposure entry.
- **Delivery:** three attempts with backoff and a per-webhook circuit
  breaker. The queue holds 4,096 events. A full queue is recorded as a failed
  delivery (`delivery queue full`) and audited; it is never dropped silently.
  Only the primary updates `last_delivery_*` and `failure_count` (a
  replicated row); members keep their attempts in `webhook_deliveries`.
- **Test:** sends a labelled event (`audit.audit.webhook_test`) through the
  same path. Response: `success`, `status`, `http_status`, `latency_ms`,
  `error`.

---

### Canary keys: /svc/keycore/canary/keys

A canary key is a decoy key ID with no material. Any reference to it through
the key API (`GetKey`'s not-found path) returns `404` to the caller, records a
trip in this node's trip log, emits `audit.keycore.canary_tripped` and raises
a critical `canary_tripped` threat signal. Its ID is minted like a real key ID
(`key_…`). Created from **Keys → Canary Key**.

| Route | Permission | Audit |
|---|---|---|
| `GET /canary/keys` | `key.canary.read` | `audit.key.canary_keys_listed` |
| `POST /canary/keys` | `key.canary.write` | `audit.key.canary_key_created` (`name`) |
| `GET /canary/keys/{id}/trips` | `key.canary.read` | `audit.key.canary_trips_listed` |
| `DELETE /canary/keys/{id}` | `key.canary.write` | `audit.key.canary_key_deactivated` (warning) |

- **Create body:** `{"name": "..."}`. Response `item`: `id`, `name`,
  `active`, `created_at`, `trip_count`, `last_tripped`.
- **Trip counts** come from the node-local trip log, so a member shows the
  trips it served. Every trip on every node reaches Posture and Reporting
  through the audit pipeline.
- **Removed in 2.0.0-beta:** `GET|POST /canary`, `GET|DELETE /canary/{id}`,
  `GET /canary/{id}/trips`, `GET /canary/summary`, and
  `POST /canary/{id}/trip`, which recorded a trip that never happened.

### Tenant IDs for the alert sync: /svc/auth/internal/tenant-ids

`GET /internal/tenant-ids` returns `{"items": [<active tenant IDs>]}`. It is
a kernel route (`audit.auth.tenant_ids_listed`, detail `count`). Only the
`kms-reporting` service identity may call it; anything else is refused with
`reason: service_identity_required`. Reporting uses it so the scheduled
alert sync covers every tenant.

### Threat detection (keycore → posture → reporting)

Keycore's `ThreatSweeper` evaluates four rules over each node's key usage
trail every minute: `new_actor`, `volume_spike`, `dormant_key_activity`, and
`canary_tripped` (raised at probe time). Each new signal emits
`audit.keycore.threat_signal_raised` with `signal_id`, `signal_type`,
`key_id`, `actor_id`, `severity` (`critical`, `high`, `medium`),
`description` and `detected_at`. There is no threat API:

- **Posture** turns each signal into one finding (`engine: corrective`,
  `finding_type: threat_<signal_type>`, evidence names the signal and audit
  event), audited as `audit.posture.threat_finding_raised`. Acknowledge or
  resolve it with `PUT /posture/findings/{id}/status`; resolving is final.
- **Reporting** raises `critical` and `high` signals as alerts, which the
  header's unread count includes.
- **Removed in 2.0.0-beta:** `GET /threat/signals`,
  `POST /threat/signals/{id}/ack`, `GET /threat/dashboard`, the
  `/credential-bindings` routes and `/keys/{id}/credential-bindings`, the
  `credential_binding` field of encrypt and wrap requests, and the posture
  leak scanner (`/leaks/*`).

---

### POST /svc/keycore/keys/{id}/derive

Body: `algorithm` (`hkdf-sha256`, `hkdf-sha384` or `hkdf-sha512`; anything
else is refused), `salt` and `info` (base64, optional), `length_bits`
(multiple of 8, at most 4096, default 256), `reference_id` (optional).

Response: `derived_key` (base64), `key_id`, `version`, `algorithm`,
`length_bits`. A key with `approval_required` answers `202`
`pending_approval`.

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
Audit: `audit.key.service_derive`; every refusal is `audit.key.service_derive_refused`, with the response's error code as `reason` (for example `service_identity_required`). See
[SECURITY/DATAPROTECT_KEY_DERIVATION.md](SECURITY/DATAPROTECT_KEY_DERIVATION.md).

---

### POST /svc/keycore/keys/{id}/mac

Body: `data`, `operation` (generate/verify), `mac` (for verify), `algorithm` (HMAC-SHA256/384/512, CMAC). Response: `mac` or `valid`.

---

### POST /svc/keycore/keys/{id}/export

Body: `wrapping_key_id` (a KEK in the same tenant) or `export_mode:
"public-plaintext"` (public half of an asymmetric key only). Needs the key's
`export_allowed`. Wrapped export responds `wrapped_material`, `material_iv`,
`kcv`, `wrapping_key_id`, `wrapping_key_kcv`, `export_format:
"aes-gcm-wrapped-by-kek"`. Public export responds `public_key_plaintext`,
`plaintext_encoding`, `component_type`, `export_format:
"public-plaintext"`. Private material never leaves keycore in the clear.

---

### GET /svc/keycore/keys/{id}/versions

Response `items[]`: `id`, `key_id`, `version`, `status`, `public_key`
(asymmetric), `rotated_from`, `rotation_reason`, `created_at`.

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

Every keycore request needs a verified token (a user token through the
gateway, or a service JWT). Since 4.0.0-beta a request without one gets
`401 unauthorized` before any handler runs, audited as
`audit.key.request_refused` (`reason: unauthenticated`). The only exceptions
is the reconciler route `GET /keys/due-for-lifecycle`, which requires the
`X-Internal-Token` instead (`POST /tenants/onboard` and `POST
/keys/{id}/archive` were removed in 5.3.0-beta: neither did anything). Keycore refuses to start without the
key that verifies tokens. Keycore decides key access from the verified token only. `X-Actor-*`,
`X-KMS-Subject` and `X-KMS-Interface` headers are ignored for authorization
and recorded in `audit.key.actor_headers_ignored`. A key operation the caller
may not perform returns `403 access_denied` and emits
`audit.key.access_refused` with a `reason`.

### Key and access management permissions (4.0.0-beta)

These routes go through the `pkg/route` kernel: a caller without the
permission gets `403` (`reason: permission_denied`), audited under the
route's own subject. Built-in `admin` and `tenant-admin` hold `*`; other
roles need the permission named here. Service principals are allowed.

| Route | Permission | Audit subject |
|---|---|---|
| `GET /keys/{id}/access-policy` | `key.access.read` | `access_policy_read` |
| `PUT /keys/{id}/access-policy` | `key.access.manage`, and the caller created the key or is a tenant admin (else `403 not_key_owner`) | `access_policy_updated` |
| `GET /access/groups`, `/access/settings`, `/access/interface-policies` | `key.access.read` | `access_groups_listed`, `access_settings_read`, `interface_policies_listed` |
| `POST /access/groups`, `DELETE /access/groups/{id}`, `PUT /access/groups/{id}/members` | `key.access.admin` | `access_group_created`, `access_group_deleted`, `access_group_members_updated` |
| `PUT /access/settings` | `key.access.admin` | `access_settings_updated` |
| `POST /access/interface-policies`, `DELETE /access/interface-policies/{id}` | `key.access.admin` | `interface_policy_upserted` / `_deleted` |
| `POST /keys` | `key.create` | `create_requested` |
| `POST /keys/import`, `POST /keys/bulk-import` | `key.import` | `import_requested`, `bulk_import_requested` |
| `POST /keys/form` | `key.form` | `form_requested` |
| `PUT /keys/{id}`, `PUT /keys/{id}/iv-mode` | `key.update` | `update_requested`, `iv_mode_update_requested` |
| `POST /keys/{id}/rotate`, `POST /keys/bulk-rotate` | `key.rotate` | `rotate_requested`, `bulk_rotate_requested` |
| `POST /keys/{id}/activate`, `POST /keys/{id}/versions/{ver}/activate` | `key.activate` | `activate_requested`, `version_activate_requested` |
| `POST /keys/{id}/deactivate`, `POST /keys/{id}/versions/{ver}/deactivate` | `key.deactivate` | `deactivate_requested`, `version_deactivate_requested` |
| `POST /keys/{id}/disable` | `key.disable` | `disable_requested` |
| `POST /keys/{id}/destroy`, `DELETE /keys/{id}/versions/{ver}`, `POST /keys/bulk-delete` | `key.destroy` | `destroy_requested`, `version_delete_requested`, `bulk_delete_requested` |
| `PUT /keys/{id}/export-policy` | `key.export_policy_update` | `export_policy_update_requested` |
| `PUT /keys/{id}/approval` | `key.approval_update` | `approval_update_requested` |
| `PUT /keys/{id}/usage/limit`, `POST /keys/{id}/usage/reset` | `key.usage_limit_update` | `usage_limit_update_requested`, `usage_reset_requested` |
| `POST /tags`, `DELETE /tags/{name}` | `key.tags.write` | `tag_upsert_requested`, `tag_delete_requested` |

| `GET /inventory/keys`, `/inventory/orphans`, `/inventory/duplicates`, `/inventory/dependencies`, `/rotation/analytics`, `/rotation/analytics/overdue`, `/enterprise/summary`, `/health/summary`, `/compromise/events`, `/analytics/usage`, `/analytics/hotspots`, `/analytics/trends`, `/enterprise/dspm/findings`, `/enterprise/dspm/events`, `/enterprise/compliance/dashboard`, `/enterprise/cost/optimization` (5.0.0-beta) | `key.inventory.read` | `inventory_keys_read`, ... (AUDIT_EVENTS_2026-09.md) |
| `GET /ceremony`, `GET /ceremony/{id}`, `GET /ceremony/guardians` | `key.ceremony.read` | `ceremonies_listed`, `ceremony_read`, `ceremony_guardians_listed` |
| `POST /ceremony`, `POST /ceremony/{id}/complete`, `POST /ceremony/{id}/abort`, `POST /ceremony/guardians`, `DELETE /ceremony/guardians/{id}` | `key.ceremony.write` | `ceremony_created`, `ceremony_completed`, `ceremony_aborted`, `ceremony_guardian_created`, `ceremony_guardian_deleted` |
| `POST /ceremony/{id}/shares` | `key.ceremony.share` | `ceremony_share_submitted` |
| `POST /compromise/events`, `POST /compromise/events/{id}/status`, `POST /compromise/advisories/ingest` | `key.compromise` | `compromise_reported`, `compromise_status_updated`, `compromise_advisories_ingested` |
| `POST /enterprise/orchestration/runs` | `key.rotate` | `orchestration_run_requested` |
| `GET /enterprise/controls`, `GET /enterprise/controls/{category}/{id}` | `key.enterprise.read` | `enterprise_controls_listed`, `enterprise_control_read` |
| `POST /enterprise/controls`, `POST /enterprise/anomaly/scan`, `POST /enterprise/dspm/findings`, `POST /enterprise/kdf/derive`, `POST /enterprise/verification/fingerprint` (key must be visible), `POST /enterprise/advanced-encryption/search-token`, and the `POST /enterprise/{area}/{kind}` control upserts | `key.enterprise.write` | `enterprise_control_upserted`, `enterprise_anomaly_scan`, `dspm_finding_upserted`, `enterprise_kdf_derive`, `fingerprint_verified`, `search_token_created`, `enterprise_<category>_upserted` |
| `GET /scheduling/jobs` | `key.scheduling.read` | `scheduling_jobs_listed` |
| `POST /scheduling/jobs`, `PATCH /scheduling/jobs/{id}`, `DELETE /scheduling/jobs/{id}` | `key.scheduling.write` | `scheduling_job_created`, `scheduling_job_updated`, `scheduling_job_deleted` |
| `POST /inventory/sync`, `POST /inventory/dependencies` | `key.inventory.write` | `inventory_synced`, `inventory_dependency_upserted` |
| `POST /analytics/metrics` | `key.analytics.write` | `analytics_metric_recorded` |
| `POST /keys/{id}/health/recalculate` | `key.health.write` (key must be visible) | `health_recalculated` |
| `POST /keys/{id}/rotation-metrics` | `key.rotation.write` (key must be visible) | `rotation_metric_recorded` |
| `POST /keys/{id}/usage/meter` | `key.usage.meter` (and the per-key grant) | `usage_meter_requested` |
| `POST /keys/{id}/attest` | `key.attest` (key must be visible) | `attest_requested` |
| `POST /keys/{id}/verify-material`, `POST /keys/{id}/destruction-check` | `key.integrity.verify` (key must be visible) | `verify_material_requested`, `destruction_checked` |
| `POST /fips/self-test` | `key.fips.selftest` | `fips_self_test_requested` |

**Destruction check (6.5.0-beta).** `POST /keys/{id}/destruction-check`
looks for a destroyed key's material where keycore keeps it: the
`key_versions` rows (the only table holding material, encrypted under the
MEK or wrapped by the HSM) and, when the HSM connector is enabled, every
HSM object under the key's label prefix (`vecta:<tenant>:key:<id>:v*`).
Response `{"check": {...}}`: `key_id`, `status`, `version_rows`, `hsm`
(`checked` | `not_configured` | `unreachable`), `hsm_objects` (labels
found), `hsm_error`, `result` (`removed` | `material_remains` |
`incomplete` when the HSM couldn't be asked), `not_covered` (what the check
can't see: database pages until vacuumed, backups, process memory) and
`checked_at`. A key that isn't destroyed is refused with 409
`key_not_destroyed`. Audited as `audit.key.destruction_checked` with
`result`, `version_rows`, `hsm`, `hsm_objects`; `material_remains` is
`severity: critical`. It replaces the former `zeroize-verify` route, whose
`zeroization_verified` looked only at the metadata cache and could never
answer for a destroyed key.

**Key visibility (5.0.0-beta).** `GET /keys` and every per-key read
(`GET /keys/{id}`, `/versions`, `/versions/{ver}`, `/kcv`, `/usage`,
`/approval`, `/iv-log`, `/iv-log/{ref}`, `/rotation-metrics`, `/health`,
`/consumers`, `/public-key`, `/access-policy`, `/hsm`) return only keys the caller can
see: keys they created, keys an active grant gives them (directly or through
a group; any operation, including the view-only `read`), keys their
workload is bound to, or every key for tenant admins, service identities
and holders of `key.inventory.read`. A hidden key gets the same `404
not_found` as a missing one and emits `audit.key.access_refused`
(`operation: read`, `reason: not_visible`). Grants accept the operation
`read`, which allows no use of the key.

**Delegated key use (6.0.0-beta).** A platform service performing a user's
request sends `X-Vecta-Delegated-Token` (the user's bearer token) and
`X-Vecta-Key-Usage` (one of `encrypt`, `decrypt`, `wrap`, `unwrap`,
`fpe-encrypt`, `fpe-decrypt`, `tokenize`, `detokenize` from dataprotect,
`certificate-sign`, `crl-sign` from certs, and `read` from ekm; payment's
usages left with it in 7.0.0-beta).
Keycore verifies the token, accepts it only from a service identity and for
a user of the key's tenant, and decides key access as that user for that
usage; otherwise `403 delegation_refused` with the reason. These headers are
internal: Envoy removes them from outside requests. Grants accept the
usages above as operations. `read` is a per-key read (ekm's public-key
read, 6.18.0-beta): it is decided by the user's view of the key, and on any
key operation it is refused (`403`, `reason: delegation_usage_mismatch`).

The actor is the verified token's. `updated_by` in `PUT
/keys/{id}/access-policy` and `created_by` in `POST /access/groups` are
rejected with `400` (they were trusted before 4.0.0-beta), and the
access-policy body must be `{"grants": [...]}` (the bare-array form is
gone). A `tenant_id` in a request body must match the token's tenant
(`403 tenant_mismatch`). The model these routes are part of is
[SECURITY/KEY_ACCESS_MODEL.md](SECURITY/KEY_ACCESS_MODEL.md).

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

Every key status change (`/activate`, `/disable`, `/deactivate`, suspend,
compromise) must be a move the lifecycle state table allows
(`services/keycore/lifecycle_state.go`, docs/AUTOMATION_ALKM_PQC.md). A
compromised key only moves to destroyed. Anything else returns
`409 status_transition_refused` and emits `audit.key.status_transition_refused`.

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

### External edge key exchange: `/svc/certs/certs/edge-tls` (6.8.0, root tenant only)

The TLS 1.3 groups the external listeners accept: Envoy's HTTPS edge and
the KMIP listener (docs/SECURITY/INTERNAL_TLS.md, "External edge key
exchange"). Same permissions as Service mTLS; another tenant is refused with
`not_root_tenant`.

- **`GET /certs/edge-tls`** (`edge_tls_read`): `edge.policy`
  (`kx_profile`, `generation`), `edge.listeners` (each with
  `expected_groups`, `observed`: the groups it accepted in the last
  measurement, the group negotiated when every group is offered, the
  certificate serial and the time, and `applied`), `edge.applied`, and the
  groups of each profile.
- **`PUT /certs/edge-tls`** (`edge_tls_policy_updated`):
  - **Body:** `{"kx_profile": "pqc-required|pqc-preferred|classical", "reason": "..."}`.
  - Published to `mtls-policy.json` (`edge`, read by KMIP on every
    handshake) and `edge-ecdh-curves` (Envoy's list; `infra/envoy/entry.sh`
    hot-restarts Envoy with it).
  - **Refusals:** `invalid_policy`, `unchanged`.
- **Measurement:** certs completes a TLS 1.3 handshake with each listener
  (`CERTS_EDGE_PROBE_TARGETS`, default `envoy=envoy:443,kmip=kmip:5696`),
  once per group, every 15 s while a change is pending and every 5 min
  after. `audit.certs.edge_tls_applied` is emitted once per generation when
  every listener accepts exactly the new groups.
  - The probe pins the certificate certs installed for each listener: a
    listener serving any other certificate is not measured.
  - Every group is measured in every FIPS mode. When Go won't offer X25519
    alone (FIPS mode on), the probe sends its own TLS 1.3 ClientHello
    offering only X25519 and reads the group the ServerHello selects; it
    performs no key exchange.
- **`GET /certs/edge-tls/measurement`** (`edge_tls_measurement_read`, any
  verified caller, 6.13.0): `listeners` (`name`, `accepted_groups`,
  `negotiated_group`, `measured_at`) and `configured`. Read by the pqc
  inventory with its service token.

### Edge certificate: `/svc/certs/certs/edge-tls/certificate` (6.13.0, root tenant only)

The certificates the external listeners serve: `listener` `https` (Envoy,
the default) or `kmip` (6.14.0) in every body below; each has its own
source. The GET above returns them as `edge.certificate` (HTTPS) and
`edge.kmip_certificate`, each with `listener`, `choice` (`source`, `ca_id`, `key_algorithm`, who and
when), `installed` (this node's certificate: serial, subject, issuer, SANs,
`not_after`, key algorithm, `from_choice`), `pending_csr` and `served` (the
probe saw exactly that certificate served).

- **`PUT /certs/edge-tls/certificate`**
  (`edge_tls_certificate_source_updated`):
  - **Body:** `{"listener": "https|kmip", "source": "runtime|ca|external", "ca_id": "...",
    "key_algorithm": "ECDSA-P256|ECDSA-P384|RSA-3072", "reason": "..."}`.
  - `runtime`: issued by `vecta-runtime-root` (default). `ca`: issued by a
    software CA from the PKI tab and renewed by certs before expiry.
    `external`: see below. Stored replicated; every node's materializer
    applies it within 5 minutes, this node at once.
  - **Refusals:** `invalid_listener`, `invalid_source`, `unknown_ca`, `ca_not_active`,
    `hsm_ca_not_supported` (renewal runs unattended), `internal_services_ca`,
    `invalid_key_algorithm`, `unchanged`.
- **`POST /certs/edge-tls/csr`** (`edge_tls_csr_created`, runs on the node
  that receives it):
  - **Body:** `{"listener": "https|kmip", "subject_cn": "...", "sans": [...], "key_algorithm": "..."}`.
  - Generates this node's key (kept on the node's runtime certificate
    volume) and returns `csr.csr_pem`. A new CSR replaces the pending key.
  - **Refusals:** `source_not_external`, `invalid_request`,
    `invalid_key_algorithm`.
- **`POST /certs/edge-tls/certificate/install`**
  (`edge_tls_certificate_installed`, runs on the node that receives it):
  - **Body:** `{"listener": "https|kmip", "certificate_pem": "...", "chain_pem": "...", "reason": "..."}`.
  - Installed only if it is for the pending key, valid now, allows TLS
    server authentication, and is signed by the first chain certificate.
    Envoy reloads it (SDS); KMIP on its next handshake. The materializer keeps it until it expires, then
    falls back to `vecta-runtime-root`; renew it with a new CSR.
  - **Refusals:** `source_not_external`, `no_pending_key`,
    `invalid_certificate`, `key_mismatch`, `not_valid_now`,
    `not_server_certificate`, `bad_chain`, `chain_required`.

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

### GET/POST /svc/certs/certs/ca

`GET` lists CAs (`items[]`: `id`, `tenant_id`, `name`, `parent_ca_id`,
`ca_level`, `algorithm`, `ca_type`, `key_backend`, `key_ref`, `cert_pem`,
`subject`, `status`, `created_at`, `updated_at`). `POST` creates one. Body:
`name`, `ca_level` (`root` or `intermediate`), `parent_ca_id` (required for
an intermediate), `algorithm`, `ca_type`, `key_backend`, `key_ref`,
`subject` (DN string), `validity_days`. Response `201`: `ca`.

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

Immutable audit log: SHA-256 hash chain, per-event HMAC and signed checkpoints ([SECURITY/AUDIT_INTEGRITY.md](SECURITY/AUDIT_INTEGRITY.md)), with SIEM export.

### AuditEvent Object

`id`, `tenant_id`, `sequence`, `timestamp`, `service`, `action` (the
subject, e.g. `audit.key.decrypt`), `actor_id`, `actor_type` (`user`,
`client`, `service`, `system`), `target_type`, `target_id`, `method`,
`endpoint`, `source_ip`, `user_agent`, `correlation_id`,
`parent_event_id`, `session_id`, `result` (`success`, `failure`,
`refused`), `status_code`, `error_message`, `duration_ms`,
`fips_compliant`, `approval_id`, `risk_score`, `tags`, `details`, and the
integrity fields `chain_hash`, `previous_hash`, `hmac_sig`, `hmac_key_id`.

---

### GET /svc/audit/audit/events

Query: `tenant_id`, `action` (exact), `action_prefix` (repeatable, up to 5,
OR-ed; matched literally, so `_` and `%` are not wildcards; the HSM tab uses
`action_prefix=audit.hsm.&action_prefix=audit.key.hsm_`), `actor_id`,
`result`, `target_id`, `session_id`, `correlation_id`, `risk_min`,
`risk_max` (inclusive; 7.17.0-beta), `service` (7.17.0-beta),
`exclude_http_requests=true` (drops generic HTTP request records;
7.17.0-beta), `from` and `to` (RFC 3339, inclusive), `order=asc` (oldest
first with a stable tiebreak, for readers that follow a cursor; default
newest first; 7.19.0-beta), `limit` (at most 1000), `offset`.
Response: `{"items": [AuditEvent, ...], "request_id": "..."}`.

```bash
printf 'Authorization: Bearer %s\n' "$TOKEN" |
  curl -sS --fail-with-body --cacert vecta-root-ca.pem -H @- \
    "https://localhost/svc/audit/audit/events?tenant_id=root&action_prefix=audit.key.&result=refused&from=2026-09-01T00:00:00Z&limit=50"
```

---

### GET /svc/audit/audit/activity/stats

Permission `audit.events.read`; kernel event `audit.audit.activity_stats_read`
(details `from`, `to`, `total`); a malformed window is refused with `reason`
`bad_window` (7.17.0-beta). The Audit Log → Activity charts. Query `from`
and `to` (RFC 3339); without `from`, the window starts at the tenant's first
event ("since uptime"). Counts are computed in SQL over the whole window,
never a sample, and exclude generic HTTP request records. Response
`{"stats": {...}}`: `from`, `to`, `bucket_seconds` (`pkg/timebucket`: an
hour for a day, 6 hours for a week, a day for a month, a week up to a year,
then whole days for at most 60 points), `total`, `by_result`,
`top_services` and `top_actors` (top ten `{key, count}`), `actors`,
`services` (distinct), `risk_buckets` (`0-20` … `81-100`), `series`
(`{start, count}` per bucket). Each count equals the number of events
`GET /audit/events` returns for the same window with `exclude_http_requests`
and the matching `result`, `service`, `actor_id`, `risk_min`/`risk_max`, or
the bucket's `from`/`to` (`TestAuditStatsWindows`, on SQLite and Postgres).

---

### Operations metrics: /svc/audit/ops-metrics

Built by the audit service from every persisted event whose details carry
`metered_op` (`pkg/audit.MeteredOp`) with `duration_ms` and `result`
(`success`, `refused` or `failure`). Emitters set it with
`pkg/audit.Metered(details, op, start)`, and a kernel route with
`route.Spec{Metered: "<op>"}`. Meter an operation only in the service that
does its cryptography, so one request is counted once. There is no write
endpoint (the record endpoint was removed in 2.1.0-beta). Every read takes
`?window=1h|6h|24h|7d|30d` (default `24h`). On a cluster primary the
figures cover every node: members' operations are counted as the audit
relay passes their replicated events. A member forwards these reads to the
primary, so every node returns the cluster figures (2.3.0-beta).

| Method | Path | Returns |
|---|---|---|
| GET | `/svc/audit/ops-metrics/overview` | `overview`: `total_ops`, `total_values` (values processed; a batch call's `count`), `total_errors` (refused + failed), `error_rate`, `avg_latency_ms`, `scope` (`cluster` on the primary, `node` on a member, `standalone`), `by_node` (`node`, `total_ops`), `recorded_since` (first recorded hour, or `null`: operations before it were not measured) |
| GET | `/svc/audit/ops-metrics/timeseries` | `items`: per hour `total_ops`, `total_errors`, `avg_latency_ms` |
| GET | `/svc/audit/ops-metrics/latency` | `items`: per service and `op_type`, `avg_ms` (exact) and `p50_ms` / `p90_ms` / `p99_ms`: the upper bound of the histogram bucket (0.1 to 1000 ms) each percentile falls in; `null` is slower than 1000 ms |
| GET | `/svc/audit/ops-metrics/by-service` | `items`: `total_ops`, `total_errors`, `error_rate`, `avg_latency_ms` |
| GET | `/svc/audit/ops-metrics/errors` | `items`: `service`, `op_type`, `error_count`, `total_count` |

### GET /svc/audit/audit/events/{id}

Single event.

---

### GET /svc/audit/audit/targets/{target_id}/integrity

Permission `audit.integrity.read`; kernel event
`audit.audit.target_integrity_verified` (details `verdict`, `events_checked`,
`failed`). Verifies the newest 500 (or `limit`) audit events whose
`target_id` is `{target_id}` (for a key, its ID). Every check recomputes from
what is stored now and compares with an independent record:

| Field | Check | Values |
|---|---|---|
| `content` | the row's fields reproduce its `chain_hash` | `intact`, `altered` |
| `link` | the predecessor's `chain_hash` is this row's `previous_hash`, and the successor's `previous_hash` is this row's `chain_hash` | `linked`, `genesis`, `anchor` (a replicated chain's first row here), `broken`, `predecessor_missing` |
| `signature` | per-event HMAC over the chain hash, under a key derived from the audit master key | `verified`, `unsigned`, `not_checked` (no key on this node), `mismatch`, `key_unknown` |
| `seal` | the first checkpoint of the event's chain at or after it verifies under a trusted key, and the stored rows from the event to the signed head are contiguous, linked and end at the signed chain hash | `sealed`, `pending` (no checkpoint yet), `key_unknown`, `signature_invalid`, `head_mismatch` |

Response `integrity`: `verdict` (`intact`, `tampered`, `no_events`),
`events_checked`, `failed`, `sealed`, `pending`, `unsigned`, `truncated`,
`signing_key_configured`, `verified_at`, and `events[]` with the fields above,
`failures[]` and, once a checkpoint covers the event, `checkpoint_id` and
`checkpoint_sequence`. A `tampered` verdict also raises the
critical `audit.audit.chain_broken` (details `scope: target`, `target_id`,
`breaks`). The Keys detail view's **History & usage** panel calls this from
**Verify integrity**.

---

### GET /svc/audit/audit/checkpoints

Permission `audit.integrity.read`; kernel event
`audit.audit.checkpoints_listed` (details `checkpoints`, `failed`). Query
`limit` (default 50, max 200). Returns `items[]`, newest first, each
re-verified now: `event_id`, `chain_node`, `sequence` (the signed head),
`chain_hash`, `signed_at`, `key_id`, `algorithm` (`ECDSA-P384`), `message`
(the exact signed bytes), `signature` (base64 DER), `public_key_pem` (when
the key is trusted) and `status` (`verified`, `key_unknown`,
`signature_invalid`, `head_mismatch`). Any failure also raises the critical
`audit.audit.chain_broken` (`scope: checkpoints`). Checkpoints are signed
every 10 minutes for each chain that moved; see
[SECURITY/AUDIT_INTEGRITY.md](SECURITY/AUDIT_INTEGRITY.md) for trust rules
and how to verify with openssl.

`GET /svc/audit/audit/chain/verify` also checks every checkpoint; its break
reasons add `checkpoint_key_unknown`, `checkpoint_signature_invalid` and
`checkpoint_head_mismatch`.

---

## Service 5: Governance (`/svc/governance/`)

**Playbook approvals and email (2.5.0-beta).** A built-in policy,
"Playbook actions (built-in)", covers `playbook.*`. It is created on first
use, and its approvers are admins and tenant admins other than the person
the playbook acts for. Disabling it stops approval-gated playbook steps.
`POST /svc/governance/governance/notify/email` (route kernel, audited
`notification_email_sent`) is callable only by `kms-compliance`, for a
playbook's `send_email`. Body: `to[]` (emails of the tenant's active users,
or `role:<name>`; anything else is refused with
`recipient_not_tenant_user`), `subject` (up to 200 characters), `body` (up
to 16 KiB), `playbook_run_id`. It sends through the tenant's SMTP settings:
`409 smtp_not_configured` when there are none, `502 send_failed` naming any
recipient that failed.

**Approval notices through connections (2.10.0-beta).** Slack and Teams
approval notices go through a compliance connection. `GET` / `PUT
/governance/settings` carry `slack_connection_id` and `teams_connection_id`
(a `slack` / `teams` connection of the tenant, checked with compliance when
it changes). `slack_webhook_url` and `teams_webhook_url` are no longer
returned or accepted: those URLs are credentials and were stored in
plaintext. The primary moves any it finds into connections (recorded as
exposed in compliance's register; audited
`audit.governance.notify_connections_migrated`) and clears them; rotate
those Slack/Teams webhooks. `POST /governance/settings/webhook/test` takes
`{"channel": "slack"|"teams"}` and sends through the saved connection; a
`webhook_url` in the body is refused (`audit.governance.webhook_tested`,
`result: refused`, `reason: ad_hoc_url_refused`). `kms-compliance` may read
`GET /governance/settings` to check whether a connection it is asked to
delete is in use.

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

Approval policies decide who approves an action. Reading needs an
authenticated caller in the tenant; creating, changing or deleting needs a
tenant administrator.

Policy fields: `name` (unique in the tenant), `description`, `scope`,
`trigger_actions[]` (exact actions, `domain.*` or `*`), `quorum_mode`
(`threshold` | `and` | `or`), `required_approvals`, `total_approvers`,
`approver_roles[]`, `approver_users[]` (emails), `timeout_hours`,
`escalation_hours`, `escalation_to[]`, `retention_days`,
`notification_channels[]`, `status` (`active` or inactive). A request uses
the first active policy whose trigger actions cover its action. Approvers
are the policy's users plus active holders of its roles (direct or through
a group), minus the requester.

```bash
curl -sk -X POST https://localhost/svc/governance/governance/policies \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: t1" -H "Content-Type: application/json" \
  -d '{"tenant_id":"t1","name":"Key destruction","scope":"key","trigger_actions":["key.destroy"],"quorum_mode":"threshold","required_approvals":2,"approver_roles":["security-officer"]}'
```

Response `201`: `policy`, `request_id`. `GET` (query `scope`, `status`)
returns `items[]`, `request_id`.

**Built-in policies (1.35.0-beta).** When a request's action has no active
policy, governance creates the built-in policy covering it, once per tenant,
and audits it as `audit.governance.builtin_policy_created`. There are two:
- **Posture escalation (built-in):** `trigger_actions`
  `["posture.escalate_remediation"]`, `approver_roles`
  `["admin","tenant-admin"]`, one approval, `scope` `posture`. After
  creation it is an ordinary policy: edit its approvers or quorum, or set it
  inactive (it is then never recreated).
- **Playbook actions (built-in):** `trigger_actions` `["playbook.*"]`, the
  same approvers, `scope` `playbook`. It is **required** (2.6.0-beta):
  approvers and quorum can change, but `PUT` with a status other than
  `active`, or without `playbook.*` in `trigger_actions`, is refused with
  `409 builtin_policy` (`approval_refused`, `reason:
  builtin_policy_required`). One disabled under 2.5.0-beta is switched back
  on at the next request (`audit.governance.builtin_policy_restored`).

Each has a fixed ID per tenant.

---

### DELETE /svc/governance/governance/policies/{id}

Tenant administrator. Deleting a built-in policy is refused with
`409 builtin_policy`, audited as `audit.governance.approval_refused` with
`reason: builtin_policy_delete`. Disable it instead.

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

System administrators only. Response `state`: the platform's system settings, which include the FIPS fields (`fips_mode`, `fips_mode_policy`, `fips_crypto_library`, `fips_module_version`, `fips_library_validated`, `fips_runtime_enabled`, `fips_runtime_enforced`, `fips_tls_profile`, `fips_rng_mode`, `fips_entropy_source`, `fips_entropy_health`), `go_runtime_version`, `flight_recorder_ready`, `runtime_secret_ready` and the posture switches (`posture_force_quorum_destructive_ops`, `posture_require_step_up_auth`, `posture_pause_connector_sync`). It holds no service up/down map; service health is `GET /svc/auth/auth/system-health`.

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
- `audit.auth.sso_login_refused` (SAML/OIDC callback refused: signature, issuer, audience, recipient, request binding, replay, state), `audit.auth.client_activation_refused` (`reason`; missing or unapproved governance request, cross-tenant), not pending (`client_state`) or unknown
- `audit.auth.client_key_rotated`, `audit.auth.client_revoked`, `audit.auth.api_key_revoked` (kernel events; refusals `client_state`, `service_identity_protected`), `audit.auth.unbound_api_keys_retired` (startup): REST client credentials (7.16.0-beta)
- `audit.governance.approval_refused` (`reason`: `authentication_required`, `tenant_required`, `tenant_mismatch`, `insufficient_privileges`, `not_a_user`, `no_user_email`, `builtin_policy_delete` (deleting a built-in policy), `builtin_policy_required` (disabling or narrowing the playbook policy), and `vote_refused` for a refused vote: not an approver, the requester, a wrong challenge code), `audit.governance.link_refused` (approval page with an invalid or used token)
- `audit.hyok.dke_refused` (Microsoft DKE: missing or invalid token, Entra issuer/audience/tenant/user not allowed, anonymous fetch on another host, non-current key version), `audit.hyok.admin_refused` (endpoint administration), `audit.hyok.approval_refused` (retry with an approval that is not approved, for another key/operation/payload, or already used), `audit.hyok.request_denied` with `reason: key_access_unavailable`, `result: refused` (key access deployed but unreachable)
- `audit.signing.sign_refused` (identity, policy or token refusal, with `code`), `audit.signing.request_refused` (`reason: tenant_mismatch`)
- `audit.confidential.key_released` (key sealed to the attested recipient key; `recipient_key_binding`, `key_version`, `seal_algorithm`), `audit.confidential.key_release_refused` (`reason`: no binding, verdict, keycore refusal), `audit.confidential.key_release` (kernel), `audit.key.attested_release` (keycore kernel, refusals included)
- `audit.ekm.request_refused` (EKM `401`/`403`: no verified tenant token, cross-tenant, BitLocker agent token missing or wrong role)
- `audit.ekm.tde_key_accessed` with `operation: public`: `result: success` with `key_version`, or `result: refused` with `reason: public_key_unavailable` (EKM `424`: keycore gave no public key; 6.12.0-beta) or keycore's own refusal reason (`not_found`, `delegation_refused`, ...; 6.18.0-beta)
- `audit.ekm.key_access_denied` (TDE `wrap`, `unwrap`, `rotate` refused by key access: `reason` is the deny reason, or `key_access_unavailable` when the service is deployed but gives no decision; `result: refused`), `audit.cloud.key_access_denied` (BYOK `import`, `rotate`, `sync`, same reasons, `result: refused`)
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

Query: `template_id` (optional). Response `delta`: `latest_assessment_id`, `previous_assessment_id`, `latest_score`, `previous_score`, `score_delta`, `summary`, `added_findings`, `resolved_findings`, `recovered_domains`, `regressed_domains`, `new_failing_connectors`, `compared_at`.

---

### GET /svc/compliance/compliance/assessment/history

Query: `template_id` (optional), `limit`. Response `items[]`: past assessments, newest first.

---

### POST /svc/compliance/compliance/assessment/run

Body (or query): `template_id`, `recompute` (optional). Runs synchronously. Response `200`: `assessment`.

---

### Playbooks (route kernel; response layer since 2.5.0-beta)

A playbook responds to an audited event, or runs by hand. It can notify
through sealed connections, act on keys, certificates, users, API keys,
clients, alerts and incidents, run assessments and scans, and pause for a
governance approval. Actions run as the compliance service identity, on the
authority of a person:

- **Saving an enabled playbook** needs every permission its actions use, and
  a user (not an API client): `authorized_by` records them. A disabled
  playbook may be saved by any `compliance.playbook.write` holder and stays
  unauthorized.
- **Every automatic run** first asks auth whether `authorized_by` is still
  active and still holds those permissions (`POST /auth/delegated/authority`).
  If not, or if auth can't be reached, the run doesn't start
  (`playbook_triggered`, `refused`, `authority_revoked` /
  `authority_unverified`).
- **Manual runs, retries and cancels** need the caller to hold every action
  permission.
- **Delegated actions** (`disable_user`, `revoke_api_key`, `revoke_client`)
  are performed by auth, which re-checks the person's permission.
- **Approval-gated steps** (`deactivate_key`, `revoke_certificate` and the
  delegated actions always; any step with `require_approval`) pause the run.
  Governance opens a request under the built-in "Playbook actions" policy,
  and the person the playbook acts for can't approve. The run resumes on
  `audit.governance.quorum_reached` only after compliance reads the request
  back from governance. It must be approved, name this run's action and
  requester, and carry the hash of the action as the playbook now defines
  it. The person's authority is then re-checked.

| Route | Permission | Audit action |
|---|---|---|
| `GET /svc/compliance/compliance/playbooks/catalog` | `compliance.playbook.read` | `playbook_catalog_read` |
| `GET /svc/compliance/compliance/playbooks/summary` | `compliance.playbook.read` | `playbook_summary_read` |
| `GET /svc/compliance/compliance/playbooks` | `compliance.playbook.read` | `playbooks_listed` |
| `POST /svc/compliance/compliance/playbooks` | `compliance.playbook.write` (+ action permissions if enabled) | `playbook_created` |
| `GET /svc/compliance/compliance/playbooks/{id}` | `compliance.playbook.read` | `playbook_read` |
| `PUT /svc/compliance/compliance/playbooks/{id}` | `compliance.playbook.write` (+ action permissions if enabled) | `playbook_updated` |
| `DELETE /svc/compliance/compliance/playbooks/{id}` | `compliance.playbook.delete` | `playbook_deleted` |
| `POST /svc/compliance/compliance/playbooks/{id}/run` | `compliance.playbook.run` + every action permission | `playbook_run_requested` |
| `POST /svc/compliance/compliance/playbooks/{id}/dry-run` | `compliance.playbook.run` | `playbook_dry_run` |
| `GET /svc/compliance/compliance/playbooks/{id}/runs` | `compliance.playbook.read` | `playbook_runs_listed` |
| `GET /svc/compliance/compliance/playbook-runs?status=&incident_id=` | `compliance.playbook.read` | `playbook_runs_searched` |
| `GET /svc/compliance/compliance/playbook-runs/{run_id}` | `compliance.playbook.read` | `playbook_run_read` |
| `POST /svc/compliance/compliance/playbook-runs/{run_id}/cancel` | `compliance.playbook.run` + every action permission | `playbook_run_cancelled` |
| `POST /svc/compliance/compliance/playbook-runs/{run_id}/retry` | `compliance.playbook.run` + every action permission | `playbook_run_retried` |
| `GET /svc/compliance/compliance/playbooks/connections` | `compliance.playbook.read` | `connections_listed` |
| `POST /svc/compliance/compliance/playbooks/connections` | `compliance.playbook.write` | `connection_created` |
| `PUT /svc/compliance/compliance/playbooks/connections/{id}` | `compliance.playbook.write` | `connection_updated` |
| `DELETE /svc/compliance/compliance/playbooks/connections/{id}` | `compliance.playbook.delete` | `connection_deleted` |
| `POST /svc/compliance/compliance/playbooks/connections/{id}/test` | `compliance.playbook.write` | `connection_tested` |
| `POST /svc/compliance/compliance/connections/{id}/resolve` | `kms-audit` / `kms-governance` / `kms-discovery` service identity | `connection_resolved` |
| `POST /svc/compliance/compliance/connections/import` | `kms-audit` / `kms-governance` service identity | `connection_imported` |
| `GET /svc/compliance/mek/exposure` | `compliance.read` | `mek_exposure_listed` (pkg/mek) |

**Playbook body** (unknown fields are rejected with 400):

```json
{
  "name": "Lock out a brute-forced account",
  "category": "access_control",
  "enabled": true,
  "trigger": {
    "type": "login_failed",
    "filters": [{"field": "details.reason", "op": "neq", "value": "mfa_required"}],
    "threshold": 5, "window_seconds": 300, "group_by": "target_id"
  },
  "actions": [
    {"type": "send_slack", "parameters": {"connection_id": "pbconn_...", "message": "5 failed logins for {{event.target_id}}"}},
    {"type": "disable_user", "parameters": {"user_id": "{{event.target_id}}"},
     "condition": [{"field": "severity", "op": "in", "value": "high,critical"}]},
    {"type": "send_email", "parameters": {"to": "role:admin", "subject": "Account {{event.target_id}} disabled", "body": "Run {{run.id}}"}}
  ]
}
```

- **Trigger:** a catalogue `type`, or `custom_event` with `subject` (an
  audit subject, exact or ending in `.*`; never a playbook's own events),
  plus optional `filters` (`field`, `op` from `eq`, `neq`, `in`, `not_in`,
  `contains`, `prefix`, and `value`). With `threshold` above 1 it fires when
  that many matching events arrive within `window_seconds`, counted per
  `group_by` value. Counts are stored (`compliance_playbook_threshold_hits`,
  replicated, written by the primary), so a failover continues them; they
  reset when the playbook fires, is edited or is deleted. A count that can't
  be stored refuses the firing (`threshold_unavailable`).
- **Fields** for filters, conditions and templates: `subject`, `tenant_id`,
  `service`, `result`, `severity`, `target_type`, `target_id`, `actor_id`,
  `actor_type`, `correlation_id`, `details.<key>`.
- **Templates** in parameters: `{{event.<field>}}`, `{{run.id}}`,
  `{{playbook.id}}`, `{{playbook.name}}`, `{{trigger}}`. A required
  parameter that resolves empty fails the step (it never calls with
  nothing). `connection_id` can't be templated.
- **Action options:** `condition` (filters; the step is skipped and audited
  `skipped` when they don't match), `require_approval`, `delay_seconds`
  (0-3600), and `stop_on_failure=true` in parameters.
- **Events playbooks don't react to:** their own events, events whose actor
  is `kms-compliance`, events correlated to a run (`pbrun_...`), and alerts
  raised from such events. Also refused: events more than 15 minutes old,
  and a second firing of the same playbook within 60 s (`cooldown`; the
  last firing is stored with the playbook, so it holds across a failover,
  and a claim that can't be checked is refused as `cooldown_unavailable`).

**Catalogue** (`GET .../playbooks/catalog`): `triggers`, `actions` (with
`permission`, `required` / `optional` parameters, `connection`, `approval`,
`delegated`), `categories`, `connection_types`, `event_fields`,
`filter_ops`, `templates`, `incident_statuses`. The dashboard renders only
this.

- Triggers: `alert_raised` (`audit.reporting.alert_created`),
  `incident_opened` (`audit.reporting.incident_opened`), `canary_tripped`,
  `threat_signal_raised`, `threat_finding_raised`,
  `sustained_risk_detected` (`audit.security.sustained_risk_detected`),
  `key_compromised`,
  `audit_chain_broken` (`audit.audit.chain_broken`),
  `secret_exposed` (`audit.discovery.secret_exposed`, 7.18.0-beta),
  `key_created`, `key_rotated`, `key_destroyed`, `key_exported` (success
  only), `key_access_refused`, `key_request_replay_detected`,
  `key_hsm_refused`, `crypto_policy_refused`
  (`audit.key.crypto_policy_refused`), `crypto_risk_decision_recorded` (`audit.key.caraf_decision_recorded`), `crypto_policy_changed` (a migration
  rule created, updated or deleted), `cert_revoked`, `cert_renewal_window_missed`,
  `cert_mass_renewal_risk`, `crl_generation_failed`, `login_failed`,
  `account_locked`, `dpop_replay_detected`, `posture_changed`,
  `fips_mode_changed`, `backup_restored`, `cluster_member_joined`,
  `service_health_degraded` (fires the platform tenant's playbooks), and
  `custom_event`.
- Actions (permission; approval): `send_slack`, `send_teams`,
  `send_webhook`, `create_jira_ticket`, `create_servicenow_incident` (a
  connection of the matching type), `send_siem_alert` (any SIEM connection;
  optional `title`, `severity` of `info`, `low`, `warning`, `high` (default)
  or `critical`; sends the playbook, run, authorizing person and triggering
  event as one `audit.compliance.playbook_alert` record), `send_email` (governance sends to this
  tenant's active users, by email or `role:<name>`), `create_audit_event`;
  `rotate_key` (`key.rotate`), `disable_key` (`key.disable`),
  `deactivate_key` (`key.deactivate`; approval), `activate_key`
  (`key.activate`), `trigger_rotation_policy` (`key.rotation.write`),
  `renew_certificate` (`cert.renew`), `revoke_certificate` (`cert.revoke`;
  approval), `disable_user` (`auth.user.write`; approval, delegated),
  `revoke_api_key` (`auth.api_key.write`; approval, delegated),
  `revoke_client` (`auth.client.write`; approval, delegated),
  `acknowledge_alert`, `resolve_alert`, `set_incident_status`,
  `assign_incident`, `generate_report` (`reporting.write`),
  `trigger_assessment` (`compliance.assessment.run`), `snapshot_posture`
  (`compliance.posture.refresh`), `run_posture_scan` (`posture.write`).

**Connections** are the platform's one store of outbound endpoints and
credentials (docs/SECURITY/CONNECTIONS.md). Playbook actions, event streams
(`/svc/audit/webhooks`) and governance approval notices all name a
connection. The catalogue's `connection_types` gives each type's `fields`,
`optional`, `secrets` (masked in the form), `category` (`notify`,
`ticketing`, `siem`) and `stream` (can carry an event stream):

| Type | Fields (optional in brackets) | Sends |
|---|---|---|
| `slack` / `teams` | `webhook_url` | messages; approval notices; streams |
| `webhook` | `url` [`headers` JSON, `signing_secret` ≥ 16 chars] | JSON, signed `X-KMS-Signature` when a secret is set |
| `jira` | `base_url` [`api_token`] | issues |
| `servicenow` | `instance_url` [`auth_token`] | incidents |
| `splunk_hec` | `url`, `token` [`index`, `sourcetype`, default `vecta:audit`] | HEC events; a bare host gets `/services/collector/event` |
| `datadog` | `url` (the Logs intake, e.g. `https://http-intake.logs.datadoghq.com/api/v2/logs`), `api_key` | Logs intake array |
| `elastic` | `url`, `api_key` (encoded) [`index`, default `vecta-kms-audit`] | Bulk API, `_id` = event ID; a rejected document is a failure |
| `sentinel` | `dce_url`, `dcr_immutable_id` (`dcr-<32 hex>`), `stream_name` (`Custom-…`), `azure_tenant_id`, `client_id`, `client_secret` | Azure Monitor Logs Ingestion API with an Entra client-credentials token. The DCR stream must declare `TimeGenerated`, `EventId`, `Action`, `TenantId`, `Service`, `Actor`, `TargetType`, `TargetId`, `Result`, `Severity`, `SourceIp`, `Event` (dynamic). The retired HTTP Data Collector API is not used. |
| `syslog` | `address` (`host:port`, usually 6514) [`ca_pem`, `server_name`] | CEF in RFC 5424 messages over TLS 1.3 (RFC 5425), for QRadar, ArcSight and other collectors. No plain UDP/TCP. Success means written to the TLS session (syslog has no acknowledgement). |

Every field is sealed as one envelope under the compliance master key from
keycore (`pkg/mek`). The API returns the name, type, endpoint host and the
names of fields set, never a value. On update, a field sent as `********`
keeps its stored value. Replacing every field retires an exposure-register
entry. The endpoint must be a public address reached over TLS: platform hosts
and private or metadata addresses are refused (`url_blocked`), and calls go
through `pkg/ssrfguard` (the syslog address included). SIEM fields are
checked by building the destination (`pkg/siem`). `POST .../test` makes a
real call: a test message for Slack, Teams and webhooks, an authenticated
read for Jira and ServiceNow, and one labelled event
(`audit.compliance.connection_tested`) for a SIEM.

A connection in use can't be deleted (`409 connection_in_use`, naming the
playbooks, event streams and governance approval notices that use it).
Compliance asks the audit service and, for the root tenant, governance, as
the `kms-compliance` identity; if either can't answer, the delete is refused
(`503`, `reason: connection_usage_unverified`). Credentials that releases
before 2.5.0-beta kept inline in actions are moved into connections at
startup by the primary, audited (`playbook_connections_migrated`) and
recorded in the exposure register: rotate those webhook URLs and tokens.

**Service routes** (internal mTLS; the kernel audits each call):

| Route | Caller | Audit action |
|---|---|---|
| `POST /compliance/connections/{id}/resolve` | `kms-audit` (stream types), `kms-governance` (`slack`, `teams`), `kms-discovery` (`git`, 7.20.0-beta) | `connection_resolved` |
| `POST /compliance/connections/import` | `kms-audit`, `kms-governance` | `connection_imported` |

`resolve` returns `{id, name, type, endpoint, fields}` with the opened
fields. Any other caller, users and administrators included, is refused
(`403`, `reason: service_identity_required`); a type the caller can't use is
refused (`409`, `reason: connection_use_unsupported`). `import` takes
`{source_id, name, type, fields, exposed}` and creates
`pbconn_<service>_<source_id>` (the same ID on a retry, answered
`already_imported`); `exposed: true` records the connection in the exposure
register (credentials once stored in plaintext).

**Runs.** `POST .../run` (optional body `{"event": {...}}`, recorded as
supplied by the runner) returns `202 {"run_id"}`. A run record has `status`,
`context` (the event), `results` (one per action: `done`, `skipped`,
`pending_approval`, `awaiting_approval`, `failed`, `refused`, with target
and error), `actor`, `incident_id`, `approval_request_id` while paused, and
`retry_of`. Status is one of: `running`, `awaiting_approval`, `completed`,
`pending_approval` (a platform service opened its own approval),
`partial_failure`, `failed` (a `stop_on_failure` step failed), `cancelled`,
`approval_denied` or `approval_expired`. Cancel stops a running run at its
next step, or ends a paused one and withdraws its governance request. Retry
starts a new run with the same event, on the caller's authority, from the
first step that didn't complete. `POST .../dry-run` resolves every step and
reads each target from its owning service (key, certificate, alert,
incident, connection). It changes nothing and sends nothing.

**Refusals:** `tenant_mismatch`, `tenant_conflict`, `permission_denied`,
`unauthenticated` (kernel); `action_permission_denied` (403, with
`missing_permissions`), `user_required` (403), `url_blocked` (400),
`connection_invalid` (400), `playbook_invalid` (409), `connection_in_use`,
`run_not_cancellable`, `run_not_retryable` (409).

---

## Service 7: Posture (`/svc/posture/`)

Risk findings, risk drivers, blast radius, remediation actions, and findings
for keycore's [threat signals](#threat-detection-keycore--posture--reporting).
Every route is on the `pkg/route` kernel (1.32.0-beta): a verified bearer token is required, the
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
| `GET /posture/risk` | `posture.read` | `audit.posture.risk_read` (`assessed: false` when the tenant was never scanned). The snapshot carries `assessed` and `baseline_days`: until the baseline has 14 days, `assessed` is false and `risk_24h`/`risk_7d` are 0, meaning not assessed (7.19.0-beta) |
| `GET /posture/baseline` | `posture.read` | `audit.posture.baseline_read` (`ready`, `days`). Returns `baseline`: `ready` (14 days), `stable` (28), `days`, `required_days`, `stable_days`, `from`, `synced_through`, `spike_alpha`, and per signal `key`, `label`, `kind` (`count`/`rate`), `status` (`building`, `needs_events`, `ready`), `current_24h`, `baseline_daily_mean`, `floor`, `events_24h`, `baseline_events`, `required_baseline_events`, `baseline_failure_rate`, `unusual`, `p_value` (7.19.0-beta, docs/SECURITY/POSTURE_BASELINE.md) |
| `GET /posture/risk/history` | `posture.read` | `audit.posture.risk_history_read`. With `trend=true` and optional `from`/`to` (RFC 3339; no `from` is since the first snapshot), returns the latest snapshot in each `pkg/timebucket` bucket, newest first, and `bucket_seconds`; a malformed window is refused with `reason` `bad_window` (7.17.0-beta) |
| `POST /posture/scan` | `posture.write` | `audit.posture.scan_run` (`sync_audit`, `risk_24h`) |
| `POST /posture/events` | `posture.write` | `audit.posture.events_ingested` (`submitted`, `inserted`) |
| `POST /posture/events/batch` | `posture.write` | `audit.posture.events_ingested` (`batch: true`) |
| `POST /posture/ingest/audit` | `posture.write` | `audit.posture.audit_synced` (`inserted`) |
| `GET /posture/findings` | `posture.read` | `audit.posture.findings_listed` |
| `PUT /posture/findings/{id}/status` | `posture.write` | `audit.posture.finding_status_updated` (`status`) |
| `GET /posture/actions` | `posture.read` | `audit.posture.actions_listed` |
| `POST /posture/actions/{id}/execute` | `posture.action.execute` | `audit.posture.action_executed` (warning; `approval_request_id`, `action_type`, `severity_from`, `severity_to`; refusals `approval_pending`, `approval_invalid`, `approval_unavailable`, `not_executable`) |

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

Runs the action's executor as the verified caller (`executed_by`). An
`actor` body field is rejected (`400`) and `X-Actor-ID` is ignored.

- **Executable types (1.34.0-beta):** only `escalate_remediation`. It
  raises the overdue source finding one severity level (info → warning →
  high → critical), restarts its SLA at that level, and resolves the
  SLA-breach finding. If the engine later re-detects the source condition,
  its own assessment applies again. The engine creates no other action
  type; older rows of other types are `withdrawn` or `not_performed`.
- **Approval (dual control):** an approval-required action runs only when
  governance holds an **approved** request with `target_type`
  `posture_action`, `target_id` the action ID, action
  `posture.<action_type>`, a `payload_hash` over tenant, action, type and
  finding, and `requester_id` = the caller. The first call opens that
  request as posture's service identity (governance excludes the requester
  from the approvers and refuses their vote), sets the action to
  `awaiting_approval`, and is refused `409 approval_pending` with the
  request ID in the message. Call again once it is approved. Another user
  can't run on it: they get their own request. With no policy of the
  tenant's own, the built-in **Posture escalation** policy applies: any
  other tenant administrator approves (see governance policies).
- **Body (optional):** `approval_request_id`. It is checked, never
  trusted: it must be one of the approved requests above.
- **Response `200`:** `ok`, `result` (`action_type`, `finding_id`,
  `escalated_finding_id`, `severity_from`, `severity_to`, `sla_due_at`),
  `request_id`.
- **Refusals** (audited `result: refused`): `409 approval_pending`,
  `403 approval_invalid`, `503 approval_unavailable` (governance not
  configured or unreachable; fail closed), `409 not_executable`.
  **Errors:** `404` unknown action, `409 already_executed`,
  `409 finding_not_open` (the action is marked `failed`).

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

**Incidents and playbooks (2.5.0-beta).** A new incident emits
`audit.reporting.incident_opened` (target the incident; `title`,
`severity`), and each alert emits `audit.reporting.alert_created`, with the
alert as target and `severity`, `incident_id`, `source_actor_id`,
`source_target_id` and `source_service` in details. Compliance playbooks
trigger on both. `PUT /incidents/{id}/status` accepts only `open`,
`investigating`, `resolved` and `closed` (otherwise 400).
`PUT /incidents/{id}/status` and `/assign` return 404 for an incident that
doesn't exist; until 2.5.0-beta they answered 200.

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

Query: `severity` (`info` also matches unknown severities, as the statistics
count them), `status`, `action`, `target_type`, `target_id`, `actor_id`,
`source_ip`, `service`, `resolved=true` (resolved alerts, which MTTR
measures), `linked=true` (alerts that link an audit event, which MTTD
measures), `from`, `to` (RFC 3339, inclusive), `limit` (default 100, at most
500 per page), `offset`. The filters after `target_id` are 7.17.0-beta.
Response: `{"items": Alert[]}`, newest first.

Alert: `id`, `audit_event_id`, `audit_action`, `severity`, `category`,
`title`, `description`, `service`, `actor_id`, `target_type`, `target_id`,
`source_ip`, `status`, `acknowledged_by`, `acknowledged_at`, `resolved_by`,
`resolved_at` (year 1 when unset), `dedup_count`, `created_at`, `updated_at`.

---

### GET /svc/reporting/alerts/{id} / PUT /svc/reporting/alerts/{id}/{op}

`op` is `acknowledge`, `resolve`, `false-positive` or `escalate`
(`audit.reporting.alert_updated`, `operation` in the details). Body: optional
`note` (resolve, false-positive) or `severity` (escalate). Response:
`{"status":"ok"}`.

---

All four statistics take a window: `from` and `to` (RFC 3339; without
`from`, since the first alert). A malformed window is refused with `reason`
`bad_window`. Before 7.17.0-beta they had no window and read the newest 5000
alerts; before 7.15.0-beta the store cut them to the newest 100.

### GET /svc/reporting/alerts/stats

Counts every alert created in the window. Response:
`{"stats": {"total", "by_severity", "by_status", "top_actions", "daily_trend" (UTC date → count), "from", "to", "bucket_seconds", "series" ([{start, count}], pkg/timebucket), "generated_at"}}`.

---

### GET /svc/reporting/alerts/stats/mttd

Mean minutes from the linked audit event to the alert, by severity. It looks
up each alert's audit event, so it measures the newest 5000 alerts in the
window that link one. Response:
`{"mttd_minutes": {"critical": 4.2, ...}, "measured": n, "truncated": bool}`.

---

### GET /svc/reporting/alerts/stats/mttr

Mean minutes from creation to resolution, by severity, over every resolved
alert in the window. Response: `{"mttr_minutes": {...}}`

---

### GET /svc/reporting/alerts/stats/top-sources

Top ten actors, source IPs and services among every alert in the window. Response: `{"top_actors": [{"key", "count"}], "top_ips": [...], "top_services": [...]}`

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

SPIFFE SVIDs from a per-tenant CA, and exchange of a verified SVID for a
scoped KMS access token. There is no agent and no attestation: `selectors`
are recorded, not checked. Details and open items:
[IDENTITY_AND_PQC.md](IDENTITY_AND_PQC.md#section-1-workload-identity).

Every route is served by the `pkg/route` kernel (since 6.9.0-beta): the
tenant comes from the verified token (a conflicting `tenant_id` is refused
as `tenant_mismatch`), each call emits its own `audit.workload.<action>`,
refusals included, and the service no longer reads `tenant_id` or
`X-Tenant-ID` on its own. Permissions: `workload.read` (every `GET`),
`workload.write` (settings, registrations, federation bundles) and
`workload.issue` (`POST .../issue`, whose X.509 response carries the
private key). **The token exchange needs no bearer token**: the SVID is the
credential (docs/DECISIONS.md 2026-09-29, below).

| Route | Body / query | Response key |
|---|---|---|
| `GET` / `PUT /svc/workload/workload-identity/settings` | `enabled`, `trust_domain`, `token_exchange_enabled`, `federation_enabled` (federated bundles verify SVIDs only while it is on), `default_x509_ttl_seconds`, `default_jwt_ttl_seconds`, `rotation_window_seconds`, `allowed_audiences` (the only audiences an exchange accepts). `disable_static_api_keys` and `rotation_alert_*` were removed in 6.9.0-beta (nothing acted on them); sending them is a 400 | `settings` |
| `POST .../settings/rotate-signing-keys` | none (`workload.write`) | `settings`. Replaces the tenant's SPIFFE root CA and JWT-SVID signer with new keys in the same trust domain (6.11.0-beta); SVIDs issued under the old keys stop verifying. Closes the tenant's exposure-register entry. Audited `signing_keys_rotated` |
| `GET .../summary` | | `summary`; `key_usage_unavailable` says why the key-usage counts are missing when the audit log can't be read with the caller's token |
| `GET` / `POST .../registrations`, `PUT` / `DELETE .../registrations/{id}` | `name`, `spiffe_id`, `selectors`, `allowed_interfaces`, `allowed_key_ids`, `permissions`, `issue_x509_svid`, `issue_jwt_svid`, `default_ttl_seconds`, `enabled` | `items` / `registration` |
| `GET` / `POST .../federation`, `PUT` / `DELETE .../federation/{id}` | `trust_domain`, `jwks_json`, `ca_bundle_pem`, `bundle_endpoint` (stored, not fetched), `enabled` | `items` / `bundle` |
| `POST .../issue` | `registration_id` or `spiffe_id`, `svid_type` (`x509` / `jwt`), `audiences`, `ttl_seconds` | `issued`: X.509 returns `certificate_pem`, `private_key_pem` (generated by the service), `bundle_pem`; JWT returns `jwt_svid` (RS256), `jwks_json` |
| `GET .../issuances?limit=` | | `items` |
| `POST .../token/exchange` (no bearer token) | `tenant_id`; one of `jwt_svid` (+ optional `audience`, which must be in `allowed_audiences`; without it the SVID's `aud` must include one) or `x509_svid_chain_pem` + `x509_svid_proof`; `registration_id` (optional; must be the SVID's own), `interface_name`, `requested_permissions`, `requested_key_ids`. Not RFC 8693. `client_id` was removed in 6.9.0-beta: the token's client is the registration | `exchange`: `kms_access_token`, `kms_access_token_expiry`, `allowed_permissions`, `allowed_key_ids` |
| `GET .../graph` | | `graph`: `nodes`, `edges`, `key_usage_unavailable` |
| `GET .../usage?limit=` | | `items`; 502 `audit_unavailable` when the audit log can't be read with the caller's token |

**`x509_svid_proof`**: an X.509-SVID chain is public, so it buys a token only
with `{"signed_at": "<RFC 3339 UTC>", "signature": "<base64>"}`, signed with
the SVID's private key over exactly

```
vecta-kms/workload-token-exchange/v1
tenant=<tenant_id>
leaf-sha256=<lowercase hex SHA-256 of the leaf certificate DER>
signed-at=<signed_at as sent>
```

(RSA PKCS#1 v1.5 or PSS with SHA-256, ECDSA P-256/P-384 with SHA-256 in
ASN.1, or Ed25519). `signed_at` must be within two minutes of the server's
clock, and each signature is accepted once (members forward the exchange to
the primary, which remembers accepted proofs in memory for the window).

Exchange refusals (401/403/409, `result: refused` on
`audit.workload.token_exchanged`): `svid_invalid`, `audience_not_allowed`,
`svid_proof_required`, `svid_proof_invalid`, `svid_proof_expired`,
`svid_proof_replayed`, `registration_not_found`,
`svid_registration_mismatch`, `registration_disabled`,
`interface_not_allowed`, `permissions_not_allowed`, `keys_not_allowed`,
`workload_identity_disabled`, `token_exchange_disabled`.

**Signing keys at rest (6.11.0-beta).** The root CA and JWT-SVID signer
private keys are sealed together per tenant under the workload master key
from keycore (`pkg/mek`; nothing to configure). The service needs
`KEYCORE_URL` (default `https://keycore:8010`) and the
`kms-workload-identity` service identity, and doesn't start without the key.
Rows an earlier release stored in plaintext are sealed by the primary and
recorded in the exposure register:

| Route | Permission | Meaning |
|---|---|---|
| `GET /svc/workload/mek/exposure?open=false` | `workload.read` | the tenant's exposure register: signing keys stored as plaintext PEM before 6.11.0-beta (`item_type: workload_signing_keys`, `item_id` = tenant), open until rotated |
| `POST /svc/workload/mek/exposure/{item_type}/{item_id}/acknowledge` | `workload.exposure.acknowledge` | close an entry with `{"reason": "..."}` (at least 10 characters) |
| `POST /svc/workload/mek/rewrap-legacy` | `kms-governance` only | backup re-wrap (docs/SECURITY/SERVICE_MASTER_KEYS.md) |

Audit: `audit.workload.<action>` for every route; the actions are in the
Audit Action Subject Reference below.

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

### Policy, evaluate and history

Kernel routes since 6.9.0-beta: the tenant comes from the verified token,
and the evaluation's recorded `requester` is the verified caller (a body
`requester` is ignored). Permissions: `confidential.read` (policy, summary,
release history), `confidential.write` (`PUT .../policy`),
`confidential.evaluate` (`POST .../evaluate`).

| Route | Body / query | Response key |
|---|---|---|
| `GET` / `PUT /svc/confidential/confidential/policy` | one policy per tenant: `enabled`, `provider` (`aws_nitro_enclaves`, `aws_nitro_tpm`, `azure_secure_key_release`, `gcp_confidential_space`, `generic`), `mode` (`enforce` / `monitor`), `fallback_action` (`deny` / `review`), `key_scopes`, `approved_images`, `approved_subjects`, `allowed_attesters`, `required_measurements`, `required_claims`, `require_secure_boot`, `require_debug_disabled`, `max_evidence_age_sec` (≤ 86400), `cluster_scope`, `allowed_cluster_nodes` | `policy` |
| `GET .../summary` | | `summary` |
| `POST .../evaluate` | `key_id`, `key_scope`, `provider`, `attestation_document`, `attestation_format`, `nonce` (expected value; the service issues none), `audience`, `cluster_node_id`, `release_reason`, `dry_run`, `recipient_public_key` | `result`: `decision`, `allowed`, `reasons`, matched / missing claims and measurements, `cryptographically_verified`, `verification_mode`, `attestation_document_hash` |
| `GET .../releases?limit=` (default 100) | | `items` |
| `GET .../releases/{id}` | | `item` |

Intel TDX quotes and raw AMD SEV-SNP reports are not verified.
Audit: `audit.confidential.policy_viewed`, `policy_updated`,
`summary_viewed`, `key_release_evaluated`, `releases_viewed`,
`release_viewed`, `key_release`, refusals included.

---

## Service 11: PQC (`/svc/pqc/`)

Post-quantum inventory by algorithm, readiness scans and migration planning.

Every route is served by the `pkg/route` kernel behind a verified JWT (since
5.2.0-beta): the tenant comes from the token (a conflicting `tenant_id` is
refused as `tenant_mismatch`), each call emits its own `audit.pqc.<action>`
event, refusals included, and the actor recorded for plan creation,
execution and rollback is the verified caller (body `actor` and
`created_by` are ignored). Permissions: `pqc.read`, `pqc.write` (scans,
plans, execute, rollback). Kernel actions: `inventory_read`,
`scan_requested`, `scans_listed`, `scan_read`, `readiness_read`,
`migration_report_read`, `plan_create_requested`, `plans_listed`,
`plan_read`, `plan_execute_requested`, `plan_rollback_requested`,
`plan_runs_listed`, `timeline_read`, `cbom_exported`.

**Removed in 6.3.0-beta:** `GET`/`PUT /svc/pqc/pqc/policy` (the tenant PQC
policy: `profile_id`, `default_kem`, `default_signature`,
`interface_default_mode`, `certificate_default_mode`, `hqc_backup_enabled`,
the three `flag_*` switches and `require_pqc_for_new_keys`). Nothing enforced
them. To refuse new protection with quantum-vulnerable keys, add a Crypto
Agility migration rule with `match_kind: quantum_vulnerable` and `action:
decrypt_only` (`POST /svc/keycore/agility/policy/rules`), which keycore
enforces on every key operation. Also removed: `readiness_score` (scans, report),
`readiness_score` and `quantum_readiness_percent` (inventory), `policy`
(inventory, report), `non_migrated_interfaces`, and a plan summary's
`readiness_score` and `estimated_risk_reduced`. They were hand-weighted
numbers; the counts they blended are still returned.

---

### GET /svc/pqc/pqc/inventory

Returns `{"inventory": {...}}`, the tenant's keys (keycore) and certificates
(certs), each counted by the algorithm it actually has:

| Field | Description |
|---|---|
| `keys`, `certificates` | `{total, classical, hybrid, pqc_only, algorithms}` |
| `interfaces` | `measured`, `not_measured` (certs has measured no listener yet) or `unavailable` (certs didn't answer) (6.13.0) |
| `listeners` | the external listeners as certs measured them: `name`, `accepted_groups`, `negotiated_group`, `measured_at`, `classification` (`classical` if any accepted group is quantum-vulnerable, `hybrid` if all are hybrid ML-KEM, `not_assessed` if a group is unknown; from `pkg/cryptocatalog`), `quantum_vulnerable_groups` |
| `classical_usage` | every RSA / ECC key and certificate still active |
| `non_migrated_certificates` | every classical certificate |
| `recommendations` | only for what the counts found; empty when nothing is classical |

Event: `audit.pqc.inventory_viewed` (`key_count`, `certificate_count`,
`classical_usage_count`, `non_migrated_cert_count`).

---

### GET /svc/pqc/pqc/readiness

Returns the latest readiness scan (`{"readiness": {...}}`), running one if
none exists. Algorithm facts come from `pkg/cryptocatalog`
(docs/SECURITY/ALGORITHM_TRANSITIONS.md):

- `total_assets`, `pqc_ready_assets` (ML-KEM, ML-DSA, SLH-DSA, LMS/XMSS),
  `hybrid_assets`, `classical_assets`, `algorithm_summary`.
- `risk_items`: assets that are weak or quantum-vulnerable (or not
  assessed), each with `classification` (`weak`, `quantum_vulnerable`,
  `exposed` for a secret in code, `unknown` when the name states no
  parameter set; discovery's pre-7.11.0-beta `vulnerable` may appear), `qsl_score` (100 when neither weak
  nor quantum-vulnerable, else 0) and `migration_target` (empty when not
  assessed).
- `timeline_status`: the customer's plan deadlines
  (`{plan, deadline, status, days_remaining, affected_assets}`), keyed by
  plan ID.

`GET /svc/pqc/pqc/timeline` returns the customer's migration plans that have
a deadline, as `[{id, standard, title, due_date, status, days_left,
affected_assets, description}]`: `standard` is the plan's own
`timeline_standard` label, `status` `upcoming`, `due_within_year`, `overdue`
or `met`, `affected_assets` the steps still open. The product sets no
deadlines of its own.

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

List or get migration plans. `POST` creates one from the latest scan; the
`deadline` and `timeline_standard` (default `customer`) are the customer's;
a plan without a deadline has none. Steps are phased `classical_to_hybrid`, `classical_to_pqc`,
`hybrid_to_pqc`, `pqc_hardening` or `classical_replacement` (e.g. 3DES to
AES-256); a key step with no target is `manual_required`.

---

### GET /svc/pqc/pqc/migration/report

Returns `{"report": {tenant_id, generated_at, inventory, latest_readiness,
timeline, top_risks, next_actions}}`: the inventory above, the latest scan,
the customer's plan deadlines, the first eight risk items and the
inventory's recommendations. There is no score.

---

## Policy algorithm floor (`spec.minAlgorithmTier`)

A `CryptoPolicy` may set `spec.minAlgorithmTier`: every request it targets
must use an algorithm at or above that tier, or it is denied with rule
`crypto-floor` before any other rule runs. Floors, weakest first:
`classical-112`, `classical-128`, `classical-192`, `classical-256`,
`pqc-hybrid`, `pqc-only`. Classical tiers are the security strength from
`pkg/cryptocatalog` (RSA-2048 is `classical-112`, RSA-3072 and RSA-4096
`classical-128`, P-384 `classical-192`, HMAC-SHA-256 with a 256-bit key
`classical-256`). A weak algorithm (broken, under 112 bits, or an unsafe mode
such as ECB) is `deprecated`; a name that states no parameter set is
`not-assessed`;
neither meets any floor. A policy whose floor is not one of the six is
refused on create and update (`400`, `audit.policy.floor_refused`). A
denial emits `audit.policy.violated` and `audit.policy.crypto_floor_violation`. Before
3.2.0-beta RSA-2048 met `classical-128`, RSA-3072 met `classical-192`, and
HMAC, Ed25519 and ECDH were refused under every floor
(docs/SECURITY/ALGORITHM_TRANSITIONS.md).

---

## Service 12: Keyaccess (`/svc/keyaccess/`)

Justification codes for key operations that `ekm` (TDE wrap / unwrap /
rotate), `cloud` (BYOK import / rotate / sync) and `hyok` perform. Callers
send `justification_code` and `justification_text` in those services'
request bodies. Keycore's own routes don't consult it, and there is no
justification header. Details:
[IDENTITY_AND_PQC.md](IDENTITY_AND_PQC.md#section-3-key-access-justifications).

Kernel routes since 6.9.0-beta: the tenant comes from the verified token and
each call emits `audit.keyaccess.<action>`, refusals included. Permissions:
`keyaccess.read` (settings, summary, codes, decisions) and `keyaccess.write`
(settings and codes). `POST .../evaluate` needs `keyaccess.evaluate` and
answers only the `kms-ekm`, `kms-cloud` and `kms-hyok-proxy` service
identities, each for its own service (`evaluator_identity_required`,
`service_mismatch` otherwise); `pkg/keyaccess` sends the caller's service
JWT (before 6.9.0-beta it sent none and every evaluation got 401).

| Route | Body / query | Response key |
|---|---|---|
| `GET` / `PUT /svc/keyaccess/key-access/settings` | `enabled`, `mode` (`enforce` / `audit`), `default_action` (`allow` / `deny` / `approval`), `require_justification_code`, `require_justification_text`, `approval_policy_id` | `settings` |
| `GET .../summary` | | `summary`: 24 h totals and per-service counts |
| `GET` / `POST .../codes`, `PUT` / `DELETE .../codes/{id}` | `code`, `label`, `description`, `action` (`allow` / `deny` / `approval`), `services`, `operations`, `require_text`, `approval_policy_id`, `enabled`. No codes are built in | `items` / `rule` |
| `GET .../decisions?service=&action=&limit=` | | `items` |
| `POST .../evaluate` | called by ekm, cloud and hyok: `tenant_id`, `operation`, `key_id`, `justification_code`, `justification_text`, requester fields; `service` is optional and, if sent, must be the caller's own | `result`: `action`, `reason`, `bypass_detected`, `approval_request_id` |

Rule `allowed_time_windows` / `outside_window_action` were removed in
6.9.0-beta: they were never stored or enforced.

Audit: `audit.keyaccess.settings_viewed`, `settings_updated`,
`summary_viewed`, `codes_viewed`, `code_upserted`, `code_deleted`,
`decisions_viewed`, `decision_evaluated` (with `approval_required` and
`approval_request_id`; the separate `audit.keyaccess.approval_required`
event was removed in 6.9.0-beta).

---

## Service 13: Dataprotect (`/svc/dataprotect/`)

Tokenization, masking, field-level encryption, and secure vault search.

**Permissions and audit (7.4.0-beta).** Every route is on the route kernel:
`dataprotect.read` for GETs, `dataprotect.use` for data operations
(tokenize/detokenize, FPE, mask, redact, `/app/*`, leases, receipts),
`dataprotect.write` for configuration (vaults, policies, profiles, wrapper
registration, lease revoke, `/kdf/keys/*`), `dataprotect.delete` for
DELETEs. Each request emits `audit.dataprotect.<action>` (for example
`tokenize`, `fpe_decrypt`, `policy_update`, `token_vault_delete`), refusals
included (`reason` = `unauthenticated`, `permission_denied`,
`tenant_mismatch`, `tenant_conflict`).

**Authentication (7.2.0-beta).** Every route needs a verified platform JWT
(`Authorization: Bearer`), which dataprotect forwards to keycore so keys are
used as the user (pkg/delegation). The exceptions are the wrapper runtime
routes `POST /field-encryption/leases`, `POST /field-encryption/receipts`,
`POST /field-encryption/leases/{id}/renew` and `GET /field-protection/resolve`
with a named `wrapper_id`: a registered wrapper calls them with
`X-Wrapper-Token` alone, verified against its registration. Wrapper
registration (`register/init`, `register/complete`) needs a platform token.
Anything else gets `401 unauthorized`, audited as
`audit.dataprotect.request_refused` (`reason: unauthenticated |
invalid_token`). Dataprotect refuses to start without the key that verifies
tokens. Before 7.2.0-beta nothing checked a token on any route.

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

`dataprotect.use`. Tokenizes one or more values.

**Body**: `values[]`, `mode` (`vault` or `vaultless`), `vault_id` (vault
mode), `key_id` (vaultless mode), `token_type`, `format`,
`custom_token_format`, `custom_regex`, `ttl_hours`, `one_time_token`,
`metadata_tags`.

**Response 200**: `items[]`, one per value: `input` index, `token`,
`token_type`, `mode` (or `error` for a value that failed).

```bash
printf 'Authorization: Bearer %s\n' "$TOKEN" |
  curl -sS --fail-with-body --cacert vecta-root-ca.pem -X POST https://localhost/svc/dataprotect/tokenize \
    -H @- -H "Content-Type: application/json" \
    -d '{"mode":"vault","vault_id":"'"$VAULT_ID"'","token_type":"pan","values":["4111111111111111"]}'
```

---

### POST /svc/dataprotect/detokenize

`dataprotect.use` (audited at `warning`). **Body**: `tokens[]`, `purpose`,
`workflow`, `justification`, `metadata_tags`, `renew_ttl_hours`.

**Response 200**: `items[]`: `token`, `value` (or `error`), `vault_id`,
`purpose`, `workflow`, `use_count`, `use_limit`, `renew_count`,
`created_at`, `expires_at`.

---

### POST /svc/dataprotect/mask

`dataprotect.use`. Applies a masking policy. **Body**: `policy_id`, `data`
(object), `role`, or `document` with `field_path`.
`POST /svc/dataprotect/mask/preview` is the same call audited as `mask_preview`. **Response
200**: `masked`.

---

## Service 15: Autokey (`/svc/autokey/`)

Policy-driven key provisioning: templates, handles, per-service defaults, governed self-service.

---

### GET /svc/autokey/autokey/settings

Response `settings`: `enabled`, `mode` (`enforce` or `audit`),
`require_approval`, `require_justification`, `allow_template_override`,
`default_policy_id`, `default_rotation_days`, `updated_by`, `updated_at`.

```bash
printf 'Authorization: Bearer %s\n' "$TOKEN" |
  curl -sS --fail-with-body --cacert vecta-root-ca.pem -H @- "https://localhost/svc/autokey/autokey/settings?tenant_id=root"
```

---

### PUT /svc/autokey/autokey/settings

Updates the fields above.

---

### GET /svc/autokey/autokey/summary

Response `summary`: `enabled`, `mode`, `template_count`,
`service_policy_count`, `handle_count`, `pending_approvals`,
`provisioned_24h`, `denied_count`, `failed_count`, `policy_matched_count`,
`policy_mismatch_count`, `services[]`.

---

### GET /svc/autokey/autokey/templates / POST /svc/autokey/autokey/templates

Template: `name`, `service_name`, `resource_type`, `handle_name_pattern`,
`key_name_pattern`, `algorithm`, `key_type`, `purpose`, `export_allowed`,
`iv_mode`, `tags[]`, `labels`, `ops_limit`, `ops_limit_window`,
`approval_required`, `approval_policy_id`, `description`, `enabled`.

```bash
printf 'Authorization: Bearer %s\n' "$TOKEN" |
  curl -sS --fail-with-body --cacert vecta-root-ca.pem -X POST https://localhost/svc/autokey/autokey/templates \
    -H @- -H "Content-Type: application/json" \
    -d '{"tenant_id":"root","name":"s3-encryption","service_name":"storage","resource_type":"s3-bucket","key_name_pattern":"s3-{resource}-dek","algorithm":"AES-256","purpose":"encrypt","labels":{"managed-by":"autokey"},"approval_required":false}'
```

---

### PUT/DELETE /svc/autokey/autokey/templates/{id}

---

### GET /svc/autokey/autokey/service-policies / POST /svc/autokey/autokey/service-policies

Service policy: `service_name`, `display_name`, `default_template_id`,
key defaults (`algorithm`, `key_type`, `purpose`, `export_allowed`,
`iv_mode`, `tags`, `labels`, `ops_limit`, `ops_limit_window`),
`approval_required`, `approval_policy_id`, `enforce_policy`,
`description`, `enabled`.

---

### PUT/DELETE /svc/autokey/autokey/service-policies/{service}

---

### POST /svc/autokey/autokey/requests

Creates a key-handle provisioning request. The service either reuses an existing handle, creates a pending governance request, or provisions immediately.

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| service_name | string | Yes | Service requesting the key |
| resource_type | string | Yes | Resource type requesting the key |
| resource_ref | string | Yes | Resource identifier |
| template_id | string | No | Override template (if `allow_template_override`) |
| handle_name, key_name | string | No | Names; default from the template patterns |
| requested_algorithm, requested_key_type, requested_purpose | string | No | Checked against the policy (a mismatch is recorded as `policy_mismatch_reason`) |
| justification | string | Conditional | Required when `require_justification` |
| tags, labels | string[], object | No | Added to the key |

**Response**: `request`: `id`, `status` (`pending_approval`, `provisioned`, `denied`, `failed`), `approval_required`,
`governance_request_id` (when pending), `handle_id`, `key_id` (when
provisioned), `policy_matched`, `policy_mismatch_reason`,
`failure_reason`, `created_at`, `fulfilled_at`.

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

Create body: `name`, `profile_id`, `role` (`kmip-client`, `kmip-admin`,
`kmip-service`), `enrollment_mode`:
- `internal`: the profile's CA issues the client certificate. Send
  `csr_pem` to keep the private key on the client. Without a CSR the
  response carries `issued_key_pem` once.
- `external`: send the client's `certificate_pem` (and optionally
  `ca_bundle_pem`; a `private_key_pem`, if sent, is only checked against
  the certificate).

Optional: `common_name`, `registration_token`, `metadata_json`. Response
`201`: `client` (`id`, `profile_id`, `name`, `role`, `status`,
`enrollment_mode`, `cert_subject`, `cert_issuer`, `cert_serial`,
`cert_fingerprint_sha256`, `cert_not_before`, `cert_not_after`), plus
`issued_cert_pem` / `issued_key_pem` for internal enrollment.

```bash
jq -n --rawfile csr client.csr '{tenant_id: "root", name: "storage-array", profile_id: env.KMIP_PROFILE_ID,
        role: "kmip-client", enrollment_mode: "internal", csr_pem: $csr}' |
  { printf 'Authorization: Bearer %s\n' "$TOKEN" > "$HDR"; \
    curl -sS --fail-with-body --cacert vecta-root-ca.pem -X POST https://localhost/svc/kmip/kmip/clients \
      -H @"$HDR" -H "Content-Type: application/json" --data-binary @-; rm -f "$HDR"; }
```

---

### GET/DELETE /svc/kmip/kmip/clients/{id}

---

## Service 20: Signing (`/svc/signing/`)

Artifact signing, container image signing, Git artifact signing, keyless provenance.

---

### GET /svc/signing/signing/settings

Response `settings`: `enabled`, `default_profile_id`,
`allowed_identity_modes[]` (`oidc`, `workload`), `updated_by`,
`updated_at`.

---

### PUT /svc/signing/signing/settings

Updates `enabled`, `default_profile_id`, `allowed_identity_modes`.

---

### GET /svc/signing/signing/summary

Response `summary`: `enabled`, `profile_count`, `record_count_24h`,
`transparency_logged_24h`, `workload_signed_24h`, `oidc_signed_24h`,
`verification_failures_24h`, `artifact_counts`.

---

### GET /svc/signing/signing/profiles / POST /svc/signing/signing/profiles

Profile: `name`, `artifact_type`, `key_id`, `signing_algorithm`,
`identity_mode` (`oidc` or `workload`), `allowed_oidc_issuers[]` (exact
match), `allowed_subject_patterns[]`, `allowed_workload_patterns[]`,
`allowed_repositories[]`, `policy` (`required_branch_patterns`,
`required_artifact_tags`, `allowed_digests`, `block_non_ci_commits`,
`require_commit_signature`), `enabled`, `description`.

```bash
printf 'Authorization: Bearer %s\n' "$TOKEN" |
  curl -sS --fail-with-body --cacert vecta-root-ca.pem -X POST https://localhost/svc/signing/signing/profiles \
    -H @- -H "Content-Type: application/json" \
    -d '{"tenant_id":"root","name":"release","artifact_type":"blob","key_id":"'"$KEY_ID"'","identity_mode":"oidc","allowed_oidc_issuers":["https://token.actions.githubusercontent.com"],"allowed_subject_patterns":["repo:acme/app:ref:refs/heads/main"],"enabled":true}'
```

---

### PUT/DELETE /svc/signing/signing/profiles/{id}

---

### POST /svc/signing/signing/blob, POST /svc/signing/signing/git

Signs an artifact with the profile's keycore key; the key never leaves
keycore. **Body**: `profile_id` (else the default profile),
`artifact_type`, `artifact_name`, `digest_sha256` (hex) or `payload`
(base64, hashed server side), `identity_mode` with `oidc_token` (the CI
job's ID token, audience `vecta-kms-signing`) for `oidc`; for git also
`repository`, `commit_sha`; `oci_reference`, `metadata`. Issuer, subject
and repository are taken only from the verified token.

**Response 201**: `result.record` (`id`, `profile_id`, `artifact_type`,
`artifact_name`, `digest_sha256`, `signature`, `key_id`,
`signing_algorithm`, `identity_mode`, `oidc_issuer`, `oidc_subject`,
`workload_identity`, `repository`, `commit_sha`, `oci_reference`,
`transparency_entry_id`, `transparency_hash`, `transparency_index`,
`created_at`) and `result.envelope` (the exact signed statement). A refusal
is audited `audit.signing.sign_refused` with its `code`.

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

Query: `profile_id`, `artifact_type`, `limit`. Response `items[]`: signing
records (fields above), newest first.

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
  search and webhook tests; the cluster services themselves.
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
- `audit.<svc>.dev_mek_rewrapped`, `dev_mek_rewrap_refused`, `mek_rewrapped`, `mek_rewrap_refused`, `mek_unreadable`, `mek_check_refused`, `mek_exposure_remediated`, `mek_exposure_listed`, `mek_exposure_acknowledged`, `mek_backup_rewrap` for `<svc>` in secrets, cert, cloud, ekm, audit, compliance, workload: service master keys (docs/SECURITY/SERVICE_MASTER_KEYS.md)
- `audit.dataprotect.request_refused` (a dataprotect request without a verified platform token, or without a wrapper token on a wrapper runtime route; `reason: unauthenticated | invalid_token`): dataprotect authentication (7.2.0-beta)
- `audit.key.system_key_ensure`, `audit.key.system_key_created`, `audit.key.system_key_change_refused`: keycore system keys
- `audit.key.status_transition_refused`: keycore refused a key status change the lifecycle state table does not allow
- `audit.key.delegation_refused` (a service's delegated request refused, with `reason`), `audit.key.access_refused` (every key-access denial, `result: refused` with `reason`), `audit.key.actor_headers_ignored` (identity headers were sent and ignored), `audit.key.request_refused` (a request without a verified token, `reason: unauthenticated`): keycore key access
- `audit.key.access_policy_read`, `access_policy_updated` (refusal reason `not_key_owner`), `access_groups_listed`, `access_group_created`, `access_group_deleted`, `access_group_members_updated`, `access_settings_read`, `access_settings_updated`, `interface_policies_listed`, `interface_policy_upserted`, `interface_policy_deleted`: keycore access management (kernel, 4.0.0-beta). `interface_tls_config_*` and `interface_port*` were removed with their routes in 6.8.0-beta
- `audit.key.<action>_requested` for `create`, `import`, `form`, `bulk_import`, `bulk_rotate`, `bulk_delete`, `update`, `rotate`, `activate`, `deactivate`, `disable`, `destroy`, `export_policy_update`, `version_activate`, `version_deactivate`, `version_delete`, `usage_limit_update`, `usage_reset`, `approval_update`, `iv_mode_update`, `tag_upsert`, `tag_delete`: keycore key-management requests (kernel, 4.0.0-beta)
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

### Secrets by ID

Secrets are addressed by ID (`/secrets/{id}`), not by path. Values are
sealed under the secrets service's master key and are returned only by
`/value`. Permissions: `secrets.read` (metadata), `secrets.value.read`
(value, audited at `warning`), `secrets.write`, `secrets.delete`.

Secret object: `id`, `tenant_id`, `name`, `secret_type`, `description`,
`labels`, `metadata`, `status`, `lease_ttl_seconds`, `expires_at`,
`current_version`, `created_by`, `created_at`, `updated_at`.

`secret_type`: `api_key`, `password`, `token`, `database_credentials`,
`oauth_client_secret`, `ssh_private_key`, `ssh_public_key`,
`pgp_private_key`, `pgp_public_key`, `ppk`, `x509_certificate`,
`tls_certificate`, `tls_private_key`, `pkcs12`, `jwk`, `kerberos_keytab`,
`wireguard_private_key`, `wireguard_public_key`, `bitlocker_keys`,
`age_key`, `binary_blob`.

| Route | Body / query | Response |
|---|---|---|
| `GET /svc/secrets/secrets` | `secret_type`, `limit`, `offset` | `items[]` (no values) |
| `POST /svc/secrets/secrets` | `name`, `secret_type`, `value`, `description`, `labels`, `metadata`, `lease_ttl_seconds` | `201` `secret` |
| `GET /svc/secrets/secrets/{id}` | | `secret` |
| `GET /svc/secrets/secrets/{id}/value` | `format` (optional) | `value`, `format`, `content_type` |
| `PUT /svc/secrets/secrets/{id}` | any of `name`, `description`, `labels`, `metadata`, `lease_ttl_seconds`, `value` (a new value makes a new version) | `secret` |
| `POST /svc/secrets/secrets/{id}/rotate` | `value` | `secret` |
| `DELETE /svc/secrets/secrets/{id}` | | `status: deleted` |
| `GET /svc/secrets/secrets/{id}/versions` | | `versions[]`: `version`, `value_hash`, `created_at` |
| `GET /svc/secrets/secrets/{id}/audit` | | the secret's audit trail |
| `GET /svc/secrets/secrets/stats` | | counts |
| `POST /svc/secrets/secrets/generate/ssh_key`, `/generate/keypair` | key parameters | `201` `secret` (generated server side) |

---

## Discovery (`/svc/discovery/`) — scan sources

**Authentication, permissions and audit (7.9.0-beta).** Every route needs a
verified platform JWT and is on the route kernel: `discovery.read` for GETs,
`discovery.write` for `POST /discovery/scan`, `POST /discovery/upload`,
`PUT /discovery/assets/{id}/classify`, `DELETE /discovery/assets/{id}`,
`POST /discovery/targets`, `DELETE /discovery/targets/{id}`,
`POST /discovery/repositories`, `DELETE /discovery/repositories/{id}`,
`POST /discovery/repositories/{id}/test` and `PUT /discovery/schedule`. The tenant
comes from the token (a different `tenant_id` is refused as
`tenant_mismatch`). Each request emits `audit.discovery.<action>`
(`scan_start`, `scans_list`, `scan_read`, `assets_list`, `asset_read`,
`asset_review`, `asset_remove`, `summary_read`, `sources_read`,
`upload_scan`, `targets_list`, `target_add`, `target_remove`,
`repositories_list`, `repository_add`, `repository_remove`,
`repository_test`, `schedule_read`, `schedule_update`), refusals
included. `POST /discovery/pii/scan`, `GET /discovery/pii/patterns`,
`GET /discovery/data-inventory` and the `GET /discovery/posture` alias are
removed (content inspection is out of the KMS's scope). The dashboard page is
Keys & lifecycle → Crypto Discovery.

**Scans (background since 7.18.0-beta).** `POST /discovery/scan` (body
`scan_types`: `network`, `cloud`, `certs`, `code`; default all) returns
`202 {"scan": {...}}` with `status: "running"` at once and reads the
sources concurrently in the background, with a 10-minute deadline. Poll
`GET /discovery/scans/{id}`: `stats.sources_done` lists the sources that
have finished, `stats.<source>_assets` their counts, `stats.errors` each
failed or unconfigured source, and `stats.assets_discovered` what was
stored. The final `status` is `completed`, `completed_with_errors`, or
`failed` if every source failed. A scan left running by a restart reads as
`interrupted`. One scan runs per tenant: a second is refused with
`409 scan_running` (the audit event carries `running_scan_id`). Each source
records only what it observed:

- `network`: each endpoint in `DISCOVERY_TLS_ENDPOINTS` (operator config, no
  default) and each tenant target (below), 32 at a time. A TLS target
  records the negotiated key exchange, protocol, cipher, leaf key and
  `chain_trusted`. An SSH target records the key exchange, cipher and MAC
  algorithms the server offers (`metadata.weak_*_offered` lists the weak
  ones) as an `ssh_endpoint` whose algorithm is the strongest key exchange
  offered, and one `ssh_host_key` per host key with its size and
  `SHA256:` fingerprint. `stats.network_endpoints`, `network_no_service`
  (addresses in a range that did not answer) and `network_skipped`
  (platform addresses in a range) describe the sweep.
- `cloud`: each registered account's live KMS inventory via the cloud
  service (`CLOUD_URL`, default `https://cloud:8080`).
- `certs`: the certs service's certificates.
- `code`: the tree mounted at `WORKSPACE_ROOT` (required). Private keys,
  keystores, cloud access keys and long hex strings are recorded by
  file:line and `fingerprint_sha256_prefix`, never the secret; certificates,
  certificate requests, public keys and SSH public keys (`authorized_keys`,
  `known_hosts`, `.pub`) by the key they hold.

**Uploads (7.18.0-beta).** `POST /discovery/upload` with body
`{"name": "bundle.pem", "content": "<base64>"}` inventories one file of at
most 2 MiB with the code scan's parser and returns
`200 {"scan": {...}, "assets": [...]}`. The file is parsed in memory and
never stored or logged. It is recorded as a scan with `scan_type: "upload"`
and its assets have `source: "upload"`. Refusals: `400 invalid_upload`
(empty or not base64) and `413 upload_too_large`.

**Assets.** `GET /discovery/assets` returns `{"items": [...], "total": n}`:
one page (`limit`, default 1000, at most 10000; `offset`) of the assets that
match, most recently updated first, and how many match in the whole
inventory. Filters: `source`, `asset_type`, `classification` (one class or
several separated by commas), `algorithm` (exact; an empty value selects
assets with no algorithm), `pqc_ready=true`, `expiring_days=N` (a
`not_after` that has passed or falls within N days), `not_seen=true` (not
observed by its source's last scan) and `q` (text in the name, location,
algorithm, type or source). `GET /discovery/assets/{id}` reads one and
`DELETE /discovery/assets/{id}` removes one from the inventory (a later scan
that observes it adds it back).

Each asset's `strength_bits` is the classical security strength (RSA-2048 is
112, ML-KEM-768 192; 0 when not assessed), and `classification`, `pqc_ready`
and `qsl_score` come from `pkg/cryptocatalog` (since 3.2.0-beta; before, the
key or parameter size and a hand-kept score). `classification` is `weak`,
`quantum_vulnerable` (sound today, broken by a quantum computer, for example
ECDSA-P256), `strong`, `unknown` (not assessed), or `exposed` for a secret
found in code or an upload. It is derived from the algorithm on every read; before
7.11.0-beta `weak` and `quantum_vulnerable` were one `vulnerable`.

**Reviews.** `PUT /discovery/assets/{id}/classify` records a review:
`status` (`active`, `reviewed`, `accepted_risk` or `remediated`) and
`notes`. Since 7.18.0-beta it is stored in the asset's `metadata`
(`review_status`, `review_notes`, `reviewed_by`, `reviewed_at`) and a rescan
keeps it; the asset's `status` is what the scan observed. A
`classification` other than the catalogue's is refused with
`409 classification_is_catalogue`.

**Summary.** `GET /discovery/summary` counts the whole inventory:
`total_assets`, `classification_counts`, `source_distribution`,
`algorithm_distribution`, `pqc_ready_count`, `pqc_readiness_percent`, and
(7.18.0-beta) `algorithm_classes` and `source_classification` (counts by
class for each algorithm and source) and `expiring_30d`. Each number equals
the `total` of `GET /discovery/assets` with the matching filter. It no
longer returns `average_qsl` or `posture_score`.

**Sources (7.18.0-beta).** `GET /discovery/sources` returns
`{"items": [{id, configured, detail, error?, last_scan?}]}` for `network`
(`detail`: `targets`, `hosts`, `ranges`, `ssh`, `addresses`,
`operator_endpoints`), `cloud` (`accounts`, `providers`), `certs`
(`certificates`), `code` (whether a readable tree is mounted; the path is
not returned) and `upload`. `last_scan` is `{scan_id, started_at, at,
assets, error?}` from the newest finished scan that read the source.
`error` says the cloud or certs service could not be reached.

**Network targets (7.11.0-beta; SSH and ranges 7.18.0-beta).**
`GET /discovery/targets` lists the tenant's targets
(`{"items": [{id, host, port, protocol, created_by, created_at}]}`).
`POST /discovery/targets` with body
`{"host": "api.example.com", "port": 443, "protocol": "tls"}` adds one
(`201 {"target": {...}}`). `protocol` is `tls` (default) or `ssh`. `host`
is a DNS name, an IP address or a range in CIDR notation of at most 256
addresses (`10.0.4.0/24`, or `/120` for IPv6), without scheme or path, and
is stored lower-case. `DELETE /discovery/targets/{id}` removes one.
Refusals: `400 invalid_target` (bad host, port or protocol, a range that is
too large, or a loopback, link-local, metadata, multicast or unspecified
address, including any inside a range), `400 platform_target` (a bare KMS
platform hostname such as `keycore` or `postgres`; 7.13.0-beta),
`409 target_exists`, and `409 target_limit` (256 targets or 4096 addresses
per tenant). Private addresses are allowed. The scan dials every endpoint,
operator and tenant alike, through the same check after DNS resolution: a
reserved address, or one that a platform host or discovery itself uses,
fails as `refused <addr>` in `stats.errors` (in a range it is counted in
`network_skipped`). The inventory never lists the KMS's own services. The
certs source skips `cert_class: internal-mtls`, and assets earlier scans
stored for platform services are hidden. Their certificates are in the
PKI tab.

**Git repositories (7.20.0-beta).** Scan source `git`. `GET
/discovery/repositories` lists the tenant's repositories
(`{"items": [{id, url, ref, provider, connection_id, created_by,
created_at}]}`). `POST /discovery/repositories` with body
`{"url": "https://github.com/acme/app", "ref": "main", "provider": "",
"connection_id": ""}` adds one (`201 {"repository": {...}}`). `url` is the
repository's https address, stored without `.git`; `ref` is a branch, tag or
commit (empty: the default branch); `provider` is `github`, `gitlab`,
`bitbucket` or `gitea`, detected for github.com, gitlab.com, bitbucket.org,
codeberg.org and gitea.com and required for any other host;
`connection_id` names a sealed `git` connection for a private repository.
`DELETE /discovery/repositories/{id}` removes one. Refusals:
`400 invalid_repository` (not an https repository URL, a user name or token
in the URL, a reserved address, an unknown provider or a bad ref),
`400 platform_target`, `409 repository_exists`, `409 repository_limit`
(100 per tenant) and `400 connection_unfit` (the connection is not a `git`
connection or is for another host). `502 connection_unavailable` means
compliance could not open the connection.

The scan requests the hosting API's tar.gz of the ref (GitHub
`/repos/{owner}/{repo}/tarball/{ref}`, GitLab
`/api/v4/projects/{path}/repository/archive.tar.gz`, Bitbucket
`/{workspace}/{repo}/get/{ref}.tar.gz`, Gitea
`/api/v1/repos/{owner}/{repo}/archive/{ref}.tar.gz`) over TLS 1.3 through
the scan's dial guard, and reads it in memory with the code scan's parser:
files of at most 2 MiB, at most 512 MiB and 50000 entries an archive,
skipping `.git`, `node_modules`, `vendor`, `bin`, `dist` and lock files.
Assets have `source: "git"`, `location` `host/owner/repo[@ref]/path:line`,
and `metadata.repository`, `path`, `ref` and `commit`. The token is sent
only to the connection's host and not along a redirect to another host.
Only the ref's latest commit is read. `stats.git_repositories` and
`stats.git_files` describe the scan; a repository that fails is named in
`stats.errors.git` and the others are still scanned.

`POST /discovery/repositories/{id}/test` reads the start of the archive
with the repository's connection and returns `200 {"ok": true, "commit"}`,
or `502 repository_unreachable` with the reason. It stores nothing.

**Schedule (7.20.0-beta).** `GET /discovery/schedule` returns
`{"schedule": {enabled, interval_hours, sources, authorized_by,
next_run_at, last_run_at, last_scan_id, paused_reason}}` (a tenant that
never saved one has `enabled: false`). `PUT /discovery/schedule` with body
`{"enabled": true, "interval_hours": 24, "sources": ["network", "git"]}`
saves it: `interval_hours` 1 to 720, `sources` from `network`, `cloud`,
`certs`, `code`, `git`. The first run is one interval later. Only a
signed-in user can save one (`403 user_required` for an API client or a
service): the schedule runs as the discovery service on that user's
authority, and before every run auth is asked whether they are still active
and still hold `discovery.write`. If not, the schedule gets a
`paused_reason` and stops until it is saved again; if auth can't be
reached, the run is postponed 15 minutes. `400 invalid_schedule` refuses a
bad interval or source. Each run or refusal emits
`audit.discovery.scheduled_scan` (`result: refused`, `reason:
authority_revoked` or `authority_unknown`), and the scan it starts has
`trigger: "scheduled"`. Schedules run on the cluster primary.

**Exposed secrets.** The first time a private key, keystore or access key
is found, discovery emits `audit.discovery.secret_exposed` (target: the
asset; details: type, source, location and fingerprint prefix). Playbooks
can trigger on it (`secret_exposed`). Finding the same secret again does
not repeat the event.

---

## Service 26: SBOM (`/svc/sbom/`)

Software BOM and Cryptographic BOM: generation, history, diff and export.
The KMS does not match the SBOM against CVE feeds: export it (CycloneDX or
SPDX) to your vulnerability-management tool. `GET /sbom/vulnerabilities` and
`/sbom/advisories` were removed in 2.19.0-beta.

Every route is on the `pkg/route` kernel (since 1.33.0-beta; before it sbom
verified no token at all): a verified bearer token is required and each request
emits `audit.sbom.<action>`, refusals included. Permissions: `sbom.read`,
`sbom.write` (generate). CBOM
routes are scoped to the token's tenant (`kms-*` service principals act for the
tenant they name). The platform SBOM is shared by every tenant, so
`POST /sbom/generate` also requires the platform tenant (or a
tenant-less root token or service principal); anyone else is refused with
reason `platform_tenant_required`.

---

### GET /svc/sbom/sbom/latest

Returns the latest SBOM snapshot. **Response 200**: `item`: `id`,
`source_hash`, `created_at`, `document` (the components), `summary`.

---

### POST /svc/sbom/sbom/generate

Generates a fresh software BOM snapshot (platform tenant only, see above).
**Body** (optional): `trigger`. **Response 202**: `status: accepted`,
`snapshot` (as above). Export with `GET /svc/sbom/sbom/{id}/export`.

---

### POST /svc/sbom/cbom/generate

Generates a Cryptographic BOM snapshot for the token's tenant (a named
`tenant_id` must match it). **Body** (optional): `trigger`. **Response
202**: `status: accepted`, `snapshot` (`id`, `tenant_id`, `source_hash`,
`created_at`, `document`, `summary`).

---

### GET /svc/sbom/cbom/pqc-readiness

From the latest CBOM. **Response 200**: `pqc_readiness`: `tenant_id`,
`total_assets`, `pqc_ready_count`, `pqc_readiness_percent`, `status`.

---

## Platform health (watchdog, reconciler)

Shown in **Administration > System Administration > Health**, under the
live service list from `GET /auth/system-health` (1.39.0-beta; the separate
Platform > Health tab is gone). Both services are on the `pkg/route` kernel:
a verified bearer token holding `health.read` is required (administrators
hold it through `*`), and every read is audited, refusals included. Before
1.39.0-beta these routes were unauthenticated and Envoy did not route them,
so the dashboard tab was always empty.

| Method | Path | Returns | Audit |
|---|---|---|---|
| GET | `/svc/watchdog/watchdog/heartbeats` | `items[]`: `service`, `state`, `last_seen`, `silence_seconds`, `healthy` (silent over 90s or reporting `degraded` = unhealthy), sorted by service | `audit.watchdog.heartbeats_listed` |
| GET | `/svc/watchdog/watchdog/incidents` | `items[]`: `id`, `service`, `reason`, `action`, `recommendation`, `timestamp` (rolling in-memory window) | `audit.watchdog.incidents_listed` |
| GET | `/svc/reconciler/reconciler/status` | `items[]`: `name`, `last_run_at` (absent until the first pass), `last_error` | `audit.reconciler.status_read` |

Heartbeats come from `pkg/heartbeat` on `health.<service>.heartbeat`. Every
service started through `platform.Boot` publishes one once it is serving;
keycore, kmip, audit and policy publish their own.

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
Built-in approval policies: `audit.governance.builtin_policy_created` (`policy_id`, `name`, `trigger_actions`, `approver_roles`, `trigger`), emitted once per tenant and policy; `audit.governance.builtin_policy_restored` (`policy_id`, `name`, `trigger`) when a required policy disabled under 2.5.0-beta is switched back on.

**HYOK.** Crypto routes accept only a verified bearer JWT (no client
certificate or `X-Client-*` header identity). `auth_mode` is `jwt`; `mtls` is
refused (`400 auth_mode_unavailable`), stored `mtls_or_jwt` reads as `jwt`.
A `202 pending_approval` response carries `approval_request_id`; retrying the
same request body with `"approval_request_id"` runs it once the approval is
approved for that key, operation and payload (`403 approval_invalid`
otherwise; `audit.hyok.approval_refused`). When the
`key_access_justifications` profile is deployed (or the deployment's profiles
are unknown) an unreachable key-access service refuses (`424
key_access_unavailable`); when it
isn't deployed the request runs with `key_access_reason:
key_access_not_deployed`. The same holds for EKM TDE and cloud BYOK
operations. An unreachable policy service likewise refuses (`424
policy_unavailable`, `audit.hyok.request_denied` with `reason:
policy_unavailable`); `HYOK_POLICY_FAIL_CLOSED` was removed in 6.20.0-beta.
`approver_emails` is no longer accepted.

**EKM TDE keys have no read or export route.** `GET /ekm/tde/keys/{id}` and
`POST /ekm/tde/keys/{id}/export` do not exist; the EKM agent that called them
had its local key cache removed (6.15.0-beta). Agents wrap and unwrap DEKs
only through `POST /ekm/tde/keys/{id}/wrap` and `/unwrap`. The agent
settings `key_cache_enabled` and `key_cache_ttl_sec` (`KEY_CACHE_ENABLED`,
`KEY_CACHE_TTL_SEC`) are gone and ignored if still set.

**EKM TDE public key.** `GET /ekm/tde/keys/{id}/public` returns the key's
current public key read from keycore's `GET /keys/{id}/public-key` on every
call (`format: pem`, `key_version`), for the caller: ekm forwards the
caller's verified token with usage `read`, so keycore decides by the user's
view (6.18.0-beta). Keycore's refusal is returned with its status and reason
(`403`, or `404` for a key the user can't see); any other failure is
`424 public_key_unavailable`. Each is audited as
`audit.ekm.tde_key_accessed`, `result: refused` with the reason. It no longer
returns an `EKM-PUBLIC-` value derived from the tenant and key ID
(6.12.0-beta). A rotation clears the stored copy and refreshes it from
keycore. `GET /ekm/agents/{id}/status` carries
`assigned_key_algorithm`, the algorithm of the agent's assigned TDE key.
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

Audit events use dot-separated action subjects. On a service fully on the
route kernel, a request with no bearer token or an invalid one is refused
by the kernel and audited as `audit.<service>.<action>` with `result:
refused` and `reason` `unauthenticated` or `invalid_token` (7.10.0-beta). On a service still on a
raw mux the JWT layer audits it as `audit.<service>.request_refused` with
the same reasons (7.12.0-beta).
Common prefixes:

| Prefix | Domain |
|--------|--------|
| audit.auth.* | Authentication and identity |
| audit.key.* | Key lifecycle and crypto operations |
| audit.keycore.* | Canary trips and threat signals |
| audit.cert.* | Certificate and CA operations |
| audit.governance.* | Approvals, encrypted backup/restore, platform FIPS mode |
| audit.backup.* | Backup scheduler (preview): policy changes and refused runs/restores |
| audit.cluster.* | Cluster join, replication publications, write forwarding |
| audit.kmip.* | KMIP sessions, operations and denials |
| audit.dataprotect.* | Data protection operations and key-derivation migration |
| audit.discovery.* | Discovery scans, inventory reads, asset reviews and network targets (route kernel, 7.9.0-beta; `targets_list`, `target_add`, `target_remove` 7.11.0-beta; `sources_read`, `upload_scan`, `asset_remove` 7.18.0-beta); scan lifecycle events `scan_initiated`, `asset_found`, `scan_completed`, `asset_classified`; `secret_exposed` when a secret is first found (7.18.0-beta); git repositories and the schedule (`repositories_list`, `repository_add`, `repository_remove`, `repository_test`, `schedule_read`, `schedule_update`) and `scheduled_scan` for each scheduled run or refusal (7.20.0-beta) |
| audit.policy.* | Crypto policy changes, evaluations and refusals |
| audit.compliance.* | Compliance assessments |
| audit.posture.* | Posture engine (reads, scans, event ingest, action execution, threat findings) |
| audit.scim.* | SCIM provisioning |
| audit.mpc.* | MPC ceremonies |
| audit.signing.* | Artifact signing |
| audit.workload.* | Workload identity |
| audit.confidential.* | Attestation verdicts and attested key release |
| audit.keyaccess.* | Key access justification policy and decisions |
| audit.ekm.* | EKM agents and TDE keys; `audit.ekm.key_access_denied` for a TDE operation refused by key access (deny, or `key_access_unavailable`) |
| audit.cloud.* | Cloud BYOK accounts, bindings and sync; `audit.cloud.key_access_denied` for a refusal by key access |
| audit.hyok.* | HYOK proxy requests; `audit.hyok.request_denied` for policy and key access refusals |
| audit.security.* | Audit-side detection signals (sustained risk) |
| audit.secrets.* | Secret vault access |
| audit.sbom.* | SBOM/CBOM generation |
| audit.watchdog.* | Watchdog heartbeat and incident reads |
| audit.reconciler.* | Reconciler status reads |
| audit.health.* | Watchdog incidents (a service went silent or degraded) |
| audit.ai.* | AI queries and recommendations |

Selected events with dedicated audit classification:
- `audit.dataprotect.fpe_encrypted`, `audit.dataprotect.fpe_decrypted` (FF1), `audit.dataprotect.fpe_legacy_decrypted` (pre-1.26.0 migration), `audit.dataprotect.fpe_refused` (FF3-1, legacy encrypt, unknown; `result: refused`)
- `audit.key.create_refused` (unsupported algorithm), `audit.key.algorithm_label_corrected` (startup relabel of faked key material), `audit.key.kdf_refused` (scrypt/Argon2id in strict mode)
- `audit.crypto.random` (with the source that produced the bytes; `hsm_serial` for `hsm-trng`), `audit.crypto.random_refused` (QKD/QRNG/no HSM)
- `audit.hsm.random_generated` (hsm-connector `POST /hsm/random`)
- `audit.pqc.migration_step_executed` (per step: `successor_created` or `rotated`), `audit.pqc.migration_executed`, `audit.pqc.migration_failed`, `audit.pqc.migration_rolled_back`
- `audit.sbom.generated` (`snapshot_id`, `component_count`, `trigger`), `audit.sbom.cbom_generated` (was `audit.cbom.generated` before 1.37.0-beta): the snapshot produced, manual or scheduled (`trigger`), emitted through `pkg/audit` with actor `kms-sbom`. `GET /cbom/history` returns `[]` when no snapshot exists; it never generates one
- `audit.workload.mek_signing_keys_sealed` / `mek_signing_keys_seal_refused` (6.11.0-beta): the primary sealed a tenant's plaintext signing keys from an earlier release, or couldn't (`result: refused`, `reason: seal_failed`); `audit.workload.mek_exposure_recorded` precedes each seal
- `audit.workload.*` request events (route kernel, 6.9.0-beta): `settings_viewed`, `settings_updated`, `signing_keys_rotated` (6.11.0-beta), `summary_viewed`, `registrations_viewed`, `registration_upserted`, `registration_deleted`, `federation_viewed`, `federation_bundle_upserted`, `federation_bundle_deleted`, `svid_issued`, `issuance_history_viewed`, `token_exchanged` (actor: the verified SPIFFE ID), `graph_viewed`, `key_usage_viewed`
- `audit.keyaccess.*` request events (route kernel, 6.9.0-beta): `settings_viewed`, `settings_updated`, `summary_viewed`, `codes_viewed`, `code_upserted`, `code_deleted`, `decisions_viewed`, `decision_evaluated` (refusals `evaluator_identity_required`, `service_mismatch`)
- `audit.confidential.*` request events (route kernel, 6.9.0-beta): `policy_viewed`, `policy_updated`, `summary_viewed`, `key_release_evaluated`, `releases_viewed`, `release_viewed`, `key_release`
- `audit.sbom.*` request events (route kernel): `sbom_generate_requested`, `sbom_latest_read`, `sbom_history_listed`, `sbom_diff_read`, `sbom_exported`, `sbom_read`, `cbom_generate_requested`, `cbom_latest_read`, `cbom_history_listed`, `cbom_summary_read`, `cbom_pqc_readiness_read`, `cbom_diff_read`, `cbom_exported`, `cbom_read`; handler refusal reason `platform_tenant_required`
- `audit.reporting.*` request events (route kernel): `alerts_listed`, `alerts_feed_streamed`, `alerts_unread_counted`, `alert_read`, `alert_updated` (`operation`: acknowledge / resolve / false_positive / escalate; replaces `alert_escalated`), `alerts_bulk_acknowledged`, `alerts_bulk_resolved`, `incidents_listed`, `incident_read`, `incident_status_updated`, `incident_assigned`, `rules_listed`, `rule_created`, `rule_updated`, `rule_deleted`, `rule_tested` (2.13.0-beta: `POST /svc/reporting/alerts/rules/test` checks a rule without saving it, with details `valid`, `replay_hours`, `replay_matched`, `replay_fired`; see docs/GOVERNANCE_AND_COMPLIANCE.md §4.1), `severity_config_read`, `severity_config_updated`, `channels_listed`, `channels_updated`, `report_templates_listed`, `report_requested`, `report_jobs_listed`, `report_job_read`, `report_downloaded`, `report_deleted`, `scheduled_reports_listed`, `report_scheduled`, `error_telemetry_captured`, `error_telemetry_listed`, `alert_stats_read`, `mttd_stats_viewed`, `mttr_stats_read`, `top_sources_read`. Background: `audit.reporting.alert_created`, `audit.reporting.report_requested` (`trigger: scheduled`), `audit.reporting.evidence_pack_requested`
- `audit.compliance.*` playbook events (2.5.0-beta). Route kernel: `playbook_catalog_read`, `playbook_summary_read`, `playbooks_listed`, `playbook_created`, `playbook_read`, `playbook_updated`, `playbook_deleted`, `playbook_run_requested`, `playbook_dry_run`, `playbook_runs_listed`, `playbook_runs_searched`, `playbook_run_read`, `playbook_run_cancelled`, `playbook_run_retried`, `connections_listed`, `connection_created`, `connection_updated`, `connection_deleted`, `connection_tested`, `connection_resolved`, `connection_imported` (2.10.0-beta; refusals `service_identity_required`, `connection_use_unsupported`) (refusals `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`, `action_permission_denied`, `user_required`, `url_blocked`, `connection_invalid`, `playbook_invalid`, `connection_in_use`, `connection_usage_unverified`, `run_not_cancellable`, `run_not_retryable`). Engine: `playbook_triggered` (`success` with `run_id`, or `refused` with `reason` `playbook_not_authorized` / `authority_revoked` / `authority_unverified` / `cooldown` / `cooldown_unavailable` / `stale_event` / `threshold_unavailable`), `playbook_action_executed` (per action: `success`, `pending` (`outcome` `pending_approval` or `awaiting_approval`), `skipped`, `failure`, or `refused` with `reason` `action_removed` / `approval_mismatch` / `approval_unverified` / `definition_changed` / `authority_revoked` / `authority_unverified`), `playbook_approval_requested`, `playbook_approval_granted`, `playbook_run_completed` (`status`; `refused` for cancelled, denied or expired approvals), `playbook_action` (the `create_audit_event` action), `playbook_connections_migrated` (inline credentials sealed; `refused` with `seal_failed`), and the `pkg/mek` events `audit.compliance.mek_*`
- `audit.auth.tenant_ids_listed` (kernel event, `count`; refusals `service_identity_required`, `unauthenticated`): tenant IDs for reporting's alert sync (6.22.0-beta)
- `audit.auth.delegated_authority_checked`, `audit.auth.delegated_user_disabled`, `audit.auth.delegated_api_key_revoked`, `audit.auth.delegated_client_revoked` (kernel events; `on_behalf_of`, `via: kms-compliance`, `playbook_run_id`; refusals `service_identity_required`, `delegator_unknown`, `delegator_inactive`, `delegator_lacks_permission`, `self_target`, `last_administrator`, `service_identity_protected`): playbook delegated operations (2.5.0-beta)
- `audit.governance.notify_connections_migrated` (plaintext Slack/Teams approval-notice URLs moved into compliance connections; `connection_ids`), `audit.governance.webhook_sent` / `audit.governance.webhook_failed` (one per approval notice and channel), `audit.governance.webhook_tested` (also `refused` with `reason: ad_hoc_url_refused`) (2.10.0-beta)
- `audit.governance.notification_email_sent` (kernel event; refusals `service_identity_required`, `recipient_not_tenant_user`; failures `smtp_not_configured`, `send_failed`): playbook email (2.5.0-beta)
- `audit.reporting.incident_opened` (a new incident: target the incident, `title`, `severity`), `audit.reporting.alert_created` (target the alert; `severity`, `incident_id`, `source_*`): playbook triggers (2.5.0-beta)
- `audit.watchdog.heartbeats_listed`, `audit.watchdog.incidents_listed`, `audit.reconciler.status_read` (kernel events, permission `health.read`; refusals `unauthenticated`, `permission_denied`): platform health reads (1.39.0-beta)
- `audit.key.encrypt`, `audit.key.decrypt`, `audit.key.wrap`, `audit.key.unwrap`, `audit.key.sign`, `audit.key.verify`, `audit.key.mac`, `audit.key.derive`, `audit.key.kem_encapsulate`, `audit.key.kem_decapsulate`: every key operation, named after the operation that ran, with `duration_ms` and `result` `success` / `refused` (`reason`) / `failure` / `pending_approval` (2.1.0-beta; these feed the Operations metrics)
- `audit.key.rotate`, `audit.key.destroy`, `audit.key.export`
- `audit.dataprotect.<op>_refused`, `audit.dataprotect.<op>_failed` (`op`: `tokenize`, `detokenize`, `fpe_encrypt`, `fpe_decrypt`, `field_encrypt`, `field_decrypt`, `envelope_encrypt`, `envelope_decrypt`, `searchable_encrypt`, `searchable_decrypt`)
- `audit.cert.cert_issue_failed`, `audit.cert.ocsp_sign_failed`
- Metered operations (`metered_op` in details) feed the Operations metrics; see "Operations metrics"
- `audit.key.data_key_generated` (refusals: `reason` = `ops_limit_reached`, `policy_denied`, `fips_mode_violation`, access and HSM refusals, `permission_denied`): envelope-encryption DEK generation
- `audit.key.rotation_policies_listed`, `audit.key.rotation_policy_created`, `audit.key.rotation_policy_updated`, `audit.key.rotation_policy_deleted`, `audit.key.rotation_policy_triggered`, `audit.key.rotation_runs_listed`, `audit.key.rotation_upcoming_listed` (kernel events; refusals `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`), `audit.key.rotation_policy_run` (scheduled run; `result: failure` when any key failed): key rotation policies
- `audit.audit.checkpoints_listed` (kernel event for `GET /audit/checkpoints`; details `checkpoints`, `failed`), `audit.audit.checkpoint_signed` (a signed chain head: `chain_node`, `sequence`, `chain_hash`, `signed_at`, `key_id`, `algorithm`, `signature`), `audit.audit.checkpoint_key_created` (root; `target_id` key ID, `public_key_pem`), `audit.audit.checkpoint_refused` (`reason` `key_generation_failed`/`signing_failed`), `audit.audit.event_hmac_key_installed` (root; HMAC key derived from the audit master key; `mek_version`, `unavailable_mek_versions`).
- `audit.audit.activity_stats_read` (kernel event for `GET /audit/activity/stats`, 7.17.0-beta; details `from`, `to`, `total`; refusals `result: refused`, `reason` `bad_window` or the kernel's).
- `audit.audit.target_integrity_verified` (kernel event for `GET /audit/targets/{target_id}/integrity`; details `verdict`, `events_checked`, `failed`), `audit.audit.chain_broken` (critical; `scope: target` with `target_id` and per-event `breaks`, or the whole tenant chain; `break_count`). Published on the `AUDIT` stream (recorded by ingest, directly if the publish fails), so playbooks can trigger on it: audit trail integrity
- `audit.key.key_consumers_read` (kernel event for `GET /keys/{id}/consumers`; detail `consumers`): a key's callers and rotate/delete impact
- `audit.key.public_key_read` (kernel event for `GET /keys/{id}/public-key`; details `algorithm`, `version`; refusals `not_asymmetric`, `key_deleted`, `spki_unavailable` and the kernel's own): an asymmetric key's public key read (6.18.0-beta)
- `audit.audit.webhooks_listed`, `audit.audit.webhook_created`, `audit.audit.webhook_updated`, `audit.audit.webhook_deleted`, `audit.audit.webhook_tested`, `audit.audit.webhook_deliveries_listed` (kernel events; also refused with `reason: url_blocked`), `audit.audit.webhook_delivered` (every delivery, `result` success/failure), `audit.audit.webhook_credentials_sealed` / `audit.audit.webhook_credentials_seal_refused` (plaintext rows from before 1.25.0-beta), `audit.audit.webhook_migrated` / `audit.audit.webhook_migration_refused` (legacy streams moved into compliance connections, 2.10.0-beta; also refused on create/update with `connection_not_streamable`), `audit.audit.mek_exposure_recorded` and the `audit.audit.mek_*` master-key events: webhooks
- `audit.posture.health_read`, `audit.posture.dashboard_viewed`, `audit.posture.risk_read`, `audit.posture.risk_history_read`, `audit.posture.scan_run`, `audit.posture.events_ingested`, `audit.posture.audit_synced`, `audit.posture.findings_listed`, `audit.posture.finding_status_updated`, `audit.posture.actions_listed`, `audit.posture.action_executed` (kernel events; refusals `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`, `tenant_wildcard`), `audit.posture.events_ingested` (also from the scheduled audit sync, `source: scheduled_audit_sync`, under the synced tenant), `audit.posture.risk_snapshot`, `audit.posture.preventive_controls_applied`, `audit.posture.actions_corrected` (engine events; `audit.posture.runbook.execute` is no longer emitted as of 1.34.0-beta): posture engine
- `audit.key.canary_keys_listed`, `audit.key.canary_key_created`, `audit.key.canary_trips_listed`, `audit.key.canary_key_deactivated` (kernel events; refusals `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`), `audit.keycore.canary_tripped` (a canary key ID was referenced through the key API: `canary_id`, `actor_id`, `actor_ip`): canary keys
- `audit.keycore.threat_signal_raised` (scheduled sweep or canary trip: `signal_id`, `signal_type`, `key_id`, `actor_id`, `severity`, `description`), `audit.posture.threat_finding_raised` (posture raised a finding for a signal: `finding_id`, `signal_id`, `signal_type`, `severity`): threat detection
- `audit.key.cryptoperiods_listed`, `audit.key.cryptoperiod_set`, `audit.key.cryptoperiod_reset` (kernel events for `/rotation/cryptoperiods`; details `days`, `default_days`; refusals `invalid_days`, `unknown_category`, `not_custom`)
- `audit.security.sustained_risk_detected` (audit's sustained-risk signal: 3 events scoring ≥80 on one target within 5 minutes, once per window; `target_type` / `target_id` name the key, target or tenant, details `reason`, `score_threshold`, `window_seconds`, `result: warning`). It changes nothing itself; the `sustained_risk_detected` playbook trigger responds. Replaced `audit.security.auto_quarantined` in 5.3.0-beta, which quarantined nothing
- `audit.policy.floor_refused` (a policy create or update refused because `spec.minAlgorithmTier` is not a floor; `result: refused`, `reason: invalid_min_algorithm_tier`, `policy_name`, `min_algorithm_tier`). A request denied by a valid floor emits `audit.policy.violated` (`result: refused`, `rules: ["crypto-floor"]`, `algorithm`) and `audit.policy.crypto_floor_violation` (`reason: below_min_algorithm_tier`, `policy_id`, `algorithm`, `tier`)
- `audit.key.agility_drill_run`, `audit.key.agility_drills_listed` (swap drill kernel events, above), `audit.key.caraf_*` (risk assessment kernel events, above), `audit.key.crypto_policy_refused` (a key operation refused by the tenant's migration policy; `result: refused`, `reason`, `operation`, `algorithm`, `key_id`, `rule_id`, `rule_name`, `rule_action`), `audit.key.agility_policy_rules_listed`, `audit.key.agility_policy_rule_created`, `audit.key.agility_policy_rule_updated`, `audit.key.agility_policy_rule_deleted` (kernel events; refusals `result: refused`)
- `audit.key.algorithm_changed` (a rotation moved the key to `to_algorithm` under the same key ID; `from_algorithm`, `version`), `audit.key.algorithm_change_refused` (`result: refused`, `reason`), `audit.key.ciphertext_rewrapped` (kernel event; refusals as below): crypto agility under a stable key ID
- `audit.key.agility_posture_read`, `audit.key.agility_inventory_read`, `audit.key.agility_keys_by_algorithm_read` (kernel events; refusals `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`): crypto agility
- `audit.auth.login`, `audit.auth.logout`, `audit.auth.mfa_verified`
- `audit.auth.scim_user_provisioned`, `audit.auth.scim_user_deprovisioned`
- `audit.auth.scim_settings_updated`, `audit.auth.scim_token_rotated`
- `audit.cert.internal_subca_created`, `audit.certs.internal_enroll` (refusals: `reason` = `invalid_request`, `invalid_csr`, `proof_rejected`, `issuance_refused`), `audit.cert.internal_enrolled`: internal mTLS (docs/SECURITY/INTERNAL_TLS.md)
- `audit.auth.cli_session_refused` (`reason`: `invalid_credentials`, `public_default_password`), `audit.auth.cli_ssh_password_synced`, `audit.auth.cli_password_revoked`: CLI/SSH access to hsm-integration (docs/SECURITY/HSM_INTEGRATION.md)
- `audit.hsm.provider_library_inventory`, `audit.hsm.provider_library_added`, `audit.hsm.provider_library_changed`, `audit.hsm.provider_library_removed`: files in the PKCS#11 provider workspace, with SHA-256
- `audit.certs.internal_mtls_inventory_read`, `audit.certs.internal_mtls_policy_updated`, `audit.certs.internal_mtls_rotated`, `audit.certs.internal_mtls_rotated_all` (refusals: `not_root_tenant`, `unchanged`, `invalid_policy`, `unknown_identity`, `kx_profile_not_applicable`, `force_not_available`, `confirmation_required`), `audit.certs.internal_mtls_applied` (a change is running on every instance), `audit.certs.edge_tls_read`, `audit.certs.edge_tls_policy_updated` (refusals: `not_root_tenant`, `invalid_policy`, `unchanged`), `audit.certs.edge_tls_applied` (every external listener was measured accepting exactly the new groups), `audit.certs.edge_tls_certificate_source_updated`, `audit.certs.edge_tls_csr_created`, `audit.certs.edge_tls_certificate_installed` (refusals listed under Edge certificate), `audit.certs.edge_tls_measurement_read`, `audit.certs.certificate_key_label_corrected`: Service mTLS (docs/SECURITY/INTERNAL_TLS.md)
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
- `audit.key.service_derive`, `audit.key.service_derive_refused`, enterprise control upserts carry `feature_status` / `feature_id`
- Services on the `pkg/route` kernel emit one `audit.<service>.<action>` per request, including `result: failure` (with `error_code`) and `result: refused` (with `reason`: `unauthenticated`, `permission_denied`, `tenant_mismatch`, `tenant_conflict`, or a handler reason such as `feature_preview`). `audit.secrets.*`: `created`, `listed`, `read`, `value_read`, `updated`, `deleted`, `generated`, `versions_listed`, `audit_log_read`, `rotated`, `stats_read`, `vault_kv_read`, `vault_kv_written`, `vault_kv_deleted`, `vault_metadata_read`, `vault_token_lookup`, `vault_health_read`, `vault_seal_status_read`
- `audit.kmip.client_connected`, `audit.kmip.authorization_denied`, `audit.kmip.operation_panic` (critical), `audit.kmip.<operation>` with `status` / `reason` (lifecycle-state refusals included)
- `audit.dataprotect.kdf_legacy_used`, `audit.dataprotect.kdf_migration_started`, `audit.dataprotect.kdf_vault_reprotected`, `audit.dataprotect.kdf_migration_completed`, `audit.dataprotect.kdf_migration_aborted`
- `audit.mpc.dkg_initiated`, `audit.mpc.sign_initiated`, `audit.mpc.sign_completed`
- `audit.signing.artifact_signed`, `audit.signing.artifact_verified` (`verification_status`: verified / signature_invalid / artifact_mismatch), `audit.signing.records_viewed`
- `audit.confidential.key_released`, `audit.confidential.attestation_denied`

---

## Appendix: Common Workflows

Credentials go to curl on stdin, never in argv
([SECRET_HANDLING.md](SECURITY/SECRET_HANDLING.md)). `kms` below is a small
helper; `vecta-root-ca.pem` is the internal root CA from the PKI tab.

```bash
kms() {  # kms METHOD PATH [JSON]
  printf 'Authorization: Bearer %s\n' "$TOKEN" |
    curl -sS --fail-with-body --cacert vecta-root-ca.pem -X "$1" -H @- \
      -H "Content-Type: application/json" "https://localhost$2" ${3:+-d "$3"}
}
```

### Encrypt application data

```bash
# 1. Log in (a user whose role holds key.create and key.encrypt)
export TOKEN=$(jq -n '{tenant_id: "root", username: env.KMS_USER, password: env.KMS_PASSWORD}' |
  curl -sS --fail-with-body --cacert vecta-root-ca.pem -X POST https://localhost/svc/auth/auth/login \
    -H "Content-Type: application/json" --data-binary @- | jq -r .access_token)

# 2. Create a key (once)
KEY_ID=$(kms POST /svc/keycore/keys '{"name":"app-data-key","algorithm":"AES-256","purpose":"encrypt"}' | jq -r .key_id)

# 3. Encrypt; keep ciphertext, iv and version for decrypt
kms POST "/svc/keycore/keys/$KEY_ID/encrypt" '{"plaintext":"c2Vuc2l0aXZlIGRhdGE="}'
```

### Issue a TLS certificate from a CSR

```bash
# 1. Generate the key and CSR where the key will live
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout server.key \
  -subj "/CN=api.acme.example/O=Acme Corp" -out server.csr

# 2. Have a KMS CA sign it (the private key never leaves your host)
kms POST /svc/certs/certs/sign-csr "$(jq -n --rawfile csr server.csr --arg ca "$CA_ID" \
  '{ca_id: $ca, cert_type: "server", csr_pem: $csr, sans: ["api.acme.example"], validity_days: 90}')" |
  jq -r .certificate.cert_pem > server.crt
```

### Provision a workload key via Autokey

```bash
kms POST /svc/autokey/autokey/requests \
  '{"tenant_id":"root","service_name":"data-pipeline","resource_type":"s3-bucket","resource_ref":"my-app-data-bucket","justification":"production encryption"}' |
  jq '.request | {status, key_id, governance_request_id}'
```

## Appendix: Route index (generated)

<!-- route-index:start (generated by scripts/check-doc-routes.py --write-index) -->

Every route each service registers, as reached through the edge. Generated
from the code; do not edit by hand.

### audit (`/svc/audit/`)

- `GET /svc/audit/audit/activity/stats`
- `GET /svc/audit/audit/cbom/diff`
- `GET /svc/audit/audit/cbom/inventory`
- `GET /svc/audit/audit/chain/verify`
- `GET /svc/audit/audit/checkpoints`
- `POST /svc/audit/audit/cluster/signing-key/export`
- `POST /svc/audit/audit/cluster/signing-key/import`
- `POST /svc/audit/audit/cluster/signing-key/join-key`
- `GET /svc/audit/audit/config`
- `GET /svc/audit/audit/correlation/{id}`
- `GET /svc/audit/audit/events`
- `GET /svc/audit/audit/events/{id}`
- `GET /svc/audit/audit/fips/boundary`
- `POST /svc/audit/audit/publish`
- `POST /svc/audit/audit/search`
- `GET /svc/audit/audit/session/{session_id}`
- `GET /svc/audit/audit/stream`
- `GET /svc/audit/audit/targets/{target_id}/integrity`
- `GET /svc/audit/audit/timeline/{target_id}`
- `GET /svc/audit/metrics`
- `GET /svc/audit/ops-metrics/by-service`
- `GET /svc/audit/ops-metrics/errors`
- `GET /svc/audit/ops-metrics/latency`
- `GET /svc/audit/ops-metrics/overview`
- `GET /svc/audit/ops-metrics/timeseries`
- `GET /svc/audit/webhooks`
- `POST /svc/audit/webhooks`
- `DELETE /svc/audit/webhooks/{id}`
- `PATCH /svc/audit/webhooks/{id}`
- `GET /svc/audit/webhooks/{id}/deliveries`
- `POST /svc/audit/webhooks/{id}/test`

### auth (`/svc/auth/`)

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
- `POST /svc/auth/auth/delegated/api-keys/{id}/revoke`
- `POST /svc/auth/auth/delegated/authority`
- `POST /svc/auth/auth/delegated/clients/{id}/revoke`
- `POST /svc/auth/auth/delegated/users/{id}/disable`
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
- `GET /svc/auth/internal/tenant-ids`
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
- `GET /svc/certs/certs/edge-tls`
- `PUT /svc/certs/certs/edge-tls`
- `PUT /svc/certs/certs/edge-tls/certificate`
- `POST /svc/certs/certs/edge-tls/certificate/install`
- `POST /svc/certs/certs/edge-tls/csr`
- `GET /svc/certs/certs/edge-tls/measurement`
- `GET /svc/certs/certs/internal-mtls`
- `POST /svc/certs/certs/internal-mtls/rotate-all`
- `PUT /svc/certs/certs/internal-mtls/{identity}/policy`
- `POST /svc/certs/certs/internal-mtls/{identity}/rotate`
- `GET /svc/certs/certs/inventory`
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
- `POST /svc/compliance/compliance/connections/import`
- `POST /svc/compliance/compliance/connections/{id}/resolve`
- `GET /svc/compliance/compliance/evidence/export`
- `GET /svc/compliance/compliance/frameworks`
- `GET /svc/compliance/compliance/frameworks/{id}/controls`
- `GET /svc/compliance/compliance/frameworks/{id}/gaps`
- `GET /svc/compliance/compliance/keys/expired`
- `GET /svc/compliance/compliance/keys/hygiene`
- `GET /svc/compliance/compliance/keys/orphaned`
- `GET /svc/compliance/compliance/playbook-runs`
- `GET /svc/compliance/compliance/playbook-runs/{run_id}`
- `POST /svc/compliance/compliance/playbook-runs/{run_id}/cancel`
- `POST /svc/compliance/compliance/playbook-runs/{run_id}/retry`
- `GET /svc/compliance/compliance/playbooks`
- `POST /svc/compliance/compliance/playbooks`
- `GET /svc/compliance/compliance/playbooks/catalog`
- `GET /svc/compliance/compliance/playbooks/connections`
- `POST /svc/compliance/compliance/playbooks/connections`
- `DELETE /svc/compliance/compliance/playbooks/connections/{id}`
- `PUT /svc/compliance/compliance/playbooks/connections/{id}`
- `POST /svc/compliance/compliance/playbooks/connections/{id}/test`
- `GET /svc/compliance/compliance/playbooks/summary`
- `DELETE /svc/compliance/compliance/playbooks/{id}`
- `GET /svc/compliance/compliance/playbooks/{id}`
- `PUT /svc/compliance/compliance/playbooks/{id}`
- `POST /svc/compliance/compliance/playbooks/{id}/dry-run`
- `POST /svc/compliance/compliance/playbooks/{id}/run`
- `GET /svc/compliance/compliance/playbooks/{id}/runs`
- `GET /svc/compliance/compliance/posture`
- `GET /svc/compliance/compliance/posture/breakdown`
- `GET /svc/compliance/compliance/posture/history`
- `GET /svc/compliance/compliance/risk/keys`
- `GET /svc/compliance/compliance/risk/remediation`
- `GET /svc/compliance/compliance/risk/summary`
- `GET /svc/compliance/compliance/templates`
- `POST /svc/compliance/compliance/templates`
- `DELETE /svc/compliance/compliance/templates/{id}`
- `GET /svc/compliance/compliance/templates/{id}`

### confidential (`/svc/confidential/`)

- `POST /svc/confidential/confidential/evaluate`
- `GET /svc/confidential/confidential/policy`
- `PUT /svc/confidential/confidential/policy`
- `POST /svc/confidential/confidential/release`
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
- `DELETE /svc/discovery/discovery/assets/{id}`
- `GET /svc/discovery/discovery/assets/{id}`
- `PUT /svc/discovery/discovery/assets/{id}/classify`
- `GET /svc/discovery/discovery/crypto/assets`
- `GET /svc/discovery/discovery/repositories`
- `POST /svc/discovery/discovery/repositories`
- `DELETE /svc/discovery/discovery/repositories/{id}`
- `POST /svc/discovery/discovery/repositories/{id}/test`
- `POST /svc/discovery/discovery/scan`
- `GET /svc/discovery/discovery/scans`
- `GET /svc/discovery/discovery/scans/{id}`
- `GET /svc/discovery/discovery/schedule`
- `PUT /svc/discovery/discovery/schedule`
- `GET /svc/discovery/discovery/sources`
- `GET /svc/discovery/discovery/summary`
- `GET /svc/discovery/discovery/targets`
- `POST /svc/discovery/discovery/targets`
- `DELETE /svc/discovery/discovery/targets/{id}`
- `POST /svc/discovery/discovery/upload`

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
- `POST /svc/governance/governance/notify/email`
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
- `GET /svc/keycore/access/settings`
- `PUT /svc/keycore/access/settings`
- `GET /svc/keycore/agility/algorithms`
- `GET /svc/keycore/agility/caraf/assessment`
- `GET /svc/keycore/agility/caraf/assets`
- `POST /svc/keycore/agility/caraf/assets`
- `DELETE /svc/keycore/agility/caraf/assets/{id}`
- `PUT /svc/keycore/agility/caraf/assets/{id}`
- `PUT /svc/keycore/agility/caraf/assets/{id}/decision`
- `GET /svc/keycore/agility/caraf/threats`
- `POST /svc/keycore/agility/caraf/threats`
- `DELETE /svc/keycore/agility/caraf/threats/{id}`
- `PUT /svc/keycore/agility/caraf/threats/{id}`
- `GET /svc/keycore/agility/drills`
- `POST /svc/keycore/agility/drills`
- `GET /svc/keycore/agility/keys-by-algorithm`
- `GET /svc/keycore/agility/policy/rules`
- `POST /svc/keycore/agility/policy/rules`
- `DELETE /svc/keycore/agility/policy/rules/{id}`
- `PUT /svc/keycore/agility/policy/rules/{id}`
- `GET /svc/keycore/agility/posture`
- `GET /svc/keycore/analytics/algorithms`
- `GET /svc/keycore/analytics/hotspots`
- `POST /svc/keycore/analytics/metrics`
- `GET /svc/keycore/analytics/trends`
- `GET /svc/keycore/analytics/usage`
- `GET /svc/keycore/attestation/public-key`
- `GET /svc/keycore/canary/keys`
- `POST /svc/keycore/canary/keys`
- `DELETE /svc/keycore/canary/keys/{id}`
- `GET /svc/keycore/canary/keys/{id}/trips`
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
- `POST /svc/keycore/crypto/hash`
- `POST /svc/keycore/crypto/random`
- `POST /svc/keycore/enterprise/advanced-encryption/modes`
- `POST /svc/keycore/enterprise/advanced-encryption/search-token`
- `POST /svc/keycore/enterprise/anomaly/scan`
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
- `POST /svc/keycore/keys/{id}/attest`
- `POST /svc/keycore/keys/{id}/attested-release`
- `GET /svc/keycore/keys/{id}/consumers`
- `POST /svc/keycore/keys/{id}/deactivate`
- `POST /svc/keycore/keys/{id}/decrypt`
- `POST /svc/keycore/keys/{id}/derive`
- `POST /svc/keycore/keys/{id}/destroy`
- `POST /svc/keycore/keys/{id}/destruction-check`
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
- `GET /svc/keycore/keys/{id}/public-key`
- `POST /svc/keycore/keys/{id}/rewrap`
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
- `GET /svc/keycore/rotation/analytics`
- `GET /svc/keycore/rotation/analytics/overdue`
- `GET /svc/keycore/rotation/cryptoperiods`
- `DELETE /svc/keycore/rotation/cryptoperiods/{category}`
- `PUT /svc/keycore/rotation/cryptoperiods/{category}`
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

### kmip (`/svc/kmip/`)

- `GET /svc/kmip/kmip/capabilities`
- `GET /svc/kmip/kmip/clients`
- `POST /svc/kmip/kmip/clients`
- `DELETE /svc/kmip/kmip/clients/{id}`
- `GET /svc/kmip/kmip/clients/{id}`
- `GET /svc/kmip/kmip/interop/targets`
- `POST /svc/kmip/kmip/interop/targets`
- `DELETE /svc/kmip/kmip/interop/targets/{id}`
- `POST /svc/kmip/kmip/interop/targets/{id}/validate`
- `GET /svc/kmip/kmip/profiles`
- `POST /svc/kmip/kmip/profiles`
- `DELETE /svc/kmip/kmip/profiles/{id}`

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

- `GET /svc/posture/posture/actions`
- `POST /svc/posture/posture/actions/{id}/execute`
- `GET /svc/posture/posture/baseline`
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
- `GET /svc/pqc/pqc/readiness`
- `POST /svc/pqc/pqc/scan`
- `GET /svc/pqc/pqc/scans`
- `GET /svc/pqc/pqc/scans/{id}`
- `GET /svc/pqc/pqc/timeline`

### reconciler (`/svc/reconciler/`)

- `GET /svc/reconciler/reconciler/status`

### reporting (`/svc/reporting/`)

- `GET /svc/reporting/alerts`
- `POST /svc/reporting/alerts/bulk/acknowledge`
- `POST /svc/reporting/alerts/bulk/resolve`
- `GET /svc/reporting/alerts/channels`
- `PUT /svc/reporting/alerts/channels`
- `GET /svc/reporting/alerts/feed`
- `GET /svc/reporting/alerts/rules`
- `POST /svc/reporting/alerts/rules`
- `POST /svc/reporting/alerts/rules/test`
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
- `PUT /svc/reporting/alerts/{id}/{op}`
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
- `GET /svc/sbom/sbom/diff`
- `POST /svc/sbom/sbom/generate`
- `GET /svc/sbom/sbom/history`
- `GET /svc/sbom/sbom/latest`
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

### watchdog (`/svc/watchdog/`)

- `GET /svc/watchdog/watchdog/heartbeats`
- `GET /svc/watchdog/watchdog/incidents`

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
- `POST /svc/workload/workload-identity/settings/rotate-signing-keys`
- `GET /svc/workload/workload-identity/summary`
- `POST /svc/workload/workload-identity/token/exchange`
- `GET /svc/workload/workload-identity/usage`

<!-- route-index:end -->
