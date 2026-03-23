# Vecta KMS Administration Guide

This guide is the definitive operational reference for platform administrators responsible for deploying, configuring, and maintaining Vecta KMS. It covers every administrative surface: authentication, session management, user and tenant lifecycle, identity providers, SCIM provisioning, API client management, system health monitoring, FIPS mode, network configuration, and dashboard navigation.

---

## Table of Contents

1. [Overview and Admin Philosophy](#1-overview-and-admin-philosophy)
2. [Authentication and Session Management](#2-authentication-and-session-management)
3. [Password and Security Policies](#3-password-and-security-policies)
4. [User Management](#4-user-management)
5. [Tenant Management](#5-tenant-management)
6. [Identity Providers](#6-identity-providers)
7. [SCIM 2.0 Provisioning](#7-scim-20-provisioning)
8. [API Client Management](#8-api-client-management)
9. [System Health Monitoring](#9-system-health-monitoring)
10. [FIPS Mode](#10-fips-mode)
11. [Network Configuration](#11-network-configuration)
12. [Dashboard UI Navigation](#12-dashboard-ui-navigation)
13. [Day 0 Checklist](#13-day-0-checklist)
14. [Day 1 Operations](#14-day-1-operations)
15. [Day 2 Hardening](#15-day-2-hardening)
16. [Troubleshooting Quick Reference](#16-troubleshooting-quick-reference)

---

## 1. Overview and Admin Philosophy

Vecta KMS is a control plane — not a single key store. Administration is the practice of setting policy, configuring boundaries, provisioning access, and ensuring the platform operates within declared constraints. Every administrative action should be visible in Audit, intentional, and reversible where possible.

### Core Administrative Principles

| Principle | Meaning |
|---|---|
| Least privilege | Users and clients receive the minimum role needed. Escalate via role change, not shared credentials. |
| Tenant isolation | Data, tokens, and configuration do not leak across tenant boundaries. Always scope admin actions to the correct tenant. |
| Audit visibility | Every sensitive change emits an audit event. Treat the Audit Log as your primary accountability surface. |
| Governance before disruption | Disabling tenants, deleting tenants, and toggling FIPS mode require governance approval. Do not bypass the workflow. |
| Prefer SCIM over manual | If an IdP owns identity lifecycle, configure SCIM and let the directory be the source of truth. Do not mirror lifecycle manually. |

### Who This Guide Is For

- **Platform administrators** who own the KMS installation and are responsible for tenant and user lifecycle, service health, and security posture.
- **Security architects** who need to understand what each configuration field controls and what the security implications are.
- **Automation engineers** who need to call admin APIs programmatically rather than through the dashboard.

### Dashboard vs API

Every action in this guide can be performed either through the dashboard or through the REST API. The dashboard proxies all calls through `/svc/<service>/...` routes. The API examples in this guide use the same proxied paths, so they work directly from a browser developer console or automation scripts pointing at the dashboard host.

```
Dashboard URL:  http://<host>:5173/
API base:       http://<host>:5173/svc/
```

> **Note:** In production environments the dashboard should be served over HTTPS. The HTTP default is appropriate only for local or airgapped lab deployments.

---

## 2. Authentication and Session Management

All human and machine identities must authenticate through the `auth` service before calling any other service. The auth service is the single source of JWT issuance for the platform.

### 2.1 Token Architecture

Vecta KMS uses a dual-token model:

| Token | Lifetime | Purpose |
|---|---|---|
| Access token (JWT) | 15 minutes | Presented on every API call in `Authorization: Bearer <token>` |
| Refresh token | Configurable | Used to obtain new access tokens without re-entering credentials |

The access token is a signed JWT and contains:
- `sub`: user ID
- `tenant_id`: tenant scope
- `role`: the user's current role
- `exp`: expiry timestamp
- `jti`: unique token identifier for replay tracking

> **Warning:** Access tokens are short-lived by design. Any automation that stores an access token and does not implement refresh logic will fail after 15 minutes. Always implement refresh in long-running processes.

### 2.2 Login

```
POST /svc/auth/auth/login
Content-Type: application/json

{
  "username": "admin@example.com",
  "password": "S3cur3P@ssword!",
  "tenant_id": "root"
}
```

The `tenant_id` field is optional when the user exists in only one tenant. When a user is provisioned across multiple tenants, `tenant_id` must be provided to disambiguate.

**Successful response:**

```json
{
  "access_token": "eyJhbGci...",
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2g...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "usr_01HXYZ",
    "username": "admin@example.com",
    "role": "admin",
    "must_change_password": false
  }
}
```

**cURL example:**

```bash
curl -s -X POST http://localhost:5173/svc/auth/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin@example.com",
    "password": "S3cur3P@ssword!",
    "tenant_id": "root"
  }' | jq .
```

**Error conditions:**

| HTTP Status | Meaning |
|---|---|
| 400 | Missing or malformed body |
| 401 | Invalid credentials |
| 403 | Account locked or suspended |
| 404 | Tenant not found |
| 429 | Too many failed attempts — lockout active |

### 2.3 Token Refresh

When the access token is about to expire, use the refresh token to obtain a new access token without re-authenticating with a password.

```
POST /svc/auth/auth/refresh
Content-Type: application/json

{
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2g..."
}
```

**cURL example:**

```bash
REFRESH_TOKEN="dGhpcyBpcyBhIHJlZnJlc2g..."

curl -s -X POST http://localhost:5173/svc/auth/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"${REFRESH_TOKEN}\"}" | jq .
```

The response contains a new `access_token` and optionally a rotated `refresh_token`.

> **Best practice:** Implement refresh logic so that refresh fires when the access token has less than 60 seconds remaining. Do not wait for a 401 response to trigger a refresh — the round trip adds unnecessary latency.

### 2.4 Logout

```
POST /svc/auth/auth/logout
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2g..."
}
```

Logout invalidates the refresh token server-side. The access token remains cryptographically valid until its `exp` is reached, but the session is considered ended. The platform's idle timeout will also trigger implicit session termination (see Section 3.2).

**cURL example:**

```bash
TOKEN="eyJhbGci..."
REFRESH_TOKEN="dGhpcyBpcyBhIHJlZnJlc2g..."

curl -s -X POST http://localhost:5173/svc/auth/auth/logout \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"${REFRESH_TOKEN}\"}"
```

### 2.5 Single Sign-On (SSO)

Vecta KMS supports SSO through multiple identity provider types. The SSO flow is browser-redirect based and begins by discovering available providers for a tenant.

#### Listing Available SSO Providers

```
GET /svc/auth/auth/sso/providers?tenant_id=root
Authorization: Bearer <access_token>
```

**Response:**

```json
{
  "providers": [
    {
      "id": "entra",
      "name": "Azure Entra ID",
      "enabled": true,
      "protocol": "oidc"
    },
    {
      "id": "okta",
      "name": "Okta",
      "enabled": true,
      "protocol": "oidc"
    }
  ]
}
```

#### Initiating SSO Login

```
GET /svc/auth/auth/sso/{provider}/login?tenant_id=root
```

This endpoint redirects the browser to the identity provider's authentication page. After successful authentication, the IdP redirects back to KMS with an authorization code or SAML assertion, which KMS exchanges for an access and refresh token pair.

**Supported SSO providers:**

| Provider ID | Protocol | Notes |
|---|---|---|
| `ad` | Active Directory FS (SAML/WS-Fed) | On-premises AD FS deployments |
| `entra` | Azure Entra ID (OIDC) | Microsoft cloud identity — preferred for M365 environments |
| `okta` | Okta (OIDC) | Okta-managed identity estates |
| `oidc` | Generic OIDC | Any standards-compliant OIDC provider |
| `saml` | Generic SAML 2.0 | Any standards-compliant SAML 2.0 IdP |

> **Note:** SSO providers are configured per-tenant. A tenant may have multiple providers enabled simultaneously. The login page will present all enabled providers for selection.

---

## 3. Password and Security Policies

Password and security policies are configured per-tenant and control the complexity requirements for local credentials as well as the account protection thresholds for failed attempts and idle sessions.

### 3.1 Password Policy Fields

The password policy governs what constitutes an acceptable password when users set or reset local KMS credentials.

| Field | Type | Range | Description |
|---|---|---|---|
| `min_length` | integer | 8–128 | Minimum character count. Values below 8 are rejected. NIST SP 800-63B recommends at least 8; for privileged accounts, prefer 16 or higher. |
| `max_length` | integer | — | Maximum character count. Useful when downstream systems have length limits, but generally should not be set below 64. |
| `require_upper` | boolean | — | At least one uppercase letter (A–Z) must be present. |
| `require_lower` | boolean | — | At least one lowercase letter (a–z) must be present. |
| `require_digit` | boolean | — | At least one numeric digit (0–9) must be present. |
| `require_special` | boolean | — | At least one special character must be present. |
| `require_no_whitespace` | boolean | — | Password must not contain space, tab, or other whitespace characters. |
| `deny_username` | boolean | — | Password must not contain the user's own username as a substring. |
| `deny_email_local_part` | boolean | — | Password must not contain the local part (before `@`) of the user's email address. |
| `min_unique_chars` | integer | — | Minimum number of unique characters in the password. Prevents single-character repetition attacks. |

**Example: Retrieve the current password policy**

```bash
TOKEN="eyJhbGci..."

curl -s http://localhost:5173/svc/auth/auth/policy/password?tenant_id=root \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

**Example: Update the password policy**

```bash
curl -s -X PUT http://localhost:5173/svc/auth/auth/policy/password \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "min_length": 14,
    "max_length": 128,
    "require_upper": true,
    "require_lower": true,
    "require_digit": true,
    "require_special": true,
    "require_no_whitespace": true,
    "deny_username": true,
    "deny_email_local_part": true,
    "min_unique_chars": 8
  }'
```

> **Warning:** Changes to the password policy do not retroactively invalidate existing passwords. Users are only evaluated against the new policy when they next set or change their password. If you need to enforce the new policy immediately, trigger a forced password reset for all users.

### 3.2 Security Policy Fields

The security policy controls account lockout behavior and idle session termination.

| Field | Type | Range | Description |
|---|---|---|---|
| `max_failed_attempts` | integer | 3–10 | Number of consecutive failed login attempts before the account is locked. Recommended: 5 for most environments, 3 for privileged admin accounts. |
| `lockout_minutes` | integer | 5–1440 | Duration in minutes before a locked account can attempt login again. 1440 minutes = 24 hours. |
| `idle_timeout_minutes` | integer | 5–480 | Minutes of inactivity before the dashboard session is terminated. 480 minutes = 8 hours. |

**Example: Configure security policy**

```bash
curl -s -X PUT http://localhost:5173/svc/auth/auth/policy/security \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "max_failed_attempts": 5,
    "lockout_minutes": 30,
    "idle_timeout_minutes": 60
  }'
```

**Policy design recommendations:**

| Scenario | max_failed_attempts | lockout_minutes | idle_timeout_minutes |
|---|---|---|---|
| General enterprise use | 5 | 30 | 60 |
| High-security / privileged | 3 | 60 | 15 |
| Lab / development | 10 | 5 | 480 |
| Compliance-driven (PCI-DSS) | 6 | 30 | 15 |

> **Note:** Account lockouts do not affect refresh token validity. A locked user who still has a valid refresh token can continue to obtain new access tokens until the refresh token expires or is explicitly invalidated. To fully terminate a session, use the user status update API to set `status: locked` AND revoke refresh tokens.

---

## 4. User Management

Users in Vecta KMS are scoped to a tenant. A user record in one tenant is completely independent of a record with the same email in another tenant. There is no global user identity that spans tenants.

### 4.1 The AuthUser Model

| Field | Type | Values / Notes |
|---|---|---|
| `id` | string | Platform-generated unique ID. Immutable after creation. |
| `tenant_id` | string | Tenant this user belongs to. |
| `username` | string | Login name. Typically email format. Must be unique within the tenant. |
| `email` | string | Email address. Used for password reset communications. |
| `role` | enum | `admin`, `operator`, `viewer`, `auditor` |
| `status` | enum | `active`, `locked`, `suspended` |
| `must_change_password` | boolean | When `true`, the user is forced to set a new password on next login. |

### 4.2 Roles and Permissions

| Role | Capabilities |
|---|---|
| `admin` | Full platform control: create/delete users, create/delete tenants, manage all keys and certificates, configure policies, approve governance actions, manage SCIM and IdP settings, view all audit data. |
| `operator` | Key and certificate operations: create, rotate, retire, and use keys; issue and renew certificates; manage interface configurations. Cannot create or delete users, cannot modify tenant settings. |
| `viewer` | Read-only access to all non-sensitive configuration and operational state. Cannot perform any write or cryptographic operation. Suitable for monitoring dashboards and read-only observers. |
| `auditor` | Read-only access to audit logs, compliance assessments, and posture findings. Cannot view raw key material. Focused on accountability and regulatory evidence functions. |

> **Best practice:** Assign the `auditor` role to compliance officers and external assessors. Do not give auditors the `viewer` role — `viewer` exposes more operational configuration than an auditor typically needs. Reserve `admin` for a small number of named individuals who own the platform.

### 4.3 Listing Users

```
GET /svc/auth/auth/users?tenant_id=root
Authorization: Bearer <access_token>
```

**cURL example:**

```bash
curl -s "http://localhost:5173/svc/auth/auth/users?tenant_id=root" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

**Response shape:**

```json
{
  "users": [
    {
      "id": "usr_01HXYZ",
      "tenant_id": "root",
      "username": "admin@example.com",
      "email": "admin@example.com",
      "role": "admin",
      "status": "active",
      "must_change_password": false
    },
    {
      "id": "usr_02HABC",
      "tenant_id": "root",
      "username": "operator1@example.com",
      "email": "operator1@example.com",
      "role": "operator",
      "status": "active",
      "must_change_password": true
    }
  ],
  "total": 2
}
```

### 4.4 Creating a User

```
POST /svc/auth/auth/users
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "tenant_id": "root",
  "username": "new.operator@example.com",
  "email": "new.operator@example.com",
  "password": "Temp@12345!",
  "role": "operator",
  "must_change_password": true
}
```

**cURL example:**

```bash
curl -s -X POST http://localhost:5173/svc/auth/auth/users \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "username": "new.operator@example.com",
    "email": "new.operator@example.com",
    "password": "Temp@12345!",
    "role": "operator",
    "must_change_password": true
  }' | jq .
```

Setting `must_change_password: true` forces the user to set their own password immediately after first login. This is the recommended pattern when an administrator creates an account on someone else's behalf — the admin sets a temporary password and the user replaces it.

**User creation checklist:**

- [ ] Username follows the tenant's naming convention
- [ ] Role matches the minimum needed for the user's function
- [ ] `must_change_password` is set to `true` for new accounts
- [ ] The temporary password satisfies the current password policy
- [ ] The new user is notified of their credentials through a secure channel

### 4.5 Changing a User's Role

```
PUT /svc/auth/auth/users/{id}/role
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "role": "viewer"
}
```

**cURL example:**

```bash
USER_ID="usr_02HABC"

curl -s -X PUT "http://localhost:5173/svc/auth/auth/users/${USER_ID}/role" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"role": "viewer"}' | jq .
```

> **Warning:** Role changes take effect on the user's next token issue. An existing access token will retain the old role until it expires (up to 15 minutes). If an immediate role downgrade is required, also revoke the user's active sessions.

### 4.6 Locking and Unlocking a User

Use the status endpoint to lock a user account (preventing login) or to unlock a previously locked account.

```
PUT /svc/auth/auth/users/{id}/status
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "status": "locked"
}
```

| Status value | Effect |
|---|---|
| `active` | User can log in normally. |
| `locked` | User cannot log in. Existing sessions remain valid until token expiry. |
| `suspended` | User cannot log in. Intended for longer-term administrative holds pending investigation or offboarding. |

**Lock a user immediately:**

```bash
curl -s -X PUT "http://localhost:5173/svc/auth/auth/users/${USER_ID}/status" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"status": "locked"}'
```

**Unlock a user:**

```bash
curl -s -X PUT "http://localhost:5173/svc/auth/auth/users/${USER_ID}/status" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"status": "active"}'
```

> **Note:** Accounts locked by the automated lockout policy (exceeded `max_failed_attempts`) are unlocked in the same way — either by an admin changing status back to `active`, or automatically when the `lockout_minutes` duration elapses.

### 4.7 Admin-Initiated Password Reset

Administrators can force a password reset for any user in their tenant without knowing the user's current password.

```
POST /svc/auth/auth/users/{id}/reset-password
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "new_password": "Temp@Reset99!",
  "must_change_password": true
}
```

**cURL example:**

```bash
curl -s -X POST "http://localhost:5173/svc/auth/auth/users/${USER_ID}/reset-password" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "new_password": "Temp@Reset99!",
    "must_change_password": true
  }' | jq .
```

**Incident response password reset flow:**

1. Lock the account immediately: `PUT /users/{id}/status` → `{"status": "locked"}`
2. Investigate the audit log for the account's recent activity.
3. When satisfied the account is safe, reset the password: `POST /users/{id}/reset-password`
4. Restore account to active: `PUT /users/{id}/status` → `{"status": "active"}`
5. Communicate the temporary password to the user securely.
6. Confirm the user completes the forced password change on next login.

### 4.8 Dashboard: User Management

**Navigation path:** `Admin → User Admin → Users`

The Users pane shows:
- A searchable table of all users in the current tenant
- Status indicators (active/locked/suspended) with color coding
- Role badges
- Last login time
- Quick actions: Edit Role, Lock/Unlock, Reset Password

**Creating a user through the dashboard:**
1. Click `New User` in the top-right corner of the Users pane.
2. Fill in username, email, role, and a temporary password.
3. Check `Force password change on first login`.
4. Click `Create`.
5. Securely communicate credentials to the new user.

---

## 5. Tenant Management

Multi-tenancy is a first-class concept in Vecta KMS. Each tenant is a fully isolated logical partition with its own:

- User directory
- Key inventory
- Certificate inventory
- Policy configuration
- Audit trail
- SCIM settings and provisioned identity state
- SSO and IdP bindings
- API clients

### 5.1 The AuthTenant Model

| Field | Type | Values / Notes |
|---|---|---|
| `id` | string | Platform-generated unique ID. Immutable. |
| `name` | string | Human-readable tenant name. Used in the dashboard. |
| `status` | enum | `active`, `disabled`, `suspended` |
| `created_at` | timestamp | ISO 8601 creation timestamp. |

### 5.2 Tenant Isolation Guarantees

| Boundary | Guarantee |
|---|---|
| Keys | Keys in tenant A are never accessible from tenant B |
| Users | User accounts are scoped to a single tenant |
| Tokens | JWTs are tenant-scoped and will be rejected if presented against a different tenant's resources |
| Configuration | Password policy, security policy, IdP settings, and SCIM settings are independent per tenant |
| Audit | Audit events are partitioned by tenant. Tenant A's admin cannot read tenant B's audit log |
| SCIM | Each tenant maintains its own SCIM token, settings, and managed user/group state |

### 5.3 Listing Tenants

Only users with the `admin` role can list tenants. This operation is scoped to the platform level, not a specific tenant.

```
GET /svc/auth/tenants
Authorization: Bearer <access_token>
```

**cURL example:**

```bash
curl -s http://localhost:5173/svc/auth/tenants \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

**Response:**

```json
{
  "tenants": [
    {
      "id": "root",
      "name": "Root Tenant",
      "status": "active",
      "created_at": "2025-01-15T09:00:00Z"
    },
    {
      "id": "tenant_finance",
      "name": "Finance Operations",
      "status": "active",
      "created_at": "2025-03-01T14:30:00Z"
    }
  ]
}
```

### 5.4 Creating a Tenant

```
POST /svc/auth/tenants
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "Engineering Platform"
}
```

**cURL example:**

```bash
curl -s -X POST http://localhost:5173/svc/auth/tenants \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name": "Engineering Platform"}' | jq .
```

After creation, the response includes the new tenant's ID. Use this ID when creating users, configuring IdPs, and calling any tenant-scoped API.

**Post-creation checklist:**
- [ ] Create at least one `admin` user in the new tenant
- [ ] Configure the password and security policy
- [ ] If using SSO: configure the identity provider for the tenant
- [ ] If using SCIM: configure SCIM provisioning and issue the token to the IdP
- [ ] Create initial keys if the tenant team needs them immediately
- [ ] Confirm the Audit Log shows the tenant creation event

### 5.5 Updating a Tenant

```
PUT /svc/auth/tenants/{id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "Engineering Platform - Production"
}
```

**cURL example:**

```bash
TENANT_ID="tenant_engineering"

curl -s -X PUT "http://localhost:5173/svc/auth/tenants/${TENANT_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name": "Engineering Platform - Production"}' | jq .
```

### 5.6 Disabling a Tenant

Disabling a tenant prevents all users in that tenant from logging in and suspends all service-to-service calls that carry tenant-scoped tokens. This is a significant operational action and requires governance approval.

```
POST /svc/auth/tenants/{id}/disable
Authorization: Bearer <access_token>
```

> **Warning:** Disabling a tenant does not delete any data. Keys, certificates, audit logs, and configuration are preserved. However, all users in the tenant will be unable to authenticate until the tenant is re-enabled. Applications using that tenant's API clients will also lose access.

The governance approval flow for tenant disable:
1. Admin calls `POST /svc/auth/tenants/{id}/disable`.
2. A governance approval request is created.
3. A second authorized admin reviews and approves the request in `Governance → Approval Requests`.
4. The platform executes the disable action.
5. An audit event is emitted recording both the requester and approver.

### 5.7 Deleting a Tenant

Tenant deletion is irreversible and requires both a governance approval and a successful readiness check.

#### Step 1: Check Delete Readiness

```
GET /svc/auth/tenants/{id}/delete-readiness
Authorization: Bearer <access_token>
```

**cURL example:**

```bash
curl -s "http://localhost:5173/svc/auth/tenants/${TENANT_ID}/delete-readiness" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

**Response:**

```json
{
  "tenant_id": "tenant_engineering",
  "ready_to_delete": false,
  "blockers": [
    {
      "type": "active_sessions",
      "count": 3,
      "description": "3 active user sessions exist. Sessions must be terminated before deletion."
    },
    {
      "type": "service_links",
      "count": 2,
      "description": "2 registered API clients still reference this tenant."
    },
    {
      "type": "active_keys",
      "count": 47,
      "description": "47 active keys would be permanently deleted. Back up any key material needed for future decryption."
    }
  ]
}
```

The readiness check evaluates:
- **Active sessions:** Users currently logged in
- **Service links:** Registered API clients and SCIM connectors
- **Active keys:** Keys that would be permanently destroyed
- **Active certificates:** Unexpired certificates that would become invalid
- **Pending governance requests:** Approval requests still in flight for this tenant

#### Step 2: Resolve All Blockers

For each blocker:
- **Active sessions:** Wait for natural expiry or force-expire refresh tokens.
- **Service links:** Deregister or revoke API clients. Disable SCIM.
- **Active keys:** Confirm with the application team that no future decryption operations are needed. Back up exported key material if required.

#### Step 3: Submit Deletion Request

```
DELETE /svc/auth/tenants/{id}
Authorization: Bearer <access_token>
```

This creates a governance approval request. After approval, the platform permanently destroys all tenant data.

> **Warning:** Tenant deletion is permanent and irreversible. Key material stored exclusively in Vecta KMS for this tenant will be permanently lost. Ensure a backup exists for any data encrypted under tenant keys before proceeding.

### 5.8 Dashboard: Tenant Management

**Navigation path:** `Admin → Tenant Admin`

The Tenant Admin pane shows:
- All tenants with status indicators
- Creation timestamps
- Quick actions: Edit Name, Disable, Delete Readiness Check
- A `New Tenant` button in the top-right

---

## 6. Identity Providers

Identity providers (IdPs) allow users to authenticate to Vecta KMS using their existing enterprise directory credentials rather than maintaining a separate KMS-local password. IdPs are configured per-tenant.

### 6.1 Supported Identity Providers

| Provider ID | Protocol | Best For |
|---|---|---|
| `ad` | Active Directory FS (SAML/WS-Fed) | On-premises Windows environments with AD FS infrastructure |
| `entra` | Azure Entra ID (OIDC) | Microsoft cloud identity, M365 environments |
| `saml` | Generic SAML 2.0 | Any IdP that exposes a SAML 2.0 endpoint (Ping, Shibboleth, etc.) |
| `oidc` | Generic OIDC | Any OIDC-compliant provider (Keycloak, Auth0, etc.) |
| `ldap` | Generic LDAP | On-premises LDAP directories (OpenLDAP, FreeIPA, etc.) |

### 6.2 Listing Configured Providers

```
GET /svc/auth/auth/identity/providers?tenant_id=root
Authorization: Bearer <access_token>
```

**cURL example:**

```bash
curl -s "http://localhost:5173/svc/auth/auth/identity/providers?tenant_id=root" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

### 6.3 Configuring a Provider

```
PUT /svc/auth/auth/identity/providers/{provider}
Authorization: Bearer <access_token>
Content-Type: application/json
```

The configuration body varies by provider type. Common fields appear across all types; protocol-specific fields are noted below.

#### Active Directory / Generic LDAP Configuration

```json
{
  "tenant_id": "root",
  "enabled": true,
  "config": {
    "server": "ldap://dc01.corp.example.com",
    "base_dn": "DC=corp,DC=example,DC=com",
    "bind_dn": "CN=kms-svc,OU=Service Accounts,DC=corp,DC=example,DC=com",
    "bind_password": "svc_account_password",
    "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
    "group_filter": "(&(objectClass=group)(member={dn}))",
    "user_attr_username": "sAMAccountName",
    "user_attr_email": "mail",
    "user_attr_display_name": "displayName",
    "tls_enabled": true,
    "tls_skip_verify": false
  }
}
```

**cURL example for AD:**

```bash
curl -s -X PUT http://localhost:5173/svc/auth/auth/identity/providers/ad \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "enabled": true,
    "config": {
      "server": "ldap://dc01.corp.example.com",
      "base_dn": "DC=corp,DC=example,DC=com",
      "bind_dn": "CN=kms-svc,OU=Service Accounts,DC=corp,DC=example,DC=com",
      "bind_password": "svc_account_password",
      "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
      "group_filter": "(&(objectClass=group)(member={dn}))"
    }
  }' | jq .
```

#### Azure Entra ID Configuration

```json
{
  "tenant_id": "root",
  "enabled": true,
  "config": {
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "your_client_secret",
    "tenant_id_azure": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "redirect_uri": "https://kms.example.com/svc/auth/auth/sso/entra/callback",
    "scopes": ["openid", "profile", "email", "offline_access"]
  }
}
```

#### Okta Configuration

```json
{
  "tenant_id": "root",
  "enabled": true,
  "config": {
    "issuer": "https://your-org.okta.com/oauth2/default",
    "client_id": "0oa1234567890abcdef",
    "client_secret": "your_client_secret",
    "redirect_uri": "https://kms.example.com/svc/auth/auth/sso/oidc/callback",
    "scopes": ["openid", "profile", "email", "offline_access"]
  }
}
```

#### Generic SAML 2.0 Configuration

```json
{
  "tenant_id": "root",
  "enabled": true,
  "config": {
    "idp_entity_id": "https://idp.example.com/saml/metadata",
    "idp_sso_url": "https://idp.example.com/saml/sso",
    "idp_certificate": "MIIDxTCC...base64cert...",
    "sp_entity_id": "https://kms.example.com/saml/metadata",
    "sp_acs_url": "https://kms.example.com/svc/auth/auth/sso/saml/callback",
    "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "attribute_username": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
    "attribute_email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
  }
}
```

### 6.4 Testing a Provider Configuration

Before enabling an IdP in production, test the configuration to confirm connectivity and credential binding work correctly.

```
POST /svc/auth/auth/identity/providers/{provider}/test
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "tenant_id": "root",
  "test_username": "testuser@example.com",
  "test_password": "test_password"
}
```

**cURL example:**

```bash
curl -s -X POST http://localhost:5173/svc/auth/auth/identity/providers/ad/test \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "test_username": "testuser@corp.example.com",
    "test_password": "test_password"
  }' | jq .
```

A successful test response confirms:
- Directory server is reachable
- Bind credentials are accepted
- User filter returns the test user
- Group filter returns the user's groups
- Attribute mappings are resolved correctly

### 6.5 Importing Users from an IdP

After configuring an LDAP or AD provider, you can import user records from the directory into the KMS tenant. This is useful for initial provisioning before SCIM is configured, or for environments that prefer a batch import model.

```
POST /svc/auth/auth/identity/import/users
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "tenant_id": "root",
  "provider": "ad",
  "group_filter": "CN=KMS-Users,OU=Groups,DC=corp,DC=example,DC=com",
  "default_role": "operator",
  "default_status": "active"
}
```

**cURL example:**

```bash
curl -s -X POST http://localhost:5173/svc/auth/auth/identity/import/users \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "provider": "ad",
    "group_filter": "CN=KMS-Users,OU=Groups,DC=corp,DC=example,DC=com",
    "default_role": "operator",
    "default_status": "active"
  }' | jq .
```

> **Note:** User import is a one-time copy. If the directory changes after the import, those changes are not automatically reflected in KMS. For ongoing synchronization, configure SCIM instead.

### 6.6 Group-to-Role Mappings

Directory groups can be mapped to KMS roles so that a user's KMS role is derived from their group membership in the IdP rather than being set manually per user.

```
PUT /svc/auth/auth/groups/{groupId}/role
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "role_name": "operator"
}
```

**Example: Map the AD group "KMS-Operators" to the operator role:**

```bash
GROUP_ID="CN=KMS-Operators,OU=Groups,DC=corp,DC=example,DC=com"

curl -s -X PUT "http://localhost:5173/svc/auth/auth/groups/${GROUP_ID}/role" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"role_name": "operator"}' | jq .
```

**Group-to-role mapping table example:**

| Directory Group | KMS Role |
|---|---|
| `KMS-Platform-Admins` | `admin` |
| `KMS-Key-Operators` | `operator` |
| `KMS-Readonly-Observers` | `viewer` |
| `KMS-Compliance-Team` | `auditor` |

> **Best practice:** Define group-to-role mappings before importing users or enabling SCIM group push. This way, users arrive in KMS with the correct role automatically rather than landing in a default role that then needs to be adjusted.

---

## 7. SCIM 2.0 Provisioning

SCIM (System for Cross-domain Identity Management) allows an external identity provider to manage the complete lifecycle of users and groups in Vecta KMS automatically. When SCIM is active, the IdP is the authoritative source of truth for who can access KMS and in what role.

### 7.1 The SCIMSettings Model

| Field | Type | Description |
|---|---|---|
| `enabled` | boolean | Whether SCIM provisioning is active for this tenant. |
| `token_prefix` | string | A label identifying the current SCIM token generation (e.g., `scim_2025_03`). |
| `default_role` | enum | Role assigned to newly provisioned users who are not covered by a group-role mapping. |
| `default_status` | enum | Initial status for provisioned users: `active` or a holding state. |
| `deprovision_mode` | enum | `disable` — set user status to locked when deprovisioned. `delete` — permanently remove the user record. |
| `group_role_mappings_enabled` | boolean | Whether directory group membership drives KMS role assignment. |

### 7.2 Getting SCIM Settings

```
GET /svc/auth/auth/scim/settings?tenant_id=root
Authorization: Bearer <access_token>
```

**cURL example:**

```bash
curl -s "http://localhost:5173/svc/auth/auth/scim/settings?tenant_id=root" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

### 7.3 Updating SCIM Settings

```
PUT /svc/auth/auth/scim/settings
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "tenant_id": "root",
  "enabled": true,
  "default_role": "operator",
  "default_status": "active",
  "deprovision_mode": "disable",
  "group_role_mappings_enabled": true
}
```

**cURL example:**

```bash
curl -s -X PUT http://localhost:5173/svc/auth/auth/scim/settings \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "root",
    "enabled": true,
    "default_role": "operator",
    "default_status": "active",
    "deprovision_mode": "disable",
    "group_role_mappings_enabled": true
  }' | jq .
```

### 7.4 SCIM Token Management

The SCIM provisioning token is the bearer token that the IdP presents when making SCIM API calls to KMS. This token is separate from the administrative JWT — it is a long-lived provisioning credential specific to SCIM.

**Initial token issuance and rotation:**

```
POST /svc/auth/auth/scim/settings/rotate-token
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "tenant_id": "root"
}
```

**cURL example:**

```bash
curl -s -X POST http://localhost:5173/svc/auth/auth/scim/settings/rotate-token \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "root"}' | jq .
```

The response includes the new token value. **This is the only time the token is displayed in plaintext.** Copy it immediately and configure it in the IdP before closing the response.

> **Warning:** Rotating the SCIM token immediately invalidates the previous token. The IdP will fail all SCIM operations until you update the IdP configuration with the new token. Coordinate token rotation with IdP configuration updates to avoid a provisioning gap.

**Token rotation schedule recommendation:**

| Scenario | Rotation Frequency |
|---|---|
| Standard enterprise | Quarterly |
| High-security environments | Monthly |
| After suspected exposure | Immediately |
| Staff change (admin who held token) | Immediately |

### 7.5 SCIM Base URL and Endpoints

The SCIM v2 base URL is:

```
https://{host}/svc/auth/scim/v2/
```

The platform implements SCIM 2.0 as defined in RFC 7643 (data model) and RFC 7644 (protocol operations).

**Supported SCIM endpoints:**

| Endpoint | Methods | Description |
|---|---|---|
| `/scim/v2/Users` | GET, POST | List and create users |
| `/scim/v2/Users/{id}` | GET, PUT, PATCH, DELETE | Retrieve, update, or deprovision a user |
| `/scim/v2/Groups` | GET, POST | List and create groups |
| `/scim/v2/Groups/{id}` | GET, PUT, PATCH, DELETE | Retrieve, update, or delete a group |
| `/scim/v2/ServiceProviderConfig` | GET | Capabilities discovery |
| `/scim/v2/Schemas` | GET | Schema discovery |

All SCIM requests must include:
```
Authorization: Bearer <scim_token>
Content-Type: application/scim+json
```

### 7.6 SCIM Summary Statistics

```
GET /svc/auth/auth/scim/summary?tenant_id=root
Authorization: Bearer <access_token>
```

**cURL example:**

```bash
curl -s "http://localhost:5173/svc/auth/auth/scim/summary?tenant_id=root" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

**Response:**

```json
{
  "tenant_id": "root",
  "enabled": true,
  "managed_users": 142,
  "managed_groups": 8,
  "disabled_users": 3,
  "last_sync": "2026-03-22T08:15:00Z",
  "deprovision_mode": "disable"
}
```

### 7.7 IdP Integration Instructions

#### Okta

1. In the Okta Admin Console, navigate to **Applications → Applications**.
2. Click **Browse App Catalog** and search for **SCIM 2.0**.
3. Select **SCIM 2.0 Test App (OAuth Bearer Token)**.
4. In the **Provisioning** tab, configure:
   - **SCIM connector base URL:** `https://<kms-host>/svc/auth/scim/v2/`
   - **Unique identifier field for users:** `email`
   - **Authentication Mode:** `HTTP Header`
   - **Authorization:** `Bearer <your-scim-token>`
5. Enable provisioning features: Create Users, Update User Attributes, Deactivate Users.
6. Under **Push Groups**, enable group push if using group-role mappings.
7. Test the connection and assign the application to users/groups.

#### Azure Active Directory / Entra ID

1. In the Azure portal, navigate to **Azure Active Directory → Enterprise Applications**.
2. Click **New application → Create your own application**.
3. Select **Integrate any other application you don't find in the gallery**.
4. Under **Provisioning**, set Mode to **Automatic**.
5. Configure:
   - **Tenant URL:** `https://<kms-host>/svc/auth/scim/v2/`
   - **Secret Token:** `<your-scim-token>`
6. Click **Test Connection** to confirm.
7. Under **Mappings**, configure attribute mappings:
   - `userPrincipalName` → `userName`
   - `mail` → `emails[type eq "work"].value`
   - `displayName` → `displayName`
8. Set **Provisioning Scope** to All users and groups.
9. Enable provisioning.

#### Google Workspace

1. In the Google Admin Console, navigate to **Apps → Web and mobile apps**.
2. Click **Add app → Add custom SAML app** or use a custom SCIM application.
3. Configure the SCIM endpoint and bearer token as provided.
4. Map Google Directory attributes to SCIM schema fields.
5. Enable auto-provisioning.

#### OneLogin

1. In OneLogin, navigate to **Applications → Add App**.
2. Search for **SCIM Provisioner with SAML (SCIM v2 Enterprise)**.
3. In the **Configuration** tab:
   - **SCIM Base URL:** `https://<kms-host>/svc/auth/scim/v2/`
   - **SCIM Bearer Token:** `<your-scim-token>`
4. In the **Provisioning** tab, enable **Enable provisioning**.
5. Map attribute fields and assign users.

---

## 8. API Client Management

API clients are registered machine identities that allow automation scripts, SDK integrations, and service agents to authenticate to Vecta KMS without using a human user account.

### 8.1 The AuthClientRegistration Model

| Field | Type | Values / Notes |
|---|---|---|
| `id` | string | Platform-generated unique client ID. |
| `client_name` | string | Human-readable name for the client. |
| `client_type` | enum | `service` — internal platform service. `agent` — protocol agent (EKM, KMIP). `integration` — external application. |
| `auth_mode` | enum | `bearer` — plain bearer token. `oauth_mtls` — OAuth 2.0 mTLS (RFC 8705). `dpop` — Demonstrating Proof-of-Possession (RFC 9449). `http_signature` — HTTP Message Signatures (RFC 9421). |
| `replay_protection_enabled` | boolean | Whether duplicate request detection is active. |
| `mtls_cert_fingerprint` | string | Expected client certificate fingerprint for `oauth_mtls` mode. |
| `http_signature_algorithm` | string | Algorithm for `http_signature` mode (e.g., `ecdsa-p256-sha256`, `rsa-pss-sha512`). |

### 8.2 Authentication Modes Compared

| Mode | Security Level | Use Case | Credential Type |
|---|---|---|---|
| `bearer` | Standard | Internal services, lab automation | Static API key / bearer token |
| `oauth_mtls` | High | Production services, HSM agents | Client TLS certificate |
| `dpop` | High | Browser-based or mobile integrations | Ephemeral proof key |
| `http_signature` | Very High | Payment, high-assurance service-to-service | Signing key with per-request signatures |

> **Best practice:** Start new production integrations with `oauth_mtls` at minimum. Reserve `bearer` mode for internal-only tools and lab environments. Use `http_signature` for payment flows or any integration that requires non-repudiation.

### 8.3 Listing API Clients

```
GET /svc/auth/auth/clients
Authorization: Bearer <access_token>
```

**cURL example:**

```bash
curl -s "http://localhost:5173/svc/auth/auth/clients?tenant_id=root" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

### 8.4 Getting a Specific Client

```
GET /svc/auth/auth/clients/{id}
Authorization: Bearer <access_token>
```

**cURL example:**

```bash
CLIENT_ID="client_01HXYZ"

curl -s "http://localhost:5173/svc/auth/auth/clients/${CLIENT_ID}" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

### 8.5 Updating a Client

```
PUT /svc/auth/auth/clients/{id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "auth_mode": "oauth_mtls",
  "mtls_cert_fingerprint": "sha256:AABBCC...",
  "replay_protection_enabled": true,
  "rate_limit_rpm": 1000,
  "allowed_ips": ["10.0.1.0/24", "10.0.2.0/24"]
}
```

**cURL example:**

```bash
curl -s -X PUT "http://localhost:5173/svc/auth/auth/clients/${CLIENT_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_mode": "oauth_mtls",
    "mtls_cert_fingerprint": "sha256:AABBCC...",
    "replay_protection_enabled": true,
    "rate_limit_rpm": 1000,
    "allowed_ips": ["10.0.1.0/24"]
  }' | jq .
```

### 8.6 Rotating a Client API Key

Key rotation generates a new API key for a client. The old key is immediately invalidated.

```
POST /svc/auth/auth/clients/{id}/rotate-key
Authorization: Bearer <access_token>
```

**cURL example:**

```bash
curl -s -X POST "http://localhost:5173/svc/auth/auth/clients/${CLIENT_ID}/rotate-key" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

The response contains the new key value. As with SCIM tokens, this is the only time the key is displayed in plaintext.

**Key rotation procedure:**
1. Call `rotate-key` to generate the new key.
2. Copy the new key immediately.
3. Update the application's secret store with the new key.
4. Restart or trigger a config reload on the application.
5. Confirm the application successfully authenticates with the new key.
6. Verify the old key no longer works.

> **Warning:** There is no grace period after key rotation. The old key stops working immediately when `rotate-key` is called. Ensure the new key is injected into the application before rotating in environments where downtime is unacceptable.

### 8.7 Revoking a Client

```
POST /svc/auth/auth/clients/{id}/revoke
Authorization: Bearer <access_token>
```

Revocation permanently prevents the client from authenticating. All active sessions for the client are terminated. This action is recorded in the audit log.

**cURL example:**

```bash
curl -s -X POST "http://localhost:5173/svc/auth/auth/clients/${CLIENT_ID}/revoke" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

Use revocation for:
- Decommissioned applications
- Compromised credentials
- Clients that have been migrated to a new registration

### 8.8 Dashboard: API Clients

**Navigation path:** `Admin → API Clients` or `REST API → Client Security`

The Client Security pane shows:
- A table of all registered clients with their auth mode, type, and replay protection status
- Risk indicators for clients still using `bearer` mode
- Signature failure counters
- Quick actions: Edit, Rotate Key, Revoke

---

## 9. System Health Monitoring

The system health surface gives administrators real-time visibility into the operational status of every service in the platform.

### 9.1 The SystemServiceHealth Model

| Field | Type | Values / Notes |
|---|---|---|
| `name` | string | Service name (e.g., `keycore`, `auth`, `certs`) |
| `status` | enum | `healthy` — service is running normally. `degraded` — service is running but with reduced capability. `unavailable` — service is not responding. |
| `source` | string | How the health status was determined (e.g., `tcp_probe`, `http_health_check`, `process_check`). |
| `address` | string | IP or hostname the service is bound to. |
| `port` | integer | Port the service is listening on. |
| `instances` | integer | Number of running instances (relevant for replicated services). |
| `output` | string | Human-readable status output or error message from the last health check. |
| `restart_allowed` | boolean | Whether the platform supports a forced restart of this service via the admin API. |

### 9.2 Services Monitored

| Service | Function |
|---|---|
| `keycore` | Core cryptographic engine — key lifecycle, encryption, signing |
| `auth` | Authentication, user management, tenant management |
| `certs` | PKI and certificate lifecycle |
| `audit` | Audit event storage and retrieval |
| `governance` | Approval workflows, backup/restore |
| `cluster` | Multi-node coordination and replication |
| `compliance` | Compliance assessment and control mapping |
| `reporting` | Operational reports and evidence export |
| `posture` | Security posture analysis and risk findings |
| `workload` | Workload identity (SPIFFE/SVID) |
| `payment` | Payment crypto and protocol surfaces |
| `autokey` | Self-service key provisioning templates |
| `keyaccess` | Key access justifications |
| `signing` | Artifact signing and transparency |
| `confidential` | Confidential compute and TEE attestation |
| `pqc` | Post-quantum cryptography migration |
| `discovery` | Asset discovery |
| `sbom` | Software bill of materials |

### 9.3 Retrieving System Health

```
GET /svc/auth/auth/system-health
Authorization: Bearer <access_token>
```

**cURL example:**

```bash
curl -s http://localhost:5173/svc/auth/auth/system-health \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

**Response:**

```json
{
  "services": [
    {
      "name": "keycore",
      "status": "healthy",
      "source": "http_health_check",
      "address": "127.0.0.1",
      "port": 8001,
      "instances": 1,
      "output": "OK",
      "restart_allowed": true
    },
    {
      "name": "certs",
      "status": "degraded",
      "source": "http_health_check",
      "address": "127.0.0.1",
      "port": 8003,
      "instances": 1,
      "output": "ACME renewal worker stalled — last renewal attempt failed. Retry scheduled in 5m.",
      "restart_allowed": true
    },
    {
      "name": "payment",
      "status": "unavailable",
      "source": "tcp_probe",
      "address": "127.0.0.1",
      "port": 8010,
      "instances": 0,
      "output": "Connection refused",
      "restart_allowed": true
    }
  ],
  "overall": "degraded",
  "checked_at": "2026-03-22T12:00:00Z"
}
```

**Health status interpretation:**

| Overall Status | Meaning | Action |
|---|---|---|
| `healthy` | All services responding normally | No action required |
| `degraded` | One or more services degraded but core function intact | Investigate affected services; consider restart if `restart_allowed` |
| `unavailable` | One or more critical services not responding | Immediate investigation; check logs; consider platform restart |

### 9.4 Restarting a Service

When a service is `degraded` or `unavailable` and `restart_allowed` is `true`, an administrator can trigger a controlled restart.

```
POST /svc/auth/auth/system-health/restart?service=certs
Authorization: Bearer <access_token>
```

**cURL example:**

```bash
curl -s -X POST "http://localhost:5173/svc/auth/auth/system-health/restart?service=certs" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

> **Warning:** Restarting `keycore` will briefly interrupt all cryptographic operations. Restarting `auth` will invalidate in-flight authentication requests. Plan service restarts during low-traffic windows when possible, and always check the audit log for the restart event afterwards.

**Restart decision matrix:**

| Service | Risk of restart | Alternative |
|---|---|---|
| `keycore` | High — interrupts all crypto | Check for underlying HSM or storage issue first |
| `auth` | Medium — interrupts login/token refresh | Wait for token expiry cycles to clear if possible |
| `certs` | Low — ACME/renewal worker restarts cleanly | Safe to restart for stalled renewals |
| `audit` | Medium — may lose in-flight events | Check disk space and DB connectivity first |
| `payment` | Low if no active payment sessions | Verify TLS and port binding first |

### 9.5 Dashboard: System Health

**Navigation path:** Dashboard home → Health Summary widget, or `Admin → System Health`

The health dashboard shows:
- Color-coded status tiles for each service (green/amber/red)
- Last-checked timestamp
- Expandable detail view with `output` message
- Restart button for eligible services

The home dashboard widget polls for health status and updates the display automatically. The unread alert badge in the sidebar navigation increments when new health degradation events are detected.

---

## 10. FIPS Mode

FIPS (Federal Information Processing Standard) mode restricts the platform to using only NIST FIPS 140-3 validated cryptographic algorithms. This mode is required for US federal deployments and many regulated financial and healthcare environments.

### 10.1 What FIPS Mode Changes

When FIPS mode is enabled:

| Category | FIPS-Approved (Allowed) | Non-FIPS (Rejected) |
|---|---|---|
| Symmetric encryption | AES-CBC-256, AES-GCM-256, AES-CBC-128 | ChaCha20-Poly1305, DES, 3DES |
| Hash functions | SHA-256, SHA-384, SHA-512 | MD5, SHA-1 |
| Asymmetric keys | RSA-2048, RSA-3072, RSA-4096 | — |
| Elliptic curves | P-256 (NIST), P-384 (NIST), P-521 (NIST) | Ed25519, X25519, Curve25519 |
| Key agreement | ECDH (P-curves), RSA-OAEP | X25519, Ed25519 DH |
| Signatures | ECDSA (P-curves), RSA-PSS | Ed25519 |

FIPS mode affects:
- Key creation: requests for non-FIPS algorithms will be rejected with an error
- Existing non-FIPS keys: they remain readable but new operations (encrypt, sign, derive) are blocked until the key is migrated
- Interface TLS: non-FIPS cipher suites are removed from the negotiation list
- SCIM and SSO: token signing algorithms are constrained to FIPS-approved curves
- Certificate issuance: non-FIPS signature algorithms are rejected

### 10.2 FIPS Mode and FIPS 140-3

Vecta KMS stores the FIPS mode flag in governance system state. This flag:
- Survives service restarts
- Is propagated to all services on startup
- Cannot be changed without governance approval

### 10.3 Checking FIPS Status

```
GET /svc/governance/governance/system/state
Authorization: Bearer <access_token>
```

**cURL example:**

```bash
curl -s http://localhost:5173/svc/governance/governance/system/state \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

**Response:**

```json
{
  "fips_mode": false,
  "fips_mode_enforced_since": null,
  "platform_version": "1.4.0",
  "last_modified": "2026-01-15T09:00:00Z",
  "last_modified_by": "admin@example.com"
}
```

### 10.4 Enabling FIPS Mode

> **Warning:** Enabling FIPS mode is a platform-wide breaking change for any existing non-FIPS key material or algorithm usage. Conduct a full inventory audit before enabling FIPS mode in a production environment.

**Pre-enablement checklist:**
- [ ] Run a key algorithm audit: identify all keys using non-FIPS algorithms
- [ ] Identify all interfaces using non-FIPS TLS cipher suites
- [ ] Identify certificates signed with non-FIPS algorithms (SHA-1, Ed25519)
- [ ] Communicate the change to all application teams
- [ ] Schedule a maintenance window
- [ ] Ensure at least two admins are available to provide governance approval

```
PUT /svc/governance/governance/system/state
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "fips_mode": true
}
```

This creates a governance approval request. A second administrator must approve before the change takes effect.

**cURL example:**

```bash
curl -s -X PUT http://localhost:5173/svc/governance/governance/system/state \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"fips_mode": true}' | jq .
```

### 10.5 Disabling FIPS Mode

Disabling FIPS mode follows the same governance approval flow.

```
PUT /svc/governance/governance/system/state
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "fips_mode": false
}
```

> **Note:** Disabling FIPS mode does not automatically re-enable rejected operations or revert configuration changes made while FIPS mode was active. Review interface TLS settings and algorithm policies after disabling.

### 10.6 FIPS Mode Migration Workflow

If the platform has been operating in non-FIPS mode and needs to migrate to FIPS compliance:

1. **Inventory phase:** Use the Compliance and Posture panels to identify all non-FIPS key algorithms, certificate signature algorithms, and TLS cipher configurations.

2. **Key migration phase:** For each non-FIPS key:
   - Create a new FIPS-compliant key (AES-256-GCM, ECDSA P-384, RSA-4096)
   - Migrate application usage to the new key
   - Retire the old key

3. **Interface phase:** Update all interface TLS settings to use FIPS-approved cipher suites only.

4. **Certificate phase:** Reissue any certificates signed with SHA-1 or using Ed25519.

5. **Approval phase:** Submit the FIPS enable request. Get governance approval.

6. **Verification phase:** After enabling, confirm the PQC and Compliance panels reflect FIPS compliance.

---

## 11. Network Configuration

Network configuration controls how Vecta KMS exposes itself to the network — which addresses it binds to, which ports it listens on, and how TLS is configured per interface.

### 11.1 Interface Types and Default Ports

| Interface | Protocol | Default Port | Purpose |
|---|---|---|---|
| REST / Dashboard | HTTP/HTTPS | 5173 | Dashboard UI and REST API |
| KMIP | TLS | 5696 | KMIP protocol for KMIP-native clients |
| gRPC | TLS | 50051 | Internal and SDK gRPC communication |
| Payment TCP | TLS | (configurable) | Payment protocol surfaces |
| EKM Agent | TLS | (configurable) | Database EKM and TDE integration |

### 11.2 Configuring Interfaces

Interface configuration is managed through the Governance service and applied atomically to avoid partial configuration states.

Interface configuration fields:

| Field | Description |
|---|---|
| `bind_address` | IP address to bind to. `0.0.0.0` for all interfaces, `127.0.0.1` for loopback only. |
| `port` | TCP port to listen on. |
| `tls_mode` | `none` (plain), `tls` (server TLS), `mtls` (mutual TLS). |
| `tls_cert_source` | Source for TLS certificate: `internal_ca`, `file`, `acme`. |
| `tls_cert_path` | Path to certificate file if `file` source. |
| `tls_key_path` | Path to private key file if `file` source. |
| `pqc_mode` | `inherit`, `classical`, `hybrid`, `pqc_only`. |

### 11.3 Applying Network Configuration Changes

```
POST /svc/governance/governance/system/network/apply
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "interfaces": [
    {
      "name": "rest",
      "bind_address": "0.0.0.0",
      "port": 5173,
      "tls_mode": "tls",
      "tls_cert_source": "internal_ca"
    },
    {
      "name": "kmip",
      "bind_address": "0.0.0.0",
      "port": 5696,
      "tls_mode": "mtls",
      "tls_cert_source": "file",
      "tls_cert_path": "/certs/kmip-server.pem",
      "tls_key_path": "/certs/kmip-server-key.pem"
    },
    {
      "name": "grpc",
      "bind_address": "127.0.0.1",
      "port": 50051,
      "tls_mode": "tls",
      "tls_cert_source": "internal_ca"
    }
  ]
}
```

**cURL example:**

```bash
curl -s -X POST http://localhost:5173/svc/governance/governance/system/network/apply \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "interfaces": [
      {
        "name": "rest",
        "bind_address": "0.0.0.0",
        "port": 5173,
        "tls_mode": "tls",
        "tls_cert_source": "internal_ca"
      }
    ]
  }' | jq .
```

> **Warning:** Applying network configuration changes causes the affected interface to briefly restart. If the REST interface is reconfigured, the dashboard connection will be interrupted. Ensure you have an alternative access path (e.g., local console access) before applying REST interface changes.

### 11.4 TLS Certificate Sources

| Source | Description | Use Case |
|---|---|---|
| `internal_ca` | Certificate issued by the KMS internal PKI | Default for all services in an integrated deployment |
| `file` | Static certificate and key files on disk | Externally managed PKI, bring-your-own certificates |
| `acme` | Automatically issued via ACME (Let's Encrypt or internal ACME CA) | Public-facing endpoints where automated renewal is preferred |

### 11.5 Network Security Recommendations

| Concern | Recommendation |
|---|---|
| Dashboard exposure | Bind to a management network or VPN interface, not `0.0.0.0` in production |
| KMIP exposure | Use mTLS with client certificate pinning. Restrict to known client IP ranges. |
| gRPC exposure | Bind to loopback `127.0.0.1` unless cross-host gRPC is required |
| Payment TCP | Enable mTLS and IP allowlisting. Consider a dedicated VLAN. |
| TLS cipher selection | Apply FIPS mode if compliance is required. Otherwise prefer TLS 1.3 with ECDHE. |

### 11.6 Dashboard: Network Configuration

**Navigation path:** `Admin → System → Network` or `Infrastructure → Interfaces`

The Interfaces pane shows:
- Current bind address and port for each interface
- TLS mode and certificate source
- Listening status (active/inactive)
- Edit and Apply buttons

---

## 12. Dashboard UI Navigation

The Vecta KMS dashboard is organized into tab groups in the left sidebar. Each group contains one or more tabs, and each tab may contain sub-panes for drilling into specific features.

### 12.1 Sidebar Structure

The sidebar is divided into the following tab groups:

| Group | Purpose |
|---|---|
| **CORE** | Health, keys, and primary operational surfaces |
| **CRYPTO & PKI** | Certificate lifecycle, PKI, and protocol interfaces |
| **DATA & POLICY** | Data protection, tokenization, and payment policy |
| **CLOUD & IDENTITY** | Cloud integrations, workload identity, and BYOK/HYOK |
| **INFRASTRUCTURE** | Interfaces, network, cluster, and HSM integration |
| **GOVERNANCE** | Approvals, backups, audit, and compliance |
| **ADMIN** | User management, tenant management, SCIM, system settings |

### 12.2 CORE Group

| Tab | Sub-panes | Purpose |
|---|---|---|
| **Dashboard** | Health, Summary, Alerts | Overview of platform health, key counts, certificate expiry alerts, compliance posture |
| **Keys** | Key List, Create Key, Versions, Operations | Full key lifecycle management — create, rotate, retire, test operations |
| **Secrets** | Secret List, Create Secret, Versions | Software vault for application secrets and structured data |
| **Autokey** | Templates, Requests, Handles | Self-service key provisioning with centralized policy templates |

### 12.3 CRYPTO & PKI Group

| Tab | Sub-panes | Purpose |
|---|---|---|
| **Certificates** | CA Hierarchy, Issued Certs, Renewal, ACME | Internal PKI, certificate issuance, renewal intelligence |
| **Signing** | Profiles, Records, Verification | Artifact signing for CI/CD pipelines, OCI, and Git workflows |
| **Post-Quantum** | Policy, Migration Status, PQC Inventory | PQC migration planning and readiness scoring |
| **KMIP** | Sessions, Operations Log | KMIP protocol session management |

### 12.4 DATA & POLICY Group

| Tab | Sub-panes | Purpose |
|---|---|---|
| **Data Protection** | Tokenization, Masking, Payment Policy | Field-level and payment data protection configuration |
| **Workbench** | Payment Crypto, Protocol Testing | Controlled testing environment — not production state |

### 12.5 CLOUD & IDENTITY Group

| Tab | Sub-panes | Purpose |
|---|---|---|
| **Cloud** | BYOK, HYOK, Cloud Key Import | Cloud provider key management integration |
| **Workload Identity** | Trust Domains, Registrations, SVIDs, Federation | SPIFFE/SVID-based workload authentication |
| **Confidential Compute** | Attestation Policy, Release History | TEE attestation and attested key release |
| **Key Access** | Reason Codes, Rules, Decisions | Key access justification enforcement and review |

### 12.6 INFRASTRUCTURE Group

| Tab | Sub-panes | Purpose |
|---|---|---|
| **Interfaces** | REST, KMIP, gRPC, Payment TCP | Request-handling surface configuration |
| **REST API** | Client Security, Sender Constraints | API client auth mode and sender-constrained security |
| **Cluster** | Nodes, Replication Profiles, Sync | Multi-node coordination and replication state |
| **HSM Integration** | HSM Connections, Operations | Hardware security module integration |
| **EKM** | Agent Config, Database TDE | Transparent data encryption for databases |

### 12.7 GOVERNANCE Group

| Tab | Sub-panes | Purpose |
|---|---|---|
| **Governance** | Approvals, Backup, Restore | Approval workflows, backup creation, and restore operations |
| **Audit Log** | Event Search, Export | Searchable audit event trail |
| **Compliance** | Assessments, Frameworks, Gaps | Compliance framework alignment and control gap analysis |
| **Posture** | Findings, Risk, Remediation | Operational security posture and risk triage |
| **Reporting** | Report Library, Export | Evidence reports for external auditors |

### 12.8 ADMIN Group

| Tab | Sub-panes | Purpose |
|---|---|---|
| **User Admin** | Users, SCIM, Groups | User lifecycle, SCIM settings, group management |
| **Tenant Admin** | Tenants, Delete Readiness | Tenant lifecycle and isolation management |
| **API Clients** | Client List, Security Posture | Machine identity and API client management |
| **System** | Health, Network, FIPS, Logs | System health monitoring, network config, FIPS toggle |
| **Identity Providers** | Provider List, Configure, Test | SSO and directory integration |

### 12.9 Sidebar Features

**Pinned tabs:** Frequently used tabs can be pinned to the top of the sidebar for quick access. Click the pin icon on any tab to pin it.

**Theme toggle:** The bottom of the sidebar has a theme toggle with three options:
- `Dark` — dark background with light text
- `Light` — light background with dark text
- `Auto` — follows the operating system preference

**Timezone picker:** The current timezone is shown at the bottom of the sidebar. Click it to change the display timezone for all timestamps in the dashboard. This does not affect the underlying UTC timestamps in the database.

**Search:** A global search bar at the top of the sidebar searches across key names, certificate common names, user accounts, and audit events. Press `/` from anywhere in the dashboard to focus the search bar.

**Alert badge:** The sidebar displays an unread alert count badge that refreshes every 10 seconds. Click the badge to navigate to the Alerts pane.

**Keyboard shortcuts:**

| Shortcut | Action |
|---|---|
| `/` | Focus global search |
| `g h` | Go to Dashboard (home) |
| `g k` | Go to Keys |
| `g c` | Go to Certificates |
| `g a` | Go to Audit Log |
| `g u` | Go to User Admin |
| `g s` | Go to System Health |
| `?` | Show keyboard shortcut reference |

### 12.10 Sub-pane Navigation

Within a tab, sub-panes are accessed through a secondary navigation bar that appears horizontally below the tab title. The active sub-pane is underlined or highlighted.

For example, within the **Certificates** tab:
```
[ CA Hierarchy ] [ Issued Certs ] [ Renewal ] [ ACME ] [ STAR ]
                  ^^^^^^^^^^^^^^^^^^^
                  Currently active sub-pane
```

Clicking a sub-pane loads its content in the main panel. State (such as search filters and scroll position) is preserved when switching between sub-panes within the same tab session.

---

## 13. Day 0 Checklist

Use this checklist immediately after installation before onboarding any users or applications.

### Platform Integrity

- [ ] Dashboard loads at `http://<host>:5173/` (or HTTPS equivalent)
- [ ] All services show `healthy` in System Health
- [ ] Default admin account is accessible
- [ ] Login succeeds and access token is issued
- [ ] Audit Log shows the initial admin login event

### Security Baseline

- [ ] Change the default admin password immediately
- [ ] Configure the password policy (`min_length` ≥ 14, require complexity)
- [ ] Configure the security policy (`max_failed_attempts` ≤ 5, reasonable `lockout_minutes`)
- [ ] Decide whether the REST interface should stay on HTTP or move to HTTPS
- [ ] If HTTPS: configure TLS on the REST interface, confirm certificate is valid
- [ ] Verify the internal CA is initialized (check Certificates → CA Hierarchy)

### Tenant and User Setup

- [ ] Confirm the root tenant is the intended scope for initial operations
- [ ] Create the initial set of admin users (do not rely solely on the bootstrap account)
- [ ] Decide on SCIM vs manual user management
- [ ] If SCIM: configure settings, issue the SCIM token, and configure the IdP
- [ ] If manual: create initial operator, viewer, and auditor accounts

### Backup

- [ ] Run an initial backup through Governance → Backup
- [ ] Confirm the backup completed and the file is accessible
- [ ] Document the backup recovery procedure

### Deployment Profile

- [ ] Confirm which services are enabled in the deployment profile
- [ ] Disable any services not needed in this environment
- [ ] If KMIP is enabled: confirm KMIP interface TLS is configured
- [ ] If payment features are enabled: confirm payment interface is configured and restricted to known client IPs

---

## 14. Day 1 Operations

### User Provisioning Flow

```
1. Determine source of truth
   ├── IdP-managed (preferred): Configure SCIM → IdP pushes users
   └── Manual: Admin creates each user via POST /svc/auth/auth/users

2. Set default role
   ├── operator  → for application teams needing key operations
   ├── viewer    → for monitoring-only access
   └── auditor   → for compliance and audit-only access

3. Communicate credentials
   └── Use secure channel — never email plaintext passwords

4. Verify first login
   └── Confirm audit event shows successful login and forced password change
```

### Key Creation Flow

```
1. Determine key purpose
   ├── Application encryption KEK  → AES-256-GCM
   ├── Signing key                 → ECDSA P-384 or RSA-4096
   ├── Wrapping key                → AES-256 or RSA-4096
   └── Payment key                 → AES-128/192/256 (per payment scheme)

2. Create via Dashboard (Keys → Create Key) or API (POST /svc/keycore/keys)

3. Label with metadata
   └── application, environment, owner, rotation schedule

4. Confirm in audit log
   └── Creation event with actor and timestamp
```

### Interface Configuration Flow

```
1. Determine required interfaces
   ├── REST only       → lab or API-only deployments
   ├── REST + KMIP     → KMIP-native client environments
   ├── REST + EKM      → database TDE environments
   └── All interfaces  → full production deployment

2. Configure TLS for each enabled interface

3. Apply via POST /svc/governance/governance/system/network/apply

4. Verify all interfaces show healthy in System Health
```

---

## 15. Day 2 Hardening

### Migrate API Clients from Bearer to Sender-Constrained

1. Audit current client auth modes: `GET /svc/auth/auth/clients`
2. Identify all clients still using `bearer` mode
3. For each client:
   - Generate a client TLS certificate (or DPoP key for browser clients)
   - Update client with `PUT /svc/auth/auth/clients/{id}` → `auth_mode: oauth_mtls`
   - Provide the cert fingerprint in `mtls_cert_fingerprint`
   - Enable `replay_protection_enabled: true`
4. Update the application to present the client certificate on every request
5. Monitor signature failure counts in the REST API pane

### Configure Key Access Justifications

1. Navigate to `Cloud & Identity → Key Access`
2. Define reason codes for sensitive decrypt/sign/unwrap operations
3. Bind reason codes to specific services and operations
4. Enable approval requirements for operations above a defined risk threshold
5. Review the Key Access Decisions pane to confirm enforcement

### Enable Posture and Compliance Baselines

1. Navigate to `Governance → Compliance`
2. Run an initial baseline assessment
3. Review control gaps
4. Assign remediation owners to high-priority findings
5. Set a recurring assessment schedule (recommended: weekly)

### Enable Audit Export

1. Navigate to `Governance → Reporting`
2. Configure an external SIEM or log management destination
3. Enable continuous audit event export
4. Verify events are arriving in the destination system

---

## 16. Troubleshooting Quick Reference

| Symptom | Likely Cause | Resolution |
|---|---|---|
| Login returns 401 | Wrong credentials or account locked | Check account status via GET /svc/auth/auth/users; unlock if locked |
| Login returns 403 | Account suspended or tenant disabled | Check tenant status; check user status |
| Login returns 429 | Lockout policy triggered | Wait for lockout_minutes to elapse or admin-unlock |
| SCIM provisioning fails | Invalid or rotated SCIM token | Rotate token via rotate-token; update IdP with new token |
| Service shows degraded | Worker stalled or resource contention | Check output field; restart if restart_allowed |
| FIPS mode blocks key creation | Requested algorithm is non-FIPS | Use AES-GCM-256, ECDSA P-384, or RSA-4096 |
| Tenant delete readiness fails | Active sessions or service links | Revoke clients; terminate sessions; re-run readiness check |
| Client API key stops working after rotation | Old key presented | Update application secret store with new key from rotate-key response |
| IdP SSO login fails | Incorrect redirect URI or certificate mismatch | Test provider config via POST /identity/providers/{provider}/test |
| Alert badge not updating | Network connectivity to dashboard | Hard-refresh the browser; check REST interface health |
| Audit log shows unexpected actions | Compromised account or client | Lock account; revoke client; investigate audit trail |

---

*This guide is current as of Vecta KMS version 1.4.x. For changelog details and migration notes between versions, see the OPERATIONS_GUIDE.md.*
