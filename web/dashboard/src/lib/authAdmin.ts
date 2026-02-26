import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type AuthUser = {
  id: string;
  tenant_id: string;
  username: string;
  email: string;
  role: string;
  status: string;
  must_change_password: boolean;
  created_at?: string;
};

export type AuthTenant = {
  id: string;
  name: string;
  status: string;
  created_at?: string;
};

export type GroupRoleBinding = {
  tenant_id: string;
  group_id: string;
  role_name: string;
  updated_at?: string;
};

export type TenantActivityBlocker = {
  code: string;
  label: string;
  count: number;
  details?: string[];
  remediation?: string;
};

export type TenantDeleteReadiness = {
  tenant_id: string;
  tenant_status: string;
  checked_at?: string;
  active_ui_session_count?: number;
  active_service_link_count?: number;
  requires_governance_approval?: boolean;
  can_disable?: boolean;
  can_delete?: boolean;
  blockers?: TenantActivityBlocker[];
};

export type PasswordPolicy = {
  tenant_id: string;
  min_length: number;
  max_length: number;
  require_upper: boolean;
  require_lower: boolean;
  require_digit: boolean;
  require_special: boolean;
  require_no_whitespace: boolean;
  deny_username: boolean;
  deny_email_local_part: boolean;
  min_unique_chars: number;
  updated_by?: string;
  updated_at?: string;
};

export type SecurityPolicy = {
  tenant_id: string;
  max_failed_attempts: number;
  lockout_minutes: number;
  idle_timeout_minutes: number;
  updated_by?: string;
  updated_at?: string;
};

export type CLIStatus = {
  enabled: boolean;
  cli_username: string;
  host: string;
  port: number;
  transport: string;
  requires_additional_auth: boolean;
  default_cli_user_protected: boolean;
};

export type CLISessionOpenResult = {
  status: string;
  cli_session_id: string;
  expires_at: string;
  putty_uri: string;
  ssh_command: string;
  host: string;
  port: number;
  username: string;
  additional_auth: boolean;
};

type UsersResponse = { items: AuthUser[] };
type UserCreateResponse = { user_id: string };
type StatusResponse = { status: string };
type PolicyResponse = { policy: PasswordPolicy };
type SecurityPolicyResponse = { policy: SecurityPolicy };
type TenantsResponse = { items: AuthTenant[] };
type TenantCreateResponse = { status: string; tenant_id: string };
type GroupRoleBindingsResponse = { items: GroupRoleBinding[] };
type GroupRoleBindingResponse = { binding: GroupRoleBinding };
type TenantReadinessResponse = { readiness: TenantDeleteReadiness };
type TenantDeleteResponse = {
  status: string;
  tenant_id: string;
  tables_purged?: number;
  rows_purged?: number;
  deleted_by_table?: Record<string, number>;
};
type TenantDisableResponse = {
  status: string;
  tenant_id: string;
  readiness?: TenantDeleteReadiness;
};

export async function listAuthUsers(session: AuthSession, tenantID?: string): Promise<AuthUser[]> {
  const targetTenant = String(tenantID || "").trim();
  const path = targetTenant ? `/auth/users?tenant_id=${encodeURIComponent(targetTenant)}` : "/auth/users";
  const out = await serviceRequest<UsersResponse>(session, "auth", path);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function listAuthTenants(session: AuthSession): Promise<AuthTenant[]> {
  const out = await serviceRequest<TenantsResponse>(session, "auth", "/tenants");
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createAuthTenant(
  session: AuthSession,
  input: {
    id: string;
    name: string;
    status?: string;
    admin_username?: string;
    admin_email?: string;
    admin_password?: string;
    admin_role?: string;
    admin_status?: string;
    admin_must_change_password?: boolean;
  }
): Promise<string> {
  const out = await serviceRequest<TenantCreateResponse>(session, "auth", "/tenants", {
    method: "POST",
    body: JSON.stringify({
      id: String(input.id || "").trim(),
      name: String(input.name || "").trim(),
      status: String(input.status || "active").trim(),
      admin_username: String(input.admin_username || "").trim(),
      admin_email: String(input.admin_email || "").trim(),
      admin_password: String(input.admin_password || ""),
      admin_role: String(input.admin_role || "tenant-admin").trim(),
      admin_status: String(input.admin_status || "active").trim(),
      admin_must_change_password: Boolean(input.admin_must_change_password ?? true)
    })
  });
  return String(out?.tenant_id || "");
}

export async function deleteAuthTenant(
  session: AuthSession,
  tenantID: string,
  governanceApprovalID: string
): Promise<TenantDeleteResponse> {
  const target = String(tenantID || "").trim();
  const approval = String(governanceApprovalID || "").trim();
  const query = new URLSearchParams({
    confirm_tenant_id: target,
    force: "true",
    governance_approval_id: approval
  }).toString();
  return serviceRequest<TenantDeleteResponse>(session, "auth", `/tenants/${encodeURIComponent(target)}?${query}`, {
    method: "DELETE",
    body: JSON.stringify({
      confirm_tenant_id: target,
      force: true,
      governance_approval_id: approval
    })
  });
}

export async function getAuthTenantDeleteReadiness(
  session: AuthSession,
  tenantID: string
): Promise<TenantDeleteReadiness> {
  const target = String(tenantID || "").trim();
  const out = await serviceRequest<TenantReadinessResponse>(
    session,
    "auth",
    `/tenants/${encodeURIComponent(target)}/delete-readiness`
  );
  return out?.readiness;
}

export async function disableAuthTenant(
  session: AuthSession,
  tenantID: string,
  governanceApprovalID: string
): Promise<TenantDeleteReadiness> {
  const target = String(tenantID || "").trim();
  const out = await serviceRequest<TenantDisableResponse>(
    session,
    "auth",
    `/tenants/${encodeURIComponent(target)}/disable`,
    {
      method: "POST",
      body: JSON.stringify({
        governance_approval_id: String(governanceApprovalID || "").trim()
      })
    }
  );
  return out?.readiness || {
    tenant_id: target,
    tenant_status: "disabled",
    can_delete: true
  };
}

export async function createAuthUser(
  session: AuthSession,
  input: {
    tenant_id?: string;
    username: string;
    email: string;
    password: string;
    role: string;
    status?: string;
    must_change_password?: boolean;
  }
): Promise<string> {
  const out = await serviceRequest<UserCreateResponse>(session, "auth", "/auth/users", {
    method: "POST",
    body: JSON.stringify({
      username: String(input.username || "").trim(),
      email: String(input.email || "").trim(),
      password: String(input.password || ""),
      tenant_id: String(input.tenant_id || "").trim(),
      role: String(input.role || "").trim(),
      status: String(input.status || "active").trim(),
      must_change_password: Boolean(input.must_change_password)
    })
  });
  return String(out?.user_id || "");
}

export async function updateAuthUserRole(
  session: AuthSession,
  userID: string,
  role: string,
  tenantID?: string
): Promise<void> {
  const targetTenant = String(tenantID || "").trim();
  const qs = targetTenant ? `?tenant_id=${encodeURIComponent(targetTenant)}` : "";
  await serviceRequest<StatusResponse>(
    session,
    "auth",
    `/auth/users/${encodeURIComponent(String(userID || "").trim())}/role${qs}`,
    {
      method: "PUT",
      body: JSON.stringify({ role: String(role || "").trim() })
    }
  );
}

export async function updateAuthUserStatus(
  session: AuthSession,
  userID: string,
  status: string,
  tenantID?: string
): Promise<void> {
  const targetTenant = String(tenantID || "").trim();
  const qs = targetTenant ? `?tenant_id=${encodeURIComponent(targetTenant)}` : "";
  await serviceRequest<StatusResponse>(
    session,
    "auth",
    `/auth/users/${encodeURIComponent(String(userID || "").trim())}/status${qs}`,
    {
      method: "PUT",
      body: JSON.stringify({ status: String(status || "").trim() })
    }
  );
}

export async function resetAuthUserPassword(
  session: AuthSession,
  userID: string,
  input: { new_password: string; must_change_password?: boolean; tenant_id?: string }
): Promise<void> {
  const targetTenant = String(input.tenant_id || "").trim();
  const qs = targetTenant ? `?tenant_id=${encodeURIComponent(targetTenant)}` : "";
  await serviceRequest<StatusResponse>(
    session,
    "auth",
    `/auth/users/${encodeURIComponent(String(userID || "").trim())}/reset-password${qs}`,
    {
      method: "POST",
      body: JSON.stringify({
        new_password: String(input.new_password || ""),
        must_change_password: Boolean(input.must_change_password)
      })
    }
  );
}

export async function getAuthPasswordPolicy(session: AuthSession): Promise<PasswordPolicy> {
  const out = await serviceRequest<PolicyResponse>(session, "auth", "/auth/password-policy");
  return out.policy;
}

export async function updateAuthPasswordPolicy(
  session: AuthSession,
  input: Partial<PasswordPolicy>
): Promise<PasswordPolicy> {
  const out = await serviceRequest<PolicyResponse>(session, "auth", "/auth/password-policy", {
    method: "PUT",
    body: JSON.stringify(input || {})
  });
  return out.policy;
}

export async function getAuthSecurityPolicy(session: AuthSession): Promise<SecurityPolicy> {
  const out = await serviceRequest<SecurityPolicyResponse>(session, "auth", "/auth/security-policy");
  return out.policy;
}

export async function updateAuthSecurityPolicy(
  session: AuthSession,
  input: Partial<SecurityPolicy>
): Promise<SecurityPolicy> {
  const out = await serviceRequest<SecurityPolicyResponse>(session, "auth", "/auth/security-policy", {
    method: "PUT",
    body: JSON.stringify(input || {})
  });
  return out.policy;
}

export async function getAuthCLIStatus(session: AuthSession): Promise<CLIStatus> {
  return serviceRequest<CLIStatus>(session, "auth", "/auth/cli/status");
}

export async function openAuthCLISession(
  session: AuthSession,
  input: { username: string; password: string }
): Promise<CLISessionOpenResult> {
  return serviceRequest<CLISessionOpenResult>(session, "auth", "/auth/cli/session", {
    method: "POST",
    body: JSON.stringify({
      username: String(input.username || "").trim(),
      password: String(input.password || "")
    })
  });
}

export async function listAuthGroupRoleBindings(
  session: AuthSession,
  tenantID?: string
): Promise<GroupRoleBinding[]> {
  const targetTenant = String(tenantID || "").trim();
  const qs = targetTenant ? `?tenant_id=${encodeURIComponent(targetTenant)}` : "";
  const out = await serviceRequest<GroupRoleBindingsResponse>(session, "auth", `/auth/groups/roles${qs}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function upsertAuthGroupRoleBinding(
  session: AuthSession,
  groupID: string,
  roleName: string,
  tenantID?: string
): Promise<GroupRoleBinding> {
  const targetTenant = String(tenantID || "").trim();
  const qs = targetTenant ? `?tenant_id=${encodeURIComponent(targetTenant)}` : "";
  const out = await serviceRequest<GroupRoleBindingResponse>(
    session,
    "auth",
    `/auth/groups/${encodeURIComponent(String(groupID || "").trim())}/role${qs}`,
    {
      method: "PUT",
      body: JSON.stringify({ role_name: String(roleName || "").trim() })
    }
  );
  return out?.binding;
}

export async function deleteAuthGroupRoleBinding(
  session: AuthSession,
  groupID: string,
  tenantID?: string
): Promise<void> {
  const targetTenant = String(tenantID || "").trim();
  const qs = targetTenant ? `?tenant_id=${encodeURIComponent(targetTenant)}` : "";
  await serviceRequest<StatusResponse>(
    session,
    "auth",
    `/auth/groups/${encodeURIComponent(String(groupID || "").trim())}/role${qs}`,
    { method: "DELETE" }
  );
}
