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

export type SystemServiceHealth = {
  name: string;
  status: string;
  source?: string;
  address?: string;
  port?: number;
  instances?: number;
  output?: string;
  restart_allowed?: boolean;
  restart_block_reason?: string;
};

export type SystemHealthSummary = {
  total?: number;
  running?: number;
  degraded?: number;
  down?: number;
  unknown?: number;
  all_ok?: boolean;
};

export type AuthSystemHealthSnapshot = {
  summary?: SystemHealthSummary;
  services?: SystemServiceHealth[];
  collected_at?: string;
  warning?: string;
  request_id?: string;
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

export type CLIHSMOnboarding = {
  workspace_root?: string;
  workspace_incoming_dir?: string;
  provider_library_dir?: string;
  pkcs11_config_file?: string;
  checksums_file?: string;
  integration_service?: string;
  supports_package_install?: boolean;
  scp_upload_command?: string;
  sftp_command?: string;
  prepare_workspace_command?: string;
  install_library_command?: string;
  verify_checksum_command?: string;
  verify_provider_command?: string;
  list_partitions_command?: string;
  run_vendor_utility_command?: string;
  docker_copy_command?: string;
  next_ui_step?: string;
  security_notes?: string[];
  pkcs11_config_template?: Record<string, unknown>;
};

export type CLIStatus = {
  enabled: boolean;
  cli_username: string;
  host: string;
  port: number;
  transport: string;
  requires_additional_auth: boolean;
  default_cli_user_protected: boolean;
  hsm_pkcs11_onboarding?: CLIHSMOnboarding;
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
  hsm_pkcs11_onboarding?: CLIHSMOnboarding;
};

export type CLIHSMPartitionSlot = {
  slot_id: string;
  slot_name: string;
  token_label?: string;
  token_model?: string;
  token_manufacturer?: string;
  serial_number?: string;
  token_present?: boolean;
  partition?: string;
};

export type CLIHSMPartitionList = {
  items: CLIHSMPartitionSlot[];
  raw_output?: string;
  library_path?: string;
  service_name?: string;
};

export type HSMProviderConfig = {
  tenant_id: string;
  provider_name: string;
  integration_service: string;
  library_path: string;
  slot_id: string;
  partition_label: string;
  token_label: string;
  pin_env_var: string;
  read_only: boolean;
  enabled: boolean;
  metadata?: Record<string, unknown>;
  updated_by?: string;
  created_at?: string;
  updated_at?: string;
};

export type IdentityProviderName = "ad" | "entra";

export type IdentityProviderConfigView = {
  tenant_id: string;
  provider: IdentityProviderName;
  enabled: boolean;
  config?: Record<string, unknown>;
  secret_presence?: Record<string, unknown>;
  updated_by?: string;
  created_at?: string;
  updated_at?: string;
};

export type ExternalDirectoryUser = {
  external_id: string;
  username: string;
  email: string;
  display_name?: string;
  source?: string;
  dn?: string;
};

export type ExternalDirectoryGroup = {
  external_id: string;
  name: string;
  description?: string;
  source?: string;
  dn?: string;
  member_count?: number;
  provider_name?: string;
};

type UsersResponse = { items: AuthUser[] };
type UserCreateResponse = { user_id: string };
type StatusResponse = { status: string };
type PolicyResponse = { policy: PasswordPolicy };
type SecurityPolicyResponse = { policy: SecurityPolicy };
type HSMProviderConfigResponse = {
  config: HSMProviderConfig;
  persisted?: boolean;
};
type CLIHSMPartitionListResponse = {
  items?: CLIHSMPartitionSlot[];
  raw_output?: string;
  library_path?: string;
  service_name?: string;
};
type IdentityProvidersResponse = { items: IdentityProviderConfigView[] };
type IdentityProviderResponse = { config: IdentityProviderConfigView };
type IdentityProviderTestResponse = {
  status?: string;
  provider?: IdentityProviderName;
  result?: Record<string, unknown>;
};
type ExternalDirectoryUsersResponse = {
  items?: ExternalDirectoryUser[];
  provider?: IdentityProviderName;
  tenant_id?: string;
  request_id?: string;
};
type ExternalDirectoryGroupsResponse = {
  items?: ExternalDirectoryGroup[];
  provider?: IdentityProviderName;
  tenant_id?: string;
  request_id?: string;
};
type IdentityImportResponse = {
  status?: string;
  provider?: IdentityProviderName;
  tenant_id?: string;
  group_id?: string;
  created?: Array<Record<string, unknown>>;
  existing?: Array<Record<string, unknown>>;
  failed?: Array<Record<string, unknown>>;
};
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
type RestartServiceResponse = {
  status?: string;
  service?: string;
  request_id?: string;
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

export async function getAuthSystemHealth(
  session: AuthSession,
  options?: { skipGlobalLoading?: boolean }
): Promise<AuthSystemHealthSnapshot> {
  const out = await serviceRequest<AuthSystemHealthSnapshot>(session, "auth", "/auth/system-health", {
    skipGlobalLoading: Boolean(options?.skipGlobalLoading)
  });
  return {
    ...out,
    services: Array.isArray(out?.services) ? out.services : []
  };
}

export async function restartAuthSystemService(
  session: AuthSession,
  serviceName: string
): Promise<RestartServiceResponse> {
  return serviceRequest<RestartServiceResponse>(session, "auth", "/auth/system-health/restart", {
    method: "POST",
    body: JSON.stringify({
      service: String(serviceName || "").trim()
    })
  });
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

export async function listAuthCLIHSMPartitions(
  session: AuthSession,
  libraryPath: string,
  slotID?: string
): Promise<CLIHSMPartitionList> {
  const qp = new URLSearchParams();
  qp.set("library_path", String(libraryPath || "").trim());
  if (String(slotID || "").trim()) {
    qp.set("slot_id", String(slotID || "").trim());
  }
  const out = await serviceRequest<CLIHSMPartitionListResponse>(
    session,
    "auth",
    `/auth/cli/hsm/partitions?${qp.toString()}`
  );
  return {
    items: Array.isArray(out?.items) ? out.items : [],
    raw_output: String(out?.raw_output || ""),
    library_path: String(out?.library_path || ""),
    service_name: String(out?.service_name || "")
  };
}

export async function getAuthCLIHSMConfig(session: AuthSession): Promise<HSMProviderConfig> {
  const out = await serviceRequest<HSMProviderConfigResponse>(session, "auth", "/auth/cli/hsm/config");
  return out?.config;
}

export async function upsertAuthCLIHSMConfig(
  session: AuthSession,
  input: Partial<HSMProviderConfig>
): Promise<HSMProviderConfig> {
  const out = await serviceRequest<HSMProviderConfigResponse>(session, "auth", "/auth/cli/hsm/config", {
    method: "PUT",
    body: JSON.stringify(input || {})
  });
  return out?.config;
}

export async function listAuthIdentityProviders(
  session: AuthSession,
  tenantID?: string
): Promise<IdentityProviderConfigView[]> {
  const targetTenant = String(tenantID || "").trim();
  const qs = targetTenant ? `?tenant_id=${encodeURIComponent(targetTenant)}` : "";
  const out = await serviceRequest<IdentityProvidersResponse>(session, "auth", `/auth/identity/providers${qs}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getAuthIdentityProviderConfig(
  session: AuthSession,
  provider: IdentityProviderName,
  tenantID?: string
): Promise<IdentityProviderConfigView> {
  const targetTenant = String(tenantID || "").trim();
  const qs = targetTenant ? `?tenant_id=${encodeURIComponent(targetTenant)}` : "";
  const out = await serviceRequest<IdentityProviderResponse>(
    session,
    "auth",
    `/auth/identity/providers/${encodeURIComponent(String(provider || "").trim())}${qs}`
  );
  return out?.config;
}

export async function upsertAuthIdentityProviderConfig(
  session: AuthSession,
  provider: IdentityProviderName,
  input: {
    tenant_id?: string;
    enabled?: boolean;
    config?: Record<string, unknown>;
    secrets?: Record<string, unknown>;
    clear_secrets?: string[];
  }
): Promise<IdentityProviderConfigView> {
  const targetTenant = String(input?.tenant_id || "").trim();
  const qs = targetTenant ? `?tenant_id=${encodeURIComponent(targetTenant)}` : "";
  const out = await serviceRequest<IdentityProviderResponse>(
    session,
    "auth",
    `/auth/identity/providers/${encodeURIComponent(String(provider || "").trim())}${qs}`,
    {
      method: "PUT",
      body: JSON.stringify({
        tenant_id: targetTenant,
        enabled: typeof input?.enabled === "boolean" ? Boolean(input.enabled) : undefined,
        config: input?.config || {},
        secrets: input?.secrets || {},
        clear_secrets: Array.isArray(input?.clear_secrets) ? input.clear_secrets : []
      })
    }
  );
  return out?.config;
}

export async function testAuthIdentityProviderConfig(
  session: AuthSession,
  provider: IdentityProviderName,
  input?: {
    tenant_id?: string;
    enabled?: boolean;
    config?: Record<string, unknown>;
    secrets?: Record<string, unknown>;
    clear_secrets?: string[];
  }
): Promise<IdentityProviderTestResponse> {
  const targetTenant = String(input?.tenant_id || "").trim();
  const qs = targetTenant ? `?tenant_id=${encodeURIComponent(targetTenant)}` : "";
  return serviceRequest<IdentityProviderTestResponse>(
    session,
    "auth",
    `/auth/identity/providers/${encodeURIComponent(String(provider || "").trim())}/test${qs}`,
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: targetTenant,
        enabled: typeof input?.enabled === "boolean" ? Boolean(input.enabled) : undefined,
        config: input?.config || {},
        secrets: input?.secrets || {},
        clear_secrets: Array.isArray(input?.clear_secrets) ? input.clear_secrets : []
      })
    }
  );
}

export async function listAuthIdentityProviderUsers(
  session: AuthSession,
  provider: IdentityProviderName,
  input?: {
    tenant_id?: string;
    query?: string;
    limit?: number;
  }
): Promise<ExternalDirectoryUser[]> {
  const qs = new URLSearchParams();
  const tenantID = String(input?.tenant_id || "").trim();
  const query = String(input?.query || "").trim();
  const limit = Number(input?.limit || 50);
  if (tenantID) {
    qs.set("tenant_id", tenantID);
  }
  if (query) {
    qs.set("query", query);
  }
  if (Number.isFinite(limit) && limit > 0) {
    qs.set("limit", String(limit));
  }
  const out = await serviceRequest<ExternalDirectoryUsersResponse>(
    session,
    "auth",
    `/auth/identity/providers/${encodeURIComponent(String(provider || "").trim())}/users${qs.toString() ? `?${qs.toString()}` : ""}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function listAuthIdentityProviderGroups(
  session: AuthSession,
  provider: IdentityProviderName,
  input?: {
    tenant_id?: string;
    query?: string;
    limit?: number;
  }
): Promise<ExternalDirectoryGroup[]> {
  const qs = new URLSearchParams();
  const tenantID = String(input?.tenant_id || "").trim();
  const query = String(input?.query || "").trim();
  const limit = Number(input?.limit || 50);
  if (tenantID) {
    qs.set("tenant_id", tenantID);
  }
  if (query) {
    qs.set("query", query);
  }
  if (Number.isFinite(limit) && limit > 0) {
    qs.set("limit", String(limit));
  }
  const out = await serviceRequest<ExternalDirectoryGroupsResponse>(
    session,
    "auth",
    `/auth/identity/providers/${encodeURIComponent(String(provider || "").trim())}/groups${qs.toString() ? `?${qs.toString()}` : ""}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function listAuthIdentityProviderGroupMembers(
  session: AuthSession,
  provider: IdentityProviderName,
  groupID: string,
  input?: {
    tenant_id?: string;
    limit?: number;
  }
): Promise<ExternalDirectoryUser[]> {
  const qs = new URLSearchParams();
  const tenantID = String(input?.tenant_id || "").trim();
  const limit = Number(input?.limit || 500);
  if (tenantID) {
    qs.set("tenant_id", tenantID);
  }
  if (Number.isFinite(limit) && limit > 0) {
    qs.set("limit", String(limit));
  }
  const out = await serviceRequest<ExternalDirectoryUsersResponse>(
    session,
    "auth",
    `/auth/identity/providers/${encodeURIComponent(String(provider || "").trim())}/groups/${encodeURIComponent(String(groupID || "").trim())}/members${qs.toString() ? `?${qs.toString()}` : ""}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function importAuthIdentityUsers(
  session: AuthSession,
  input: {
    tenant_id?: string;
    provider: IdentityProviderName;
    group_id?: string;
    role?: string;
    status?: string;
    must_change_password?: boolean;
    users?: ExternalDirectoryUser[];
    limit?: number;
  }
): Promise<IdentityImportResponse> {
  return serviceRequest<IdentityImportResponse>(session, "auth", "/auth/identity/import/users", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: String(input?.tenant_id || "").trim(),
      provider: String(input?.provider || "").trim(),
      group_id: String(input?.group_id || "").trim(),
      role: String(input?.role || "").trim(),
      status: String(input?.status || "").trim(),
      must_change_password: Boolean(input?.must_change_password ?? true),
      users: Array.isArray(input?.users) ? input.users : [],
      limit: Number(input?.limit || 0)
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
