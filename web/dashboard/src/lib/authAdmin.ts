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

export async function listAuthUsers(session: AuthSession): Promise<AuthUser[]> {
  const out = await serviceRequest<UsersResponse>(session, "auth", "/auth/users");
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createAuthUser(
  session: AuthSession,
  input: {
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
  role: string
): Promise<void> {
  await serviceRequest<StatusResponse>(
    session,
    "auth",
    `/auth/users/${encodeURIComponent(String(userID || "").trim())}/role`,
    {
      method: "PUT",
      body: JSON.stringify({ role: String(role || "").trim() })
    }
  );
}

export async function updateAuthUserStatus(
  session: AuthSession,
  userID: string,
  status: string
): Promise<void> {
  await serviceRequest<StatusResponse>(
    session,
    "auth",
    `/auth/users/${encodeURIComponent(String(userID || "").trim())}/status`,
    {
      method: "PUT",
      body: JSON.stringify({ status: String(status || "").trim() })
    }
  );
}

export async function resetAuthUserPassword(
  session: AuthSession,
  userID: string,
  input: { new_password: string; must_change_password?: boolean }
): Promise<void> {
  await serviceRequest<StatusResponse>(
    session,
    "auth",
    `/auth/users/${encodeURIComponent(String(userID || "").trim())}/reset-password`,
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
