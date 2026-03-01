import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type GovernanceSettings = {
  tenant_id: string;
  approval_expiry_minutes: number;
  expiry_check_interval_seconds: number;
  approval_delivery_mode: "notify" | "kms_only" | string;
  smtp_host: string;
  smtp_port: string;
  smtp_username: string;
  smtp_password?: string;
  smtp_from: string;
  smtp_starttls: boolean;
  notify_dashboard: boolean;
  notify_email: boolean;
  notify_slack: boolean;
  notify_teams: boolean;
  slack_webhook_url: string;
  teams_webhook_url: string;
  delivery_webhook_timeout_seconds: number;
  challenge_response_enabled: boolean;
  updated_by?: string;
  updated_at?: string;
};

export type GovernanceSystemState = Record<string, unknown>;

export type GovernanceSystemStateResponse = {
  state: GovernanceSystemState;
  request_id?: string;
};

export type GovernancePolicy = {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  scope: string;
  trigger_actions: string[];
  quorum_mode?: "and" | "or" | string;
  required_approvals: number;
  total_approvers: number;
  approver_roles?: string[];
  approver_users?: string[];
  timeout_hours?: number;
  escalation_hours?: number;
  escalation_to?: string[];
  retention_days?: number;
  notification_channels?: string[];
  status: string;
  created_at?: string;
};

export type GovernanceRequest = {
  id: string;
  tenant_id: string;
  policy_id: string;
  action: string;
  target_type: string;
  target_id: string;
  target_details?: Record<string, unknown>;
  requester_id?: string;
  requester_email?: string;
  requester_ip?: string;
  status: string;
  required_approvals: number;
  current_approvals: number;
  current_denials: number;
  created_at?: string;
  expires_at?: string;
  resolved_at?: string;
};

export type GovernanceVote = {
  id: string;
  request_id: string;
  tenant_id: string;
  approver_id: string;
  approver_email: string;
  vote: string;
  vote_method: string;
  comment?: string;
  voted_at?: string;
  ip_address?: string;
};

export type GovernanceBackupJob = {
  id: string;
  tenant_id: string;
  scope: "system" | "tenant" | string;
  target_tenant_id?: string;
  status: string;
  backup_format: string;
  encryption_algorithm: string;
  ciphertext_sha256: string;
  artifact_size_bytes: number;
  row_count_total: number;
  table_count: number;
  hsm_bound: boolean;
  hsm_provider_name?: string;
  hsm_slot_id?: string;
  hsm_partition_label?: string;
  hsm_token_label?: string;
  hsm_binding_fingerprint?: string;
  key_package?: Record<string, unknown>;
  created_by?: string;
  created_at?: string;
  completed_at?: string;
  failure_reason?: string;
};

export type GovernanceRestoreBackupResult = {
  scope: "system" | "tenant" | string;
  target_tenant_id?: string;
  rows_restored: number;
  tables_processed: number;
  tables_skipped?: string[];
  excluded_tables?: string[];
  backup_captured_at?: string;
};

export async function getGovernanceSettings(session: AuthSession): Promise<GovernanceSettings> {
  const out = await serviceRequest<{ settings: GovernanceSettings }>(
    session,
    "governance",
    `/governance/settings?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return out.settings;
}

export async function getGovernanceSystemState(session: AuthSession): Promise<GovernanceSystemStateResponse> {
  const out = await serviceRequest<GovernanceSystemStateResponse>(
    session,
    "governance",
    `/governance/system/state?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  const requestID = String(out?.request_id || "").trim();
  return {
    state: out?.state && typeof out.state === "object" ? out.state : {},
    ...(requestID ? { request_id: requestID } : {})
  };
}

export async function patchGovernanceSystemState(
  session: AuthSession,
  input: GovernanceSystemState
): Promise<GovernanceSystemStateResponse> {
  const out = await serviceRequest<GovernanceSystemStateResponse>(session, "governance", "/governance/system/state", {
    method: "PUT",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...(input || {})
    })
  });
  const requestID = String(out?.request_id || "").trim();
  return {
    state: out?.state && typeof out.state === "object" ? out.state : {},
    ...(requestID ? { request_id: requestID } : {})
  };
}

export async function testGovernanceSystemSNMP(session: AuthSession, target: string): Promise<void> {
  await serviceRequest<Record<string, unknown>>(session, "governance", "/governance/system/snmp/test", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      target: String(target || "").trim()
    })
  });
}

export async function updateGovernanceSettings(
  session: AuthSession,
  input: Partial<GovernanceSettings>
): Promise<GovernanceSettings> {
  const out = await serviceRequest<{ settings: GovernanceSettings }>(session, "governance", "/governance/settings", {
    method: "PUT",
    body: JSON.stringify({
      ...input,
      tenant_id: session.tenantId
    })
  });
  return out.settings;
}

export async function testGovernanceSMTP(session: AuthSession, to: string): Promise<void> {
  await serviceRequest<Record<string, unknown>>(session, "governance", "/governance/settings/smtp/test", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      to
    })
  });
}

export async function testGovernanceWebhook(
  session: AuthSession,
  channel: "slack" | "teams",
  webhook_url?: string
): Promise<void> {
  await serviceRequest<Record<string, unknown>>(session, "governance", "/governance/settings/webhook/test", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      channel,
      webhook_url: webhook_url || ""
    })
  });
}

export async function createGovernanceBackup(
  session: AuthSession,
  input: {
    scope: "system" | "tenant";
    target_tenant_id?: string;
    bind_to_hsm?: boolean;
    created_by?: string;
  }
): Promise<GovernanceBackupJob> {
  const out = await serviceRequest<{ job: GovernanceBackupJob }>(session, "governance", "/governance/backups", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      scope: input.scope,
      target_tenant_id: String(input.target_tenant_id || "").trim(),
      bind_to_hsm: typeof input.bind_to_hsm === "boolean" ? input.bind_to_hsm : true,
      created_by: String(input.created_by || "").trim()
    })
  });
  return out.job;
}

export async function listGovernanceBackups(
  session: AuthSession,
  options?: { scope?: string; status?: string; limit?: number }
): Promise<GovernanceBackupJob[]> {
  const qp = new URLSearchParams();
  qp.set("tenant_id", session.tenantId);
  if (String(options?.scope || "").trim()) qp.set("scope", String(options?.scope || "").trim());
  if (String(options?.status || "").trim()) qp.set("status", String(options?.status || "").trim());
  if (Number(options?.limit || 0) > 0) qp.set("limit", String(Math.trunc(Number(options?.limit || 0))));
  const out = await serviceRequest<{ items?: GovernanceBackupJob[] }>(session, "governance", `/governance/backups?${qp.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function downloadGovernanceBackupArtifact(
  session: AuthSession,
  backupID: string
): Promise<{ file_name: string; content_type: string; content_base64: string }> {
  const out = await serviceRequest<{ artifact: { file_name: string; content_type: string; content_base64: string } }>(
    session,
    "governance",
    `/governance/backups/${encodeURIComponent(String(backupID || "").trim())}/artifact?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return out.artifact;
}

export async function downloadGovernanceBackupKey(
  session: AuthSession,
  backupID: string
): Promise<{ file_name: string; content_type: string; content_base64: string; key_package?: Record<string, unknown> }> {
  const out = await serviceRequest<{ artifact: { file_name: string; content_type: string; content_base64: string; key_package?: Record<string, unknown> } }>(
    session,
    "governance",
    `/governance/backups/${encodeURIComponent(String(backupID || "").trim())}/key?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return out.artifact;
}

export async function restoreGovernanceBackup(
  session: AuthSession,
  input: {
    artifact_file_name: string;
    artifact_content_base64: string;
    key_file_name: string;
    key_content_base64: string;
    created_by?: string;
  }
): Promise<GovernanceRestoreBackupResult> {
  const out = await serviceRequest<{ result: GovernanceRestoreBackupResult }>(session, "governance", "/governance/backups/restore", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      artifact_file_name: String(input.artifact_file_name || "").trim(),
      artifact_content_base64: String(input.artifact_content_base64 || "").trim(),
      key_file_name: String(input.key_file_name || "").trim(),
      key_content_base64: String(input.key_content_base64 || "").trim(),
      created_by: String(input.created_by || "").trim()
    })
  });
  return out.result;
}

export async function deleteGovernanceBackup(
  session: AuthSession,
  backupID: string,
  actor?: string
): Promise<void> {
  const qp = new URLSearchParams();
  qp.set("tenant_id", session.tenantId);
  if (String(actor || "").trim()) {
    qp.set("actor", String(actor || "").trim());
  }
  await serviceRequest<Record<string, unknown>>(
    session,
    "governance",
    `/governance/backups/${encodeURIComponent(String(backupID || "").trim())}?${qp.toString()}`,
    {
      method: "DELETE"
    }
  );
}

export async function listGovernancePolicies(
  session: AuthSession,
  options?: { scope?: string; status?: string }
): Promise<GovernancePolicy[]> {
  const params = new URLSearchParams();
  params.set("tenant_id", session.tenantId);
  if (options?.scope) {
    params.set("scope", options.scope);
  }
  if (options?.status) {
    params.set("status", options.status);
  }
  const out = await serviceRequest<{ items: GovernancePolicy[] }>(
    session,
    "governance",
    `/governance/policies?${params.toString()}`
  );
  return Array.isArray(out.items) ? out.items : [];
}

export async function createGovernancePolicy(
  session: AuthSession,
  policy: Partial<GovernancePolicy>
): Promise<GovernancePolicy> {
  const out = await serviceRequest<{ policy: GovernancePolicy }>(session, "governance", "/governance/policies", {
    method: "POST",
    body: JSON.stringify({
      ...policy,
      tenant_id: session.tenantId
    })
  });
  return out.policy;
}

export async function updateGovernancePolicy(
  session: AuthSession,
  policyID: string,
  policy: Partial<GovernancePolicy>
): Promise<GovernancePolicy> {
  const out = await serviceRequest<{ policy: GovernancePolicy }>(
    session,
    "governance",
    `/governance/policies/${encodeURIComponent(policyID)}`,
    {
      method: "PUT",
      body: JSON.stringify({
        ...policy,
        id: policyID,
        tenant_id: session.tenantId
      })
    }
  );
  return out.policy;
}

export async function listGovernanceRequests(
  session: AuthSession,
  options?: { status?: string; target_type?: string; target_id?: string }
): Promise<GovernanceRequest[]> {
  const params = new URLSearchParams();
  params.set("tenant_id", session.tenantId);
  if (options?.status) {
    params.set("status", options.status);
  }
  if (options?.target_type) {
    params.set("target_type", options.target_type);
  }
  if (options?.target_id) {
    params.set("target_id", options.target_id);
  }
  const out = await serviceRequest<{ items: GovernanceRequest[] }>(
    session,
    "governance",
    `/governance/requests?${params.toString()}`
  );
  return Array.isArray(out.items) ? out.items : [];
}

export async function createGovernanceRequest(
  session: AuthSession,
  input: {
    policy_id?: string;
    action: string;
    target_type: string;
    target_id: string;
    target_details?: Record<string, unknown>;
    requester_id?: string;
    requester_email?: string;
    requester_ip?: string;
    callback_service?: string;
    callback_action?: string;
    callback_payload?: Record<string, unknown>;
  }
): Promise<GovernanceRequest> {
  const out = await serviceRequest<{ request: GovernanceRequest }>(session, "governance", "/governance/requests", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      policy_id: String(input.policy_id || "").trim(),
      action: String(input.action || "").trim(),
      target_type: String(input.target_type || "").trim(),
      target_id: String(input.target_id || "").trim(),
      target_details: input.target_details || {},
      requester_id: String(input.requester_id || session.username || "").trim(),
      requester_email: String(input.requester_email || "").trim(),
      requester_ip: String(input.requester_ip || "").trim(),
      callback_service: String(input.callback_service || "").trim(),
      callback_action: String(input.callback_action || "").trim(),
      callback_payload: input.callback_payload || {}
    })
  });
  return out.request;
}

export async function getGovernanceRequest(
  session: AuthSession,
  requestID: string
): Promise<{ request: GovernanceRequest; votes: GovernanceVote[] }> {
  const out = await serviceRequest<{ request: GovernanceRequest; votes: GovernanceVote[] }>(
    session,
    "governance",
    `/governance/requests/${encodeURIComponent(requestID)}?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return {
    request: out.request,
    votes: Array.isArray(out.votes) ? out.votes : []
  };
}

export async function voteGovernanceRequest(
  session: AuthSession,
  requestID: string,
  input: {
    vote: "approved" | "denied";
    approver_email?: string;
    approver_id?: string;
    comment?: string;
    challenge_code?: string;
  }
): Promise<GovernanceRequest> {
  const out = await serviceRequest<{ request: GovernanceRequest }>(
    session,
    "governance",
    `/governance/approve/${encodeURIComponent(requestID)}`,
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        request_id: requestID,
        vote: input.vote,
        approver_email: input.approver_email || "",
        approver_id: input.approver_id || "",
        comment: input.comment || "",
        challenge_code: input.challenge_code || "",
        vote_method: input.challenge_code ? "dashboard_challenge" : "dashboard"
      })
    }
  );
  return out.request;
}
