import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type GovernanceSettings = {
  tenant_id: string;
  approval_expiry_minutes: number;
  expiry_check_interval_seconds: number;
  smtp_host: string;
  smtp_port: string;
  smtp_username: string;
  smtp_password?: string;
  smtp_from: string;
  smtp_starttls: boolean;
  notify_dashboard: boolean;
  notify_email: boolean;
  challenge_response_enabled: boolean;
  updated_by?: string;
  updated_at?: string;
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

export async function getGovernanceSettings(session: AuthSession): Promise<GovernanceSettings> {
  const out = await serviceRequest<{ settings: GovernanceSettings }>(
    session,
    "governance",
    `/governance/settings?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return out.settings;
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
