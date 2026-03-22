import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type KeyAccessSettings = {
  tenant_id: string;
  enabled: boolean;
  mode: string;
  default_action: string;
  require_justification_code: boolean;
  require_justification_text: boolean;
  approval_policy_id?: string;
  updated_by?: string;
  updated_at?: string;
};

export type KeyAccessRule = {
  id?: string;
  tenant_id?: string;
  code: string;
  label: string;
  description?: string;
  action: string;
  services: string[];
  operations: string[];
  require_text: boolean;
  approval_policy_id?: string;
  enabled: boolean;
  updated_by?: string;
  updated_at?: string;
};

export type KeyAccessDecision = {
  id: string;
  service: string;
  connector?: string;
  operation: string;
  key_id?: string;
  resource_id?: string;
  requester_id?: string;
  requester_email?: string;
  requester_ip?: string;
  justification_code?: string;
  justification_text?: string;
  decision: string;
  approval_required: boolean;
  approval_request_id?: string;
  matched_code?: string;
  reason?: string;
  bypass_detected: boolean;
  created_at?: string;
};

export type KeyAccessSummary = {
  tenant_id: string;
  enabled: boolean;
  mode: string;
  default_action: string;
  rule_count: number;
  total_requests_24h: number;
  allow_count_24h: number;
  deny_count_24h: number;
  approval_count_24h: number;
  bypass_count_24h: number;
  unjustified_count_24h: number;
  services?: Array<{
    service: string;
    requests_24h: number;
    allow_count_24h: number;
    deny_count_24h: number;
    approval_count_24h: number;
    bypass_count_24h: number;
    unjustified_count_24h: number;
  }>;
};

export async function getKeyAccessSettings(session: AuthSession): Promise<KeyAccessSettings> {
  const out = await serviceRequest<{ settings: KeyAccessSettings }>(session, "keyaccess", `/key-access/settings?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return out.settings;
}

export async function updateKeyAccessSettings(session: AuthSession, input: Partial<KeyAccessSettings>): Promise<KeyAccessSettings> {
  const out = await serviceRequest<{ settings: KeyAccessSettings }>(session, "keyaccess", "/key-access/settings", {
    method: "PUT",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return out.settings;
}

export async function getKeyAccessSummary(session: AuthSession): Promise<KeyAccessSummary> {
  const out = await serviceRequest<{ summary: KeyAccessSummary }>(session, "keyaccess", `/key-access/summary?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return out.summary;
}

export async function listKeyAccessRules(session: AuthSession): Promise<KeyAccessRule[]> {
  const out = await serviceRequest<{ items: KeyAccessRule[] }>(session, "keyaccess", `/key-access/codes?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return Array.isArray(out.items) ? out.items : [];
}

export async function upsertKeyAccessRule(session: AuthSession, input: KeyAccessRule): Promise<KeyAccessRule> {
  const path = input.id ? `/key-access/codes/${encodeURIComponent(input.id)}` : "/key-access/codes";
  const method = input.id ? "PUT" : "POST";
  const out = await serviceRequest<{ rule: KeyAccessRule }>(session, "keyaccess", path, {
    method,
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return out.rule;
}

export async function deleteKeyAccessRule(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "keyaccess", `/key-access/codes/${encodeURIComponent(id)}?tenant_id=${encodeURIComponent(session.tenantId)}`, { method: "DELETE" });
}

export async function listKeyAccessDecisions(
  session: AuthSession,
  opts: { service?: string; action?: string; limit?: number } = {}
): Promise<KeyAccessDecision[]> {
  const params = new URLSearchParams({
    tenant_id: session.tenantId,
    limit: String(opts.limit || 100)
  });
  if (opts.service) params.set("service", opts.service);
  if (opts.action) params.set("action", opts.action);
  const out = await serviceRequest<{ items: KeyAccessDecision[] }>(session, "keyaccess", `/key-access/decisions?${params.toString()}`);
  return Array.isArray(out.items) ? out.items : [];
}
