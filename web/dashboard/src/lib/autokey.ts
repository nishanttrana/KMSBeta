import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type AutokeySettings = {
  tenant_id: string;
  enabled: boolean;
  mode: string;
  require_approval: boolean;
  require_justification: boolean;
  allow_template_override: boolean;
  default_policy_id?: string;
  default_rotation_days: number;
  updated_by?: string;
  updated_at?: string;
};

export type AutokeyTemplate = {
  id: string;
  tenant_id: string;
  name: string;
  service_name: string;
  resource_type: string;
  handle_name_pattern: string;
  key_name_pattern: string;
  algorithm: string;
  key_type: string;
  purpose: string;
  export_allowed: boolean;
  iv_mode: string;
  tags: string[];
  labels: Record<string, string>;
  ops_limit: number;
  ops_limit_window: string;
  approval_required: boolean;
  approval_policy_id?: string;
  description?: string;
  enabled: boolean;
  updated_by?: string;
  updated_at?: string;
};

export type AutokeyServicePolicy = {
  tenant_id: string;
  service_name: string;
  display_name?: string;
  default_template_id?: string;
  algorithm?: string;
  key_type?: string;
  purpose?: string;
  export_allowed: boolean;
  iv_mode?: string;
  tags: string[];
  labels: Record<string, string>;
  ops_limit: number;
  ops_limit_window?: string;
  approval_required: boolean;
  approval_policy_id?: string;
  enforce_policy: boolean;
  description?: string;
  enabled: boolean;
  updated_by?: string;
  updated_at?: string;
};

export type AutokeyRequest = {
  id: string;
  tenant_id: string;
  service_name: string;
  resource_type: string;
  resource_ref: string;
  template_id?: string;
  requester_id?: string;
  requester_email?: string;
  requester_ip?: string;
  justification?: string;
  requested_algorithm?: string;
  requested_key_type?: string;
  requested_purpose?: string;
  handle_name?: string;
  key_name?: string;
  status: string;
  approval_required: boolean;
  governance_request_id?: string;
  handle_id?: string;
  key_id?: string;
  policy_matched: boolean;
  policy_mismatch_reason?: string;
  resolved_spec?: Record<string, unknown>;
  failure_reason?: string;
  created_at?: string;
  updated_at?: string;
  fulfilled_at?: string;
};

export type AutokeyHandle = {
  id: string;
  tenant_id: string;
  service_name: string;
  resource_type: string;
  resource_ref: string;
  handle_name: string;
  key_id: string;
  template_id?: string;
  request_id?: string;
  status: string;
  managed: boolean;
  policy_matched: boolean;
  spec?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
};

export type AutokeySummary = {
  tenant_id: string;
  enabled: boolean;
  mode: string;
  template_count: number;
  service_policy_count: number;
  handle_count: number;
  pending_approvals: number;
  provisioned_24h: number;
  denied_count: number;
  failed_count: number;
  policy_matched_count: number;
  policy_mismatch_count: number;
  services: Array<{
    service_name: string;
    handle_count: number;
    pending_approvals: number;
    provisioned_24h: number;
    policy_mismatch_count: number;
  }>;
};

export type CreateAutokeyRequestInput = {
  tenant_id?: string;
  service_name: string;
  resource_type: string;
  resource_ref: string;
  template_id?: string;
  handle_name?: string;
  key_name?: string;
  requested_algorithm?: string;
  requested_key_type?: string;
  requested_purpose?: string;
  tags?: string[];
  labels?: Record<string, string>;
  justification?: string;
  requester_id?: string;
  requester_email?: string;
  requester_ip?: string;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function getAutokeySettings(session: AuthSession): Promise<AutokeySettings> {
  const out = await serviceRequest<{ settings: AutokeySettings }>(session, "autokey", `/autokey/settings?${tenantQuery(session)}`);
  return (out?.settings || {}) as AutokeySettings;
}

export async function updateAutokeySettings(session: AuthSession, input: Partial<AutokeySettings>): Promise<AutokeySettings> {
  const out = await serviceRequest<{ settings: AutokeySettings }>(session, "autokey", `/autokey/settings?${tenantQuery(session)}`, {
    method: "PUT",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return (out?.settings || {}) as AutokeySettings;
}

export async function getAutokeySummary(session: AuthSession): Promise<AutokeySummary> {
  const out = await serviceRequest<{ summary: AutokeySummary }>(session, "autokey", `/autokey/summary?${tenantQuery(session)}`);
  return (out?.summary || {}) as AutokeySummary;
}

export async function listAutokeyTemplates(session: AuthSession): Promise<AutokeyTemplate[]> {
  const out = await serviceRequest<{ items: AutokeyTemplate[] }>(session, "autokey", `/autokey/templates?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function upsertAutokeyTemplate(session: AuthSession, input: Partial<AutokeyTemplate>): Promise<AutokeyTemplate> {
  const id = String(input?.id || "").trim();
  const path = id ? `/autokey/templates/${encodeURIComponent(id)}` : "/autokey/templates";
  const out = await serviceRequest<{ template: AutokeyTemplate }>(session, "autokey", path, {
    method: id ? "PUT" : "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return (out?.template || {}) as AutokeyTemplate;
}

export async function deleteAutokeyTemplate(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "autokey", `/autokey/templates/${encodeURIComponent(String(id || "").trim())}?${tenantQuery(session)}`, {
    method: "DELETE"
  });
}

export async function listAutokeyServicePolicies(session: AuthSession): Promise<AutokeyServicePolicy[]> {
  const out = await serviceRequest<{ items: AutokeyServicePolicy[] }>(session, "autokey", `/autokey/service-policies?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function upsertAutokeyServicePolicy(session: AuthSession, input: Partial<AutokeyServicePolicy>): Promise<AutokeyServicePolicy> {
  const serviceName = String(input?.service_name || "").trim();
  const path = serviceName ? `/autokey/service-policies/${encodeURIComponent(serviceName)}` : "/autokey/service-policies";
  const out = await serviceRequest<{ policy: AutokeyServicePolicy }>(session, "autokey", path, {
    method: serviceName ? "PUT" : "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return (out?.policy || {}) as AutokeyServicePolicy;
}

export async function deleteAutokeyServicePolicy(session: AuthSession, serviceName: string): Promise<void> {
  await serviceRequest(session, "autokey", `/autokey/service-policies/${encodeURIComponent(String(serviceName || "").trim())}?${tenantQuery(session)}`, {
    method: "DELETE"
  });
}

export async function createAutokeyRequest(session: AuthSession, input: CreateAutokeyRequestInput): Promise<AutokeyRequest> {
  const out = await serviceRequest<{ request: AutokeyRequest }>(session, "autokey", "/autokey/requests", {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return (out?.request || {}) as AutokeyRequest;
}

export async function listAutokeyRequests(session: AuthSession, options?: { status?: string; limit?: number }): Promise<AutokeyRequest[]> {
  const params = new URLSearchParams();
  params.set("tenant_id", session.tenantId);
  if (options?.status) params.set("status", String(options.status));
  if (options?.limit) params.set("limit", String(options.limit));
  const out = await serviceRequest<{ items: AutokeyRequest[] }>(session, "autokey", `/autokey/requests?${params.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getAutokeyRequest(session: AuthSession, id: string): Promise<AutokeyRequest> {
  const out = await serviceRequest<{ request: AutokeyRequest }>(session, "autokey", `/autokey/requests/${encodeURIComponent(String(id || "").trim())}?${tenantQuery(session)}`);
  return (out?.request || {}) as AutokeyRequest;
}

export async function listAutokeyHandles(session: AuthSession, options?: { service_name?: string; limit?: number }): Promise<AutokeyHandle[]> {
  const params = new URLSearchParams();
  params.set("tenant_id", session.tenantId);
  if (options?.service_name) params.set("service_name", String(options.service_name));
  if (options?.limit) params.set("limit", String(options.limit));
  const out = await serviceRequest<{ items: AutokeyHandle[] }>(session, "autokey", `/autokey/handles?${params.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}
