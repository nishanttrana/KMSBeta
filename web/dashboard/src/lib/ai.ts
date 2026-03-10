import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type ContextSources = {
  keys: { enabled: boolean; limit: number; fields: string[] };
  policies: { enabled: boolean; all: boolean; limit: number };
  audit: { enabled: boolean; last_hours: number; limit: number };
  posture: { enabled: boolean; current: boolean };
  alerts: { enabled: boolean; unresolved: boolean; limit: number };
};

export type ProviderAuthConfig = {
  required: boolean;
  type: "none" | "api_key" | "bearer" | string;
};

export type MCPConfig = {
  enabled: boolean;
  endpoint: string;
};

export type AIConfig = {
  tenant_id: string;
  backend: string;
  endpoint: string;
  model: string;
  api_key_secret: string;
  provider_auth: ProviderAuthConfig;
  mcp: MCPConfig;
  max_context_tokens: number;
  temperature: number;
  context_sources: ContextSources;
  redaction_fields: string[];
  updated_at: string;
};

export type AIConfigUpdate = {
  backend?: string;
  endpoint?: string;
  model?: string;
  api_key_secret?: string;
  provider_auth?: ProviderAuthConfig;
  mcp?: MCPConfig;
  max_context_tokens?: number;
  temperature?: number;
  context_sources?: Partial<ContextSources>;
  redaction_fields?: string[];
};

export type AIResponse = {
  action: string;
  tenant_id: string;
  answer: string;
  backend: string;
  model: string;
  redactions_applied: number;
  context_summary: Record<string, unknown>;
  warnings: string[];
  generated_at: string;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function getAIConfig(session: AuthSession): Promise<AIConfig> {
  const out = await serviceRequest<{ config: AIConfig }>(
    session,
    "ai",
    `/ai/config?${tenantQuery(session)}`
  );
  return out.config;
}

export async function updateAIConfig(
  session: AuthSession,
  update: AIConfigUpdate
): Promise<AIConfig> {
  const out = await serviceRequest<{ config: AIConfig }>(
    session,
    "ai",
    `/ai/config?${tenantQuery(session)}`,
    { method: "PUT", body: JSON.stringify(update) }
  );
  return out.config;
}

export async function queryAI(
  session: AuthSession,
  query: string,
  includeContext = false
): Promise<AIResponse> {
  const out = await serviceRequest<{ result: AIResponse }>(
    session,
    "ai",
    "/ai/query",
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        query,
        include_context: includeContext,
      }),
    }
  );
  return out.result;
}

export async function analyzeIncident(
  session: AuthSession,
  input: { incident_id?: string; title: string; description: string }
): Promise<AIResponse> {
  const out = await serviceRequest<{ result: AIResponse }>(
    session,
    "ai",
    "/ai/analyze/incident",
    {
      method: "POST",
      body: JSON.stringify({ tenant_id: session.tenantId, ...input }),
    }
  );
  return out.result;
}

export async function recommendPosture(
  session: AuthSession,
  focus?: string
): Promise<AIResponse> {
  const out = await serviceRequest<{ result: AIResponse }>(
    session,
    "ai",
    "/ai/recommend/posture",
    {
      method: "POST",
      body: JSON.stringify({ tenant_id: session.tenantId, focus: focus || "" }),
    }
  );
  return out.result;
}

export async function explainPolicy(
  session: AuthSession,
  policyId: string,
  policy?: Record<string, unknown>
): Promise<AIResponse> {
  const out = await serviceRequest<{ result: AIResponse }>(
    session,
    "ai",
    "/ai/explain/policy",
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        policy_id: policyId,
        policy: policy || {},
      }),
    }
  );
  return out.result;
}

export async function checkAIServiceHealth(session: AuthSession): Promise<boolean> {
  try {
    await getAIConfig(session);
    return true;
  } catch {
    return false;
  }
}
