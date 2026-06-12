import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type FFStage =
  | "received"
  | "classified"
  | "validated"
  | "policy_ok"
  | "dryrun_ok"
  | "tested_ok"
  | "staged"
  | "awaiting_prod"
  | "deployed_prod"
  | "rejected"
  | "failed";

export type FFMode = "config" | "scaffold";

export type FFCatalogAction = {
  name: string;
  summary: string;
  required_params: Record<string, string>;
  requires_quorum: boolean;
  sensitive: boolean;
  applier: string;
};

export type FFIntent = {
  id: string;
  tenant_id: string;
  actor: string;
  raw_text: string;
  mode: FFMode;
  stage: FFStage;
  action: string;
  params: Record<string, unknown>;
  confidence: number;
  reasons: string[];
  mcp_job_id?: string;
  approval_id?: string;
  created_at: string;
  updated_at: string;
};

export type FFEvent = {
  intent_id: string;
  tenant_id: string;
  actor: string;
  action: string;
  stage: FFStage;
  outcome: string;
  detail: string;
  timestamp: string;
};

export type FFApproval = {
  intent_id: string;
  tenant_id: string;
  approver: string;
  comment?: string;
  created_at: string;
};

export type FFIntentResponse = {
  intent: FFIntent;
  trail: FFEvent[];
  approvals?: FFApproval[];
  request_id?: string;
};

export async function listFFCatalog(session: AuthSession): Promise<FFCatalogAction[]> {
  const r = await serviceRequest<{ actions: FFCatalogAction[] }>(session, "featureforge", "/catalog");
  return r?.actions || [];
}

export async function listFFIntents(session: AuthSession, tenantId: string): Promise<FFIntent[]> {
  const r = await serviceRequest<{ intents: FFIntent[] }>(
    session,
    "featureforge",
    `/intents?tenant_id=${encodeURIComponent(tenantId)}`
  );
  return r?.intents || [];
}

export async function submitFFIntent(
  session: AuthSession,
  tenantId: string,
  actor: string,
  text: string
): Promise<FFIntentResponse> {
  return serviceRequest<FFIntentResponse>(session, "featureforge", "/intents", {
    method: "POST",
    body: JSON.stringify({ tenant_id: tenantId, actor, text })
  });
}

export async function getFFIntent(session: AuthSession, id: string): Promise<FFIntentResponse> {
  return serviceRequest<FFIntentResponse>(session, "featureforge", `/intents/${encodeURIComponent(id)}`);
}

export async function approveFFIntent(
  session: AuthSession,
  id: string,
  actor: string,
  comment = ""
): Promise<FFIntentResponse> {
  return serviceRequest<FFIntentResponse>(session, "featureforge", `/intents/${encodeURIComponent(id)}/approve`, {
    method: "POST",
    body: JSON.stringify({ actor, comment })
  });
}

export async function promoteFFIntent(session: AuthSession, id: string, actor = ""): Promise<FFIntentResponse> {
  return serviceRequest<FFIntentResponse>(session, "featureforge", `/intents/${encodeURIComponent(id)}/promote`, {
    method: "POST",
    body: JSON.stringify({ actor })
  });
}
