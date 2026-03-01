import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type PostureFinding = {
  id: string;
  tenant_id: string;
  engine: string;
  finding_type: string;
  title: string;
  description: string;
  severity: string;
  risk_score: number;
  recommended_action: string;
  auto_action_allowed: boolean;
  status: string;
  fingerprint: string;
  evidence?: Record<string, unknown>;
  detected_at?: string;
  updated_at?: string;
  resolved_at?: string;
  sla_due_at?: string;
  reopen_count?: number;
};

export type PostureRiskSnapshot = {
  id?: string;
  tenant_id: string;
  risk_24h: number;
  risk_7d: number;
  predictive_score: number;
  preventive_score: number;
  corrective_score: number;
  top_signals?: Record<string, unknown>;
  captured_at?: string;
};

export type PostureAction = {
  id: string;
  tenant_id: string;
  finding_id: string;
  action_type: string;
  recommended_action: string;
  safety_gate: string;
  approval_required: boolean;
  approval_request_id?: string;
  status: string;
  executed_by?: string;
  executed_at?: string;
  evidence?: Record<string, unknown>;
  result_message?: string;
  created_at?: string;
  updated_at?: string;
};

export type PostureDashboard = {
  risk?: PostureRiskSnapshot;
  recent_findings?: PostureFinding[];
  pending_actions?: PostureAction[];
  open_findings?: number;
  critical_findings?: number;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function getPostureDashboard(session: AuthSession): Promise<PostureDashboard> {
  return serviceRequest<PostureDashboard>(session, "posture", `/posture/dashboard?${tenantQuery(session)}`);
}

export async function runPostureScan(session: AuthSession, syncAudit = true): Promise<PostureRiskSnapshot> {
  const out = await serviceRequest<{ risk?: PostureRiskSnapshot }>(
    session,
    "posture",
    `/posture/scan?${tenantQuery(session)}&sync_audit=${syncAudit ? "true" : "false"}`,
    { method: "POST" }
  );
  return out?.risk || ({ tenant_id: session.tenantId } as PostureRiskSnapshot);
}

export async function getPostureRisk(session: AuthSession): Promise<PostureRiskSnapshot> {
  const out = await serviceRequest<{ risk?: PostureRiskSnapshot }>(session, "posture", `/posture/risk?${tenantQuery(session)}`);
  return out?.risk || ({ tenant_id: session.tenantId } as PostureRiskSnapshot);
}

export async function listPostureRiskHistory(session: AuthSession, limit = 50): Promise<PostureRiskSnapshot[]> {
  const out = await serviceRequest<{ items?: PostureRiskSnapshot[] }>(
    session,
    "posture",
    `/posture/risk/history?${tenantQuery(session)}&limit=${Math.max(1, Math.trunc(limit || 50))}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function listPostureFindings(
  session: AuthSession,
  opts: { status?: string; severity?: string; engine?: string; limit?: number; offset?: number } = {}
): Promise<PostureFinding[]> {
  const params = new URLSearchParams();
  params.set("tenant_id", session.tenantId);
  if (String(opts.status || "").trim()) params.set("status", String(opts.status).trim());
  if (String(opts.severity || "").trim()) params.set("severity", String(opts.severity).trim());
  if (String(opts.engine || "").trim()) params.set("engine", String(opts.engine).trim());
  params.set("limit", String(Math.max(1, Math.trunc(opts.limit || 100))));
  params.set("offset", String(Math.max(0, Math.trunc(opts.offset || 0))));
  const out = await serviceRequest<{ items?: PostureFinding[] }>(session, "posture", `/posture/findings?${params.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function updatePostureFindingStatus(
  session: AuthSession,
  findingID: string,
  status: "open" | "acknowledged" | "resolved" | "reopened"
): Promise<void> {
  await serviceRequest(session, "posture", `/posture/findings/${encodeURIComponent(String(findingID || "").trim())}/status?${tenantQuery(session)}`, {
    method: "PUT",
    body: JSON.stringify({ status })
  });
}

export async function listPostureActions(
  session: AuthSession,
  opts: { status?: string; actionType?: string; limit?: number; offset?: number } = {}
): Promise<PostureAction[]> {
  const params = new URLSearchParams();
  params.set("tenant_id", session.tenantId);
  if (String(opts.status || "").trim()) params.set("status", String(opts.status).trim());
  if (String(opts.actionType || "").trim()) params.set("action_type", String(opts.actionType).trim());
  params.set("limit", String(Math.max(1, Math.trunc(opts.limit || 100))));
  params.set("offset", String(Math.max(0, Math.trunc(opts.offset || 0))));
  const out = await serviceRequest<{ items?: PostureAction[] }>(session, "posture", `/posture/actions?${params.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function executePostureAction(
  session: AuthSession,
  actionID: string,
  payload: { actor?: string; approval_request_id?: string } = {}
): Promise<void> {
  await serviceRequest(session, "posture", `/posture/actions/${encodeURIComponent(String(actionID || "").trim())}/execute?${tenantQuery(session)}`, {
    method: "POST",
    body: JSON.stringify({
      actor: String(payload.actor || session.username || "dashboard").trim(),
      approval_request_id: String(payload.approval_request_id || "").trim()
    })
  });
}
