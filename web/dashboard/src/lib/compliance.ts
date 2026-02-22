import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type AssessmentFinding = {
  id: string;
  severity: string;
  title: string;
  fix: string;
  count: number;
};

export type AssessmentResult = {
  id: string;
  tenant_id: string;
  trigger: string;
  overall_score: number;
  framework_scores: Record<string, number>;
  findings: AssessmentFinding[];
  pqc: {
    ready_percent: number;
    ml_kem_migrated: number;
    ml_dsa_migrated: number;
    pending: number;
    total_evaluated: number;
  };
  cert_metrics: Record<string, number>;
  posture: any;
  created_at: string;
};

export type AssessmentSchedule = {
  tenant_id: string;
  enabled: boolean;
  frequency: "daily" | "hourly" | "weekly";
  last_run_at?: string;
  next_run_at?: string;
  updated_at?: string;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function getComplianceAssessment(session: AuthSession): Promise<AssessmentResult> {
  const out = await serviceRequest<{ assessment?: AssessmentResult }>(session, "compliance", `/compliance/assessment?${tenantQuery(session)}`);
  return out?.assessment || ({} as AssessmentResult);
}

export async function runComplianceAssessment(session: AuthSession): Promise<AssessmentResult> {
  const out = await serviceRequest<{ assessment?: AssessmentResult }>(session, "compliance", `/compliance/assessment/run?${tenantQuery(session)}`, {
    method: "POST"
  });
  return out?.assessment || ({} as AssessmentResult);
}

export async function listComplianceAssessmentHistory(session: AuthSession, limit = 20): Promise<AssessmentResult[]> {
  const out = await serviceRequest<{ items?: AssessmentResult[] }>(
    session,
    "compliance",
    `/compliance/assessment/history?${tenantQuery(session)}&limit=${Math.max(1, Math.trunc(limit || 20))}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getComplianceAssessmentSchedule(session: AuthSession): Promise<AssessmentSchedule> {
  const out = await serviceRequest<{ schedule?: AssessmentSchedule }>(session, "compliance", `/compliance/assessment/schedule?${tenantQuery(session)}`);
  return (
    out?.schedule || {
      tenant_id: session.tenantId,
      enabled: false,
      frequency: "daily"
    }
  );
}

export async function updateComplianceAssessmentSchedule(
  session: AuthSession,
  payload: Pick<AssessmentSchedule, "enabled" | "frequency">
): Promise<AssessmentSchedule> {
  const out = await serviceRequest<{ schedule?: AssessmentSchedule }>(session, "compliance", "/compliance/assessment/schedule", {
    method: "PUT",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      enabled: Boolean(payload.enabled),
      frequency: payload.frequency || "daily"
    })
  });
  return (
    out?.schedule || {
      tenant_id: session.tenantId,
      enabled: Boolean(payload.enabled),
      frequency: (payload.frequency || "daily") as "daily" | "hourly" | "weekly"
    }
  );
}
