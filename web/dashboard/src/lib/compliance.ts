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
  template_id: string;
  template_name: string;
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

export type ComplianceFrameworkControl = {
  id: string;
  title: string;
  category: string;
  requirement: string;
  weight: number;
  status?: string;
  score?: number;
  evidence?: string;
};

export type ComplianceFramework = {
  id: string;
  name: string;
  version: string;
  description: string;
  controls?: ComplianceFrameworkControl[];
};

export type ComplianceTemplateControl = {
  id: string;
  title: string;
  category: string;
  requirement: string;
  enabled: boolean;
  weight: number;
  threshold: number;
};

export type ComplianceTemplateFramework = {
  framework_id: string;
  label: string;
  enabled: boolean;
  weight: number;
  controls: ComplianceTemplateControl[];
};

export type ComplianceTemplate = {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  enabled: boolean;
  frameworks: ComplianceTemplateFramework[];
  created_at?: string;
  updated_at?: string;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

function queryWithTemplate(session: AuthSession, templateId?: string): string {
  const params = new URLSearchParams();
  params.set("tenant_id", session.tenantId);
  if (String(templateId || "").trim()) {
    params.set("template_id", String(templateId).trim());
  }
  return params.toString();
}

export async function getComplianceAssessment(session: AuthSession, templateId = ""): Promise<AssessmentResult> {
  const out = await serviceRequest<{ assessment?: AssessmentResult }>(
    session,
    "compliance",
    `/compliance/assessment?${queryWithTemplate(session, templateId)}`
  );
  return out?.assessment || ({} as AssessmentResult);
}

export async function runComplianceAssessment(
  session: AuthSession,
  opts: { templateId?: string; recompute?: boolean } = {}
): Promise<AssessmentResult> {
  const out = await serviceRequest<{ assessment?: AssessmentResult }>(
    session,
    "compliance",
    `/compliance/assessment/run?${queryWithTemplate(session, opts.templateId)}`,
    {
      method: "POST",
      body: JSON.stringify({
        template_id: String(opts.templateId || "").trim(),
        recompute: opts.recompute === undefined ? true : Boolean(opts.recompute)
      })
    }
  );
  return out?.assessment || ({} as AssessmentResult);
}

export async function listComplianceAssessmentHistory(session: AuthSession, limit = 20, templateId = ""): Promise<AssessmentResult[]> {
  const out = await serviceRequest<{ items?: AssessmentResult[] }>(
    session,
    "compliance",
    `/compliance/assessment/history?${queryWithTemplate(session, templateId)}&limit=${Math.max(1, Math.trunc(limit || 20))}`
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

export async function listComplianceFrameworkCatalog(session: AuthSession): Promise<ComplianceFramework[]> {
  const out = await serviceRequest<{ items?: ComplianceFramework[] }>(session, "compliance", "/compliance/frameworks");
  return Array.isArray(out?.items) ? out.items : [];
}

export async function listComplianceTemplates(session: AuthSession): Promise<ComplianceTemplate[]> {
  const out = await serviceRequest<{ items?: ComplianceTemplate[] }>(session, "compliance", `/compliance/templates?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getComplianceTemplate(session: AuthSession, templateID: string): Promise<ComplianceTemplate> {
  const out = await serviceRequest<{ template?: ComplianceTemplate }>(
    session,
    "compliance",
    `/compliance/templates/${encodeURIComponent(String(templateID || "").trim())}?${tenantQuery(session)}`
  );
  return out?.template || ({} as ComplianceTemplate);
}

export async function upsertComplianceTemplate(
  session: AuthSession,
  payload: Partial<ComplianceTemplate> & Pick<ComplianceTemplate, "name">
): Promise<ComplianceTemplate> {
  const out = await serviceRequest<{ template?: ComplianceTemplate }>(session, "compliance", `/compliance/templates?${tenantQuery(session)}`, {
    method: "POST",
    body: JSON.stringify({
      ...payload,
      tenant_id: session.tenantId,
      id: String(payload?.id || "").trim(),
      name: String(payload?.name || "").trim(),
      description: String(payload?.description || "").trim(),
      enabled: payload?.enabled !== undefined ? Boolean(payload.enabled) : true,
      frameworks: Array.isArray(payload?.frameworks) ? payload.frameworks : []
    })
  });
  return out?.template || ({} as ComplianceTemplate);
}

export async function deleteComplianceTemplate(session: AuthSession, templateID: string): Promise<void> {
  await serviceRequest(session, "compliance", `/compliance/templates/${encodeURIComponent(String(templateID || "").trim())}?${tenantQuery(session)}`, {
    method: "DELETE"
  });
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

/* ── Posture Breakdown ── */

export type PostureBreakdown = {
  overall_score: number;
  key_hygiene: number;
  policy_compliance: number;
  access_security: number;
  crypto_posture: number;
  pqc_readiness: number;
  framework_scores: Record<string, number>;
  metrics: Record<string, number>;
  gap_count: number;
};

export async function getCompliancePostureBreakdown(session: AuthSession): Promise<PostureBreakdown> {
  const out = await serviceRequest<{ posture?: PostureBreakdown }>(
    session,
    "compliance",
    `/compliance/posture/breakdown?${tenantQuery(session)}`
  );
  return out?.posture || ({} as PostureBreakdown);
}

/* ── Key Hygiene ── */

export type KeyHygieneReport = {
  total_keys: number;
  approved_algorithm_percent: number;
  rotation_coverage_percent: number;
  policy_coverage_percent: number;
  orphaned_count: number;
  expiring_count: number;
  deprecated_count: number;
  pqc_readiness_percent: number;
  algorithm_distribution: Record<string, number>;
  orphaned_keys: any[];
  expiring_keys: any[];
};

export async function getComplianceKeyHygiene(session: AuthSession): Promise<KeyHygieneReport> {
  const out = await serviceRequest<{ report?: KeyHygieneReport }>(
    session,
    "compliance",
    `/compliance/keys/hygiene?${tenantQuery(session)}`
  );
  return out?.report || ({} as KeyHygieneReport);
}

/* ── Framework Gaps ── */

export type ComplianceGap = {
  id: string;
  framework_id: string;
  control_id: string;
  severity: string;
  title: string;
  description: string;
  status: string;
  detected_at?: string;
  resolved_at?: string;
};

export async function getComplianceFrameworkGaps(session: AuthSession, frameworkId: string): Promise<ComplianceGap[]> {
  const out = await serviceRequest<{ items?: ComplianceGap[] }>(
    session,
    "compliance",
    `/compliance/frameworks/${encodeURIComponent(frameworkId)}/gaps?${tenantQuery(session)}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

/* ── Audit Correlations & Anomalies ── */

export type AuditCorrelation = {
  correlation_id: string;
  count: number;
  first_seen: string;
  last_seen: string;
  top_actions: string[];
};

export type AuditAnomaly = {
  id: string;
  type: string;
  severity: string;
  description: string;
  count: number;
  detected_at: string;
};

export async function getComplianceAuditAnomalies(session: AuthSession): Promise<AuditAnomaly[]> {
  const out = await serviceRequest<{ items?: AuditAnomaly[] }>(
    session,
    "compliance",
    `/compliance/audit/anomalies?${tenantQuery(session)}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}
