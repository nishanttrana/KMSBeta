import type { AuthSession } from "./auth";
import { serviceRequest, serviceRequestRaw } from "./serviceApi";

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

export type AssessmentDelta = {
  latest_assessment_id: string;
  previous_assessment_id?: string;
  latest_score: number;
  previous_score: number;
  score_delta: number;
  summary: string;
  added_findings: Array<{
    title: string;
    severity: string;
    current_count: number;
    previous_count: number;
    delta: number;
  }>;
  resolved_findings: Array<{
    title: string;
    severity: string;
    current_count: number;
    previous_count: number;
    delta: number;
  }>;
  recovered_domains: Array<{
    domain: string;
    label: string;
    current_score: number;
    previous_score: number;
    delta: number;
    status: string;
  }>;
  regressed_domains: Array<{
    domain: string;
    label: string;
    current_score: number;
    previous_score: number;
    delta: number;
    status: string;
  }>;
  new_failing_connectors: Array<{
    connector: string;
    label: string;
    current_fails: number;
    previous_fails: number;
    delta: number;
    last_failure_at?: string;
    status: string;
  }>;
  compared_at?: string;
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

async function parseComplianceError(response: Response): Promise<string> {
  const fallback = `Request failed (${response.status})`;
  try {
    const payload = (await response.json()) as { error?: { message?: string } };
    return payload?.error?.message || fallback;
  } catch {
    return fallback;
  }
}

export async function getComplianceAssessment(session: AuthSession, templateId = ""): Promise<AssessmentResult | null> {
  const response = await serviceRequestRaw(
    session,
    "compliance",
    `/compliance/assessment?${queryWithTemplate(session, templateId)}`
  );
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(await parseComplianceError(response));
  }
  const out = (await response.json()) as { assessment?: AssessmentResult };
  return out?.assessment || null;
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

export async function getComplianceAssessmentDelta(session: AuthSession, templateId = ""): Promise<AssessmentDelta | null> {
  const response = await serviceRequestRaw(
    session,
    "compliance",
    `/compliance/assessment/delta?${queryWithTemplate(session, templateId)}`
  );
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(await parseComplianceError(response));
  }
  const out = (await response.json()) as { delta?: AssessmentDelta };
  return out?.delta || null;
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
  const out = await serviceRequest<{ posture?: PostureBreakdown; breakdown?: PostureBreakdown }>(
    session,
    "compliance",
    `/compliance/posture/breakdown?${tenantQuery(session)}`
  );
  return out?.breakdown || out?.posture || ({} as PostureBreakdown);
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

/* ── Evidence Export ── */

export type EvidenceExportOptions = {
  framework?: string;
  period?: "7d" | "30d" | "90d" | "1y";
};

/**
 * Downloads a compliance evidence report as a JSON file.
 * Triggers a browser download directly.
 */
export async function downloadEvidenceReport(
  session: AuthSession,
  opts: EvidenceExportOptions = {}
): Promise<void> {
  const { serviceRequestRaw } = await import("./serviceApi");
  const params = new URLSearchParams();
  params.set("tenant_id", session.tenantId);
  params.set("framework", opts.framework || "gdpr");
  params.set("period", opts.period || "30d");
  params.set("format", "json");

  const res = await serviceRequestRaw(
    session,
    "compliance",
    `/compliance/evidence/export?${params.toString()}`
  );
  if (!res.ok) {
    throw new Error(`Evidence export failed (${res.status})`);
  }

  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = /filename="([^"]+)"/.exec(disposition);
  const filename = match?.[1] ?? `compliance-evidence-${opts.framework ?? "gdpr"}.json`;

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
