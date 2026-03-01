import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type ReportingAlert = {
  id: string;
  tenant_id: string;
  audit_action: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  service: string;
  actor_id?: string;
  target_id?: string;
  status: string;
  source_ip?: string;
  actor_type?: string;
  target_type?: string;
  created_at?: string;
  updated_at?: string;
};

type AlertsResponse = {
  items: ReportingAlert[];
};

type UnreadResponse = {
  counts?: Record<string, number>;
};

type AlertStatsResponse = {
  stats?: {
    total?: number;
    by_severity?: Record<string, number>;
    by_status?: Record<string, number>;
    daily_trend?: Record<string, number>;
    generated_at?: string;
  };
};

type MTTRResponse = {
  mttr_minutes?: Record<string, number>;
};

type ChannelsResponse = {
  items?: Array<{
    tenant_id: string;
    name: string;
    enabled: boolean;
    config?: Record<string, unknown>;
    updated_at?: string;
  }>;
};

export type ReportingAlertRule = {
  id?: string;
  tenant_id?: string;
  name: string;
  condition?: string;
  severity: string;
  event_pattern: string;
  threshold: number;
  window_seconds: number;
  channels: string[];
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
};

type RulesResponse = {
  items?: ReportingAlertRule[];
  item?: ReportingAlertRule;
};

export type ReportTemplate = {
  id: string;
  name: string;
  description: string;
  formats: string[];
};

export type ReportJob = {
  id: string;
  tenant_id: string;
  template_id: string;
  format: string;
  status: string;
  filters?: Record<string, unknown>;
  requested_by?: string;
  error?: string;
  result_content_type?: string;
  created_at?: string;
  updated_at?: string;
  completed_at?: string;
};

export type ScheduledReport = {
  id: string;
  tenant_id: string;
  name: string;
  template_id: string;
  format: string;
  schedule: string;
  recipients: string[];
  enabled: boolean;
  last_run_at?: string;
  next_run_at?: string;
  created_at?: string;
  updated_at?: string;
};

type TemplatesResponse = {
  items?: ReportTemplate[];
};

type JobsResponse = {
  items?: ReportJob[];
  job?: ReportJob;
};

type ScheduledResponse = {
  items?: ScheduledReport[];
  item?: ScheduledReport;
};

type ReportDownloadResponse = {
  content?: string;
  content_type?: string;
  template_id?: string;
  generated_at?: string;
  report_job_id?: string;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function listReportingAlerts(
  session: AuthSession,
  options?: {
    status?: string;
    severity?: string;
    limit?: number;
    offset?: number;
  }
): Promise<ReportingAlert[]> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  q.set("limit", String(Math.max(1, Math.min(500, Math.trunc(Number(options?.limit || 100))))));
  q.set("offset", String(Math.max(0, Math.trunc(Number(options?.offset || 0)))));
  if (String(options?.status || "").trim()) {
    q.set("status", String(options?.status || "").trim().toLowerCase());
  }
  if (String(options?.severity || "").trim()) {
    q.set("severity", String(options?.severity || "").trim().toLowerCase());
  }
  const out = await serviceRequest<AlertsResponse>(session, "reporting", `/alerts?${q.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getUnreadAlertCounts(
  session: AuthSession,
  options?: { skipGlobalLoading?: boolean }
): Promise<Record<string, number>> {
  const out = await serviceRequest<UnreadResponse>(session, "reporting", `/alerts/unread?${tenantQuery(session)}`, {
    skipGlobalLoading: Boolean(options?.skipGlobalLoading)
  });
  return out?.counts && typeof out.counts === "object" ? out.counts : {};
}

export async function getReportingAlertStats(
  session: AuthSession
): Promise<{ total: number; by_severity: Record<string, number>; by_status: Record<string, number>; daily_trend: Record<string, number> }> {
  const out = await serviceRequest<AlertStatsResponse>(session, "reporting", `/alerts/stats?${tenantQuery(session)}`);
  const stats = out?.stats || {};
  return {
    total: Math.max(0, Number(stats.total || 0)),
    by_severity: stats.by_severity && typeof stats.by_severity === "object" ? stats.by_severity : {},
    by_status: stats.by_status && typeof stats.by_status === "object" ? stats.by_status : {},
    daily_trend: stats.daily_trend && typeof stats.daily_trend === "object" ? stats.daily_trend : {}
  };
}

export async function getReportingMTTR(session: AuthSession): Promise<Record<string, number>> {
  const out = await serviceRequest<MTTRResponse>(session, "reporting", `/alerts/stats/mttr?${tenantQuery(session)}`);
  return out?.mttr_minutes && typeof out.mttr_minutes === "object" ? out.mttr_minutes : {};
}

export async function listReportingChannels(
  session: AuthSession
): Promise<Array<{ tenant_id: string; name: string; enabled: boolean; config?: Record<string, unknown>; updated_at?: string }>> {
  const out = await serviceRequest<ChannelsResponse>(session, "reporting", `/alerts/channels?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function listReportingRules(session: AuthSession): Promise<ReportingAlertRule[]> {
  const out = await serviceRequest<RulesResponse>(session, "reporting", `/alerts/rules?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createReportingRule(session: AuthSession, rule: ReportingAlertRule): Promise<ReportingAlertRule> {
  const out = await serviceRequest<RulesResponse>(session, "reporting", `/alerts/rules?${tenantQuery(session)}`, {
    method: "POST",
    body: JSON.stringify({
      ...rule,
      tenant_id: session.tenantId
    })
  });
  return out?.item || (out?.items && out.items[0]) || { ...rule, tenant_id: session.tenantId };
}

export async function acknowledgeAlert(session: AuthSession, alertID: string, actor?: string): Promise<void> {
  await serviceRequest(session, "reporting", `/alerts/${encodeURIComponent(String(alertID || "").trim())}/acknowledge?${tenantQuery(session)}`, {
    method: "PUT",
    body: JSON.stringify({
      actor: String(actor || session.username || "dashboard").trim() || "dashboard"
    })
  });
}

export async function acknowledgeAlertsBulk(
  session: AuthSession,
  input?: {
    ids?: string[];
    severity?: string;
    status?: string;
    action?: string;
    actor?: string;
    note?: string;
  }
): Promise<number> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  if (String(input?.severity || "").trim()) {
    q.set("severity", String(input?.severity || "").trim().toLowerCase());
  }
  if (String(input?.status || "").trim()) {
    q.set("status", String(input?.status || "").trim().toLowerCase());
  }
  if (String(input?.action || "").trim()) {
    q.set("action", String(input?.action || "").trim().toLowerCase());
  }
  const out = await serviceRequest<{ updated?: number }>(session, "reporting", `/alerts/bulk/acknowledge?${q.toString()}`, {
    method: "POST",
    body: JSON.stringify({
      ids: Array.isArray(input?.ids)
        ? input?.ids.map((value) => String(value || "").trim()).filter(Boolean)
        : [],
      actor: String(input?.actor || session.username || "dashboard").trim() || "dashboard",
      note: String(input?.note || "").trim()
    })
  });
  return Math.max(0, Number(out?.updated || 0));
}

export async function escalateAlert(session: AuthSession, alertID: string, severity?: string): Promise<void> {
  await serviceRequest(session, "reporting", `/alerts/${encodeURIComponent(String(alertID || "").trim())}/escalate?${tenantQuery(session)}`, {
    method: "PUT",
    body: JSON.stringify({
      severity: String(severity || "critical").trim().toLowerCase()
    })
  });
}

export type TopSourcesResponse = {
  top_actors?: Array<{ key: string; count: number }>;
  top_ips?: Array<{ key: string; count: number }>;
  top_services?: Array<{ key: string; count: number }>;
};

export async function getReportingTopSources(session: AuthSession): Promise<TopSourcesResponse> {
  const out = await serviceRequest<TopSourcesResponse>(
    session,
    "reporting",
    `/alerts/stats/top-sources?${tenantQuery(session)}`
  );
  return {
    top_actors: Array.isArray(out?.top_actors) ? out.top_actors : [],
    top_ips: Array.isArray(out?.top_ips) ? out.top_ips : [],
    top_services: Array.isArray(out?.top_services) ? out.top_services : []
  };
}

export async function listReportingReportTemplates(session: AuthSession): Promise<ReportTemplate[]> {
  const out = await serviceRequest<TemplatesResponse>(session, "reporting", "/reports/templates");
  return Array.isArray(out?.items) ? out.items : [];
}

export async function generateReportingReport(
  session: AuthSession,
  input: {
    template_id: string;
    format: string;
    requested_by?: string;
    filters?: Record<string, unknown>;
  }
): Promise<ReportJob> {
  const out = await serviceRequest<JobsResponse>(session, "reporting", "/reports/generate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      template_id: String(input?.template_id || "").trim(),
      format: String(input?.format || "pdf").trim().toLowerCase(),
      requested_by: String(input?.requested_by || session.username || "dashboard").trim() || "dashboard",
      filters: input?.filters && typeof input.filters === "object" ? input.filters : {}
    })
  });
  if (!out?.job) {
    throw new Error("Report job was not returned by reporting service.");
  }
  return out.job;
}

export async function getReportingReportJob(session: AuthSession, id: string): Promise<ReportJob> {
  const out = await serviceRequest<JobsResponse>(
    session,
    "reporting",
    `/reports/jobs/${encodeURIComponent(String(id || "").trim())}?${tenantQuery(session)}`
  );
  if (!out?.job) {
    throw new Error("Report job not found.");
  }
  return out.job;
}

export async function listReportingReportJobs(session: AuthSession, limit = 50, offset = 0): Promise<ReportJob[]> {
  const out = await serviceRequest<JobsResponse>(
    session,
    "reporting",
    `/reports/jobs?${tenantQuery(session)}&limit=${Math.max(1, Math.min(500, Math.trunc(Number(limit || 50))))}&offset=${Math.max(0, Math.trunc(Number(offset || 0)))}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function downloadReportingReport(
  session: AuthSession,
  jobID: string
): Promise<{
  content: string;
  content_type: string;
  template_id?: string | undefined;
  generated_at?: string | undefined;
  report_job_id?: string | undefined;
}> {
  const out = await serviceRequest<ReportDownloadResponse>(
    session,
    "reporting",
    `/reports/jobs/${encodeURIComponent(String(jobID || "").trim())}/download?${tenantQuery(session)}`
  );
  return {
    content: String(out?.content || ""),
    content_type: String(out?.content_type || "application/octet-stream"),
    template_id: out?.template_id,
    generated_at: out?.generated_at,
    report_job_id: out?.report_job_id
  };
}

export async function deleteReportingReportJob(session: AuthSession, jobID: string, actor?: string): Promise<void> {
  const id = encodeURIComponent(String(jobID || "").trim());
  const actorID = encodeURIComponent(String(actor || session.username || "dashboard").trim() || "dashboard");
  await serviceRequest(session, "reporting", `/reports/jobs/${id}?${tenantQuery(session)}&actor=${actorID}`, {
    method: "DELETE"
  });
}

export async function listReportingScheduledReports(session: AuthSession): Promise<ScheduledReport[]> {
  const out = await serviceRequest<ScheduledResponse>(session, "reporting", `/reports/scheduled?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createReportingScheduledReport(
  session: AuthSession,
  input: {
    name: string;
    template_id: string;
    format: string;
    schedule: "hourly" | "daily" | "weekly";
    recipients: string[];
    filters?: Record<string, unknown>;
  }
): Promise<ScheduledReport> {
  const out = await serviceRequest<ScheduledResponse>(session, "reporting", "/reports/scheduled", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      name: String(input?.name || "").trim() || "scheduled-report",
      template_id: String(input?.template_id || "").trim(),
      format: String(input?.format || "pdf").trim().toLowerCase(),
      schedule: String(input?.schedule || "daily").trim().toLowerCase(),
      recipients: Array.isArray(input?.recipients)
        ? input.recipients.map((value) => String(value || "").trim()).filter(Boolean)
        : [],
      filters: input?.filters && typeof input.filters === "object" ? input.filters : {}
    })
  });
  if (!out?.item) {
    throw new Error("Scheduled report was not returned by reporting service.");
  }
  return out.item;
}
