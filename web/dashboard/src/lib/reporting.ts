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
  audit_event_id?: string;
  resolved_at?: string;
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
    from?: string;
    to?: string;
    bucket_seconds?: number;
    series?: Array<{ start: string; count: number }>;
    generated_at?: string;
  };
};

type MTTRResponse = {
  mttr_minutes?: Record<string, number>;
};

type MTTDResponse = {
  mttd_minutes?: Record<string, number>;
  measured?: number;
  truncated?: boolean;
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
  expression?: string;
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

// Filters of GET /alerts. The drill-down ones (actor_id, source_ip, service,
// resolved, linked, from/to) select exactly the alerts a chart segment counts.
export type AlertListQuery = {
  status?: string;
  severity?: string;
  actor_id?: string;
  source_ip?: string;
  service?: string;
  resolved?: boolean;
  linked?: boolean;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
};

// A chart window: RFC 3339 bounds; no from means since the first alert.
export type StatsWindow = { from?: string; to?: string };

const windowQuery = (session: AuthSession, w?: StatsWindow) => {
  const q = new URLSearchParams(tenantQuery(session));
  if (w?.from) q.set("from", w.from);
  if (w?.to) q.set("to", w.to);
  return q.toString();
};

export async function listReportingAlerts(
  session: AuthSession,
  options?: AlertListQuery
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
  for (const k of ["actor_id", "source_ip", "service", "from", "to"] as const) {
    if (String(options?.[k] || "").trim()) q.set(k, String(options?.[k]).trim());
  }
  if (options?.resolved) q.set("resolved", "true");
  if (options?.linked) q.set("linked", "true");
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
  session: AuthSession,
  window?: StatsWindow
): Promise<{
  total: number; by_severity: Record<string, number>; by_status: Record<string, number>; daily_trend: Record<string, number>;
  from: string; to: string; bucket_seconds: number; series: Array<{ start: string; count: number }>;
}> {
  const out = await serviceRequest<AlertStatsResponse>(session, "reporting", `/alerts/stats?${windowQuery(session, window)}`);
  const stats = out?.stats || {};
  return {
    total: Math.max(0, Number(stats.total || 0)),
    by_severity: stats.by_severity && typeof stats.by_severity === "object" ? stats.by_severity : {},
    by_status: stats.by_status && typeof stats.by_status === "object" ? stats.by_status : {},
    daily_trend: stats.daily_trend && typeof stats.daily_trend === "object" ? stats.daily_trend : {},
    from: String(stats.from || ""),
    to: String(stats.to || ""),
    bucket_seconds: Number(stats.bucket_seconds || 0),
    series: Array.isArray(stats.series) ? stats.series : []
  };
}

export async function getReportingMTTR(session: AuthSession, window?: StatsWindow): Promise<Record<string, number>> {
  const out = await serviceRequest<MTTRResponse>(session, "reporting", `/alerts/stats/mttr?${windowQuery(session, window)}`);
  return out?.mttr_minutes && typeof out.mttr_minutes === "object" ? out.mttr_minutes : {};
}

// MTTD looks up each alert's audit event, so it measures at most the newest
// 5000 alerts in the window; truncated says the window held more.
export async function getReportingMTTD(session: AuthSession, window?: StatsWindow): Promise<{ minutes: Record<string, number>; measured: number; truncated: boolean }> {
  const out = await serviceRequest<MTTDResponse>(session, "reporting", `/alerts/stats/mttd?${windowQuery(session, window)}`);
  return {
    minutes: out?.mttd_minutes && typeof out.mttd_minutes === "object" ? out.mttd_minutes : {},
    measured: Number(out?.measured || 0),
    truncated: Boolean(out?.truncated)
  };
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

// RuleCheck is reporting's answer to POST /alerts/rules/test: the rule is
// validated, decided for one event, and replayed over recent audit events,
// without being saved.
export type RuleCheck = {
  valid: boolean;
  error?: string;
  event?: { action: string; matched: boolean; fires_now: boolean; in_window?: number };
  replay?: {
    hours: number; from: string; to: string; events_scanned: number; matched: number; fired: number;
    truncated: boolean; basis: string;
    samples: { event_id: string; action: string; actor_id: string; timestamp: string }[];
  };
  replay_error?: string;
};

export async function testReportingRule(
  session: AuthSession,
  rule: ReportingAlertRule,
  opts: { event?: Record<string, unknown>; replayHours?: number } = {}
): Promise<RuleCheck> {
  const out = await serviceRequest<{ result: RuleCheck }>(session, "reporting", `/alerts/rules/test?${tenantQuery(session)}`, {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, rule, event: opts.event, replay_hours: opts.replayHours ?? 24 })
  });
  return out.result;
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

export async function updateReportingRule(session: AuthSession, ruleID: string, rule: Partial<ReportingAlertRule>): Promise<void> {
  await serviceRequest(session, "reporting", `/alerts/rules/${encodeURIComponent(ruleID)}?${tenantQuery(session)}`, {
    method: "PUT",
    body: JSON.stringify({ ...rule, tenant_id: session.tenantId })
  });
}

export async function deleteReportingRule(session: AuthSession, ruleID: string): Promise<void> {
  await serviceRequest(session, "reporting", `/alerts/rules/${encodeURIComponent(ruleID)}?${tenantQuery(session)}`, {
    method: "DELETE"
  });
}

// The acting user is the signed-in caller; reporting takes it from the token.
export async function acknowledgeAlert(session: AuthSession, alertID: string): Promise<void> {
  await serviceRequest(session, "reporting", `/alerts/${encodeURIComponent(String(alertID || "").trim())}/acknowledge?${tenantQuery(session)}`, {
    method: "PUT"
  });
}

export async function acknowledgeAlertsBulk(
  session: AuthSession,
  input?: {
    ids?: string[];
    severity?: string;
    status?: string;
    action?: string;
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

export async function getReportingTopSources(session: AuthSession, window?: StatsWindow): Promise<TopSourcesResponse> {
  const out = await serviceRequest<TopSourcesResponse>(
    session,
    "reporting",
    `/alerts/stats/top-sources?${windowQuery(session, window)}`
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
    filters?: Record<string, unknown>;
  }
): Promise<ReportJob> {
  // The requester is the signed-in caller; reporting takes it from the token.
  const out = await serviceRequest<JobsResponse>(session, "reporting", `/reports/generate?${tenantQuery(session)}`, {
    method: "POST",
    body: JSON.stringify({
      template_id: String(input?.template_id || "").trim(),
      format: String(input?.format || "pdf").trim().toLowerCase(),
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

export async function deleteReportingReportJob(session: AuthSession, jobID: string): Promise<void> {
  const id = encodeURIComponent(String(jobID || "").trim());
  await serviceRequest(session, "reporting", `/reports/jobs/${id}?${tenantQuery(session)}`, {
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
    filters?: Record<string, unknown>;
  }
): Promise<ScheduledReport> {
  const out = await serviceRequest<ScheduledResponse>(session, "reporting", `/reports/scheduled?${tenantQuery(session)}`, {
    method: "POST",
    body: JSON.stringify({
      name: String(input?.name || "").trim() || "scheduled-report",
      template_id: String(input?.template_id || "").trim(),
      format: String(input?.format || "pdf").trim().toLowerCase(),
      schedule: String(input?.schedule || "daily").trim().toLowerCase(),
      filters: input?.filters && typeof input.filters === "object" ? input.filters : {}
    })
  });
  if (!out?.item) {
    throw new Error("Scheduled report was not returned by reporting service.");
  }
  return out.item;
}
