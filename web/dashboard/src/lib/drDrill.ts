import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export interface DrillSchedule {
  id: string;
  name: string;
  cron_expr: string;
  drill_type: "key_restore" | "full_failover" | "partial_restore" | "backup_verify";
  scope: "all_keys" | "critical_keys" | "selected";
  key_ids?: string[];
  target_env: string;
  enabled: boolean;
  last_run_at?: string;
  next_run_at?: string;
  created_at: string;
}

export interface DrillRun {
  id: string;
  schedule_id?: string;
  schedule_name?: string;
  drill_type: string;
  status: "running" | "passed" | "failed" | "partial" | "aborted";
  started_at: string;
  completed_at?: string;
  rto_seconds?: number;
  rpo_seconds?: number;
  total_keys: number;
  restored_keys: number;
  failed_keys: number;
  steps: DrillStep[];
  triggered_by: string;
  report_url?: string;
}

export interface DrillStep {
  name: string;
  status: "pending" | "running" | "passed" | "failed" | "skipped";
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  message?: string;
}

export interface DrillMetrics {
  total_drills: number;
  pass_rate: number;
  avg_rto_seconds: number;
  last_30d_drills: number;
  last_failure_at?: string;
  trend: { date: string; rto: number; status: string }[];
}

export async function listSchedules(session: AuthSession): Promise<DrillSchedule[]> {
  const res = await serviceRequest<any>(session, "keycore", "/dr-drill/schedules");
  return res.data ?? [];
}

export async function createSchedule(session: AuthSession, data: Partial<DrillSchedule>): Promise<DrillSchedule> {
  return serviceRequest<DrillSchedule>(session, "keycore", "/dr-drill/schedules", { method: "POST", body: JSON.stringify(data) });
}

export async function deleteSchedule(session: AuthSession, id: string): Promise<void> {
  return serviceRequest<void>(session, "keycore", `/dr-drill/schedules/${id}`, { method: "DELETE" });
}

export async function triggerDrill(session: AuthSession, scheduleId?: string, type?: string): Promise<DrillRun> {
  const res = await serviceRequest<any>(session, "keycore", "/dr-drill/trigger", {
    method: "POST",
    body: JSON.stringify({ schedule_id: scheduleId, drill_type: type })
  });
  return res.data ?? res;
}

export async function listRuns(session: AuthSession): Promise<DrillRun[]> {
  const res = await serviceRequest<any>(session, "keycore", "/dr-drill/runs");
  return res.data ?? [];
}

export async function getRun(session: AuthSession, id: string): Promise<DrillRun> {
  const res = await serviceRequest<any>(session, "keycore", `/dr-drill/runs/${id}`);
  return res.data ?? res;
}

export async function getMetrics(session: AuthSession): Promise<DrillMetrics> {
  const res = await serviceRequest<any>(session, "keycore", "/dr-drill/metrics");
  return res.data ?? res;
}
