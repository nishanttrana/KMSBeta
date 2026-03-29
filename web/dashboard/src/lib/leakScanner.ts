import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type ScanTargetType = "git_repo" | "container_image" | "log_stream" | "s3_bucket" | "env_file";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "acknowledged" | "resolved" | "false_positive";

export interface ScanTarget {
  id: string;
  name: string;
  type: ScanTargetType;
  uri: string;
  enabled: boolean;
  last_scanned_at?: string;
  created_at: string;
  scan_count: number;
  open_findings: number;
}

export interface ScanJob {
  id: string;
  target_id: string;
  target_name: string;
  target_type: ScanTargetType;
  status: "queued" | "running" | "completed" | "failed";
  started_at?: string;
  completed_at?: string;
  findings_count: number;
  error?: string;
  progress_pct?: number;
}

export interface LeakFinding {
  id: string;
  job_id: string;
  target_id: string;
  target_name: string;
  severity: FindingSeverity;
  type: string; // "aws_access_key", "generic_api_key", "jwt_token", etc.
  description: string;
  location: string; // file path, line number, etc.
  context_preview: string; // redacted snippet
  entropy: number;
  status: FindingStatus;
  detected_at: string;
  resolved_at?: string;
  resolved_by?: string;
  notes?: string;
}

export async function listTargets(session: AuthSession): Promise<ScanTarget[]> {
  const res = await serviceRequest<any>(session, "posture", "/leaks/targets");
  return res.items ?? [];
}

export async function createTarget(session: AuthSession, data: Partial<ScanTarget>): Promise<ScanTarget> {
  return serviceRequest<ScanTarget>(session, "posture", "/leaks/targets", { method: "POST", body: JSON.stringify(data) });
}

export async function deleteTarget(session: AuthSession, id: string): Promise<void> {
  return serviceRequest<void>(session, "posture", `/leaks/targets/${id}`, { method: "DELETE" });
}

export async function triggerScan(session: AuthSession, targetId: string): Promise<ScanJob> {
  return serviceRequest<ScanJob>(session, "posture", `/leaks/targets/${targetId}/scan`, { method: "POST" });
}

export async function listJobs(session: AuthSession): Promise<ScanJob[]> {
  const res = await serviceRequest<any>(session, "posture", "/leaks/jobs");
  return res.items ?? [];
}

export async function listFindings(session: AuthSession, params?: { status?: FindingStatus; severity?: FindingSeverity }): Promise<LeakFinding[]> {
  const q = new URLSearchParams();
  if (params?.status) q.set("status", params.status);
  if (params?.severity) q.set("severity", params.severity);
  const res = await serviceRequest<any>(session, "posture", `/leaks/findings?${q}`);
  return res.items ?? [];
}

export async function updateFinding(session: AuthSession, id: string, data: { status: FindingStatus; notes?: string }): Promise<LeakFinding> {
  return serviceRequest<LeakFinding>(session, "posture", `/leaks/findings/${id}`, { method: "PATCH", body: JSON.stringify(data) });
}

// Aliases for tab compatibility
export const listLeakTargets = listTargets;
export const addLeakTarget = createTarget;
export const deleteLeakTarget = deleteTarget;
export const triggerLeakScan = triggerScan;
export const listLeakFindings = listFindings;
export const listLeakJobs = listJobs;
export const resolveLeakFinding = updateFinding;
