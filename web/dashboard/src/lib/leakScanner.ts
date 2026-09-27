import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Shapes mirror posture services/posture/leak_scanner.go. Scans read content
// submitted with the scan, or files under the server's LEAK_SCAN_ROOT; remote
// sources are not fetched (the job fails with that reason).

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
  created_at: string;
  findings_count: number;
  error?: string;
  progress_pct: number;
}

export interface LeakFinding {
  id: string;
  job_id: string;
  target_id: string;
  target_name: string;
  severity: FindingSeverity;
  type: string;
  description: string;
  location: string;
  context_preview: string; // redacted by the scanner
  entropy: number;
  status: FindingStatus;
  detected_at: string;
  resolved_at?: string;
  resolved_by?: string; // the verified caller who resolved it
  notes?: string;
}

export async function listTargets(session: AuthSession): Promise<ScanTarget[]> {
  const res = await serviceRequest<{ items: ScanTarget[] }>(session, "posture", "/leaks/targets");
  return res.items ?? [];
}

export async function createTarget(session: AuthSession, data: { name: string; type: ScanTargetType; uri: string; enabled: boolean }): Promise<ScanTarget> {
  const res = await serviceRequest<{ target: ScanTarget }>(session, "posture", "/leaks/targets", { method: "POST", body: JSON.stringify(data) });
  return res.target;
}

export async function deleteTarget(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "posture", `/leaks/targets/${encodeURIComponent(id)}`, { method: "DELETE" });
}

// triggerScan queues a scan. With content, that text is scanned; without it,
// the target's files under LEAK_SCAN_ROOT are.
export async function triggerScan(session: AuthSession, targetId: string, content?: { content: string; filename: string }): Promise<ScanJob> {
  const res = await serviceRequest<{ job: ScanJob }>(session, "posture", `/leaks/targets/${encodeURIComponent(targetId)}/scan`, {
    method: "POST",
    ...(content ? { body: JSON.stringify(content) } : {}),
  });
  return res.job;
}

export async function listJobs(session: AuthSession): Promise<ScanJob[]> {
  const res = await serviceRequest<{ items: ScanJob[] }>(session, "posture", "/leaks/jobs");
  return res.items ?? [];
}

export async function listFindings(session: AuthSession): Promise<LeakFinding[]> {
  const res = await serviceRequest<{ items: LeakFinding[] }>(session, "posture", "/leaks/findings");
  return res.items ?? [];
}

export async function updateFinding(session: AuthSession, id: string, data: { status: FindingStatus; notes?: string }): Promise<void> {
  await serviceRequest(session, "posture", `/leaks/findings/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(data) });
}
