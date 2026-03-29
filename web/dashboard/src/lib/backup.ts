import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export interface BackupPolicy {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  scope: "all_keys" | "critical_keys" | "tagged";
  tag_filter: string;
  cron_expr: string;
  retention_days: number;
  encrypt_backup: boolean;
  compress: boolean;
  destination: "local" | "s3" | "gcs" | "azure_blob";
  destination_uri: string;
  enabled: boolean;
  last_run_at?: string;
  next_run_at?: string;
  created_at: string;
}

export interface BackupRun {
  id: string;
  tenant_id: string;
  policy_id?: string;
  policy_name?: string;
  status: "running" | "completed" | "failed" | "partial";
  scope: string;
  total_keys: number;
  backed_up_keys: number;
  failed_keys: number;
  backup_size_bytes: number;
  destination: string;
  destination_path: string;
  triggered_by: "manual" | "schedule";
  started_at: string;
  completed_at?: string;
  error?: string;
}

export interface RestorePoint {
  id: string;
  tenant_id: string;
  run_id: string;
  name: string;
  key_count: number;
  backup_size_bytes: number;
  created_at: string;
  expires_at?: string;
  checksum: string;
  status: "available" | "restoring" | "expired" | "deleted";
}

export interface BackupMetrics {
  total_policies: number;
  last_backup_at?: string;
  last_backup_status: string;
  total_restore_points: number;
  total_backup_size_bytes: number;
  success_rate_30d: number;
  avg_backup_duration_seconds: number;
}

export async function listPolicies(session: AuthSession): Promise<BackupPolicy[]> {
  const res = await serviceRequest<any>(session, "backup", "/backup/policies");
  return res.items ?? [];
}

export async function createPolicy(session: AuthSession, data: Partial<BackupPolicy>): Promise<BackupPolicy> {
  return serviceRequest<BackupPolicy>(session, "backup", "/backup/policies", { method: "POST", body: JSON.stringify(data) });
}

export async function updatePolicy(session: AuthSession, id: string, data: Partial<BackupPolicy>): Promise<BackupPolicy> {
  return serviceRequest<BackupPolicy>(session, "backup", `/backup/policies/${id}`, { method: "PATCH", body: JSON.stringify(data) });
}

export async function deletePolicy(session: AuthSession, id: string): Promise<void> {
  return serviceRequest<void>(session, "backup", `/backup/policies/${id}`, { method: "DELETE" });
}

export async function triggerBackup(session: AuthSession, policyId: string): Promise<BackupRun> {
  return serviceRequest<BackupRun>(session, "backup", `/backup/policies/${policyId}/trigger`, { method: "POST" });
}

export async function listRuns(session: AuthSession): Promise<BackupRun[]> {
  const res = await serviceRequest<any>(session, "backup", "/backup/runs");
  return res.items ?? [];
}

export async function getRun(session: AuthSession, id: string): Promise<BackupRun> {
  return serviceRequest<BackupRun>(session, "backup", `/backup/runs/${id}`);
}

export async function listRestorePoints(session: AuthSession): Promise<RestorePoint[]> {
  const res = await serviceRequest<any>(session, "backup", "/backup/restore-points");
  return res.items ?? [];
}

export async function restoreFromPoint(session: AuthSession, pointId: string): Promise<{ job_id: string }> {
  return serviceRequest<{ job_id: string }>(session, "backup", `/backup/restore-points/${pointId}/restore`, { method: "POST" });
}

export async function getMetrics(session: AuthSession): Promise<BackupMetrics> {
  const res = await serviceRequest<any>(session, "backup", "/backup/metrics");
  return res.metrics ?? res;
}
