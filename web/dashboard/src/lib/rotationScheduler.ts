import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export interface RotationPolicy {
  id: string;
  tenant_id: string;
  name: string;
  target_type: "key" | "secret" | "certificate";
  target_filter: string; // tag selector or glob
  interval_days: number;
  cron_expr?: string;
  auto_rotate: boolean;
  notify_days_before: number;
  last_rotation_at?: string;
  next_rotation_at: string;
  enabled: boolean;
  created_at: string;
  total_rotations: number;
  status: "active" | "paused" | "error";
  last_error?: string;
}

export interface RotationRun {
  id: string;
  policy_id: string;
  policy_name: string;
  target_id: string;
  target_name: string;
  target_type: string;
  started_at: string;
  completed_at?: string;
  status: "running" | "success" | "failed" | "skipped";
  error?: string;
  triggered_by: "schedule" | "manual" | "expiry";
}

export interface UpcomingRotation {
  policy_id: string;
  policy_name: string;
  target_id: string;
  target_name: string;
  target_type: string;
  scheduled_at: string;
  days_until: number;
  overdue: boolean;
}

export async function listPolicies(session: AuthSession): Promise<RotationPolicy[]> {
  const res = await serviceRequest<any>(session, "keycore", "/rotation/policies");
  return res.items ?? [];
}

export async function createPolicy(session: AuthSession, data: Partial<RotationPolicy>): Promise<RotationPolicy> {
  return serviceRequest<RotationPolicy>(session, "keycore", "/rotation/policies", { method: "POST", body: JSON.stringify(data) });
}

export async function updatePolicy(session: AuthSession, id: string, data: Partial<RotationPolicy>): Promise<RotationPolicy> {
  return serviceRequest<RotationPolicy>(session, "keycore", `/rotation/policies/${id}`, { method: "PATCH", body: JSON.stringify(data) });
}

export async function deletePolicy(session: AuthSession, id: string): Promise<void> {
  return serviceRequest<void>(session, "keycore", `/rotation/policies/${id}`, { method: "DELETE" });
}

export async function triggerRotation(session: AuthSession, policyId: string): Promise<RotationRun> {
  return serviceRequest<RotationRun>(session, "keycore", `/rotation/policies/${policyId}/trigger`, { method: "POST" });
}

export async function listRuns(session: AuthSession, policyId?: string): Promise<RotationRun[]> {
  const q = policyId ? `?policy_id=${policyId}` : "";
  const res = await serviceRequest<any>(session, "keycore", `/rotation/runs${q}`);
  return res.items ?? [];
}

export async function listUpcoming(session: AuthSession): Promise<UpcomingRotation[]> {
  const res = await serviceRequest<any>(session, "keycore", "/rotation/upcoming");
  return res.items ?? [];
}
