import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Shapes mirror keycore services/keycore/rotation.go. A policy rotates the
// tenant's active keys that match target_filter: now on a trigger (as the
// caller), and on schedule when auto_rotate is set (on the primary).

export interface RotationPolicy {
  id: string;
  tenant_id: string;
  name: string;
  target_type: "key";
  target_filter: string; // "*", "tag:<tag>", "id:<key id>" or a key-name glob
  interval_days: number;
  auto_rotate: boolean;
  last_rotation_at?: string;
  next_rotation_at?: string;
  enabled: boolean;
  created_at: string;
  total_rotations: number;
  status: "active" | "error";
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
  status: "success" | "failed";
  error?: string;
  triggered_by: string; // "schedule" or "manual:<actor>"
}

export interface UpcomingRotation {
  policy_id: string;
  policy_name: string;
  target_type: string;
  scheduled_at: string;
  days_until: number;
  overdue: boolean;
}

export interface RotationOutcome {
  matched: number;
  rotated: number;
  failed: number;
  runs: RotationRun[];
}

export interface RotationPolicyInput {
  name: string;
  target_filter: string;
  interval_days: number;
  auto_rotate: boolean;
}

export async function listPolicies(session: AuthSession): Promise<RotationPolicy[]> {
  const res = await serviceRequest<{ items: RotationPolicy[] }>(session, "keycore", "/rotation/policies");
  return res.items ?? [];
}

export async function createPolicy(session: AuthSession, data: RotationPolicyInput): Promise<RotationPolicy> {
  const res = await serviceRequest<{ policy: RotationPolicy }>(session, "keycore", "/rotation/policies", { method: "POST", body: JSON.stringify(data) });
  return res.policy;
}

export async function updatePolicy(session: AuthSession, id: string, data: Partial<RotationPolicyInput> & { enabled?: boolean }): Promise<RotationPolicy> {
  const res = await serviceRequest<{ policy: RotationPolicy }>(session, "keycore", `/rotation/policies/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(data) });
  return res.policy;
}

export async function deletePolicy(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "keycore", `/rotation/policies/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function triggerRotation(session: AuthSession, policyId: string): Promise<RotationOutcome> {
  const res = await serviceRequest<{ outcome: RotationOutcome }>(session, "keycore", `/rotation/policies/${encodeURIComponent(policyId)}/trigger`, { method: "POST" });
  return res.outcome;
}

export async function listRuns(session: AuthSession, policyId?: string): Promise<RotationRun[]> {
  const q = policyId ? `?policy_id=${encodeURIComponent(policyId)}` : "";
  const res = await serviceRequest<{ items: RotationRun[] }>(session, "keycore", `/rotation/runs${q}`);
  return res.items ?? [];
}

export async function listUpcoming(session: AuthSession): Promise<UpcomingRotation[]> {
  const res = await serviceRequest<{ items: UpcomingRotation[] }>(session, "keycore", "/rotation/upcoming");
  return res.items ?? [];
}
