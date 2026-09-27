import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Shapes mirror keycore services/keycore/agility.go. Every figure is computed
// server-side from the tenant's live keys; nothing here is estimated.

export interface AlgorithmUsage {
  algorithm: string;
  key_count: number;
  percentage: number;
  is_legacy: boolean;
  is_quantum_safe: boolean;
}

export interface AgilityScore {
  assessed: boolean; // false when the tenant has no live keys: nothing to score
  score: number; // 0-100
  grade: string; // A-F
  quantum_readiness: number; // % of live keys on quantum-safe algorithms
  legacy_key_count: number;
  total_keys: number;
  algorithms: AlgorithmUsage[];
  recommendations: string[];
}

export type MigrationPlanStatus = "planned" | "in_progress" | "paused" | "completed";

export interface MigrationPlan {
  id: string;
  name: string;
  from_algorithm: string;
  to_algorithm: string;
  affected_keys: number; // live from_algorithm keys when the plan was created
  completed_keys: number; // derived from the keys table
  remaining_keys: number; // live from_algorithm keys now
  status: MigrationPlanStatus;
  created_at: string;
  target_date?: string;
}

export async function getAgilityScore(session: AuthSession): Promise<AgilityScore> {
  const res = await serviceRequest<{ data: AgilityScore }>(session, "keycore", "/agility/score");
  return res.data;
}

export async function getAlgorithmInventory(session: AuthSession): Promise<AlgorithmUsage[]> {
  const res = await serviceRequest<{ data: AlgorithmUsage[] }>(session, "keycore", "/agility/algorithms");
  return res.data ?? [];
}

export async function listMigrationPlans(session: AuthSession): Promise<MigrationPlan[]> {
  const res = await serviceRequest<{ data: MigrationPlan[] }>(session, "keycore", "/agility/migration-plans");
  return res.data ?? [];
}

export interface NewMigrationPlan {
  name: string;
  from_algorithm: string;
  to_algorithm: string;
  target_date?: string; // YYYY-MM-DD
}

export async function createMigrationPlan(
  session: AuthSession,
  data: NewMigrationPlan,
): Promise<MigrationPlan> {
  const res = await serviceRequest<{ data: MigrationPlan }>(session, "keycore", "/agility/migration-plans", { method: "POST", body: JSON.stringify(data) });
  return res.data;
}

export async function updateMigrationPlanStatus(session: AuthSession, id: string, status: MigrationPlanStatus): Promise<MigrationPlan> {
  const res = await serviceRequest<{ data: MigrationPlan }>(session, "keycore", `/agility/migration-plans/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ status }) });
  return res.data;
}
