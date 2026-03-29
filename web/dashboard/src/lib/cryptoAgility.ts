import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export interface AlgorithmUsage {
  algorithm: string;
  family: string; // "symmetric", "asymmetric", "hash", "pqc"
  key_count: number;
  cert_count: number;
  ops_last_30d: number;
  pqc_safe: boolean;
  nist_status: "approved" | "deprecated" | "disallowed" | "candidate";
  migration_urgency: "none" | "low" | "medium" | "high" | "critical";
  replacement?: string;
}

export interface MigrationPlan {
  id: string;
  name: string;
  from_algorithm: string;
  to_algorithm: string;
  affected_keys: number;
  completed_keys: number;
  status: "planned" | "in_progress" | "completed" | "paused";
  created_at: string;
  target_date: string;
}

export interface AgilityScore {
  overall: number; // 0-100
  pqc_readiness: number;
  deprecated_ratio: number;
  key_diversity: number;
  last_updated: string;
  by_group: Record<string, number>;
}

export interface KeysByAlgorithm {
  algorithm: string;
  count: number;
  active: number;
  expiring_soon: number;
}

export async function getAgilityScore(session: AuthSession): Promise<AgilityScore> {
  const res = await serviceRequest<any>(session, "keycore", "/agility/score");
  return res.data ?? res;
}

export async function getAlgorithmInventory(session: AuthSession): Promise<AlgorithmUsage[]> {
  const res = await serviceRequest<any>(session, "keycore", "/agility/algorithms");
  return res.data ?? [];
}

export async function getKeysByAlgorithm(session: AuthSession): Promise<KeysByAlgorithm[]> {
  const res = await serviceRequest<any>(session, "keycore", "/agility/keys-by-algorithm");
  return res.data ?? res;
}

export async function listMigrationPlans(session: AuthSession): Promise<MigrationPlan[]> {
  const res = await serviceRequest<any>(session, "keycore", "/agility/migration-plans");
  return res.data ?? [];
}

export async function createMigrationPlan(session: AuthSession, data: Partial<MigrationPlan>): Promise<MigrationPlan> {
  return serviceRequest<MigrationPlan>(session, "keycore", "/agility/migration-plans", { method: "POST", body: JSON.stringify(data) });
}

export async function updateMigrationPlan(session: AuthSession, id: string, data: Partial<MigrationPlan>): Promise<MigrationPlan> {
  return serviceRequest<MigrationPlan>(session, "keycore", `/agility/migration-plans/${id}`, { method: "PATCH", body: JSON.stringify(data) });
}
