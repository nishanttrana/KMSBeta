import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Shapes mirror keycore services/keycore/agility.go. Counts come from the
// tenant's live keys; every status, date and strength comes from
// pkg/cryptocatalog, which cites the NIST table it was copied from.

// SP 800-131A statuses, plus not_approved (no NIST standard approves it) and
// not_tabled (recognised, but the cited drafts give no status).
export type NISTStatus = "acceptable" | "deprecated" | "disallowed" | "legacy_use" | "not_approved" | "not_tabled";

export interface NISTStep {
  from?: string; // YYYY-MM-DD the status applies from; absent = in force now
  status: NISTStatus;
  source: string;
  ref: string;
}

export interface NISTSource {
  id: string;
  label: string;
  title: string;
  revision: "final" | "ipd" | "withdrawn" | string;
  date: string;
  url: string;
}

export interface AlgorithmUsage {
  algorithm: string;
  key_count: number;
  percentage: number;
  assessed: boolean; // false: the name doesn't identify a parameter set
  canonical?: string;
  family?: string;
  security_bits?: number;
  pqc_category?: number;
  quantum_vulnerable: boolean;
  post_quantum: boolean;
  nist_status?: NISTStatus;
  next_change?: NISTStep;
  schedule?: NISTStep[];
  note?: string;
}

export interface TransitionMilestone {
  date: string;
  status: NISTStatus;
  source: string;
  ref: string;
  citation: string;
  key_count: number;
  algorithms: string[];
}

export interface AgilityPosture {
  assessed: boolean; // false when the tenant has no live keys
  as_of: string;
  total_keys: number;
  not_assessed_keys: number;
  quantum_vulnerable_keys: number;
  post_quantum_keys: number;
  status_counts: Partial<Record<NISTStatus, number>>;
  milestones: TransitionMilestone[];
  algorithms: AlgorithmUsage[];
  findings: string[];
  sources: NISTSource[];
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

export async function getAgilityPosture(session: AuthSession): Promise<AgilityPosture> {
  const res = await serviceRequest<{ data: AgilityPosture }>(session, "keycore", "/agility/posture");
  return res.data;
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
