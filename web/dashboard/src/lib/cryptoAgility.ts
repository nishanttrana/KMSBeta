import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Shapes mirror keycore services/keycore/agility.go. Counts come from the
// tenant's live keys, technical facts (strength, quantum vulnerability,
// weakness) from pkg/cryptocatalog, and every status and date from the
// tenant's own migration policy rules. The product sets no dates.

export type PolicyAction = "deprecated" | "decrypt_only" | "disallowed";
export type PolicyStatus = "allowed" | PolicyAction;
export type MatchKind = "algorithm" | "family" | "quantum_vulnerable" | "weak" | "below_strength";

export interface AgilityRule {
  id: string;
  name: string;
  match_kind: MatchKind;
  match_value?: string;
  action: PolicyAction;
  effective_date: string;
  target_algorithm?: string;
  note?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export interface NewAgilityRule {
  name: string;
  match_kind: MatchKind;
  match_value?: string;
  action: PolicyAction;
  effective_date: string; // YYYY-MM-DD
  target_algorithm?: string;
  note?: string;
}

export interface PolicyChange {
  date: string;
  action: PolicyAction;
  rule_id: string;
  rule_name: string;
  target_algorithm?: string;
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
  weak: boolean;
  note?: string;
  policy_status: PolicyStatus;
  policy_rule?: string;
  target_algorithm?: string;
  next_change?: PolicyChange;
}

export interface PolicyMilestone extends PolicyChange {
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
  weak_keys: number;
  uncovered_keys: number; // weak or quantum-vulnerable with no rule
  policy_rules: number;
  min_algorithm_tier?: string;
  status_counts: Partial<Record<PolicyStatus, number>>;
  milestones: PolicyMilestone[];
  algorithms: AlgorithmUsage[];
  findings: string[];
}

// ruleCovers mirrors keycore's AgilityRule.matches for previewing a rule.
export function ruleCovers(rule: Pick<NewAgilityRule, "match_kind" | "match_value">, a: AlgorithmUsage): boolean {
  const v = String(rule.match_value || "").trim().toUpperCase();
  switch (rule.match_kind) {
    case "algorithm": return a.algorithm.toUpperCase() === v || String(a.canonical || "").toUpperCase() === v;
    case "family": return a.assessed && String(a.family || "").toUpperCase() === v;
    case "quantum_vulnerable": return a.assessed && a.quantum_vulnerable;
    case "weak": return a.assessed && a.weak;
    case "below_strength": {
      const n = Number(v);
      return a.assessed && Number.isFinite(n) && (a.security_bits ?? 0) > 0 && (a.security_bits ?? 0) < n;
    }
  }
  return false;
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

export async function listAgilityRules(session: AuthSession): Promise<AgilityRule[]> {
  const res = await serviceRequest<{ data: AgilityRule[] }>(session, "keycore", "/agility/policy/rules");
  return res.data ?? [];
}

export async function createAgilityRule(session: AuthSession, rule: NewAgilityRule): Promise<AgilityRule> {
  const res = await serviceRequest<{ data: AgilityRule }>(session, "keycore", "/agility/policy/rules", { method: "POST", body: JSON.stringify(rule) });
  return res.data;
}

export async function updateAgilityRule(session: AuthSession, id: string, rule: NewAgilityRule): Promise<AgilityRule> {
  const res = await serviceRequest<{ data: AgilityRule }>(session, "keycore", `/agility/policy/rules/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(rule) });
  return res.data;
}

export async function deleteAgilityRule(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "keycore", `/agility/policy/rules/${encodeURIComponent(id)}`, { method: "DELETE" });
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
