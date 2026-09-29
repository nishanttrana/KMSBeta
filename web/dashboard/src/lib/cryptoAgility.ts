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

// ---- Crypto agility risk assessment (CARAF), keycore /agility/caraf ----
// Every input is the customer's: threats with the years they expect each
// (Z), assets with shelf life (X), migration time (Y), cost and the keys they
// use. Keycore computes exposure (X + Y against the soonest threat) and
// tracks the decision recorded for each asset.

export type CarafTimeline = "exposed" | "at_limit" | "time_to_spare" | "not_assessed" | "no_threat";
export type CarafDecisionKind = "secure" | "accept" | "phase_out" | "compensating_control";

export interface CarafThreat {
  id: string;
  name: string;
  category: "quantum" | "cryptanalytic" | "regulatory" | "business" | "other";
  match_kind: MatchKind;
  match_value?: string;
  years_to_threat: number;
  note?: string;
}
export type NewCarafThreat = Omit<CarafThreat, "id">;

export interface CarafDecision {
  decision?: CarafDecisionKind;
  owner?: string;
  due?: string;
  review_by?: string;
  status?: "open" | "in_progress" | "done";
  note?: string;
  decided_by?: string;
  decided_at?: string;
}

export interface CarafAsset {
  id: string;
  name: string;
  description?: string;
  owner?: string;
  ownership: string;
  implementation: string;
  pqc_support: string;
  location: string;
  jurisdiction?: string;
  sensitivity: string;
  shelf_life_years?: number;
  migration_years?: number;
  cost: string;
  algorithms: string[];
  key_ids: string[];
  decision: CarafDecision;
}
export type NewCarafAsset = Omit<CarafAsset, "id" | "decision">;

export interface CarafAssetAssessment {
  asset: CarafAsset;
  algorithms: string[];
  missing_keys: string[];
  threats: { id: string; name: string; years_to_threat: number; algorithms: string[] }[];
  x?: number;
  y?: number;
  z?: number;
  timeline: CarafTimeline;
  margin_years?: number;
  missing: string[];
  suggestion?: "secure" | "accept" | "phase_out";
  decision_state: string; // undecided, accepted, acceptance_expired, open, in_progress, done, overdue
}

export interface CarafAssessment {
  as_of: string;
  summary: {
    assets: number; threats: number; exposed: number; at_limit: number; time_to_spare: number;
    not_assessed: number; no_threat: number; undecided_at_risk: number; overdue: number; acceptance_expired: number;
  };
  // Assets carrying each part of their profile ("unknown" is not counted).
  profile: { owner: number; shelf_life: number; migration_time: number; cost: number; sensitivity: number; live_keys: number; complete: number };
  // Assets by sensitivity, then timeline.
  heatmap: Record<string, Record<string, number>>;
  assets: CarafAssetAssessment[];
  roadmap: { asset_id: string; asset: string; decision: CarafDecisionKind; owner: string; date: string; state: string }[];
  findings: string[];
}

export async function getCarafAssessment(session: AuthSession): Promise<CarafAssessment> {
  const res = await serviceRequest<{ data: CarafAssessment }>(session, "keycore", "/agility/caraf/assessment");
  return res.data;
}

export async function listCarafThreats(session: AuthSession): Promise<CarafThreat[]> {
  const res = await serviceRequest<{ data: CarafThreat[] }>(session, "keycore", "/agility/caraf/threats");
  return res.data ?? [];
}

export async function saveCarafThreat(session: AuthSession, threat: NewCarafThreat, id?: string): Promise<CarafThreat> {
  const path = id ? `/agility/caraf/threats/${encodeURIComponent(id)}` : "/agility/caraf/threats";
  const res = await serviceRequest<{ data: CarafThreat }>(session, "keycore", path, { method: id ? "PUT" : "POST", body: JSON.stringify(threat) });
  return res.data;
}

export async function deleteCarafThreat(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "keycore", `/agility/caraf/threats/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function saveCarafAsset(session: AuthSession, asset: NewCarafAsset, id?: string): Promise<CarafAsset> {
  const path = id ? `/agility/caraf/assets/${encodeURIComponent(id)}` : "/agility/caraf/assets";
  const res = await serviceRequest<{ data: CarafAsset }>(session, "keycore", path, { method: id ? "PUT" : "POST", body: JSON.stringify(asset) });
  return res.data;
}

export async function deleteCarafAsset(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "keycore", `/agility/caraf/assets/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function setCarafDecision(session: AuthSession, id: string, decision: CarafDecision): Promise<CarafAsset> {
  const res = await serviceRequest<{ data: CarafAsset }>(session, "keycore", `/agility/caraf/assets/${encodeURIComponent(id)}/decision`, { method: "PUT", body: JSON.stringify(decision) });
  return res.data;
}

// ---- Algorithm-swap drill (services/keycore/agility_drill.go) ----
// A real rehearsal on a keycore node: throwaway keys from keycore's own key
// generation, checked round trips through the key engine, medians in µs.

export interface DrillMeasure {
  algorithm: string;
  operation: "sign_verify" | "encrypt_decrypt" | "encapsulate_decapsulate";
  keygen_us: number;
  operation_us: number;
  check_us: number;
  private_key_bytes: number;
  public_key_bytes?: number;
  output_bytes: number;
  round_trips: number;
}

export interface AgilityDrill {
  id: string;
  from: DrillMeasure;
  to: DrillMeasure;
  iterations: number;
  result: "passed" | "failed";
  error?: string;
  comparison: { keygen_ratio: number; operation_ratio: number; check_ratio: number; output_bytes_diff: number; public_key_bytes_diff: number };
  run_by: string;
  created_at: string;
}

export async function listAgilityDrills(session: AuthSession): Promise<AgilityDrill[]> {
  const res = await serviceRequest<{ items: AgilityDrill[] }>(session, "keycore", "/agility/drills");
  return res.items ?? [];
}

export async function runAgilityDrill(session: AuthSession, req: { from_algorithm: string; to_algorithm: string; iterations: number }): Promise<AgilityDrill> {
  const res = await serviceRequest<{ data: AgilityDrill }>(session, "keycore", "/agility/drills", { method: "POST", body: JSON.stringify(req) });
  return res.data;
}
