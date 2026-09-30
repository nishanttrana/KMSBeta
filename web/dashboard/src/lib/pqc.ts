import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type InventoryBreakdown = {
  total: number;
  classical: number;
  hybrid: number;
  pqc_only: number;
  algorithms?: Record<string, number>;
};

export type ClassicalUsageItem = {
  asset_type: string;
  asset_id: string;
  name: string;
  algorithm: string;
  location: string;
  qsl_score: number;
  reason: string;
};

export type CertificatePQCItem = {
  cert_id: string;
  subject_cn: string;
  algorithm: string;
  cert_class: string;
  status: string;
  not_after?: string;
  migration_state: string;
};

// Keys and certificates counted by the algorithm each actually has; there is
// no score. Listeners are the external listeners as certs measured them by
// handshake; interfaces says whether that measurement was available.
export type PQCInventory = {
  tenant_id: string;
  generated_at: string;
  keys: InventoryBreakdown;
  certificates: InventoryBreakdown;
  interfaces: "measured" | "not_measured" | "unavailable";
  listeners: {
    name: string;
    accepted_groups: string[] | null;
    negotiated_group: string;
    measured_at: string;
    classification: "classical" | "hybrid" | "not_assessed";
    quantum_vulnerable_groups: string[] | null;
  }[];
  classical_usage: ClassicalUsageItem[];
  non_migrated_certificates: CertificatePQCItem[];
  recommendations: string[];
};

export type PQCAssetRisk = {
  asset_id: string;
  asset_type: string;
  name: string;
  source: string;
  algorithm: string;
  classification: string;
  qsl_score: number;
  migration_target: string;
  priority: number;
  reason: string;
};

export type PQCReadinessScan = {
  id: string;
  tenant_id: string;
  status: string;
  total_assets: number;
  pqc_ready_assets: number;
  hybrid_assets: number;
  classical_assets: number;
  average_qsl: number;
  algorithm_summary: Record<string, number>;
  risk_items: PQCAssetRisk[];
  created_at?: string;
  completed_at?: string;
};

// A customer migration plan's deadline; standard is the plan's own label.
export type PQCTimelineMilestone = {
  id: string;
  standard: string;
  title: string;
  due_date: string;
  status: "upcoming" | "due_within_year" | "overdue" | "met" | string;
  days_left: number;
  affected_assets: number; // steps still open
  description: string; // algorithms still to migrate
};

export type PQCMigrationReport = {
  tenant_id: string;
  generated_at: string;
  inventory: PQCInventory;
  latest_readiness: PQCReadinessScan;
  timeline: PQCTimelineMilestone[];
  top_risks: PQCAssetRisk[];
  next_actions: string[];
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function getPQCInventory(session: AuthSession): Promise<PQCInventory> {
  const out = await serviceRequest<{ inventory: PQCInventory }>(session, "pqc", `/pqc/inventory?${tenantQuery(session)}`);
  return (out?.inventory || {}) as PQCInventory;
}

export async function getPQCMigrationReport(session: AuthSession): Promise<PQCMigrationReport> {
  const out = await serviceRequest<{ report: PQCMigrationReport }>(session, "pqc", `/pqc/migration/report?${tenantQuery(session)}`);
  return (out?.report || {}) as PQCMigrationReport;
}

export async function getPQCReadiness(session: AuthSession): Promise<PQCReadinessScan> {
  const out = await serviceRequest<{ readiness: PQCReadinessScan }>(session, "pqc", `/pqc/readiness?${tenantQuery(session)}`);
  return (out?.readiness || {}) as PQCReadinessScan;
}

export async function runPQCScan(session: AuthSession, trigger = "manual"): Promise<PQCReadinessScan> {
  const out = await serviceRequest<{ scan: PQCReadinessScan }>(session, "pqc", "/pqc/scan", {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, trigger })
  });
  return (out?.scan || {}) as PQCReadinessScan;
}

// Migration plans built from the latest readiness scan. Executing one changes
// keys in keycore (a successor key of the target algorithm per key step);
// certificate, TLS and code steps are manual. The pqc service records the
// verified caller as the actor.
export type PQCMigrationStep = {
  id: string;
  asset_id: string;
  asset_type: string;
  name: string;
  current_algorithm: string;
  target_algorithm: string;
  phase: string;
  status: string; // pending, algorithm_changed (same key ID), successor_created, rotated, manual_required, failed, rolled_back
  reason: string;
  metadata?: Record<string, unknown>;
  executed_at?: string;
  executed_by?: string;
};

export type PQCMigrationPlan = {
  id: string;
  name: string;
  status: string;
  target_profile: string;
  timeline_standard: string;
  deadline?: string;
  summary: Record<string, unknown>;
  steps: PQCMigrationStep[];
  created_by: string;
  created_at: string;
  executed_at?: string;
};

export type PQCMigrationRun = {
  id: string;
  plan_id: string;
  status: string;
  dry_run: boolean;
  summary: Record<string, unknown>;
};

export async function listPQCPlans(session: AuthSession): Promise<PQCMigrationPlan[]> {
  const out = await serviceRequest<{ items: PQCMigrationPlan[] }>(session, "pqc", `/pqc/migration/plans?tenant_id=${encodeURIComponent(session.tenantId)}&limit=50`);
  return out?.items ?? [];
}

export async function createPQCPlan(session: AuthSession, input: { name: string; deadline?: string; timeline_standard?: string }): Promise<PQCMigrationPlan> {
  const out = await serviceRequest<{ plan: PQCMigrationPlan }>(session, "pqc", "/pqc/migration/plans", {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return out.plan;
}

export async function executePQCPlan(session: AuthSession, id: string, dryRun: boolean): Promise<PQCMigrationRun> {
  const out = await serviceRequest<{ run: PQCMigrationRun }>(session, "pqc", `/pqc/migration/plans/${encodeURIComponent(id)}/execute`, {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, dry_run: dryRun })
  });
  return out.run;
}

export async function rollbackPQCPlan(session: AuthSession, id: string): Promise<PQCMigrationPlan> {
  const out = await serviceRequest<{ plan: PQCMigrationPlan }>(session, "pqc", `/pqc/migration/plans/${encodeURIComponent(id)}/rollback`, {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId })
  });
  return out.plan;
}
