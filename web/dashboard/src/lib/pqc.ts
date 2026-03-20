import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type PQCPolicy = {
  tenant_id: string;
  profile_id: string;
  default_kem: string;
  default_signature: string;
  interface_default_mode: "classical" | "hybrid" | "pqc_only" | string;
  certificate_default_mode: "classical" | "hybrid" | "pqc_only" | string;
  hqc_backup_enabled: boolean;
  flag_classical_usage: boolean;
  flag_classical_certificates: boolean;
  flag_non_migrated_interfaces: boolean;
  require_pqc_for_new_keys: boolean;
  updated_by?: string;
  updated_at?: string;
};

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

export type InterfacePQCItem = {
  interface_name: string;
  description: string;
  bind_address: string;
  port: number;
  protocol: string;
  pqc_mode: string;
  effective_pqc_mode: string;
  enabled: boolean;
  status: string;
  certificate_source: string;
  ca_id?: string;
  certificate_id?: string;
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

export type PQCInventory = {
  tenant_id: string;
  generated_at: string;
  policy: PQCPolicy;
  readiness_score: number;
  quantum_readiness_percent: number;
  keys: InventoryBreakdown;
  certificates: InventoryBreakdown;
  interfaces: InventoryBreakdown;
  classical_usage: ClassicalUsageItem[];
  non_migrated_interfaces: InterfacePQCItem[];
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
  readiness_score: number;
  algorithm_summary: Record<string, number>;
  risk_items: PQCAssetRisk[];
  created_at?: string;
  completed_at?: string;
};

export type PQCTimelineMilestone = {
  id: string;
  standard: string;
  title: string;
  due_date: string;
  status: string;
  days_left: number;
  description: string;
};

export type PQCMigrationReport = {
  tenant_id: string;
  generated_at: string;
  policy: PQCPolicy;
  inventory: PQCInventory;
  latest_readiness: PQCReadinessScan;
  timeline: PQCTimelineMilestone[];
  top_risks: PQCAssetRisk[];
  next_actions: string[];
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function getPQCPolicy(session: AuthSession): Promise<PQCPolicy> {
  const out = await serviceRequest<{ policy: PQCPolicy }>(session, "pqc", `/pqc/policy?${tenantQuery(session)}`);
  return (out?.policy || {}) as PQCPolicy;
}

export async function updatePQCPolicy(session: AuthSession, input: Partial<PQCPolicy>): Promise<PQCPolicy> {
  const out = await serviceRequest<{ policy: PQCPolicy }>(session, "pqc", `/pqc/policy?${tenantQuery(session)}`, {
    method: "PUT",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return (out?.policy || {}) as PQCPolicy;
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
