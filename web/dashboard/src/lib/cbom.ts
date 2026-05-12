// CBOM (Cryptographic Bill of Materials) API client.
//
// The endpoints are served by the audit service. The inventory is
// derived from the immutable audit chain so the data is tamper-evident
// by construction — the dashboard does not need to trust any non-audit
// source for crypto-agility reporting.

export type CBOMTier =
  | "classical-128"
  | "classical-192"
  | "classical-256"
  | "pqc-hybrid"
  | "pqc-only"
  | "deprecated";

export interface CBOMEntry {
  algorithm: string;
  parameters?: string;
  key_count: number;
  tier: CBOMTier;
  first_seen_at?: string;
  last_used_at?: string;
  deprecated?: boolean;
  note?: string;
}

export interface CBOMInventory {
  tenant_id: string;
  generated_at: string;
  entries: CBOMEntry[];
  total_keys: number;
  floor_tier?: CBOMTier;
  readiness_percent: number;
}

export interface CBOMDiffResponse {
  target: CBOMTier;
  total_keys: number;
  below_floor: CBOMEntry[];
  ready_percent: number;
  request_id: string;
}

const auditBase = () =>
  (typeof window !== "undefined" && (window as any).__VECTA_AUDIT_BASE__) || "/api/audit";

async function get<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(auditBase() + path, {
    headers: { Accept: "application/json" },
    ...init,
  });
  if (!resp.ok) {
    throw new Error(`CBOM ${path} → HTTP ${resp.status}`);
  }
  return resp.json() as Promise<T>;
}

export async function fetchCBOMInventory(tenantID: string, floor?: CBOMTier): Promise<CBOMInventory> {
  const params = new URLSearchParams({ tenant_id: tenantID });
  if (floor) params.set("floor", floor);
  const data = await get<{ inventory: CBOMInventory; request_id: string }>(
    `/audit/cbom/inventory?${params.toString()}`,
  );
  return data.inventory;
}

export async function fetchCBOMDiff(tenantID: string, target: CBOMTier): Promise<CBOMDiffResponse> {
  const params = new URLSearchParams({ tenant_id: tenantID, target });
  return get<CBOMDiffResponse>(`/audit/cbom/diff?${params.toString()}`);
}
