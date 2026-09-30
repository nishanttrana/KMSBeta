import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type DiscoveryScan = {
  id: string;
  tenant_id: string;
  scan_type: string;
  status: string;
  trigger: string;
  stats: Record<string, unknown>;
  started_at: string;
  completed_at?: string;
  created_at: string;
};

export type CryptoAsset = {
  id: string;
  tenant_id: string;
  scan_id: string;
  asset_type: string;
  name: string;
  location: string;
  source: string;
  algorithm: string;
  strength_bits: number;
  status: string;
  classification: string;
  pqc_ready: boolean;
  qsl_score: number;
  metadata: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
};

export type DiscoverySummary = {
  tenant_id: string;
  total_assets: number;
  source_distribution: Record<string, number>;
  algorithm_distribution: Record<string, number>;
  classification_counts: Record<string, number>;
  pqc_ready_count: number;
  pqc_readiness_percent: number;
};

// A TLS endpoint the tenant added for the network scan.
export type DiscoveryTarget = {
  id: string;
  tenant_id: string;
  host: string;
  port: number;
  created_by: string;
  created_at: string;
};

// Sources a scan can read (services/discovery normalizeScanTypes).
export const DISCOVERY_SCAN_TYPES = ["network", "cloud", "certs", "code"] as const;

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function startDiscoveryScan(
  session: AuthSession,
  scanTypes: string[] = [...DISCOVERY_SCAN_TYPES]
): Promise<DiscoveryScan> {
  const res = await serviceRequest<{ scan?: DiscoveryScan }>(
    session,
    "discovery",
    "/discovery/scan",
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        scan_types: scanTypes,
        trigger: "manual",
      }),
    }
  );
  return res?.scan ?? ({} as DiscoveryScan);
}

export async function listDiscoveryScans(
  session: AuthSession,
  limit = 20
): Promise<DiscoveryScan[]> {
  const res = await serviceRequest<{ items?: DiscoveryScan[] }>(
    session,
    "discovery",
    `/discovery/scans?${tenantQuery(session)}&limit=${limit}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}

export async function getDiscoveryScan(
  session: AuthSession,
  id: string
): Promise<DiscoveryScan> {
  const res = await serviceRequest<{ scan?: DiscoveryScan }>(
    session,
    "discovery",
    `/discovery/scans/${encodeURIComponent(id)}?${tenantQuery(session)}`
  );
  return res?.scan ?? ({} as DiscoveryScan);
}

export async function listDiscoveryAssets(
  session: AuthSession,
  opts: {
    limit?: number;
    source?: string;
    asset_type?: string;
    classification?: string;
  } = {}
): Promise<CryptoAsset[]> {
  const params = new URLSearchParams();
  params.set("tenant_id", session.tenantId);
  if (opts.limit) params.set("limit", String(opts.limit));
  if (opts.source) params.set("source", opts.source);
  if (opts.asset_type) params.set("asset_type", opts.asset_type);
  if (opts.classification) params.set("classification", opts.classification);
  const res = await serviceRequest<{ items?: CryptoAsset[] }>(
    session,
    "discovery",
    `/discovery/assets?${params.toString()}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}

// reviewAsset records an operator review (status, notes). The
// classification is the algorithm catalogue's and can't be changed here.
export async function reviewAsset(
  session: AuthSession,
  id: string,
  status: string,
  notes = ""
): Promise<CryptoAsset> {
  const res = await serviceRequest<{ asset?: CryptoAsset }>(
    session,
    "discovery",
    `/discovery/assets/${encodeURIComponent(id)}/classify?${tenantQuery(session)}`,
    {
      method: "PUT",
      body: JSON.stringify({ tenant_id: session.tenantId, status, notes }),
    }
  );
  return res?.asset ?? ({} as CryptoAsset);
}

export async function getDiscoverySummary(
  session: AuthSession
): Promise<DiscoverySummary> {
  const res = await serviceRequest<{ summary?: DiscoverySummary }>(
    session,
    "discovery",
    `/discovery/summary?${tenantQuery(session)}`
  );
  if (!res?.summary) {
    throw new Error("discovery returned no summary");
  }
  return res.summary;
}

export async function listDiscoveryTargets(session: AuthSession): Promise<DiscoveryTarget[]> {
  const res = await serviceRequest<{ items?: DiscoveryTarget[] }>(
    session,
    "discovery",
    `/discovery/targets?${tenantQuery(session)}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}

export async function addDiscoveryTarget(
  session: AuthSession,
  host: string,
  port: number
): Promise<DiscoveryTarget> {
  const res = await serviceRequest<{ target?: DiscoveryTarget }>(
    session,
    "discovery",
    `/discovery/targets?${tenantQuery(session)}`,
    { method: "POST", body: JSON.stringify({ host, port }) }
  );
  return res?.target ?? ({} as DiscoveryTarget);
}

export async function removeDiscoveryTarget(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(
    session,
    "discovery",
    `/discovery/targets/${encodeURIComponent(id)}?${tenantQuery(session)}`,
    { method: "DELETE" }
  );
}
