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
  average_qsl: number;
  posture_score: number;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function startDiscoveryScan(
  session: AuthSession,
  scanTypes: string[] = ["keys", "certificates", "secrets"]
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

export async function classifyAsset(
  session: AuthSession,
  id: string,
  classification: string,
  notes = ""
): Promise<CryptoAsset> {
  const res = await serviceRequest<{ asset?: CryptoAsset }>(
    session,
    "discovery",
    `/discovery/assets/${encodeURIComponent(id)}/classify?${tenantQuery(session)}`,
    {
      method: "PUT",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        classification,
        notes,
      }),
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
  return (
    res?.summary ?? {
      tenant_id: session.tenantId,
      total_assets: 0,
      source_distribution: {},
      algorithm_distribution: {},
      classification_counts: {},
      pqc_ready_count: 0,
      pqc_readiness_percent: 0,
      average_qsl: 0,
      posture_score: 0,
    }
  );
}
