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

// An endpoint the tenant added for the network scan: a host, IP or CIDR
// range (at most 256 addresses), probed over TLS or SSH.
export type DiscoveryTarget = {
  id: string;
  tenant_id: string;
  host: string;
  port: number;
  protocol?: "tls" | "ssh";
  created_by: string;
  created_at: string;
};

// What each scan source has to read, and its last scan (GET /discovery/sources).
export type DiscoverySource = {
  id: string;
  configured: boolean;
  detail: Record<string, any>;
  error?: string;
  last_scan?: { scan_id: string; started_at: string; at: string; assets: number; error?: string };
};

// Sources a scan can read (services/discovery normalizeScanTypes).
export const DISCOVERY_SCAN_TYPES = ["network", "cloud", "certs", "code", "git", "storage"] as const;

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
    `/discovery/scans/${encodeURIComponent(id)}?${tenantQuery(session)}`,
    { skipGlobalLoading: true }
  );
  return res?.scan ?? ({} as DiscoveryScan);
}

// Filters GET /discovery/assets takes. The summary counts with the same
// ones, so a chart's number equals the total of its list.
export type AssetQuery = {
  q?: string;
  source?: string;
  asset_type?: string;
  classification?: string; // one class, or several separated by commas
  algorithm?: string; // exact; "" is the assets with no algorithm
  pqc_ready?: boolean;
  expiring_days?: number;
  not_seen?: boolean;
};

export async function listDiscoveryAssets(
  session: AuthSession,
  query: AssetQuery = {},
  offset = 0,
  limit = 25
): Promise<{ items: CryptoAsset[]; total: number }> {
  const params = new URLSearchParams();
  params.set("tenant_id", session.tenantId);
  params.set("limit", String(limit));
  params.set("offset", String(offset));
  if (query.q) params.set("q", query.q);
  if (query.source) params.set("source", query.source);
  if (query.asset_type) params.set("asset_type", query.asset_type);
  if (query.classification) params.set("classification", query.classification);
  if (query.algorithm !== undefined) params.set("algorithm", query.algorithm);
  if (query.pqc_ready) params.set("pqc_ready", "true");
  if (query.expiring_days) params.set("expiring_days", String(query.expiring_days));
  if (query.not_seen) params.set("not_seen", "true");
  const res = await serviceRequest<{ items?: CryptoAsset[]; total?: number }>(
    session,
    "discovery",
    `/discovery/assets?${params.toString()}`
  );
  const items = Array.isArray(res?.items) ? res.items : [];
  return { items, total: Number(res?.total ?? items.length) };
}

export type DiscoverySummary = {
  tenant_id: string;
  total_assets: number;
  source_distribution: Record<string, number>;
  algorithm_distribution: Record<string, number>;
  classification_counts: Record<string, number>;
  pqc_ready_count: number;
  pqc_readiness_percent: number;
  algorithm_classes: Record<string, Record<string, number>>;
  source_classification: Record<string, Record<string, number>>;
  expiring_30d: number;
};

export async function getDiscoverySummary(session: AuthSession): Promise<DiscoverySummary> {
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
  port: number,
  protocol: "tls" | "ssh" = "tls"
): Promise<DiscoveryTarget> {
  const res = await serviceRequest<{ target?: DiscoveryTarget }>(
    session,
    "discovery",
    `/discovery/targets?${tenantQuery(session)}`,
    { method: "POST", body: JSON.stringify({ host, port, protocol }) }
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

export async function getDiscoverySources(session: AuthSession): Promise<DiscoverySource[]> {
  const res = await serviceRequest<{ items?: DiscoverySource[] }>(
    session,
    "discovery",
    `/discovery/sources?${tenantQuery(session)}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}

// The largest file POST /discovery/upload accepts.
export const DISCOVERY_UPLOAD_MAX_BYTES = 2 << 20;

function toBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

// uploadDiscoveryFile sends one file to be inventoried. The service parses it
// in memory and keeps only what it found (fingerprints for secrets).
export async function uploadDiscoveryFile(
  session: AuthSession,
  file: File
): Promise<{ scan: DiscoveryScan; assets: CryptoAsset[] }> {
  const content = toBase64(await file.arrayBuffer());
  const res = await serviceRequest<{ scan?: DiscoveryScan; assets?: CryptoAsset[] }>(
    session,
    "discovery",
    `/discovery/upload?${tenantQuery(session)}`,
    { method: "POST", body: JSON.stringify({ name: file.name, content }) }
  );
  return { scan: res?.scan ?? ({} as DiscoveryScan), assets: Array.isArray(res?.assets) ? res.assets : [] };
}

export async function removeDiscoveryAsset(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(
    session,
    "discovery",
    `/discovery/assets/${encodeURIComponent(id)}?${tenantQuery(session)}`,
    { method: "DELETE" }
  );
}

// A git repository the tenant added for the "git" scan source. The URL holds
// no credential; a private repository names a sealed Git connection
// (Playbooks, Connections).
export type DiscoveryRepository = {
  id: string;
  tenant_id: string;
  url: string;
  ref: string;
  provider: "github" | "gitlab" | "bitbucket" | "gitea";
  connection_id: string;
  created_by: string;
  created_at: string;
};

export async function listDiscoveryRepositories(session: AuthSession): Promise<DiscoveryRepository[]> {
  const res = await serviceRequest<{ items?: DiscoveryRepository[] }>(
    session,
    "discovery",
    `/discovery/repositories?${tenantQuery(session)}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}

export async function addDiscoveryRepository(
  session: AuthSession,
  repo: { url: string; ref: string; provider: string; connection_id: string }
): Promise<DiscoveryRepository> {
  const res = await serviceRequest<{ repository?: DiscoveryRepository }>(
    session,
    "discovery",
    `/discovery/repositories?${tenantQuery(session)}`,
    { method: "POST", body: JSON.stringify(repo) }
  );
  return res?.repository ?? ({} as DiscoveryRepository);
}

export async function removeDiscoveryRepository(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(
    session,
    "discovery",
    `/discovery/repositories/${encodeURIComponent(id)}?${tenantQuery(session)}`,
    { method: "DELETE" }
  );
}

// testDiscoveryRepository reads the start of the repository's archive with
// its connection; it throws with the hosting service's reason when it can't.
export async function testDiscoveryRepository(session: AuthSession, id: string): Promise<{ commit: string }> {
  const res = await serviceRequest<{ commit?: string }>(
    session,
    "discovery",
    `/discovery/repositories/${encodeURIComponent(id)}/test?${tenantQuery(session)}`,
    { method: "POST", body: "{}" }
  );
  return { commit: String(res?.commit || "") };
}

// The tenant's scan schedule. authorized_by is the user who saved it; their
// permission is re-checked before every run, and paused_reason says when it
// no longer holds.
export type DiscoverySchedule = {
  tenant_id: string;
  enabled: boolean;
  interval_hours: number;
  sources: string[];
  authorized_by: string;
  next_run_at?: string;
  last_run_at?: string;
  last_scan_id: string;
  paused_reason: string;
};

export async function getDiscoverySchedule(session: AuthSession): Promise<DiscoverySchedule> {
  const res = await serviceRequest<{ schedule?: DiscoverySchedule }>(
    session,
    "discovery",
    `/discovery/schedule?${tenantQuery(session)}`
  );
  if (!res?.schedule) {
    throw new Error("discovery returned no schedule");
  }
  return res.schedule;
}

export async function saveDiscoverySchedule(
  session: AuthSession,
  schedule: { enabled: boolean; interval_hours: number; sources: string[] }
): Promise<DiscoverySchedule> {
  const res = await serviceRequest<{ schedule?: DiscoverySchedule }>(
    session,
    "discovery",
    `/discovery/schedule?${tenantQuery(session)}`,
    { method: "PUT", body: JSON.stringify(schedule) }
  );
  if (!res?.schedule) {
    throw new Error("discovery returned no schedule");
  }
  return res.schedule;
}

// Source connections (sealed in compliance) a private repository (git) or
// bucket (s3, azure_blob) can use. Only the name, ID and host come back,
// never a field value.
export type SourceConnection = { id: string; name: string; type: string; endpoint: string };
export type GitConnection = SourceConnection;

export async function listSourceConnections(session: AuthSession, types: string[]): Promise<SourceConnection[]> {
  const res = await serviceRequest<{ data?: SourceConnection[] }>(
    session,
    "compliance",
    `/compliance/playbooks/connections?${tenantQuery(session)}`
  );
  return (Array.isArray(res?.data) ? res.data : []).filter((c) => types.includes(c.type));
}

export const listGitConnections = (session: AuthSession) => listSourceConnections(session, ["git"]);

// An object storage bucket the tenant added for the "storage" scan source:
// provider "s3" (S3 or a service that speaks its API) or "azure" (a Blob
// container). The endpoint holds no credential; a private bucket names a
// sealed s3 or azure_blob connection (Playbooks, Connections).
export type DiscoveryBucket = {
  id: string;
  tenant_id: string;
  provider: "s3" | "azure";
  endpoint: string;
  bucket: string;
  prefix: string;
  region: string;
  connection_id: string;
  created_by: string;
  created_at: string;
};

// The connection type a provider's private bucket reads with.
export const BUCKET_CONNECTION_TYPE: Record<DiscoveryBucket["provider"], string> = { s3: "s3", azure: "azure_blob" };

export async function listDiscoveryBuckets(session: AuthSession): Promise<DiscoveryBucket[]> {
  const res = await serviceRequest<{ items?: DiscoveryBucket[] }>(
    session,
    "discovery",
    `/discovery/buckets?${tenantQuery(session)}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}

export async function addDiscoveryBucket(
  session: AuthSession,
  bucket: { provider: string; endpoint: string; bucket: string; prefix: string; region: string; connection_id: string }
): Promise<DiscoveryBucket> {
  const res = await serviceRequest<{ bucket?: DiscoveryBucket }>(
    session,
    "discovery",
    `/discovery/buckets?${tenantQuery(session)}`,
    { method: "POST", body: JSON.stringify(bucket) }
  );
  return res?.bucket ?? ({} as DiscoveryBucket);
}

export async function removeDiscoveryBucket(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(
    session,
    "discovery",
    `/discovery/buckets/${encodeURIComponent(id)}?${tenantQuery(session)}`,
    { method: "DELETE" }
  );
}

// testDiscoveryBucket lists the bucket and reads one object with its
// connection; it throws with the storage service's reason when it can't.
export async function testDiscoveryBucket(session: AuthSession, id: string): Promise<{ objects_listed: number; objects_read: number }> {
  const res = await serviceRequest<{ objects_listed?: number; objects_read?: number }>(
    session,
    "discovery",
    `/discovery/buckets/${encodeURIComponent(id)}/test?${tenantQuery(session)}`,
    { method: "POST", body: "{}" }
  );
  return { objects_listed: Number(res?.objects_listed || 0), objects_read: Number(res?.objects_read || 0) };
}
