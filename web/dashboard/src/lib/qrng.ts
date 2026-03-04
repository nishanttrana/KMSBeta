// ── QRNG Types ─────────────────────────────────────────────

export interface QRNGSource {
  id: string;
  tenant_id: string;
  name: string;
  vendor: string;
  endpoint: string;
  mode: string;
  status: string;
  min_entropy_bpb: number;
  pull_interval_s: number;
  last_seen_at: string;
  last_error: string;
  created_at: string;
  updated_at: string;
}

export interface QRNGPoolStatus {
  tenant_id: string;
  total_samples: number;
  available_samples: number;
  consumed_samples: number;
  avg_entropy_bpb: number;
  pool_healthy: boolean;
  last_ingest_at: string;
  active_source_count: number;
}

export interface QRNGHealthEvent {
  id: string;
  tenant_id: string;
  source_id: string;
  check_type: string;
  result: string;
  entropy_bpb: number;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface QRNGOverview {
  tenant_id: string;
  pool: QRNGPoolStatus;
  sources: QRNGSource[];
}

export interface RegisterSourceInput {
  tenant_id: string;
  name: string;
  vendor: string;
  endpoint: string;
  auth_token: string;
  mode: string;
  min_entropy_bpb: number;
  pull_interval_s: number;
}

export interface IngestResult {
  sample_id: string;
  byte_count: number;
  entropy_bpb: number;
  accepted: boolean;
  reject_reason?: string;
}

// ── API Functions ──────────────────────────────────────────

const BASE = "/svc/qrng";

async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(opts?.headers as Record<string, string> || {}) },
    ...opts,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.error?.message || `QRNG API ${res.status}`);
  }
  return res.json();
}

export function listQRNGSources(tenantId: string): Promise<QRNGSource[]> {
  return api<{ items: QRNGSource[] }>(`/qrng/v1/sources?tenant_id=${tenantId}`).then(r => Array.isArray(r.items) ? r.items : []);
}

export function getQRNGSource(tenantId: string, id: string): Promise<QRNGSource> {
  return api<{ source: QRNGSource }>(`/qrng/v1/sources/${id}?tenant_id=${tenantId}`).then(r => r.source);
}

export function registerQRNGSource(input: RegisterSourceInput): Promise<QRNGSource> {
  return api<{ source: QRNGSource }>(`/qrng/v1/sources`, {
    method: "POST",
    body: JSON.stringify(input),
  }).then(r => r.source);
}

export function updateQRNGSource(tenantId: string, id: string, input: Partial<RegisterSourceInput>): Promise<QRNGSource> {
  return api<{ source: QRNGSource }>(`/qrng/v1/sources/${id}?tenant_id=${tenantId}`, {
    method: "PUT",
    body: JSON.stringify(input),
  }).then(r => r.source);
}

export function deleteQRNGSource(tenantId: string, id: string): Promise<void> {
  return api(`/qrng/v1/sources/${id}?tenant_id=${tenantId}`, { method: "DELETE" }).then(() => {});
}

export function getQRNGPoolStatus(tenantId: string): Promise<QRNGPoolStatus> {
  return api<{ pool: QRNGPoolStatus }>(`/qrng/v1/pool/status?tenant_id=${tenantId}`).then(r => r.pool);
}

export function getQRNGOverview(tenantId: string): Promise<QRNGOverview> {
  return api<{ overview: QRNGOverview }>(`/qrng/v1/overview?tenant_id=${tenantId}`).then(r => r.overview);
}

export function listQRNGHealthEvents(tenantId: string, limit = 50): Promise<QRNGHealthEvent[]> {
  return api<{ items: QRNGHealthEvent[] }>(`/qrng/v1/health?tenant_id=${tenantId}&limit=${limit}`).then(r => Array.isArray(r.items) ? r.items : []);
}

export function ingestEntropy(tenantId: string, sourceId: string, entropyB64: string): Promise<IngestResult> {
  return api<{ result: IngestResult }>(`/qrng/v1/ingest`, {
    method: "POST",
    body: JSON.stringify({ tenant_id: tenantId, source_id: sourceId, entropy: entropyB64 }),
  }).then(r => r.result);
}

export function drawEntropy(tenantId: string, bytes: number): Promise<{ entropy: string; byte_count: number }> {
  return api<{ result: { entropy: string; byte_count: number } }>(`/qrng/v1/draw`, {
    method: "POST",
    body: JSON.stringify({ tenant_id: tenantId, bytes }),
  }).then(r => r.result);
}

export const QRNG_VENDORS = [
  { value: "id-quantique-quantis", label: "ID Quantique Quantis" },
  { value: "quintessencelabs-qstream", label: "QuintessenceLabs qStream" },
  { value: "toshiba", label: "Toshiba QRNG" },
  { value: "cloud-aws", label: "AWS CloudHSM QRNG" },
  { value: "cloud-azure", label: "Azure Quantum" },
  { value: "custom", label: "Custom / Other" },
];
