import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type QKDConfig = {
  tenant_id: string;
  qber_threshold: number;
  pool_low_threshold: number;
  pool_capacity: number;
  auto_inject: boolean;
  service_enabled: boolean;
  etsi_api_enabled: boolean;
  protocol: string;
  distance_km: number;
  updated_at?: string;
};

export type QKDOverview = {
  tenant_id: string;
  slave_sae_id: string;
  config: {
    service_enabled: boolean;
    etsi_api_enabled: boolean;
    protocol: string;
    distance_km: number;
    qber_threshold: number;
    pool_low_threshold: number;
    pool_capacity: number;
    auto_inject: boolean;
    updated_at?: string;
  };
  status: {
    active: boolean;
    link_status: string;
    source: string;
    destination: string;
    key_rate: number;
    qber_avg: number;
    keys_received_today: number;
  };
  pool: {
    available_keys: number;
    used_today: number;
    total_keys: number;
    pool_fill_pct: number;
    low: boolean;
  };
};

export type QKDKey = {
  id: string;
  tenant_id: string;
  device_id: string;
  slave_sae_id: string;
  external_key_id: string;
  status: string;
  qber: number;
  key_size_bits: number;
  keycore_key_id?: string;
  created_at?: string;
  updated_at?: string;
  injected_at?: string;
};

export type QKDLogEntry = {
  id: string;
  tenant_id: string;
  action: string;
  level: string;
  message: string;
  meta?: Record<string, unknown>;
  created_at?: string;
};

export type QKDInjectResult = {
  qkd_key_id: string;
  keycore_key_id: string;
  status: string;
};

export type QKDGenerateTestInput = {
  slave_sae_id: string;
  device_id?: string;
  device_name?: string;
  role?: string;
  link_status?: "up" | "down";
  count?: number;
  key_size_bits?: number;
  qber_min?: number;
  qber_max?: number;
};

type ConfigResponse = { config: QKDConfig };
type OverviewResponse = { overview: QKDOverview };
type KeysResponse = { items: QKDKey[] };
type LogsResponse = { items: QKDLogEntry[] };
type InjectResponse = { result: QKDInjectResult };
type GenerateResponse = {
  result: {
    slave_sae_id: string;
    accepted_key_ids: string[];
    discarded_key_ids: string[];
    accepted_count: number;
    discarded_count: number;
  };
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function getQKDConfig(session: AuthSession): Promise<QKDConfig> {
  const out = await serviceRequest<ConfigResponse>(session, "qkd", `/qkd/v1/config?${tenantQuery(session)}`);
  return out.config;
}

export async function updateQKDConfig(session: AuthSession, input: Partial<QKDConfig>): Promise<QKDConfig> {
  const out = await serviceRequest<ConfigResponse>(session, "qkd", "/qkd/v1/config", {
    method: "PUT",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out.config;
}

export async function getQKDOverview(session: AuthSession, slaveSAEID = ""): Promise<QKDOverview> {
  const qs = new URLSearchParams();
  qs.set("tenant_id", session.tenantId);
  if (String(slaveSAEID || "").trim()) {
    qs.set("slave_sae_id", String(slaveSAEID).trim());
  }
  const out = await serviceRequest<OverviewResponse>(session, "qkd", `/qkd/v1/overview?${qs.toString()}`);
  return out.overview;
}

export async function listQKDKeys(
  session: AuthSession,
  opts: { slave_sae_id: string; status?: string[]; limit?: number }
): Promise<QKDKey[]> {
  const qs = new URLSearchParams();
  qs.set("tenant_id", session.tenantId);
  qs.set("slave_sae_id", opts.slave_sae_id);
  if (Array.isArray(opts.status) && opts.status.length) {
    qs.set("status", opts.status.join(","));
  }
  if (opts.limit && opts.limit > 0) {
    qs.set("limit", String(opts.limit));
  }
  const out = await serviceRequest<KeysResponse>(session, "qkd", `/qkd/v1/keys?${qs.toString()}`);
  return Array.isArray(out.items) ? out.items : [];
}

export async function listQKDLogs(session: AuthSession, limit = 100): Promise<QKDLogEntry[]> {
  const qs = new URLSearchParams();
  qs.set("tenant_id", session.tenantId);
  qs.set("limit", String(Math.max(1, Math.min(500, Number(limit || 100)))));
  const out = await serviceRequest<LogsResponse>(session, "qkd", `/qkd/v1/logs?${qs.toString()}`);
  return Array.isArray(out.items) ? out.items : [];
}

export async function injectQKDKey(
  session: AuthSession,
  keyID: string,
  input?: { name?: string; purpose?: string; consume?: boolean }
): Promise<QKDInjectResult> {
  const out = await serviceRequest<InjectResponse>(session, "qkd", `/qkd/v1/keys/${encodeURIComponent(keyID)}/inject`, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      name: input?.name || "",
      purpose: input?.purpose || "encrypt",
      consume: input?.consume ?? true
    })
  });
  return out.result;
}

export async function runQKDTestGenerate(session: AuthSession, input: QKDGenerateTestInput): Promise<GenerateResponse["result"]> {
  const out = await serviceRequest<GenerateResponse>(session, "qkd", "/qkd/v1/test/generate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out.result;
}

// ── Slave SAE Registry ─────────────────────────────────────

export type SlaveSAE = {
  id: string;
  tenant_id: string;
  name: string;
  endpoint: string;
  auth_token?: string;
  protocol: string;
  role: string;
  mode: string;
  status: string;
  last_sync_at?: string;
  keys_distributed: number;
  keys_available: number;
  max_key_rate: number;
  qber_threshold: number;
  created_at?: string;
  updated_at?: string;
};

export type Distribution = {
  id: string;
  tenant_id: string;
  slave_sae_id: string;
  key_count: number;
  key_size_bits: number;
  status: string;
  error_message?: string;
  distributed_at?: string;
};

export type RegisterSAEInput = {
  name: string;
  endpoint: string;
  auth_token?: string;
  protocol?: string;
  role?: string;
  mode?: string;
  max_key_rate?: number;
  qber_threshold?: number;
};

export type DistributeKeysInput = {
  count: number;
  key_size_bits?: number;
};

type SAEResponse = { sae: SlaveSAE };
type SAEListResponse = { items: SlaveSAE[] };
type DistributeResponse = { result: { distribution_id: string; slave_sae_id: string; key_count: number; key_ids: string[]; status: string } };
type DistributionListResponse = { items: Distribution[] };

export async function registerSlaveSAE(session: AuthSession, input: RegisterSAEInput): Promise<SlaveSAE> {
  const out = await serviceRequest<SAEResponse>(session, "qkd", "/qkd/v1/sae", {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return out.sae;
}

export async function listSlaveSAEs(session: AuthSession): Promise<SlaveSAE[]> {
  const out = await serviceRequest<SAEListResponse>(session, "qkd", `/qkd/v1/sae?${tenantQuery(session)}`);
  return Array.isArray(out.items) ? out.items : [];
}

export async function getSlaveSAE(session: AuthSession, id: string): Promise<SlaveSAE> {
  const out = await serviceRequest<SAEResponse>(session, "qkd", `/qkd/v1/sae/${encodeURIComponent(id)}?${tenantQuery(session)}`);
  return out.sae;
}

export async function updateSlaveSAE(session: AuthSession, id: string, input: RegisterSAEInput): Promise<SlaveSAE> {
  const out = await serviceRequest<SAEResponse>(session, "qkd", `/qkd/v1/sae/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return out.sae;
}

export async function deleteSlaveSAE(session: AuthSession, id: string): Promise<void> {
  await serviceRequest<{ deleted: boolean }>(session, "qkd", `/qkd/v1/sae/${encodeURIComponent(id)}?${tenantQuery(session)}`, {
    method: "DELETE"
  });
}

export async function distributeKeys(session: AuthSession, saeId: string, input: DistributeKeysInput): Promise<DistributeResponse["result"]> {
  const out = await serviceRequest<DistributeResponse>(session, "qkd", `/qkd/v1/sae/${encodeURIComponent(saeId)}/distribute`, {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, slave_sae_id: saeId, ...input })
  });
  return out.result;
}

export async function listDistributions(session: AuthSession, slaveSaeId?: string, limit = 50): Promise<Distribution[]> {
  const qs = new URLSearchParams();
  qs.set("tenant_id", session.tenantId);
  if (slaveSaeId) qs.set("slave_sae_id", slaveSaeId);
  if (limit > 0) qs.set("limit", String(limit));
  const out = await serviceRequest<DistributionListResponse>(session, "qkd", `/qkd/v1/distributions?${qs.toString()}`);
  return Array.isArray(out.items) ? out.items : [];
}
