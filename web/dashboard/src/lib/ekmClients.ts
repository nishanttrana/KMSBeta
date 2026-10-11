import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// EKM database clients (services/ekm/clients.go). A client is pending until
// its agent presents the one-time registration token; health is the age of
// its last verified check-in, judged by the service.
export type EKMClientHealth = "pending" | "healthy" | "degraded" | "offline";

export type EKMClient = {
  id: string;
  name: string;
  db_engine: string;
  host: string;
  registration: "pending" | "registered";
  health: EKMClientHealth;
  last_seen_at?: string;
  last_seen_age_sec?: number;
  registered_at?: string;
  created_at?: string;
  source_ip: string;
  version: string;
  tde_state: string;
  heartbeat_interval_sec: number;
  assigned_key_id: string;
  assigned_key_version: string;
  credential: "" | "client_key" | "service_token";
  token_expires_at?: string;
};

export type EKMClientThresholds = { healthy_within_sec: number; degraded_within_sec: number };

export type EKMClientCheckIn = { at: string; source_ip: string; version: string; status: string };

export type EKMClientList = { items: EKMClient[]; thresholds: EKMClientThresholds; server_time: string };

export type EKMClientDetail = {
  client: EKMClient;
  check_ins: EKMClientCheckIn[];
  thresholds: EKMClientThresholds;
  server_time: string;
  key?: { id: string; name: string; algorithm: string; version: string; status: string };
  last_key_request?: { at: string; operation: string; status: string };
  metrics?: { hostname: string; os_name: string; os_version: string; cpu_usage_pct: number; memory_usage_pct: number; disk_usage_pct: number; uptime_sec: number };
  databases?: number;
  tde_enabled_databases?: number;
};

export type EKMRegistrationToken = { token: string; expires_at: string; client_id: string; enroll_path: string };

export type CreateEKMClientInput = { name: string; db_engine: string; host: string; auto_provision_tde: boolean };

const tenant = (session: AuthSession) => `tenant_id=${encodeURIComponent(String(session.tenantId || "").trim())}`;

// Polls don't raise the global loading bar.
export async function listEKMClients(session: AuthSession, quiet = false): Promise<EKMClientList> {
  const out = await serviceRequest<EKMClientList>(session, "ekm", `/ekm/clients?${tenant(session)}`, { skipGlobalLoading: quiet });
  return { ...out, items: Array.isArray(out?.items) ? out.items : [] };
}

export async function getEKMClient(session: AuthSession, id: string, quiet = false): Promise<EKMClientDetail> {
  const out = await serviceRequest<EKMClientDetail>(session, "ekm", `/ekm/clients/${encodeURIComponent(id)}?${tenant(session)}`, { skipGlobalLoading: quiet });
  return { ...out, check_ins: Array.isArray(out?.check_ins) ? out.check_ins : [] };
}

export async function createEKMClient(session: AuthSession, input: CreateEKMClientInput): Promise<EKMClient> {
  const out = await serviceRequest<{ client: EKMClient }>(session, "ekm", "/ekm/clients", {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, name: input.name.trim(), db_engine: input.db_engine, host: input.host.trim(), auto_provision_tde: input.auto_provision_tde }),
  });
  return out.client;
}

// The token is returned once and never stored by the dashboard.
export async function issueEKMClientToken(session: AuthSession, id: string): Promise<EKMRegistrationToken> {
  return serviceRequest<EKMRegistrationToken>(session, "ekm", `/ekm/clients/${encodeURIComponent(id)}/registration-token?${tenant(session)}`, { method: "POST" });
}
