import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type EKMAgent = {
  id: string;
  tenant_id: string;
  name: string;
  role: string;
  db_engine: string;
  host: string;
  version: string;
  status: string;
  tde_state: string;
  heartbeat_interval_sec: number;
  last_heartbeat_at?: string;
  assigned_key_id: string;
  assigned_key_version: string;
  config_version: number;
  config_version_ack: number;
  metadata_json?: string;
  tls_client_cn?: string;
  created_at?: string;
  updated_at?: string;
};

export type EKMAgentStatus = {
  agent: EKMAgent;
  managed_databases: number;
  tde_enabled_databases: number;
  last_heartbeat_age_sec: number;
};

export type EKMAgentHealth = {
  agent: EKMAgent;
  health: "healthy" | "degraded" | "down" | string;
  last_heartbeat_age_sec: number;
  metrics: {
    hostname: string;
    os_name: string;
    os_version: string;
    kernel: string;
    arch: string;
    cpu_usage_pct: number;
    memory_usage_pct: number;
    disk_usage_pct: number;
    load_1: number;
    uptime_sec: number;
    agent_runtime_sec: number;
  };
  warnings: string[];
};

export type EKMAccessLog = {
  id: string;
  tenant_id: string;
  key_id: string;
  agent_id: string;
  database_id: string;
  operation: string;
  status: string;
  error_message: string;
  created_at?: string;
};

export type EKMDeployPackageFile = {
  path: string;
  content: string;
  mode: string;
};

export type EKMDeployPackage = {
  agent_id: string;
  name: string;
  db_engine: string;
  target_os: "linux" | "windows" | string;
  created_at?: string;
  pkcs11_provider: string;
  heartbeat_path: string;
  register_path: string;
  rotate_path: string;
  supported_databases: string[];
  recommended_profiles: string[];
  files: EKMDeployPackageFile[];
};

export type EKMBitLockerClient = {
  id: string;
  tenant_id: string;
  name: string;
  host: string;
  os_version: string;
  status: string;
  health: string;
  protection_status: string;
  encryption_percentage: number;
  mount_point: string;
  heartbeat_interval_sec: number;
  last_heartbeat_at?: string;
  tpm_present: boolean;
  tpm_ready: boolean;
  jwt_subject?: string;
  tls_client_cn?: string;
  metadata_json?: string;
  created_at?: string;
  updated_at?: string;
};

export type EKMBitLockerJob = {
  id: string;
  tenant_id: string;
  client_id: string;
  operation: string;
  params_json?: string;
  status: string;
  requested_by: string;
  request_id: string;
  requested_at?: string;
  dispatched_at?: string;
  completed_at?: string;
  result_json?: string;
  error_message?: string;
  recovery_key_ref?: string;
};

export type EKMBitLockerRecovery = {
  id: string;
  client_id: string;
  volume_mount_point: string;
  protector_id: string;
  key_fingerprint: string;
  key_masked: string;
  source: string;
  created_at?: string;
};

export type RegisterBitLockerClientInput = {
  client_id?: string;
  name: string;
  host: string;
  os_version?: string;
  mount_point?: string;
  heartbeat_interval_sec?: number;
  metadata_json?: string;
};

export type EKMSDKProvider = {
  id: string;
  name: string;
  artifact_name: string;
  version: string;
  status: string;
  size_label: string;
  transport: string;
  sessions_active: number;
  ops_24h: number;
  clients_connected: number;
  top_mechanism: string;
  platforms: string[];
  capabilities: string[];
};

export type EKMSDKMechanism = {
  mechanism: string;
  ops_24h: number;
  percent: number;
};

export type EKMSDKClient = {
  id: string;
  name: string;
  sdk: string;
  mechanism: string;
  ops_24h: number;
  status: string;
};

export type EKMSDKOverview = {
  refreshed_at: string;
  providers: EKMSDKProvider[];
  mechanisms: EKMSDKMechanism[];
  clients: EKMSDKClient[];
};

export type EKMSDKArtifact = {
  provider: string;
  target_os: string;
  filename: string;
  content_type: string;
  encoding: string;
  content: string;
  size_bytes: number;
  sha256: string;
};

export type EKMDeleteAgentResult = {
  agent_id: string;
  deleted_databases: number;
  deleted_keys: number;
  deleted_logs: number;
  deleted_key_ids: string[];
};

export type RegisterEKMAgentInput = {
  agent_id?: string;
  name: string;
  role?: string;
  db_engine: "mssql" | "oracle";
  host: string;
  version: string;
  heartbeat_interval_sec?: number;
  metadata_json?: string;
  auto_provision_tde?: boolean;
};

type ListAgentsResponse = { items: EKMAgent[] };
type AgentStatusResponse = { status: EKMAgentStatus };
type AgentHealthResponse = { health: EKMAgentHealth };
type AgentLogsResponse = { items: EKMAccessLog[] };
type RegisterAgentResponse = { agent: EKMAgent };
type RotateResponse = { rotation: { key_id: string; version_id: string; affected_agent_ids: string[] } };
type DeleteAgentResponse = { deleted: EKMDeleteAgentResult };
type DeployResponse = { package: EKMDeployPackage };
type SDKOverviewResponse = { overview: EKMSDKOverview };
type SDKDownloadResponse = { artifact: EKMSDKArtifact };
type BitLockerClientsResponse = { items: EKMBitLockerClient[] };
type BitLockerClientResponse = { client: EKMBitLockerClient };
type BitLockerJobResponse = { job: EKMBitLockerJob };
type BitLockerJobsResponse = { items: EKMBitLockerJob[] };
type BitLockerRecoveryResponse = { items: EKMBitLockerRecovery[] };
type BitLockerDeployResponse = { package: EKMDeployPackage };
type PublicKeyResponse = {
  public_key: {
    key_id: string;
    algorithm: string;
    public_key: string;
    format: string;
    key_version: string;
  };
};

function tenantQuery(session: AuthSession, tenantOverride?: string): string {
  const tenant = String(tenantOverride || session.tenantId || "").trim();
  return `tenant_id=${encodeURIComponent(tenant)}`;
}

export async function listEKMAgents(session: AuthSession): Promise<EKMAgent[]> {
  const out = await serviceRequest<ListAgentsResponse>(session, "ekm", `/ekm/agents?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getEKMAgentStatus(session: AuthSession, agentID: string): Promise<EKMAgentStatus> {
  const out = await serviceRequest<AgentStatusResponse>(
    session,
    "ekm",
    `/ekm/agents/${encodeURIComponent(agentID)}/status?${tenantQuery(session)}`
  );
  return out.status;
}

export async function getEKMAgentHealth(session: AuthSession, agentID: string): Promise<EKMAgentHealth> {
  const out = await serviceRequest<AgentHealthResponse>(
    session,
    "ekm",
    `/ekm/agents/${encodeURIComponent(agentID)}/health?${tenantQuery(session)}`
  );
  return out.health;
}

export async function listEKMAgentLogs(session: AuthSession, agentID: string, limit = 20): Promise<EKMAccessLog[]> {
  const out = await serviceRequest<AgentLogsResponse>(
    session,
    "ekm",
    `/ekm/agents/${encodeURIComponent(agentID)}/logs?${tenantQuery(session)}&limit=${Math.max(1, Math.min(200, Math.trunc(limit)))}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function registerEKMAgent(session: AuthSession, input: RegisterEKMAgentInput): Promise<EKMAgent> {
  const out = await serviceRequest<RegisterAgentResponse>(session, "ekm", "/ekm/agents/register", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      agent_id: String(input.agent_id || "").trim(),
      name: String(input.name || "").trim(),
      role: String(input.role || "ekm-agent").trim(),
      db_engine: String(input.db_engine || "mssql").trim(),
      host: String(input.host || "").trim(),
      version: String(input.version || "").trim(),
      heartbeat_interval_sec: Math.max(5, Math.min(300, Math.trunc(Number(input.heartbeat_interval_sec || 30)))),
      metadata_json: String(input.metadata_json || "{}"),
      auto_provision_tde: input.auto_provision_tde !== false
    })
  });
  return out.agent;
}

export async function rotateEKMAgentKey(session: AuthSession, agentID: string, reason = "manual"): Promise<void> {
  await serviceRequest<RotateResponse>(
    session,
    "ekm",
    `/ekm/agents/${encodeURIComponent(agentID)}/rotate`,
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        reason
      })
    }
  );
}

export async function deleteEKMAgent(
  session: AuthSession,
  agentID: string,
  reason = "manual-delete"
): Promise<EKMDeleteAgentResult> {
  const out = await serviceRequest<DeleteAgentResponse>(
    session,
    "ekm",
    `/ekm/agents/${encodeURIComponent(agentID)}`,
    {
      method: "DELETE",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        reason
      })
    }
  );
  return out.deleted;
}

export async function getEKMDeployPackage(
  session: AuthSession,
  agentID: string,
  targetOS: "linux" | "windows"
): Promise<EKMDeployPackage> {
  const out = await serviceRequest<DeployResponse>(
    session,
    "ekm",
    `/ekm/agents/${encodeURIComponent(agentID)}/deploy?${tenantQuery(session)}&os=${encodeURIComponent(targetOS)}`
  );
  return out.package;
}

export async function listBitLockerClients(
  session: AuthSession,
  limit = 1000,
  tenantOverride?: string
): Promise<EKMBitLockerClient[]> {
  const out = await serviceRequest<BitLockerClientsResponse>(
    session,
    "ekm",
    `/ekm/bitlocker/clients?${tenantQuery(session, tenantOverride)}&limit=${Math.max(1, Math.min(100000, Math.trunc(limit)))}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getBitLockerClient(
  session: AuthSession,
  clientID: string,
  tenantOverride?: string
): Promise<EKMBitLockerClient> {
  const out = await serviceRequest<BitLockerClientResponse>(
    session,
    "ekm",
    `/ekm/bitlocker/clients/${encodeURIComponent(clientID)}?${tenantQuery(session, tenantOverride)}`
  );
  return out.client;
}

export async function registerBitLockerClient(
  session: AuthSession,
  input: RegisterBitLockerClientInput,
  tenantOverride?: string
): Promise<EKMBitLockerClient> {
  const out = await serviceRequest<BitLockerClientResponse>(
    session,
    "ekm",
    "/ekm/bitlocker/clients/register",
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: String(tenantOverride || session.tenantId || "").trim(),
        client_id: String(input.client_id || "").trim(),
        name: String(input.name || "").trim(),
        host: String(input.host || "").trim(),
        os_version: String(input.os_version || "windows").trim(),
        mount_point: String(input.mount_point || "C:").trim(),
        heartbeat_interval_sec: Math.max(5, Math.min(300, Math.trunc(Number(input.heartbeat_interval_sec || 30)))),
        metadata_json: String(input.metadata_json || "{}")
      })
    }
  );
  return out.client;
}

export async function queueBitLockerOperation(
  session: AuthSession,
  clientID: string,
  operation: "enable" | "disable" | "pause" | "resume" | "remove" | "rotate" | "fetch_recovery",
  params: Record<string, unknown> = {},
  tenantOverride?: string
): Promise<EKMBitLockerJob> {
  const out = await serviceRequest<BitLockerJobResponse>(
    session,
    "ekm",
    `/ekm/bitlocker/clients/${encodeURIComponent(clientID)}/operations`,
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: String(tenantOverride || session.tenantId || "").trim(),
        operation,
        requested_by: String(session.username || "dashboard").trim() || "dashboard",
        request_id: "",
        params
      })
    }
  );
  return out.job;
}

export async function listBitLockerJobs(
  session: AuthSession,
  clientID: string,
  limit = 100,
  tenantOverride?: string
): Promise<EKMBitLockerJob[]> {
  const out = await serviceRequest<BitLockerJobsResponse>(
    session,
    "ekm",
    `/ekm/bitlocker/clients/${encodeURIComponent(clientID)}/jobs?${tenantQuery(session, tenantOverride)}&limit=${Math.max(1, Math.min(5000, Math.trunc(limit)))}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function listBitLockerRecoveryKeys(
  session: AuthSession,
  clientID: string,
  limit = 200,
  tenantOverride?: string
): Promise<EKMBitLockerRecovery[]> {
  const out = await serviceRequest<BitLockerRecoveryResponse>(
    session,
    "ekm",
    `/ekm/bitlocker/recovery?${tenantQuery(session, tenantOverride)}&client_id=${encodeURIComponent(clientID)}&limit=${Math.max(1, Math.min(20000, Math.trunc(limit)))}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getBitLockerDeployPackage(
  session: AuthSession,
  clientID: string,
  targetOS: "windows" = "windows",
  tenantOverride?: string
): Promise<EKMDeployPackage> {
  const out = await serviceRequest<BitLockerDeployResponse>(
    session,
    "ekm",
    `/ekm/bitlocker/clients/${encodeURIComponent(clientID)}/deploy?${tenantQuery(session, tenantOverride)}&os=${encodeURIComponent(targetOS)}`
  );
  return out.package;
}

export async function getEKMTDEPublicKey(
  session: AuthSession,
  keyID: string
): Promise<{ algorithm: string; key_version: string }> {
  const out = await serviceRequest<PublicKeyResponse>(
    session,
    "ekm",
    `/ekm/tde/keys/${encodeURIComponent(keyID)}/public?${tenantQuery(session)}`
  );
  return {
    algorithm: String(out?.public_key?.algorithm || ""),
    key_version: String(out?.public_key?.key_version || "")
  };
}

export async function getEKMSDKOverview(session: AuthSession, tenantOverride?: string): Promise<EKMSDKOverview> {
  const out = await serviceRequest<SDKOverviewResponse>(
    session,
    "ekm",
    `/ekm/sdk/overview?${tenantQuery(session, tenantOverride)}`
  );
  return out.overview || { refreshed_at: "", providers: [], mechanisms: [], clients: [] };
}

export async function downloadEKMSDK(
  session: AuthSession,
  provider: "pkcs11" | "jca",
  targetOS: "linux" | "windows" | "macos" | "all" = "all",
  tenantOverride?: string
): Promise<EKMSDKArtifact> {
  const out = await serviceRequest<SDKDownloadResponse>(
    session,
    "ekm",
    `/ekm/sdk/download?${tenantQuery(session, tenantOverride)}&provider=${encodeURIComponent(provider)}&os=${encodeURIComponent(targetOS)}`
  );
  return out.artifact;
}
