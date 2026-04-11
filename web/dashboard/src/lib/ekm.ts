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

export type EKMBitLockerDeletePreview = {
  client_id: string;
  client_name: string;
  host: string;
  latest_recovery_key: string;
  latest_recovery_key_masked: string;
  latest_recovery_at?: string;
  recovery_keys_available: number;
};

export type EKMDeleteBitLockerClientResult = {
  client_id: string;
  deleted_clients: number;
  deleted_jobs: number;
  deleted_recovery_keys: number;
};

export type EKMBitLockerNetworkCandidate = {
  ip: string;
  host: string;
  os_guess: string;
  confidence: string;
  smb_reachable: boolean;
  winrm_reachable: boolean;
  ports_open: number[];
};

export type EKMBitLockerNetworkScanResult = {
  ip_range: string;
  scanned_hosts: number;
  windows_hosts: number;
  candidates: EKMBitLockerNetworkCandidate[];
  duration_ms: number;
};

export type EKMBitLockerNetworkScanInput = {
  ip_range: string;
  port_timeout_ms?: number;
  max_hosts?: number;
  concurrency?: number;
  require_winrm?: boolean;
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
  db_engine: "mssql" | "oracle" | "postgresql" | "mysql" | "db2";
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
type BitLockerDeletePreviewResponse = { preview: EKMBitLockerDeletePreview };
type BitLockerDeleteResponse = { deleted: EKMDeleteBitLockerClientResult };
type BitLockerNetworkScanResponse = { scan: EKMBitLockerNetworkScanResult };
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

export async function getBitLockerDeletePreview(
  session: AuthSession,
  clientID: string,
  tenantOverride?: string
): Promise<EKMBitLockerDeletePreview> {
  const out = await serviceRequest<BitLockerDeletePreviewResponse>(
    session,
    "ekm",
    `/ekm/bitlocker/clients/${encodeURIComponent(clientID)}/delete-preview?${tenantQuery(session, tenantOverride)}`
  );
  return out.preview;
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

export async function deleteBitLockerClient(
  session: AuthSession,
  clientID: string,
  options: { reason?: string; confirm_backup?: boolean } = {},
  tenantOverride?: string
): Promise<EKMDeleteBitLockerClientResult> {
  const out = await serviceRequest<BitLockerDeleteResponse>(
    session,
    "ekm",
    `/ekm/bitlocker/clients/${encodeURIComponent(clientID)}`,
    {
      method: "DELETE",
      body: JSON.stringify({
        tenant_id: String(tenantOverride || session.tenantId || "").trim(),
        reason: String(options.reason || "manual-dashboard-delete").trim(),
        confirm_backup: options.confirm_backup === true
      })
    }
  );
  return out.deleted;
}

export async function scanBitLockerWindows(
  session: AuthSession,
  input: EKMBitLockerNetworkScanInput,
  tenantOverride?: string
): Promise<EKMBitLockerNetworkScanResult> {
  const out = await serviceRequest<BitLockerNetworkScanResponse>(
    session,
    "ekm",
    "/ekm/bitlocker/network/scan",
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: String(tenantOverride || session.tenantId || "").trim(),
        ip_range: String(input.ip_range || "").trim(),
        port_timeout_ms: Math.max(50, Math.min(5000, Math.trunc(Number(input.port_timeout_ms || 350)))),
        max_hosts: Math.max(1, Math.min(4096, Math.trunc(Number(input.max_hosts || 256)))),
        concurrency: Math.max(1, Math.min(128, Math.trunc(Number(input.concurrency || 32)))),
        require_winrm: input.require_winrm !== false
      })
    }
  );
  return out.scan || { ip_range: "", scanned_hosts: 0, windows_hosts: 0, candidates: [], duration_ms: 0 };
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

export type EKMDatabaseInstance = {
  id: string;
  tenant_id: string;
  agent_id: string;
  name: string;
  engine: string;
  host: string;
  port: number;
  database_name: string;
  tde_enabled: boolean;
  tde_state: string;
  key_id: string;
  auto_provisioned: boolean;
  metadata_json?: string;
  last_seen_at?: string;
  created_at?: string;
  updated_at?: string;
};

type ListDatabasesResponse = { items: EKMDatabaseInstance[] };
type RegisterDatabaseResponse = { database: EKMDatabaseInstance; auto_provisioned_key?: unknown };

export async function listEKMDatabases(
  session: AuthSession,
  agentID?: string
): Promise<EKMDatabaseInstance[]> {
  let url = `/ekm/databases?${tenantQuery(session)}`;
  if (agentID) url += `&agent_id=${encodeURIComponent(agentID)}`;
  const out = await serviceRequest<ListDatabasesResponse>(session, "ekm", url);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function registerEKMDatabase(
  session: AuthSession,
  input: {
    agent_id: string;
    name: string;
    engine?: string;
    host?: string;
    port?: number;
    database_name?: string;
    tde_enabled?: boolean;
    auto_provision_key?: boolean;
  }
): Promise<EKMDatabaseInstance> {
  const out = await serviceRequest<RegisterDatabaseResponse>(session, "ekm", "/ekm/databases", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      agent_id: String(input.agent_id || "").trim(),
      name: String(input.name || "").trim(),
      engine: String(input.engine || "mssql").trim(),
      host: String(input.host || "").trim(),
      port: Math.max(0, Math.trunc(Number(input.port || 0))),
      database_name: String(input.database_name || "").trim(),
      tde_enabled: input.tde_enabled !== false,
      auto_provision_key: input.auto_provision_key !== false
    })
  });
  return out.database;
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

/* ═══════════════ Azure EKM ═══════════════ */

export type AzureEKMConfig = {
  id: string;
  tenant_id: string;
  azure_tenant_id: string;
  subscription_id: string;
  resource_group: string;
  vault_name: string;
  vault_url: string;
  managed_hsm_name?: string;
  managed_hsm_url?: string;
  client_id: string;
  client_secret: string;
  auth_mode: string;
  status: string;
  key_mappings: number;
  last_sync_at?: string;
  created_at?: string;
};

export type AzureKeyMapping = {
  id: string;
  tenant_id: string;
  config_id: string;
  vecta_key_id: string;
  azure_key_name: string;
  azure_key_version: string;
  azure_key_id: string;
  purpose: string;
  sync_status: string;
  last_sync_at?: string;
  created_at?: string;
};

export type AzureSyncResult = {
  mapping_id: string;
  status: string;
  azure_key_id?: string;
  error?: string;
};

export async function listAzureEKMConfigs(session: AuthSession): Promise<AzureEKMConfig[]> {
  const out = await serviceRequest<{ items: AzureEKMConfig[] }>(session, "ekm", `/ekm/azure/configs?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getAzureEKMConfig(session: AuthSession, configID: string): Promise<AzureEKMConfig> {
  const out = await serviceRequest<{ config: AzureEKMConfig }>(
    session, "ekm", `/ekm/azure/configs/${encodeURIComponent(configID)}?${tenantQuery(session)}`
  );
  return out.config;
}

export async function createAzureEKMConfig(session: AuthSession, input: {
  azure_tenant_id: string;
  subscription_id?: string;
  resource_group?: string;
  vault_name: string;
  vault_url?: string;
  managed_hsm_name?: string;
  managed_hsm_url?: string;
  client_id: string;
  client_secret: string;
  auth_mode?: string;
}): Promise<AzureEKMConfig> {
  const out = await serviceRequest<{ config: AzureEKMConfig }>(session, "ekm", `/ekm/azure/configs`, {
    method: "POST",
    body: JSON.stringify({ ...input, tenant_id: session.tenantId }),
  });
  return out.config;
}

export async function updateAzureEKMConfig(session: AuthSession, configID: string, input: Partial<{
  azure_tenant_id: string;
  subscription_id: string;
  resource_group: string;
  vault_name: string;
  vault_url: string;
  managed_hsm_name: string;
  managed_hsm_url: string;
  client_id: string;
  client_secret: string;
  auth_mode: string;
}>): Promise<AzureEKMConfig> {
  const out = await serviceRequest<{ config: AzureEKMConfig }>(
    session, "ekm", `/ekm/azure/configs/${encodeURIComponent(configID)}`, {
      method: "PUT",
      body: JSON.stringify({ ...input, tenant_id: session.tenantId }),
    }
  );
  return out.config;
}

export async function deleteAzureEKMConfig(session: AuthSession, configID: string): Promise<void> {
  await serviceRequest(session, "ekm", `/ekm/azure/configs/${encodeURIComponent(configID)}?${tenantQuery(session)}`, {
    method: "DELETE",
  });
}

export async function testAzureConnection(session: AuthSession, configID: string): Promise<{ connected: boolean; authenticated?: boolean; error?: string }> {
  const out = await serviceRequest<{ connected: boolean; authenticated?: boolean; error?: string }>(
    session, "ekm", `/ekm/azure/configs/${encodeURIComponent(configID)}/test?${tenantQuery(session)}`, { method: "POST" }
  );
  return out;
}

export async function syncAzureKeys(session: AuthSession, configID: string): Promise<{ results: AzureSyncResult[]; total: number; synced: number }> {
  const out = await serviceRequest<{ results: AzureSyncResult[]; total: number; synced: number }>(
    session, "ekm", `/ekm/azure/configs/${encodeURIComponent(configID)}/sync?${tenantQuery(session)}`, { method: "POST" }
  );
  return out;
}

export async function listAzureKeyMappings(session: AuthSession, configID?: string): Promise<AzureKeyMapping[]> {
  const q = configID ? `&config_id=${encodeURIComponent(configID)}` : "";
  const out = await serviceRequest<{ items: AzureKeyMapping[] }>(session, "ekm", `/ekm/azure/mappings?${tenantQuery(session)}${q}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createAzureKeyMapping(session: AuthSession, input: {
  config_id: string;
  vecta_key_id: string;
  azure_key_name: string;
  purpose?: string;
}): Promise<AzureKeyMapping> {
  const out = await serviceRequest<{ mapping: AzureKeyMapping }>(session, "ekm", `/ekm/azure/mappings`, {
    method: "POST",
    body: JSON.stringify({ ...input, tenant_id: session.tenantId }),
  });
  return out.mapping;
}

export async function deleteAzureKeyMapping(session: AuthSession, mappingID: string): Promise<void> {
  await serviceRequest(session, "ekm", `/ekm/azure/mappings/${encodeURIComponent(mappingID)}?${tenantQuery(session)}`, {
    method: "DELETE",
  });
}

export async function importKeyToAzure(session: AuthSession, mappingID: string): Promise<{ azure_key_id: string; azure_key_version: string }> {
  const out = await serviceRequest<{ azure_key_id: string; azure_key_version: string }>(
    session, "ekm", `/ekm/azure/mappings/${encodeURIComponent(mappingID)}/import?${tenantQuery(session)}`, { method: "POST" }
  );
  return out;
}

export async function rotateAzureKey(session: AuthSession, mappingID: string): Promise<{ new_version: string }> {
  const out = await serviceRequest<{ new_version: string }>(
    session, "ekm", `/ekm/azure/mappings/${encodeURIComponent(mappingID)}/rotate?${tenantQuery(session)}`, { method: "POST" }
  );
  return out;
}

export async function wrapAzureKey(session: AuthSession, mappingID: string, valueB64: string, algorithm?: string): Promise<{ wrapped: string }> {
  const out = await serviceRequest<{ wrapped: string }>(
    session, "ekm", `/ekm/azure/mappings/${encodeURIComponent(mappingID)}/wrap`, {
      method: "POST",
      body: JSON.stringify({ tenant_id: session.tenantId, value: valueB64, algorithm: algorithm || "RSA-OAEP-256" }),
    }
  );
  return out;
}

export async function unwrapAzureKey(session: AuthSession, mappingID: string, valueB64: string, algorithm?: string): Promise<{ unwrapped: string }> {
  const out = await serviceRequest<{ unwrapped: string }>(
    session, "ekm", `/ekm/azure/mappings/${encodeURIComponent(mappingID)}/unwrap`, {
      method: "POST",
      body: JSON.stringify({ tenant_id: session.tenantId, value: valueB64, algorithm: algorithm || "RSA-OAEP-256" }),
    }
  );
  return out;
}

// ═══════════════════════ Google CSE (Client-Side Encryption) ═══════════════════════

export type GoogleCSEConfig = {
  id: string;
  tenant_id: string;
  google_workspace_customer_id: string;
  service_account_email: string;
  service_account_key_json: string;
  allowed_domains: string[];
  kacls_endpoint: string;
  status: string;
  key_count: number;
  last_activity_at?: string;
  created_at: string;
};

export type GoogleCSEKey = {
  id: string;
  tenant_id: string;
  config_id: string;
  key_name: string;
  vecta_key_id: string;
  google_key_uri: string;
  purpose: string;
  status: string;
  wrap_count: number;
  unwrap_count: number;
  last_used_at?: string;
  created_at: string;
};

export async function listGoogleCSEConfigs(session: AuthSession): Promise<GoogleCSEConfig[]> {
  const { items } = await serviceRequest<{ items: GoogleCSEConfig[] }>(
    session, "ekm", `/ekm/google-cse/configs?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return items || [];
}

export async function createGoogleCSEConfig(session: AuthSession, input: {
  google_workspace_customer_id: string;
  service_account_email?: string;
  service_account_key_json?: string;
  allowed_domains: string[];
  kacls_endpoint?: string;
}): Promise<GoogleCSEConfig> {
  const { config } = await serviceRequest<{ config: GoogleCSEConfig }>(
    session, "ekm", "/ekm/google-cse/configs", {
      method: "POST",
      body: JSON.stringify({ tenant_id: session.tenantId, ...input }),
    }
  );
  return config;
}

export async function deleteGoogleCSEConfig(session: AuthSession, configID: string): Promise<void> {
  await serviceRequest(
    session, "ekm", `/ekm/google-cse/configs/${encodeURIComponent(configID)}?tenant_id=${encodeURIComponent(session.tenantId)}`, {
      method: "DELETE",
    }
  );
}

export async function listGoogleCSEKeys(session: AuthSession, configID?: string): Promise<GoogleCSEKey[]> {
  let url = `/ekm/google-cse/keys?tenant_id=${encodeURIComponent(session.tenantId)}`;
  if (configID) url += `&config_id=${encodeURIComponent(configID)}`;
  const { items } = await serviceRequest<{ items: GoogleCSEKey[] }>(session, "ekm", url);
  return items || [];
}

export async function createGoogleCSEKey(session: AuthSession, input: {
  config_id: string;
  key_name: string;
  vecta_key_id: string;
  purpose?: string;
}): Promise<GoogleCSEKey> {
  const { key } = await serviceRequest<{ key: GoogleCSEKey }>(
    session, "ekm", "/ekm/google-cse/keys", {
      method: "POST",
      body: JSON.stringify({ tenant_id: session.tenantId, ...input }),
    }
  );
  return key;
}

export async function deleteGoogleCSEKey(session: AuthSession, keyID: string): Promise<void> {
  await serviceRequest(
    session, "ekm", `/ekm/google-cse/keys/${encodeURIComponent(keyID)}?tenant_id=${encodeURIComponent(session.tenantId)}`, {
      method: "DELETE",
    }
  );
}

// Key revocation
export async function revokeEKMTDEKey(session: AuthSession, keyId: string): Promise<any> {
  const out = await serviceRequest<any>(
    session,
    "ekm",
    `/ekm/tde/keys/${encodeURIComponent(keyId)}/revoke`,
    {
      method: "POST",
      body: JSON.stringify({ tenant_id: session.tenantId })
    }
  );
  return out;
}

// Database TDE revocation
export async function revokeDatabaseTDE(session: AuthSession, dbId: string): Promise<any> {
  const out = await serviceRequest<any>(
    session,
    "ekm",
    `/ekm/databases/${encodeURIComponent(dbId)}/revoke-tde`,
    {
      method: "POST",
      body: JSON.stringify({ tenant_id: session.tenantId })
    }
  );
  return out;
}

// Validate agent deployment
export async function validateAgentDeployment(session: AuthSession, agentId: string): Promise<any> {
  const out = await serviceRequest<any>(
    session,
    "ekm",
    `/ekm/agents/${encodeURIComponent(agentId)}/validate-deploy?${tenantQuery(session)}`
  );
  return out;
}

export type FileEncryptDownloadParams = {
  os: "linux" | "windows";
  distro?: string;
  key_id?: string;
  watch_dirs?: string;
  file_patterns?: string;
  rotation_days?: number;
  api_base_url?: string;
};

export type FileEncryptPackageFile = {
  path: string;
  content: string;
  mode: string;
};

export type FileEncryptPackage = {
  target_os: string;
  distro: string;
  created_at: string;
  algorithm: string;
  mode: string;
  key_id: string;
  rotation_days: number;
  files: FileEncryptPackageFile[];
};

// Download file encryption TDE agent package (user-space, no kernel)
export async function getFileEncryptAgentPackage(
  session: AuthSession,
  params: FileEncryptDownloadParams
): Promise<{ package: FileEncryptPackage }> {
  const qs = new URLSearchParams({ tenant_id: session.tenantId, os: params.os });
  if (params.distro) qs.set("distro", params.distro);
  if (params.key_id) qs.set("key_id", params.key_id);
  if (params.watch_dirs) qs.set("watch_dirs", params.watch_dirs);
  if (params.file_patterns) qs.set("file_patterns", params.file_patterns);
  if (params.rotation_days) qs.set("rotation_days", String(params.rotation_days));
  if (params.api_base_url) qs.set("api_base_url", params.api_base_url);
  const out = await serviceRequest<{ package: FileEncryptPackage }>(
    session,
    "tfe",
    `/tfe/file-encrypt/download?${qs.toString()}`
  );
  return out;
}
