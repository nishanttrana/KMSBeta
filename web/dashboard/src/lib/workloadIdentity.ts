import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type WorkloadIdentitySettings = {
  tenant_id: string;
  enabled: boolean;
  trust_domain: string;
  federation_enabled: boolean;
  token_exchange_enabled: boolean;
  disable_static_api_keys: boolean;
  default_x509_ttl_seconds: number;
  default_jwt_ttl_seconds: number;
  rotation_window_seconds: number;
  allowed_audiences: string[];
  local_bundle_jwks?: string;
  local_ca_certificate_pem?: string;
  jwt_signer_key_id?: string;
  updated_by?: string;
  updated_at?: string;
};

export type WorkloadRegistration = {
  id: string;
  tenant_id: string;
  name: string;
  spiffe_id: string;
  selectors: string[];
  allowed_interfaces: string[];
  allowed_key_ids: string[];
  permissions: string[];
  issue_x509_svid: boolean;
  issue_jwt_svid: boolean;
  default_ttl_seconds: number;
  enabled: boolean;
  last_issued_at?: string;
  last_used_at?: string;
  created_at?: string;
  updated_at?: string;
};

export type WorkloadFederationBundle = {
  id: string;
  tenant_id: string;
  trust_domain: string;
  bundle_endpoint?: string;
  jwks_json?: string;
  ca_bundle_pem?: string;
  enabled: boolean;
  updated_at?: string;
};

export type WorkloadIssuanceRecord = {
  id: string;
  tenant_id: string;
  registration_id: string;
  spiffe_id: string;
  svid_type: string;
  audiences?: string[];
  serial_or_key_id: string;
  document_hash?: string;
  expires_at: string;
  rotation_due_at?: string;
  status: string;
  issued_at: string;
};

export type WorkloadUsageRecord = {
  event_id: string;
  tenant_id: string;
  workload_identity: string;
  trust_domain?: string;
  key_id?: string;
  operation: string;
  interface_name?: string;
  client_id?: string;
  result?: string;
  created_at: string;
};

export type WorkloadIdentitySummary = {
  tenant_id: string;
  enabled: boolean;
  trust_domain: string;
  federation_enabled: boolean;
  token_exchange_enabled: boolean;
  disable_static_api_keys: boolean;
  registration_count: number;
  enabled_registration_count: number;
  federated_trust_domain_count: number;
  issuance_count_24h: number;
  token_exchange_count_24h: number;
  key_usage_count_24h: number;
  unique_workloads_using_keys_24h: number;
  unique_keys_used_24h: number;
  expiring_svid_count: number;
  expired_svid_count: number;
  over_privileged_count: number;
  last_exchange_at?: string;
  last_key_use_at?: string;
  rotation_healthy: boolean;
};

export type WorkloadAuthorizationGraph = {
  tenant_id: string;
  generated_at: string;
  nodes: Array<{ id: string; label: string; kind: string; status: string; detail?: string }>;
  edges: Array<{ source: string; target: string; label: string; kind: string; weight?: number }>;
};

export type IssuedSVID = {
  issuance_id: string;
  registration_id: string;
  spiffe_id: string;
  svid_type: string;
  certificate_pem?: string;
  private_key_pem?: string;
  bundle_pem?: string;
  jwt_svid?: string;
  jwks_json?: string;
  serial_or_key_id: string;
  expires_at: string;
  rotation_due_at: string;
  cryptographically_signed: boolean;
};

export type TokenExchangeResult = {
  tenant_id: string;
  registration_id: string;
  spiffe_id: string;
  trust_domain: string;
  svid_type: string;
  interface_name: string;
  allowed_permissions: string[];
  allowed_key_ids: string[];
  kms_access_token: string;
  kms_access_token_expiry: string;
  svid_expires_at?: string;
  rotation_due_at?: string;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function getWorkloadIdentitySettings(session: AuthSession): Promise<WorkloadIdentitySettings> {
  const out = await serviceRequest<{ settings: WorkloadIdentitySettings }>(session, "workload", `/workload-identity/settings?${tenantQuery(session)}`);
  return (out?.settings || {}) as WorkloadIdentitySettings;
}

export async function updateWorkloadIdentitySettings(session: AuthSession, input: Partial<WorkloadIdentitySettings>): Promise<WorkloadIdentitySettings> {
  const out = await serviceRequest<{ settings: WorkloadIdentitySettings }>(session, "workload", `/workload-identity/settings?${tenantQuery(session)}`, {
    method: "PUT",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return (out?.settings || {}) as WorkloadIdentitySettings;
}

export async function getWorkloadIdentitySummary(session: AuthSession): Promise<WorkloadIdentitySummary> {
  const out = await serviceRequest<{ summary: WorkloadIdentitySummary }>(session, "workload", `/workload-identity/summary?${tenantQuery(session)}`);
  return (out?.summary || {}) as WorkloadIdentitySummary;
}

export async function listWorkloadRegistrations(session: AuthSession): Promise<WorkloadRegistration[]> {
  const out = await serviceRequest<{ items: WorkloadRegistration[] }>(session, "workload", `/workload-identity/registrations?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function upsertWorkloadRegistration(session: AuthSession, input: Partial<WorkloadRegistration>): Promise<WorkloadRegistration> {
  const id = String(input?.id || "").trim();
  const path = id ? `/workload-identity/registrations/${encodeURIComponent(id)}` : "/workload-identity/registrations";
  const method = id ? "PUT" : "POST";
  const out = await serviceRequest<{ registration: WorkloadRegistration }>(session, "workload", path, {
    method,
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return (out?.registration || {}) as WorkloadRegistration;
}

export async function deleteWorkloadRegistration(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "workload", `/workload-identity/registrations/${encodeURIComponent(String(id || "").trim())}?${tenantQuery(session)}`, {
    method: "DELETE"
  });
}

export async function listWorkloadFederationBundles(session: AuthSession): Promise<WorkloadFederationBundle[]> {
  const out = await serviceRequest<{ items: WorkloadFederationBundle[] }>(session, "workload", `/workload-identity/federation?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function upsertWorkloadFederationBundle(session: AuthSession, input: Partial<WorkloadFederationBundle>): Promise<WorkloadFederationBundle> {
  const id = String(input?.id || "").trim();
  const path = id ? `/workload-identity/federation/${encodeURIComponent(id)}` : "/workload-identity/federation";
  const method = id ? "PUT" : "POST";
  const out = await serviceRequest<{ bundle: WorkloadFederationBundle }>(session, "workload", path, {
    method,
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return (out?.bundle || {}) as WorkloadFederationBundle;
}

export async function deleteWorkloadFederationBundle(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "workload", `/workload-identity/federation/${encodeURIComponent(String(id || "").trim())}?${tenantQuery(session)}`, {
    method: "DELETE"
  });
}

export async function issueWorkloadSVID(
  session: AuthSession,
  input: { registration_id?: string; spiffe_id?: string; svid_type: string; audiences?: string[]; ttl_seconds?: number; requested_by?: string }
): Promise<IssuedSVID> {
  const out = await serviceRequest<{ issued: IssuedSVID }>(session, "workload", "/workload-identity/issue", {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return (out?.issued || {}) as IssuedSVID;
}

export async function listWorkloadIssuances(session: AuthSession, limit = 100): Promise<WorkloadIssuanceRecord[]> {
  const out = await serviceRequest<{ items: WorkloadIssuanceRecord[] }>(session, "workload", `/workload-identity/issuances?${tenantQuery(session)}&limit=${Math.max(1, Math.min(500, Number(limit) || 100))}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function exchangeWorkloadToken(
  session: AuthSession,
  input: { registration_id?: string; interface_name: string; client_id?: string; audience?: string; jwt_svid?: string; x509_svid_chain_pem?: string; requested_permissions?: string[]; requested_key_ids?: string[] }
): Promise<TokenExchangeResult> {
  const out = await serviceRequest<{ exchange: TokenExchangeResult }>(session, "workload", "/workload-identity/token/exchange", {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return (out?.exchange || {}) as TokenExchangeResult;
}

export async function getWorkloadAuthorizationGraph(session: AuthSession): Promise<WorkloadAuthorizationGraph> {
  const out = await serviceRequest<{ graph: WorkloadAuthorizationGraph }>(session, "workload", `/workload-identity/graph?${tenantQuery(session)}`);
  return (out?.graph || {}) as WorkloadAuthorizationGraph;
}

export async function listWorkloadUsage(session: AuthSession, limit = 100): Promise<WorkloadUsageRecord[]> {
  const out = await serviceRequest<{ items: WorkloadUsageRecord[] }>(session, "workload", `/workload-identity/usage?${tenantQuery(session)}&limit=${Math.max(1, Math.min(500, Number(limit) || 100))}`);
  return Array.isArray(out?.items) ? out.items : [];
}
