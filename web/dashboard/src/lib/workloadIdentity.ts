import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type WorkloadIdentitySettings = {
  tenant_id: string;
  enabled: boolean;
  trust_domain: string;
  federation_enabled: boolean;
  token_exchange_enabled: boolean;
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
  key_usage_unavailable?: string;
};

export type WorkloadAuthorizationGraph = {
  tenant_id: string;
  generated_at: string;
  nodes: Array<{ id: string; label: string; kind: string; status: string; detail?: string }>;
  edges: Array<{ source: string; target: string; label: string; kind: string; weight?: number }>;
  key_usage_unavailable?: string;
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

// rotateWorkloadSigningKeys replaces the tenant's SPIFFE root CA and JWT-SVID
// signer (same trust domain). SVIDs issued under the old keys stop verifying.
export async function rotateWorkloadSigningKeys(session: AuthSession): Promise<WorkloadIdentitySettings> {
  const out = await serviceRequest<{ settings: WorkloadIdentitySettings }>(session, "workload", `/workload-identity/settings/rotate-signing-keys?${tenantQuery(session)}`, {
    method: "POST",
    body: "{}"
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
  input: { registration_id?: string; spiffe_id?: string; svid_type: string; audiences?: string[]; ttl_seconds?: number }
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
  input: {
    registration_id?: string;
    interface_name: string;
    audience?: string;
    jwt_svid?: string;
    x509_svid_chain_pem?: string;
    x509_svid_proof?: X509ExchangeProof;
    requested_permissions?: string[];
    requested_key_ids?: string[];
  }
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

// The token exchange needs no bearer token: the SVID is the credential. An
// X.509-SVID chain is public, so it goes with this proof of possession: a
// signature by the SVID's private key over the tenant, the leaf certificate's
// SHA-256 and the signing time (services/workload/proof.go). Accepted once,
// within two minutes.
export type X509ExchangeProof = { signed_at: string; signature: string };

function pemBlocks(pem: string, type: string): Uint8Array<ArrayBuffer>[] {
  const re = new RegExp(`-----BEGIN ${type}-----([^-]+)-----END ${type}-----`, "g");
  const out: Uint8Array<ArrayBuffer>[] = [];
  for (const m of pem.matchAll(re)) {
    const bin = atob(String(m[1] || "").replace(/\s+/g, ""));
    out.push(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  }
  return out;
}

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function signX509ExchangeProof(tenantId: string, certificatePEM: string, privateKeyPEM: string): Promise<X509ExchangeProof> {
  const [leaf] = pemBlocks(certificatePEM, "CERTIFICATE");
  const [pkcs8] = pemBlocks(privateKeyPEM, "PRIVATE KEY");
  if (!leaf || !pkcs8) {
    throw new Error("the SVID certificate and its PKCS#8 private key are required to sign the proof");
  }
  const signedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const leafSHA256 = toHex(await crypto.subtle.digest("SHA-256", leaf));
  const message = `vecta-kms/workload-token-exchange/v1\ntenant=${tenantId}\nleaf-sha256=${leafSHA256}\nsigned-at=${signedAt}`;
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(message)));
  return { signed_at: signedAt, signature: btoa(String.fromCharCode(...sig)) };
}
