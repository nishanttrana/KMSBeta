import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type HYOKProtocol = "dke" | "salesforce" | "google" | "generic";

export type HYOKEndpoint = {
  tenant_id: string;
  protocol: HYOKProtocol;
  enabled: boolean;
  auth_mode: "mtls_or_jwt" | "mtls" | "jwt";
  policy_id: string;
  governance_required: boolean;
  metadata_json: string;
  created_at?: string;
  updated_at?: string;
};

export type HYOKRequestLog = {
  id: string;
  tenant_id: string;
  protocol: HYOKProtocol | string;
  operation: string;
  key_id: string;
  endpoint: string;
  auth_mode: string;
  auth_subject: string;
  requester_id: string;
  requester_email: string;
  policy_decision: string;
  governance_required: boolean;
  approval_request_id: string;
  status: string;
  request_json: string;
  response_json: string;
  error_message: string;
  created_at?: string;
  completed_at?: string;
};

export type HYOKHealth = {
  status: string;
  tenant_id: string;
  endpoint_count: number;
  enabled_endpoints: number;
  policy_fail_closed: boolean;
  checked_at: string;
};

export type HYOKCryptoInput = {
  plaintext?: string;
  ciphertext?: string;
  iv?: string;
  reference_id?: string;
  requester_id?: string;
  requester_email?: string;
  approver_emails?: string[];
};

type EndpointListResponse = { items: HYOKEndpoint[] };
type EndpointUpdateResponse = { endpoint: HYOKEndpoint };
type RequestListResponse = { items: HYOKRequestLog[] };
type HealthResponse = { health: HYOKHealth };
type CryptoResponse = {
  result: {
    status: string;
    key_id: string;
    protocol: string;
    operation: string;
    version?: number;
    ciphertext?: string;
    plaintext?: string;
    iv?: string;
    approval_request_id?: string;
  };
};
type DKEPublicKeyResponse = {
  key: {
    key_id: string;
    algorithm: string;
    public_key: string;
    format: string;
    key_version?: number;
  };
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

function normalizeProtocol(v: string): HYOKProtocol {
  const raw = String(v || "").trim().toLowerCase();
  if (raw === "dke" || raw === "salesforce" || raw === "google" || raw === "generic") {
    return raw;
  }
  return "generic";
}

export async function listHYOKEndpoints(session: AuthSession): Promise<HYOKEndpoint[]> {
  const out = await serviceRequest<EndpointListResponse>(session, "hyok", `/hyok/v1/endpoints?${tenantQuery(session)}`);
  return Array.isArray(out.items) ? out.items : [];
}

export async function configureHYOKEndpoint(
  session: AuthSession,
  protocol: string,
  input: {
    enabled: boolean;
    auth_mode: "mtls_or_jwt" | "mtls" | "jwt";
    policy_id?: string;
    governance_required?: boolean;
    metadata_json?: string;
  }
): Promise<HYOKEndpoint> {
  const out = await serviceRequest<EndpointUpdateResponse>(session, "hyok", `/hyok/v1/endpoints/${encodeURIComponent(normalizeProtocol(protocol))}`, {
    method: "PUT",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      enabled: Boolean(input.enabled),
      auth_mode: input.auth_mode || "mtls_or_jwt",
      policy_id: String(input.policy_id || "").trim(),
      governance_required: Boolean(input.governance_required),
      metadata_json: String(input.metadata_json || "{}")
    })
  });
  return out.endpoint;
}

export async function deleteHYOKEndpoint(session: AuthSession, protocol: string): Promise<void> {
  await serviceRequest(session, "hyok", `/hyok/v1/endpoints/${encodeURIComponent(normalizeProtocol(protocol))}?${tenantQuery(session)}`, {
    method: "DELETE"
  });
}

export async function listHYOKRequests(
  session: AuthSession,
  opts?: { protocol?: string; limit?: number; offset?: number }
): Promise<HYOKRequestLog[]> {
  const qs = new URLSearchParams();
  qs.set("tenant_id", session.tenantId);
  if (String(opts?.protocol || "").trim()) {
    qs.set("protocol", normalizeProtocol(String(opts?.protocol || "")));
  }
  if (opts?.limit && opts.limit > 0) {
    qs.set("limit", String(opts.limit));
  }
  if (opts?.offset && opts.offset > 0) {
    qs.set("offset", String(opts.offset));
  }
  const out = await serviceRequest<RequestListResponse>(session, "hyok", `/hyok/v1/requests?${qs.toString()}`);
  return Array.isArray(out.items) ? out.items : [];
}

export async function getHYOKHealth(session: AuthSession): Promise<HYOKHealth> {
  const out = await serviceRequest<HealthResponse>(session, "hyok", `/hyok/v1/health?${tenantQuery(session)}`);
  return out.health;
}

export async function hyokCrypto(
  session: AuthSession,
  protocol: string,
  operation: string,
  keyID: string,
  input: HYOKCryptoInput
): Promise<CryptoResponse["result"]> {
  const p = normalizeProtocol(protocol);
  const op = String(operation || "").trim().toLowerCase();
  const out = await serviceRequest<CryptoResponse>(
    session,
    "hyok",
    `/hyok/${p}/v1/keys/${encodeURIComponent(String(keyID || "").trim())}/${encodeURIComponent(op)}?${tenantQuery(session)}`,
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        plaintext: String(input?.plaintext || "").trim(),
        ciphertext: String(input?.ciphertext || "").trim(),
        iv: String(input?.iv || "").trim(),
        reference_id: String(input?.reference_id || "").trim(),
        requester_id: String(input?.requester_id || "").trim(),
        requester_email: String(input?.requester_email || "").trim(),
        approver_emails: Array.isArray(input?.approver_emails) ? input?.approver_emails : []
      })
    }
  );
  return out.result;
}

export async function getHYOKDKEPublicKey(
  session: AuthSession,
  keyID: string
): Promise<DKEPublicKeyResponse["key"]> {
  const out = await serviceRequest<DKEPublicKeyResponse>(
    session,
    "hyok",
    `/hyok/dke/v1/keys/${encodeURIComponent(String(keyID || "").trim())}/publickey?${tenantQuery(session)}`
  );
  return out.key;
}
