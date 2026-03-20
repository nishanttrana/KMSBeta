import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type AttestationPolicy = {
  tenant_id: string;
  enabled: boolean;
  provider: string;
  mode: string;
  key_scopes: string[];
  approved_images: string[];
  approved_subjects: string[];
  allowed_attesters: string[];
  required_measurements: Record<string, string>;
  required_claims: Record<string, string>;
  require_secure_boot: boolean;
  require_debug_disabled: boolean;
  max_evidence_age_sec: number;
  cluster_scope: string;
  allowed_cluster_nodes: string[];
  fallback_action: string;
  updated_by?: string;
  updated_at?: string;
};

export type AttestationSummary = {
  tenant_id: string;
  policy_enabled: boolean;
  provider: string;
  approved_image_count: number;
  key_scope_count: number;
  release_count_24h: number;
  deny_count_24h: number;
  review_count_24h: number;
  cryptographically_verified_count_24h: number;
  unique_cluster_nodes: number;
  last_decision_at?: string;
  latest_decision?: string;
};

export type AttestedReleaseRequest = {
  tenant_id?: string;
  key_id: string;
  key_scope?: string;
  provider: string;
  attestation_document?: string;
  attestation_format?: string;
  workload_identity?: string;
  attester?: string;
  image_ref?: string;
  image_digest?: string;
  audience?: string;
  nonce?: string;
  evidence_issued_at?: string;
  claims?: Record<string, string>;
  measurements?: Record<string, string>;
  secure_boot?: boolean;
  debug_disabled?: boolean;
  cluster_node_id?: string;
  requester?: string;
  release_reason?: string;
  dry_run?: boolean;
};

export type AttestedReleaseDecision = {
  release_id: string;
  decision: string;
  allowed: boolean;
  reasons: string[];
  matched_claims: string[];
  matched_measurements: string[];
  missing_claims: string[];
  missing_measurements: string[];
  missing_attributes: string[];
  measurement_hash: string;
  claims_hash: string;
  policy_version: string;
  provider: string;
  cluster_node_id: string;
  cryptographically_verified: boolean;
  verification_mode?: string;
  verification_issuer?: string;
  verification_key_id?: string;
  attestation_document_hash?: string;
  attestation_document_format?: string;
  expires_at?: string;
  evaluated_at?: string;
  policy: AttestationPolicy;
};

export type AttestedReleaseRecord = {
  id: string;
  tenant_id: string;
  key_id: string;
  key_scope?: string;
  provider: string;
  workload_identity?: string;
  attester?: string;
  image_ref?: string;
  image_digest?: string;
  audience?: string;
  nonce?: string;
  evidence_issued_at?: string;
  claims?: Record<string, string>;
  measurements?: Record<string, string>;
  secure_boot?: boolean;
  debug_disabled?: boolean;
  cluster_node_id?: string;
  requester?: string;
  release_reason?: string;
  decision: string;
  allowed: boolean;
  reasons: string[];
  matched_claims: string[];
  matched_measurements: string[];
  missing_claims: string[];
  missing_measurements: string[];
  missing_attributes: string[];
  measurement_hash: string;
  claims_hash: string;
  policy_version: string;
  cryptographically_verified: boolean;
  verification_mode?: string;
  verification_issuer?: string;
  verification_key_id?: string;
  attestation_document_hash?: string;
  attestation_document_format?: string;
  expires_at?: string;
  created_at?: string;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function getConfidentialPolicy(session: AuthSession): Promise<AttestationPolicy> {
  const out = await serviceRequest<{ policy: AttestationPolicy }>(
    session,
    "confidential",
    `/confidential/policy?${tenantQuery(session)}`
  );
  return (out?.policy || {}) as AttestationPolicy;
}

export async function updateConfidentialPolicy(
  session: AuthSession,
  input: Partial<AttestationPolicy>
): Promise<AttestationPolicy> {
  const out = await serviceRequest<{ policy: AttestationPolicy }>(
    session,
    "confidential",
    `/confidential/policy?${tenantQuery(session)}`,
    {
      method: "PUT",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        ...input
      })
    }
  );
  return (out?.policy || {}) as AttestationPolicy;
}

export async function getConfidentialSummary(session: AuthSession): Promise<AttestationSummary> {
  const out = await serviceRequest<{ summary: AttestationSummary }>(
    session,
    "confidential",
    `/confidential/summary?${tenantQuery(session)}`
  );
  return (out?.summary || {}) as AttestationSummary;
}

export async function evaluateConfidentialRelease(
  session: AuthSession,
  input: AttestedReleaseRequest
): Promise<AttestedReleaseDecision> {
  const out = await serviceRequest<{ result: AttestedReleaseDecision }>(
    session,
    "confidential",
    "/confidential/evaluate",
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        ...input
      })
    }
  );
  return (out?.result || {}) as AttestedReleaseDecision;
}

export async function listConfidentialReleases(
  session: AuthSession,
  limit = 100
): Promise<AttestedReleaseRecord[]> {
  const out = await serviceRequest<{ items: AttestedReleaseRecord[] }>(
    session,
    "confidential",
    `/confidential/releases?${tenantQuery(session)}&limit=${Math.max(1, Math.min(500, Number(limit) || 100))}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getConfidentialRelease(
  session: AuthSession,
  id: string
): Promise<AttestedReleaseRecord> {
  const out = await serviceRequest<{ item: AttestedReleaseRecord }>(
    session,
    "confidential",
    `/confidential/releases/${encodeURIComponent(String(id || "").trim())}?${tenantQuery(session)}`
  );
  return (out?.item || {}) as AttestedReleaseRecord;
}
