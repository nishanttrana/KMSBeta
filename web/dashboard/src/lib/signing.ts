import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type SigningSettings = {
  tenant_id: string;
  enabled: boolean;
  default_profile_id?: string;
  require_transparency: boolean;
  allowed_identity_modes: string[];
  updated_by?: string;
  updated_at?: string;
};

export type SigningProfile = {
  id?: string;
  tenant_id?: string;
  name: string;
  artifact_type: string;
  key_id: string;
  signing_algorithm: string;
  identity_mode: string;
  allowed_workload_patterns: string[];
  allowed_oidc_issuers: string[];
  allowed_subject_patterns: string[];
  allowed_repositories: string[];
  transparency_required: boolean;
  enabled: boolean;
  description?: string;
  updated_by?: string;
  updated_at?: string;
};

export type SigningRecord = {
  id: string;
  profile_id: string;
  artifact_type: string;
  artifact_name: string;
  digest_sha256: string;
  signature: string;
  key_id: string;
  signing_algorithm: string;
  identity_mode: string;
  oidc_issuer?: string;
  oidc_subject?: string;
  workload_identity?: string;
  repository?: string;
  commit_sha?: string;
  oci_reference?: string;
  transparency_entry_id?: string;
  transparency_hash?: string;
  transparency_index?: number;
  verification_status?: string;
  metadata?: Record<string, unknown>;
  created_at?: string;
};

export type SigningSummary = {
  tenant_id: string;
  enabled: boolean;
  profile_count: number;
  record_count_24h: number;
  transparency_logged_24h: number;
  workload_signed_24h: number;
  oidc_signed_24h: number;
  verification_failures_24h: number;
  artifact_counts?: Array<{ artifact_type: string; count_24h: number }>;
};

export type SignArtifactInput = {
  tenant_id?: string;
  profile_id?: string;
  artifact_type?: string;
  artifact_name: string;
  payload?: string;
  digest_sha256?: string;
  repository?: string;
  commit_sha?: string;
  oci_reference?: string;
  identity_mode?: string;
  oidc_issuer?: string;
  oidc_subject?: string;
  workload_identity?: string;
  metadata?: Record<string, unknown>;
  requested_by?: string;
};

export async function getSigningSettings(session: AuthSession): Promise<SigningSettings> {
  const out = await serviceRequest<{ settings: SigningSettings }>(session, "signing", `/signing/settings?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return out.settings;
}

export async function updateSigningSettings(session: AuthSession, input: Partial<SigningSettings>): Promise<SigningSettings> {
  const out = await serviceRequest<{ settings: SigningSettings }>(session, "signing", "/signing/settings", {
    method: "PUT",
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return out.settings;
}

export async function getSigningSummary(session: AuthSession): Promise<SigningSummary> {
  const out = await serviceRequest<{ summary: SigningSummary }>(session, "signing", `/signing/summary?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return out.summary;
}

export async function listSigningProfiles(session: AuthSession): Promise<SigningProfile[]> {
  const out = await serviceRequest<{ items: SigningProfile[] }>(session, "signing", `/signing/profiles?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return Array.isArray(out.items) ? out.items : [];
}

export async function upsertSigningProfile(session: AuthSession, input: SigningProfile): Promise<SigningProfile> {
  const path = input.id ? `/signing/profiles/${encodeURIComponent(input.id)}` : "/signing/profiles";
  const method = input.id ? "PUT" : "POST";
  const out = await serviceRequest<{ profile: SigningProfile }>(session, "signing", path, {
    method,
    body: JSON.stringify({ tenant_id: session.tenantId, ...input })
  });
  return out.profile;
}

export async function deleteSigningProfile(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "signing", `/signing/profiles/${encodeURIComponent(id)}?tenant_id=${encodeURIComponent(session.tenantId)}`, { method: "DELETE" });
}

export async function listSigningRecords(
  session: AuthSession,
  opts: { profile_id?: string; artifact_type?: string; limit?: number } = {}
): Promise<SigningRecord[]> {
  const params = new URLSearchParams({
    tenant_id: session.tenantId,
    limit: String(opts.limit || 100)
  });
  if (opts.profile_id) params.set("profile_id", opts.profile_id);
  if (opts.artifact_type) params.set("artifact_type", opts.artifact_type);
  const out = await serviceRequest<{ items: SigningRecord[] }>(session, "signing", `/signing/records?${params.toString()}`);
  return Array.isArray(out.items) ? out.items : [];
}

export async function signBlob(session: AuthSession, input: SignArtifactInput): Promise<{ record: SigningRecord; envelope: Record<string, unknown> }> {
  const body = {
    tenant_id: session.tenantId,
    ...input,
    payload: input.payload ? btoa(input.payload) : undefined
  };
  const out = await serviceRequest<{ result: { record: SigningRecord; envelope: Record<string, unknown> } }>(session, "signing", "/signing/blob", {
    method: "POST",
    body: JSON.stringify(body)
  });
  return out.result;
}

export async function signGitArtifact(session: AuthSession, input: SignArtifactInput): Promise<{ record: SigningRecord; envelope: Record<string, unknown> }> {
  const body = {
    tenant_id: session.tenantId,
    ...input,
    payload: input.payload ? btoa(input.payload) : undefined
  };
  const out = await serviceRequest<{ result: { record: SigningRecord; envelope: Record<string, unknown> } }>(session, "signing", "/signing/git", {
    method: "POST",
    body: JSON.stringify(body)
  });
  return out.result;
}

export async function verifySigningRecord(session: AuthSession, record_id: string): Promise<{ valid: boolean; record_id: string; transparency_hash?: string; transparency_entry_id?: string; verified_at?: string }> {
  const out = await serviceRequest<{ result: { valid: boolean; record_id: string; transparency_hash?: string; transparency_entry_id?: string; verified_at?: string } }>(session, "signing", "/signing/verify", {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, record_id })
  });
  return out.result;
}
