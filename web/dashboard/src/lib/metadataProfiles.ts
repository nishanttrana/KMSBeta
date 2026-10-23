import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Key metadata profiles (keycore, 13.50.0-beta; docs/KEYS.md "Metadata
// profiles"): what metadata a tenant's keys must carry, checked when a key
// is created, imported or updated.

export type MetadataLabelRule = { key: string; required: boolean; allowed?: string[]; pattern?: string; default?: string };

export type MetadataProfileInput = {
  name: string;
  purposes: string[];
  status: string;
  require_owner: boolean;
  require_description: boolean;
  labels: MetadataLabelRule[];
  required_tags: string[];
};

export type MetadataProfile = MetadataProfileInput & { id: string; created_by: string; updated_by: string; updated_at: string };

export type MetadataViolation = { key_id: string; name: string; purpose: string; problems: string[] };

const q = (session: AuthSession) => `tenant_id=${encodeURIComponent(session.tenantId)}`;

export async function listMetadataProfiles(session: AuthSession): Promise<MetadataProfile[]> {
  const out = await serviceRequest<{ items?: MetadataProfile[] }>(session, "keycore", `/metadata-profiles?${q(session)}`);
  if (!Array.isArray(out?.items)) throw new Error("keycore returned no metadata profile list");
  return out.items;
}

export async function saveMetadataProfile(session: AuthSession, input: MetadataProfileInput, id?: string): Promise<MetadataProfile> {
  const path = id ? `/metadata-profiles/${encodeURIComponent(id)}?${q(session)}` : `/metadata-profiles?${q(session)}`;
  const out = await serviceRequest<{ profile: MetadataProfile }>(session, "keycore", path, { method: id ? "PUT" : "POST", body: JSON.stringify(input) });
  return out.profile;
}

export async function deleteMetadataProfile(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "keycore", `/metadata-profiles/${encodeURIComponent(id)}?${q(session)}`, { method: "DELETE" });
}

export async function metadataProfileViolations(session: AuthSession, id: string): Promise<{ items: MetadataViolation[]; checked: number }> {
  const out = await serviceRequest<{ items?: MetadataViolation[]; checked?: number }>(session, "keycore", `/metadata-profiles/${encodeURIComponent(id)}/violations?${q(session)}`);
  return { items: Array.isArray(out?.items) ? out.items : [], checked: Number(out?.checked || 0) };
}

// toInput keeps only what the API takes (PUT refuses unknown fields).
export const toInput = (p: MetadataProfileInput): MetadataProfileInput => ({
  name: p.name, purposes: p.purposes, status: p.status, require_owner: p.require_owner,
  require_description: p.require_description, labels: p.labels, required_tags: p.required_tags
});
