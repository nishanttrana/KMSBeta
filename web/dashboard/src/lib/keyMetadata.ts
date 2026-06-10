import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listKeyMetadataExt(token: string) {
  const r = await trackedFetch(`${BASE}/metadata/extended`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function getKeyMetadataExt(token: string, keyId: string) {
  const r = await trackedFetch(`${BASE}/keys/${keyId}/metadata/extended`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function upsertKeyMetadataExt(token: string, keyId: string, body: {
  owner?: string;
  project?: string;
  classification?: string;
  custom_tags?: Record<string, string>;
  data_types?: string[];
  regulatory_scope?: string[];
}) {
  const r = await trackedFetch(`${BASE}/keys/${keyId}/metadata/extended`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
