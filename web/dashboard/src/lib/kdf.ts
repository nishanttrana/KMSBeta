import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listKDFConfigs(token: string) {
  const r = await trackedFetch(`${BASE}/kdf/configs`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function createKDFConfig(token: string, body: {
  label: string; algorithm: string; params: Record<string, unknown>;
}) {
  const r = await trackedFetch(`${BASE}/kdf/configs`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function deriveKey(token: string, configId: string, body: { info?: string; salt?: string }) {
  const r = await trackedFetch(`${BASE}/kdf/configs/${configId}/derive`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function deleteKDFConfig(token: string, id: string) {
  const r = await trackedFetch(`${BASE}/kdf/configs/${id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
}
