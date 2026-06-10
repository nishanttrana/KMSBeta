import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listKeyInventory(token: string) {
  const r = await trackedFetch(`${BASE}/inventory/keys`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function listKeyDependencies(token: string) {
  const r = await trackedFetch(`${BASE}/inventory/dependencies`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function exportInventory(token: string) {
  const r = await trackedFetch(`${BASE}/inventory/export`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
