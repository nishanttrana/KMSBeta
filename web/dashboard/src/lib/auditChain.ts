import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function getAuditChain(token: string, limit = 100) {
  const r = await trackedFetch(`${BASE}/audit/chain?limit=${limit}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function verifyAuditChain(token: string) {
  const r = await trackedFetch(`${BASE}/audit/chain/verify`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function anchorAuditChain(token: string) {
  const r = await trackedFetch(`${BASE}/audit/chain/anchor`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function getAuditEvents(token: string, limit = 200) {
  const r = await trackedFetch(`${BASE}/audit/events?limit=${limit}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
