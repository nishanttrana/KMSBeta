import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listCompromiseEvents(token: string) {
  const r = await trackedFetch(`${BASE}/compromise/events`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function reportCompromise(token: string, body: { key_id: string; reason: string; severity?: string }) {
  const r = await trackedFetch(`${BASE}/compromise/report`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function rotateCompromisedKey(token: string, keyId: string) {
  const r = await trackedFetch(`${BASE}/compromise/keys/${keyId}/rotate`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function getThreatSignals(token: string) {
  const r = await trackedFetch(`${BASE}/threat/signals`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
