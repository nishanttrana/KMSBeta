import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listKeyHealthScores(token: string) {
  const r = await trackedFetch(`${BASE}/health/scores`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function refreshKeyHealthScore(token: string, keyId: string) {
  const r = await trackedFetch(`${BASE}/health/scores/${keyId}/refresh`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function getHealthSummary(token: string) {
  const r = await trackedFetch(`${BASE}/health/summary`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
