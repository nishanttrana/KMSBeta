import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listAnomalySignals(token: string) {
  const r = await trackedFetch(`${BASE}/ml/anomalies`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function runAnomalyDetection(token: string) {
  const r = await trackedFetch(`${BASE}/ml/detect`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function getAccessHeatmap(token: string) {
  const r = await trackedFetch(`${BASE}/ml/access-heatmap`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function dismissAnomaly(token: string, id: string) {
  const r = await trackedFetch(`${BASE}/ml/anomalies/${id}/dismiss`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
