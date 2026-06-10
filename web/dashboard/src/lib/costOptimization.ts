import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function getCostMetrics(token: string) {
  const r = await trackedFetch(`${BASE}/cost/metrics`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function getOptimizationSuggestions(token: string) {
  const r = await trackedFetch(`${BASE}/cost/suggestions`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function applyOptimization(token: string, suggestionId: string) {
  const r = await trackedFetch(`${BASE}/cost/suggestions/${suggestionId}/apply`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
