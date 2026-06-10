import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function getRotationAnalytics(token: string) {
  const r = await trackedFetch(`${BASE}/rotation/analytics`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function listRotationRuns(token: string, policyId = "", limit = 50) {
  const params = new URLSearchParams();
  if (policyId) params.set("policy_id", policyId);
  if (limit) params.set("limit", String(limit));
  const r = await trackedFetch(`${BASE}/rotation/runs?${params}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function listOverdueRotations(token: string) {
  const r = await trackedFetch(`${BASE}/rotation/analytics/overdue`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function getEnterpriseSummary(token: string) {
  const r = await trackedFetch(`${BASE}/enterprise/summary`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
