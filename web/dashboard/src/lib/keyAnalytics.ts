import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function getKeyAnalytics(token: string, params?: { from?: string; to?: string; alg?: string }) {
  const q = new URLSearchParams(params as Record<string, string> | undefined);
  const r = await trackedFetch(`${BASE}/analytics/keys?${q}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function exportKeyReport(token: string, format = "json") {
  const r = await trackedFetch(`${BASE}/analytics/report?format=${format}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return format === "json" ? r.json() : r.text();
}

export async function getUsageTimeline(token: string) {
  const r = await trackedFetch(`${BASE}/analytics/usage-timeline`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
