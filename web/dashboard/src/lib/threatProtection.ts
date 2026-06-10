import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function getThreatDashboard(token: string) {
  const r = await trackedFetch(`${BASE}/threat/dashboard`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function listThreatSignals(token: string) {
  const r = await trackedFetch(`${BASE}/threat/signals`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function acknowledgeSignal(token: string, id: string) {
  const r = await trackedFetch(`${BASE}/threat/signals/${id}/ack`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function listCanaryKeys(token: string) {
  const r = await trackedFetch(`${BASE}/canary/keys`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function createCanaryKey(token: string, body: { label: string; alert_on_use: boolean }) {
  const r = await trackedFetch(`${BASE}/canary/keys`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
