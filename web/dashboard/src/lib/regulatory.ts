import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function getRegulatoryCompliance(token: string) {
  const r = await trackedFetch(`${BASE}/compliance/regulatory`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function getComplianceDashboard(token: string) {
  const r = await trackedFetch(`${BASE}/compliance/dashboard`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function exportComplianceReport(token: string, framework: string) {
  const r = await trackedFetch(`${BASE}/compliance/report?framework=${encodeURIComponent(framework)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
