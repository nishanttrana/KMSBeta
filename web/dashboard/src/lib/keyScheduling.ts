import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listSchedulingJobs(token: string) {
  const r = await trackedFetch(`${BASE}/scheduling/jobs`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function createSchedulingJob(token: string, body: {
  key_id: string; schedule_type: string; cron_expr?: string; interval_seconds?: number; action: string;
}) {
  const r = await trackedFetch(`${BASE}/scheduling/jobs`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function updateSchedulingJob(token: string, id: string, body: Partial<{
  schedule_type: string; cron_expr: string; interval_seconds: number; action: string; enabled: boolean;
}>) {
  const r = await trackedFetch(`${BASE}/scheduling/jobs/${id}`, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function deleteSchedulingJob(token: string, id: string) {
  const r = await trackedFetch(`${BASE}/scheduling/jobs/${id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
}
