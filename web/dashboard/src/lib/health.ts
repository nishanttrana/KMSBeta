// Watchdog + reconciler health client. The watchdog exposes /watchdog/*
// endpoints; the reconciler exposes /reconciler/status. Both are
// lightweight read APIs and safe to poll from the dashboard.

export interface ServiceState {
  service: string;
  last_seen: string;
  state: string;
  silence_seconds: number;
  healthy: boolean;
}

export interface Incident {
  id: string;
  service: string;
  reason: string;
  action: string;
  timestamp: string;
}

export interface ReconcilerStatus {
  name: string;
  last_run_at: string;
  last_error?: string;
}

const watchdogBase = () =>
  (typeof window !== "undefined" && (window as any).__VECTA_WATCHDOG_BASE__) || "/api/watchdog";

const reconcilerBase = () =>
  (typeof window !== "undefined" && (window as any).__VECTA_RECONCILER_BASE__) || "/api/reconciler";

async function getJSON<T>(url: string): Promise<T> {
  const resp = await fetch(url, { headers: { Accept: "application/json" } });
  if (!resp.ok) {
    throw new Error(`${url} → HTTP ${resp.status}`);
  }
  return resp.json() as Promise<T>;
}

export async function fetchHeartbeats(): Promise<ServiceState[]> {
  return getJSON<ServiceState[]>(watchdogBase() + "/watchdog/heartbeats");
}

export async function fetchIncidents(): Promise<Incident[]> {
  return getJSON<Incident[]>(watchdogBase() + "/watchdog/incidents");
}

export async function fetchReconcilerStatus(): Promise<ReconcilerStatus[]> {
  return getJSON<ReconcilerStatus[]>(reconcilerBase() + "/reconciler/status");
}
