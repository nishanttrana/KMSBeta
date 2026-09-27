// Watchdog + reconciler health client, shown in Administration > Health.
// Both services serve these reads through the route kernel: the caller needs
// health.read and every read is audited (audit.watchdog.*, audit.reconciler.*).
import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

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
  recommendation?: string;
  timestamp: string;
}

export interface ReconcilerStatus {
  name: string;
  last_run_at?: string; // absent until the controller's first pass
  last_error?: string;
}

type Items<T> = { items?: T[] };

const opts = { skipGlobalLoading: true };

export async function fetchHeartbeats(session: AuthSession): Promise<ServiceState[]> {
  const out = await serviceRequest<Items<ServiceState>>(session, "watchdog", "/watchdog/heartbeats", opts);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function fetchIncidents(session: AuthSession): Promise<Incident[]> {
  const out = await serviceRequest<Items<Incident>>(session, "watchdog", "/watchdog/incidents", opts);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function fetchReconcilerStatus(session: AuthSession): Promise<ReconcilerStatus[]> {
  const out = await serviceRequest<Items<ReconcilerStatus>>(session, "reconciler", "/reconciler/status", opts);
  return Array.isArray(out?.items) ? out.items : [];
}
