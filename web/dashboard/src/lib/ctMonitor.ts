import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export interface WatchedDomain {
  id: string;
  domain: string;
  include_subdomains: boolean;
  alert_on_unknown_ca: boolean;
  alert_on_expiring_days: number;
  enabled: boolean;
  added_at: string;
  last_checked_at?: string;
  cert_count: number;
  alert_count: number;
}

export interface CTLogEntry {
  id: string;
  domain: string;
  subject_cn: string;
  san: string[];
  issuer: string;
  issuer_fingerprint: string;
  not_before: string;
  not_after: string;
  serial: string;
  ct_log: string;
  logged_at: string;
  is_known_ca: boolean;
  is_revoked: boolean;
  alert_triggered: boolean;
  alert_reason?: string;
}

export interface CTAlert {
  id: string;
  domain: string;
  entry_id: string;
  reason: string;
  severity: "critical" | "high" | "medium" | "info";
  status: "open" | "acknowledged" | "resolved";
  triggered_at: string;
  cert_summary: string;
}

export async function listDomains(session: AuthSession): Promise<WatchedDomain[]> {
  const res = await serviceRequest<any>(session, "certs", "/ct-monitor/domains");
  return res.items ?? [];
}

export async function addDomain(session: AuthSession, data: Partial<WatchedDomain>): Promise<WatchedDomain> {
  return serviceRequest<WatchedDomain>(session, "certs", "/ct-monitor/domains", { method: "POST", body: JSON.stringify(data) });
}

export async function deleteDomain(session: AuthSession, id: string): Promise<void> {
  return serviceRequest<void>(session, "certs", `/ct-monitor/domains/${id}`, { method: "DELETE" });
}

export async function listEntries(session: AuthSession, domain?: string): Promise<CTLogEntry[]> {
  const q = domain ? `?domain=${encodeURIComponent(domain)}` : "";
  const res = await serviceRequest<any>(session, "certs", `/ct-monitor/entries${q}`);
  return res.items ?? [];
}

export async function listAlerts(session: AuthSession): Promise<CTAlert[]> {
  const res = await serviceRequest<any>(session, "certs", "/ct-monitor/alerts");
  return res.items ?? [];
}

export async function acknowledgeAlert(session: AuthSession, id: string): Promise<CTAlert> {
  return serviceRequest<CTAlert>(session, "certs", `/ct-monitor/alerts/${id}/acknowledge`, { method: "POST" });
}

// Aliases for tab compatibility
export const listWatchedDomains = listDomains;
export const addWatchedDomain = addDomain;
export const deleteWatchedDomain = deleteDomain;
export const listCTLogEntries = listEntries;
export const listCTAlerts = listAlerts;
export const acknowledgeCTAlert = acknowledgeAlert;

// Toggle enable/disable (patch shortcut)
export async function toggleWatchedDomain(session: import("./auth").AuthSession, id: string, enabled: boolean): Promise<WatchedDomain> {
  return (await import("./serviceApi")).serviceRequest<WatchedDomain>(session, "certs", `/ct-monitor/domains/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ enabled })
  });
}
