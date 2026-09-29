import type { AuthSession } from "./auth";
import { serviceRequest, serviceRequestRaw } from "./serviceApi";

// Exposure register (pkg/mek, docs/SECURITY/SERVICE_MASTER_KEYS.md): items
// whose material was once stored where a database copy can reveal it: under
// a public development key before 1.2.0-beta, or in plaintext (webhook
// credentials before 1.25.0-beta, playbook connection credentials before
// 2.5.0-beta, workload signing keys before 6.11.0-beta). The live data is now under a
// keycore-held key, but a copy or backup made earlier still holds the old
// form, so an item stays listed until its material is replaced (rotated,
// re-issued, deleted) or an administrator acknowledges it with a reason.

export type ExposureItem = {
  tenant_id: string;
  item_type: string;
  item_id: string;
  source: string;
  exposed_since: string;
  remediated_at?: string;
  remediation?: string;
  remediated_by?: string;
};

export type ExposureStatus = "ok" | "no_access" | "unavailable";

export type ExposureReport = {
  service: string;
  label: string;
  status: ExposureStatus;
  items: ExposureItem[];
  error?: string;
};

// Services that stored data under a master key, and how to fix an exposed item.
export const EXPOSURE_SERVICES: { service: string; label: string; remedy: string }[] = [
  { service: "secrets", label: "Secrets", remedy: "Rotate the value where it is issued, then rotate it here (or delete the secret)." },
  { service: "certs", label: "CA signing keys", remedy: "Replace the CA: issue a new CA, re-issue its certificates, then delete this CA." },
  { service: "cloud", label: "Cloud credentials", remedy: "Rotate the credentials at the cloud provider, then re-register the account and delete this one." },
  { service: "ekm", label: "BitLocker recovery keys", remedy: "Run a BitLocker rotate job for the volume (or delete the client)." },
  { service: "audit", label: "Webhook credentials", remedy: "Rotate the signing secret and every header token (Splunk, Datadog) at the receiver, then enter the new values on the webhook (or delete it)." },
  { service: "compliance", label: "Playbook connections", remedy: "Rotate the webhook URL or token where it was issued (Slack, Teams, Jira, ServiceNow, the receiver), then enter every new value on the connection under Playbooks → Connections (or delete it)." },
  { service: "workload", label: "Workload signing keys", remedy: "Rotate the tenant's SPIFFE root CA and JWT-SVID signer under Workload Identity → Rotate Signing Keys, then give federated trust domains the new JWKS." }
];

// exposureSource says how an item was exposed.
export function exposureSource(source: string): string {
  return source === "plaintext_storage" ? "stored in plaintext by an earlier release" : "stored under the public development key before 1.2.0-beta";
}

// reportFrom turns one service's response into a report. A 403 means the
// user can't see that service's register; a 404/5xx means it isn't deployed or
// is unreachable. Neither is an error for the page as a whole.
export function reportFrom(service: string, label: string, status: number, body: unknown): ExposureReport {
  if (status === 403) return { service, label, status: "no_access", items: [] };
  if (status < 200 || status >= 300) {
    return { service, label, status: "unavailable", items: [], error: `HTTP ${status}` };
  }
  const items = Array.isArray((body as { items?: unknown })?.items) ? ((body as { items: ExposureItem[] }).items) : [];
  return { service, label, status: "ok", items };
}

export type ExposureSummary = { open: number; remediated: number; servicesChecked: number; servicesUnknown: number };

export function summarize(reports: ExposureReport[]): ExposureSummary {
  let open = 0;
  let remediated = 0;
  let checked = 0;
  for (const r of reports) {
    if (r.status !== "ok") continue;
    checked += 1;
    for (const i of r.items) {
      if (i.remediated_at) remediated += 1;
      else open += 1;
    }
  }
  return { open, remediated, servicesChecked: checked, servicesUnknown: reports.length - checked };
}

export async function listExposureReports(session: AuthSession): Promise<ExposureReport[]> {
  return Promise.all(
    EXPOSURE_SERVICES.map(async ({ service, label }) => {
      try {
        const res = await serviceRequestRaw(session, service, "/mek/exposure?open=false", { skipGlobalLoading: true });
        let body: unknown = null;
        try {
          body = await res.json();
        } catch {
          body = null;
        }
        return reportFrom(service, label, res.status, body);
      } catch (error) {
        return { service, label, status: "unavailable" as const, items: [], error: String(error) };
      }
    })
  );
}

export async function acknowledgeExposure(session: AuthSession, service: string, item: ExposureItem, reason: string): Promise<void> {
  await serviceRequest(session, service, `/mek/exposure/${encodeURIComponent(item.item_type)}/${encodeURIComponent(item.item_id)}/acknowledge`, {
    method: "POST",
    body: JSON.stringify({ reason })
  });
}
