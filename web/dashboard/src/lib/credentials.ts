import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Credentials are the platform's one store of external credentials
// (Playbooks → Credentials; compliance's sealed connections). A feature that
// needs one holds its ID; no secret field value is ever returned.

export type CredentialType = {
  type: string;
  label: string;
  fields: string[];
  optional?: string[];
  secrets: string[];
  category: string;
  use?: string;
  stream?: boolean;
  choices?: Record<string, string[]>;
  public?: string[];
  default_endpoint?: string;
};

export type Credential = {
  id: string;
  tenant_id: string;
  name: string;
  type: string;
  endpoint: string;
  fields_set: string[];
  attributes: Record<string, string>;
  created_by: string;
  created_at: string;
  updated_at: string;
  credentials_changed_at: string;
  expires_at?: string;
  rotate_after_days: number;
  last_tested_at?: string;
  last_test_ok: boolean;
  last_test_error?: string;
};

export type CredentialInput = {
  name: string;
  type: string;
  fields: Record<string, string>;
  expires_at?: string | null;
  rotate_after_days: number;
};

const q = (session: AuthSession) => `tenant_id=${encodeURIComponent(session.tenantId)}`;
const json = (method: string, body?: unknown) => ({ method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });

export async function listCredentials(session: AuthSession): Promise<{ items: Credential[]; types: CredentialType[] }> {
  const res = await serviceRequest<{ data?: Credential[]; types?: CredentialType[] }>(session, "compliance", `/compliance/playbooks/connections?${q(session)}`);
  return { items: res.data ?? [], types: res.types ?? [] };
}

// Credentials a feature's picker offers: one type, or a whole category. It
// needs only the compliance.connection.use permission.
export async function listCredentialChoices(session: AuthSession, by: { type?: string; category?: string }): Promise<Credential[]> {
  const filter = by.type ? `type=${encodeURIComponent(by.type)}` : `category=${encodeURIComponent(by.category ?? "")}`;
  const res = await serviceRequest<{ data?: Credential[] }>(session, "compliance", `/compliance/connections?${filter}&${q(session)}`);
  return res.data ?? [];
}

export async function saveCredential(session: AuthSession, id: string | undefined, input: CredentialInput): Promise<Credential> {
  const path = id ? `/compliance/playbooks/connections/${encodeURIComponent(id)}` : "/compliance/playbooks/connections";
  const res = await serviceRequest<{ data: Credential }>(session, "compliance", `${path}?${q(session)}`, json(id ? "PUT" : "POST", input));
  return res.data;
}

export async function testCredential(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "compliance", `/compliance/playbooks/connections/${encodeURIComponent(id)}/test?${q(session)}`, json("POST", {}));
}

export async function deleteCredential(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "compliance", `/compliance/playbooks/connections/${encodeURIComponent(id)}?${q(session)}`, json("DELETE"));
}

export async function credentialUsage(session: AuthSession, id: string): Promise<string[]> {
  const res = await serviceRequest<{ data?: { used_by?: string[] } }>(session, "compliance", `/compliance/connections/${encodeURIComponent(id)}/usage?${q(session)}`);
  return res.data?.used_by ?? [];
}

// An HSM a key can be created, formed or imported on (keycore).
export type HSMTarget = {
  id: string; // "" is the tenant's HSM profile
  kind: "tenant_profile" | "credential";
  name: string;
  topology?: string;
  vendor?: string;
  usable: boolean;
  reason?: string;
  status: { connected?: boolean; manufacturer?: string; model?: string; token_label?: string; serial_number?: string; error?: string };
};

export type HSMTargets = { targets: HSMTarget[]; credentials_state: "listed" | "not_deployed" | "not_permitted" | "unavailable"; credentials_error?: string };

export async function listHSMTargets(session: AuthSession): Promise<HSMTargets> {
  const res = await serviceRequest<Partial<HSMTargets>>(session, "keycore", `/hsm/targets?${q(session)}`);
  return { targets: res.targets ?? [], credentials_state: res.credentials_state ?? "unavailable", credentials_error: res.credentials_error ?? "" };
}

export const topologyLabel = (t?: string) => (t === "ha_group" ? "HA group" : "Single HSM");

// Where credentials are added. A feature that needs one links here.
const VIEW_HINT = "vecta.playbooks.view";

export function openCredentials(onNavigate?: (tab: string) => void): void {
  try { window.sessionStorage.setItem(VIEW_HINT, "connections"); } catch { /* storage unavailable: the tab opens on its overview */ }
  onNavigate?.("playbooks");
}

// The view another tab asked Playbooks to open on, read once.
export function takePlaybooksView(): string {
  try {
    const v = window.sessionStorage.getItem(VIEW_HINT) || "";
    window.sessionStorage.removeItem(VIEW_HINT);
    return v;
  } catch {
    return "";
  }
}
