import type { AuthSession } from "./auth";
import { serviceRequest, serviceRequestRaw } from "./serviceApi";
import { parseServiceJSON } from "./wire";

// Cloud BYOK (services/cloud byok_*.go, docs/SECURITY/CLOUD_BYOK.md): KMS
// keys whose material is imported into a cloud KMS, wrapped by keycore or
// inside the PKCS#11 HSM the key lives in.

export type BYOKOperation = "rotate" | "reimport" | "revoke" | "restore" | "verify" | "sync";

export type BYOKCapabilities = {
  rotate: boolean;
  reimport: boolean;
  revoke: boolean;
  revoke_deletes: boolean;
  expiry: boolean;
  verify: boolean;
  specs: string[];
};

export type BYOKProviderInfo = { provider: string; capabilities: BYOKCapabilities };

export type BYOKKey = {
  id: string;
  account_id: string;
  provider: string;
  region: string;
  key_id: string;
  source: "kms" | "hsm" | "";
  origin: "byok" | "cloud-generated";
  key_spec: string;
  usage: string;
  cloud_key_id: string;
  cloud_key_ref: string;
  alias: string;
  cloud_state: string;
  material_state: "pending_import" | "current" | "revoked" | "failed" | string;
  current_material_id: string;
  settings?: Record<string, string>;
  expires_at?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
};

export type BYOKMaterial = {
  id: string;
  byok_id: string;
  kms_version: number;
  kcv: string;
  cloud_material_id: string;
  state: string;
  scheme: string;
  source: string;
  wrapping_key_sha256: string;
  imported_at: string;
  expires_at?: string;
  revoked_at?: string;
};

export type BYOKStep = {
  name: string;
  status: "succeeded" | "failed" | "skipped";
  call?: string;
  cli?: string;
  detail?: string;
  error?: string;
  started_at: string;
  finished_at: string;
};

export type BYOKRun = {
  id: string;
  byok_id: string;
  operation: string;
  status: "succeeded" | "failed";
  steps: BYOKStep[];
  actor: string;
  error?: string;
  started_at: string;
  finished_at: string;
};

export type BYOKDetail = { key: BYOKKey; materials: BYOKMaterial[]; runs: BYOKRun[] };

export type CreateBYOKInput = {
  account_id: string;
  key_id: string;
  region?: string;
  alias?: string;
  description?: string;
  validity_days?: number;
  certificate_name?: string;
  certificate_pem?: string;
  secret_type?: string;
};

// A run that failed comes back with its steps; the error carries them.
export class BYOKRunError extends Error {
  run: BYOKRun | undefined;
  constructor(message: string, run?: BYOKRun) {
    super(message);
    this.run = run;
  }
}

const BYOK_TIMEOUT_MS = 180_000; // Google's import jobs take a while to activate

type RunResponse = { key: BYOKKey; run: BYOKRun; error?: { code?: string; message?: string } };

async function run(session: AuthSession, path: string, body: unknown): Promise<{ key: BYOKKey; run: BYOKRun }> {
  const res = await serviceRequestRaw(session, "cloud", path, { method: "POST", body: JSON.stringify(body ?? {}) }, BYOK_TIMEOUT_MS);
  const payload = (await res.text().then((t) => parseServiceJSON(t)).catch(() => ({}))) as Partial<RunResponse>;
  if (!res.ok) {
    throw new BYOKRunError(payload.error?.message || `Request failed (${res.status})`, payload.run);
  }
  return payload as RunResponse;
}

export async function listBYOKProviders(session: AuthSession): Promise<BYOKProviderInfo[]> {
  const out = await serviceRequest<{ items?: BYOKProviderInfo[] }>(session, "cloud", "/cloud/byok/providers");
  return out.items ?? [];
}

export async function listBYOKKeys(session: AuthSession): Promise<BYOKKey[]> {
  const out = await serviceRequest<{ items?: BYOKKey[] }>(session, "cloud", "/cloud/byok/keys");
  return out.items ?? [];
}

export async function getBYOKKey(session: AuthSession, id: string): Promise<BYOKDetail> {
  return serviceRequest<BYOKDetail>(session, "cloud", `/cloud/byok/keys/${encodeURIComponent(id)}`);
}

export async function listBYOKRuns(session: AuthSession): Promise<BYOKRun[]> {
  const out = await serviceRequest<{ items?: BYOKRun[] }>(session, "cloud", "/cloud/byok/runs");
  return out.items ?? [];
}

export function createBYOKKey(session: AuthSession, input: CreateBYOKInput) {
  return run(session, "/cloud/byok/keys", input);
}

export function runBYOKOperation(session: AuthSession, id: string, op: BYOKOperation, body?: { validity_days?: number; reason?: string; material_id?: string }) {
  return run(session, `/cloud/byok/keys/${encodeURIComponent(id)}/${op}`, body ?? {});
}

// The command an operator would type for each step, as a shell script.
export function runsToScript(runs: BYOKRun[]): string {
  const lines = ["#!/bin/sh", "# Cloud calls the KMS made for BYOK, as the equivalent CLI commands.", "# Wrapped key material and import tokens are files the KMS produced; they are not included.", ""];
  for (const r of runs) {
    lines.push(`# ${r.started_at} ${r.operation} ${r.byok_id} by ${r.actor || "unknown"}: ${r.status}`);
    for (const s of r.steps) {
      if (s.cli) lines.push(s.status === "succeeded" ? s.cli : `# (${s.status}) ${s.cli}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

// ---- Cloud console (13.2.0-beta): a fixed catalogue of key operations in
// KMS terms; each cloud supports the ones its API has.

export type ConsoleParam = { name: string; type: "string" | "int" | "json" | "base64"; required?: boolean; help?: string };
export type ConsoleOp = {
  name: string;
  label: string;
  group: string;
  mutating: boolean;
  danger?: boolean;
  needs_key: boolean;
  params?: ConsoleParam[];
  supported: boolean;
};
export type ConsoleCall = { account_id: string; key?: string; version?: string; region?: string; params?: Record<string, string> };
export type ConsoleResult = { result: unknown; cli: string; operation: string; provider?: string };

export class ConsoleError extends Error {
  cli: string;
  constructor(message: string, cli: string) {
    super(message);
    this.cli = cli;
  }
}

export async function listConsoleOperations(session: AuthSession, accountId: string): Promise<{ items: ConsoleOp[]; provider: string }> {
  const out = await serviceRequest<{ items?: ConsoleOp[]; provider?: string }>(session, "cloud", `/cloud/console/operations?account_id=${encodeURIComponent(accountId)}`);
  return { items: out.items ?? [], provider: out.provider ?? "" };
}

export async function runConsoleOperation(session: AuthSession, op: string, call: ConsoleCall): Promise<ConsoleResult> {
  const res = await serviceRequestRaw(session, "cloud", `/cloud/console/${encodeURIComponent(op)}`, { method: "POST", body: JSON.stringify(call) }, BYOK_TIMEOUT_MS);
  const payload = (await res.text().then((t) => parseServiceJSON(t)).catch(() => ({}))) as Partial<ConsoleResult> & { error?: { message?: string } };
  if (!res.ok) throw new ConsoleError(payload.error?.message || `Request failed (${res.status})`, payload.cli || "");
  return payload as ConsoleResult;
}

// ---- Automation (13.2.0-beta): rules on a key, acted on by playbooks.

export type BYOKAutomation = { renew_before_days: number; rotate_every_days: number; renew_validity_days: number };

export function automationOf(k: BYOKKey): BYOKAutomation {
  const n = (v?: string) => Number(v || 0) || 0;
  return { renew_before_days: n(k.settings?.renew_before_days), rotate_every_days: n(k.settings?.rotate_every_days), renew_validity_days: n(k.settings?.renew_validity_days) };
}

export async function setBYOKAutomation(session: AuthSession, id: string, a: BYOKAutomation): Promise<BYOKKey> {
  const out = await serviceRequest<{ key: BYOKKey }>(session, "cloud", `/cloud/byok/keys/${encodeURIComponent(id)}/automation`, { method: "PUT", body: JSON.stringify(a) });
  return out.key;
}

type Playbook = { id: string; name: string; trigger?: { type?: string }; enabled?: boolean };

// The two tenant playbooks that act on the automation events, one per
// trigger, for every BYOK key. Created on the caller's authority (they
// must hold cloud.write), named so they are found again.
export const AUTOMATION_PLAYBOOKS = [
  { name: "Cloud BYOK: renew expiring material", trigger: "byok_material_expiring", action: "byok_reimport",
    parameters: { byok_id: "{{event.target_id}}", validity_days: "{{event.details.validity_days}}" } },
  { name: "Cloud BYOK: rotate material when due", trigger: "byok_rotation_due", action: "byok_rotate",
    parameters: { byok_id: "{{event.target_id}}" } },
] as const;

export async function automationPlaybooks(session: AuthSession): Promise<Record<string, Playbook | undefined>> {
  const out = await serviceRequest<{ data?: Playbook[] }>(session, "compliance", "/compliance/playbooks");
  const list = out.data ?? [];
  const found: Record<string, Playbook | undefined> = {};
  for (const p of AUTOMATION_PLAYBOOKS) found[p.trigger] = list.find((x) => x.trigger?.type === p.trigger && x.name === p.name);
  return found;
}

export async function createAutomationPlaybook(session: AuthSession, trigger: string): Promise<void> {
  const p = AUTOMATION_PLAYBOOKS.find((x) => x.trigger === trigger);
  if (!p) throw new Error(`no automation playbook for ${trigger}`);
  await serviceRequest(session, "compliance", "/compliance/playbooks", {
    method: "POST",
    body: JSON.stringify({ name: p.name, enabled: true, trigger: { type: p.trigger }, actions: [{ type: p.action, parameters: p.parameters }] }),
  });
}
