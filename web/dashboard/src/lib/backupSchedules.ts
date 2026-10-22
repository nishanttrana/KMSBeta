import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Scheduled encrypted backups (governance, root administrators;
// services/governance/backup_schedule.go). A schedule takes a backup every
// interval_hours on the authority of the administrator who saved it and
// keeps the newest retain_count. Its key is wrapped in the tenant's HSM or
// sealed to the administrator's RSA public key; nobody is there to take a
// software key file.

export type BackupKeyProtection = "hsm" | "recipient";

export type BackupSchedule = {
  id: string;
  tenant_id: string;
  name: string;
  enabled: boolean;
  scope: "system" | "tenant";
  target_tenant_id?: string;
  interval_hours: number;
  retain_count: number;
  key_protection: BackupKeyProtection;
  recipient_public_key?: string;
  recipient_key_sha256?: string;
  authorized_by: string;
  paused_reason?: string;
  next_run_at?: string;
  last_run_at?: string;
  last_result?: string;
  last_backup_id?: string;
  last_error?: string;
  created_at: string;
  updated_at: string;
};

// Exactly the fields POST and PUT accept.
export type BackupScheduleInput = {
  name: string;
  enabled: boolean;
  scope: "system" | "tenant";
  target_tenant_id: string;
  interval_hours: number;
  retain_count: number;
  key_protection: BackupKeyProtection;
  recipient_public_key: string;
};

const base = "/governance/backups/schedules";
const tenantQuery = (session: AuthSession) => `tenant_id=${encodeURIComponent(session.tenantId)}`;

export async function listBackupSchedules(session: AuthSession): Promise<BackupSchedule[]> {
  const out = await serviceRequest<{ items?: BackupSchedule[] }>(session, "governance", `${base}?${tenantQuery(session)}`);
  if (!Array.isArray(out?.items)) throw new Error("governance returned no schedule list");
  return out.items;
}

export async function saveBackupSchedule(session: AuthSession, id: string, input: BackupScheduleInput): Promise<BackupSchedule> {
  const body: BackupScheduleInput = {
    name: input.name, enabled: input.enabled, scope: input.scope, target_tenant_id: input.target_tenant_id,
    interval_hours: input.interval_hours, retain_count: input.retain_count, key_protection: input.key_protection,
    recipient_public_key: input.key_protection === "recipient" ? input.recipient_public_key : "",
  };
  const path = id ? `${base}/${encodeURIComponent(id)}?${tenantQuery(session)}` : `${base}?${tenantQuery(session)}`;
  const out = await serviceRequest<{ schedule?: BackupSchedule }>(session, "governance", path, { method: id ? "PUT" : "POST", body: JSON.stringify(body) });
  if (!out?.schedule) throw new Error("governance returned no schedule");
  return out.schedule;
}

export async function deleteBackupSchedule(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "governance", `${base}/${encodeURIComponent(id)}?${tenantQuery(session)}`, { method: "DELETE" });
}

export async function runBackupSchedule(session: AuthSession, id: string): Promise<{ id: string }> {
  const out = await serviceRequest<{ job?: { id: string } }>(session, "governance", `${base}/${encodeURIComponent(id)}/run?${tenantQuery(session)}`, { method: "POST", body: "{}" });
  if (!out?.job?.id) throw new Error("governance returned no backup");
  return out.job;
}

// ── Unsealing a scheduled backup's key, in this browser ─────────────────

export const SEALED_KEY_MODE = "recipient_sealed";

const b64ToBytes = (b64: string): Uint8Array<ArrayBuffer> => {
  const s = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(s.length));
  for (let i = 0; i < s.length; i += 1) out[i] = s.charCodeAt(i);
  return out;
};
const bytesToB64 = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));

// The key package inside a .key.json file, or null when it isn't JSON.
export function keyPackageOf(contentBase64: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(b64ToBytes(contentBase64)));
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

export function isSealedKeyFile(contentBase64: string): boolean {
  const pkg = keyPackageOf(contentBase64);
  return pkg?.mode === SEALED_KEY_MODE && !pkg.backup_key_b64;
}

// unsealKeyFile opens a sealed key file with the administrator's private
// key (PKCS#8 PEM) here, with WebCrypto, and returns the key file with
// backup_key_b64 set, as restore takes it. The private key goes nowhere.
export async function unsealKeyFile(contentBase64: string, privateKeyPem: string): Promise<string> {
  const pkg = keyPackageOf(contentBase64);
  if (!pkg || pkg.mode !== SEALED_KEY_MODE || typeof pkg.wrapped_key_b64 !== "string") {
    throw new Error("this is not a sealed backup key file");
  }
  const body = String(privateKeyPem || "").match(/-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----/);
  if (!body) throw new Error("the private key must be PKCS#8 PEM (BEGIN PRIVATE KEY); convert with: openssl pkcs8 -topk8 -nocrypt");
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("this browser has no WebCrypto (it needs a secure context)");
  const key = await subtle.importKey("pkcs8", b64ToBytes(body[1]!.replace(/\s+/g, "")), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  let raw: Uint8Array;
  try {
    raw = new Uint8Array(await subtle.decrypt(
      { name: "RSA-OAEP", label: new TextEncoder().encode(String(pkg.oaep_label || "")) }, key, b64ToBytes(pkg.wrapped_key_b64)));
  } catch {
    throw new Error("this private key does not open the sealed backup key");
  }
  const unsealed = { ...pkg, backup_key_b64: bytesToB64(raw) };
  raw.fill(0);
  return bytesToB64(new TextEncoder().encode(JSON.stringify(unsealed)));
}
