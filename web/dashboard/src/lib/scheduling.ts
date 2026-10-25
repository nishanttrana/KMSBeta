import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Key integrity schedules (keycore, services/keycore/integrity_schedule.go)
// and secret rotation schedules (secrets, services/secrets/rotation_schedule.go).
// Each runs on the authority of the person who last saved it, re-checked
// before every run; paused_reason says why it stopped (saving resumes it).

export type IntegritySchedule = {
  id: string;
  tenant_id: string;
  name: string;
  target_filter: string;
  interval_hours: number;
  enabled: boolean;
  authorized_by: string;
  paused_reason?: string;
  next_run_at?: string;
  last_run_at?: string;
  last_result?: "passed" | "failed" | "refused" | "error" | "";
  last_error?: string;
  last_checked: number;
  last_failed: number;
  last_not_assessed: number;
};

export type IntegrityInput = { name: string; target_filter: string; interval_hours: number; enabled: boolean };

export type IntegrityOutcome = { checked: number; verified: number; not_assessed: number; failed: number; failed_keys: string[] };

const tq = (session: AuthSession) => `tenant_id=${encodeURIComponent(session.tenantId)}`;

function schedule<T>(out: { schedule?: T } | null | undefined, what: string): T {
  if (!out?.schedule) throw new Error(`${what} answered without the schedule`);
  return out.schedule;
}

export async function listIntegritySchedules(session: AuthSession): Promise<IntegritySchedule[]> {
  const out = await serviceRequest<{ items?: IntegritySchedule[] }>(session, "keycore", `/integrity/schedules?${tq(session)}`);
  if (!Array.isArray(out?.items)) throw new Error("keycore answered without integrity schedules");
  return out.items;
}

export async function saveIntegritySchedule(session: AuthSession, id: string, input: IntegrityInput): Promise<IntegritySchedule> {
  const path = id ? `/integrity/schedules/${encodeURIComponent(id)}` : "/integrity/schedules";
  return schedule(await serviceRequest<{ schedule?: IntegritySchedule }>(session, "keycore", `${path}?${tq(session)}`, {
    method: id ? "PATCH" : "POST", body: JSON.stringify(input),
  }), "keycore");
}

export async function deleteIntegritySchedule(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "keycore", `/integrity/schedules/${encodeURIComponent(id)}?${tq(session)}`, { method: "DELETE" });
}

export async function runIntegritySchedule(session: AuthSession, id: string): Promise<{ schedule: IntegritySchedule; outcome: IntegrityOutcome }> {
  const out = await serviceRequest<{ schedule?: IntegritySchedule; outcome?: IntegrityOutcome }>(session, "keycore", `/integrity/schedules/${encodeURIComponent(id)}/run?${tq(session)}`, { method: "POST" });
  if (!out?.schedule || !out.outcome) throw new Error("keycore answered without the run's outcome");
  return { schedule: out.schedule, outcome: out.outcome };
}

export type SecretRotationSchedule = {
  tenant_id: string;
  secret_id: string;
  secret_name: string;
  secret_path: string;
  secret_type: string;
  interval_hours: number;
  enabled: boolean;
  authorized_by: string;
  paused_reason?: string;
  next_run_at?: string;
  last_run_at?: string;
  last_result?: "rotated" | "refused" | "failed" | "";
  last_error?: string;
  last_version: number;
};

export async function listSecretRotationSchedules(session: AuthSession): Promise<SecretRotationSchedule[]> {
  const out = await serviceRequest<{ items?: SecretRotationSchedule[] }>(session, "secrets", `/secrets/rotation-schedules?${tq(session)}`);
  if (!Array.isArray(out?.items)) throw new Error("secrets answered without rotation schedules");
  return out.items;
}

export async function saveSecretRotationSchedule(session: AuthSession, secretID: string, input: { interval_hours: number; enabled: boolean }): Promise<SecretRotationSchedule> {
  return schedule(await serviceRequest<{ schedule?: SecretRotationSchedule }>(session, "secrets", `/secrets/rotation-schedules/${encodeURIComponent(secretID)}?${tq(session)}`, {
    method: "PUT", body: JSON.stringify(input),
  }), "secrets");
}

export async function deleteSecretRotationSchedule(session: AuthSession, secretID: string): Promise<void> {
  await serviceRequest(session, "secrets", `/secrets/rotation-schedules/${encodeURIComponent(secretID)}?${tq(session)}`, { method: "DELETE" });
}

export async function runSecretRotationSchedule(session: AuthSession, secretID: string): Promise<SecretRotationSchedule> {
  return schedule(await serviceRequest<{ schedule?: SecretRotationSchedule }>(session, "secrets", `/secrets/rotation-schedules/${encodeURIComponent(secretID)}/run?${tq(session)}`, { method: "POST" }), "secrets");
}
