import type { AuthSession } from "../../lib/auth";
import { listBackupSchedules } from "../../lib/backupSchedules";
import { getComplianceAssessmentSchedule } from "../../lib/compliance";
import { getDiscoverySchedule } from "../../lib/discovery";
import { listReportingScheduledReports } from "../../lib/reporting";
import { listPolicies } from "../../lib/rotationScheduler";
import { listIntegritySchedules, listSecretRotationSchedules } from "../../lib/scheduling";

// Every schedule in the platform as one row, read from the service that owns
// and runs it. Each list is the service's whole set (none of these routes
// pages), so the Overview's counts are the services' own. A source that
// fails is reported as unavailable, never as "no schedules".

export type ScheduleKind = "key_rotation" | "key_integrity" | "secret_rotation" | "report" | "discovery" | "assessment" | "backup";

// Each kind's label and the sub-option that edits it.
export const KINDS: Record<ScheduleKind, { label: string; sub: string }> = {
  key_rotation: { label: "Key rotation", sub: "keys" },
  key_integrity: { label: "Key integrity", sub: "integrity" },
  secret_rotation: { label: "Secret rotation", sub: "secrets" },
  report: { label: "Report", sub: "reports" },
  discovery: { label: "Discovery scan", sub: "scans" },
  assessment: { label: "Compliance assessment", sub: "scans" },
  backup: { label: "Encrypted backup", sub: "backups" },
};

// ok: the last run did its work; failed: it ran and failed; refused: it did
// not run (authority, or a precondition); never: no run yet.
export type RunResult = "ok" | "failed" | "refused" | "never";

export type ScheduleRow = {
  kind: ScheduleKind;
  id: string;
  name: string;
  cadence: string;
  // active: runs on its schedule; paused: stopped until saved again; off.
  state: "active" | "paused" | "off";
  pausedReason: string;
  next: number | null;
  last: number | null;
  result: RunResult;
  detail: string;
  authorizedBy: string;
};

export type Source = { kind: ScheduleKind; rows: ScheduleRow[] | null; error: string };

const ts = (v?: string) => {
  const n = v ? Date.parse(v) : NaN;
  return Number.isFinite(n) && n > 0 ? n : null;
};
const every = (hours: number) => (hours % 24 === 0 ? `every ${hours / 24} day${hours === 24 ? "" : "s"}` : `every ${hours} hour${hours === 1 ? "" : "s"}`);
const state = (enabled: boolean, paused?: string): ScheduleRow["state"] => (paused ? "paused" : enabled ? "active" : "off");
const result = (last: number | null, map: Record<string, RunResult>, value?: string): RunResult =>
  !last ? "never" : (value && map[value]) || "ok";

async function load<T>(kind: ScheduleKind, fetch: () => Promise<T>, toRows: (v: T) => ScheduleRow[]): Promise<Source> {
  try {
    return { kind, rows: toRows(await fetch()), error: "" };
  } catch (e) {
    return { kind, rows: null, error: e instanceof Error ? e.message : String(e) };
  }
}

export function loadSchedules(session: AuthSession, platformAdmin: boolean): Promise<Source[]> {
  const sources: Promise<Source>[] = [
    load("key_rotation", () => listPolicies(session), (items) => items.map((p) => {
      const last = ts(p.last_rotation_at);
      return {
        kind: "key_rotation", id: p.id, name: p.name, cadence: p.auto_rotate ? `every ${p.interval_days} day${p.interval_days === 1 ? "" : "s"}` : "manual only",
        state: state(p.enabled && p.auto_rotate, p.paused_reason), pausedReason: p.paused_reason || "",
        next: p.enabled && p.auto_rotate && !p.paused_reason ? ts(p.next_rotation_at) : null, last,
        result: result(last, { error: "failed" }, p.status), detail: p.last_error || p.target_filter, authorizedBy: p.authorized_by || "",
      };
    })),
    load("key_integrity", () => listIntegritySchedules(session), (items) => items.map((s) => {
      const last = ts(s.last_run_at);
      return {
        kind: "key_integrity", id: s.id, name: s.name, cadence: every(s.interval_hours), state: state(s.enabled, s.paused_reason),
        pausedReason: s.paused_reason || "", next: s.enabled && !s.paused_reason ? ts(s.next_run_at) : null, last,
        result: result(last, { passed: "ok", failed: "failed", error: "failed", refused: "refused" }, s.last_result),
        detail: s.last_error || (last ? `${s.last_checked} checked, ${s.last_failed} failed, ${s.last_not_assessed} not assessed` : s.target_filter),
        authorizedBy: s.authorized_by,
      };
    })),
    load("secret_rotation", () => listSecretRotationSchedules(session), (items) => items.map((s) => {
      const last = ts(s.last_run_at);
      return {
        kind: "secret_rotation", id: s.secret_id, name: s.secret_path || s.secret_name, cadence: every(s.interval_hours),
        state: state(s.enabled, s.paused_reason), pausedReason: s.paused_reason || "", next: s.enabled && !s.paused_reason ? ts(s.next_run_at) : null, last,
        result: result(last, { rotated: "ok", failed: "failed", refused: "refused" }, s.last_result),
        detail: s.last_error || (s.last_version ? `version ${s.last_version}` : s.secret_type), authorizedBy: s.authorized_by,
      };
    })),
    load("report", () => listReportingScheduledReports(session), (items) => items.map((r) => {
      const last = ts(r.last_run_at);
      return {
        kind: "report", id: r.id, name: r.name, cadence: r.schedule, state: state(r.enabled, r.paused_reason), pausedReason: r.paused_reason || "",
        next: r.enabled && !r.paused_reason ? ts(r.next_run_at) : null, last,
        result: result(last, { requested: "ok", failed: "failed", refused: "refused" }, r.last_result),
        detail: r.last_error || `${r.template_id} · ${r.format.toUpperCase()}`, authorizedBy: r.authorized_by || "",
      };
    })),
    load("discovery", () => getDiscoverySchedule(session), (s) => {
      const last = ts(s.last_run_at);
      return s.enabled || s.paused_reason ? [{
        kind: "discovery", id: "discovery", name: `Scan ${s.sources.length} source${s.sources.length === 1 ? "" : "s"}`, cadence: every(s.interval_hours),
        state: state(s.enabled, s.paused_reason), pausedReason: s.paused_reason || "", next: s.enabled && !s.paused_reason ? ts(s.next_run_at) : null, last,
        result: last ? "ok" : "never", detail: s.last_scan_id ? `scan ${s.last_scan_id}` : s.sources.join(", "), authorizedBy: s.authorized_by,
      }] : [];
    }),
    load("assessment", () => getComplianceAssessmentSchedule(session), (s) => {
      const last = ts(s.last_run_at);
      return s.enabled || s.paused_reason ? [{
        kind: "assessment", id: "assessment", name: "Compliance assessment", cadence: s.frequency,
        state: state(s.enabled, s.paused_reason), pausedReason: s.paused_reason || "", next: s.enabled && !s.paused_reason ? ts(s.next_run_at) : null, last,
        result: result(last, { assessed: "ok", failed: "failed", refused: "refused" }, s.last_result),
        detail: s.last_error || "", authorizedBy: s.authorized_by || "",
      }] : [];
    }),
  ];
  // Encrypted backups are platform administration (13.43.0-beta).
  if (platformAdmin) {
    sources.push(load("backup", () => listBackupSchedules(session), (items) => items.map((b) => {
      const last = ts(b.last_run_at);
      return {
        kind: "backup", id: b.id, name: b.name, cadence: every(b.interval_hours), state: state(b.enabled, b.paused_reason),
        pausedReason: b.paused_reason || "", next: b.enabled && !b.paused_reason ? ts(b.next_run_at) : null, last,
        result: result(last, { succeeded: "ok", failed: "failed", refused: "refused" }, b.last_result),
        detail: b.last_error || `${b.scope}${b.target_tenant_id ? ` ${b.target_tenant_id}` : ""} · keep ${b.retain_count}`, authorizedBy: b.authorized_by,
      };
    })));
  }
  return Promise.all(sources);
}

// The calendar day (local) a time falls on, as the bucket of the
// upcoming-runs chart; the chart and its drill-down both use it.
export const dayOf = (t: number) => new Date(t).toDateString();
