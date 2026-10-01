// How the Alert Center words an alert: age, headline, reason and context,
// and which informational alerts the triage list hides.

export function formatAgo(value: unknown): string {
  const raw = String(value || "").trim();
  if (!raw) {
    return "-";
  }
  const ts = new Date(raw);
  if (Number.isNaN(ts.getTime())) {
    return "-";
  }
  const diffSec = Math.max(0, Math.floor((Date.now() - ts.getTime()) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

const NOISY_INFO_ACTIONS = new Set([
  "audit.posture.events_ingested",
  "audit.posture.risk_snapshot",
  "audit.posture.preventive_controls_applied",
  "audit.cert.runtime_materialized"
]);

const GENERIC_CORRELATION_TEXT = "generated from audit event correlation pipeline";

const ACTION_REASON: Record<string, string> = {
  "audit.posture.risk_snapshot": "Posture risk baseline changed and was captured by the monitoring engine.",
  "audit.posture.events_ingested": "Posture engine ingested new security events that may affect risk.",
  "audit.posture.preventive_controls_applied": "Posture preventive controls were applied automatically.",
  "audit.cert.runtime_materialized": "Certificate runtime state was materialized for policy/runtime checks."
};

function toTitleWords(value: string): string {
  return String(value || "")
    .replace(/^audit\./i, "")
    .replaceAll("_", " ")
    .replaceAll(".", " ")
    .trim()
    .replace(/\s+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function normalizeAlertAction(item: any): string {
  const direct = String(item?.audit_action || item?.action || "").trim().toLowerCase();
  if (direct) {
    return direct;
  }
  const title = String(item?.title || "").trim().toLowerCase();
  const base = title.split(":")[0] || "";
  if (!base.startsWith("audit ")) {
    return "";
  }
  return base.replace(/\s+/g, ".");
}

export function isNoisyInfoAlert(item: any): boolean {
  const severity = String(item?.severity || "").trim().toLowerCase();
  if (severity !== "info") {
    return false;
  }
  const action = normalizeAlertAction(item);
  if (!action) {
    return false;
  }
  if (action.endsWith(".http_request")) {
    return true;
  }
  return NOISY_INFO_ACTIONS.has(action);
}

export function actionLabelForAlert(item: any): string {
  const action = normalizeAlertAction(item);
  if (!action) {
    return "General Security Event";
  }
  const parts = action.split(".").filter(Boolean);
  if (parts[0] === "audit" && parts.length >= 3) {
    return toTitleWords(parts.slice(2).join("."));
  }
  if (parts.length >= 2) {
    return toTitleWords(parts.slice(1).join("."));
  }
  return toTitleWords(action);
}

export function alertHeadline(item: any): string {
  const rawTitle = String(item?.title || "").trim();
  const targetID = String(item?.target_id || "").trim();
  const genericAuditTitle = /^audit\s+.+:\s*evt_[a-z0-9_-]+$/i.test(rawTitle);
  if (rawTitle && !genericAuditTitle) {
    return rawTitle.replaceAll("_", " ");
  }
  const label = actionLabelForAlert(item);
  if (targetID && targetID !== "-" && targetID.toLowerCase() !== "n/a" && !/^evt_/i.test(targetID)) {
    return `${label} (${targetID})`;
  }
  return label;
}

export function alertReason(item: any): string {
  const raw = String(item?.description || "").trim();
  if (raw && !raw.toLowerCase().includes(GENERIC_CORRELATION_TEXT)) {
    return raw;
  }
  const action = normalizeAlertAction(item);
  if (action && ACTION_REASON[action]) {
    return ACTION_REASON[action];
  }
  if (action) {
    return `Alert for ${actionLabelForAlert(item).toLowerCase()} activity detected by correlation engine.`;
  }
  return "Alert generated from correlated security telemetry.";
}

export function alertContext(item: any): string {
  const parts: string[] = [];
  const service = String(item?.service || "").trim();
  const actor = String(item?.actor_id || "").trim();
  const sourceIP = String(item?.source_ip || "").trim();
  const target = String(item?.target_id || "").trim();
  const dedupCount = Number(item?.dedup_count || 0);
  if (service && service !== "-") {
    parts.push(`Service: ${service}`);
  }
  if (actor && actor !== "-" && actor.toLowerCase() !== "system") {
    parts.push(`Actor: ${actor}`);
  }
  if (sourceIP && sourceIP !== "-" && sourceIP !== "::1") {
    parts.push(`IP: ${sourceIP}`);
  }
  if (target && target !== "-" && target.toLowerCase() !== "n/a" && !/^evt_/i.test(target)) {
    parts.push(`Target: ${target}`);
  }
  if (Number.isFinite(dedupCount) && dedupCount > 1) {
    parts.push(`${dedupCount} similar events`);
  }
  return parts.length ? parts.join(" • ") : "Source: correlation engine";
}

export function summarizeAlertStats(items: any[]) {
  const bySeverity: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  for (const item of Array.isArray(items) ? items : []) {
    const sev = String(item?.severity || "info").trim().toLowerCase() || "info";
    const status = String(item?.status || "new").trim().toLowerCase() || "new";
    bySeverity[sev] = (bySeverity[sev] || 0) + 1;
    byStatus[status] = (byStatus[status] || 0) + 1;
  }
  return {
    total: Array.isArray(items) ? items.length : 0,
    by_severity: bySeverity,
    by_status: byStatus
  };
}
