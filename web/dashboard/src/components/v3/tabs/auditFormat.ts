import type { AuditEvent, InvestigateDimension } from "../../../lib/audit";
import { C } from "../theme";

// How the Audit Log's views (Events, Investigate, the event card) show an
// event's fields.

export function fmtTS(v: unknown): string {
  const raw = String(v || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? raw : dt.toLocaleString();
}

export function shortTS(v: unknown): string {
  const raw = String(v || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return `${dt.getMonth() + 1}/${dt.getDate()} ${dt.getHours()}:${String(dt.getMinutes()).padStart(2, "0")}`;
}

export function resultTone(r: string): string {
  const v = String(r || "").toLowerCase();
  if (v === "success") return "green";
  if (v === "failure") return "red";
  if (v === "denied" || v === "refused") return "amber";
  return "blue";
}

export function eventOrigin(e: AuditEvent): { origin: string; agentId: string } {
  const d = (e.details || {}) as Record<string, unknown>;
  const origin = typeof d.origin === "string" && d.origin ? d.origin : "service";
  const agentId = typeof d.agent_id === "string" ? d.agent_id : "";
  return { origin, agentId };
}

export function riskColor(score: number): string {
  if (score >= 80) return C.red;
  if (score >= 60) return C.orange;
  if (score >= 40) return C.amber;
  return C.green;
}

export function abbrevHash(hash: string): string {
  const h = String(hash || "");
  if (h.length <= 12) return h || "-";
  return `${h.slice(0, 6)}...${h.slice(-6)}`;
}

export function isHTTPRequestAction(action: unknown): boolean {
  return String(action || "").trim().toLowerCase().includes(".http_request");
}

// "audit.key.export_refused" -> "Export Refused".
export function formatAction(action: unknown): string {
  const raw = String(action || "").trim();
  if (!raw) return "-";
  const parts = raw.split(".").filter(Boolean);
  const words = parts.length >= 3 && parts[0]!.toLowerCase() === "audit" ? parts.slice(2).join(" ") : raw.replaceAll(".", " ");
  return words.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export const shortService = (s: string) => String(s || "").replace(/^kms-/, "");

// The questions an investigation answers, one per dimension the audit
// service counts (GET /audit/investigate).
export const DIMENSION_LABEL: Record<InvestigateDimension, string> = {
  actor_id: "Who",
  action: "What",
  target_id: "On what",
  source_ip: "From address",
  service: "Through service",
  user_agent: "With client",
  result: "Outcome",
  session_id: "Sign-in session",
  correlation_id: "Request",
};

export function dimensionValue(d: InvestigateDimension, v: string): string {
  if (d === "action") return formatAction(v);
  if (d === "service") return shortService(v);
  return v;
}
