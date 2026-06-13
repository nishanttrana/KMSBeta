// Unified security console data layer — "two sensors, one console".
//
// Threat detection (keycore /threat/signals) and the leak scanner
// (posture /leaks/findings) stay independent services; this module is the
// presentation-layer union: it fetches both, normalizes them into a single
// SecurityFinding shape, derives cross-sensor correlations, and routes
// acknowledge/resolve actions back to the owning service. No backend coupling.

import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type FindingSource = "threat" | "leak";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "acknowledged" | "resolved";

export interface SecurityFinding {
  id: string;
  source: FindingSource;
  category: string; // signal_type or secret type, e.g. "new_actor", "aws_access_key_id"
  severity: Severity;
  title: string;
  description: string;
  subject: string; // affected key id (threat) or file:line (leak)
  keyRef?: string; // KMS key id when known — the cross-sensor join key
  detectedAt: string;
  status: FindingStatus;
  correlated?: CorrelationNote;
  raw: any;
}

export interface CorrelationNote {
  kind: "exposure_then_use";
  withId: string;
  withSource: FindingSource;
  summary: string;
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function normSeverity(s: string): Severity {
  const v = String(s || "").toLowerCase();
  return (["critical", "high", "medium", "low", "info"].includes(v) ? v : "medium") as Severity;
}

function normThreatStatus(s: any): FindingStatus {
  return s?.acknowledged_at ? "acknowledged" : "open";
}

function normLeakStatus(s: string): FindingStatus {
  const v = String(s || "open").toLowerCase();
  if (v === "resolved" || v === "false_positive" || v === "suppressed") return "resolved";
  if (v === "acknowledged") return "acknowledged";
  return "open";
}

const KEY_REF_RE = /key_[0-9a-f]{16}/;

function mapThreatSignal(s: any): SecurityFinding {
  return {
    id: `threat:${s.id}`,
    source: "threat",
    category: s.signal_type ?? s.type ?? "threat_signal",
    severity: normSeverity(s.severity),
    title: threatTitle(s.signal_type ?? s.type),
    description: s.description ?? "",
    subject: s.key_id || s.actor_id || "—",
    keyRef: typeof s.key_id === "string" && s.key_id ? s.key_id : undefined,
    detectedAt: s.detected_at ?? s.created_at ?? new Date().toISOString(),
    status: normThreatStatus(s),
    raw: s,
  };
}

function mapLeakFinding(f: any): SecurityFinding {
  // The kms_key_reference detector emits the key id in clear in the preview.
  const keyRef =
    f.type === "kms_key_reference" && typeof f.context_preview === "string"
      ? f.context_preview
      : (typeof f.location === "string" && KEY_REF_RE.exec(f.location)?.[0]) || undefined;
  return {
    id: `leak:${f.id}`,
    source: "leak",
    category: f.type ?? "secret",
    severity: normSeverity(f.severity),
    title: leakTitle(f.type),
    description: f.description ?? "",
    subject: f.location || f.target_name || "—",
    keyRef,
    detectedAt: f.detected_at ?? new Date().toISOString(),
    status: normLeakStatus(f.status),
    raw: f,
  };
}

function threatTitle(t: string): string {
  switch (t) {
    case "new_actor": return "New actor on established key";
    case "volume_spike": return "Key usage volume spike";
    case "dormant_key_activity": return "Dormant key reactivated";
    case "canary_tripped": return "Canary key tripped";
    default: return t ? t.replace(/_/g, " ") : "Threat signal";
  }
}

function leakTitle(t: string): string {
  if (!t) return "Secret exposure";
  if (t === "kms_key_reference") return "KMS key id referenced in content";
  return t.replace(/_/g, " ");
}

// correlate flags exposure-then-use: a leaked KMS key reference (leak) whose
// key id later shows a threat signal. This is the payoff of unifying the two —
// neither sensor sees it alone.
const CORRELATION_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

function correlate(findings: SecurityFinding[]): SecurityFinding[] {
  const leaksByKey = new Map<string, SecurityFinding>();
  for (const f of findings) {
    if (f.source === "leak" && f.keyRef) {
      const prev = leaksByKey.get(f.keyRef);
      if (!prev || Date.parse(f.detectedAt) < Date.parse(prev.detectedAt)) {
        leaksByKey.set(f.keyRef, f);
      }
    }
  }
  if (leaksByKey.size === 0) return findings;

  for (const f of findings) {
    if (f.source !== "threat" || !f.keyRef) continue;
    const leak = leaksByKey.get(f.keyRef);
    if (!leak) continue;
    const dt = Date.parse(f.detectedAt) - Date.parse(leak.detectedAt);
    if (dt >= 0 && dt <= CORRELATION_WINDOW_MS) {
      const note: CorrelationNote = {
        kind: "exposure_then_use",
        withId: leak.id,
        withSource: "leak",
        summary: `Key ${f.keyRef} was exposed in ${leak.subject}, then showed "${f.title}" within ${Math.max(1, Math.round(dt / 3600000))}h`,
      };
      f.correlated = note;
      leak.correlated = {
        kind: "exposure_then_use",
        withId: f.id,
        withSource: "threat",
        summary: note.summary,
      };
      // An exposure that was actually exploited is escalated to critical.
      f.severity = "critical";
      leak.severity = "critical";
    }
  }
  return findings;
}

export interface UnifiedFindings {
  findings: SecurityFinding[];
  correlations: number;
  counts: { open: number; bySeverity: Record<Severity, number>; threat: number; leak: number };
}

export async function loadUnifiedFindings(session: AuthSession): Promise<UnifiedFindings> {
  const [threatRes, leakRes] = await Promise.allSettled([
    serviceRequest<any>(session, "keycore", "/threat/signals"),
    serviceRequest<any>(session, "posture", "/leaks/findings?status=open"),
  ]);

  const findings: SecurityFinding[] = [];
  if (threatRes.status === "fulfilled") {
    const arr = threatRes.value?.signals ?? threatRes.value ?? [];
    for (const s of Array.isArray(arr) ? arr : []) findings.push(mapThreatSignal(s));
  }
  if (leakRes.status === "fulfilled") {
    const arr = leakRes.value?.items ?? leakRes.value ?? [];
    for (const f of Array.isArray(arr) ? arr : []) findings.push(mapLeakFinding(f));
  }

  correlate(findings);

  findings.sort((a, b) => {
    // Correlated findings float to the top, then by severity, then recency.
    if (!!a.correlated !== !!b.correlated) return a.correlated ? -1 : 1;
    if (SEVERITY_RANK[a.severity] !== SEVERITY_RANK[b.severity]) {
      return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    }
    return Date.parse(b.detectedAt) - Date.parse(a.detectedAt);
  });

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let open = 0, threat = 0, leak = 0, correlatedSides = 0;
  for (const f of findings) {
    if (f.status === "open") { open++; bySeverity[f.severity]++; }
    if (f.source === "threat") threat++; else leak++;
    if (f.correlated) correlatedSides++;
  }

  // Each correlation marks both its threat and leak side, so pairs = sides / 2.
  return { findings, correlations: Math.floor(correlatedSides / 2), counts: { open, bySeverity, threat, leak } };
}

// resolveFinding routes the action to the owning service.
export async function resolveFinding(session: AuthSession, f: SecurityFinding): Promise<void> {
  if (f.source === "threat") {
    const rawId = f.raw?.id;
    await serviceRequest(session, "keycore", `/threat/signals/${rawId}/ack`, { method: "POST" });
    return;
  }
  const rawId = f.raw?.id;
  await serviceRequest(session, "posture", `/leaks/findings/${rawId}`, {
    method: "PATCH",
    body: JSON.stringify({ status: "resolved" }),
  });
}
