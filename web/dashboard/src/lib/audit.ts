import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type AuditEvent = {
  id: string;
  tenant_id: string;
  sequence: number;
  chain_hash: string;
  previous_hash: string;
  timestamp: string;
  service: string;
  action: string;
  actor_id: string;
  actor_type: string;
  target_type: string;
  target_id: string;
  method: string;
  endpoint: string;
  source_ip: string;
  user_agent: string;
  request_hash: string;
  correlation_id: string;
  parent_event_id: string;
  session_id: string;
  result: string;
  status_code: number;
  error_message: string;
  duration_ms: number;
  fips_compliant: boolean;
  approval_id: string;
  risk_score: number;
  tags: string[];
  node_id: string;
  details: Record<string, unknown>;
  created_at: string;
};

export type AuditEventQuery = {
  action?: string;
  // Actions starting with any of these, e.g. ["audit.hsm.", "audit.key.hsm_"] (at most 5).
  action_prefix?: string[];
  actor_id?: string;
  result?: string;
  target_id?: string;
  session_id?: string;
  correlation_id?: string;
  // The bare address ("192.0.2.1") and the client's User-Agent as recorded.
  source_ip?: string;
  user_agent?: string;
  risk_min?: number;
  // Inclusive ceiling; with risk_min selects one Activity risk bucket.
  risk_max?: number;
  service?: string;
  // Drop generic HTTP request records, as the Activity statistics do.
  exclude_http_requests?: boolean;
  // The operations Operations metrics count: one metered operation, or any
  // with "*"; outcome "error" (refused or failed) or "success"; node is the
  // chain node that ran them ("" for an unclustered node).
  metered_op?: string;
  outcome?: "error" | "success";
  node?: string;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
};

export type KeyCount = { key: string; count: number };

// GET /audit/activity/stats: counts over the whole window, computed by the audit
// service (services/audit/activity/stats.go).
export type AuditStats = {
  from: string;
  to: string;
  bucket_seconds: number;
  total: number;
  by_result: KeyCount[];
  top_services: KeyCount[];
  top_actors: KeyCount[];
  actors: number;
  services: number;
  risk_buckets: KeyCount[];
  series: Array<{ start: string; count: number }>;
};

export async function getAuditStats(session: AuthSession, window: { from?: string; to?: string }): Promise<AuditStats> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  if (window.from) q.set("from", window.from);
  if (window.to) q.set("to", window.to);
  const out = await serviceRequest<{ stats: AuditStats }>(session, "audit", `/audit/activity/stats?${q.toString()}`);
  return out.stats;
}

export type ChainVerifyResult = {
  ok: boolean;
  breaks: Array<{ sequence: number; event_id: string; reason: string }>;
  // "since_checkpoint" (the default walk) or "full".
  scope: string;
  from_sequence: Record<string, number>;
  rows_checked: number;
  // When the hourly full walk last passed; null if it never has.
  last_full_verification: string | null;
  request_id: string;
};

export type AuditConfig = {
  fail_closed: boolean;
  wal_configured: boolean;
  wal_max_size_mb: number;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function listAuditEvents(
  session: AuthSession,
  query?: AuditEventQuery
): Promise<AuditEvent[]> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  if (String(query?.action || "").trim()) q.set("action", String(query!.action).trim());
  (query?.action_prefix || []).slice(0, 5).forEach((p) => { if (String(p).trim()) q.append("action_prefix", String(p).trim()); });
  if (String(query?.actor_id || "").trim()) q.set("actor_id", String(query!.actor_id).trim());
  if (String(query?.result || "").trim()) q.set("result", String(query!.result).trim());
  if (String(query?.target_id || "").trim()) q.set("target_id", String(query!.target_id).trim());
  if (String(query?.session_id || "").trim()) q.set("session_id", String(query!.session_id).trim());
  if (String(query?.correlation_id || "").trim()) q.set("correlation_id", String(query!.correlation_id).trim());
  if (String(query?.source_ip || "").trim()) q.set("source_ip", String(query!.source_ip).trim());
  if (String(query?.user_agent || "").trim()) q.set("user_agent", String(query!.user_agent).trim());
  if (query?.risk_min && query.risk_min > 0) q.set("risk_min", String(Math.trunc(query.risk_min)));
  if (query?.risk_max && query.risk_max > 0) q.set("risk_max", String(Math.trunc(query.risk_max)));
  if (String(query?.service || "").trim()) q.set("service", String(query!.service).trim());
  if (query?.exclude_http_requests) q.set("exclude_http_requests", "true");
  if (String(query?.metered_op || "").trim()) q.set("metered_op", String(query!.metered_op).trim());
  if (query?.outcome) q.set("outcome", query.outcome);
  if (typeof query?.node === "string") q.set("node", query.node);
  if (String(query?.from || "").trim()) q.set("from", String(query!.from).trim());
  if (String(query?.to || "").trim()) q.set("to", String(query!.to).trim());
  q.set("limit", String(Math.max(1, Math.min(500, Math.trunc(Number(query?.limit || 200))))));
  q.set("offset", String(Math.max(0, Math.trunc(Number(query?.offset || 0)))));
  const out = await serviceRequest<{ items?: AuditEvent[] }>(session, "audit", `/audit/events?${q.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

// GET /audit/investigate (services/audit/investigate.go): for the events the
// pivots select, the top values of each dimension, counted by the audit
// service over the whole window with the event list's own filter. Adding a
// value to the pivots lists exactly the events it counts.
export const INVESTIGATE_DIMENSIONS = [
  "actor_id", "action", "target_id", "source_ip", "user_agent", "service", "result", "session_id", "correlation_id"
] as const;
export type InvestigateDimension = (typeof INVESTIGATE_DIMENSIONS)[number];
export type InvestigatePivots = Partial<Record<InvestigateDimension, string>>;
export type InvestigateFacet = { key: string; kind?: string; count: number };
export type AuditInvestigation = {
  from: string;
  to: string;
  bucket_seconds: number;
  total: number;
  first_seen: string | null;
  last_seen: string | null;
  distinct: Record<InvestigateDimension, number>;
  facets: Record<InvestigateDimension, InvestigateFacet[]>;
  series: Array<{ start: string; count: number }>;
};

export async function getAuditInvestigation(
  session: AuthSession,
  pivots: InvestigatePivots,
  window: { from?: string; to?: string }
): Promise<AuditInvestigation> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  for (const d of INVESTIGATE_DIMENSIONS) {
    const v = String(pivots[d] || "").trim();
    if (v) q.set(d, v);
  }
  if (window.from) q.set("from", window.from);
  if (window.to) q.set("to", window.to);
  const out = await serviceRequest<{ investigation?: AuditInvestigation }>(session, "audit", `/audit/investigate?${q.toString()}`);
  const inv = out?.investigation;
  if (!inv || typeof inv.total !== "number" || !inv.facets || !Array.isArray(inv.series)) {
    throw new Error("the audit service returned no investigation");
  }
  return inv;
}

export async function getAuditEvent(session: AuthSession, id: string): Promise<AuditEvent> {
  const out = await serviceRequest<{ event?: AuditEvent }>(
    session, "audit",
    `/audit/events/${encodeURIComponent(String(id || "").trim())}?${tenantQuery(session)}`
  );
  if (!out?.event) throw new Error("Audit event not found.");
  return out.event;
}

export type AuditEventIntegrity = {
  event_id: string;
  sequence: number;
  timestamp: string;
  action: string;
  actor_id: string;
  result: string;
  content: "intact" | "altered";
  link: "linked" | "genesis" | "anchor" | "broken" | "predecessor_missing";
  signature: "verified" | "unsigned" | "not_checked" | "mismatch" | "key_unknown";
  seal: "sealed" | "pending" | "key_unknown" | "signature_invalid" | "head_mismatch";
  checkpoint_id?: string;
  checkpoint_sequence?: number;
  failures?: string[];
};

export type AuditTargetIntegrity = {
  target_id: string;
  verdict: "intact" | "tampered" | "no_events";
  events_checked: number;
  failed: number;
  sealed: number;
  pending: number;
  unsigned: number;
  truncated: boolean;
  signing_key_configured: boolean;
  verified_at: string;
  events: AuditEventIntegrity[];
};

export async function verifyTargetIntegrity(session: AuthSession, targetId: string): Promise<AuditTargetIntegrity> {
  const out = await serviceRequest<{ integrity: AuditTargetIntegrity }>(
    session, "audit",
    `/audit/targets/${encodeURIComponent(String(targetId || "").trim())}/integrity?${tenantQuery(session)}`
  );
  return out.integrity;
}

export async function verifyAuditChain(session: AuthSession): Promise<ChainVerifyResult> {
  const out = await serviceRequest<ChainVerifyResult>(
    session, "audit",
    `/audit/chain/verify?${tenantQuery(session)}`
  );
  return {
    ok: Boolean(out?.ok),
    breaks: Array.isArray(out?.breaks) ? out.breaks : [],
    scope: String(out?.scope || ""),
    from_sequence: out?.from_sequence && typeof out.from_sequence === "object" ? out.from_sequence : {},
    rows_checked: Number(out?.rows_checked || 0),
    last_full_verification: out?.last_full_verification ? String(out.last_full_verification) : null,
    request_id: String(out?.request_id || "")
  };
}

export async function getAuditConfig(session: AuthSession): Promise<AuditConfig> {
  const out = await serviceRequest<AuditConfig>(
    session, "audit",
    `/audit/config?${tenantQuery(session)}`
  );
  return {
    fail_closed: Boolean(out?.fail_closed),
    wal_configured: Boolean(out?.wal_configured),
    wal_max_size_mb: Math.max(0, Number(out?.wal_max_size_mb || 0))
  };
}

// GET /audit/checkpoints: the tenant's newest signed checkpoints. Each one
// is an ECDSA-P384 signature over the chain head (message), verified by the
// service against a trusted key and the stored row. message, signature
// (base64 DER) and public_key_pem are all an outside verifier needs.
export type AuditCheckpoint = {
  event_id: string;
  chain_node?: string;
  sequence: number;
  chain_hash: string;
  signed_at: string;
  key_id: string;
  algorithm: string;
  message: string;
  signature: string;
  public_key_pem?: string;
  status: "verified" | "key_unknown" | "signature_invalid" | "head_mismatch";
  // The checkpoint's RFC 3161 timestamp, verified now (13.47.0-beta).
  anchor?: AuditAnchorStatus;
};

export type AuditAnchorStatus = {
  status: "anchored" | "late" | "invalid" | "not_anchored";
  gen_time?: string;
  tsa?: string;
  serial?: string;
  trust?: string;
  token_b64?: string;
  error?: string;
};

// GET/PUT /audit/anchor: whether signed checkpoints are timestamped, and by
// which "tsa" credential (root administrators set it).
export type AuditAnchorSettings = { enabled: boolean; connection_id: string; updated_by?: string; updated_at?: string };

export async function getAuditAnchor(session: AuthSession): Promise<AuditAnchorSettings> {
  const out = await serviceRequest<{ anchor?: AuditAnchorSettings }>(session, "audit", "/audit/anchor");
  if (!out?.anchor) throw new Error("audit returned no anchoring settings");
  return out.anchor;
}

export async function saveAuditAnchor(session: AuthSession, input: { enabled: boolean; connection_id: string }): Promise<AuditAnchorSettings> {
  const out = await serviceRequest<{ anchor?: AuditAnchorSettings }>(session, "audit", "/audit/anchor", {
    method: "PUT", body: JSON.stringify({ enabled: input.enabled, connection_id: input.connection_id }),
  });
  if (!out?.anchor) throw new Error("audit returned no anchoring settings");
  return out.anchor;
}

export async function listAuditCheckpoints(session: AuthSession, limit = 50): Promise<AuditCheckpoint[]> {
  const out = await serviceRequest<{ items?: AuditCheckpoint[] }>(
    session, "audit",
    `/audit/checkpoints?${tenantQuery(session)}&limit=${limit}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

function downloadBlob(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function sha256Hex(data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function signAuditExport(
  session: AuthSession,
  content: string,
  signingKeyId: string
): Promise<{ signature: string; digest: string; keyId: string; algorithm: string; timestamp: string }> {
  const { signData } = await import("./keycore");
  const digest = await sha256Hex(content);
  const result = await signData(session, signingKeyId, digest, { algorithm: "rsassa-pkcs1-v1_5-sha256" });
  return {
    signature: String((result as any)?.signature || ""),
    digest,
    keyId: signingKeyId,
    algorithm: "rsassa-pkcs1-v1_5-sha256",
    timestamp: new Date().toISOString(),
  };
}

export async function exportEventsAsCSV(
  events: AuditEvent[],
  session?: AuthSession,
  signingKeyId?: string
): Promise<void> {
  const headers = [
    "timestamp", "service", "action", "actor_id", "actor_type", "target_id",
    "target_type", "result", "risk_score", "source_ip", "fips_compliant",
    "session_id", "correlation_id", "chain_hash", "sequence", "duration_ms",
    "status_code", "error_message"
  ];
  const rows = events.map((e) =>
    headers.map((h) => JSON.stringify(String((e as Record<string, unknown>)[h] ?? ""))).join(",")
  );
  const content = [headers.join(","), ...rows].join("\n");
  downloadBlob(content, "audit-events.csv", "text/csv");
  if (session && signingKeyId) {
    try {
      const signed = await signAuditExport(session, content, signingKeyId);
      const manifest = JSON.stringify({
        file: "audit-events.csv",
        sha256_digest: signed.digest,
        signature_b64: signed.signature,
        signing_key_id: signed.keyId,
        algorithm: signed.algorithm,
        signed_at: signed.timestamp,
        event_count: events.length,
      }, null, 2);
      downloadBlob(manifest, "audit-events.csv.sig.json", "application/json");
    } catch {
      // Signing failed — CSV was already downloaded
    }
  }
}

function cefSeverity(riskScore: number): number {
  if (riskScore >= 80) return 10;
  if (riskScore >= 60) return 7;
  if (riskScore >= 40) return 4;
  return 1;
}

export async function exportEventsAsCEF(
  events: AuditEvent[],
  session?: AuthSession,
  signingKeyId?: string
): Promise<void> {
  const lines = events.map((e) => {
    const sev = cefSeverity(Number(e.risk_score || 0));
    return `CEF:0|Vecta|KMS|1.0|${e.action}|${e.action}|${sev}|src=${e.source_ip || ""} suser=${e.actor_id || ""} dhost=${e.target_id || ""} outcome=${e.result || ""} msg=${e.action || ""} rt=${e.timestamp || ""}`;
  });
  const content = lines.join("\n");
  downloadBlob(content, "audit-events.cef", "text/plain");
  if (session && signingKeyId) {
    try {
      const signed = await signAuditExport(session, content, signingKeyId);
      const manifest = JSON.stringify({
        file: "audit-events.cef",
        sha256_digest: signed.digest,
        signature_b64: signed.signature,
        signing_key_id: signed.keyId,
        algorithm: signed.algorithm,
        signed_at: signed.timestamp,
        event_count: events.length,
      }, null, 2);
      downloadBlob(manifest, "audit-events.cef.sig.json", "application/json");
    } catch {
      // Signing failed — CEF was already downloaded
    }
  }
}
