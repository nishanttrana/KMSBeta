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

export type AuditAlert = {
  id: string;
  tenant_id: string;
  audit_event_id: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  source_service: string;
  actor_id: string;
  target_id: string;
  risk_score: number;
  status: string;
  acknowledged_by: string;
  acknowledged_at: string;
  resolved_by: string;
  resolved_at: string;
  resolution_note: string;
  dispatched_channels: string[];
  dispatch_status: Record<string, unknown>;
  dedup_key: string;
  occurrence_count: number;
  escalated_from: string;
  escalated_at: string;
  created_at: string;
  updated_at: string;
};

export type AuditAlertStats = {
  open_by_severity: Record<string, number>;
  total_open: number;
  total_acknowledged: number;
  total_resolved: number;
};

export type AuditAlertRule = {
  id: string;
  name: string;
  condition: string;
  severity: string;
  title: string;
};

export type AuditEventQuery = {
  action?: string;
  actor_id?: string;
  result?: string;
  target_id?: string;
  session_id?: string;
  correlation_id?: string;
  risk_min?: number;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
};

export type ChainVerifyResult = {
  ok: boolean;
  breaks: Array<{ sequence: number; event_id: string; reason: string }>;
  request_id: string;
};

export type AuditConfig = {
  fail_closed: boolean;
  wal_path: string;
  wal_max_size_mb: number;
  dedup_window_seconds: number;
  escalation_threshold: number;
  escalation_window_mins: number;
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
  if (String(query?.actor_id || "").trim()) q.set("actor_id", String(query!.actor_id).trim());
  if (String(query?.result || "").trim()) q.set("result", String(query!.result).trim());
  if (String(query?.target_id || "").trim()) q.set("target_id", String(query!.target_id).trim());
  if (String(query?.session_id || "").trim()) q.set("session_id", String(query!.session_id).trim());
  if (String(query?.correlation_id || "").trim()) q.set("correlation_id", String(query!.correlation_id).trim());
  if (query?.risk_min && query.risk_min > 0) q.set("risk_min", String(Math.trunc(query.risk_min)));
  if (String(query?.from || "").trim()) q.set("from", String(query!.from).trim());
  if (String(query?.to || "").trim()) q.set("to", String(query!.to).trim());
  q.set("limit", String(Math.max(1, Math.min(500, Math.trunc(Number(query?.limit || 200))))));
  q.set("offset", String(Math.max(0, Math.trunc(Number(query?.offset || 0)))));
  const out = await serviceRequest<{ items?: AuditEvent[] }>(session, "audit", `/audit/events?${q.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getAuditEvent(session: AuthSession, id: string): Promise<AuditEvent> {
  const out = await serviceRequest<{ event?: AuditEvent }>(
    session, "audit",
    `/audit/events/${encodeURIComponent(String(id || "").trim())}?${tenantQuery(session)}`
  );
  if (!out?.event) throw new Error("Audit event not found.");
  return out.event;
}

export async function getAuditTimeline(
  session: AuthSession,
  targetId: string,
  opts?: { limit?: number; offset?: number }
): Promise<AuditEvent[]> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  q.set("limit", String(Math.max(1, Math.trunc(Number(opts?.limit || 100)))));
  q.set("offset", String(Math.max(0, Math.trunc(Number(opts?.offset || 0)))));
  const out = await serviceRequest<{ items?: AuditEvent[] }>(
    session, "audit",
    `/audit/timeline/${encodeURIComponent(String(targetId || "").trim())}?${q.toString()}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getAuditSession(
  session: AuthSession,
  sessionId: string,
  opts?: { limit?: number; offset?: number }
): Promise<AuditEvent[]> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  q.set("limit", String(Math.max(1, Math.trunc(Number(opts?.limit || 100)))));
  q.set("offset", String(Math.max(0, Math.trunc(Number(opts?.offset || 0)))));
  const out = await serviceRequest<{ items?: AuditEvent[] }>(
    session, "audit",
    `/audit/session/${encodeURIComponent(String(sessionId || "").trim())}?${q.toString()}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getAuditCorrelation(
  session: AuthSession,
  correlationId: string,
  opts?: { limit?: number; offset?: number }
): Promise<AuditEvent[]> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  q.set("limit", String(Math.max(1, Math.trunc(Number(opts?.limit || 100)))));
  q.set("offset", String(Math.max(0, Math.trunc(Number(opts?.offset || 0)))));
  const out = await serviceRequest<{ items?: AuditEvent[] }>(
    session, "audit",
    `/audit/correlation/${encodeURIComponent(String(correlationId || "").trim())}?${q.toString()}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function verifyAuditChain(session: AuthSession): Promise<ChainVerifyResult> {
  const out = await serviceRequest<ChainVerifyResult>(
    session, "audit",
    `/audit/chain/verify?${tenantQuery(session)}`
  );
  return {
    ok: Boolean(out?.ok),
    breaks: Array.isArray(out?.breaks) ? out.breaks : [],
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
    wal_path: String(out?.wal_path || ""),
    wal_max_size_mb: Math.max(0, Number(out?.wal_max_size_mb || 0)),
    dedup_window_seconds: Math.max(0, Number(out?.dedup_window_seconds || 0)),
    escalation_threshold: Math.max(0, Number(out?.escalation_threshold || 0)),
    escalation_window_mins: Math.max(0, Number(out?.escalation_window_mins || 0))
  };
}

export async function listAuditAlerts(
  session: AuthSession,
  opts?: { severity?: string; category?: string; status?: string; from?: string; to?: string; limit?: number; offset?: number }
): Promise<AuditAlert[]> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  if (String(opts?.severity || "").trim()) q.set("severity", String(opts!.severity).trim());
  if (String(opts?.category || "").trim()) q.set("category", String(opts!.category).trim());
  if (String(opts?.status || "").trim()) q.set("status", String(opts!.status).trim());
  if (String(opts?.from || "").trim()) q.set("from", String(opts!.from).trim());
  if (String(opts?.to || "").trim()) q.set("to", String(opts!.to).trim());
  q.set("limit", String(Math.max(1, Math.min(500, Math.trunc(Number(opts?.limit || 100))))));
  q.set("offset", String(Math.max(0, Math.trunc(Number(opts?.offset || 0)))));
  const out = await serviceRequest<{ items?: AuditAlert[] }>(session, "audit", `/alerts?${q.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function acknowledgeAuditAlert(
  session: AuthSession,
  alertId: string,
  actor?: string,
  note?: string
): Promise<void> {
  await serviceRequest(session, "audit",
    `/alerts/${encodeURIComponent(String(alertId || "").trim())}/acknowledge?${tenantQuery(session)}`, {
      method: "PUT",
      body: JSON.stringify({
        actor: String(actor || session.username || "dashboard").trim() || "dashboard",
        note: String(note || "").trim()
      })
    });
}

export async function resolveAuditAlert(
  session: AuthSession,
  alertId: string,
  actor?: string,
  note?: string
): Promise<void> {
  await serviceRequest(session, "audit",
    `/alerts/${encodeURIComponent(String(alertId || "").trim())}/resolve?${tenantQuery(session)}`, {
      method: "PUT",
      body: JSON.stringify({
        actor: String(actor || session.username || "dashboard").trim() || "dashboard",
        resolution_note: String(note || "").trim()
      })
    });
}

export async function getAuditAlertStats(session: AuthSession): Promise<AuditAlertStats> {
  const out = await serviceRequest<{ stats?: AuditAlertStats }>(
    session, "audit",
    `/alerts/stats?${tenantQuery(session)}`
  );
  const stats: Partial<AuditAlertStats> = out?.stats || {};
  return {
    open_by_severity: stats.open_by_severity && typeof stats.open_by_severity === "object" ? stats.open_by_severity : {},
    total_open: Math.max(0, Number(stats.total_open || 0)),
    total_acknowledged: Math.max(0, Number(stats.total_acknowledged || 0)),
    total_resolved: Math.max(0, Number(stats.total_resolved || 0))
  };
}

// ── Merkle Tree Types & API ─────────────────────────────────

export type MerkleEpoch = {
  id: string;
  tenant_id: string;
  epoch_number: number;
  seq_from: number;
  seq_to: number;
  leaf_count: number;
  tree_root: string;
  created_at: string;
};

export type MerkleProofSibling = {
  hash: string;
  position: "left" | "right";
};

export type MerkleProofResponse = {
  event_id: string;
  sequence: number;
  epoch_id: string;
  leaf_hash: string;
  leaf_index: number;
  siblings: MerkleProofSibling[];
  root: string;
};

export type MerkleVerifyResult = {
  valid: boolean;
  root: string;
  request_id: string;
};

export async function listMerkleEpochs(
  session: AuthSession,
  limit = 50
): Promise<MerkleEpoch[]> {
  const out = await serviceRequest<{ items?: MerkleEpoch[] }>(
    session, "audit",
    `/audit/merkle/epochs?${tenantQuery(session)}&limit=${limit}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getEventMerkleProof(
  session: AuthSession,
  eventId: string
): Promise<MerkleProofResponse> {
  const out = await serviceRequest<{ proof?: MerkleProofResponse }>(
    session, "audit",
    `/audit/events/${encodeURIComponent(eventId)}/proof?${tenantQuery(session)}`
  );
  if (!out?.proof) throw new Error("Proof not available (event may not be in a Merkle epoch yet)");
  return out.proof;
}

export async function buildMerkleEpoch(
  session: AuthSession,
  maxLeaves = 1000
): Promise<{ epoch?: MerkleEpoch; leaves?: number; status?: string }> {
  const out = await serviceRequest<{ epoch?: MerkleEpoch; leaves?: number; status?: string }>(
    session, "audit",
    `/audit/merkle/build?${tenantQuery(session)}&max_leaves=${maxLeaves}`,
    { method: "POST" }
  );
  return out || {};
}

export async function verifyMerkleProof(
  session: AuthSession,
  proof: { leaf_hash: string; leaf_index: number; siblings: MerkleProofSibling[]; root: string }
): Promise<MerkleVerifyResult> {
  const out = await serviceRequest<MerkleVerifyResult>(
    session, "audit",
    `/audit/merkle/verify`,
    { method: "POST", body: JSON.stringify(proof) }
  );
  return {
    valid: Boolean(out?.valid),
    root: String(out?.root || ""),
    request_id: String(out?.request_id || ""),
  };
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
