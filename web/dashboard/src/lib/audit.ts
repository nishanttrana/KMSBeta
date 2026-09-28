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

// GET /audit/targets/{id}/integrity: each of the target's audit events
// recomputed from the stored row and checked against its chain links, its
// HMAC and the Merkle root sealed with its epoch.
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
  seal: "sealed" | "pending" | "leaf_mismatch" | "root_mismatch" | "epoch_unlinked";
  epoch_number?: number;
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
    wal_max_size_mb: Math.max(0, Number(out?.wal_max_size_mb || 0))
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
