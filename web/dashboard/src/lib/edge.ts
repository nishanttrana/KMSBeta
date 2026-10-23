import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Edge devices (ekm, 13.52.0-beta; docs/SECURITY/EDGE_DEVICES.md): devices
// that lease data keys and work offline, reporting signed receipts.

export type EdgeDevice = {
  id: string;
  name: string;
  status: "pending" | "active" | "revoked";
  allowed_key_ids: string[];
  max_lease_seconds: number;
  token_pending: boolean;
  last_receipt_seq: number;
  last_seen_at?: string;
  last_source_ip?: string;
  agent_version?: string;
  created_by: string;
  created_at: string;
  enrolled_at?: string;
  revoked_at?: string;
  revoked_by?: string;
  revoke_reason?: string;
};

export type EdgeLease = { id: string; key_id: string; key_version: number; issued_at: string; expires_at: string; revoked_at?: string };

export type EdgeReceipt = { seq: number; lease_id: string; operation: string; bytes: number; at: string; received_at: string };

const q = (session: AuthSession) => `tenant_id=${encodeURIComponent(session.tenantId)}`;

export async function listEdgeDevices(session: AuthSession): Promise<EdgeDevice[]> {
  const out = await serviceRequest<{ items?: EdgeDevice[] }>(session, "ekm", `/ekm/edge/devices?${q(session)}`);
  if (!Array.isArray(out?.items)) throw new Error("ekm returned no edge device list");
  return out.items;
}

export async function createEdgeDevice(session: AuthSession, input: { name: string; allowed_key_ids: string[]; max_lease_seconds: number }): Promise<EdgeDevice> {
  const out = await serviceRequest<{ device: EdgeDevice }>(session, "ekm", `/ekm/edge/devices?${q(session)}`, { method: "POST", body: JSON.stringify(input) });
  return out.device;
}

export async function issueEdgeToken(session: AuthSession, id: string): Promise<{ token: string; expires_at: string }> {
  return serviceRequest(session, "ekm", `/ekm/edge/devices/${encodeURIComponent(id)}/registration-token?${q(session)}`, { method: "POST" });
}

export async function revokeEdgeDevice(session: AuthSession, id: string, reason: string): Promise<void> {
  await serviceRequest(session, "ekm", `/ekm/edge/devices/${encodeURIComponent(id)}/revoke?${q(session)}`, { method: "POST", body: JSON.stringify({ reason }) });
}

export async function listEdgeLeases(session: AuthSession, id: string): Promise<EdgeLease[]> {
  const out = await serviceRequest<{ items?: EdgeLease[] }>(session, "ekm", `/ekm/edge/devices/${encodeURIComponent(id)}/leases?${q(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function listEdgeReceipts(session: AuthSession, id: string): Promise<EdgeReceipt[]> {
  const out = await serviceRequest<{ items?: EdgeReceipt[] }>(session, "ekm", `/ekm/edge/devices/${encodeURIComponent(id)}/receipts?limit=100&${q(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function revokeEdgeLease(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "ekm", `/ekm/edge/leases/${encodeURIComponent(id)}/revoke?${q(session)}`, { method: "POST" });
}
