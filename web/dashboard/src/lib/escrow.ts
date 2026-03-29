import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export interface EscrowGuardian {
  id: string;
  name: string;
  email: string;
  organization: string;
  notary_cert_fingerprint?: string;
  status: "active" | "suspended";
  added_at: string;
}

export interface EscrowPolicy {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  key_filter: string;
  threshold: number;
  guardian_ids: string[];
  legal_hold: boolean;
  jurisdiction: string;
  enabled: boolean;
  created_at: string;
  escrow_count: number;
}

export interface EscrowedKey {
  id: string;
  policy_id: string;
  policy_name: string;
  key_id: string;
  key_name: string;
  algorithm: string;
  escrowed_at: string;
  escrowed_by: string;
  guardian_ids: string[];
  status: "active" | "under_recovery" | "recovered" | "destroyed";
}

export interface RecoveryRequest {
  id: string;
  escrow_id: string;
  key_id: string;
  key_name: string;
  requestor: string;
  reason: string;
  legal_reference?: string;
  status: "pending" | "approved" | "denied" | "completed";
  approvals: { guardian_id: string; guardian_name: string; approved_at?: string; denied_at?: string }[];
  required_approvals: number;
  created_at: string;
  completed_at?: string;
}

export async function listGuardians(session: AuthSession): Promise<EscrowGuardian[]> {
  const res = await serviceRequest<any>(session, "keycore", "/escrow/guardians");
  return res.data ?? [];
}

export async function addGuardian(session: AuthSession, data: Partial<EscrowGuardian>): Promise<EscrowGuardian> {
  const res = await serviceRequest<any>(session, "keycore", "/escrow/guardians", { method: "POST", body: JSON.stringify(data) });
  return res.data ?? res;
}

export async function listPolicies(session: AuthSession): Promise<EscrowPolicy[]> {
  const res = await serviceRequest<any>(session, "keycore", "/escrow/policies");
  return res.data ?? [];
}

export async function createPolicy(session: AuthSession, data: Partial<EscrowPolicy>): Promise<EscrowPolicy> {
  const res = await serviceRequest<any>(session, "keycore", "/escrow/policies", { method: "POST", body: JSON.stringify(data) });
  return res.data ?? res;
}

export async function listEscrowedKeys(session: AuthSession): Promise<EscrowedKey[]> {
  const res = await serviceRequest<any>(session, "keycore", "/escrow/keys");
  return res.data ?? [];
}

export async function escrowKey(session: AuthSession, data: {
  policy_id: string;
  policy_name: string;
  key_id: string;
  key_name: string;
  algorithm: string;
  guardian_ids: string[];
  escrowed_by?: string;
}): Promise<EscrowedKey> {
  const res = await serviceRequest<any>(session, "keycore", "/escrow/keys", { method: "POST", body: JSON.stringify(data) });
  return res.data ?? res;
}

export async function listRecoveryRequests(session: AuthSession): Promise<RecoveryRequest[]> {
  const res = await serviceRequest<any>(session, "keycore", "/escrow/recovery");
  return res.data ?? [];
}

export async function createRecoveryRequest(session: AuthSession, data: { escrow_id: string; reason: string; legal_reference?: string }): Promise<RecoveryRequest> {
  const res = await serviceRequest<any>(session, "keycore", "/escrow/recovery", { method: "POST", body: JSON.stringify(data) });
  return res.data ?? res;
}

export async function approveRecovery(session: AuthSession, requestId: string): Promise<RecoveryRequest> {
  const res = await serviceRequest<any>(session, "keycore", `/escrow/recovery/${requestId}/approve`, { method: "POST" });
  return res.data ?? res;
}

export async function denyRecovery(session: AuthSession, requestId: string, reason: string): Promise<RecoveryRequest> {
  const res = await serviceRequest<any>(session, "keycore", `/escrow/recovery/${requestId}/deny`, { method: "POST", body: JSON.stringify({ reason }) });
  return res.data ?? res;
}
