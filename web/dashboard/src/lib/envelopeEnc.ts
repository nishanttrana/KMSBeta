import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export interface KEK {
  id: string;
  name: string;
  algorithm: string;
  version: number;
  status: "active" | "rotating" | "retired";
  dek_count: number;
  created_at: string;
  last_rotated_at?: string;
}

export interface DEK {
  id: string;
  kek_id: string;
  kek_name: string;
  name: string;
  wrapped_key_b64: string;
  algorithm: string;
  purpose: string; // "field_encryption", "file_encryption", "db_encryption", etc.
  owner_service: string;
  created_at: string;
  last_used_at?: string;
  status: "active" | "needs_rewrap" | "retired";
}

export interface EnvelopeHierarchyNode {
  kek_id: string;
  kek_name: string;
  kek_algorithm: string;
  kek_status: string;
  deks: { id: string; name: string; algorithm: string; status: string; owner_service: string }[];
}

export interface RewrapJob {
  id: string;
  old_kek_id: string;
  new_kek_id: string;
  total_deks: number;
  processed_deks: number;
  status: "running" | "completed" | "failed" | "pending";
  started_at?: string;
  completed_at?: string;
  error?: string;
}

export async function listKEKs(session: AuthSession): Promise<KEK[]> {
  const res = await serviceRequest<any>(session, "keycore", "/envelope/keks");
  return res.data ?? [];
}

export async function createKEK(session: AuthSession, data: { name: string; algorithm: string }): Promise<KEK> {
  return serviceRequest<KEK>(session, "keycore", "/envelope/keks", { method: "POST", body: JSON.stringify(data) });
}

export async function rotateKEK(session: AuthSession, kekId: string): Promise<KEK> {
  return serviceRequest<KEK>(session, "keycore", `/envelope/keks/${kekId}/rotate`, { method: "POST" });
}

export async function listDEKs(session: AuthSession, kekId?: string): Promise<DEK[]> {
  const q = kekId ? `?kek_id=${kekId}` : "";
  const res = await serviceRequest<any>(session, "keycore", `/envelope/deks${q}`);
  return res.data ?? [];
}

export async function getHierarchy(session: AuthSession): Promise<EnvelopeHierarchyNode[]> {
  const res = await serviceRequest<any>(session, "keycore", "/envelope/hierarchy");
  return res.data ?? res;
}

export async function startRewrap(session: AuthSession, oldKekId: string, newKekId: string): Promise<RewrapJob> {
  const res = await serviceRequest<any>(session, "keycore", "/envelope/rewrap", {
    method: "POST",
    body: JSON.stringify({ old_kek_id: oldKekId, new_kek_id: newKekId })
  });
  return res.data ?? res;
}

export async function listRewrapJobs(session: AuthSession): Promise<RewrapJob[]> {
  const res = await serviceRequest<any>(session, "keycore", "/envelope/rewrap-jobs");
  return res.data ?? [];
}
