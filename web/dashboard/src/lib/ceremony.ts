import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export interface Guardian {
  id: string;
  name: string;
  email: string;
  role: string;
  joined_at: string;
  status: "active" | "pending" | "revoked";
}

export interface CeremonyShare {
  guardian_id: string;
  guardian_name: string;
  submitted_at?: string;
  status: "pending" | "submitted" | "verified";
}

export interface Ceremony {
  id: string;
  tenant_id: string;
  name: string;
  type: "key_generation" | "key_recovery" | "key_destruction" | "root_rotation";
  threshold: number;
  total_shares: number;
  status: "draft" | "active" | "awaiting_quorum" | "completed" | "aborted";
  key_id?: string;
  key_name?: string;
  shares: CeremonyShare[];
  created_by: string;
  created_at: string;
  completed_at?: string;
  notes: string;
}

export interface CreateCeremonyRequest {
  name: string;
  type: Ceremony["type"];
  threshold: number;
  total_shares: number;
  guardian_ids: string[];
  key_id?: string;
  notes?: string;
}

export async function listGuardians(session: AuthSession): Promise<Guardian[]> {
  const res = await serviceRequest<any>(session, "keycore", "/ceremony/guardians");
  return res.items ?? [];
}

export async function createGuardian(session: AuthSession, data: Partial<Guardian>): Promise<Guardian> {
  return serviceRequest<Guardian>(session, "keycore", "/ceremony/guardians", { method: "POST", body: JSON.stringify(data) });
}

export async function deleteGuardian(session: AuthSession, id: string): Promise<void> {
  return serviceRequest<void>(session, "keycore", `/ceremony/guardians/${id}`, { method: "DELETE" });
}

export async function listCeremonies(session: AuthSession): Promise<Ceremony[]> {
  const res = await serviceRequest<any>(session, "keycore", "/ceremony");
  return res.items ?? [];
}

export async function getCeremony(session: AuthSession, id: string): Promise<Ceremony> {
  return serviceRequest<Ceremony>(session, "keycore", `/ceremony/${id}`);
}

export async function createCeremony(session: AuthSession, req: CreateCeremonyRequest): Promise<Ceremony> {
  return serviceRequest<Ceremony>(session, "keycore", "/ceremony", { method: "POST", body: JSON.stringify(req) });
}

export async function submitShare(session: AuthSession, ceremonyId: string, guardianId: string, sharePayload: string): Promise<void> {
  return serviceRequest<void>(session, "keycore", `/ceremony/${ceremonyId}/shares`, {
    method: "POST",
    body: JSON.stringify({ guardian_id: guardianId, share_payload: sharePayload })
  });
}

export async function completeCeremony(session: AuthSession, id: string): Promise<Ceremony> {
  return serviceRequest<Ceremony>(session, "keycore", `/ceremony/${id}/complete`, { method: "POST" });
}

export async function abortCeremony(session: AuthSession, id: string, reason: string): Promise<void> {
  return serviceRequest<void>(session, "keycore", `/ceremony/${id}/abort`, { method: "POST", body: JSON.stringify({ reason }) });
}
