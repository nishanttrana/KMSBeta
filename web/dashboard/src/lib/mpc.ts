import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type MPCKey = {
  id: string;
  tenant_id: string;
  name: string;
  algorithm: string;
  threshold: number;
  participant_count: number;
  participants: string[];
  status: string;
  share_version: number;
  metadata?: Record<string, unknown>;
  key_group?: string;
  expires_at?: string;
  revoked_at?: string;
  revocation_reason?: string;
  created_at?: string;
  updated_at?: string;
  last_rotated_at?: string;
};

export type MPCCeremony = {
  id: string;
  tenant_id: string;
  type: "dkg" | "sign" | "decrypt";
  key_id: string;
  algorithm: string;
  threshold: number;
  participant_count: number;
  participants: string[];
  message_hash?: string;
  ciphertext?: string;
  status: string;
  result?: Record<string, unknown>;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
  completed_at?: string;
  required_contributors: number;
};

type KeysResponse = { items: MPCKey[] };
type CeremonyResponse = { ceremony: MPCCeremony };
type ResultResponse = { result: Record<string, unknown> };

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function listMPCKeys(
  session: AuthSession,
  opts?: { limit?: number; offset?: number }
): Promise<MPCKey[]> {
  const qs = new URLSearchParams();
  qs.set("tenant_id", session.tenantId);
  if (opts?.limit && opts.limit > 0) {
    qs.set("limit", String(opts.limit));
  }
  if (opts?.offset && opts.offset > 0) {
    qs.set("offset", String(opts.offset));
  }
  const out = await serviceRequest<KeysResponse>(session, "mpc", `/mpc/keys?${qs.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function initiateMPCDKG(
  session: AuthSession,
  input: {
    key_name: string;
    algorithm: string;
    threshold: number;
    participants: string[];
    created_by?: string;
    keycore_key_id?: string;
  }
): Promise<MPCCeremony> {
  const out = await serviceRequest<CeremonyResponse>(session, "mpc", "/mpc/dkg/initiate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out.ceremony;
}

export async function contributeMPCDKG(
  session: AuthSession,
  ceremonyID: string,
  input: { party_id: string; payload?: Record<string, unknown> }
): Promise<MPCCeremony> {
  const out = await serviceRequest<CeremonyResponse>(
    session,
    "mpc",
    `/mpc/dkg/${encodeURIComponent(ceremonyID)}/contribute`,
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        party_id: input.party_id,
        payload: input.payload || {}
      })
    }
  );
  return out.ceremony;
}

export async function initiateMPCSign(
  session: AuthSession,
  input: { key_id: string; message_hash: string; participants?: string[]; created_by?: string }
): Promise<MPCCeremony> {
  const out = await serviceRequest<CeremonyResponse>(session, "mpc", "/mpc/sign/initiate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out.ceremony;
}

export async function contributeMPCSign(
  session: AuthSession,
  ceremonyID: string,
  input: { party_id: string; partial_signature?: string }
): Promise<MPCCeremony> {
  const out = await serviceRequest<CeremonyResponse>(
    session,
    "mpc",
    `/mpc/sign/${encodeURIComponent(ceremonyID)}/contribute`,
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        party_id: input.party_id,
        partial_signature: input.partial_signature || ""
      })
    }
  );
  return out.ceremony;
}

export async function getMPCSignResult(
  session: AuthSession,
  ceremonyID: string
): Promise<Record<string, unknown>> {
  const out = await serviceRequest<ResultResponse>(
    session,
    "mpc",
    `/mpc/sign/${encodeURIComponent(ceremonyID)}/result?${tenantQuery(session)}`
  );
  return out.result || {};
}

export async function initiateMPCDecrypt(
  session: AuthSession,
  input: { key_id: string; ciphertext: string; participants?: string[]; created_by?: string }
): Promise<MPCCeremony> {
  const out = await serviceRequest<CeremonyResponse>(session, "mpc", "/mpc/decrypt/initiate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out.ceremony;
}

export async function contributeMPCDecrypt(
  session: AuthSession,
  ceremonyID: string,
  input: { party_id: string }
): Promise<MPCCeremony> {
  const out = await serviceRequest<CeremonyResponse>(
    session,
    "mpc",
    `/mpc/decrypt/${encodeURIComponent(ceremonyID)}/contribute`,
    {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        party_id: input.party_id
      })
    }
  );
  return out.ceremony;
}

export async function getMPCDecryptResult(
  session: AuthSession,
  ceremonyID: string
): Promise<Record<string, unknown>> {
  const out = await serviceRequest<ResultResponse>(
    session,
    "mpc",
    `/mpc/decrypt/${encodeURIComponent(ceremonyID)}/result?${tenantQuery(session)}`
  );
  return out.result || {};
}

// ── Enterprise types ──────────────────────────────────────────

export type MPCParticipant = {
  id: string;
  tenant_id: string;
  name: string;
  endpoint: string;
  public_key: string;
  status: string;
  last_seen_at?: string;
  created_at: string;
  updated_at: string;
};

export type MPCPolicyRule = {
  id: string;
  policy_id: string;
  rule_type: string;
  params: string;
  created_at: string;
};

export type MPCPolicy = {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  key_ids: string;
  enabled: boolean;
  rules: MPCPolicyRule[];
  created_at: string;
  updated_at: string;
};

export type MPCOverviewStats = {
  total_keys: number;
  active_keys: number;
  revoked_keys: number;
  total_ceremonies: number;
  pending_ceremonies: number;
  completed_ceremonies: number;
  failed_ceremonies: number;
  active_participants: number;
  total_participants: number;
  active_policies: number;
};

export type MPCOverview = {
  stats: MPCOverviewStats;
  recent_ceremonies: MPCCeremony[];
  participants: MPCParticipant[];
};

// ── Enterprise API functions ──────────────────────────────────

export async function getMPCOverview(session: AuthSession): Promise<MPCOverview> {
  const out = await serviceRequest<{ overview: MPCOverview }>(
    session, "mpc", `/mpc/overview?${tenantQuery(session)}`
  );
  return out.overview;
}

export async function listMPCCeremonies(
  session: AuthSession,
  opts?: { type?: string; status?: string; limit?: number }
): Promise<MPCCeremony[]> {
  const qs = new URLSearchParams();
  qs.set("tenant_id", session.tenantId);
  if (opts?.type) qs.set("type", opts.type);
  if (opts?.status) qs.set("status", opts.status);
  if (opts?.limit) qs.set("limit", String(opts.limit));
  const out = await serviceRequest<{ items: MPCCeremony[] }>(
    session, "mpc", `/mpc/ceremonies?${qs.toString()}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createMPCParticipant(
  session: AuthSession,
  input: { name: string; endpoint?: string; public_key?: string }
): Promise<MPCParticipant> {
  const out = await serviceRequest<{ participant: MPCParticipant }>(
    session, "mpc", "/mpc/participants",
    { method: "POST", body: JSON.stringify({ tenant_id: session.tenantId, ...input }) }
  );
  return out.participant;
}

export async function listMPCParticipants(session: AuthSession): Promise<MPCParticipant[]> {
  const out = await serviceRequest<{ items: MPCParticipant[] }>(
    session, "mpc", `/mpc/participants?${tenantQuery(session)}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function updateMPCParticipant(
  session: AuthSession,
  id: string,
  input: { name?: string; endpoint?: string; public_key?: string; status?: string }
): Promise<MPCParticipant> {
  const out = await serviceRequest<{ participant: MPCParticipant }>(
    session, "mpc", `/mpc/participants/${encodeURIComponent(id)}?${tenantQuery(session)}`,
    { method: "PUT", body: JSON.stringify(input) }
  );
  return out.participant;
}

export async function deleteMPCParticipant(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(
    session, "mpc", `/mpc/participants/${encodeURIComponent(id)}?${tenantQuery(session)}`,
    { method: "DELETE" }
  );
}

export async function createMPCPolicy(
  session: AuthSession,
  input: { name: string; description?: string; key_ids?: string; enabled: boolean; rules: { rule_type: string; params: string }[] }
): Promise<MPCPolicy> {
  const out = await serviceRequest<{ policy: MPCPolicy }>(
    session, "mpc", "/mpc/policies",
    { method: "POST", body: JSON.stringify({ tenant_id: session.tenantId, ...input }) }
  );
  return out.policy;
}

export async function listMPCPolicies(session: AuthSession): Promise<MPCPolicy[]> {
  const out = await serviceRequest<{ items: MPCPolicy[] }>(
    session, "mpc", `/mpc/policies?${tenantQuery(session)}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function updateMPCPolicy(
  session: AuthSession,
  id: string,
  input: { name?: string; description?: string; key_ids?: string; enabled?: boolean; rules?: { rule_type: string; params: string }[] }
): Promise<MPCPolicy> {
  const out = await serviceRequest<{ policy: MPCPolicy }>(
    session, "mpc", `/mpc/policies/${encodeURIComponent(id)}?${tenantQuery(session)}`,
    { method: "PUT", body: JSON.stringify(input) }
  );
  return out.policy;
}

export async function deleteMPCPolicy(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(
    session, "mpc", `/mpc/policies/${encodeURIComponent(id)}?${tenantQuery(session)}`,
    { method: "DELETE" }
  );
}

export async function revokeMPCKey(session: AuthSession, id: string, reason: string): Promise<MPCKey> {
  const out = await serviceRequest<{ item: MPCKey }>(
    session, "mpc", `/mpc/keys/${encodeURIComponent(id)}/revoke?${tenantQuery(session)}`,
    { method: "POST", body: JSON.stringify({ reason }) }
  );
  return out.item;
}

export async function setMPCKeyGroup(session: AuthSession, id: string, group: string): Promise<MPCKey> {
  const out = await serviceRequest<{ item: MPCKey }>(
    session, "mpc", `/mpc/keys/${encodeURIComponent(id)}/group?${tenantQuery(session)}`,
    { method: "PUT", body: JSON.stringify({ group }) }
  );
  return out.item;
}
