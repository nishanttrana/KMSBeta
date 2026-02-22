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
