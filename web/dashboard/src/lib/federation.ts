import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Key federation (keycore, 13.60.0-beta; docs/FEDERATION.md): keys
// replicated to another KMS installation, and failover by promoting the
// replica there.

export type FederationIdentity = { tenant_id: string; fingerprint: string; kem_public: string; sign_public_pem: string };

export type FederationPeer = { id: string; name: string; url: string; peer_tenant_id: string; fingerprint: string; client_id: string; created_at: string };

export type FederationPeerInput = {
  name: string; url: string; peer_tenant_id: string; identity: FederationIdentity; ca_pem: string; client_id: string; api_key: string;
};

export type FederationLink = { id: string; key_id: string; peer_id: string; status: string; last_sync_at?: string; last_error?: string };

export type FederationKeyState = {
  state: { key_id: string; role: string; epoch?: number; source_peer_id?: string };
  versions: { version: number; status: string; kcv: string }[];
};

const q = (session: AuthSession) => `tenant_id=${encodeURIComponent(session.tenantId)}`;
const kc = <T,>(session: AuthSession, path: string, init?: RequestInit) =>
  serviceRequest<T>(session, "keycore", `${path}${path.includes("?") ? "&" : "?"}${q(session)}`, init);

export async function getFederationIdentity(session: AuthSession): Promise<FederationIdentity> {
  return (await kc<{ identity: FederationIdentity }>(session, "/federation/identity")).identity;
}

export async function listFederationPeers(session: AuthSession): Promise<FederationPeer[]> {
  const out = await kc<{ items?: FederationPeer[] }>(session, "/federation/peers");
  if (!Array.isArray(out?.items)) throw new Error("keycore returned no peer list");
  return out.items;
}

export async function addFederationPeer(session: AuthSession, input: FederationPeerInput): Promise<FederationPeer> {
  return (await kc<{ peer: FederationPeer }>(session, "/federation/peers", { method: "POST", body: JSON.stringify(input) })).peer;
}

export async function removeFederationPeer(session: AuthSession, id: string): Promise<void> {
  await kc(session, `/federation/peers/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function listFederationLinks(session: AuthSession): Promise<FederationLink[]> {
  const out = await kc<{ items?: FederationLink[] }>(session, "/federation/links");
  if (!Array.isArray(out?.items)) throw new Error("keycore returned no link list");
  return out.items;
}

export async function createFederationLink(session: AuthSession, keyID: string, peerID: string): Promise<FederationLink> {
  return (await kc<{ link: FederationLink }>(session, "/federation/links", { method: "POST", body: JSON.stringify({ key_id: keyID, peer_id: peerID }) })).link;
}

export async function syncFederationLink(session: AuthSession, id: string): Promise<FederationLink> {
  return (await kc<{ link: FederationLink }>(session, `/federation/links/${encodeURIComponent(id)}/sync`, { method: "POST" })).link;
}

export async function removeFederationLink(session: AuthSession, id: string): Promise<void> {
  await kc(session, `/federation/links/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function getFederationKeyState(session: AuthSession, keyID: string): Promise<FederationKeyState> {
  return kc<FederationKeyState>(session, `/federation/keys/${encodeURIComponent(keyID)}`);
}

export async function promoteFederatedKey(session: AuthSession, keyID: string, reason: string): Promise<void> {
  await kc(session, `/federation/keys/${encodeURIComponent(keyID)}/promote`, { method: "POST", body: JSON.stringify({ reason }) });
}

// The pasted identity: the other installation's GET /federation/identity.
export function parseIdentity(text: string): FederationIdentity | null {
  try {
    const raw = JSON.parse(text);
    const id = raw?.identity ?? raw;
    return typeof id?.kem_public === "string" && typeof id?.sign_public_pem === "string" ? id : null;
  } catch {
    return null;
  }
}

export const linkTone = (status: string) =>
  status === "in_sync" ? "green" : status === "pending" ? "neutral" : status === "superseded" ? "amber" : "red";
