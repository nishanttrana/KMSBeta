import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listKeySharingTokens(token: string, keyId: string) {
  const r = await trackedFetch(`${BASE}/keys/${keyId}/sharing-tokens`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function createKeySharingToken(token: string, keyId: string, body: {
  grantee_email?: string;
  permissions: string[];
  expires_at?: string;
  max_uses?: number;
}) {
  const r = await trackedFetch(`${BASE}/keys/${keyId}/sharing-tokens`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function revokeKeySharingToken(token: string, keyId: string, tokenId: string) {
  const r = await trackedFetch(`${BASE}/keys/${keyId}/sharing-tokens/${tokenId}/revoke`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
}

export async function listAllSharingTokens(token: string) {
  const r = await trackedFetch(`${BASE}/sharing/tokens`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
