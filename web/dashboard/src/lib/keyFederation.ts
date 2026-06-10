import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listFederationPeers(token: string) {
  const r = await trackedFetch(`${BASE}/federation/peers`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function addFederationPeer(token: string, body: { name: string; endpoint: string; tls_cert?: string }) {
  const r = await trackedFetch(`${BASE}/federation/peers`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function syncFederationPeer(token: string, peerId: string) {
  const r = await trackedFetch(`${BASE}/federation/peers/${peerId}/sync`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function removeFederationPeer(token: string, peerId: string) {
  const r = await trackedFetch(`${BASE}/federation/peers/${peerId}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
}
