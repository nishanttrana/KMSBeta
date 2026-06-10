import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listEscrowRecords(token: string) {
  const r = await trackedFetch(`${BASE}/recovery/escrow`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function escrowKey(token: string, body: { key_id: string; shares: number; threshold: number }) {
  const r = await trackedFetch(`${BASE}/recovery/escrow`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function initiateRecovery(token: string, keyId: string, shares: string[]) {
  const r = await trackedFetch(`${BASE}/recovery/initiate`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ key_id: keyId, shares }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
