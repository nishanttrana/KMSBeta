import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function verifyKeyMaterial(token: string, keyId: string) {
  const r = await trackedFetch(`${BASE}/keys/${keyId}/verify-material`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function listKeys(token: string) {
  const r = await trackedFetch(`${BASE}/keys`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
