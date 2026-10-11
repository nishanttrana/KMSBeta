import { trackedFetch } from "./serviceApi";
import { parseServiceJSON } from "./wire";

const BASE = "/svc/keycore";

export async function verifyKeyMaterial(token: string, keyId: string) {
  const r = await trackedFetch(`${BASE}/keys/${keyId}/verify-material`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return parseServiceJSON(await r.text());
}

export async function listKeys(token: string) {
  const r = await trackedFetch(`${BASE}/keys`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return parseServiceJSON(await r.text());
}
