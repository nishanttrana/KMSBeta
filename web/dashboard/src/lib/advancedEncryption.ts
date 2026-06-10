import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listEncryptionModes(token: string) {
  const r = await trackedFetch(`${BASE}/encryption/modes`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function encryptData(token: string, body: { key_id: string; plaintext_b64: string; mode: string; aad?: string }) {
  const r = await trackedFetch(`${BASE}/encryption/encrypt`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function decryptData(token: string, body: { key_id: string; ciphertext_b64: string; mode: string; aad?: string; iv_b64?: string }) {
  const r = await trackedFetch(`${BASE}/encryption/decrypt`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
