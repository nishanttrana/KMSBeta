import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listKeyBindingConfigs(token: string) {
  const r = await trackedFetch(`${BASE}/binding/configs`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function getKeyBinding(token: string, keyId: string) {
  const r = await trackedFetch(`${BASE}/keys/${keyId}/binding`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function upsertKeyBinding(token: string, keyId: string, body: {
  bind_to_tpm?: boolean;
  allowed_regions?: string[];
  allowed_ip_cidrs?: string[];
  hardware_attestation?: string;
  geolocation_policy?: string;
}) {
  const r = await trackedFetch(`${BASE}/keys/${keyId}/binding`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}
