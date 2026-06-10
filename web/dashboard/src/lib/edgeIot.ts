import { trackedFetch } from "./serviceApi";

const BASE = "/svc/keycore";

export async function listEdgeDevices(token: string) {
  const r = await trackedFetch(`${BASE}/edge/devices`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function createEdgeDevice(token: string, body: {
  name: string; device_type: string; platform?: string; assigned_key_id?: string;
}) {
  const r = await trackedFetch(`${BASE}/edge/devices`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function updateEdgeDeviceStatus(token: string, id: string, status: string) {
  const r = await trackedFetch(`${BASE}/edge/devices/${id}/status`, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
  return r.json();
}

export async function deleteEdgeDevice(token: string, id: string) {
  const r = await trackedFetch(`${BASE}/edge/devices/${id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error?.message ?? "Failed");
}
