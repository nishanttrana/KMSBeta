import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Key binding policies (keycore, 13.51.0-beta; docs/KEYS.md "Binding
// policies"): how a key may be reached (channel, network, workload),
// checked on every operation.

export type BindingPolicyInput = {
  name: string;
  all_keys: boolean;
  key_ids: string[];
  label_selector: Record<string, string>;
  channels: string[];
  source_networks: string[];
  workload_identities: string[];
  status: string;
};

export type BindingPolicy = BindingPolicyInput & { id: string; updated_by: string; updated_at: string };

export type BindingCheck = { allowed: boolean; channel: string; policies: { policy_id: string; name: string; allowed: boolean; problem: string }[] };

const q = (session: AuthSession) => `tenant_id=${encodeURIComponent(session.tenantId)}`;

export async function listBindingPolicies(session: AuthSession): Promise<BindingPolicy[]> {
  const out = await serviceRequest<{ items?: BindingPolicy[] }>(session, "keycore", `/binding-policies?${q(session)}`);
  if (!Array.isArray(out?.items)) throw new Error("keycore returned no binding policy list");
  return out.items;
}

export async function saveBindingPolicy(session: AuthSession, input: BindingPolicyInput, id?: string): Promise<BindingPolicy> {
  const path = id ? `/binding-policies/${encodeURIComponent(id)}?${q(session)}` : `/binding-policies?${q(session)}`;
  const out = await serviceRequest<{ policy: BindingPolicy }>(session, "keycore", path, { method: id ? "PUT" : "POST", body: JSON.stringify(input) });
  return out.policy;
}

export async function deleteBindingPolicy(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "keycore", `/binding-policies/${encodeURIComponent(id)}?${q(session)}`, { method: "DELETE" });
}

export async function checkBinding(session: AuthSession, req: { key_id: string; channel: string; source_ip: string; workload_identity: string }): Promise<BindingCheck> {
  return serviceRequest<BindingCheck>(session, "keycore", `/binding-policies/check?${q(session)}`, { method: "POST", body: JSON.stringify(req) });
}

export const toBindingInput = (p: BindingPolicyInput): BindingPolicyInput => ({
  name: p.name, all_keys: p.all_keys, key_ids: p.key_ids, label_selector: p.label_selector, channels: p.channels,
  source_networks: p.source_networks, workload_identities: p.workload_identities, status: p.status
});
