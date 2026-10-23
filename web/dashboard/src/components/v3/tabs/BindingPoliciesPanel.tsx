import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import {
  checkBinding,
  deleteBindingPolicy,
  listBindingPolicies,
  saveBindingPolicy,
  toBindingInput,
  type BindingCheck,
  type BindingPolicy,
  type BindingPolicyInput
} from "../../../lib/bindingPolicies";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Chk, FG, Inp, Row2 } from "../legacyPrimitives";

// Binding policies (docs/KEYS.md "Binding policies"): how a key may be
// reached. Every active policy that applies to a key must pass for any
// operation on it, by any caller, platform services included.

const empty = (): BindingPolicyInput => ({
  name: "", all_keys: false, key_ids: [], label_selector: {}, channels: [], source_networks: [], workload_identities: [], status: "active"
});

const list = (text: string) => text.split(",").map((s) => s.trim()).filter(Boolean);

const selectorText = (sel: Record<string, string>) => Object.entries(sel).map(([k, v]) => `${k}=${v}`).join(", ");

const parseSelector = (text: string) => {
  const out: Record<string, string> = {};
  for (const part of list(text)) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
};

function scope(p: BindingPolicyInput) {
  if (p.all_keys) return "every key";
  const parts = [];
  if (p.key_ids.length) parts.push(`${p.key_ids.length} listed key${p.key_ids.length === 1 ? "" : "s"}`);
  if (Object.keys(p.label_selector).length) parts.push(`keys labelled ${selectorText(p.label_selector)}`);
  return parts.join(" and ");
}

function conditions(p: BindingPolicyInput) {
  const parts = [];
  if (p.channels.length) parts.push(`through ${p.channels.join(", ")}`);
  if (p.source_networks.length) parts.push(`from ${p.source_networks.join(", ")}`);
  if (p.workload_identities.length) parts.push(`as ${p.workload_identities.join(", ")}`);
  return parts.join(" · ");
}

export function BindingPoliciesPanel({ session }: { session: AuthSession }) {
  const [items, setItems] = useState<BindingPolicy[] | null>(null);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState<{ id?: string; p: BindingPolicyInput } | null>(null);
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      setItems(await listBindingPolicies(session));
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const save = async () => {
    if (!editing) return;
    try {
      await saveBindingPolicy(session, editing.p, editing.id);
      setEditing(null);
      setNotice("Binding saved. It applies to the next operation on its keys.");
      void load();
    } catch (e) {
      setNotice(errMsg(e));
    }
  };
  const remove = async (p: BindingPolicy) => {
    try {
      await deleteBindingPolicy(session, p.id);
      setNotice(`Binding ${p.name} deleted.`);
      void load();
    } catch (e) {
      setNotice(errMsg(e));
    }
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <span style={{ fontSize: 11, color: C.dim }}>A key outside its bindings is refused to every caller.</span>
        {!editing && <Btn small primary onClick={() => setEditing({ p: empty() })}>New binding</Btn>}
      </div>
      {notice && <div style={{ fontSize: 11, color: C.dim, marginBottom: 6 }}>{notice}</div>}
      {editing && <BindingForm value={editing.p} onChange={(p) => setEditing({ ...editing, p })} onSave={() => void save()} onCancel={() => setEditing(null)} />}
      {error ? <div style={{ fontSize: 11, color: C.redFg }}>{`Bindings unavailable: ${error}`}</div>
        : items === null ? <div style={{ fontSize: 11, color: C.muted }}>Loading…</div>
          : items.length === 0 ? <div style={{ fontSize: 11, color: C.muted }}>No binding policies.</div>
            : items.map((p) => (
              <div key={p.id} data-testid="binding-row" style={{ borderTop: `1px solid ${C.border}`, padding: "8px 0" }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{p.name}</span>
                  <span style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <B c={p.status === "active" ? "green" : "neutral"}>{p.status}</B>
                    <Btn small onClick={() => setEditing({ id: p.id, p: toBindingInput(p) })}>Edit</Btn>
                    <Btn small danger onClick={() => void remove(p)}>Delete</Btn>
                  </span>
                </div>
                <div style={{ fontSize: 10.5, color: C.dim, marginTop: 3 }}>{`${scope(p)}: ${conditions(p)}`}</div>
              </div>
            ))}
      <CheckForm session={session} />
    </div>
  );
}

function BindingForm({ value, onChange, onSave, onCancel }: { value: BindingPolicyInput; onChange: (p: BindingPolicyInput) => void; onSave: () => void; onCancel: () => void }) {
  const set = (patch: Partial<BindingPolicyInput>) => onChange({ ...value, ...patch });
  return (
    <div style={{ border: `1px solid ${C.border}`, borderRadius: 6, padding: 10, marginBottom: 10 }}>
      <Row2>
        <FG label="Name" required><Inp aria-label="Binding name" value={value.name} onChange={(e: any) => set({ name: e.target.value })} /></FG>
        <FG label="Keys">
          <Chk label="Every key in the tenant" checked={value.all_keys} onChange={() => set({ all_keys: !value.all_keys, key_ids: [], label_selector: {} })} />
        </FG>
      </Row2>
      {!value.all_keys && (
        <Row2>
          <FG label="Key IDs" hint="Comma-separated."><Inp aria-label="Binding key IDs" value={value.key_ids.join(", ")} onChange={(e: any) => set({ key_ids: list(e.target.value) })} /></FG>
          <FG label="Keys labelled" hint="label=value, comma-separated; all must match."><Inp aria-label="Binding label selector" value={selectorText(value.label_selector)} onChange={(e: any) => set({ label_selector: parseSelector(e.target.value) })} placeholder="env=prod" /></FG>
        </Row2>
      )}
      <FG label="Channels" hint="rest (a direct caller) and platform services, e.g. kms-kmip, kms-ekm. Empty: any.">
        <Inp aria-label="Binding channels" value={value.channels.join(", ")} onChange={(e: any) => set({ channels: list(e.target.value) })} placeholder="kms-kmip" />
      </FG>
      <Row2>
        <FG label="Networks (direct callers)" hint="CIDRs or addresses."><Inp aria-label="Binding networks" value={value.source_networks.join(", ")} onChange={(e: any) => set({ source_networks: list(e.target.value) })} placeholder="10.0.0.0/8" /></FG>
        <FG label="Workload identities (direct callers)" hint="Patterns with * and ?."><Inp aria-label="Binding workloads" value={value.workload_identities.join(", ")} onChange={(e: any) => set({ workload_identities: list(e.target.value) })} placeholder="spiffe://prod.example/*" /></FG>
      </Row2>
      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
        <Chk label="Active" checked={value.status === "active"} onChange={() => set({ status: value.status === "active" ? "disabled" : "active" })} />
        <span style={{ flex: 1 }} />
        <Btn small onClick={onCancel}>Cancel</Btn>
        <Btn small primary disabled={!value.name.trim()} onClick={onSave}>Save binding</Btn>
      </div>
    </div>
  );
}

// CheckForm asks keycore whether a request would reach a key.
function CheckForm({ session }: { session: AuthSession }) {
  const [keyID, setKeyID] = useState("");
  const [channel, setChannel] = useState("rest");
  const [sourceIP, setSourceIP] = useState("");
  const [workload, setWorkload] = useState("");
  const [result, setResult] = useState<BindingCheck | null>(null);
  const [error, setError] = useState("");
  const run = async () => {
    try {
      setResult(await checkBinding(session, { key_id: keyID.trim(), channel: channel.trim(), source_ip: sourceIP.trim(), workload_identity: workload.trim() }));
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  };
  return (
    <div style={{ borderTop: `1px solid ${C.border}`, marginTop: 10, paddingTop: 8 }}>
      <div style={{ fontSize: 11, color: C.dim, marginBottom: 6 }}>Would this request reach the key?</div>
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr 1fr 1.4fr auto", gap: 6, alignItems: "center" }}>
        <Inp aria-label="Check key ID" placeholder="key ID" value={keyID} onChange={(e: any) => setKeyID(e.target.value)} />
        <Inp aria-label="Check channel" placeholder="rest" value={channel} onChange={(e: any) => setChannel(e.target.value)} />
        <Inp aria-label="Check address" placeholder="address" value={sourceIP} onChange={(e: any) => setSourceIP(e.target.value)} />
        <Inp aria-label="Check workload" placeholder="workload identity" value={workload} onChange={(e: any) => setWorkload(e.target.value)} />
        <Btn small disabled={!keyID.trim()} onClick={() => void run()}>Check</Btn>
      </div>
      {error && <div style={{ fontSize: 11, color: C.redFg, marginTop: 6 }}>{error}</div>}
      {result && (
        <div data-testid="binding-check" style={{ fontSize: 10.5, marginTop: 6 }}>
          <B c={result.allowed ? "green" : "red"}>{result.allowed ? "allowed" : "refused"}</B>
          {result.policies.length === 0 && <span style={{ color: C.dim, marginLeft: 6 }}>No binding applies to this key.</span>}
          {result.policies.filter((p) => !p.allowed).map((p) => <div key={p.policy_id} style={{ color: C.text, marginTop: 3 }}>{p.problem}</div>)}
        </div>
      )}
    </div>
  );
}
