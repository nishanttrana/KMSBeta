// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { Cpu, RefreshCcw, Save } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });
const jsonHdr = (tok: string, tid: string) => ({ ...hdr(tok, tid), "Content-Type": "application/json" });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;
const Inp = ({ label, ...p }: any) => <div style={{ marginBottom: 12 }}><div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div><input {...p} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box" }} /></div>;
const Chk = ({ label, checked, onChange }: any) => <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", marginBottom: 10 }}><input type="checkbox" checked={checked} onChange={onChange} /><span style={{ fontSize: 12, color: C.text }}>{label}</span></label>;

export function KeyBindingTab({ session }: any) {
  const [bindings, setBindings] = useState<any[]>([]);
  const [keys, setKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [selectedKey, setSelectedKey] = useState("");
  const [binding, setBinding] = useState<any>({});
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState(false);

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const [bRes, kRes] = await Promise.all([
        fetch(`${base}/binding/configs`, { headers: hdr(session.token, tid) }),
        fetch(`${base}/keys`, { headers: hdr(session.token, tid) }),
      ]);
      const b = await bRes.json().catch(() => ({}));
      const k = await kRes.json().catch(() => ({}));
      const allBindings = Array.isArray(b.configs) ? b.configs : Array.isArray(b) ? b : [];
      const allKeys = Array.isArray(k.keys) ? k.keys : Array.isArray(k) ? k : [];
      setBindings(allBindings);
      setKeys(allKeys.filter((k: any) => k.status === "active"));
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleSelectKey = async (keyId: string) => {
    const tid = session?.tenantId ?? "";
    setSelectedKey(keyId); setSuccess(false);
    if (!keyId) { setBinding({}); return; }
    try {
      const r = await fetch(`${base}/keys/${keyId}/binding`, { headers: hdr(session.token, tid) });
      const d = await r.json().catch(() => ({}));
      setBinding(d.config ?? d ?? {});
    } catch { setBinding({}); }
  };

  const handleSave = async () => {
    if (!selectedKey) return;
    const tid = session?.tenantId ?? "";
    setSaving(true); setSuccess(false);
    try {
      await fetch(`${base}/keys/${selectedKey}/binding`, { method: "PUT", headers: jsonHdr(session.token, tid), body: JSON.stringify(binding) });
      setSuccess(true); await load();
    } catch (e: any) { setErr(e.message); }
    finally { setSaving(false); }
  };

  const upd = (k: string, v: any) => setBinding((b: any) => ({ ...b, [k]: v }));

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Cpu size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Enhanced Key Binding</span>
        </div>
        <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}
      {success && <div style={{ padding: 10, borderRadius: 6, background: C.green + "15", color: C.green, fontSize: 12, marginBottom: 16 }}>Binding configuration saved.</div>}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Card>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 14 }}>Configure Binding</div>
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Select Key</div>
            <select value={selectedKey} onChange={(e: any) => handleSelectKey(e.target.value)} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
              <option value="">— select key —</option>
              {keys.map((k: any) => <option key={k.id} value={k.id}>{k.label ?? k.id}</option>)}
            </select>
          </div>
          {selectedKey && <>
            <Chk label="Bind to TPM / Hardware Security Module" checked={binding.bind_to_tpm ?? false} onChange={(e: any) => upd("bind_to_tpm", e.target.checked)} />
            <Inp label="Allowed Regions (comma-separated)" value={(binding.allowed_regions ?? []).join(",")} onChange={(e: any) => upd("allowed_regions", e.target.value.split(",").map((s: string) => s.trim()).filter(Boolean))} placeholder="us-east-1, eu-west-1" />
            <Inp label="Allowed IP CIDRs (comma-separated)" value={(binding.allowed_ip_cidrs ?? []).join(",")} onChange={(e: any) => upd("allowed_ip_cidrs", e.target.value.split(",").map((s: string) => s.trim()).filter(Boolean))} placeholder="10.0.0.0/8, 192.168.1.0/24" />
            <Inp label="Geolocation Policy" value={binding.geolocation_policy ?? ""} onChange={(e: any) => upd("geolocation_policy", e.target.value)} placeholder="e.g. us-only" />
            <Inp label="Hardware Attestation Token" value={binding.hardware_attestation ?? ""} onChange={(e: any) => upd("hardware_attestation", e.target.value)} placeholder="attestation token or TPM PCR hash" />
            <Btn onClick={handleSave} disabled={saving}><Save size={12} />{saving ? "Saving…" : "Save Binding"}</Btn>
          </>}
        </Card>

        <Card>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>Active Bindings</div>
          {bindings.length === 0 ? (
            <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No binding configurations.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><TH c="Key ID" /><TH c="TPM" /><TH c="Regions" /><TH c="Geo Policy" /></tr></thead>
                <tbody>
                  {bindings.map((b: any, i: number) => (
                    <tr key={i}>
                      <TD c={b.key_id} mono />
                      <TD c={<Badge color={b.bind_to_tpm ? C.green : C.muted}>{b.bind_to_tpm ? "Yes" : "No"}</Badge>} />
                      <TD c={(b.allowed_regions ?? []).join(", ") || "—"} />
                      <TD c={b.geolocation_policy || "—"} />
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
