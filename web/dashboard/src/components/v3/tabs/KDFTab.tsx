// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { Layers, RefreshCcw, Plus, Trash2, Play } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });
const jsonHdr = (tok: string, tid: string) => ({ ...hdr(tok, tid), "Content-Type": "application/json" });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` }, danger: { background: C.redDim, color: C.red, border: `1px solid ${C.red}33` }, amber: { background: C.amberDim, color: C.amber, border: `1px solid ${C.amber}33` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;
const Inp = ({ label, ...p }: any) => <div style={{ marginBottom: 12 }}><div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div><input {...p} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box" }} /></div>;

const defForm = { label: "", algorithm: "HKDF-SHA256", key_length: 32 };

export function KDFTab({ session }: any) {
  const [configs, setConfigs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ ...defForm });
  const [saving, setSaving] = useState(false);
  const [deriveForm, setDeriveForm] = useState({ configId: "", info: "", salt: "" });
  const [deriveResult, setDeriveResult] = useState<any>(null);
  const [deriving, setDeriving] = useState(false);

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const r = await fetch(`${base}/kdf/configs`, { headers: hdr(session.token, tid) });
      const d = await r.json().catch(() => ({}));
      setConfigs(Array.isArray(d.configs) ? d.configs : Array.isArray(d) ? d : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    const tid = session?.tenantId ?? "";
    setSaving(true);
    try {
      await fetch(`${base}/kdf/configs`, { method: "POST", headers: jsonHdr(session.token, tid), body: JSON.stringify({ label: form.label, algorithm: form.algorithm, params: { key_length: form.key_length } }) });
      setShowForm(false); setForm({ ...defForm }); await load();
    } catch (e: any) { setErr(e.message); }
    finally { setSaving(false); }
  };

  const handleDelete = async (id: string) => {
    const tid = session?.tenantId ?? "";
    await fetch(`${base}/kdf/configs/${id}`, { method: "DELETE", headers: hdr(session.token, tid) });
    await load();
  };

  const handleDerive = async () => {
    if (!deriveForm.configId) return;
    const tid = session?.tenantId ?? "";
    setDeriving(true); setDeriveResult(null);
    try {
      const body: any = {};
      if (deriveForm.info) body.info = deriveForm.info;
      if (deriveForm.salt) body.salt = deriveForm.salt;
      const r = await fetch(`${base}/kdf/configs/${deriveForm.configId}/derive`, { method: "POST", headers: jsonHdr(session.token, tid), body: JSON.stringify(body) });
      const d = await r.json();
      setDeriveResult(d);
    } catch (e: any) { setErr(e.message); }
    finally { setDeriving(false); }
  };

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Layers size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Key Derivation Functions (KDF)</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={() => setShowForm(!showForm)} small><Plus size={12} /> New Config</Btn>
          <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      {showForm && (
        <Card style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 14 }}>New KDF Configuration</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <Inp label="Label" value={form.label} onChange={(e: any) => setForm({ ...form, label: e.target.value })} placeholder="My KDF Config" />
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Algorithm</div>
              <select value={form.algorithm} onChange={(e: any) => setForm({ ...form, algorithm: e.target.value })} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
                <option>HKDF-SHA256</option><option>HKDF-SHA384</option><option>HKDF-SHA512</option>
                <option>PBKDF2-SHA256</option><option>Scrypt</option><option>Argon2id</option>
              </select>
            </div>
            <Inp label="Key Length (bytes)" type="number" min={16} max={64} value={form.key_length} onChange={(e: any) => setForm({ ...form, key_length: +e.target.value })} />
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <Btn onClick={handleCreate} disabled={saving || !form.label}>{saving ? "Creating…" : "Create Config"}</Btn>
            <Btn onClick={() => setShowForm(false)} variant="ghost">Cancel</Btn>
          </div>
        </Card>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Card>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>KDF Configurations</div>
          {configs.length === 0 ? (
            <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No KDF configurations.</div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Label" /><TH c="Algorithm" /><TH c="" /></tr></thead>
              <tbody>
                {configs.map((c: any, i: number) => (
                  <tr key={i}>
                    <TD c={c.label} />
                    <TD c={<Badge color={C.accent}>{c.algorithm}</Badge>} />
                    <TD c={
                      <div style={{ display: "flex", gap: 4 }}>
                        <Btn small variant="ghost" onClick={() => setDeriveForm({ ...deriveForm, configId: c.id })}><Play size={11} /> Use</Btn>
                        <Btn small variant="danger" onClick={() => handleDelete(c.id)}><Trash2 size={11} /></Btn>
                      </div>
                    } />
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>Derive Key Material</div>
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Config ID</div>
            <select value={deriveForm.configId} onChange={(e: any) => setDeriveForm({ ...deriveForm, configId: e.target.value })} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
              <option value="">— select config —</option>
              {configs.map((c: any) => <option key={c.id} value={c.id}>{c.label} ({c.algorithm})</option>)}
            </select>
          </div>
          <Inp label="Context Info (hex or text, optional)" value={deriveForm.info} onChange={(e: any) => setDeriveForm({ ...deriveForm, info: e.target.value })} placeholder="optional context" />
          <Inp label="Salt (hex, optional)" value={deriveForm.salt} onChange={(e: any) => setDeriveForm({ ...deriveForm, salt: e.target.value })} placeholder="optional salt" />
          <Btn onClick={handleDerive} disabled={deriving || !deriveForm.configId} variant="amber"><Play size={12} />{deriving ? "Deriving…" : "Derive"}</Btn>
          {deriveResult && (
            <div style={{ marginTop: 12, background: C.bg, borderRadius: 6, padding: 10 }}>
              <div style={{ fontSize: 10, color: C.dim, marginBottom: 4 }}>Derived Key (base64)</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: C.text, wordBreak: "break-all" }}>{deriveResult.derived_key_b64 ?? JSON.stringify(deriveResult)}</div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
