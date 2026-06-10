// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { Tag, RefreshCcw, Save, Search } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string) => ({ "Authorization": `Bearer ${tok}` });
const jsonHdr = (tok: string) => ({ ...hdr(tok), "Content-Type": "application/json" });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 6px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;
const Inp = ({ label, ...p }: any) => <div style={{ marginBottom: 12 }}><div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div><input {...p} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box" }} /></div>;

export function KeyMetadataTab({ session }: any) {
  const [metadataList, setMetadataList] = useState<any[]>([]);
  const [keys, setKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState("");
  const [form, setForm] = useState({ owner: "", project: "", classification: "internal", custom_tags: "", data_types: "", regulatory_scope: "" });
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState(false);

  const load = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true); setErr("");
    try {
      const [mRes, kRes] = await Promise.all([
        fetch(`${base}/metadata/extended`, { headers: hdr(session.token) }),
        fetch(`${base}/keys`, { headers: hdr(session.token) }),
      ]);
      const m = await mRes.json().catch(() => ({}));
      const k = await kRes.json().catch(() => ({}));
      setMetadataList(m.metadata ?? m ?? []);
      setKeys(k.keys ?? k ?? []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token]);

  useEffect(() => { load(); }, [load]);

  const handleSelect = async (keyId: string) => {
    setSelected(keyId); setSuccess(false);
    if (!keyId) { setForm({ owner: "", project: "", classification: "internal", custom_tags: "", data_types: "", regulatory_scope: "" }); return; }
    const existing = metadataList.find((m: any) => m.key_id === keyId);
    if (existing) {
      setForm({
        owner: existing.owner ?? "",
        project: existing.project ?? "",
        classification: existing.classification ?? "internal",
        custom_tags: Object.entries(existing.custom_tags ?? {}).map(([k, v]) => `${k}=${v}`).join(","),
        data_types: (existing.data_types ?? []).join(","),
        regulatory_scope: (existing.regulatory_scope ?? []).join(","),
      });
    } else {
      setForm({ owner: "", project: "", classification: "internal", custom_tags: "", data_types: "", regulatory_scope: "" });
    }
  };

  const handleSave = async () => {
    if (!selected) return;
    setSaving(true); setSuccess(false);
    try {
      const body: any = {};
      if (form.owner) body.owner = form.owner;
      if (form.project) body.project = form.project;
      if (form.classification) body.classification = form.classification;
      if (form.custom_tags) {
        const tags: Record<string, string> = {};
        form.custom_tags.split(",").forEach((t: string) => { const [k, v] = t.split("="); if (k && v) tags[k.trim()] = v.trim(); });
        body.custom_tags = tags;
      }
      if (form.data_types) body.data_types = form.data_types.split(",").map((s: string) => s.trim()).filter(Boolean);
      if (form.regulatory_scope) body.regulatory_scope = form.regulatory_scope.split(",").map((s: string) => s.trim()).filter(Boolean);
      await fetch(`${base}/keys/${selected}/metadata/extended`, { method: "PUT", headers: jsonHdr(session.token), body: JSON.stringify(body) });
      setSuccess(true); await load();
    } catch (e: any) { setErr(e.message); }
    finally { setSaving(false); }
  };

  const filtered = metadataList.filter((m: any) => !search || m.key_id?.includes(search) || m.owner?.toLowerCase().includes(search.toLowerCase()) || m.project?.toLowerCase().includes(search.toLowerCase()));
  const classColor = (c: string) => c === "public" ? C.green : c === "internal" ? C.accent : c === "confidential" ? C.amber : C.red;

  return (
    <div style={{ padding: 24, maxWidth: 1200 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Tag size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Key Metadata Management</span>
        </div>
        <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.5fr", gap: 16 }}>
        <Card>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 14 }}>Edit Metadata</div>
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Select Key</div>
            <select value={selected} onChange={(e: any) => handleSelect(e.target.value)} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
              <option value="">— select key —</option>
              {keys.map((k: any) => <option key={k.id} value={k.id}>{k.label ?? k.id}</option>)}
            </select>
          </div>
          {selected && <>
            {success && <div style={{ padding: 8, borderRadius: 5, background: C.green + "15", color: C.green, fontSize: 12, marginBottom: 12 }}>Saved.</div>}
            <Inp label="Owner" value={form.owner} onChange={(e: any) => setForm({ ...form, owner: e.target.value })} placeholder="team-security" />
            <Inp label="Project" value={form.project} onChange={(e: any) => setForm({ ...form, project: e.target.value })} placeholder="project-alpha" />
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Classification</div>
              <select value={form.classification} onChange={(e: any) => setForm({ ...form, classification: e.target.value })} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
                <option value="public">Public</option><option value="internal">Internal</option>
                <option value="confidential">Confidential</option><option value="secret">Secret</option>
              </select>
            </div>
            <Inp label="Custom Tags (key=value, comma-sep)" value={form.custom_tags} onChange={(e: any) => setForm({ ...form, custom_tags: e.target.value })} placeholder="env=prod, tier=premium" />
            <Inp label="Data Types (comma-separated)" value={form.data_types} onChange={(e: any) => setForm({ ...form, data_types: e.target.value })} placeholder="PII, PHI, PCI" />
            <Inp label="Regulatory Scope (comma-separated)" value={form.regulatory_scope} onChange={(e: any) => setForm({ ...form, regulatory_scope: e.target.value })} placeholder="GDPR, HIPAA, SOC2" />
            <Btn onClick={handleSave} disabled={saving}><Save size={12} />{saving ? "Saving…" : "Save Metadata"}</Btn>
          </>}
        </Card>

        <Card>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>Metadata Catalogue ({metadataList.length})</div>
          </div>
          <div style={{ marginBottom: 12, display: "flex", alignItems: "center", gap: 8, background: C.bg, border: `1px solid ${C.border}`, borderRadius: 6, padding: "5px 8px" }}>
            <Search size={12} style={{ color: C.muted }} />
            <input value={search} onChange={(e: any) => setSearch(e.target.value)} placeholder="Search by key ID, owner, project…" style={{ background: "none", border: "none", outline: "none", color: C.text, fontSize: 12, flex: 1 }} />
          </div>
          {filtered.length === 0 ? (
            <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No metadata. Select a key and fill in metadata above.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><TH c="Key ID" /><TH c="Owner" /><TH c="Project" /><TH c="Classification" /><TH c="Scopes" /></tr></thead>
                <tbody>
                  {filtered.map((m: any, i: number) => (
                    <tr key={i} style={{ cursor: "pointer" }} onClick={() => handleSelect(m.key_id)}>
                      <TD c={m.key_id} mono /><TD c={m.owner} /><TD c={m.project} />
                      <TD c={<Badge color={classColor(m.classification)}>{m.classification}</Badge>} />
                      <TD c={(m.regulatory_scope ?? []).map((s: string) => <Badge key={s} color={C.accent}>{s}</Badge>)} />
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
