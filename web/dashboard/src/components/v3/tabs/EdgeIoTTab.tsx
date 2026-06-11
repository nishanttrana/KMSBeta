// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { Wifi, RefreshCcw, Plus, Trash2 } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });
const jsonHdr = (tok: string, tid: string) => ({ ...hdr(tok, tid), "Content-Type": "application/json" });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` }, danger: { background: C.redDim, color: C.red, border: `1px solid ${C.red}33` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;
const Inp = ({ label, ...p }: any) => <div style={{ marginBottom: 12 }}><div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div><input {...p} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box" }} /></div>;

const defForm = { name: "", device_type: "iot", platform: "", assigned_key_id: "" };
const STATUSES = ["active", "provisioning", "revoked", "offline"];

export function EdgeIoTTab({ session }: any) {
  const [devices, setDevices] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ ...defForm });
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const r = await fetch(`${base}/edge/devices`, { headers: hdr(session.token, tid) });
      const d = await r.json().catch(() => ({}));
      setDevices(Array.isArray(d.devices) ? d.devices : Array.isArray(d) ? d : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    const tid = session?.tenantId ?? "";
    setSaving(true);
    try {
      const body: any = { name: form.name, device_type: form.device_type };
      if (form.platform) body.platform = form.platform;
      if (form.assigned_key_id) body.assigned_key_id = form.assigned_key_id;
      await fetch(`${base}/edge/devices`, { method: "POST", headers: jsonHdr(session.token, tid), body: JSON.stringify(body) });
      setShowForm(false); setForm({ ...defForm }); await load();
    } catch (e: any) { setErr(e.message); }
    finally { setSaving(false); }
  };

  const handleStatusChange = async (id: string, status: string) => {
    const tid = session?.tenantId ?? "";
    await fetch(`${base}/edge/devices/${id}/status`, { method: "PATCH", headers: jsonHdr(session.token, tid), body: JSON.stringify({ status }) });
    await load();
  };

  const handleDelete = async (id: string) => {
    const tid = session?.tenantId ?? "";
    await fetch(`${base}/edge/devices/${id}`, { method: "DELETE", headers: hdr(session.token, tid) });
    await load();
  };

  const statusColor = (s: string) => s === "active" ? C.green : s === "provisioning" ? C.amber : s === "offline" ? C.muted : C.red;
  const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleString() : "—";
  const stats = { active: devices.filter((d: any) => d.status === "active").length, total: devices.length };

  return (
    <div style={{ padding: 24, maxWidth: 1200 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Wifi size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Edge & IoT Key Management</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={() => setShowForm(!showForm)} small><Plus size={12} /> Register Device</Btn>
          <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      <div style={{ display: "flex", gap: 12, marginBottom: 20 }}>
        <Card style={{ minWidth: 120, textAlign: "center" }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: C.text }}>{stats.total}</div>
          <div style={{ fontSize: 11, color: C.muted }}>Total Devices</div>
        </Card>
        <Card style={{ minWidth: 120, textAlign: "center" }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: C.green }}>{stats.active}</div>
          <div style={{ fontSize: 11, color: C.muted }}>Active</div>
        </Card>
      </div>

      {showForm && (
        <Card style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 14 }}>Register Edge Device</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Inp label="Device Name" value={form.name} onChange={(e: any) => setForm({ ...form, name: e.target.value })} placeholder="my-iot-device-01" />
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Device Type</div>
              <select value={form.device_type} onChange={(e: any) => setForm({ ...form, device_type: e.target.value })} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
                <option value="iot">IoT Sensor</option><option value="edge">Edge Gateway</option>
                <option value="vehicle">Vehicle</option><option value="industrial">Industrial</option><option value="mobile">Mobile</option>
              </select>
            </div>
            <Inp label="Platform / OS" value={form.platform} onChange={(e: any) => setForm({ ...form, platform: e.target.value })} placeholder="Linux, RTOS, Embedded, etc." />
            <Inp label="Assigned Key ID (optional)" value={form.assigned_key_id} onChange={(e: any) => setForm({ ...form, assigned_key_id: e.target.value })} placeholder="key_xxxxxxxx" />
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <Btn onClick={handleCreate} disabled={saving || !form.name}>{saving ? "Registering…" : "Register Device"}</Btn>
            <Btn onClick={() => setShowForm(false)} variant="ghost">Cancel</Btn>
          </div>
        </Card>
      )}

      <Card>
        {devices.length === 0 ? (
          <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No devices registered.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Name" /><TH c="Type" /><TH c="Platform" /><TH c="Status" /><TH c="Assigned Key" /><TH c="Last Seen" /><TH c="Actions" /></tr></thead>
              <tbody>
                {devices.map((d: any, i: number) => (
                  <tr key={i}>
                    <TD c={d.name} />
                    <TD c={<Badge color={C.accent}>{d.device_type}</Badge>} />
                    <TD c={d.platform} />
                    <TD c={<Badge color={statusColor(d.status)}>{d.status ?? "provisioning"}</Badge>} />
                    <TD c={d.assigned_key_id} mono />
                    <TD c={fmtDate(d.last_seen_at)} />
                    <TD c={
                      <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                        <select value={d.status ?? "provisioning"} onChange={(e: any) => handleStatusChange(d.id, e.target.value)} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 4, padding: "2px 6px", color: C.text, fontSize: 10, outline: "none" }}>
                          {STATUSES.map(s => <option key={s}>{s}</option>)}
                        </select>
                        <Btn small variant="danger" onClick={() => handleDelete(d.id)}><Trash2 size={11} /></Btn>
                      </div>
                    } />
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
