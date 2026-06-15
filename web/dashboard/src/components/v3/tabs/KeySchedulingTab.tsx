// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { CalendarClock, RefreshCcw, Plus, Trash2, ToggleLeft, ToggleRight } from "lucide-react";
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
const Sel = ({ label, children, ...p }: any) => <div style={{ marginBottom: 12 }}><div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div><select {...p} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>{children}</select></div>;

// Rotation scheduling lives in the Rotation Policies view; these jobs cover the
// non-rotation maintenance actions only, so the action set excludes "rotate".
const defForm = { key_id: "", schedule_type: "cron", cron_expr: "0 2 * * *", interval_seconds: 86400, action: "verify" };

export function KeySchedulingTab({ session }: any) {
  const [jobs, setJobs] = useState<any[]>([]);
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
      const r = await fetch(`${base}/scheduling/jobs`, { headers: hdr(session.token, tid) });
      const d = await r.json().catch(() => ({}));
      setJobs(Array.isArray(d.jobs) ? d.jobs : Array.isArray(d) ? d : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    const tid = session?.tenantId ?? "";
    setSaving(true);
    try {
      const body: any = { key_id: form.key_id, schedule_type: form.schedule_type, action: form.action };
      if (form.schedule_type === "cron") body.cron_expr = form.cron_expr;
      else body.interval_seconds = form.interval_seconds;
      await fetch(`${base}/scheduling/jobs`, { method: "POST", headers: jsonHdr(session.token, tid), body: JSON.stringify(body) });
      setShowForm(false); setForm({ ...defForm }); await load();
    } catch (e: any) { setErr(e.message); }
    finally { setSaving(false); }
  };

  const handleToggle = async (job: any) => {
    const tid = session?.tenantId ?? "";
    await fetch(`${base}/scheduling/jobs/${job.id}`, { method: "PATCH", headers: jsonHdr(session.token, tid), body: JSON.stringify({ enabled: !job.enabled }) });
    await load();
  };

  const handleDelete = async (id: string) => {
    const tid = session?.tenantId ?? "";
    await fetch(`${base}/scheduling/jobs/${id}`, { method: "DELETE", headers: hdr(session.token, tid) });
    await load();
  };

  const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleString() : "—";

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <CalendarClock size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Scheduled Maintenance Jobs</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={() => setShowForm(!showForm)} small><Plus size={12} /> New Job</Btn>
          <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      {showForm && (
        <Card style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 14 }}>Create Scheduling Job</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Inp label="Key ID" value={form.key_id} onChange={(e: any) => setForm({ ...form, key_id: e.target.value })} placeholder="key_xxxxxxxx" />
            <Sel label="Action" value={form.action} onChange={(e: any) => setForm({ ...form, action: e.target.value })}>
              <option value="verify">Verify</option>
              <option value="backup">Backup</option>
              <option value="archive">Archive</option>
            </Sel>
            <Sel label="Schedule Type" value={form.schedule_type} onChange={(e: any) => setForm({ ...form, schedule_type: e.target.value })}>
              <option value="cron">Cron</option>
              <option value="interval">Interval</option>
            </Sel>
            {form.schedule_type === "cron"
              ? <Inp label="Cron Expression" value={form.cron_expr} onChange={(e: any) => setForm({ ...form, cron_expr: e.target.value })} placeholder="0 2 * * *" />
              : <Inp label="Interval (seconds)" type="number" value={form.interval_seconds} onChange={(e: any) => setForm({ ...form, interval_seconds: +e.target.value })} />
            }
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <Btn onClick={handleCreate} disabled={saving || !form.key_id}>{saving ? "Creating…" : "Create Job"}</Btn>
            <Btn onClick={() => setShowForm(false)} variant="ghost">Cancel</Btn>
          </div>
        </Card>
      )}

      <Card>
        {jobs.length === 0 ? (
          <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No scheduling jobs configured.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Key ID" /><TH c="Action" /><TH c="Type" /><TH c="Schedule" /><TH c="Enabled" /><TH c="Last Run" /><TH c="Next Run" /><TH c="Actions" /></tr></thead>
              <tbody>
                {jobs.map((j: any, i: number) => (
                  <tr key={i}>
                    <TD c={j.key_id} mono />
                    <TD c={<Badge color={C.accent}>{j.action}</Badge>} />
                    <TD c={j.schedule_type} />
                    <TD c={j.cron_expr ?? `Every ${j.interval_seconds}s`} mono />
                    <TD c={<Btn small variant="ghost" onClick={() => handleToggle(j)}>{j.enabled ? <ToggleRight size={14} style={{ color: C.green }} /> : <ToggleLeft size={14} style={{ color: C.muted }} />}{j.enabled ? "On" : "Off"}</Btn>} />
                    <TD c={fmtDate(j.last_run_at)} />
                    <TD c={fmtDate(j.next_run_at)} />
                    <TD c={<Btn small variant="danger" onClick={() => handleDelete(j.id)}><Trash2 size={11} /></Btn>} />
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
