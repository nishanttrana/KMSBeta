import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../lib/auth";
import {
  createReportingScheduledReport, deleteReportingScheduledReport, listReportingReportTemplates, listReportingScheduledReports,
  runReportingScheduledReport, updateReportingScheduledReport, type ReportTemplate, type ScheduledReport, type ScheduledReportInput,
} from "../../lib/reporting";
import { Btn, Card, Chk, FG, Inp, Modal, Sel } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { Authority, Empty, Failed, Result, TD, TH, when } from "./parts";

// Scheduling → Reports (moved from Compliance, 13.66.0-beta). A schedule
// queues a report job every hour, day or week on the authority of the person
// who saved it; the reports are listed in Compliance → Reports, not emailed.

const CADENCES = ["hourly", "daily", "weekly"] as const;

export function ReportsView({ session, onToast, onNavigate }: { session: AuthSession; onToast: (m: string) => void; onNavigate?: ((target: string) => void) | undefined }) {
  const [items, setItems] = useState<ScheduledReport[] | null>(null);
  const [templates, setTemplates] = useState<ReportTemplate[]>([]);
  const [error, setError] = useState("");
  const [form, setForm] = useState<ScheduledReportInput | null>(null);
  const [editing, setEditing] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    try {
      const [list, tpls] = await Promise.all([listReportingScheduledReports(session), listReportingReportTemplates(session)]);
      setItems(list); setTemplates(tpls); setError("");
    } catch (e) { setItems(null); setError(errMsg(e)); }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const act = async (key: string, fn: () => Promise<string>) => {
    setBusy(key);
    try { onToast(await fn()); await load(); return true; } catch (e) { onToast(errMsg(e)); return false; } finally { setBusy(""); }
  };
  const formats = templates.find((t) => t.id === form?.template_id)?.formats ?? [];
  const save = async () => {
    if (!form) return;
    if (await act("save", async () => {
      if (editing) await updateReportingScheduledReport(session, editing, form);
      else await createReportingScheduledReport(session, form);
      return "Report scheduled; it runs on your authority.";
    })) setForm(null);
  };
  const open = (r?: ScheduledReport) => {
    const first = templates[0];
    setEditing(r?.id ?? "");
    setForm(r ? { name: r.name, template_id: r.template_id, format: r.format, schedule: r.schedule as ScheduledReportInput["schedule"], enabled: r.enabled }
      : { name: "", template_id: first?.id ?? "", format: first?.formats[0] ?? "pdf", schedule: "weekly", enabled: true });
  };

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <div style={{ display: "flex", gap: 8 }}>
        <Btn small primary onClick={() => open()} disabled={!templates.length}>Schedule a report</Btn>
        <Btn small onClick={() => onNavigate?.("compliance")}>Generated reports</Btn>
      </div>
      {error ? <Failed what="Scheduled reports" error={error} /> : items && (
        <Card style={{ padding: 0, overflow: "hidden" }}>
          {items.length === 0 ? <Empty>No report is scheduled.</Empty> : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>{["Name", "Report", "Runs", "Next", "Last", "Result", "On the authority of", ""].map((h) => <th key={h} style={TH}>{h}</th>)}</tr></thead>
              <tbody>
                {items.map((r) => (
                  <tr key={r.id} data-testid="report-schedule-row">
                    <td style={{ ...TD, fontWeight: 600 }}>{r.name}</td>
                    <td style={TD}>{`${templates.find((t) => t.id === r.template_id)?.name ?? r.template_id} · ${r.format.toUpperCase()}`}</td>
                    <td style={TD}>{r.enabled ? r.schedule : "off"}</td>
                    <td style={TD}>{r.enabled && !r.paused_reason ? when(r.next_run_at) : "—"}</td>
                    <td style={TD} title={r.last_job_id}>{when(r.last_run_at)}</td>
                    <td style={TD}><Result value={r.last_result} title={r.last_error || r.last_job_id} /></td>
                    <td style={TD}><Authority by={r.authorized_by} paused={r.paused_reason} /></td>
                    <td style={{ ...TD, display: "flex", gap: 6 }}>
                      <Btn small disabled={!!busy || !!r.paused_reason} title={r.paused_reason || "Queue this report now"}
                        onClick={() => void act(`run:${r.id}`, async () => { const out = await runReportingScheduledReport(session, r.id); return out.last_result === "requested" ? "Report queued." : `Not queued: ${out.last_error}`; })}>Run now</Btn>
                      <Btn small disabled={!!busy || !templates.length} onClick={() => open(r)}>{r.paused_reason ? "Resume" : "Edit"}</Btn>
                      <Btn small danger disabled={!!busy} onClick={() => { if (window.confirm(`Delete the schedule "${r.name}"?`)) void act(`del:${r.id}`, async () => { await deleteReportingScheduledReport(session, r.id); return "Schedule deleted."; }); }}>Delete</Btn>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
      <Modal open={!!form} onClose={() => setForm(null)} title={editing ? "Edit report schedule" : "Schedule a report"}>
        {form && (
          <div style={{ padding: 18 }}>
            <FG label="Name" required><Inp value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></FG>
            <FG label="Report">
              <Sel value={form.template_id} onChange={(e) => { const t = templates.find((x) => x.id === e.target.value); setForm({ ...form, template_id: e.target.value, format: t?.formats.includes(form.format) ? form.format : t?.formats[0] ?? form.format }); }}>
                {templates.some((t) => t.id === form.template_id) ? null : <option value={form.template_id}>{form.template_id}</option>}
                {templates.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
              </Sel>
            </FG>
            <FG label="Format">
              <Sel value={form.format} onChange={(e) => setForm({ ...form, format: e.target.value })}>
                {formats.includes(form.format) ? null : <option value={form.format}>{form.format.toUpperCase()}</option>}
                {formats.map((f) => <option key={f} value={f}>{f.toUpperCase()}</option>)}
              </Sel>
            </FG>
            <FG label="Runs">
              <Sel value={form.schedule} onChange={(e) => setForm({ ...form, schedule: e.target.value as ScheduledReportInput["schedule"] })}>
                {CADENCES.map((c) => <option key={c} value={c}>{c[0]!.toUpperCase() + c.slice(1)}</option>)}
              </Sel>
            </FG>
            <Chk label="Enabled" checked={form.enabled !== false} onChange={() => setForm({ ...form, enabled: form.enabled === false })} />
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
              <Btn onClick={() => setForm(null)}>Cancel</Btn>
              <Btn primary disabled={busy === "save" || !form.name.trim() || !form.template_id} onClick={() => void save()}>{busy === "save" ? "Saving…" : "Save"}</Btn>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
