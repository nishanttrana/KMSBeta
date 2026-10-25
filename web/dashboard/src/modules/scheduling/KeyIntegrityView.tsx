import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../lib/auth";
import { deleteIntegritySchedule, listIntegritySchedules, runIntegritySchedule, saveIntegritySchedule, type IntegrityInput, type IntegritySchedule } from "../../lib/scheduling";
import { Btn, Card, Chk, FG, Inp, Modal, Sel } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { Authority, Empty, every, Failed, intervalOptions, Result, TD, TH, when } from "./parts";

// Scheduling → Key integrity (13.66.0-beta): each schedule decrypts the
// matching active keys' material and recomputes their KCV on an interval
// (keycore integrity_schedule.go). A key held in an HSM is not assessed.

const blank: IntegrityInput = { name: "", target_filter: "*", interval_hours: 24, enabled: true };

export function KeyIntegrityView({ session, onToast }: { session: AuthSession; onToast: (m: string) => void }) {
  const [items, setItems] = useState<IntegritySchedule[] | null>(null);
  const [error, setError] = useState("");
  const [form, setForm] = useState<IntegrityInput | null>(null);
  const [editing, setEditing] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    try { setItems(await listIntegritySchedules(session)); setError(""); } catch (e) { setItems(null); setError(errMsg(e)); }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const act = async (key: string, fn: () => Promise<string>) => {
    setBusy(key);
    try { onToast(await fn()); await load(); return true; } catch (e) { onToast(errMsg(e)); return false; } finally { setBusy(""); }
  };
  const save = async () => {
    if (!form) return;
    if (await act("save", async () => { await saveIntegritySchedule(session, editing, form); return editing ? "Schedule saved; it runs on your authority." : "Integrity check scheduled."; })) setForm(null);
  };

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <div><Btn small primary onClick={() => { setEditing(""); setForm(blank); }}>New integrity check</Btn></div>
      {error ? <Failed what="Integrity schedules" error={error} /> : items && (
        <Card style={{ padding: 0, overflow: "hidden" }}>
          {items.length === 0 ? <Empty>No integrity checks scheduled.</Empty> : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>{["Name", "Keys", "Runs", "Next", "Last", "Result", "On the authority of", ""].map((h) => <th key={h} style={TH}>{h}</th>)}</tr></thead>
              <tbody>
                {items.map((s) => (
                  <tr key={s.id} data-testid="integrity-row">
                    <td style={{ ...TD, fontWeight: 600 }}>{s.name}</td>
                    <td style={{ ...TD, fontFamily: "var(--font-mono)" }}>{s.target_filter}</td>
                    <td style={TD}>{s.enabled ? every(s.interval_hours) : "off"}</td>
                    <td style={TD}>{s.enabled && !s.paused_reason ? when(s.next_run_at) : "—"}</td>
                    <td style={TD}>{s.last_run_at ? `${when(s.last_run_at)} · ${s.last_checked} checked, ${s.last_failed} failed, ${s.last_not_assessed} not assessed` : "—"}</td>
                    <td style={TD}><Result value={s.last_result} title={s.last_error} /></td>
                    <td style={TD}><Authority by={s.authorized_by} paused={s.paused_reason} /></td>
                    <td style={{ ...TD, display: "flex", gap: 6 }}>
                      <Btn small disabled={!!busy || !!s.paused_reason} title={s.paused_reason || "Check these keys now"}
                        onClick={() => void act(`run:${s.id}`, async () => { const r = await runIntegritySchedule(session, s.id); return `${r.outcome.checked} checked, ${r.outcome.failed} failed, ${r.outcome.not_assessed} not assessed`; })}>Run now</Btn>
                      <Btn small disabled={!!busy} onClick={() => { setEditing(s.id); setForm({ name: s.name, target_filter: s.target_filter, interval_hours: s.interval_hours, enabled: s.enabled }); }}>{s.paused_reason ? "Resume" : "Edit"}</Btn>
                      <Btn small danger disabled={!!busy} onClick={() => { if (window.confirm(`Delete the schedule "${s.name}"?`)) void act(`del:${s.id}`, async () => { await deleteIntegritySchedule(session, s.id); return "Schedule deleted."; }); }}>Delete</Btn>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
      <Modal open={!!form} onClose={() => setForm(null)} title={editing ? "Edit integrity check" : "Schedule an integrity check"}>
        {form && (
          <div style={{ padding: 18 }}>
            <FG label="Name" required><Inp value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></FG>
            <FG label="Keys" hint="* for every active key, tag:<tag>, id:<key id>, or a key-name pattern such as pay-*">
              <Inp mono value={form.target_filter} onChange={(e) => setForm({ ...form, target_filter: e.target.value })} />
            </FG>
            <FG label="Runs">
              <Sel value={String(form.interval_hours)} onChange={(e) => setForm({ ...form, interval_hours: Number(e.target.value) })}>
                {intervalOptions(form.interval_hours).map(([h, label]) => <option key={h} value={String(h)}>{label}</option>)}
              </Sel>
            </FG>
            <Chk label="Enabled" checked={form.enabled} onChange={() => setForm({ ...form, enabled: !form.enabled })} />
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
              <Btn onClick={() => setForm(null)}>Cancel</Btn>
              <Btn primary disabled={busy === "save" || !form.name.trim()} onClick={() => void save()}>{busy === "save" ? "Saving…" : "Save"}</Btn>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
