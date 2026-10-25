import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../lib/auth";
import { searchSecrets, type SecretItem } from "../../lib/secrets";
import { deleteSecretRotationSchedule, listSecretRotationSchedules, runSecretRotationSchedule, saveSecretRotationSchedule, type SecretRotationSchedule } from "../../lib/scheduling";
import { B, Btn, Card, Chk, FG, Inp, Modal, Sel } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";
import { Authority, Empty, every, Failed, intervalOptions, Result, TD, TH, when } from "./parts";

// Scheduling → Secret rotation (13.66.0-beta): a secret the KMS generated (an
// SSH key or a key pair) gets fresh material of the same kind as its next
// version on an interval (secrets rotation_schedule.go). A secret whose value
// came from outside can't be rotated by the KMS, so only generated ones are
// offered.

type Form = { secret: SecretItem | null; secretID: string; label: string; interval_hours: number; enabled: boolean };
const generated = (s: SecretItem) => s.metadata?.generated === true;

export function SecretRotationView({ session, onToast }: { session: AuthSession; onToast: (m: string) => void }) {
  const [items, setItems] = useState<SecretRotationSchedule[] | null>(null);
  const [error, setError] = useState("");
  const [form, setForm] = useState<Form | null>(null);
  const [busy, setBusy] = useState("");
  const [q, setQ] = useState("");
  const [found, setFound] = useState<SecretItem[] | null>(null);
  const [searchError, setSearchError] = useState("");

  const load = useCallback(async () => {
    try { setItems(await listSecretRotationSchedules(session)); setError(""); } catch (e) { setItems(null); setError(errMsg(e)); }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const act = async (key: string, fn: () => Promise<string>) => {
    setBusy(key);
    try { onToast(await fn()); await load(); return true; } catch (e) { onToast(errMsg(e)); return false; } finally { setBusy(""); }
  };
  const search = async () => {
    try { setFound((await searchSecrets(session, q.trim(), 20)).filter(generated)); setSearchError(""); } catch (e) { setFound(null); setSearchError(errMsg(e)); }
  };
  const save = async () => {
    if (!form?.secretID) return;
    if (await act("save", async () => { await saveSecretRotationSchedule(session, form.secretID, { interval_hours: form.interval_hours, enabled: form.enabled }); return "Rotation scheduled; it runs on your authority."; })) setForm(null);
  };

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <div><Btn small primary onClick={() => { setForm({ secret: null, secretID: "", label: "", interval_hours: 720, enabled: true }); setQ(""); setFound(null); }}>Schedule a rotation</Btn></div>
      {error ? <Failed what="Secret rotation schedules" error={error} /> : items && (
        <Card style={{ padding: 0, overflow: "hidden" }}>
          {items.length === 0 ? <Empty>No secret rotates on a schedule.</Empty> : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>{["Secret", "Kind", "Runs", "Next", "Last", "Result", "On the authority of", ""].map((h) => <th key={h} style={TH}>{h}</th>)}</tr></thead>
              <tbody>
                {items.map((s) => (
                  <tr key={s.secret_id} data-testid="secret-rotation-row">
                    <td style={{ ...TD, fontWeight: 600 }} title={s.secret_id}>{s.secret_path || s.secret_name}</td>
                    <td style={TD}>{s.secret_type}</td>
                    <td style={TD}>{s.enabled ? every(s.interval_hours) : "off"}</td>
                    <td style={TD}>{s.enabled && !s.paused_reason ? when(s.next_run_at) : "—"}</td>
                    <td style={TD}>{s.last_run_at ? `${when(s.last_run_at)}${s.last_version ? ` · v${s.last_version}` : ""}` : "—"}</td>
                    <td style={TD}><Result value={s.last_result} title={s.last_error} /></td>
                    <td style={TD}><Authority by={s.authorized_by} paused={s.paused_reason} /></td>
                    <td style={{ ...TD, display: "flex", gap: 6 }}>
                      <Btn small disabled={!!busy || !!s.paused_reason} title={s.paused_reason || "Rotate now"}
                        onClick={() => { if (window.confirm(`Write new material to ${s.secret_path || s.secret_name} now? Readers of the latest version get it.`)) void act(`run:${s.secret_id}`, async () => { const r = await runSecretRotationSchedule(session, s.secret_id); return r.last_result === "rotated" ? `Rotated to version ${r.last_version}.` : `Not rotated: ${r.last_error}`; }); }}>Rotate now</Btn>
                      <Btn small disabled={!!busy} onClick={() => setForm({ secret: null, secretID: s.secret_id, label: s.secret_path || s.secret_name, interval_hours: s.interval_hours, enabled: s.enabled })}>{s.paused_reason ? "Resume" : "Edit"}</Btn>
                      <Btn small danger disabled={!!busy} onClick={() => { if (window.confirm("Stop rotating this secret on a schedule?")) void act(`del:${s.secret_id}`, async () => { await deleteSecretRotationSchedule(session, s.secret_id); return "Schedule removed."; }); }}>Delete</Btn>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
      <Modal open={!!form} onClose={() => setForm(null)} title={form?.label ? `Rotation of ${form.label}` : "Schedule a secret rotation"}>
        {form && (
          <div style={{ padding: 18 }}>
            {!form.label && (
              <FG label="Generated secret" required hint="SSH keys and key pairs the KMS generated">
                <div style={{ display: "flex", gap: 6 }}>
                  <Inp value={q} placeholder="Name or ID" onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void search(); }} />
                  <Btn small onClick={() => void search()} disabled={!q.trim()}>Find</Btn>
                </div>
                {searchError && <div style={{ fontSize: 11, color: C.redFg, marginTop: 6 }}>{`Search unavailable: ${searchError}`}</div>}
                {found && (found.length === 0 ? <div style={{ fontSize: 11, color: C.muted, marginTop: 6 }}>No generated secret matches.</div> : (
                  <div style={{ display: "grid", gap: 4, marginTop: 6 }}>
                    {found.map((s) => (
                      <button key={s.id} type="button" onClick={() => setForm({ ...form, secret: s, secretID: s.id })}
                        style={{ all: "unset", cursor: "pointer", padding: "6px 8px", borderRadius: "var(--radius-md)", border: `1px solid ${form.secretID === s.id ? C.accentFg : C.border}`, fontSize: 11.5, color: C.text }}>
                        {s.path || s.name} <B c="neutral">{s.secret_type}</B>
                      </button>
                    ))}
                  </div>
                ))}
              </FG>
            )}
            <FG label="Rotate">
              <Sel value={String(form.interval_hours)} onChange={(e) => setForm({ ...form, interval_hours: Number(e.target.value) })}>
                {intervalOptions(form.interval_hours).map(([h, label]) => <option key={h} value={String(h)}>{label}</option>)}
              </Sel>
            </FG>
            <Chk label="Enabled" checked={form.enabled} onChange={() => setForm({ ...form, enabled: !form.enabled })} />
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
              <Btn onClick={() => setForm(null)}>Cancel</Btn>
              <Btn primary disabled={busy === "save" || !form.secretID} onClick={() => void save()}>{busy === "save" ? "Saving…" : "Save"}</Btn>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
