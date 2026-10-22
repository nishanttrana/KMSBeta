import { useCallback, useEffect, useState } from "react";
import { B, Btn, Card, Chk, FG, Inp, Row2, Section, Sel, Stat, Txt } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";
import type { AuthSession } from "../../lib/auth";
import {
  deleteBackupSchedule, listBackupSchedules, runBackupSchedule, saveBackupSchedule,
  type BackupKeyProtection, type BackupSchedule, type BackupScheduleInput
} from "../../lib/backupSchedules";

// Backup & Restore → Schedules: encrypted backups taken on a schedule
// (governance; docs/SECURITY/BACKUP_KEYS.md, "Scheduled backups").

const EMPTY: BackupScheduleInput = {
  name: "", enabled: true, scope: "system", target_tenant_id: "", interval_hours: 24, retain_count: 7,
  key_protection: "recipient", recipient_public_key: "",
};

const inputOf = (s: BackupSchedule): BackupScheduleInput => ({
  name: s.name, enabled: s.enabled, scope: s.scope, target_tenant_id: s.target_tenant_id || "", interval_hours: s.interval_hours,
  retain_count: s.retain_count, key_protection: s.key_protection, recipient_public_key: s.recipient_public_key || "",
});

const when = (v?: string) => (v ? new Date(v).toLocaleString() : "-");

export function BackupSchedulesPanel({ session, onToast }: { session: AuthSession | null; onToast: (m: string) => void }) {
  const [items, setItems] = useState<BackupSchedule[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [form, setForm] = useState<BackupScheduleInput | null>(null);
  const [editing, setEditing] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    try {
      setItems(await listBackupSchedules(session));
      setLoadError("");
    } catch (e) {
      setItems(null);
      setLoadError(errMsg(e));
    }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const act = async (key: string, fn: () => Promise<unknown>, done: string) => {
    setBusy(key);
    try {
      await fn();
      onToast(done);
      await load();
      return true;
    } catch (e) {
      onToast(errMsg(e));
      return false;
    } finally {
      setBusy("");
    }
  };
  const save = async () => {
    if (!session || !form) return;
    if (await act("save", () => saveBackupSchedule(session, editing, form), editing ? "Schedule saved." : "Schedule created.")) setForm(null);
  };

  const list = items ?? [];
  const paused = list.filter((s) => s.paused_reason).length;
  const failed = list.filter((s) => s.last_result === "failed").length;
  const set = (patch: Partial<BackupScheduleInput>) => setForm((f) => (f ? { ...f, ...patch } : f));

  return (
    <Section title="Backup Schedules" actions={<div style={{ display: "flex", gap: 6 }}>
      <Btn small onClick={() => void load()}>Refresh</Btn>
      <Btn small primary onClick={() => { setEditing(""); setForm({ ...EMPTY }); }}>New schedule</Btn>
    </div>}>
      {loadError ? (
        <Card><div style={{ fontSize: 11, color: C.redFg }}>{`Schedules unavailable: ${loadError}`}</div></Card>
      ) : <>
        <div style={{ display: "flex", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
          <Stat l="Schedules" v={list.length} />
          <Stat l="Enabled" v={list.filter((s) => s.enabled && !s.paused_reason).length} />
          <Stat l="Paused" v={paused} c={paused ? "amber" : "green"} />
          <Stat l="Last run failed" v={failed} c={failed ? "red" : "green"} />
        </div>

        {form && (
          <Card style={{ padding: 10, marginBottom: 10, borderColor: C.accent }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 8 }}>{editing ? "Edit schedule" : "New schedule"}</div>
            <Row2>
              <FG label="Name"><Inp value={form.name} onChange={(e: { target: { value: string } }) => set({ name: e.target.value })} placeholder="nightly-system" /></FG>
              <FG label="Scope">
                <Sel value={form.scope} onChange={(e: { target: { value: string } }) => set({ scope: e.target.value as "system" | "tenant" })}>
                  <option value="system">System</option><option value="tenant">Tenant</option>
                </Sel>
              </FG>
            </Row2>
            {form.scope === "tenant" && <FG label="Tenant"><Inp value={form.target_tenant_id} onChange={(e: { target: { value: string } }) => set({ target_tenant_id: e.target.value })} placeholder="tenant-id" /></FG>}
            <Row2>
              <FG label="Every (hours)"><Inp type="number" min={1} max={720} value={String(form.interval_hours)} onChange={(e: { target: { value: string } }) => set({ interval_hours: Math.trunc(Number(e.target.value || 0)) })} /></FG>
              <FG label="Keep newest"><Inp type="number" min={1} max={90} value={String(form.retain_count)} onChange={(e: { target: { value: string } }) => set({ retain_count: Math.trunc(Number(e.target.value || 0)) })} /></FG>
            </Row2>
            <FG label="Backup key">
              <Sel value={form.key_protection} onChange={(e: { target: { value: string } }) => set({ key_protection: e.target.value as BackupKeyProtection })}>
                <option value="recipient">Sealed to my public key</option>
                <option value="hsm">Wrapped in the tenant's HSM</option>
              </Sel>
            </FG>
            {form.key_protection === "recipient" && (
              <FG label="RSA public key (PEM, 3072 bits or more)">
                <Txt rows={5} value={form.recipient_public_key} onChange={(e: { target: { value: string } }) => set({ recipient_public_key: e.target.value })} placeholder={"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"} />
              </FG>
            )}
            <div data-keep="" style={{ fontSize: 10, color: C.dim, margin: "4px 0 8px" }} title="docs/SECURITY/BACKUP_KEYS.md">
              {form.key_protection === "recipient"
                ? "Keep the private key offline. Restore asks for it and opens the key in this browser; it is never sent."
                : "Needs an enabled HSM profile for the tenant; a run without it fails instead of keeping a software key."}
            </div>
            <Chk label="Enabled" checked={form.enabled} onChange={() => set({ enabled: !form.enabled })} />
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, marginTop: 8 }}>
              <Btn small onClick={() => setForm(null)}>Cancel</Btn>
              <Btn small primary onClick={() => void save()} disabled={busy === "save"}>{busy === "save" ? "Saving..." : "Save"}</Btn>
            </div>
          </Card>
        )}

        {items !== null && list.length === 0 && !form && <Card><div style={{ fontSize: 11, color: C.muted }}>No schedules. Backups are taken only by hand until one is added.</div></Card>}
        <div style={{ display: "grid", gap: 8 }}>
          {list.map((s) => (
            <Card key={s.id} style={{ padding: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{s.name}</span>
                    {s.paused_reason ? <B c="amber">paused</B> : <B c={s.enabled ? "green" : "neutral"}>{s.enabled ? "enabled" : "disabled"}</B>}
                    {s.last_result && <B c={s.last_result === "succeeded" ? "green" : s.last_result === "failed" ? "red" : "amber"}>{`last ${s.last_result}`}</B>}
                  </div>
                  <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>
                    {`${s.scope === "tenant" ? `Tenant ${s.target_tenant_id}` : "System"} · every ${s.interval_hours} h · keeps ${s.retain_count} · `}
                    {s.key_protection === "hsm" ? "key in HSM" : <span title={s.recipient_key_sha256}>{`sealed to ${String(s.recipient_key_sha256 || "").slice(0, 12)}`}</span>}
                  </div>
                  <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{`Next ${s.paused_reason ? "-" : when(s.next_run_at)} · last ${when(s.last_run_at)} · saved by ${s.authorized_by}`}</div>
                  {s.paused_reason && <div style={{ fontSize: 10, color: C.amberFg, marginTop: 4 }}>{s.paused_reason}</div>}
                  {s.last_error && !s.paused_reason && <div style={{ fontSize: 10, color: C.redFg, marginTop: 4 }}>{s.last_error}</div>}
                </div>
                <div style={{ display: "flex", gap: 6, alignItems: "flex-start", flexWrap: "wrap" }}>
                  <Btn small primary disabled={busy !== "" || Boolean(s.paused_reason)} onClick={() => void act(`run:${s.id}`, () => runBackupSchedule(session!, s.id), "Backup taken.")}>{busy === `run:${s.id}` ? "Running..." : "Run now"}</Btn>
                  <Btn small onClick={() => { setEditing(s.id); setForm(inputOf(s)); }}>{s.paused_reason ? "Save again" : "Edit"}</Btn>
                  {!s.paused_reason && <Btn small disabled={busy !== ""} onClick={() => void act(`toggle:${s.id}`, () => saveBackupSchedule(session!, s.id, { ...inputOf(s), enabled: !s.enabled }), s.enabled ? "Schedule disabled." : "Schedule enabled.")}>{s.enabled ? "Disable" : "Enable"}</Btn>}
                  <Btn small danger disabled={busy !== ""} onClick={() => void act(`del:${s.id}`, () => deleteBackupSchedule(session!, s.id), "Schedule deleted; its backups stay.")}>Delete</Btn>
                </div>
              </div>
            </Card>
          ))}
        </div>
      </>}
    </Section>
  );
}
