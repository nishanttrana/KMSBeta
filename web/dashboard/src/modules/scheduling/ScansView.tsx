import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../lib/auth";
import { getComplianceAssessmentSchedule, runComplianceAssessmentSchedule, updateComplianceAssessmentSchedule, type AssessmentSchedule } from "../../lib/compliance";
import { getDiscoverySchedule, getDiscoverySources, type DiscoverySchedule, type DiscoverySource } from "../../lib/discovery";
import { Btn, Card, Chk, Sel } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";
import { ScheduleModal } from "../../components/v3/tabs/discovery/Schedule";
import { Authority, every, Result, when } from "./parts";

// Scheduling → Scans & assessments: the tenant's crypto discovery scan and
// compliance assessment. Each runs on the authority of the person who last
// saved it, re-checked before every run.

const title: React.CSSProperties = { fontSize: 10.5, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "var(--font-mono)" };
const Row = ({ k, v }: { k: string; v: React.ReactNode }) => (
  <div style={{ display: "grid", gridTemplateColumns: "140px 1fr", gap: 8, fontSize: 11.5, padding: "4px 0" }}>
    <span style={{ color: C.muted }}>{k}</span><span style={{ color: C.text }}>{v}</span>
  </div>
);

type Loaded<T> = { value: T | null; error: string };

export function ScansView({ session, onToast }: { session: AuthSession; onToast: (m: string) => void }) {
  const [scan, setScan] = useState<Loaded<DiscoverySchedule>>({ value: null, error: "" });
  const [sources, setSources] = useState<DiscoverySource[]>([]);
  const [assess, setAssess] = useState<Loaded<AssessmentSchedule>>({ value: null, error: "" });
  const [draft, setDraft] = useState<{ enabled: boolean; frequency: AssessmentSchedule["frequency"] } | null>(null);
  const [scanOpen, setScanOpen] = useState(false);
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    // Each loads on its own: one failing never blanks the other.
    const [s, src, a] = await Promise.allSettled([getDiscoverySchedule(session), getDiscoverySources(session), getComplianceAssessmentSchedule(session)]);
    setScan(s.status === "fulfilled" ? { value: s.value, error: "" } : { value: null, error: errMsg(s.reason) });
    setSources(src.status === "fulfilled" ? src.value : []);
    setAssess(a.status === "fulfilled" ? { value: a.value, error: "" } : { value: null, error: errMsg(a.reason) });
    if (a.status === "fulfilled") setDraft({ enabled: a.value.enabled, frequency: a.value.frequency });
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const act = async (key: string, fn: () => Promise<string>) => {
    setBusy(key);
    try { onToast(await fn()); await load(); } catch (e) { onToast(errMsg(e)); } finally { setBusy(""); }
  };
  const s = scan.value;
  const a = assess.value;

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(340px,1fr))", gap: 12 }}>
      <Card>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <span style={title}>Crypto discovery scan</span>
          <Btn small onClick={() => setScanOpen(true)} disabled={!s}>{s?.paused_reason ? "Resume" : "Edit"}</Btn>
        </div>
        {scan.error ? <div style={{ fontSize: 11.5, color: C.redFg }}>{`Unavailable: ${scan.error}`}</div> : s && (
          <>
            <Row k="Runs" v={s.enabled ? every(s.interval_hours) : "off"} />
            <Row k="Sources" v={s.sources.length ? s.sources.join(", ") : "none"} />
            <Row k="Next" v={s.enabled && !s.paused_reason ? when(s.next_run_at) : "—"} />
            <Row k="Last" v={s.last_run_at ? `${when(s.last_run_at)}${s.last_scan_id ? ` · ${s.last_scan_id}` : ""}` : "—"} />
            <Row k="On the authority of" v={<Authority by={s.authorized_by} paused={s.paused_reason} />} />
            {s.paused_reason && <div data-keep style={{ fontSize: 11, color: C.amberFg, marginTop: 6 }}>{s.paused_reason}</div>}
          </>
        )}
      </Card>
      <Card>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <span style={title}>Compliance assessment</span>
          <Btn small disabled={!a?.authorized_by || !!a?.paused_reason || !!busy} title={a?.paused_reason || "Assess now"}
            onClick={() => void act("run", async () => { const out = await runComplianceAssessmentSchedule(session); return out.last_result === "assessed" ? "Assessment recorded." : `Not assessed: ${out.last_error}`; })}>Run now</Btn>
        </div>
        {assess.error ? <div style={{ fontSize: 11.5, color: C.redFg }}>{`Unavailable: ${assess.error}`}</div> : a && draft && (
          <>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
              <Chk label="Scheduled" checked={draft.enabled} onChange={() => setDraft({ ...draft, enabled: !draft.enabled })} />
              <Sel w={120} value={draft.frequency} onChange={(e) => setDraft({ ...draft, frequency: e.target.value as AssessmentSchedule["frequency"] })}>
                <option value="hourly">Hourly</option><option value="daily">Daily</option><option value="weekly">Weekly</option>
              </Sel>
              <Btn small primary disabled={!!busy} onClick={() => void act("save", async () => { await updateComplianceAssessmentSchedule(session, draft); return "Assessment schedule saved; it runs on your authority."; })}>Save</Btn>
            </div>
            <Row k="Next" v={a.enabled && !a.paused_reason ? when(a.next_run_at) : "—"} />
            <Row k="Last" v={when(a.last_run_at)} />
            <Row k="Result" v={<Result value={a.last_result} title={a.last_error || a.last_assessment_id} />} />
            <Row k="On the authority of" v={<Authority by={a.authorized_by || ""} paused={a.paused_reason} />} />
            {a.paused_reason && <div data-keep style={{ fontSize: 11, color: C.amberFg, marginTop: 6 }}>{a.paused_reason}</div>}
          </>
        )}
      </Card>
      <ScheduleModal open={scanOpen} onClose={() => setScanOpen(false)} session={session} schedule={s} sources={sources}
        onSaved={(next) => { setScan({ value: next, error: "" }); setScanOpen(false); }} onToast={onToast} />
    </div>
  );
}
