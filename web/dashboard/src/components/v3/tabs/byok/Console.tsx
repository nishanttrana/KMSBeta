import { CloudUpload, Cpu, Download, KeyRound, ShieldOff, Timer, TriangleAlert } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import type { AuthSession } from "../../../../lib/auth";
import { listBYOKKeys, listBYOKProviders, listBYOKRuns, runsToScript, type BYOKKey, type BYOKProviderInfo, type BYOKRun } from "../../../../lib/byok";
import type { CloudAccount } from "../../../../lib/cloud";
import { DrillPanel, clickable } from "../../chartDrill";
import { errMsg } from "../../runtimeUtils";
import { B, Btn, Section, Stat } from "../../legacyPrimitives";
import { C } from "../../theme";
import { BarRow, ChartCard, Swatch, solid } from "../discovery/Charts";
import { BYOKCreateWizard } from "./CreateWizard";
import { BYOKKeyDetail } from "./KeyDetail";
import {
  CLOUD_ORDER, MONO, OPERATION_LABEL, SOURCE_LABEL, STATES, allDrill, cloudDrill, cloudLabel, expiringDrill, fmtAgo, fmtDate,
  sourceDrill, stateDrill, stateOf, type BYOKDrill,
} from "./meta";
import { RunSteps } from "./RunSteps";

type Props = {
  session: AuthSession;
  accounts: CloudAccount[];
  keyCatalog: unknown[];
  onAddConnector: () => void;
  onToast?: ((msg: string) => void) | undefined;
};

const FILL = "var(--cls-strong)";

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/x-sh" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

// The BYOK console: what is in which cloud, from where, in what state, and
// every run with the cloud calls it made.
export function BYOKConsole({ session, accounts, keyCatalog, onAddConnector, onToast }: Props) {
  const [keys, setKeys] = useState<BYOKKey[]>([]);
  const [providers, setProviders] = useState<BYOKProviderInfo[]>([]);
  const [runs, setRuns] = useState<BYOKRun[]>([]);
  const [error, setError] = useState("");
  const [drill, setDrill] = useState<BYOKDrill>(allDrill());
  const [openKey, setOpenKey] = useState("");
  const [creating, setCreating] = useState(false);
  const [openRun, setOpenRun] = useState("");
  const now = Date.now();

  const load = useCallback(async () => {
    try {
      const [k, p, r] = await Promise.all([listBYOKKeys(session), listBYOKProviders(session), listBYOKRuns(session)]);
      setKeys(k);
      setProviders(p);
      setRuns(r);
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const count = (d: BYOKDrill) => keys.filter(d.match).length;
  const select = (d: BYOKDrill) => setDrill(drill.key === d.key ? allDrill() : d);
  const tile = (d: BYOKDrill, node: ReactNode) => (
    <div role="button" tabIndex={0} title={`List: ${d.label}`} onClick={() => select(d)} onKeyDown={(e) => { if (e.key === "Enter") select(d); }}
      style={{ ...clickable, display: "flex", borderRadius: "var(--radius-md)", outline: drill.key === d.key ? `2px solid ${C.accentFg}` : "none" }}>{node}</div>
  );
  const clouds = useMemo(() => CLOUD_ORDER.map((p) => ({ p, d: cloudDrill(p) })).map((r) => ({ ...r, n: count(r.d) })).filter((r) => r.n > 0),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- count reads keys
    [keys]);
  const states = STATES.map((s) => ({ s, d: stateDrill(s.id), n: keys.filter((k) => stateOf(k) === s.id).length }));
  const sources = ["kms", "hsm"].map((s) => ({ s, d: sourceDrill(s), n: count(sourceDrill(s)) }));
  const max = (rows: { n: number }[]) => Math.max(0, ...rows.map((r) => r.n));
  const dim = (key: string) => drill.key !== "all" && drill.key !== key;
  const failedRuns = runs.filter((r) => r.status === "failed").length;
  const capsOf = (p: string) => providers.find((x) => x.provider === p)?.capabilities;
  const listed = keys.filter(drill.match);

  return (
    <div>
      <Section title="Cloud BYOK" actions={<div style={{ display: "flex", gap: 8 }}>
        <Btn small onClick={() => void load()}>Refresh</Btn>
        <Btn small primary onClick={() => setCreating(true)}><CloudUpload size={12} /> Bring your own key</Btn>
      </div>}>
        {error && <div style={{ fontSize: 11, color: C.redFg, marginBottom: 10 }}>BYOK unavailable: {error}</div>}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))", gap: 10, marginBottom: 12 }}>
          {tile(allDrill(), <Stat l="Cloud keys" v={String(keys.length)} s={`${clouds.length} clouds`} c="accent" i={KeyRound} />)}
          {tile(stateDrill("current"), <Stat l="Current material" v={String(count(stateDrill("current")))} s="imported from the KMS" c="green" i={CloudUpload} />)}
          {tile(stateDrill("pending"), <Stat l="Waiting for material" v={String(count(stateDrill("pending")))} s="created, import not done" c="amber" i={TriangleAlert} />)}
          {tile(stateDrill("revoked"), <Stat l="Revoked" v={String(count(stateDrill("revoked")))} s="restore brings it back" c="red" i={ShieldOff} />)}
          {tile(expiringDrill(now), <Stat l="Expiring in 30 days" v={String(count(expiringDrill(now)))} s="reimport renews" c="orange" i={Timer} />)}
          {tile(sourceDrill("hsm"), <Stat l="Material from an HSM" v={String(count(sourceDrill("hsm")))} s="wrapped inside the HSM" c="purple" i={Cpu} />)}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 10 }}>
          <ChartCard title="By cloud" sub={`${keys.length} keys`}>
            {clouds.map(({ p, d, n }) => <BarRow key={p} label={cloudLabel(p)} value={n} max={max(clouds)} bar={solid(FILL)} title={`${cloudLabel(p)}: ${n}`}
              active={drill.key === d.key} dim={dim(d.key)} onClick={() => select(d)} />)}
            {!clouds.length && <div style={{ fontSize: 11, color: C.muted }}>No cloud keys yet.</div>}
          </ChartCard>
          <ChartCard title="Material" sub="as the KMS recorded it">
            {states.map(({ s, d, n }) => <BarRow key={s.id} label={<><Swatch color={s.color} />{s.short}</>} value={n} max={max(states)} bar={solid(s.color)}
              title={`${s.label}: ${n}`} active={drill.key === d.key} dim={dim(d.key)} onClick={() => select(d)} />)}
          </ChartCard>
          <ChartCard title="Material from" sub="where it was generated">
            {sources.map(({ s, d, n }) => <BarRow key={s} label={SOURCE_LABEL[s] ?? s} value={n} max={max(sources)} bar={solid(FILL)}
              title={`${d.label}: ${n}`} active={drill.key === d.key} dim={dim(d.key)} onClick={() => select(d)} />)}
          </ChartCard>
        </div>
        <DrillPanel label={drill.label} count={listed.length} onClear={() => setDrill(allDrill())}>
          {listed.map((k) => (
            <div key={k.id} onClick={() => setOpenKey(k.id)} style={{ ...clickable, display: "grid", gridTemplateColumns: "1.1fr 1.6fr 1fr 70px 1fr 110px", gap: 10, alignItems: "center", padding: "7px 4px", borderBottom: `1px solid ${C.border}`, fontSize: 11 }}>
              <span style={{ color: C.text, fontWeight: 600 }}>{cloudLabel(k.provider)}</span>
              <span title={k.cloud_key_ref || k.cloud_key_id} style={{ fontFamily: MONO, fontSize: 10.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{k.alias || k.cloud_key_id || "-"}</span>
              <span style={{ fontFamily: MONO, fontSize: 10.5, color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{k.key_id}</span>
              <span>{k.origin === "byok" ? (SOURCE_LABEL[k.source] ?? k.source) : "cloud"}</span>
              <span><Swatch color={STATES.find((s) => s.id === stateOf(k))?.color ?? FILL} /> {STATES.find((s) => s.id === stateOf(k))?.label}</span>
              <span style={{ color: C.muted }}>{k.expires_at ? `expires ${fmtDate(k.expires_at)}` : fmtAgo(k.updated_at)}</span>
            </div>
          ))}
        </DrillPanel>
      </Section>

      <Section title={`Activity${failedRuns ? ` · ${failedRuns} failed` : ""}`} actions={
        <Btn small disabled={!runs.length} onClick={() => download("vecta-byok-cloud-calls.sh", runsToScript(runs))}><Download size={12} /> Export as script</Btn>
      }>
        <div style={{ display: "grid", gap: 6 }}>
          {runs.slice(0, 25).map((r) => {
            const k = keys.find((x) => x.id === r.byok_id);
            return (
              <div key={r.id} style={{ border: `1px solid ${C.border}`, borderRadius: 4, padding: "6px 10px", background: C.card }}>
                <button type="button" onClick={() => setOpenRun(openRun === r.id ? "" : r.id)} style={{ all: "unset", cursor: "pointer", display: "flex", justifyContent: "space-between", width: "100%", fontSize: 11, gap: 8 }}>
                  <span style={{ color: C.text }}>{OPERATION_LABEL[r.operation] ?? r.operation} · {k ? `${cloudLabel(k.provider)} ${k.alias || k.cloud_key_id}` : r.byok_id}</span>
                  <span style={{ display: "flex", gap: 8, color: C.muted, flexShrink: 0 }}>{r.actor} · {fmtAgo(r.started_at)} <B c={r.status === "succeeded" ? "green" : "red"}>{r.status}</B></span>
                </button>
                {openRun === r.id && <div style={{ marginTop: 8 }}><RunSteps run={r} compact /></div>}
              </div>
            );
          })}
          {!runs.length && <div style={{ fontSize: 11, color: C.muted }}>No BYOK runs yet.</div>}
        </div>
      </Section>

      {creating && <BYOKCreateWizard session={session} accounts={accounts} providers={providers} keyCatalog={keyCatalog as never[]}
        onClose={() => setCreating(false)} onDone={() => void load()} onAddConnector={() => { setCreating(false); onAddConnector(); }} onToast={onToast} />}
      {openKey && <BYOKKeyDetail session={session} id={openKey} listed={keys.find((k) => k.id === openKey)} caps={capsOf(keys.find((k) => k.id === openKey)?.provider ?? "")}
        onClose={() => setOpenKey("")} onChanged={() => void load()} onToast={onToast} />}
    </div>
  );
}
