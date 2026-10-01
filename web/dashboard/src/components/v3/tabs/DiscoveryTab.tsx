import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Atom, CalendarClock, Clock3, KeyRound, Play, Radar, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";
import { Btn, Section, Stat, Tabs } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import { DrillHint, DrillPanel, clickable, usePagedDrill } from "../chartDrill";
import {
  DISCOVERY_UPLOAD_MAX_BYTES,
  getDiscoveryScan,
  getDiscoverySchedule,
  getDiscoverySources,
  getDiscoverySummary,
  listDiscoveryAssets,
  listDiscoveryBuckets,
  listDiscoveryRepositories,
  listDiscoveryScans,
  listDiscoveryTargets,
  startDiscoveryScan,
  uploadDiscoveryFile,
  type CryptoAsset,
  type DiscoveryScan,
  type AssetQuery,
  type DiscoveryBucket,
  type DiscoveryRepository,
  type DiscoverySchedule,
  type DiscoverySource,
  type DiscoverySummary,
  type DiscoveryTarget,
} from "../../../lib/discovery";
import {
  MONO, SCANNABLE, absTime, classDrill, expiringDrill, isStale, pct, pqcDrill, relTime, riskyDrill, sourceMeta, typeLabel, type AssetDrill,
} from "./discovery/meta";
import { AlgorithmBars, ChartCard, ClassBars, SourceStack } from "./discovery/Charts";
import { CodeSetupModal, SourceCards, TargetsModal } from "./discovery/Sources";
import { ClassPill, Inventory, NO_FILTERS, type Filters } from "./discovery/Inventory";
import { AssetDetail } from "./discovery/AssetDetail";
import { RunningBanner, ScansView } from "./discovery/Scans";
import { RepositoriesModal } from "./discovery/Repositories";
import { BucketsModal } from "./discovery/Buckets";
import { ScheduleModal, scheduleLabel } from "./discovery/Schedule";


export const DiscoveryTab = ({ session, onToast, onNavigate }: any) => {
  const [view, setView] = useState("Inventory");
  const [summary, setSummary] = useState<DiscoverySummary | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [scans, setScans] = useState<DiscoveryScan[]>([]);
  const [sources, setSources] = useState<DiscoverySource[]>([]);
  const [targets, setTargets] = useState<DiscoveryTarget[]>([]);
  const [loadError, setLoadError] = useState("");
  const [sourcesError, setSourcesError] = useState("");
  const [targetsError, setTargetsError] = useState("");
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState<DiscoveryScan | null>(null);
  const [uploading, setUploading] = useState(false);
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [detail, setDetail] = useState<CryptoAsset | null>(null);
  const [drill, setDrill] = useState<AssetDrill | null>(null);
  const [repositories, setRepositories] = useState<DiscoveryRepository[]>([]);
  const [reposError, setReposError] = useState("");
  const [reposOpen, setReposOpen] = useState(false);
  const [buckets, setBuckets] = useState<DiscoveryBucket[]>([]);
  const [bucketsError, setBucketsError] = useState("");
  const [bucketsOpen, setBucketsOpen] = useState(false);
  const [schedule, setSchedule] = useState<DiscoverySchedule | null>(null);
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [targetsOpen, setTargetsOpen] = useState(false);
  const [codeOpen, setCodeOpen] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const countsRef = useRef("");

  const load = async () => {
    if (!session?.token) return;
    setLoading(true);
    const [sm, sc, src, tg, rp, sch, bk] = await Promise.allSettled([
      getDiscoverySummary(session),
      listDiscoveryScans(session, 50),
      getDiscoverySources(session),
      listDiscoveryTargets(session),
      listDiscoveryRepositories(session),
      getDiscoverySchedule(session),
      listDiscoveryBuckets(session),
    ]);
    setBuckets(bk.status === "fulfilled" ? bk.value : []);
    setBucketsError(bk.status === "rejected" ? errMsg(bk.reason) : "");
    setRepositories(rp.status === "fulfilled" ? rp.value : []);
    setReposError(rp.status === "rejected" ? errMsg(rp.reason) : "");
    setSchedule(sch.status === "fulfilled" ? sch.value : null);
    const failed = [sm, sc].find((r) => r.status === "rejected") as PromiseRejectedResult | undefined;
    setLoadError(failed ? errMsg(failed.reason) : "");
    const next = sm.status === "fulfilled" ? sm.value : null;
    // An open drill-down carries the count it was opened with; when the
    // counts change it is closed, never left showing the old number.
    if (JSON.stringify(next) !== countsRef.current) setDrill(null);
    countsRef.current = JSON.stringify(next);
    setSummary(next);
    setReloadKey((k) => k + 1);
    if (sc.status === "fulfilled") {
      setScans(sc.value);
      const live = sc.value.find((x) => x.status === "running");
      if (live) setRunning((cur) => cur ?? live);
    }
    setSources(src.status === "fulfilled" ? src.value : []);
    setSourcesError(src.status === "rejected" ? errMsg(src.reason) : "");
    setTargets(tg.status === "fulfilled" ? tg.value : []);
    setTargetsError(tg.status === "rejected" ? errMsg(tg.reason) : "");
    setLoading(false);
  };

  useEffect(() => {
    void load();
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: reload when the tenant changes; load is a per-render closure.
  }, [session?.tenantId, session?.token]);

  // Poll a running scan until it settles, then reload everything.
  useEffect(() => {
    if (!running?.id) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const sc = await getDiscoveryScan(session, running.id);
        if (stopped) return;
        if (sc.status === "running") {
          setRunning(sc);
          timer = setTimeout(tick, 2000);
          return;
        }
        setRunning(null);
        const errs = Object.keys(((sc.stats as any)?.errors as Record<string, string>) || {});
        const found = Number((sc.stats as any)?.assets_discovered ?? 0);
        onToast?.(`Scan ${sc.status.replace(/_/g, " ")}: ${found} assets${errs.length ? ` · ${errs.map((e) => sourceMeta(e).label).join(", ")} had errors` : ""}`);
        void load();
      } catch (e) {
        if (!stopped) {
          setRunning(null);
          onToast?.(`Scan status unavailable: ${errMsg(e)}`);
        }
      }
    };
    timer = setTimeout(tick, 1500);
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: one poll loop per scan ID.
  }, [running?.id]);

  const configured = sources.filter((s) => SCANNABLE.includes(s.id) && s.configured).map((s) => s.id);
  const scanAllTypes = sources.length ? configured : [...SCANNABLE];

  const runScan = async (types: string[]) => {
    if (!types.length || running) return;
    try {
      const scan = await startDiscoveryScan(session, types);
      setRunning(scan);
      setScans((prev) => [scan, ...prev]);
    } catch (e) {
      onToast?.(`Scan not started: ${errMsg(e)}`);
      void load();
    }
  };

  const upload = async (files: File[]) => {
    if (!files.length) return;
    setUploading(true);
    let total = 0;
    let exposed = 0;
    const failed: string[] = [];
    for (const f of files) {
      if (f.size > DISCOVERY_UPLOAD_MAX_BYTES) {
        failed.push(`${f.name} (over 2 MiB)`);
        continue;
      }
      try {
        const res = await uploadDiscoveryFile(session, f);
        total += res.assets.length;
        exposed += res.assets.filter((x) => x.classification === "exposed").length;
      } catch (e) {
        failed.push(`${f.name} (${errMsg(e)})`);
      }
    }
    setUploading(false);
    const found = total ? `${total} assets found${exposed ? `, ${exposed} exposed secrets` : ""}` : "No keys, certificates or secrets found";
    onToast?.(failed.length ? `${found}. Not scanned: ${failed.join("; ")}` : found);
    if (total) setFilters({ ...NO_FILTERS, source: "upload" });
    void load();
  };

  const pickUpload = () => fileRef.current?.click();

  const total = summary?.total_assets ?? 0;
  const network = sources.find((s) => s.id === "network");
  const detailStale = useMemo(() => (detail ? isStale(detail, sources) : false), [detail, sources]);
  const pickDrill = (d: AssetDrill) => setDrill((cur) => (cur?.key === d.key ? null : d));
  // The drill-down pages the service with the filter the summary counted with.
  const fetchDrill = useCallback(
    (q: AssetQuery, offset: number, limit: number) => listDiscoveryAssets(session, q, offset, limit).then((r) => r.items),
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: a new fetcher per tenant session, not per render.
    [session?.tenantId, session?.token]);
  const drilled = usePagedDrill<CryptoAsset, AssetQuery>(drill, fetchDrill);
  const tile = (d: AssetDrill, node: ReactNode) => (
    <div onClick={() => pickDrill(d)} title={`List ${d.label.toLowerCase()} assets`}
      style={{ ...clickable, display: "flex", borderRadius: "var(--radius-md)", outline: drill?.key === d.key ? `2px solid ${C.accentFg}` : "none" }}>{node}</div>
  );

  return (
    <div>
      <Section
        title={<><Radar size={16} color={C.accentFg} />Crypto Discovery</>}
        actions={<>
          <Btn small onClick={() => void load()} disabled={loading}><RefreshCw size={12} />{loading ? "Refreshing" : "Refresh"}</Btn>
          <Btn small onClick={() => setScheduleOpen(true)} title={schedule?.paused_reason || (schedule?.enabled ? `Next run ${absTime(schedule.next_run_at)}` : "Scan on a schedule")}
            style={schedule?.paused_reason ? { borderColor: C.amberFg, color: C.amberFg } : schedule?.enabled ? { borderColor: C.accentFg, color: C.accentFg } : {}}>
            <CalendarClock size={12} />{scheduleLabel(schedule)}
          </Btn>
          <Btn small primary onClick={() => void runScan(scanAllTypes)} disabled={!!running || !scanAllTypes.length}
            title={scanAllTypes.length ? `Scan ${scanAllTypes.map((t) => sourceMeta(t).label).join(", ")}` : "Set up a source first"}>
            <Play size={12} />Scan all
          </Btn>
        </>}
      />

      {running && <RunningBanner scan={running} />}

      {loadError ? (
        <div style={{ marginBottom: 14, padding: "10px 14px", border: `1px solid ${C.redFg}`, borderRadius: "var(--radius-md)", fontSize: 12, color: C.redFg }}>Discovery unavailable: {loadError}</div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))", gap: 10, marginBottom: 14 }}>
          <Stat l="Assets" v={summary ? total.toLocaleString() : "-"} s={summary ? `${Object.keys(summary.source_distribution || {}).length} sources` : ""} c="accent" i={KeyRound} />
          {summary && tile(pqcDrill(summary), <Stat l="Post-quantum" v={`${pct(summary.pqc_ready_count, total)}%`} s={`${summary.pqc_ready_count} of ${total}`} c="green" i={Atom} />)}
          {summary && tile(riskyDrill(summary), <Stat l="Weak or exposed" v={String(riskyDrill(summary).count)} s={`${pct(riskyDrill(summary).count || 0, total)}% of assets`} c="red" i={ShieldAlert} />)}
          {summary && tile(classDrill(summary, "quantum_vulnerable"), <Stat l="Quantum-vulnerable" v={String(classDrill(summary, "quantum_vulnerable").count)} s={`${pct(classDrill(summary, "quantum_vulnerable").count || 0, total)}% of assets`} c="amber" i={ShieldCheck} />)}
          {summary && tile(expiringDrill(summary), <Stat l="Expiring or expired" v={String(summary.expiring_30d || 0)} s="certificates, next 30 days" c="orange" i={Clock3} />)}
        </div>
      )}

      <div style={{ fontSize: 12, fontWeight: 600, color: C.text, margin: "4px 0 8px" }}>Sources</div>
      {sourcesError ? (
        <div style={{ fontSize: 11.5, color: C.redFg, marginBottom: 14 }}>Sources unavailable: {sourcesError}</div>
      ) : (
        <div style={{ marginBottom: 16 }}>
          <SourceCards sources={sources} assetCounts={summary?.source_distribution || {}} running={!!running} uploading={uploading}
            onScan={(t) => void runScan(t)} onTargets={() => setTargetsOpen(true)} onRepositories={() => setReposOpen(true)} onBuckets={() => setBucketsOpen(true)} onCodeSetup={() => setCodeOpen(true)}
            onPickFiles={pickUpload} onUpload={(f) => void upload(f)} onNavigate={onNavigate} />
        </div>
      )}

      {summary && total > 0 && (
        <>
          <DrillHint />
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))", gap: 10 }}>
            <ChartCard title="By class" sub={`${total.toLocaleString()} assets`}>
              <ClassBars summary={summary} active={drill?.key || ""} onDrill={pickDrill} />
            </ChartCard>
            <ChartCard title="Top algorithms">
              <AlgorithmBars summary={summary} active={drill?.key || ""} onDrill={pickDrill} />
            </ChartCard>
            <ChartCard title="By source">
              <SourceStack summary={summary} active={drill?.key || ""} onDrill={pickDrill} />
            </ChartCard>
          </div>
        </>
      )}
      {drill && (
        <DrillPanel label={drill.label} count={drill.count} onClear={() => setDrill(null)}
          loaded={drilled.rows.length} loading={drilled.loading} error={drilled.error} onMore={drilled.done ? undefined : drilled.loadMore}>
          {drilled.rows.map((a) => (
            <div key={a.id} onClick={() => setDetail(a)}
              style={{ ...clickable, display: "grid", gridTemplateColumns: "2.4fr 1.2fr 1.2fr 1fr 70px", gap: 10, alignItems: "center", padding: "7px 4px", borderBottom: `1px solid ${C.border}`, fontSize: 11 }}
              onMouseEnter={(e) => { e.currentTarget.style.background = C.cardHover; }} onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
              <span style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 600, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.name || "-"}</div>
                <div style={{ fontSize: 10, color: C.muted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{typeLabel(a.asset_type)} · <span style={{ fontFamily: MONO }}>{a.location}</span></div>
              </span>
              <span style={{ fontFamily: MONO, color: C.text }}>{a.algorithm || "-"}</span>
              <ClassPill cls={a.classification} />
              <span style={{ color: C.dim }}>{sourceMeta(a.source).label}</span>
              <span style={{ color: C.muted, textAlign: "right" }}>{relTime(a.last_seen)}</span>
            </div>
          ))}
        </DrillPanel>
      )}
      <div style={{ height: 16 }} />

      {!loadError && <>
        <Tabs tabs={["Inventory", "Scans"]} active={view} onChange={setView} />
        {view === "Inventory" ? (
          <Inventory session={session} sources={sources} filters={filters} setFilters={setFilters} onOpen={setDetail} reloadKey={reloadKey} />
        ) : (
          <ScansView scans={scans} />
        )}
      </>}

      <AssetDetail asset={detail} stale={detailStale} session={session} onClose={() => setDetail(null)} onToast={onToast}
        onChanged={(next) => {
          if (next) {
            setDetail({ ...(detail as CryptoAsset), ...next });
            setReloadKey((k) => k + 1);
          } else {
            // Removed: the counts changed, so the open drill-down is stale.
            setDetail(null);
            setDrill(null);
            void load();
          }
        }} />
      <TargetsModal open={targetsOpen} onClose={() => setTargetsOpen(false)} session={session} targets={targets} error={targetsError}
        operatorEndpoints={Number(network?.detail?.operator_endpoints || 0)} onChanged={() => void load()} onToast={onToast} />
      <RepositoriesModal open={reposOpen} onClose={() => setReposOpen(false)} session={session} repositories={repositories} error={reposError}
        onChanged={() => void load()} onToast={onToast} onNavigate={onNavigate} />
      <BucketsModal open={bucketsOpen} onClose={() => setBucketsOpen(false)} session={session} buckets={buckets} error={bucketsError}
        onChanged={() => void load()} onToast={onToast} onNavigate={onNavigate} />
      <ScheduleModal open={scheduleOpen} onClose={() => setScheduleOpen(false)} session={session} schedule={schedule} sources={sources}
        onSaved={setSchedule} onToast={onToast} />
      <input ref={fileRef} type="file" multiple hidden onChange={(e) => { void upload(Array.from(e.target.files || [])); e.target.value = ""; }} />
      <CodeSetupModal open={codeOpen} onClose={() => setCodeOpen(false)} configured={!!sources.find((s) => s.id === "code")?.configured} />
    </div>
  );
};
